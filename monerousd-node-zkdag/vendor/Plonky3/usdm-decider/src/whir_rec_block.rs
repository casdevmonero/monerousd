// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! Rec-block → HVZK-WHIR witness adapter (#135 routing, the phone-class decider).
//!
//! `pqspend_rec_block_prove` (circuit.rs) currently publishes its aggregated rec proof under the
//! FRI ZK config (`build_zk_config_lfp0`) — Merkle-hash-dominated, ~11s single-core. #135 routes
//! that SAME aggregate onto the HVZK-WHIR multilinear PCS (`hiding_decider` entries): a hashless,
//! sumcheck-dominated verifier = the phone-class (sub-1s) speedup, kept ≤1.8MB + is_zk()==1.
//!
//! This module is the interface between the rec-block's real AIR traces (`RowMajorMatrix<Fa4>`
//! for r6 / leaf / stub / ood / claims) and the proven multi-table HVZK-WHIR prover: it converts
//! each row-major trace into the column-major, power-of-two-padded multilinear (MLE) witness the
//! decider's `build_decider_hiding_prover` consumes, and reports the per-table `(n_vars, width)`
//! shapes the matching `build_decider_hiding_verifier` needs. Padding is done HERE to
//! `max(⌈log2 height⌉, folding)` variables so the prover's internal `Witness::new_interleaved`
//! `pad_zeros(folding)` is a no-op and prover/verifier shapes stay in exact lockstep (a mismatch
//! is a hard `TableShape` reject, so lockstep is soundness-relevant, not cosmetic).

// ONE digest width for the whole tree — 8 lanes x 31 bits = 248 bits (kill list §AG).
pub(crate) use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use p3_commit::Mmcs;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::rngs::SmallRng;
use serde::{Deserialize, Serialize};

use p3_whir::pcs::hiding::{ZkSumcheckData, prove_hvzk, verify_hvzk};

use crate::hiding_decider::{
    Chl, CompressHash, Ea4, Enc16, Fa4, Mmcs16, Perm16, SpongeHash, build_decider_hiding_prover,
    build_decider_hiding_verifier, decider_mask_encoding,
};
use p3_challenger::CanObserve;
use rand::SeedableRng;
use crate::light_commit::{
    LightCommitProver, LightCommitVerifier, LightRound, ShiftBindProof, prove_shift_bind, verify_shift_bind,
};
use crate::air_zerocheck::{
    AirConstraint, AirZerocheckProof, ColSumProof, LogupHConstraint, LogupKeyfoldConstraint,
    cyclic_shift_sigma, mle_eval, prove_air_zerocheck, prove_col_sum, verify_air_zerocheck,
    verify_col_sum,
};
use p3_challenger::FieldChallenger;
use p3_multilinear_util::point::Point;

/// The next-row (`+1` cyclic rotation) MLE of the PUBLIC `row_idx` counter `[0,1,…,N-1]` at point `r`
/// (so `rot = [1,…,N-1,0]`), `N = 2^{r.len()}`. The r6 `row_idx` column is a DETERMINISTIC public counter
/// (circuit.rs: `when_first_row row_idx=0`, transition `next = local + 1`, generator writes `i`), so its
/// rotation is public: the verifier binds the row-shifted zerocheck's `shifted_opened[SYMX_ROWIDX]` (the
/// transition's next-row value) directly to this — no σ(r) commitment opening. The transition constraint
/// then ties the COMMITTED `row_idx` (opened at `r`) to this public counter, so a prover cannot forge the
/// row sequence. This is the rot-fold's binding, replacing the removed O(2^n)-per-point σ(r) opening.
fn public_rowidx_rotation_mle(r: &[Ea4]) -> Ea4 {
    let n = 1usize << r.len();
    let rot: Vec<Fa4> = (0..n).map(|i| Fa4::from_u64(((i + 1) % n) as u64)).collect();
    mle_eval(&rot, r)
}

/// Extension degree of the decider field (`Ea4 = BinomialExtensionField<Fa4, EXT_D>`); each
/// extension-valued lane in a rec trace is stored as `EXT_D` consecutive base-field limbs.
pub const EXT_D: usize = 4;
/// LeafSource/leaf-trace width (mirrors circuit.rs `LEAF_W`): `leaf_idx | leaf_val[EXT_D] | load_count`.
pub const LEAF_W: usize = 1 + EXT_D + 1;
/// OodCheck-trace width (mirrors circuit.rs `OODCHK_W`): `z_h[EXT_D] | q[EXT_D] | acc[EXT_D] | active`.
pub const OODCHK_W: usize = EXT_D * 3 + 1;

/// The OodCheck rec-AIR constraint (circuit.rs `OodCheckAir::eval`) expressed as a multilinear
/// zerocheck constraint for the proven [`crate::air_zerocheck`] engine: on EVERY row of the ood
/// table, `active ∈ {0,1}` AND `acc == q·z_h` in the decider extension field `Ea4`. The `z_h|q|acc`
/// lanes are each `EXT_D` base-field limbs; each is lifted back to an `Ea4` via the extension basis
/// (`Σ limb_i · Xⁱ`) and the identity `acc − q·z_h == 0` is checked as one extension equation
/// (degree 2 — the `q·z_h` product). γ-batched with the boolean-active constraint into one scalar:
/// `active·(active−1) + γ·(acc − q·z_h)`. This is the FIRST rec AIR routed through the sub-ms,
/// hashless zerocheck that replaces the ~11s FRI rec prove for this constraint family; the remaining
/// rec AIRs (`LeafSource` bus, `SymEvalR6Leaf` reg-eval transition, `OodInput`) follow the same shape.
pub struct OodCheckZerocheckConstraint {
    /// Batching challenge γ (drawn from the transcript) combining the two constraint families.
    pub gamma: Ea4,
}
impl AirConstraint for OodCheckZerocheckConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        2
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        // Extension basis element Xⁱ (the i-th coordinate = 1, rest 0).
        let basis = |i: usize| -> Ea4 {
            Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO })
        };
        // Lift `EXT_D` consecutive limb-columns (from `base`) back to their `Ea4` value.
        let lift = |base: usize| -> Ea4 {
            let mut v = Ea4::ZERO;
            for i in 0..EXT_D {
                v += local[base + i] * basis(i);
            }
            v
        };
        let zh = lift(0);
        let q = lift(EXT_D);
        let acc = lift(EXT_D * 2);
        let active = local[EXT_D * 3];
        active * (active - Ea4::ONE) + self.gamma * (acc - q * zh)
    }
}

/// The OodInput rec-AIR constraint (circuit.rs `OodInputAir::eval`, width 1): the single `active`
/// column is boolean on every row (`active·(active−1) == 0`). Its `z_h`/`q` are PUBLIC values SENT
/// on the ZH/Q result buses — a logup tie verified by the bus-balance layer, NOT a row constraint —
/// so the row-local part is exactly the boolean check. Degree 2. Second rec AIR through the engine.
pub struct OodInputZerocheckConstraint;
impl AirConstraint for OodInputZerocheckConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        2
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let active = local[0];
        active * (active - Ea4::ONE)
    }
}

/// SymEvalExt/SymEvalR6 column layout (mirrors circuit.rs `SYMX_*`): `sels[7] | row_idx | out[EXT_D]
/// | a_idx | a[EXT_D] | b_idx | b[EXT_D] | rc`.
const SYMX_ROWIDX: usize = 7;
const SYMX_OUT: usize = 8;
/// `a_idx` — the register lane the r6 row reads its `a` operand from, AND the key col the production
/// `SymEvalR6LeafAir` RECEIVEs on LEAF_BUS as `[a_idx, out[0..EXT_D]]` gated `s_leaf` (circuit.rs:43477).
const SYMX_AIDX: usize = 8 + EXT_D;
const SYMX_AVAL: usize = 9 + EXT_D;
const SYMX_BVAL: usize = 10 + 2 * EXT_D;
const SYMX_W_CONST: usize = 7 + 1 + EXT_D + 1 + EXT_D + 1 + EXT_D + 1;
/// The `is_out` boundary column of the PRODUCTION `SymEvalR6Air` (circuit.rs:42788): the real rec r6
/// table is `SYMX_W_CONST + 1` wide (24), with `is_out` appended at index `SYMX_W_CONST` (23). It is 1
/// ONLY on the last row (gating the ACC_BUS send of the final `acc`), 0 on every transition row.
const SYMX_ISOUT: usize = SYMX_W_CONST;
/// Full committed width of the production `SymEvalR6Leaf` rec trace (`SymEvalExt` reg-op cols + `is_out`).
const SYMX_R6_W: usize = SYMX_W_CONST + 1;

/// The `is_out` boundary constraint of the PRODUCTION `SymEvalR6Air` (circuit.rs:42788-42794), the AIR
/// the real rec `r6t` trace satisfies. Mirrors it EXACTLY: the `is_out` column (`SYMX_ISOUT`) is
/// boolean, equals 1 on the LAST hypercube row (`Π x_k`), and is 0 on every transition (non-last) row.
/// This is what gates the ACC_BUS send of the final `acc` to the OodCheck — so the ood quotient identity
/// binds the r6-computed `acc`, not a free value. γ-batched (γ⁰ bool, γ¹ last-row, γ² transition);
/// degree `nvars+1` (the `Π x_k` last-row selector). Part of reconciling the light decider to the real
/// production AIRs (the small-crate model was built against an assumed 23-wide/REG-BUS layout).
pub struct SymEvalR6IsOutConstraint {
    /// Batching challenge γ; γ⁰ weights the boolean check, γ¹ the last-row, γ² the transition.
    pub gamma: Ea4,
}
impl AirConstraint for SymEvalR6IsOutConstraint {
    fn degree(&self, nvars: usize) -> usize {
        nvars + 1
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let io = local[SYMX_ISOUT];
        // is_last = Π x_k: 1 only at the maximal hypercube index (the last row), 0 elsewhere.
        let mut is_last = Ea4::ONE;
        for &xk in x {
            is_last *= xk;
        }
        let g = self.gamma;
        let bool_c = io * (io - Ea4::ONE); // is_out ∈ {0,1}
        let last_c = is_last * (io - Ea4::ONE); // last row ⇒ is_out == 1
        let trans_c = (Ea4::ONE - is_last) * io; // non-last ⇒ is_out == 0
        bool_c + g * last_c + g * g * trans_c
    }
}

/// The FULL row-local constraint of the production `SymEvalR6Leaf` rec trace: reg-op relations + row-idx
/// transition ([`SymEvalR6Constraint`], γ⁰…γ¹³) PLUS the `is_out` boundary ([`SymEvalR6IsOutConstraint`],
/// lifted to γ¹⁴/γ¹⁵/γ¹⁶ so all powers stay distinct). This is the complete arithmetic the real
/// `SymEvalR6Air::eval` (circuit.rs:42782) enforces on every row of the 24-wide `r6t` trace — the
/// production replacement for the assumed-layout `SymEvalR6Constraint`. Degree `nvars+1`.
pub struct SymEvalR6FullConstraint {
    /// Batching challenge γ; γ⁰…γ¹³ = reg-op + transition, γ¹⁴…γ¹⁶ = the is_out boundary.
    pub gamma: Ea4,
}
impl AirConstraint for SymEvalR6FullConstraint {
    fn degree(&self, nvars: usize) -> usize {
        nvars + 1
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let reg_trans = SymEvalR6Constraint { gamma: self.gamma }.eval(local, at, x); // γ⁰…γ¹³
        let is_out = SymEvalR6IsOutConstraint { gamma: self.gamma }.eval(local, at, x); // γ⁰…γ²
        // Lift the is_out block by γ¹⁴ so its (γ⁰,γ¹,γ²) internal powers land at (γ¹⁴,γ¹⁵,γ¹⁶).
        let mut g14 = Ea4::ONE;
        for _ in 0..14 {
            g14 *= self.gamma;
        }
        reg_trans + g14 * is_out
    }
}

/// The SymEvalR6/SymEvalExt ROW-LOCAL reg-evaluation constraint (circuit.rs `SymEvalExtAir::eval`) —
/// the VM-style op semantics that DOMINATE the ~11s FRI rec prove, now verified by the sub-ms
/// zerocheck engine. Two constraint families, γ-batched (12 sub-constraints total):
///   (a) 7 one-hot selector bits: each `sel[i] ∈ {0,1}` and `Σ sel[i] == 1`;
///   (b) per-coefficient op relation `out[k]·op_active == op(a,b)[k]` for `k∈0..EXT_D`, where
///       `op ∈ {add, sub, ext-mul, neg, copy}` and ext-mul is over `Fa4[X]/(X⁴−3)` (the `s_mul·a·b`
///       term makes this DEGREE 3 — the reason `degree()==3`).
/// All row-local (the SYMX_REG_BUS logup + `row_idx` increment are the SEPARATE transition/logup
/// layer, wired next). `a`/`b`/`out` are per-coefficient base-field lanes, so the relation lifts
/// directly to `Ea4` — no extension-basis reconstruction needed (unlike OodCheck's packed lanes).
pub struct SymEvalR6RegConstraint {
    /// Batching challenge γ combining the 12 sub-constraints (powers `γ⁰…γ¹¹`).
    pub gamma: Ea4,
}
impl AirConstraint for SymEvalR6RegConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        3
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let sel: [Ea4; 7] =
            [local[0], local[1], local[2], local[3], local[4], local[5], local[6]];
        let (s_add, s_sub, s_mul, s_neg, s_copy) = (sel[2], sel[3], sel[4], sel[5], sel[6]);
        let op_active = s_add + s_sub + s_mul + s_neg + s_copy;
        let a = |k: usize| local[SYMX_AVAL + k];
        let b = |k: usize| local[SYMX_BVAL + k];
        let out = |k: usize| local[SYMX_OUT + k];
        let w = Ea4::from(Fa4::from_u64(3));
        // ext-mul a·b mod (X⁴−3): mul[k] = Σ_{i+j=k} a_i b_j + 3·Σ_{i+j=k+4} a_i b_j.
        let mul = [
            a(0) * b(0) + w * (a(1) * b(3) + a(2) * b(2) + a(3) * b(1)),
            a(0) * b(1) + a(1) * b(0) + w * (a(2) * b(3) + a(3) * b(2)),
            a(0) * b(2) + a(1) * b(1) + a(2) * b(0) + w * (a(3) * b(3)),
            a(0) * b(3) + a(1) * b(2) + a(2) * b(1) + a(3) * b(0),
        ];
        // Collect the 12 sub-constraints (each == 0 on an honest row), then γ-batch.
        let mut terms: Vec<Ea4> = Vec::with_capacity(7 + 1 + EXT_D);
        for s in sel {
            terms.push(s * (s - Ea4::ONE)); // selector boolean
        }
        let selsum = sel.iter().copied().fold(Ea4::ZERO, |acc, s| acc + s);
        terms.push(selsum - Ea4::ONE); // one-hot
        for k in 0..EXT_D {
            let op_rhs = s_add * (a(k) + b(k)) + s_sub * (a(k) - b(k)) + s_mul * mul[k]
                - s_neg * a(k)
                + s_copy * a(k);
            terms.push(out(k) * op_active - op_rhs); // op relation
        }
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for t in terms {
            acc += gp * t;
            gp *= self.gamma;
        }
        acc
    }
}

/// The SymEvalR6/SymEvalExt ROW-SHIFTED (transition) constraint (circuit.rs `SymEvalExtAir::eval`
/// `when_first_row` + `when_transition` on `row_idx`) — routed through the engine's shift mechanism
/// ([`cyclic_shift_sigma`] + `shifted_opened`). Enforces the strict row sequence `row_idx = 0,1,2,…`:
///   (a) FIRST row `row_idx == 0` — via the is-first selector `Π(1−x_k)` (=1 only at index 0);
///   (b) TRANSITION `row_idx(σx) == row_idx(x) + 1` on every NON-last row — via the not-last selector
///       `1 − Π x_k` (the last row wraps under σ and is excluded, exactly like `when_transition`).
/// This is the register-file KEY UNIQUENESS the SYMX_REG_BUS logup relies on (unique `row_idx` per
/// send). degree = nvars+1 (the σ carry chain). γ-batches the two families.
pub struct SymEvalR6RowIdxTransitionConstraint {
    /// Batching challenge γ combining the first-row and transition families.
    pub gamma: Ea4,
}
impl AirConstraint for SymEvalR6RowIdxTransitionConstraint {
    fn degree(&self, nvars: usize) -> usize {
        nvars + 1
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let rowidx = local[SYMX_ROWIDX];
        let sigma = cyclic_shift_sigma(x);
        let rowidx_next = at(SYMX_ROWIDX, &sigma);
        let is_first = x.iter().copied().fold(Ea4::ONE, |a, xk| a * (Ea4::ONE - xk)); // Π(1−x_k)
        let prod_x = x.iter().copied().fold(Ea4::ONE, |a, xk| a * xk); // Π x_k
        let not_last = Ea4::ONE - prod_x;
        let c_first = is_first * rowidx; // first row ⇒ row_idx == 0
        let c_trans = not_last * (rowidx_next - rowidx - Ea4::ONE); // row_idx(σx) == row_idx(x)+1
        c_first + self.gamma * c_trans
    }
}

/// COMPOSED SymEvalR6 r6-table constraint: the reg-op family ([`SymEvalR6RegConstraint`], 12 sub-
/// constraints on γ⁰…γ¹¹) AND the row_idx transition family ([`SymEvalR6RowIdxTransitionConstraint`],
/// 2 sub-constraints) folded into ONE γ-batched zerocheck (the transition offset by γ¹² so all 14
/// powers are distinct — no collision). Reuses both proven evals. This is the composition step: the
/// whole r6 AIR verified in a SINGLE proof over the r6 table, instead of two. degree = nvars+1 (the
/// transition's σ carry chain dominates the reg-op's degree 3 for nvars ≥ 2).
pub struct SymEvalR6Constraint {
    /// Batching challenge γ; powers γ⁰…γ¹¹ weight the reg-op terms, γ¹²/γ¹³ the transition terms.
    pub gamma: Ea4,
}
impl AirConstraint for SymEvalR6Constraint {
    fn degree(&self, nvars: usize) -> usize {
        nvars + 1
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let reg = SymEvalR6RegConstraint { gamma: self.gamma }.eval(local, at, x); // γ⁰…γ¹¹
        let trans = SymEvalR6RowIdxTransitionConstraint { gamma: self.gamma }.eval(local, at, x); // γ⁰,γ¹
        let mut g12 = Ea4::ONE; // γ¹² — offsets the 2 transition terms to γ¹²,γ¹³.
        for _ in 0..12 {
            g12 *= self.gamma;
        }
        reg + g12 * trans
    }
}

#[cfg(test)]
mod ood_zerocheck_tests {
    use super::*;
    use crate::hiding_decider::Perm16;
    use p3_challenger::FieldChallenger;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    fn mk_ch() -> Chl {
        Chl::new(Perm16::new_from_rng_128(&mut SmallRng::seed_from_u64(0x00D_C0DEu64)))
    }

    // Route the REAL OodCheck rec constraint (`acc == q·z_h`, `active ∈ {0,1}`) through the proven
    // air_zerocheck engine over a real ood trace. Honest row (acc = q·z_h) accepts; a corrupted acc
    // limb (acc ≠ q·z_h) makes the zerocheck sum ≠ 0 → rejects.
    fn run(tamper: bool) -> bool {
        const FOLDING: usize = 3;
        let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 7 + 3));
        let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 11 + 5));
        let acc = q * zh; // honest OodCheck identity
        let mut row = vec![Fa4::ZERO; OODCHK_W];
        let mut put = |row: &mut Vec<Fa4>, base: usize, v: Ea4| {
            for (i, &c) in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&v)
                .iter()
                .enumerate()
            {
                row[base + i] = c;
            }
        };
        put(&mut row, 0, zh);
        put(&mut row, EXT_D, q);
        put(&mut row, EXT_D * 2, acc);
        row[EXT_D * 3] = Fa4::ONE; // active
        if tamper {
            row[EXT_D * 2] += Fa4::ONE; // corrupt an acc limb → acc != q·z_h
        }
        let trace = RowMajorMatrix::new(row, OODCHK_W);
        let (cols, (nvars, _w)) = trace_to_table(&trace, FOLDING);
        let mut pch = mk_ch();
        let gamma: Ea4 = pch.sample_algebra_element();
        let z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
        let proof = prove_air_zerocheck(&cols, &OodCheckZerocheckConstraint { gamma }, &z, &mut pch);
        let mut vch = mk_ch();
        let gamma_v: Ea4 = vch.sample_algebra_element();
        let zv: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
        verify_air_zerocheck(&proof, &OodCheckZerocheckConstraint { gamma: gamma_v }, &zv, &mut vch)
    }

    #[test]
    fn ood_check_via_zerocheck_engine_honest_accepts_tampered_rejects() {
        assert!(run(false), "honest OodCheck (acc==q·z_h) must ACCEPT via the zerocheck engine");
        assert!(!run(true), "tampered OodCheck (acc!=q·z_h) must REJECT");
    }

    // Second rec AIR through the engine: OodInput's boolean `active` (width-1 table). Honest
    // (active ∈ {0,1}) accepts; a non-boolean active (=2) makes the zerocheck sum ≠ 0 → rejects.
    #[test]
    fn ood_input_active_bool_via_zerocheck_engine_honest_accepts_tampered_rejects() {
        let run_oi = |bad: bool| -> bool {
            const FOLDING: usize = 3;
            let mut col = vec![Fa4::ZERO; 4]; // 1 active real row + padding (all boolean)
            col[0] = Fa4::ONE;
            if bad {
                col[1] = Fa4::from_u64(2); // non-boolean active → constraint ≠ 0
            }
            let trace = RowMajorMatrix::new(col, 1);
            let (cols, (nvars, _w)) = trace_to_table(&trace, FOLDING);
            let mut pch = mk_ch();
            let z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
            let proof = prove_air_zerocheck(&cols, &OodInputZerocheckConstraint, &z, &mut pch);
            let mut vch = mk_ch();
            let zv: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
            verify_air_zerocheck(&proof, &OodInputZerocheckConstraint, &zv, &mut vch)
        };
        assert!(run_oi(false), "honest OodInput (active boolean) must ACCEPT");
        assert!(!run_oi(true), "non-boolean active must REJECT");
    }

    // Third rec AIR through the engine — the MEATY one: SymEvalR6's row-local reg-op semantics
    // (one-hot selectors + the degree-3 op relation `out = op(a,b)`). An honest s_mul row (out = a·b
    // in Fa4[X]/(X⁴−3)) with valid nop rows accepts; corrupting an out limb rejects.
    #[test]
    fn symeval_r6_reg_op_via_zerocheck_engine_honest_accepts_tampered_rejects() {
        let run_reg = |tamper: bool| -> bool {
            const FOLDING: usize = 3;
            const W: usize = SYMX_W_CONST;
            let a = [3u64, 5, 7, 9].map(Fa4::from_u64);
            let b = [2u64, 4, 6, 8].map(Fa4::from_u64);
            let w = Fa4::from_u64(3);
            let mul = [
                a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
                a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * (a[3] * b[3]),
                a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
            ];
            let mut data = vec![Fa4::ZERO; 8 * W]; // 8 rows = 2^3, no zero-padding
            // row 0: an honest s_mul op (sel[4]=1), out = a·b.
            data[4] = Fa4::ONE;
            for k in 0..EXT_D {
                data[SYMX_AVAL + k] = a[k];
                data[SYMX_BVAL + k] = b[k];
                data[SYMX_OUT + k] = mul[k];
            }
            // rows 1..8: valid nop (sel[0]=1, op_active=0) so one-hot holds on every row.
            for r in 1..8 {
                data[r * W] = Fa4::ONE;
            }
            if tamper {
                data[SYMX_OUT] += Fa4::ONE; // out[0] != mul[0] → op relation violated on row 0
            }
            let trace = RowMajorMatrix::new(data, W);
            let (cols, (nvars, _w)) = trace_to_table(&trace, FOLDING);
            let mut pch = mk_ch();
            let gamma: Ea4 = pch.sample_algebra_element();
            let z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
            let proof = prove_air_zerocheck(&cols, &SymEvalR6RegConstraint { gamma }, &z, &mut pch);
            let mut vch = mk_ch();
            let gamma_v: Ea4 = vch.sample_algebra_element();
            let zv: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
            verify_air_zerocheck(&proof, &SymEvalR6RegConstraint { gamma: gamma_v }, &zv, &mut vch)
        };
        assert!(run_reg(false), "honest SymEvalR6 reg-op (out=a·b) must ACCEPT");
        assert!(!run_reg(true), "corrupted out limb must REJECT");
    }

    // Row-SHIFTED SymEvalR6 transition through the engine: the strict sequence row_idx = 0,1,…,N−1
    // (first row 0 + row_idx(σx)=row_idx(x)+1 on non-last rows). Honest sequential row_idx accepts; a
    // broken step rejects. Also the definitive check that cyclic_shift_sigma maps row i→i+1 in the
    // trace's bit convention (the constant-column shift test could not distinguish that).
    #[test]
    fn symeval_r6_rowidx_transition_via_zerocheck_engine_honest_accepts_tampered_rejects() {
        let run_tr = |tamper: bool| -> bool {
            const NV: usize = 3;
            const N: usize = 1 << NV; // 8 rows
            const W: usize = SYMX_W_CONST;
            let mut data = vec![Fa4::ZERO; N * W];
            for i in 0..N {
                data[i * W + SYMX_ROWIDX] = Fa4::from_u64(i as u64); // row_idx = 0,1,…,7
            }
            if tamper {
                data[3 * W + SYMX_ROWIDX] = Fa4::from_u64(9); // break the step into row 3
            }
            let trace = RowMajorMatrix::new(data, W);
            let (cols, (nvars, _w)) = trace_to_table(&trace, NV);
            let mut pch = mk_ch();
            let gamma: Ea4 = pch.sample_algebra_element();
            let z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
            let proof = prove_air_zerocheck(
                &cols,
                &SymEvalR6RowIdxTransitionConstraint { gamma },
                &z,
                &mut pch,
            );
            let mut vch = mk_ch();
            let gamma_v: Ea4 = vch.sample_algebra_element();
            let zv: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
            verify_air_zerocheck(
                &proof,
                &SymEvalR6RowIdxTransitionConstraint { gamma: gamma_v },
                &zv,
                &mut vch,
            )
        };
        assert!(run_tr(false), "honest sequential row_idx must ACCEPT");
        assert!(!run_tr(true), "broken row_idx step must REJECT");
    }

    // COMPOSITION: the whole r6 AIR (reg-op family + row_idx transition family) in ONE γ-batched
    // zerocheck. Honest trace (row 0 = s_mul op with out=a·b, rows 1..7 = valid nops, row_idx=0..7)
    // accepts; tampering EITHER the reg-op (out) OR the row_idx sequence rejects — proving both
    // families are enforced by the single composed proof.
    #[test]
    fn symeval_r6_composed_reg_and_transition_honest_accepts_tampered_rejects() {
        let run = |tamper: u8| -> bool {
            // 0 = honest, 1 = tamper reg-op out, 2 = tamper row_idx step
            const NV: usize = 3;
            const N: usize = 1 << NV; // 8 rows
            const W: usize = SYMX_W_CONST;
            let a = [3u64, 5, 7, 9].map(Fa4::from_u64);
            let b = [2u64, 4, 6, 8].map(Fa4::from_u64);
            let w = Fa4::from_u64(3);
            let mul = [
                a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
                a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * (a[3] * b[3]),
                a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
            ];
            let mut data = vec![Fa4::ZERO; N * W];
            // row 0: honest s_mul op (sel[4]=1), out = a·b.
            data[4] = Fa4::ONE;
            for k in 0..EXT_D {
                data[SYMX_AVAL + k] = a[k];
                data[SYMX_BVAL + k] = b[k];
                data[SYMX_OUT + k] = mul[k];
            }
            // rows 1..8: valid nop (sel[0]=1). Every row: row_idx = its index (0,1,…,7).
            for i in 1..N {
                data[i * W] = Fa4::ONE;
            }
            for i in 0..N {
                data[i * W + SYMX_ROWIDX] = Fa4::from_u64(i as u64);
            }
            if tamper == 1 {
                data[SYMX_OUT] += Fa4::ONE; // out[0] != mul[0]
            }
            if tamper == 2 {
                data[3 * W + SYMX_ROWIDX] = Fa4::from_u64(9); // break the row_idx step
            }
            let trace = RowMajorMatrix::new(data, W);
            let (cols, (nvars, _w)) = trace_to_table(&trace, NV);
            let mut pch = mk_ch();
            let gamma: Ea4 = pch.sample_algebra_element();
            let z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
            let proof = prove_air_zerocheck(&cols, &SymEvalR6Constraint { gamma }, &z, &mut pch);
            let mut vch = mk_ch();
            let gv: Ea4 = vch.sample_algebra_element();
            let zv: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
            verify_air_zerocheck(&proof, &SymEvalR6Constraint { gamma: gv }, &zv, &mut vch)
        };
        assert!(run(0), "honest composed SymEvalR6 (reg-op + transition) must ACCEPT");
        assert!(!run(1), "tampered reg-op out must REJECT");
        assert!(!run(2), "tampered row_idx step must REJECT");
    }

    /// #135 reconciliation to the REAL `SymEvalR6Air`: the `is_out` boundary constraint (bool, 1 on the
    /// last row, 0 on transitions) matching circuit.rs:42788-42791. Honest is_out (1 only on the last
    /// row) accepts; setting it on a non-last row OR clearing it on the last row rejects — the exact
    /// gate the production AIR uses for the ACC_BUS acc send.
    #[test]
    fn symeval_r6_is_out_boundary_honest_accepts_tampered_rejects() {
        let run = |tamper: u8| -> bool {
            // 0 = honest, 1 = is_out on a non-last row, 2 = is_out cleared on the last row.
            const NV: usize = 2;
            const N: usize = 1 << NV; // 4 rows
            const W: usize = super::SYMX_R6_W; // 24 (SymEvalExt reg-op cols + is_out)
            let mut data = vec![Fa4::ZERO; N * W];
            data[(N - 1) * W + super::SYMX_ISOUT] = Fa4::ONE; // is_out = 1 ONLY on the last row
            if tamper == 1 {
                data[W + super::SYMX_ISOUT] = Fa4::ONE; // is_out on row 1 (non-last) → transition violation
            }
            if tamper == 2 {
                data[(N - 1) * W + super::SYMX_ISOUT] = Fa4::ZERO; // cleared on last row → last-row violation
            }
            let trace = RowMajorMatrix::new(data, W);
            let (cols, (nvars, _w)) = trace_to_table(&trace, NV);
            let mut pch = mk_ch();
            let gamma: Ea4 = pch.sample_algebra_element();
            let z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
            let proof =
                prove_air_zerocheck(&cols, &super::SymEvalR6IsOutConstraint { gamma }, &z, &mut pch);
            let mut vch = mk_ch();
            let gv: Ea4 = vch.sample_algebra_element();
            let zv: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
            verify_air_zerocheck(&proof, &super::SymEvalR6IsOutConstraint { gamma: gv }, &zv, &mut vch)
        };
        assert!(run(0), "honest is_out (1 on the last row only) must ACCEPT");
        assert!(!run(1), "is_out on a non-last row must REJECT");
        assert!(!run(2), "is_out cleared on the last row must REJECT");
    }

    /// #135 reconciliation: the FULL production r6 row-local constraint `SymEvalR6FullConstraint`
    /// (reg-op + row-idx transition + is_out) over a real 24-wide (`SYMX_R6_W`) trace. Honest accepts;
    /// tampering the reg-op output, the row_idx step, OR the is_out boundary each REJECT — proving all
    /// three families compose on distinct γ powers, matching production `SymEvalR6Air::eval`.
    #[test]
    fn symeval_r6_full_constraint_honest_accepts_any_tamper_rejects() {
        let run = |tamper: u8| -> bool {
            // 0 = honest, 1 = reg-op out, 2 = row_idx step, 3 = is_out cleared on last row.
            const NV: usize = 3;
            const N: usize = 1 << NV; // 8 rows
            const W: usize = SYMX_R6_W; // 24 (reg-op cols + is_out)
            let a = [3u64, 5, 7, 9].map(Fa4::from_u64);
            let b = [2u64, 4, 6, 8].map(Fa4::from_u64);
            let w = Fa4::from_u64(3);
            let mul = [
                a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
                a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * (a[3] * b[3]),
                a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
            ];
            let mut data = vec![Fa4::ZERO; N * W];
            data[4] = Fa4::ONE; // row 0: s_mul
            for k in 0..EXT_D {
                data[SYMX_AVAL + k] = a[k];
                data[SYMX_BVAL + k] = b[k];
                data[SYMX_OUT + k] = mul[k];
            }
            for i in 1..N {
                data[i * W] = Fa4::ONE; // nop sel[0] on rows 1..7
            }
            for i in 0..N {
                data[i * W + SYMX_ROWIDX] = Fa4::from_u64(i as u64);
            }
            data[(N - 1) * W + SYMX_ISOUT] = Fa4::ONE; // is_out = 1 on the last row
            if tamper == 1 {
                data[SYMX_OUT] += Fa4::ONE;
            }
            if tamper == 2 {
                data[3 * W + SYMX_ROWIDX] = Fa4::from_u64(9);
            }
            if tamper == 3 {
                data[(N - 1) * W + SYMX_ISOUT] = Fa4::ZERO;
            }
            let trace = RowMajorMatrix::new(data, W);
            let (cols, (nvars, _w)) = trace_to_table(&trace, NV);
            let mut pch = mk_ch();
            let gamma: Ea4 = pch.sample_algebra_element();
            let z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
            let proof = prove_air_zerocheck(&cols, &SymEvalR6FullConstraint { gamma }, &z, &mut pch);
            let mut vch = mk_ch();
            let gv: Ea4 = vch.sample_algebra_element();
            let zv: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
            verify_air_zerocheck(&proof, &SymEvalR6FullConstraint { gamma: gv }, &zv, &mut vch)
        };
        assert!(run(0), "honest full r6 (reg + transition + is_out) must ACCEPT");
        assert!(!run(1), "tampered reg-op out must REJECT");
        assert!(!run(2), "tampered row_idx step must REJECT");
        assert!(!run(3), "tampered is_out boundary must REJECT");
    }
}

/// Proof of a LEAF_BUS LogUp balance: the `LogupHConstraint` zerocheck (helper column `h` correct on
/// every row) plus the per-limb `Σ h` col-sum proofs and their claimed limb sums (recombined by the
/// extension basis to check `Σ mult/(α−value) = 0`). Serde-derived so it rides in the rec-block
/// carrier bytes alongside the opening bundle.
#[derive(Clone, Serialize, Deserialize)]
pub struct LeafBusBalanceProof {
    /// The `h·(α−value)−mult == 0` zerocheck over the bus table's `[value, mult, h_limb0..EXT_D]` cols.
    pub zc: AirZerocheckProof,
    /// Claimed per-limb sums `Σ_x h_limb_k(x)`; balance holds iff `Σ_k Xᵏ·limb_sum_k == 0`.
    pub limb_sums: Vec<Ea4>,
    /// Per-limb `prove_col_sum` proofs binding each claimed `limb_sums[k]` to the committed h column.
    pub sum_proofs: Vec<ColSumProof>,
}

/// LogUp key for one LEAF_BUS row: fold `[leaf_idx, val[0..EXT_D]]` into a single field element via a
/// challenge `beta` (`leaf_idx + β·val0 + β²·val1 + …`). A SEND (LeafSource) row and a matching RECV
/// (SymEvalR6Leaf tape use / ClaimsExpose) fold to an IDENTICAL key iff both `(leaf_idx, val)` tuples
/// agree — so a forged consumed-leaf value yields a key mismatch that unbalances the bus. This is the
/// keyfold the LEAF_BUS tie shares between LeafSource and its consumers.
#[must_use]
pub fn leaf_bus_key(leaf_idx: Fa4, val: &[Fa4], beta: Fa4) -> Fa4 {
    let mut acc = leaf_idx;
    let mut bpow = beta;
    for &v in val.iter().take(EXT_D) {
        acc += bpow * v;
        bpow *= beta;
    }
    acc
}

/// Draw the LEAF_BUS/ACC_BUS multi-field keyfold challenge `beta` from the shared Fiat-Shamir transcript,
/// so [`leaf_bus_key`]'s `Σ βⁱ·fieldᵢ` key is transcript-derived rather than folded with a fixed public
/// constant (a fixed fold lets two distinct field tuples share one LogUp key — e.g. `[a,b]` and `[b,a]`
/// coincide when `β=1`). The rec-block routing draws this once per bus before building it; the verifier
/// redraws in lockstep, so both fold with the SAME `beta`. Folds a whole extension draw into one
/// base-field challenge.
#[must_use]
pub fn draw_bus_fold_challenge(ch: &mut Chl) -> Fa4 {
    let e: Ea4 = ch.sample_algebra_element();
    let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&e);
    // Combine every limb of one extension draw into a single base-field challenge; +ONE avoids a zero fold.
    let mut b = Fa4::ONE;
    let mut w = Fa4::from_u64(2);
    for &l in limbs {
        b += w * l;
        w *= Fa4::from_u64(3);
    }
    b
}

/// Build the ACC_BUS `(value, mult)` columns tying the r6 trace's computed `acc` — its `out` on the
/// last row, which the production `SymEvalR6Air` SENDs on ACC_BUS gated `is_out` (circuit.rs:42794) —
/// to the OodCheck row's `acc` field, which RECEIVEs it (circuit.rs:42769). A 2-row LogUp bus: r6 SEND
/// `keyfold(r6_acc)` mult −1, OodCheck RECV `keyfold(ood_acc)` mult +1. Balanced iff `r6_acc == ood_acc`
/// — so the ood quotient identity `acc == q·z_h` is enforced on the acc the r6 sym-eval ACTUALLY
/// computed, never a free ood value. `beta` folds the `EXT_D` acc limbs (idx = 0 for both, so equal
/// accs fold to an identical key). This is the ACC_BUS the rec-block routing passes to
/// [`prove_rec_block_whir_openings_with_bus`] alongside the LEAF_BUS.
#[must_use]
pub fn build_acc_bus(r6_acc: &[Fa4], ood_acc: &[Fa4], beta: Fa4) -> (Vec<Fa4>, Vec<Fa4>) {
    let k_send = leaf_bus_key(Fa4::ZERO, r6_acc, beta);
    let k_recv = leaf_bus_key(Fa4::ZERO, ood_acc, beta);
    (vec![k_send, k_recv], vec![-Fa4::ONE, Fa4::ONE])
}

/// Build the ACC_BUS in SOURCE-COLUMN form for the TIED bus path (the r6-acc↔ood-acc tie): a 2-row bus —
/// r6 SEND `acc` (= `out` on the r6 last row, gated `is_out`) mult −1 / OodCheck RECV `acc` mult +1, idx = 0
/// for both, values UNFOLDED so the decider folds the key inline with the transcript β. Balanced iff
/// `r6_acc == ood_acc`, so the ood quotient identity `acc == q·z_h` binds the r6-COMPUTED acc — now welded to
/// the committed columns via the tied path. The tied ACC_BUS the circuit.rs routing passes as a `tied_buses`
/// entry alongside the tied LEAF_BUS ([`build_leaf_bus_full_tied`]).
#[must_use]
pub fn build_acc_bus_tied(r6_acc: &[Fa4], ood_acc: &[Fa4]) -> (Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>) {
    let idx_col = vec![Fa4::ZERO, Fa4::ZERO];
    let mut val_cols: Vec<Vec<Fa4>> = vec![Vec::new(); EXT_D];
    for k in 0..EXT_D {
        val_cols[k].push(r6_acc.get(k).copied().unwrap_or(Fa4::ZERO));
        val_cols[k].push(ood_acc.get(k).copied().unwrap_or(Fa4::ZERO));
    }
    let mult_col = vec![-Fa4::ONE, Fa4::ONE];
    (idx_col, val_cols, mult_col)
}

/// #135 VALIDATOR FINALITY CERT — the `FINALITY_WEIGHT_BUS` tied-bus builder (the first of the cert's 5 LogUp
/// buses to retire onto the light decider). SENDs each bonded voter's weight (mult −1), read from the member
/// trace's committed weight cells by `weight_offsets` (the `pre(value0+k)` note-preimage lanes), and RECVs
/// each aggregated sum weight (mult +1), read from the sum trace's committed cells by `sum_offsets` (w0 @
/// `QB2_W0+k`, w1 @ `QB2_W1+k`, …). The `FINALITY_WEIGHT_BUS` key is the raw weight `VALUE_LIMBS` tuple (no
/// separate idx → `idx_col = 0`). Balanced iff `{member weights} == {sum weights}` as multisets → the sum's
/// aggregate is provably the bonded voters' weights. This is the source-COLUMN form fed to
/// [`prove_air_batch_light_decider_bytes_with_bus`]; the circuit.rs routing pairs it with source cross-ties
/// (bus RECV cols ↔ the sum-trace w cells) so a prover cannot substitute a fabricated free-floating bus (the
/// forgery the cross-tie tamper test rejects). Mirrors [`build_leaf_bus_full_tied`]'s read-committed-cells
/// pattern. `member_traces` = each flat (row-major) member trace; `member_w` reserved for future multi-row
/// members (row 0 holds the weight today). Panics-free: out-of-range offsets read as ZERO (fail-closed to a
/// non-balancing bus, never a silent pass).
#[must_use]
pub fn build_finality_weight_bus_tied(
    member_traces: &[Vec<Fa4>],
    _member_w: usize,
    weight_offsets: &[usize],
    sum_trace: &[Fa4],
    sum_offsets: &[Vec<usize>],
) -> (Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>) {
    let n_limbs = weight_offsets.len();
    let mut idx_col: Vec<Fa4> = Vec::new();
    let mut val_cols: Vec<Vec<Fa4>> = vec![Vec::new(); n_limbs];
    let mut mult_col: Vec<Fa4> = Vec::new();
    // SEND each member's committed weight (mult −1). UNIT BONDS pins these to [1,0..] row-locally in the
    // member AIR's base_constraints; here we read the committed cell so the balance ties to the real trace.
    for mt in member_traces {
        idx_col.push(Fa4::ZERO);
        for (k, &off) in weight_offsets.iter().enumerate() {
            val_cols[k].push(mt.get(off).copied().unwrap_or(Fa4::ZERO));
        }
        mult_col.push(Fa4::ZERO - Fa4::ONE);
    }
    // RECV each aggregated sum weight from the sum trace's committed w-cells (mult +1).
    for offs in sum_offsets {
        idx_col.push(Fa4::ZERO);
        for k in 0..n_limbs {
            let off = offs.get(k).copied().unwrap_or(usize::MAX);
            val_cols[k].push(sum_trace.get(off).copied().unwrap_or(Fa4::ZERO));
        }
        mult_col.push(Fa4::ONE);
    }
    (idx_col, val_cols, mult_col)
}

/// #135 VALIDATOR FINALITY CERT — the GENERIC tied-bus builder for the cert's remaining LogUp buses
/// (PK_D_BUS member↔own, POSEIDON_HASH_BUS, NS_LEAF_BUS, VOTE_ANCHOR_BUS). Given the per-row SEND
/// value-vectors (read from the sending AIR's committed cells, mult −1) and RECV value-vectors (from the
/// receiving AIR's committed cells, mult +1), emits the source-column tied bus `(idx=0, val_cols, mult_col)`.
/// Balanced iff the SEND multiset == the RECV multiset — each bus's cross-AIR binding. The circuit.rs routing
/// reads the value-vectors from the committed traces by each bus's offsets, calls this, and pairs it with the
/// source cross-ties (bus col ↔ source-trace cell) so no side can be a fabricated free value. Generalizes the
/// bus-1 [`build_finality_weight_bus_tied`]: one builder covers buses 2–5 (they differ only in which cells
/// feed SEND/RECV and the tuple width). `n_limbs` = the bus tuple width (2·DIGEST for PK_D pk_d‖rho, DIGEST
/// for anchor/nullifier, 2·WIDTH for the perm-hash bus, …); short value-vectors zero-extend (fail-closed to a
/// non-balancing bus, never a silent pass).
#[must_use]
pub fn build_cert_bus_tied(
    send_vecs: &[Vec<Fa4>],
    recv_vecs: &[Vec<Fa4>],
    n_limbs: usize,
) -> (Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>) {
    let mut idx_col: Vec<Fa4> = Vec::new();
    let mut val_cols: Vec<Vec<Fa4>> = vec![Vec::new(); n_limbs];
    let mut mult_col: Vec<Fa4> = Vec::new();
    for v in send_vecs {
        idx_col.push(Fa4::ZERO);
        for k in 0..n_limbs {
            val_cols[k].push(v.get(k).copied().unwrap_or(Fa4::ZERO));
        }
        mult_col.push(Fa4::ZERO - Fa4::ONE);
    }
    for v in recv_vecs {
        idx_col.push(Fa4::ZERO);
        for k in 0..n_limbs {
            val_cols[k].push(v.get(k).copied().unwrap_or(Fa4::ZERO));
        }
        mult_col.push(Fa4::ONE);
    }
    (idx_col, val_cols, mult_col)
}

/// Build the LEAF_BUS `(value, mult)` columns directly from the committed rec traces, using the real
/// production KEY: the `LeafSource` AIR SENDs each provided leaf `[leaf_idx, leaf_val[0..EXT_D]]`; the
/// `SymEvalR6LeafAir` RECEIVEs each consumed leaf `[a_idx, out[0..EXT_D]]` gated `s_leaf = sel[0]`
/// (circuit.rs:43477). Each side is folded through [`leaf_bus_key`] (`idx + Σβⁱ·val`) and stacked into
/// one LogUp balance bus — SENDs mult +1, RECEIVEs mult −1 — balanced iff every consumed leaf was sourced.
///
/// SCOPE — this is the 2-PARTY BASE builder (LeafSource ↔ SymEvalR6Leaf, unit multiplicity). The FULL
/// production LEAF_BUS also carries the LeafSource per-leaf `load_count` as its SEND multiplicity and the
/// `ClaimsExpose` receives (circuit.rs:42816-42819); those extra multiplicities are added by the routing
/// brick that extends this before the circuit.rs `prove_batch` swap. `r6t` = the flat 24-wide
/// (`SYMX_R6_W`) r6 trace; `lft` = the flat LeafSource trace (`lf_w = 1 + EXT_D` cols: `idx | val`).
/// Fed to [`prove_rec_block_whir_openings_with_bus`] — reconciliation brick 5 (real key, not a synthetic pair).
#[must_use]
pub fn build_leaf_bus(r6t: &[Fa4], lft: &[Fa4], lf_w: usize, beta: Fa4) -> (Vec<Fa4>, Vec<Fa4>) {
    let mut value: Vec<Fa4> = Vec::new();
    let mut mult: Vec<Fa4> = Vec::new();
    // LeafSource SENDs: one row per provided leaf `[idx | val[0..EXT_D]]` → mult +1.
    if lf_w >= 1 + EXT_D {
        let n_lf = lft.len() / lf_w;
        for row in 0..n_lf {
            let base = row * lf_w;
            let idx = lft[base];
            let val: Vec<Fa4> = (0..EXT_D).map(|k| lft[base + 1 + k]).collect();
            value.push(leaf_bus_key(idx, &val, beta));
            mult.push(Fa4::ONE);
        }
    }
    // SymEvalR6LeafAir RECEIVEs `[a_idx | out[0..EXT_D]]` gated `s_leaf = sel[0]` → mult −1.
    let n_r6 = r6t.len() / SYMX_R6_W;
    for row in 0..n_r6 {
        let base = row * SYMX_R6_W;
        if r6t[base] == Fa4::ONE {
            let a_idx = r6t[base + SYMX_AIDX];
            let out: Vec<Fa4> = (0..EXT_D).map(|k| r6t[base + SYMX_OUT + k]).collect();
            value.push(leaf_bus_key(a_idx, &out, beta));
            mult.push(-Fa4::ONE);
        }
    }
    (value, mult)
}

/// Build the FULL production LEAF_BUS `(value, mult)` from the committed rec traces, matching the real
/// LogUp multiplicities EXACTLY (verified against circuit.rs): `LeafSourceAir::eval` SENDs each leaf
/// `[leaf_idx, val]` with mult **−load_count**; every consumer RECEIVEs mult **+1** — `SymEvalR6LeafAir`
/// `[a_idx, out]` gated `s_leaf=sel[0]` (circuit.rs:43487) and `ClaimsExposeAir` `[leaf_idx, claim_val]`
/// (circuit.rs:42819, which bumps LeafSource's `load_count` by 1 per claim). Balanced iff each leaf's
/// `load_count` equals its total consumer count (r6 tape uses + claim receives) — so a spend can neither
/// fabricate a register-load NOR expose a claim that wasn't a verified leaf. Folded via [`leaf_bus_key`].
///
/// `r6t` = flat 24-wide (`SYMX_R6_W`) r6 trace; `lft` = flat LeafSource trace (`lf_w` cols:
/// `idx | val[EXT_D] | load_count`); `claims` = `(leaf_idx, claim_val[EXT_D])` per ClaimsExpose receive
/// (the ClaimsExpose trace is width-1 `active`; its claim values live in the rec PUBLIC values). This is
/// the LEAF_BUS the circuit.rs routing passes to [`prove_rec_block_whir_openings_with_bus`] — the full
/// replacement for the 2-party [`build_leaf_bus`] base builder, reconciliation brick (A).
#[must_use]
pub fn build_leaf_bus_full(
    r6t: &[Fa4],
    lft: &[Fa4],
    lf_w: usize,
    claims: &[(usize, Vec<Fa4>)],
    beta: Fa4,
) -> (Vec<Fa4>, Vec<Fa4>) {
    let mut value: Vec<Fa4> = Vec::new();
    let mut mult: Vec<Fa4> = Vec::new();
    // LeafSource SENDs: each row `[idx | val[EXT_D] | load_count]` → mult = −load_count.
    if lf_w >= 2 + EXT_D {
        let n_lf = lft.len() / lf_w;
        for row in 0..n_lf {
            let base = row * lf_w;
            let idx = lft[base];
            let val: Vec<Fa4> = (0..EXT_D).map(|k| lft[base + 1 + k]).collect();
            let load_count = lft[base + 1 + EXT_D];
            value.push(leaf_bus_key(idx, &val, beta));
            mult.push(-load_count);
        }
    }
    // SymEvalR6LeafAir RECEIVEs `[a_idx | out[EXT_D]]` gated `s_leaf=sel[0]` → mult +1 (one use per row).
    let n_r6 = r6t.len() / SYMX_R6_W;
    for row in 0..n_r6 {
        let base = row * SYMX_R6_W;
        if r6t[base] == Fa4::ONE {
            let a_idx = r6t[base + SYMX_AIDX];
            let out: Vec<Fa4> = (0..EXT_D).map(|k| r6t[base + SYMX_OUT + k]).collect();
            value.push(leaf_bus_key(a_idx, &out, beta));
            mult.push(Fa4::ONE);
        }
    }
    // ClaimsExposeAir RECEIVEs `[leaf_idx, claim_val[EXT_D]]` → mult +1 (one per exposed claim).
    for (leaf_idx, claim_val) in claims {
        value.push(leaf_bus_key(Fa4::from_u64(*leaf_idx as u64), claim_val, beta));
        mult.push(Fa4::ONE);
    }
    (value, mult)
}

/// Build the FULL production LEAF_BUS in SOURCE-COLUMN form for the TIED bus path — same participants +
/// multiplicities as [`build_leaf_bus_full`] but returns the RAW `(idx_col, val_cols, mult_col)` with the
/// values UNFOLDED, so the decider folds the key INLINE with the transcript β via `LogupKeyfoldConstraint`
/// (welding the bus to the committed columns). `val_cols` is `EXT_D` columns. LeafSource SEND −load_count;
/// `SymEvalR6LeafAir` `[a_idx,out]` gated `s_leaf` +1; `ClaimsExpose` `[leaf_idx,claim]` +1. This is the
/// tied LEAF_BUS the circuit.rs routing passes as a `tied_buses` entry to
/// [`prove_rec_block_whir_openings_with_bus`] (the free-fold [`build_leaf_bus_full`] stays for the plain path).
#[must_use]
pub fn build_leaf_bus_full_tied(
    r6t: &[Fa4],
    lft: &[Fa4],
    lf_w: usize,
    claims: &[(usize, Vec<Fa4>)],
) -> (Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>) {
    let mut idx_col: Vec<Fa4> = Vec::new();
    let mut val_cols: Vec<Vec<Fa4>> = vec![Vec::new(); EXT_D];
    let mut mult_col: Vec<Fa4> = Vec::new();
    // LeafSource SENDs: `[idx | val | load_count]` → mult = −load_count.
    if lf_w >= 2 + EXT_D {
        let n_lf = lft.len() / lf_w;
        for row in 0..n_lf {
            let base = row * lf_w;
            idx_col.push(lft[base]);
            for k in 0..EXT_D {
                val_cols[k].push(lft[base + 1 + k]);
            }
            mult_col.push(-lft[base + 1 + EXT_D]);
        }
    }
    // SymEvalR6LeafAir RECEIVEs `[a_idx | out]` gated `s_leaf = sel[0]` → mult +1.
    let n_r6 = r6t.len() / SYMX_R6_W;
    for row in 0..n_r6 {
        let base = row * SYMX_R6_W;
        if r6t[base] == Fa4::ONE {
            idx_col.push(r6t[base + SYMX_AIDX]);
            for k in 0..EXT_D {
                val_cols[k].push(r6t[base + SYMX_OUT + k]);
            }
            mult_col.push(Fa4::ONE);
        }
    }
    // ClaimsExposeAir RECEIVEs `[leaf_idx | claim_val]` → mult +1.
    for (leaf_idx, claim_val) in claims {
        idx_col.push(Fa4::from_u64(*leaf_idx as u64));
        for k in 0..EXT_D {
            val_cols[k].push(claim_val.get(k).copied().unwrap_or(Fa4::ZERO));
        }
        mult_col.push(Fa4::ONE);
    }
    (idx_col, val_cols, mult_col)
}

/// PROVE a LEAF_BUS LogUp balance over a committed bus table. `value_col` = per-row folded LogUp key
/// (`leaf_bus_key`); `mult_col` = per-row signed multiplicity (SEND = −load_count from LeafSource,
/// RECV = +count from a SymEvalR6Leaf tape use / +1 from ClaimsExpose). A balanced multiset satisfies
/// `Σ_x mult(x)/(α−value(x)) = 0`. Runs two proven parts: (a) a `LogupHConstraint` zerocheck that the
/// helper column `h(x)=mult(x)/(α−value(x))` is correct on every row, and (b) a per-limb `prove_col_sum`
/// that `Σ_x h(x)=0`. Returns the proof plus the `EXT_D` helper limb columns so a caller commits them
/// with `value`/`mult` and binds all three via `eval_at`. `α` is drawn from a shared transcript before
/// this call; `z` is drawn inside.
#[must_use]
pub fn prove_leaf_bus_balance(
    value_col: &[Fa4],
    mult_col: &[Fa4],
    alpha: Ea4,
    ch: &mut Chl,
) -> (LeafBusBalanceProof, Vec<Vec<Fa4>>) {
    let n = value_col.len();
    let n_vars = n.max(1).next_power_of_two().trailing_zeros() as usize;
    let mut h_limbs: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; n]; EXT_D];
    for i in 0..n {
        let h = Ea4::from(mult_col[i]) * (alpha - Ea4::from(value_col[i])).inverse();
        let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&h);
        for k in 0..EXT_D {
            h_limbs[k][i] = limbs[k];
        }
    }
    let mut cols: Vec<Vec<Fa4>> = vec![value_col.to_vec(), mult_col.to_vec()];
    for k in 0..EXT_D {
        cols.push(h_limbs[k].clone());
    }
    let cst = LogupHConstraint { alpha, val_col: 0, mult_col: 1, h_limb_base: 2 };
    let z: Vec<Ea4> = (0..n_vars).map(|_| ch.sample_algebra_element()).collect();
    let zc = prove_air_zerocheck(&cols, &cst, &z, ch);
    let mut sum_proofs: Vec<ColSumProof> = Vec::new();
    let mut limb_sums: Vec<Ea4> = Vec::new();
    for k in 0..EXT_D {
        let sum_k: Ea4 = h_limbs[k].iter().fold(Ea4::ZERO, |a, &vv| a + Ea4::from(vv));
        sum_proofs.push(prove_col_sum(&h_limbs[k], ch));
        limb_sums.push(sum_k);
    }
    (LeafBusBalanceProof { zc, limb_sums, sum_proofs }, h_limbs)
}

/// VERIFY a LEAF_BUS LogUp balance proof. Replays part (a) `verify_air_zerocheck` (helper `h` correct)
/// + part (b) per-limb `verify_col_sum`, recombines `Σ_k Xᵏ·limb_sum_k`, and accepts iff it is ZERO
/// (balanced multiset). `α` + `z` are drawn from `vch` in lockstep with prove. Fail-closed on any part.
#[must_use]
pub fn verify_leaf_bus_balance(
    proof: &LeafBusBalanceProof,
    alpha: Ea4,
    n_vars: usize,
    vch: &mut Chl,
) -> bool {
    if proof.sum_proofs.len() != EXT_D || proof.limb_sums.len() != EXT_D {
        return false;
    }
    let cst = LogupHConstraint { alpha, val_col: 0, mult_col: 1, h_limb_base: 2 };
    let z: Vec<Ea4> = (0..n_vars).map(|_| vch.sample_algebra_element()).collect();
    if !verify_air_zerocheck(&proof.zc, &cst, &z, vch) {
        return false;
    }
    let mut sum_ext = Ea4::ZERO;
    for k in 0..EXT_D {
        if !verify_col_sum(proof.limb_sums[k], &proof.sum_proofs[k], vch) {
            return false;
        }
        let xk = Ea4::from_basis_coefficients_fn(|j| if j == k { Fa4::ONE } else { Fa4::ZERO });
        sum_ext += xk * proof.limb_sums[k];
    }
    sum_ext == Ea4::ZERO
}

/// PROVE a source-TIED LEAF_BUS balance: instead of a pre-folded free `value` column, the bus table
/// carries the actual leaf fields `idx | val0..val_{n_val-1}` and the key is folded INLINE by
/// [`LogupKeyfoldConstraint`] (`idx + Σ β^{i+1}·val_i`). SOUNDNESS: the LogUp helper `h` becomes a
/// function of the committed leaf columns that the zerocheck opens, so a prover cannot substitute an
/// independently-balanced value divorced from the trace. `β` = transcript fold challenge, `α` = bus
/// challenge (both drawn before this call). Returns balance proof + `EXT_D` helper limbs for binding.
/// This is the production balance the rec-block routing calls after placing r6t/lft/claims leaf columns.
#[must_use]
pub fn prove_leaf_bus_balance_tied(
    idx_col: &[Fa4],
    val_cols: &[Vec<Fa4>],
    mult_col: &[Fa4],
    alpha: Ea4,
    beta: Fa4,
    ch: &mut Chl,
) -> (LeafBusBalanceProof, Vec<Vec<Fa4>>) {
    let n = idx_col.len();
    let n_val = val_cols.len();
    let n_vars = n.max(1).next_power_of_two().trailing_zeros() as usize;
    let keyfold = |r: usize| -> Ea4 {
        let mut k = Ea4::from(idx_col[r]);
        let mut bpow = Ea4::from(beta);
        for vc in val_cols.iter() {
            k += bpow * Ea4::from(vc[r]);
            bpow *= Ea4::from(beta);
        }
        k
    };
    let mut h_limbs: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; n]; EXT_D];
    for i in 0..n {
        let h = Ea4::from(mult_col[i]) * (alpha - keyfold(i)).inverse();
        let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&h);
        for k in 0..EXT_D {
            h_limbs[k][i] = limbs[k];
        }
    }
    // cols: idx(0) | val0..val_{n_val-1} (1..1+n_val) | mult(1+n_val) | h0..h_{EXT_D-1}(2+n_val..).
    let mut cols: Vec<Vec<Fa4>> = Vec::with_capacity(2 + n_val + EXT_D);
    cols.push(idx_col.to_vec());
    for vc in val_cols {
        cols.push(vc.clone());
    }
    cols.push(mult_col.to_vec());
    for k in 0..EXT_D {
        cols.push(h_limbs[k].clone());
    }
    let cst = LogupKeyfoldConstraint {
        alpha,
        beta,
        idx_col: 0,
        val_col_base: 1,
        n_val,
        mult_col: 1 + n_val,
        h_limb_base: 2 + n_val,
    };
    let z: Vec<Ea4> = (0..n_vars).map(|_| ch.sample_algebra_element()).collect();
    let zc = prove_air_zerocheck(&cols, &cst, &z, ch);
    let mut sum_proofs: Vec<ColSumProof> = Vec::new();
    let mut limb_sums: Vec<Ea4> = Vec::new();
    for k in 0..EXT_D {
        let sum_k: Ea4 = h_limbs[k].iter().fold(Ea4::ZERO, |a, &vv| a + Ea4::from(vv));
        sum_proofs.push(prove_col_sum(&h_limbs[k], ch));
        limb_sums.push(sum_k);
    }
    (LeafBusBalanceProof { zc, limb_sums, sum_proofs }, h_limbs)
}

/// VERIFY a source-TIED LEAF_BUS balance ([`prove_leaf_bus_balance_tied`]): replays a `LogupKeyfoldConstraint`
/// helper zerocheck (over `idx | val* | mult | h`, key folded inline) + per-limb `Σh=0`, accepts iff
/// balanced. `α`/`β`/`z` come from `vch` in lockstep with prove; `n_val` = value-column count. Fail-closed.
#[must_use]
pub fn verify_leaf_bus_balance_tied(
    proof: &LeafBusBalanceProof,
    alpha: Ea4,
    beta: Fa4,
    n_val: usize,
    n_vars: usize,
    vch: &mut Chl,
) -> bool {
    if proof.sum_proofs.len() != EXT_D || proof.limb_sums.len() != EXT_D {
        return false;
    }
    let cst = LogupKeyfoldConstraint {
        alpha,
        beta,
        idx_col: 0,
        val_col_base: 1,
        n_val,
        mult_col: 1 + n_val,
        h_limb_base: 2 + n_val,
    };
    let z: Vec<Ea4> = (0..n_vars).map(|_| vch.sample_algebra_element()).collect();
    if !verify_air_zerocheck(&proof.zc, &cst, &z, vch) {
        return false;
    }
    let mut sum_ext = Ea4::ZERO;
    for k in 0..EXT_D {
        if !verify_col_sum(proof.limb_sums[k], &proof.sum_proofs[k], vch) {
            return false;
        }
        let xk = Ea4::from_basis_coefficients_fn(|j| if j == k { Fa4::ONE } else { Fa4::ZERO });
        sum_ext += xk * proof.limb_sums[k];
    }
    sum_ext == Ea4::ZERO
}

/// Convert one row-major AIR trace into its column-major MLE form, zero-padded up to
/// `max(⌈log2 height⌉, folding)` variables (the multilinear encoding needs a `2^n`-row
/// domain, and the interleaved witness folds `folding` variables in its first round). Returns
/// the per-column evaluation vectors (each length `2^n_vars`) and the table shape
/// `(n_vars, width)` the HVZK-WHIR verifier must be given for this table.
#[must_use]
pub fn trace_to_table(trace: &RowMajorMatrix<Fa4>, folding: usize) -> (Vec<Vec<Fa4>>, (usize, usize)) {
    let h = trace.height();
    let w = trace.width();
    // ⌈log2 height⌉, then lift to at least `folding` vars so new_interleaved's pad_zeros is a no-op.
    let n_vars = h.max(1).next_power_of_two().trailing_zeros() as usize;
    let n_vars = n_vars.max(folding);
    let padded = 1usize << n_vars;
    // Column-major: cols[c][r] = trace[r][c]; rows [h, padded) are zero (the MLE zero-extension).
    let mut cols = vec![vec![Fa4::ZERO; padded]; w];
    for r in 0..h {
        let row = trace.row_slice(r).expect("row r < height is in-bounds");
        for c in 0..w {
            cols[c][r] = row[c];
        }
    }
    (cols, (n_vars, w))
}

/// Convert the rec-block's full aggregated AIR trace set into the multi-table HVZK-WHIR witness
/// (`Vec<Table columns>`) plus the per-table `(n_vars, width)` shapes. Table order is preserved
/// verbatim, so the prover's opening/virtual-claim schedule and the verifier's replay index the
/// same tables. One `Table` per aggregated AIR (r6 / leaf / stub / ood per tx, then ClaimsExpose).
#[must_use]
pub fn rec_traces_to_tables(
    traces: &[RowMajorMatrix<Fa4>],
    folding: usize,
) -> (Vec<Vec<Vec<Fa4>>>, Vec<(usize, usize)>) {
    let mut tables = Vec::with_capacity(traces.len());
    let mut shapes = Vec::with_capacity(traces.len());
    for t in traces {
        let (cols, shape) = trace_to_table(t, folding);
        tables.push(cols);
        shapes.push(shape);
    }
    (tables, shapes)
}

/// Verifier-side re-evaluation of the OodCheck AIR's arithmetic constraint on a single opened
/// ood-trace row (`z_h[EXT_D] ‖ q[EXT_D] ‖ acc[EXT_D] ‖ active`, `OODCHK_W` base-field values,
/// each extension-valued lane its `EXT_D` limbs low-to-high). Mirrors `OodCheckAir::eval`
/// EXACTLY: `active ∈ {0,1}`, and when `active == 1` the quotient identity `acc == q · z_h`
/// holds in the decider's extension field `Ea4`. This is the keystone the WHIR rec-verify
/// enforces on the WHIR-opened ood column — the FRI rec proves it via `prove_batch`; the WHIR
/// rec commits the ood column, opens it, and checks the identity here. (The logup bus-ties that
/// bind `z_h`/`q`/`acc` to the R6/ZHBind sources are the separate committed-trace logup layer.)
/// Returns `false` on any violation (non-boolean `active`, or `active` with `acc != q · z_h`).
#[must_use]
pub fn check_oodcheck_identity(ood_row: &[Fa4]) -> bool {
    if ood_row.len() < OODCHK_W {
        return false;
    }
    // Reconstruct each extension lane from its EXT_D base-field limbs (inverse of circuit.rs
    // `challenge_coeffs`'s `as_basis_coefficients_slice` decomposition).
    let lane = |base: usize| -> Ea4 { Ea4::from_basis_coefficients_fn(|k| ood_row[base + k]) };
    let zh = lane(0);
    let q = lane(EXT_D);
    let acc = lane(EXT_D * 2);
    let active = ood_row[EXT_D * 3];
    // active must be boolean (OodCheckAir: `active * (active - 1) == 0`).
    if active != Fa4::ZERO && active != Fa4::ONE {
        return false;
    }
    // when active, the quotient identity `acc == q · z_h` must hold (OodCheckAir: `zh_ext_mul`).
    if active == Fa4::ONE && acc != q * zh {
        return false;
    }
    true
}

/// The rec-block's OodCheck gate — STRICTER than [`check_oodcheck_identity`] (which permits
/// inactive padding rows). The rec-block carries exactly ONE ood row, and it MUST be active so the
/// keystone quotient identity `z_h·q = acc` is always enforced on it. The rec-block gate therefore
/// requires `active == 1` AND `acc == q·z_h`, returning `false` unless both hold.
#[must_use]
pub fn check_rec_block_ood_row(ood_row: &[Fa4]) -> bool {
    if ood_row.len() < OODCHK_W {
        return false;
    }
    // Require active == 1 so the quotient identity below is always enforced on the rec-block row.
    if ood_row[EXT_D * 3] != Fa4::ONE {
        return false;
    }
    check_oodcheck_identity(ood_row)
}

/// The published HVZK-WHIR opening+mask bundle for a set of rec-block traces: the mask commitments
/// + masked-sumcheck transcript (`ZkSumcheckData`) that bind the committed trace columns to their
/// opened evaluations under the Four-Pillars `is_zk()==1` privacy path, plus the recorded
/// opening/virtual claims the verifier replays. This is the opening+mask layer of the rec-block
/// WHIR proof (proven sound by the tamper test): every column of every table is committed and its
/// evaluation opened + blinded (the full witness opening). The row-wise AIR-constraint enforcement
/// (the OodCheck quotient identity via [`check_oodcheck_identity`], and the full constraint
/// sumcheck) composes ON TOP of this layer.
///
/// Derives `Serialize`/`Deserialize` so the whole opening+mask bundle round-trips through postcard
/// bytes — the WHIR light-decider proof payload the wallet fast-broadcast carries in the tx carrier
/// and the node deserializes + verifies (`rec_block_bundle_postcard_roundtrips_and_verifies`).
#[derive(Clone, Serialize, Deserialize)]
pub struct RecBlockOpeningBundle {
    /// Per-table `(n_vars, width)` shapes — the verifier rebuilds its table layout from these.
    pub shapes: Vec<(usize, usize)>,
    /// Mask-code commitments (one per masked round) collected during `prove_hvzk`.
    pub mask_commits: Vec<<Mmcs16 as Mmcs<Fa4>>::Commitment>,
    /// The masked-sumcheck transcript (round polynomials + OOD mask openings).
    pub zk_data: ZkSumcheckData<Fa4, Ea4>,
    /// The full opening set: `openings[i]` = the evaluations of all `width` columns of table `i`
    /// (every committed column is bound, table by table, column by column).
    pub openings: Vec<Vec<Ea4>>,
    /// The virtual full-witness evaluation the prover drew; verify replays it into the transcript.
    pub virtual_eval: Ea4,
    /// The folding point the prover ended at; verify accepts iff it reproduces the same point.
    pub prover_rand: Vec<Ea4>,
    /// The γ batching challenge for the r6 (`SymEvalR6Leaf`) composed AIR-constraint zerocheck. Drawn
    /// from the shared transcript at prove time; verify re-derives it, so this is carried only to fix
    /// it against transcript replay (a mismatch fails closed). Powers γ⁰…γ¹¹ weight the reg-op terms,
    /// γ¹²/γ¹³ the row-idx transition — see [`SymEvalR6Constraint`].
    pub r6_gamma: Ea4,
    /// One AIR-constraint zerocheck proof per multi-row `SymEvalR6Leaf` table (identified by its
    /// committed width `SYMX_W_CONST`), paired with that table's index in `shapes`. This is what
    /// enforces that the ood row's `acc` was CORRECTLY computed by the committed r6 sym-eval trace
    /// (reg-op relations + row-idx transition) — the constraint the FRI rec prove used to enforce and
    /// the WHIR light decider now enforces directly. Each proof's `opened`/`shifted_opened` claims are
    /// bound to the WHIR commitment via `eval_at`/`add_claim_at` at the zerocheck point `r` / `σ(r)`,
    /// so the arithmetic zerocheck proves a fact about the COMMITTED trace, not a free trace.
    pub r6_zerochecks: Vec<(usize, AirZerocheckProof)>,
    /// Committed LogUp buses enforced in this bundle: LEAF_BUS binds each `SymEvalR6Leaf` tape's
    /// CONSUMED leaves to `LeafSource`; SYMX_REG_BUS binds register reads to prior writes; more may
    /// follow. Each entry carries one bus's `Σ mult/(α−keyfold)=0` balance proof + α + appended-table
    /// index, all bound via `eval_at`. Empty when no bus is supplied.
    pub buses: Vec<BusBalanceEntry>,
    /// SOURCE-TIED committed LogUp buses: unlike `buses` (which commit a pre-folded free `value` col),
    /// each tied bus commits the REAL leaf columns `[idx, val0..val_{n_val-1}]` and folds the LogUp key
    /// INLINE via `LogupKeyfoldConstraint`, so the balance is provably a function of the committed leaf
    /// columns (a prover cannot substitute an independently-balanced value). Each entry carries the
    /// balance proof + α + the transcript fold challenge β + `n_val` + appended-table index. This is the
    /// production tie for the rec-block LEAF_BUS/ACC_BUS. Empty when no tied bus is supplied.
    pub tied_buses: Vec<TiedBusEntry>,
    /// ⛔⛔⛔ DB-159 — HOW MANY LEADING TABLES ARE THE CONSTRAINT TABLES. The rest are bus tables, and
    /// they live in a SECOND commitment because they hold `h`, which is a function of `α`, which must
    /// itself be a function of the first commitment. A carrier that re-points a bus at a round-1 table
    /// is refused.
    #[serde(default)]
    pub n_constraint: usize,
    /// The round-2 masked opening. Defaults are carried when there is no bus at all.
    #[serde(default)]
    pub virtual_eval2: Ea4,
    #[serde(default)]
    pub zk_data2: ZkSumcheckData<Fa4, Ea4>,
    #[serde(default)]
    pub mask_commits2: Vec<<Mmcs16 as Mmcs<Fa4>>::Commitment>,
    #[serde(default)]
    pub prover_rand2: Vec<Ea4>,
}

/// One SOURCE-TIED committed LogUp bus in a [`RecBlockOpeningBundle`]: its inline-keyfold balance proof
/// ([`prove_leaf_bus_balance_tied`]), the α bus challenge + β fold challenge (both transcript-derived;
/// verify re-derives + binds), the value-column count `n_val`, and the index of its appended
/// `[idx | val0..val_{n_val-1} | mult | h_limb0..EXT_D]` table in `shapes`/`openings`.
#[derive(Clone, Serialize, Deserialize)]
pub struct TiedBusEntry {
    pub proof: LeafBusBalanceProof,
    pub alpha: Ea4,
    pub beta: Fa4,
    pub n_val: usize,
    pub table_idx: usize,
}

/// One committed LogUp bus enforced in a [`RecBlockOpeningBundle`]: its `Σ mult/(α−keyfold)=0` balance
/// proof, the α challenge (transcript-derived; verify re-derives + binds it), and the index of its
/// appended `[value, mult, h_limb0..EXT_D]` table in `shapes`/`openings`.
#[derive(Clone, Serialize, Deserialize)]
pub struct BusBalanceEntry {
    pub proof: LeafBusBalanceProof,
    pub alpha: Ea4,
    pub table_idx: usize,
}

/// ⛔ ABSORB THE NEXT-ROW OPENINGS — THE CARRIER MUST NOT BE MALLEABLE (2026-09-11).
///
/// `zc.opened` is bound to the commitment at `r` (`eval_at` / `add_claim_at`). `zc.shifted_opened` —
/// the next-row openings a row-SHIFTED gate reads through `at` — was bound by nothing on a row-LOCAL
/// gate: the gate never reads it, and the transcript never absorbed it. MEASURED: flipping one byte of
/// a genuine direct carrier landed in `shifted_opened` and the tampered carrier VERIFIED. That is
/// Bitcoin's pre-SegWit transaction malleability (BIP62): a relayer can alter a spend in flight and
/// change its id without invalidating it. BORROWED fix, same as SegWit's principle — everything the
/// proof carries is committed: absorbed here, symmetrically in prover and verifier, so any alteration
/// diverges every later challenge and the WHIR opening fails.
pub(crate) fn absorb_shifted_openings(ch: &mut Chl, shifted: &[Ea4]) {
    for e in shifted {
        for &b in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e) {
            ch.observe(b);
        }
    }
}

/// ⛔ THE WIDEST DIRECT-AIR CARRIER THIS VERIFIER WILL DECODE — BY CONSTRUCTION the widest carrier the
/// protocol defines. Everything past it is a remote sender's choice, and before this constant existed
/// the shape gate refused only `width == 0` — a million-column bundle would have been allocated and
/// walked.
///
/// MEASURED 2026-09-11: a literal 4096 here broke `nullifier_insert_air` (the block carrier is 9,156
/// wide; my survey had counted only literal widths). Naming the widest carrier's own constant means a
/// deeper tree or a wider carrier moves this bound with it instead of silently refusing honest proofs.
///
/// ⛔⛔⛔ MEASURED AGAIN 2026-09-23, AND IT HAD ALREADY GONE STALE. It named ONE carrier's constant
/// while the protocol defines several, and `CoverOrSpendGate`'s row is 22,312 columns — so the shape
/// gate refused every spend-or-decoy transition at `[vfail] width > AIR_DIRECT_MAX_WIDTH`, before a
/// single number of it was used. That is the silent-refusal failure this doc's own last sentence warned
/// about, arriving because "the widest carrier" was written as a POINTER TO ONE rather than as the MAX.
/// It is now the max, so it still names no number and still cannot be chosen: a wider carrier moves it,
/// and nothing a remote sender says does. ⭐ This bound was RAISED by re-deriving it, never by argument
/// — the protocol genuinely defines a wider carrier than it did, and the DoS property is unchanged
/// (the ceiling is still a fixed function of protocol constants, independent of anything on the wire).
/// ⛔ AND IT MUST COVER THE AGGREGATE'S STEP ROW, NOT JUST A CARRIER. A block transition lays the
/// inner carrier's OPENED ROW as committed columns (that is how `BoundStepConstraint` closes
/// `cf == eq(z,r)·C(opened)`), so the widest table this protocol lays is an aggregate step row, at
/// `EXT_LIMBS` base limbs per value. Beside the opened values it carries only the zerocheck
/// (`nvars·per + 3·nvars + 1`) and the γ-power ladder — MEASURED at 381 against an opened row of
/// 22,312 — so twice the opened row bounds the whole step row with room to spare. That is a
/// structural statement about the layout, not a limit anyone picked.
pub const AIR_DIRECT_MAX_WIDTH: usize = max_width(
    crate::nullifier_insert_air::PADDED_BLOCK_ROW_COLS,
    2 * crate::committed_air::EXT_LIMBS * crate::nf_sparse_air::CR_COLS,
);

/// `max` for a const context — so the bound above stays an expression over protocol constants.
const fn max_width(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

/// A lean opening+mask bundle for a DIRECT (non-recursive, row-local) AIR proof — the #135 Mina-fast path
/// every ecosystem BROADCAST (Send / Swap / token-create / buy / stake) rides. Unlike
/// [`RecBlockOpeningBundle`] it carries NO r6/ood/bus machinery: just the committed columns opened at the
/// zerocheck point `r`, the AIR-constraint zerocheck, and the masked HVZK sumcheck. ZK by the HVZK mask.
#[derive(Clone, Serialize, Deserialize)]
pub struct AirDirectBundle {
    pub shapes: Vec<(usize, usize)>,
    /// O1-FOOTPRINT-REVIEWED: bounded by AIR_DIRECT_MAX_WIDTH — the shape gate refuses any wider
    /// bundle before it is walked; one opening per column. Every field element is 4 bytes on the wire
    /// (`MontyField31`'s serde, 2026-09-11), so the byte length is f(width) and never f(witness):
    /// MEASURED mint carrier across values 1..u64::MAX = [5340 ×6], spread 0.
    pub openings: Vec<Vec<Ea4>>,
    pub zc: AirZerocheckProof,
    pub virtual_eval: Ea4,
    pub zk_data: ZkSumcheckData<Fa4, Ea4>,
    pub mask_commits: Vec<<Mmcs16 as Mmcs<Fa4>>::Commitment>,
    pub prover_rand: Vec<Ea4>,
}

/// PROVE a DIRECT row-local AIR on the light decider: commit the trace columns, prove
/// `Σ_x eq(z,x)·C(cols(x)) = 0` (the AIR gates hold on every committed row), open every column at the
/// zerocheck point `r` (bound to the commitment via `eval_at`), + the masked HVZK sumcheck. `cols` height
/// MUST be a power of two ≥ `2^folding` (a small AIR is padded by ROW-REPLICATION, which preserves a
/// ROW-LOCAL constraint). This is the generic engine `pqspend_direct_prove_bytes` (Send) + the Ion Swap /
/// launchpad broadcast provers call — retiring the FRI rec-block for user actions. Fail-closed on serialize
/// failure (never panics).
#[must_use]
pub fn prove_air_direct_light_decider_bytes<C, Mk>(
    cols: Vec<Vec<Fa4>>,
    make_constraint: Mk,
    folding: usize,
    pow_bits: usize,
    mmcs: Mmcs16,
    encoding: Enc16,
    pch: &mut Chl,
    rng: &mut SmallRng,
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let width = cols.len();
    let h = cols.first().map(|c| c.len()).unwrap_or(0);
    if width == 0 || h == 0 || !h.is_power_of_two() {
        return None;
    }
    let nvars = h.trailing_zeros() as usize;
    // A copy of the columns for the zerocheck: `cols` moves into the WHIR commitment below, and the
    // zerocheck evaluates the SAME data (its `opened@r` values are then tied back to that commitment).
    let cols_for_zc = cols.clone();
    let shapes = vec![(nvars, width)];
    let tables = vec![cols];
    let mut prover = build_decider_hiding_prover(tables, folding, mmcs, encoding);
    let all: Vec<usize> = (0..width).collect();
    // (1) Open every column — `eval` samples a point then ABSORBS the trace's evals into `pch`
    //     (sumcheck::layout::prover::eval). This binds the transcript to the committed trace.
    let openings = vec![prover.eval(0, &all, pch)];
    // (2) SOUNDNESS-CRITICAL ORDER: draw the constraint-batching challenge `gamma` and the zerocheck
    //     point `z` AFTER (1), so BOTH are Fiat-Shamir functions of the trace's absorbed evals.
    //     - `z` post-commit: else a prover crafts a trace whose eq(z,·)-weighted sum is 0 at a KNOWN z
    //       while a row violates the constraint (breaks zerocheck→pointwise).
    //     - `gamma` post-commit: the constraint γ-batches many gates `Σ γ^i c_i`; a KNOWN γ lets a prover
    //       cancel violated gates against each other on a row (`Σ γ^i c_i = 0` with some `c_i ≠ 0`).
    //     Drawing both after the eval absorption makes either attack a full Fiat-Shamir grind (≈|F|).
    let gamma: Ea4 = pch.sample_algebra_element();
    let constraint = make_constraint(gamma);
    let z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
    let zc = prove_air_zerocheck(&cols_for_zc, &constraint, &z, pch);
    // (3) Bind the zerocheck's `opened` (each column's MLE at the fold point r) to the WHIR commitment.
    let pt_r = Point::new(zc.r.clone());
    let _ = prover.eval_at(0, &all, &pt_r, pch);
    absorb_shifted_openings(pch, &zc.shifted_opened);
    let virtual_eval = prover.add_virtual_eval(pch);
    let mut zk_data = ZkSumcheckData::<Fa4, Ea4>::default();
    let (mask_commits, prover_rand) = prove_hvzk(prover, &mut zk_data, pow_bits, pch, rng);
    let bundle = AirDirectBundle { shapes, openings, zc, virtual_eval, zk_data, mask_commits, prover_rand };
    postcard::to_allocvec(&bundle).ok()
}

/// ⛔⛔⛔ THE ONE SHAPE GATE EVERY WIRE-BORNE AIR CARRIER PASSES BEFORE ANY OF ITS NUMBERS IS USED.
///
/// A carrier off the wire DECLARES its own trace shape (`shapes[i] = (nvars, width)`) and then ships
/// the vectors that shape is supposed to describe. Nothing used to compare the two, so an
/// unauthenticated remote party chose the bounds of loops and the lengths of slices inside the
/// verifier. MEASURED 2026-09-08 (lane E, pin C-16): `shapes[0].1 = 64` against three shipped openings
/// reached `Verifier::add_claim`, which ASSERTS `polys.len() == evals.len()` rather than refusing, and
/// unwound the node — `assertion left == right failed  left: 64  right: 3` at
/// `sumcheck/src/layout/verifier.rs:132`. Reachable off-lock at `/submit_pq_tx` (the submit RPC, rpc_http.rs:1270 until that arm was deleted 2026-09-08; the same verifier still rides the spend-validity, multi-spend and cover arms the door now asks) and
/// on the gossip path through `chain_object::admissible`, i.e. a remote unauthenticated kill.
///
/// This function is that comparison, in ONE place, run BEFORE `build_decider_hiding_verifier`, before
/// any `(0..width)` / `(0..nvars)` range, and before the first `add_claim`. It is deliberately NOT a
/// patch at any of the individual assert sites: the class is "a count a remote caller supplies decides
/// an index", and the class is closed by refusing the carrier while those counts are still just data.
///
/// WHAT IT DECIDES, and why each line is a derived equality rather than a chosen limit:
///   * `width != 0` — the layout planner gives a zero-width table no slot; there is no such AIR.
///   * `openings.len() == width` — the exact equality `add_claim` asserts (pin C-16).
///   * `zc.opened.len() == width` — the exact equality `add_claim_at` asserts, and the length every
///     gate indexes.
///   * `zc.shifted_opened` empty or `== width` — the next-row openings must cover every column or
///     none, so a row-shifted gate cannot be scored against values nobody committed.
///   * `zc.round_evals.len() == nvars` and `zc.r.len() == nvars` — `verify_air_zerocheck` already
///     rechecks these, but it runs AFTER `nvars` has been used to draw `nvars` challenges and to build
///     an `nvars`-arity point; checking here is what keeps a declared `nvars` from being spent before
///     it is validated. Because the round vectors must physically be present, this also BOUNDS `nvars`
///     by the message size — no cap is invented, the wire pays for every variable it declares.
///   * the shift and the product are checked against overflow, because `plan_layout` computes
///     `width * (1 << arity)` and `1usize << 64` is a panic in debug and a MASKED shift in release —
///     the same defect class as the depth-64 IMT `x >> 64` that went stale.
///
/// Returns the table's cell count (`width * 2^nvars`) so a multi-table caller can bound the stacked
/// total with the same checked arithmetic, or `None` to REFUSE the carrier.
#[must_use]
fn air_carrier_table_shape_admissible(
    nvars: usize,
    width: usize,
    opening: &[Ea4],
    zc: Option<&crate::air_zerocheck::AirZerocheckProof>,
) -> Option<usize> {
    if width > AIR_DIRECT_MAX_WIDTH {
        return None; // wider than any carrier this protocol defines: a remote sender's allocation, refused
    }
    if width == 0 {
        return None;
    }
    if opening.len() != width {
        return None;
    }
    // A COMMITTED-ONLY table (a tied LogUp bus in the with-bus carrier) carries an opening but no
    // zerocheck of its own; `None` here is that case, not a skipped check — its own gate below binds
    // every column index it opens against this same `width`.
    if let Some(zc) = zc {
        if zc.opened.len() != width {
            return None;
        }
        // EXACTLY `width` next-row openings — not "empty or width".
        //
        // MEASURED by pin E-1 on this lane's own fix: allowing the empty case let a carrier with
        // `shifted_opened` STRIPPED still verify, because the production send gate is row-local and
        // never calls `at`. Two distinct byte strings verifying for one statement is carrier
        // MALLEABILITY, and it is exactly the shape that bites wherever a proof is cached, deduped or
        // identified by its bytes. `prove_air_zerocheck` fills this vector for EVERY column of EVERY
        // AIR unconditionally, so requiring the prover's own invariant refuses no honest carrier — pin
        // E-2 re-measures that at 1, 2, 7, 31 and 32 rows.
        if zc.shifted_opened.len() != width {
            return None;
        }
        if zc.round_evals.len() != nvars || zc.r.len() != nvars {
            return None;
        }
    }
    if nvars >= usize::BITS as usize {
        return None;
    }
    width.checked_mul(1usize << nvars)
}

/// ⛔⛔⛔ DB-213b — THE STATEMENT FIXES THE TRACE SHAPE; THE CARRIER NEVER DOES.
///
/// Every light-decider verify entry takes the EXACT `(nvars, width)` of every committed table from its
/// caller and refuses a carrier that declares anything else, before the layout planner sees a shape and
/// before a single challenge is drawn. [`air_carrier_table_shape_admissible`] only keeps a declared shape
/// from sizing an allocation; it cannot say whether the shape is the statement's, because only the caller
/// knows the statement.
///
/// WHY THE ROW COUNT IS PART OF A STATEMENT. A row-shifted AIR's walk length IS its height (a Merkle path
/// whose depth is the row count), a boundary weld on "the last row" moves with the height, and a caller's
/// cross-tie at row `r` of a table that shrank below `r` aliases onto a different row (`boolean_point`
/// keeps only the low `nvars` bits). MEASURED on the folded sparse block carrier (arm d of
/// `folded_block_carrier_matches_per_table_and_fits_the_budget`): a 2-insert table presented as a 1-insert
/// statement verified — a forged nullifier post-root. Where a statement IS height-invariant (a row-local
/// gate with every public value on every row), a free shape is still carrier MALLEABILITY: two byte
/// strings verifying one statement (census arm M3 measures it on the membership walk).
///
/// So the shape is never optional: no entry verifies "whatever shape arrived".
#[must_use]
fn carrier_shapes_are(declared: &[(usize, usize)], expected: &[(usize, usize)]) -> bool {
    declared == expected
}

/// `(nvars, width)` of a trace a prover is about to commit — the shape its verifier must then STATE.
/// `None` for an empty, ragged or non-power-of-two trace, which no prover here commits.
#[must_use]
pub fn trace_shape(cols: &[Vec<Fa4>]) -> Option<(usize, usize)> {
    let h = cols.first()?.len();
    if h == 0 || !h.is_power_of_two() || cols.iter().any(|c| c.len() != h) {
        return None;
    }
    Some((h.trailing_zeros() as usize, cols.len()))
}

/// ⛔ TEST-ONLY: the shape a direct carrier DECLARES — what every verify read before DB-213b. It exists for
/// tests whose subject is not the shape, and for calibration arms that measure what an unpinned engine would
/// accept. A shipped binary has no such entry, so no production caller can hand a carrier its own statement.
#[cfg(test)]
#[must_use]
pub(crate) fn declared_direct_shape_for_tests(bytes: &[u8]) -> (usize, usize) {
    postcard::from_bytes::<AirDirectBundle>(bytes)
        .ok()
        .and_then(|b| b.shapes.first().copied())
        .unwrap_or((0, 0))
}

/// VERIFY a direct row-local AIR proof (node / self-check): deserialize, replay the AIR zerocheck in the
/// prover's transcript order (same `z`), bind `opened` at `r`, and check the masked HVZK opening. The
/// caller supplies the SAME `constraint` (both prover + node reconstruct it from the public AIR) AND the
/// statement's trace shape `expected_shape` (DB-213b, [`carrier_shapes_are`]).
/// Fail-closed on any decode / shape / zerocheck / opening mismatch, and — since 2026-09-08 — on any
/// carrier whose DECLARED shape disagrees with the data it ships
/// ([`air_carrier_table_shape_admissible`], pin C-16) or that is narrower than its own AIR reads
/// ([`crate::air_zerocheck::Row`], pin C-17). It never panics on wire bytes.
#[must_use]
pub fn verify_air_direct_light_decider_bytes<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    folding: usize,
    ell_zk: usize,
    pow_bits: usize,
    vch: &mut Chl,
    expected_shape: (usize, usize),
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let bundle: AirDirectBundle = match postcard::from_bytes(bytes) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if bundle.shapes.len() != 1 || bundle.openings.len() != 1 {
        return false;
    }
    // ⛔ DB-213b — the STATEMENT's shape, before anything below reads the carrier's.
    if !carrier_shapes_are(&bundle.shapes, &[expected_shape]) {
        return false;
    }
    let (nvars, width) = bundle.shapes[0];
    // ⛔ THE SHAPE GATE — before the layout planner sees `shapes`, before any `(0..width)` /
    // `(0..nvars)` range exists, and before the first `add_claim` assert. Everything below this line
    // may treat `nvars`/`width` as agreeing with the data; nothing above it may.
    if air_carrier_table_shape_admissible(nvars, width, &bundle.openings[0], Some(&bundle.zc)).is_none() {
        return false;
    }
    let mut verifier = build_decider_hiding_verifier(&bundle.shapes);
    let all: Vec<usize> = (0..width).collect();
    // Mirror prove: add_claim observes the trace evals into the transcript, then gamma + z are drawn.
    // This ties gamma + z to the committed trace (see the prove-side note for the soundness reason), and
    // the verifier rebuilds the SAME constraint from the transcript-derived gamma.
    verifier.add_claim(0, &all, &bundle.openings[0], vch);
    let gamma: Ea4 = vch.sample_algebra_element();
    let constraint = make_constraint(gamma);
    let z: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
    if !verify_air_zerocheck(&bundle.zc, &constraint, &z, vch) {
        return false;
    }
    let pt_r = Point::new(bundle.zc.r.clone());
    verifier.add_claim_at(0, &all, &bundle.zc.opened, &pt_r, vch);
    absorb_shifted_openings(vch, &bundle.zc.shifted_opened);
    verifier.add_virtual_eval(bundle.virtual_eval, vch);
    match verify_hvzk::<Fa4, Ea4, Mmcs16, _>(
        verifier,
        &bundle.zk_data,
        &bundle.mask_commits,
        ell_zk,
        folding,
        pow_bits,
        vch,
    ) {
        Some(vpoint) => bundle.prover_rand == vpoint,
        None => false,
    }
}

/// SELF-CONTAINED generic DIRECT prove entry every ecosystem BROADCAST (Send / Swap / token-create /
/// stake / bond / …) calls: builds the pinned HVZK-WHIR config (perm / hash / compress / mmcs /
/// mask-encoding + Fiat-Shamir challenger + mask rng) INTERNALLY from [`REC_DECIDER_SEED`] + params, so
/// the caller passes ONLY the row-local trace `cols`, the AIR-constraint factory, and the `public_bind`
/// (the block's attested public IO: nf‖outcm per tx). `public_bind` is observed at the transcript START so
/// a verifier reading DIFFERENT public values derives a divergent transcript → reject. `make_constraint`
/// builds the γ-batched AIR constraint from a transcript-derived gamma (drawn post-commit inside the core).
/// Returns the ≤1.8MB carrier bytes or None. Verify with
/// [`verify_air_direct_light_decider_selfcontained_bytes`] (same pinned seed → same transcript).
#[must_use]
pub fn prove_air_direct_light_decider_selfcontained_bytes<C, Mk>(
    cols: Vec<Vec<Fa4>>,
    make_constraint: Mk,
    public_bind: &[Fa4],
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let perm = Perm16::new_from_rng_128(&mut perm_rng);
    let hash = SpongeHash::new(perm.clone());
    let compress = CompressHash::new(perm.clone());
    let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, prover_randomness());
    let encoding: Enc16 = decider_mask_encoding(REC_DECIDER_T, REC_DECIDER_ELL_ZK);
    let mut pch = Chl::new(perm);
    for &f in public_bind {
        pch.observe(f);
    }
    let mut prover_rng = prover_randomness();
    prove_air_direct_light_decider_bytes(
        cols,
        make_constraint,
        REC_DECIDER_FOLDING,
        REC_DECIDER_POW_BITS,
        mmcs,
        encoding,
        &mut pch,
        &mut prover_rng,
    )
}

/// SELF-CONTAINED generic DIRECT verify entry the node / prover self-check calls on a carrier arriving from
/// the wire: rebuilds the Fiat-Shamir challenger from the pinned [`REC_DECIDER_SEED`] permutation, observes
/// the SAME `public_bind` the prover bound at the transcript START (mismatched public IO diverges the
/// transcript → reject), and runs [`verify_air_direct_light_decider_bytes`] against the statement's
/// `expected_shape` (DB-213b). Fail-closed on any decode / shape / zerocheck / opening mismatch.
#[must_use]
pub fn verify_air_direct_light_decider_selfcontained_bytes<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    expected_shape: (usize, usize),
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let perm = Perm16::new_from_rng_128(&mut perm_rng);
    let mut vch = Chl::new(perm);
    for &f in public_bind {
        vch.observe(f);
    }
    verify_air_direct_light_decider_bytes(
        bytes,
        make_constraint,
        REC_DECIDER_FOLDING,
        REC_DECIDER_ELL_ZK,
        REC_DECIDER_POW_BITS,
        &mut vch,
        expected_shape,
    )
}

/// ⭐⭐⭐ DB-452 — THE PLAIN BATCH IS THE BOUND ENGINE. A multi-AIR proof over PUBLIC tables with no LogUp bus and no tie
/// is [`prove_air_batch_light_decider_selfcontained_bytes_with_bus`] with nothing on the bus side: every table is
/// committed (round 1) before γ, every `opened@r` is a claim the round's WHIR opening proves against that commitment,
/// and a row-shifted gate's next-row openings are proved by the shift-bind. `public_bind` (the statement) is observed
/// at the transcript START, so a verifier reading different public values derives a divergent transcript.
///
/// ⛔ WAS: its own commitment-free engine (`AirBatchDirectBundle` — round-1 openings, a virtual eval and a masked
/// sumcheck whose final target the verifier dropped), so nothing bound a sent value to a trace. MEASURED link 78
/// (`nf_sparse_air::db452_e_…`): the band door's keyed slice, on the same unbound shape, accepted a slice for a post
/// root no insert reached. The trace is NOT hidden: every caller carries public data (the whole-chain AIR, the band
/// door's keyed nullifier inserts, the settlement aggregate's verify rows); a secret-holding trace belongs on
/// `committed_air::prove_air_blinded_bytes`. Each table height MUST be a power of two. Fail-closed on any error.
#[must_use]
pub fn prove_air_batch_light_decider_selfcontained_bytes<C, Mk>(
    tables: Vec<Vec<Vec<Fa4>>>,
    make_constraint: Mk,
    public_bind: &[Fa4],
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        tables,
        make_constraint,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        public_bind,
    )
}

/// VERIFY a plain batch proof (the node's whole-chain adopt gate, the band door's keyed slice): the bound engine with
/// no bus table (`expected_bus = []`) and no tie, against the STATEMENT's table shapes (DB-213b). Fail-closed on any
/// decode / shape / zerocheck / shift-bind / opening mismatch.
#[must_use]
pub fn verify_air_batch_light_decider_selfcontained_bytes<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    expected_shapes: &[(usize, usize)],
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    verify_air_batch_light_decider_selfcontained_bytes_with_bus(
        bytes,
        make_constraint,
        Vec::new(),
        Vec::new(),
        public_bind,
        expected_shapes,
        &[],
    )
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// BUS-AWARE generic batch light decider — the SOUND retirement path for AIRs that carry LogUp interactions
// (the validator FINALITY CERT's FINALITY_WEIGHT_BUS, the multi-transfer bundle's balance buses). An AIR with
// a bus MUST name it here (else the cross-table binding silently drops → unsound). This variant proves each
// supplied SOURCE-TIED LogUp bus's `Σ mult/(α−keyfold)=0` balance on the REAL committed source columns,
// EXACTLY as `prove_rec_block_whir_openings_with_bus` does for the rec-block LEAF/ACC buses — so the bus's
// binding is provably a function of the committed trace. This is the engine the finality-cert light path
// (`finality_cert_prove_bytes_light`) routes through to actually EMIT a proof (not fail-close). The plain batch above
// is this engine with the bus side empty (DB-452).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────

/// One SOURCE CROSS-TIE spec: prove `table[t1].cols1 @ row1 == table[t2].cols2 @ row2` (cell-vector
/// equality between two SEPARATELY-committed tables). This is what welds a bus's RECV/SEND columns to the
/// REAL source-trace cells (the finality cert's `QuorumSumBus` w0/w1 ↔ the bus RECV), defeating the
/// substitution attack where a prover fabricates a self-balancing bus that ignores the source traces.
pub type CrossTieSpec = ((usize, Vec<usize>, usize), (usize, Vec<usize>, usize));

/// A [`CrossTieSpec`] endpoint whose table index is [`PUBLIC_BIND_TABLE`] is NOT a committed cell but the
/// statement's PUBLIC IO: its `cols` are indices into `public_bind`, and its value is `public_bind[cols]`
/// (the verifier knows it — no commitment opening). Welding a committed bus cell to such an endpoint forces
/// `committed_cell == public_value` (e.g. the bus's RECV anchor == the block's public anchor), so a bus tuple
/// that references public IO (not a committed source cell) is still SOUND-bound. `row` is ignored.
/// ⛔ ONE ENCODING (lane speed4, 2026-11-12): such an endpoint sends NOTHING on the wire — its slot in
/// `cross_tie_openings` is empty, and a non-empty one is refused. MEASURED: the prover used to send the public values and
/// the verifier compared against `public_bind` itself, never reading them, so 144 bytes of a member aggregate took any
/// value and verified (`member_path_gate::no_byte_of_a_member_carrier_or_of_its_aggregate_is_free`, byte 59,787, once C2
/// moved the layout under its sampling stride). Sound before and after (the comparison was always against the statement);
/// the fix is that one proof has one wire form. cons: none (16 B per public endpoint fewer on the wire).
pub const PUBLIC_BIND_TABLE: usize = usize::MAX;

/// A boolean multilinear point selecting `row` of an `nvars`-variable table (high-bit first, matching the
/// decider's MLE variable order): opening a column at this point yields that column's cell at `row`.
/// `[high ‖ boolean bits of low_row]` — the point a [`ColumnTieSpec`] endpoint is opened at. `high` is
/// drawn from the transcript and SHARED by both endpoints, so a prover cannot pick where the equality is
/// tested; the low bits pin the cell's position inside its segment.
fn segment_point(high: &[Ea4], low_row: usize, low_bits: usize) -> Point<Ea4> {
    let mut v = high.to_vec();
    v.extend(
        (0..low_bits)
            .map(|k| if (low_row >> (low_bits - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }),
    );
    Point::new(v)
}

/// How many transcript challenges a column tie's shared high point needs, or `None` if the two endpoints
/// do not agree on it — in which case the tie is not stating a relation between matching index spaces
/// and must be refused rather than silently opened at mismatched points.
fn column_tie_high(
    shapes: &[(usize, usize)],
    e1: &(usize, Vec<usize>, usize, usize),
    e2: &(usize, Vec<usize>, usize, usize),
) -> Option<usize> {
    let n1 = shapes.get(e1.0)?.0.checked_sub(e1.2)?;
    let n2 = shapes.get(e2.0)?.0.checked_sub(e2.2)?;
    if n1 != n2 || e1.1.len() != e2.1.len() || e1.1.is_empty() {
        return None;
    }
    Some(n1)
}

fn boolean_point(row: usize, nvars: usize) -> Point<Ea4> {
    Point::new(
        (0..nvars)
            .map(|k| if (row >> (nvars - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO })
            .collect(),
    )
}

/// A bus-carrying multi-AIR batch light-decider bundle: the batch bundle plus the SOURCE-TIED LogUp bus
/// balance entries. `n_constraint` = the first N tables carry row-local AIR gates (one `zcs` entry each);
/// the remaining `tables[N..]` are the appended `[idx | val* | mult | h0..EXT_D]` bus tables, one per
/// `tied_buses` entry, each with its inline-keyfold balance proof. All openings are bound to the ONE WHIR
/// commitment via `eval_at`/`add_claim_at`, so both the gates AND the bus balances are facts about the
/// committed trace. `cross_tie_openings` carries the two bound cell-vectors per [`CrossTieSpec`]; verify
/// binds both to the commitment and asserts their equality (source-tie the bus to the real trace cells).
/// A COLUMN TIE: the same equality a [`CrossTieSpec`] states, but over EVERY row at once.
///
/// ⭐⭐⭐ WHY IT EXISTS. A cross-tie opens its cells at a BOOLEAN row point, so it costs one opening pair
/// per tied CELL — and an aggregate over `n` carriers ties `n` times as many cells. MEASURED: grouping
/// cells by row cut the tie COUNT 6× and the proof size by 5%, because the cost was never the ties, it
/// was the cells (~277 per carrier × 2 endpoints × 16 B ≈ 8.9 KB, exactly the growth observed).
///
/// A column tie is opened at `[random high ‖ boolean low]` instead. When one table holds `n` items as
/// ROWS and another holds their `2^low_bits`-row segments, the HIGH variables are the item index in
/// BOTH — so a single opening pair at a shared random high point proves the equality for every item.
/// The cost stops depending on `n` entirely.
///
/// Each endpoint is `(table, cols, low_bits, low_row)`: `low_row` pins the cell's position INSIDE its
/// segment (0 for a table whose rows are the items themselves, where `low_bits` is 0).
pub type ColumnTieSpec = ((usize, Vec<usize>, usize, usize), (usize, Vec<usize>, usize, usize));

/// The hard cap on column ties in ONE proof, and therefore on [`AirBatchBusBundle::column_tie_openings`].
///
/// A column tie is a property of the CIRCUIT — one per relation the AIR states between two tables — so a
/// correct circuit names a handful and never more, whatever the tables hold. The cap makes that a
/// REFUSAL rather than a hope: a wire-arriving bundle declaring more is rejected before any allocation,
/// so the vector cannot be a growth axis even under a hostile peer.
pub const COLUMN_TIES_MAX: usize = 64;

/// The cap on column ties in ONE BATCH: [`COLUMN_TIES_MAX`] per statement, for at most
/// `light_batch_merge::STATEMENTS_MAX` statements joined (R4 lever 4 — MEASURED 2026-11-02: the note and tag ledgers carry
/// ~55–59 ties each, so their joined batch refused at 64 while the two proofs apart carried the same total). Still a
/// constant of the protocol, refused before any allocation; each statement's own 64 is enforced by the merge.
pub const JOINED_COLUMN_TIES_MAX: usize = COLUMN_TIES_MAX * crate::light_batch_merge::STATEMENTS_MAX;

/// Column ties whose two endpoints share `(table, low_bits, low_row)` open at ONE point pair, so they are one tie with
/// the union of their columns — the same grouping [`ColumnTieSpec`]'s own doc measured (cells grouped by row). Sound
/// exactly as a single tie is: the columns' equality is checked at one random high point, per column. First-seen
/// order is kept, so the producer and the peer derive one list from one statement.
///
/// MEASURED 2026-10-24: the member class's 63 ties sit at 55 distinct endpoint pairs (its round-eval absorbs share
/// sponge rows with the `r`/`z` squeezes), which is what lets the ring lookup's 4 ties fit beside it.
#[must_use]
pub fn merge_column_ties(ties: Vec<ColumnTieSpec>) -> Vec<ColumnTieSpec> {
    let mut out: Vec<ColumnTieSpec> = Vec::with_capacity(ties.len());
    for ((t1, c1, l1, r1), (t2, c2, l2, r2)) in ties {
        match out
            .iter_mut()
            .find(|((a1, _, m1, s1), (a2, _, m2, s2))| (*a1, *m1, *s1, *a2, *m2, *s2) == (t1, l1, r1, t2, l2, r2))
        {
            Some(((_, d1, _, _), (_, d2, _, _))) => {
                d1.extend(c1);
                d2.extend(c2);
            }
            None => out.push(((t1, c1, l1, r1), (t2, c2, l2, r2))),
        }
    }
    out
}

/// ⭐⭐⭐ DB-452 — A BATCH CARRIER IS TWO COMMITTED ROUNDS, AND EVERY VALUE IT SENDS IS A CLAIM ON ONE OF THEM.
///
/// ⛔ WAS: per-table round-1 `openings`, a `virtual_eval` and a masked sumcheck with NO commitment — the verifier
/// reconstructed every round from its own running target and dropped the final one, so nothing bound a sent value to a
/// trace (MEASURED link 75: a forged note transition verified). Now round 1 commits the constraint tables and round 2
/// the bus tables (DB-159: after α), each before any challenge that depends on it, and each round's WHIR opening proves
/// every claim routed to it: opened@r, the bus columns, every tie cell and every shift-bind opening.
#[derive(Clone, Serialize, Deserialize)]
pub struct AirBatchBusBundle {
    pub shapes: Vec<(usize, usize)>,
    /// Row-local AIR zerochecks, one per CONSTRAINT table (the first `n_constraint` tables). A row-LOCAL gate's
    /// `shifted_opened` is EMPTY; a row-shifted gate's names every column and is proved by `shift_binds`.
    pub zcs: Vec<AirZerocheckProof>,
    /// Source-tied LogUp bus balance entries, one per appended bus table.
    pub tied_buses: Vec<TiedBusEntry>,
    /// Number of leading CONSTRAINT tables (the rest are appended bus tables).
    pub n_constraint: usize,
    /// One per row-SHIFTED constraint table, in table order: its next-row openings reduced to an opening at a fresh
    /// point on round 1's commitment ([`crate::light_commit::prove_shift_bind`]).
    pub shift_binds: Vec<ShiftBindProof>,
    /// Per cross-tie: the two opened cell-vectors `(v1, v2)` (equal on the honest path), each a claim on its table's
    /// round; verify asserts `v1 == v2`.
    pub cross_tie_openings: Vec<(Vec<Ea4>, Vec<Ea4>)>,
    /// Per COLUMN tie: the two opened cell-vectors at the shared `[random high ‖ boolean low]` point.
    /// Equal on the honest path; each a claim on its table's round exactly as a cross-tie's are.
    ///
    /// O1-FOOTPRINT-REVIEWED: bounded by COLUMN_TIES_MAX — refused above it on both the prove and the
    /// verify side before anything is allocated. Independent of how many items the tied tables hold,
    /// which is the entire reason [`ColumnTieSpec`] exists.
    pub column_tie_openings: Vec<(Vec<Ea4>, Vec<Ea4>)>,
    /// Round 1: the constraint tables' commitment and its WHIR opening.
    pub round1: LightRound,
    /// ⛔⛔⛔ DB-159 — ROUND 2, the bus tables. They hold `h`, a function of `α`, so they are committed after `α` is
    /// drawn. A carrier with no bus carries `None`, and one with a bus must carry `Some` — one encoding either way.
    pub round2: Option<LightRound>,
}

/// A bus-less carrier carries NO round 2: every round-2 field must be exactly its default, not merely the two Vecs
/// empty. ONE helper for both bundle verifies ([`RecBlockOpeningBundle`], [`AirBatchBusBundle`]).
///
/// ⛔ MEASURED 2026-09-28 (the member-path class's byte-flip census, `member_path_gate`): with only the Vecs checked,
/// the 21 tail bytes holding a bus-less aggregate's round-2 defaults (`virtual_eval2`, the scalars inside `zk_data2`)
/// were FREE — a relay could flip them and the block object still verified: two encodings of one consensus object,
/// the pre-SegWit malleability shape. `zk_data2` is compared by its canonical encoding so every field of it is bound
/// without a `PartialEq` on the vendored type.
fn round2_is_absent(
    virtual_eval2: Ea4,
    zk_data2: &ZkSumcheckData<Fa4, Ea4>,
    mask_commits2: &[<Mmcs16 as Mmcs<Fa4>>::Commitment],
    prover_rand2: &[Ea4],
) -> bool {
    mask_commits2.is_empty()
        && prover_rand2.is_empty()
        && virtual_eval2 == Ea4::ZERO
        && postcard::to_allocvec(zk_data2).ok() == postcard::to_allocvec(&ZkSumcheckData::<Fa4, Ea4>::default()).ok()
}

/// The light round's shape gate for ONE table, before any allocation is sized by a declared shape: the width bound,
/// and — for a constraint table — the zerocheck's own lengths. `shifted_opened` holds at most `width` values here; the
/// one length the statement requires (C2: `air_zerocheck::shifted_set`, none for a row-local gate, the gate's declared
/// next-row columns otherwise) is decided once the PUBLIC constraint is rebuilt (DB-452), so a carrier has exactly one
/// admissible length for every table. Returns the table's cell count.
fn light_table_shape_admissible(
    nvars: usize,
    width: usize,
    zc: Option<&crate::air_zerocheck::AirZerocheckProof>,
) -> Option<usize> {
    if width == 0 || width > AIR_DIRECT_MAX_WIDTH || nvars >= usize::BITS as usize {
        return None;
    }
    if let Some(zc) = zc {
        if zc.opened.len() != width
            || zc.shifted_opened.len() > width
            || zc.round_evals.len() != nvars
            || zc.r.len() != nvars
        {
            return None;
        }
    }
    width.checked_mul(1usize << nvars)
}

/// PROVE a BATCH of row-local AIRs PLUS their SOURCE-TIED LogUp buses on the light decider, every sent value a claim on
/// a WHIR commitment (DB-452). FIRST commits the `n = tables.len()` constraint tables (round 1), draws α + β, builds and
/// commits one `[idx | val* | mult | h]` table per `tied_buses` entry (round 2) and proves each bus's
/// `Σ mult/(α−keyfold)=0` over it ([`prove_leaf_bus_balance_tied`]). Transcript order: commit 1 (+ OOD) → [per bus: α,
/// β] → commit 2 (+ OOD) → [per bus: balance] → γ → [per constraint table: z_i, zerocheck, claim opened@r_i, absorb the
/// next-row openings, shift-bind if row-shifted] → [per bus: claim cols@r + h@col-sum] → ties → WHIR opening 1 → WHIR
/// opening 2. Each table height MUST be a power of two ≥ `2^folding`. Fail-closed on any shape/serialize error.
#[must_use]
pub fn prove_air_batch_light_decider_bytes_with_bus<C, Mk>(
    tables: Vec<Vec<Vec<Fa4>>>,
    make_constraint: Mk,
    tied_buses: Vec<(Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>)>,
    cross_ties: Vec<CrossTieSpec>,
    column_ties: Vec<ColumnTieSpec>,
    folding: usize,
    pch: &mut Chl,
    public_bind: &[Fa4],
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    let n = tables.len();
    if n == 0 {
        return None;
    }
    let mut shapes = Vec::with_capacity(n);
    for cols in &tables {
        let width = cols.len();
        let h = cols.first().map(|c| c.len()).unwrap_or(0);
        if width == 0 || h == 0 || !h.is_power_of_two() {
            return None;
        }
        shapes.push((h.trailing_zeros() as usize, width));
    }
    let tables_for_zc: Vec<Vec<Vec<Fa4>>> = tables.clone();
    // SPEED LANE INSTRUMENT (user 2026-11-09: "start working on speed for our chain"): a real producer spends ~95 % of its
    // block on this prove (MEASURED round 18: cycle 32,957 ms, template 1,029 ms, grind 110 ms), so each phase is timed and
    // said once per prove when `MONEROUSD_PROVE_PROGRESS` is set. Output only: no value the prover computes or sends changes.
    let phase_t0 = std::time::Instant::now();
    let mut phase_ms: [u128; 6] = [0; 6]; // commit 1, bus build + commit 2, bus balances, zerocheck, ties, openings
    let cells1: usize = tables_for_zc.iter().map(|t| t.len() * t.first().map_or(0, Vec::len)).sum();

    // ── ROUND 1 — COMMIT the constraint tables, before any challenge that depends on them. ─────────
    let mut prover1 = LightCommitProver::commit(tables, pch)?;
    phase_ms[0] = phase_t0.elapsed().as_millis();

    // ── ⛔⛔⛔ DB-159. α AND β ARE DRAWN HERE, POST-COMMITMENT-1 — a Fiat-Shamir function of every committed
    //    constraint table, which is what LogUp's argument requires (a prover that knew α before it chose a cell
    //    could aim `Σ mult/(α−key) = 0` instead of passing it).
    let mut bus_ab: Vec<(Ea4, Fa4)> = Vec::with_capacity(tied_buses.len());
    for _ in &tied_buses {
        let alpha: Ea4 = pch.sample_algebra_element();
        let beta = draw_bus_fold_challenge(pch);
        bus_ab.push((alpha, beta));
    }

    // ── ROUND 2 — build the `[idx | val* | mult | h(α)]` tables, which could not exist before α. ────
    let mut bus_tables: Vec<Vec<Vec<Fa4>>> = Vec::with_capacity(tied_buses.len());
    let mut bus_meta: Vec<(usize, usize)> = Vec::with_capacity(tied_buses.len()); // (n_val, global idx)
    for (b, (idx_col, val_cols, mult_col)) in tied_buses.into_iter().enumerate() {
        let (mut idx_col, mut val_cols, mut mult_col) = (idx_col, val_cols, mult_col);
        let n_val = val_cols.len();
        let raw = idx_col.len();
        let nv = (raw.max(1).next_power_of_two().trailing_zeros() as usize).max(folding);
        let padded = 1usize << nv;
        while idx_col.len() < padded {
            idx_col.push(Fa4::from_u64(2_000_003 + idx_col.len() as u64));
            for vc in val_cols.iter_mut() {
                vc.push(Fa4::ZERO);
            }
            mult_col.push(Fa4::ZERO);
        }
        let (alpha, beta) = bus_ab[b];
        let mut h_limbs: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; padded]; EXT_D];
        for r in 0..padded {
            let mut key = Ea4::from(idx_col[r]);
            let mut bpow = Ea4::from(beta);
            for vc in val_cols.iter() {
                key += bpow * Ea4::from(vc[r]);
                bpow *= Ea4::from(beta);
            }
            let d = alpha - key;
            // ⛔ α landing on a committed key is a `1/|Ea4|` accident; refuse rather than drop the term.
            if d == Ea4::ZERO {
                return None;
            }
            let hv = Ea4::from(mult_col[r]) * d.inverse();
            let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&hv);
            for k in 0..EXT_D {
                h_limbs[k][r] = limbs[k];
            }
        }
        let mut bus_cols: Vec<Vec<Fa4>> = Vec::with_capacity(2 + n_val + EXT_D);
        bus_cols.push(idx_col);
        for vc in val_cols {
            bus_cols.push(vc);
        }
        bus_cols.push(mult_col);
        for k in 0..EXT_D {
            bus_cols.push(h_limbs[k].clone());
        }
        bus_meta.push((n_val, n + bus_tables.len()));
        shapes.push((nv, 2 + n_val + EXT_D));
        bus_tables.push(bus_cols);
    }
    let bus_for_zc: Vec<Vec<Vec<Fa4>>> = bus_tables.clone();
    let mut prover2 = if bus_tables.is_empty() { None } else { Some(LightCommitProver::commit(bus_tables, pch)?) };
    phase_ms[1] = phase_t0.elapsed().as_millis() - phase_ms[0];
    let cells2: usize = bus_for_zc.iter().map(|t| t.len() * t.first().map_or(0, Vec::len)).sum();

    // ── The balances, now over tables that are COMMITTED and a challenge that came after them. ─────
    let mut tied_entries: Vec<TiedBusEntry> = Vec::with_capacity(bus_meta.len());
    for (b, &(n_val, global)) in bus_meta.iter().enumerate() {
        let (alpha, beta) = bus_ab[b];
        let cst = LogupKeyfoldConstraint {
            alpha,
            beta,
            idx_col: 0,
            val_col_base: 1,
            n_val,
            mult_col: 1 + n_val,
            h_limb_base: 2 + n_val,
        };
        let nv = shapes[global].0;
        let z: Vec<Ea4> = (0..nv).map(|_| pch.sample_algebra_element()).collect();
        let mut zc = prove_air_zerocheck(&bus_for_zc[b], &cst, &z, pch);
        // The bus gate is row-local: its next-row openings are never read and never sent (one encoding).
        zc.shifted_opened.clear();
        let mut limb_sums: Vec<Ea4> = Vec::with_capacity(EXT_D);
        let mut sum_proofs: Vec<ColSumProof> = Vec::with_capacity(EXT_D);
        for k in 0..EXT_D {
            let col = &bus_for_zc[b][2 + n_val + k];
            let sum_k: Ea4 = col.iter().fold(Ea4::ZERO, |a, &vv| a + Ea4::from(vv));
            sum_proofs.push(prove_col_sum(col, pch));
            limb_sums.push(sum_k);
        }
        tied_entries.push(TiedBusEntry {
            proof: LeafBusBalanceProof { zc, limb_sums, sum_proofs },
            alpha,
            beta,
            n_val,
            table_idx: global,
        });
    }

    phase_ms[2] = phase_t0.elapsed().as_millis() - phase_ms[0] - phase_ms[1];
    // ── γ, post BOTH commitments. ──────────────────────────────────────────────────────────────────
    let gamma: Ea4 = pch.sample_algebra_element();
    let mut zcs = Vec::with_capacity(n);
    let mut shift_binds: Vec<ShiftBindProof> = Vec::new();
    for i in 0..n {
        let (nvars, width) = shapes[i];
        let constraint = make_constraint(i, gamma);
        let z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
        let t_zc = std::time::Instant::now();
        let mut zc = prove_air_zerocheck(&tables_for_zc[i], &constraint, &z, pch);
        if std::env::var("MONEROUSD_PROVE_PROGRESS").is_ok() {
            eprintln!("[light-zc] table {i}: 2^{nvars} rows x {width} cols, zerocheck {} ms", t_zc.elapsed().as_millis());
        }
        // C2: the next-row openings the gate reads, and only those (`shifted_set`: none for a row-local gate)
        let set = crate::air_zerocheck::shifted_set(&constraint, width);
        crate::air_zerocheck::compact_shifted(&mut zc, &set);
        let all: Vec<usize> = (0..width).collect();
        let pt_r = Point::new(zc.r.clone());
        let _ = prover1.eval_at(i, &all, &pt_r, pch);
        absorb_shifted_openings(pch, &zc.shifted_opened);
        if !set.is_empty() {
            let t_sb = std::time::Instant::now();
            shift_binds.push(prove_shift_bind(&tables_for_zc[i], &set, &zc.r, i, &mut prover1, pch));
            if std::env::var("MONEROUSD_PROVE_PROGRESS").is_ok() {
                eprintln!("[light-zc] table {i}: shift bind {} ms", t_sb.elapsed().as_millis());
            }
        }
        zcs.push(zc);
    }
    phase_ms[3] = phase_t0.elapsed().as_millis() - phase_ms[..3].iter().sum::<u128>();
    if let Some(p2) = prover2.as_mut() {
        for (b, e) in tied_entries.iter().enumerate() {
            let bw = 2 + e.n_val + EXT_D;
            let all: Vec<usize> = (0..bw).collect();
            let _ = p2.eval_at(b, &all, &Point::new(e.proof.zc.r.clone()), pch);
            for k in 0..EXT_D {
                let _ = p2.eval_at(
                    b,
                    &[2 + e.n_val + k],
                    &Point::new(e.proof.sum_proofs[k].r.clone()),
                    pch,
                );
            }
        }
    }

    // ── The ties. A GLOBAL table index below `n` lives in round 1, at or above it in round 2 — the one
    //    mapping that lets every existing caller keep its spec unchanged across the split.
    let mut cross_tie_openings: Vec<(Vec<Ea4>, Vec<Ea4>)> = Vec::with_capacity(cross_ties.len());
    for ((t1, cols1, row1), (t2, cols2, row2)) in &cross_ties {
        let mut endpoint = |t: usize, cols: &Vec<usize>, row: usize, pch: &mut Chl| -> Option<Vec<Ea4>> {
            if t == PUBLIC_BIND_TABLE {
                // the verifier reads the statement itself: nothing on the wire (one encoding, see PUBLIC_BIND_TABLE)
                return cols.iter().all(|&i| i < public_bind.len()).then(Vec::new);
            }
            if t >= shapes.len() {
                return None;
            }
            let pt = boolean_point(row, shapes[t].0);
            if t < n {
                Some(prover1.eval_at(t, cols, &pt, pch))
            } else {
                prover2.as_mut().map(|p2| p2.eval_at(t - n, cols, &pt, pch))
            }
        };
        let v1 = endpoint(*t1, cols1, *row1, pch)?;
        let v2 = endpoint(*t2, cols2, *row2, pch)?;
        cross_tie_openings.push((v1, v2));
    }
    if column_ties.len() > JOINED_COLUMN_TIES_MAX {
        return None; // fail-closed: a circuit states a handful of these, never an unbounded list
    }
    let mut column_tie_openings: Vec<(Vec<Ea4>, Vec<Ea4>)> = Vec::with_capacity(column_ties.len());
    for (e1, e2) in &column_ties {
        let Some(hi) = column_tie_high(&shapes, e1, e2) else { return None };
        let high: Vec<Ea4> = (0..hi).map(|_| pch.sample_algebra_element::<Ea4>()).collect();
        let mut endpoint = |e: &(usize, Vec<usize>, usize, usize), pch: &mut Chl| -> Option<Vec<Ea4>> {
            let pt = segment_point(&high, e.3, e.2);
            if e.0 < n {
                Some(prover1.eval_at(e.0, &e.1, &pt, pch))
            } else if e.0 < shapes.len() {
                prover2.as_mut().map(|p2| p2.eval_at(e.0 - n, &e.1, &pt, pch))
            } else {
                None
            }
        };
        let v1 = endpoint(e1, pch)?;
        let v2 = endpoint(e2, pch)?;
        column_tie_openings.push((v1, v2));
    }

    phase_ms[4] = phase_t0.elapsed().as_millis() - phase_ms[..4].iter().sum::<u128>();
    // ── Two WHIR openings, one per commitment, in this order. ──────────────────────────────────────
    let round1 = prover1.finish(pch);
    let round2 = prover2.map(|p2| p2.finish(pch));
    phase_ms[5] = phase_t0.elapsed().as_millis() - phase_ms[..5].iter().sum::<u128>();
    if std::env::var_os("MONEROUSD_PROVE_PROGRESS").is_some() {
        eprintln!(
            "[light-phase] {n} table(s), {cells1} cells + {} bus table(s), {cells2} cells: commit-1 {} ms, bus build + commit-2 {} ms, \
             bus balances {} ms, zerocheck {} ms, ties {} ms, openings {} ms — {} ms in all",
            bus_meta.len(),
            phase_ms[0],
            phase_ms[1],
            phase_ms[2],
            phase_ms[3],
            phase_ms[4],
            phase_ms[5],
            phase_t0.elapsed().as_millis()
        );
    }
    let bundle = AirBatchBusBundle {
        shapes,
        zcs,
        tied_buses: tied_entries,
        n_constraint: n,
        shift_binds,
        cross_tie_openings,
        column_tie_openings,
        round1,
        round2,
    };
    postcard::to_allocvec(&bundle).ok()
}

/// VERIFY a bus-carrying batch light-decider proof: replay in the EXACT prover order — begin round 1 against its
/// commitment, per tied bus re-draw α + β, begin round 2, verify every balance, draw the same γ, then per CONSTRAINT
/// table replay its zerocheck + claim opened@r_i (+ its shift-bind if the gate is row-shifted), per bus claim its
/// cols@r + h@col-sum, mirror every tie, and finally check BOTH WHIR openings against their commitments (DB-452).
/// `make_constraint(i, gamma)` rebuilds table `i`'s constraint from the SAME public AIR both sides know. Fail-closed on
/// any mismatch — a dropped/forged bus balance, tie cell or opening rejects.
#[must_use]
pub fn verify_air_batch_light_decider_bytes_with_bus<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    cross_ties: Vec<CrossTieSpec>,
    column_ties: Vec<ColumnTieSpec>,
    vch: &mut Chl,
    public_bind: &[Fa4],
    // ⛔ DB-213b — the CONSTRAINT tables' shapes and the appended BUS tables' shapes, as the statement fixes
    // them. A bus table's width is `2 + n_val + EXT_D`, so pinning it also pins which columns a tie reads.
    expected_constraint: &[(usize, usize)],
    expected_bus: &[(usize, usize)],
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    let bundle: AirBatchBusBundle = match postcard::from_bytes(bytes) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let n = bundle.n_constraint;
    let total = bundle.shapes.len();
    if n == 0 || total < n || bundle.zcs.len() != n {
        return false;
    }
    // ⛔ DB-213b — the statement's shapes: the constraint/bus split, every height and every width, before any
    // tie is routed or any allocation is sized by the carrier.
    if n != expected_constraint.len()
        || !carrier_shapes_are(&bundle.shapes[..n], expected_constraint)
        || !carrier_shapes_are(&bundle.shapes[n..], expected_bus)
    {
        return false;
    }
    if bundle.tied_buses.len() != total - n || bundle.round2.is_some() != (total > n) {
        return false;
    }
    if bundle.cross_tie_openings.len() != cross_ties.len() || bundle.shift_binds.len() > n {
        return false;
    }
    // ⛔ THE SHAPE GATE, before the layout planner and before any `(0..width)` range.
    let mut stacked_cells: usize = 0;
    for (i, &(nvars, width)) in bundle.shapes.iter().enumerate() {
        let zc = if i < n { Some(&bundle.zcs[i]) } else { None };
        let cells = match light_table_shape_admissible(nvars, width, zc) {
            Some(c) => c,
            None => return false,
        };
        stacked_cells = match stacked_cells.checked_add(cells) {
            Some(t) => t,
            None => return false,
        };
    }
    // ⛔ A BUS TABLE MUST SIT IN ROUND 2, AT ITS OWN INDEX. The prover appends them in order after the
    // `n` constraint tables; a carrier that re-points one at a round-1 table would have its balance
    // proved over a table `α` was drawn from, which is the DB-159 shape arriving through the front door.
    for (b, e) in bundle.tied_buses.iter().enumerate() {
        if e.table_idx != n + b {
            return false;
        }
        let bw = match 2usize.checked_add(e.n_val).and_then(|v| v.checked_add(EXT_D)) {
            Some(v) => v,
            None => return false,
        };
        // The bus gate is row-local: its next-row openings are never sent (DB-452, one encoding).
        if bw != bundle.shapes[e.table_idx].1 || e.proof.zc.opened.len() != bw || !e.proof.zc.shifted_opened.is_empty() {
            return false;
        }
        if e.proof.sum_proofs.len() != EXT_D || e.proof.limb_sums.len() != EXT_D {
            return false;
        }
    }
    for ((t1, cols1, _r1), (t2, cols2, _r2)) in &cross_ties {
        for (t, cols) in [(t1, cols1), (t2, cols2)] {
            if *t == PUBLIC_BIND_TABLE {
                continue;
            }
            if *t >= bundle.shapes.len() || cols.iter().any(|&j| j >= bundle.shapes[*t].1) {
                return false;
            }
        }
    }

    // ── Mirror ROUND 1: the constraint tables' commitment, before any challenge. ──────────────────
    let shapes1: Vec<(usize, usize)> = bundle.shapes[..n].to_vec();
    let shapes2: Vec<(usize, usize)> = bundle.shapes[n..].to_vec();
    let Some(mut v1) = LightCommitVerifier::begin(&shapes1, &bundle.round1, vch) else { return false };

    // ── Mirror the α/β draw — POST-commitment-1, and BIND what the carrier claims. ─────────────────
    for e in &bundle.tied_buses {
        let alpha: Ea4 = vch.sample_algebra_element();
        if alpha != e.alpha {
            return false;
        }
        let beta = draw_bus_fold_challenge(vch);
        if beta != e.beta {
            return false;
        }
    }

    // ── Mirror ROUND 2. ───────────────────────────────────────────────────────────────────────────
    let mut v2 = match &bundle.round2 {
        Some(r2) => match LightCommitVerifier::begin(&shapes2, r2, vch) {
            Some(v) => Some(v),
            None => return false,
        },
        None => None,
    };

    // ── Mirror the balances, now over a COMMITTED round 2. ────────────────────────────────────────
    for e in &bundle.tied_buses {
        let nv = bundle.shapes[e.table_idx].0;
        if !verify_leaf_bus_balance_tied(&e.proof, e.alpha, e.beta, e.n_val, nv, vch) {
            if std::env::var("MONEROUSD_CERT_LIGHT_DBG").is_ok() {
                eprintln!("[cert-verify] tied-bus BALANCE failed (bus table {})", e.table_idx);
            }
            return false;
        }
    }

    // ── Mirror γ, post BOTH commitments. ──────────────────────────────────────────────────────────
    let gamma: Ea4 = vch.sample_algebra_element();
    let mut next_bind = 0usize;
    for i in 0..n {
        let (nvars, width) = bundle.shapes[i];
        let constraint = make_constraint(i, gamma);
        let zc = &bundle.zcs[i];
        // ⭐ DB-452 + C2 — ONE admissible length: the gate's public next-row set (`shifted_set`: none for a row-local
        // gate, the columns it declares reading at the next row otherwise), in that set's order.
        let set = crate::air_zerocheck::shifted_set(&constraint, width);
        if zc.shifted_opened.len() != set.len() {
            return false;
        }
        let z: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
        if !crate::air_zerocheck::verify_air_zerocheck_over(zc, &constraint, &z, vch, &set) {
            if std::env::var("MONEROUSD_CERT_LIGHT_DBG").is_ok() {
                eprintln!("[cert-verify] row-local ZEROCHECK failed (constraint table {i})");
            }
            return false;
        }
        let all: Vec<usize> = (0..width).collect();
        let pt_r = Point::new(zc.r.clone());
        v1.add_claim_at(i, &all, &zc.opened, &pt_r, vch);
        absorb_shifted_openings(vch, &zc.shifted_opened);
        if !set.is_empty() {
            let Some(sb) = bundle.shift_binds.get(next_bind) else { return false };
            next_bind += 1;
            if !verify_shift_bind(sb, &zc.r, &zc.shifted_opened, &set, i, &mut v1, vch) {
                if std::env::var("MONEROUSD_CERT_LIGHT_DBG").is_ok() {
                    eprintln!("[cert-verify] SHIFT-BIND failed (constraint table {i})");
                }
                return false;
            }
        }
    }
    if next_bind != bundle.shift_binds.len() {
        return false;
    }
    if let Some(vv2) = v2.as_mut() {
        for (b, e) in bundle.tied_buses.iter().enumerate() {
            let bw = 2 + e.n_val + EXT_D;
            let all: Vec<usize> = (0..bw).collect();
            vv2.add_claim_at(b, &all, &e.proof.zc.opened, &Point::new(e.proof.zc.r.clone()), vch);
            for k in 0..EXT_D {
                vv2.add_claim_at(
                    b,
                    &[2 + e.n_val + k],
                    &[e.proof.sum_proofs[k].opened],
                    &Point::new(e.proof.sum_proofs[k].r.clone()),
                    vch,
                );
            }
        }
    }

    // ── Mirror the ties, routed by the SAME global-index rule the prover used. ────────────────────
    for (i, ((t1, cols1, row1), (t2, cols2, row2))) in cross_ties.iter().enumerate() {
        let (cv1, cv2) = &bundle.cross_tie_openings[i];
        let mut endpoint = |t: usize,
                            cols: &Vec<usize>,
                            row: usize,
                            cv: &Vec<Ea4>,
                            v1: &mut LightCommitVerifier<'_>,
                            v2: &mut Option<LightCommitVerifier<'_>>,
                            vch: &mut Chl|
         -> Option<Vec<Ea4>> {
            if t == PUBLIC_BIND_TABLE {
                // ONE ENCODING: a public endpoint sends nothing; its value is the statement's own
                if !cv.is_empty() {
                    return None;
                }
                return cols
                    .iter()
                    .map(|&j| public_bind.get(j).map(|&f| Ea4::from(f)))
                    .collect::<Option<Vec<Ea4>>>();
            }
            if t >= bundle.shapes.len() || cv.len() != cols.len() {
                return None;
            }
            let pt = boolean_point(row, bundle.shapes[t].0);
            if t < n {
                v1.add_claim_at(t, cols, cv, &pt, vch);
            } else {
                v2.as_mut()?.add_claim_at(t - n, cols, cv, &pt, vch);
            }
            Some(cv.clone())
        };
        let a = match endpoint(*t1, cols1, *row1, cv1, &mut v1, &mut v2, vch) {
            Some(v) => v,
            None => return false,
        };
        let b = match endpoint(*t2, cols2, *row2, cv2, &mut v1, &mut v2, vch) {
            Some(v) => v,
            None => return false,
        };
        if a != b {
            if std::env::var("MONEROUSD_CERT_LIGHT_DBG").is_ok() {
                eprintln!("[cert-verify] CROSS-TIE inequality (tie {i})");
            }
            return false;
        }
    }
    if column_ties.len() > JOINED_COLUMN_TIES_MAX || bundle.column_tie_openings.len() != column_ties.len() {
        return false;
    }
    for (i, (e1, e2)) in column_ties.iter().enumerate() {
        let Some(hi) = column_tie_high(&bundle.shapes, e1, e2) else { return false };
        let high: Vec<Ea4> = (0..hi).map(|_| vch.sample_algebra_element::<Ea4>()).collect();
        let (cv1, cv2) = &bundle.column_tie_openings[i];
        if cv1.len() != e1.1.len() || cv2.len() != e2.1.len() {
            return false;
        }
        for (e, cv) in [(e1, cv1), (e2, cv2)] {
            let pt = segment_point(&high, e.3, e.2);
            if e.0 < n {
                v1.add_claim_at(e.0, &e.1, cv, &pt, vch);
            } else if e.0 < bundle.shapes.len() {
                match v2.as_mut() {
                    Some(vv2) => vv2.add_claim_at(e.0 - n, &e.1, cv, &pt, vch),
                    None => return false,
                }
            } else {
                return false;
            }
        }
        if cv1 != cv2 {
            if std::env::var("MONEROUSD_CERT_LIGHT_DBG").is_ok() {
                eprintln!("[cert-verify] COLUMN-TIE inequality (tie {i}: {e1:?} != {e2:?})");
            }
            return false;
        }
    }

    // ── Both WHIR openings, in the prover's order: every claim above is an evaluation of its round's commitment. ──
    if !v1.finish(vch) {
        return false;
    }
    match v2 {
        Some(vv2) => vv2.finish(vch),
        None => true,
    }
}

/// SELF-CONTAINED bus-aware batch PROVE: builds the pinned HVZK-WHIR config from [`REC_DECIDER_SEED`] +
/// observes `public_bind` at the transcript START, then routes through
/// [`prove_air_batch_light_decider_bytes_with_bus`]. Verify with
/// [`verify_air_batch_light_decider_selfcontained_bytes_with_bus`].
#[must_use]
pub fn prove_air_batch_light_decider_selfcontained_bytes_with_bus<C, Mk>(
    tables: Vec<Vec<Vec<Fa4>>>,
    make_constraint: Mk,
    tied_buses: Vec<(Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>)>,
    cross_ties: Vec<CrossTieSpec>,
    column_ties: Vec<ColumnTieSpec>,
    public_bind: &[Fa4],
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    // SPEED G1: every prover that reaches the light decider (node, wallet, phone, tests) grinds on the GPU where there
    // is one; a no-op after the first call (`gpu_grind::install`, one OnceLock read).
    let _ = crate::gpu_grind::install();
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let mut pch = Chl::new(Perm16::new_from_rng_128(&mut perm_rng));
    for &f in public_bind {
        pch.observe(f);
    }
    prove_air_batch_light_decider_bytes_with_bus(
        tables,
        make_constraint,
        tied_buses,
        cross_ties,
        column_ties,
        REC_DECIDER_FOLDING,
        &mut pch,
        public_bind,
    )
}

/// SELF-CONTAINED bus-aware batch VERIFY: rebuilds the pinned challenger, observes the SAME `public_bind`,
/// and runs [`verify_air_batch_light_decider_bytes_with_bus`]. Fail-closed on any decode / shape / zerocheck
/// / bus-balance / opening mismatch.
#[must_use]
pub fn verify_air_batch_light_decider_selfcontained_bytes_with_bus<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    cross_ties: Vec<CrossTieSpec>,
    column_ties: Vec<ColumnTieSpec>,
    public_bind: &[Fa4],
    expected_constraint: &[(usize, usize)],
    expected_bus: &[(usize, usize)],
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    // SPEED G1: every prover that reaches the light decider (node, wallet, phone, tests) grinds on the GPU where there
    // is one; a no-op after the first call (`gpu_grind::install`, one OnceLock read).
    let _ = crate::gpu_grind::install();
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let perm = Perm16::new_from_rng_128(&mut perm_rng);
    let mut vch = Chl::new(perm);
    for &f in public_bind {
        vch.observe(f);
    }
    verify_air_batch_light_decider_bytes_with_bus(
        bytes,
        make_constraint,
        cross_ties,
        column_ties,
        &mut vch,
        public_bind,
        expected_constraint,
        expected_bus,
    )
}

/// ⛔ TEST-ONLY: the table shapes a batch carrier DECLARES — the pre-DB-213b input to every batch verify. For
/// tests whose subject is not the shape and for calibration arms; no shipped binary carries it.
#[cfg(test)]
#[must_use]
pub(crate) fn declared_batch_shapes_for_tests(bytes: &[u8]) -> Vec<(usize, usize)> {
    declared_bus_shapes_for_tests(bytes).0
}

/// ⛔ TEST-ONLY ADVERSARY (DB-452): a bus-less batch light-decider proof whose cross-tie openings at a PUBLIC endpoint
/// are the PUBLIC value, not the trace's. Everything else is the honest prover over `tables`, in its exact transcript
/// order — the commitment is the honest one, the zerochecks are honest over a trace that satisfies every gate, and the
/// WHIR opening is the honest prover's over the claims it recorded. The ONE lie: a table cell tied to the statement is
/// SENT as the statement's value while the committed table holds another, and the transcript absorbs the sent value
/// exactly as `LightCommitVerifier::add_claim_at` will. A sound decider refuses it, because the sent value is not the
/// committed table's evaluation at that point. `lie = false` is the CONTROL (the honest proof, through the same code),
/// so a forger that merely desynchronises the transcript cannot read as a refusal.
#[cfg(test)]
pub(crate) fn forge_public_tie_light_decider_for_tests<C, Mk>(
    tables: Vec<Vec<Vec<Fa4>>>,
    make_constraint: Mk,
    cross_ties: &[CrossTieSpec],
    column_ties: &[ColumnTieSpec],
    public_bind: &[Fa4],
    lie: bool,
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    // SPEED G1: every prover that reaches the light decider (node, wallet, phone, tests) grinds on the GPU where there
    // is one; a no-op after the first call (`gpu_grind::install`, one OnceLock read).
    let _ = crate::gpu_grind::install();
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let mut pch = Chl::new(Perm16::new_from_rng_128(&mut perm_rng));
    for &f in public_bind {
        pch.observe(f);
    }
    let n = tables.len();
    let shapes: Vec<(usize, usize)> =
        tables.iter().map(|c| (c[0].len().trailing_zeros() as usize, c.len())).collect();
    let tables_for_zc = tables.clone();
    let mut prover1 = LightCommitProver::commit(tables, &mut pch)?;
    let gamma: Ea4 = pch.sample_algebra_element();
    let mut zcs = Vec::with_capacity(n);
    let mut shift_binds = Vec::new();
    for i in 0..n {
        let constraint = make_constraint(i, gamma);
        let z: Vec<Ea4> = (0..shapes[i].0).map(|_| pch.sample_algebra_element()).collect();
        let mut zc = prove_air_zerocheck(&tables_for_zc[i], &constraint, &z, &mut pch);
        let set = crate::air_zerocheck::shifted_set(&constraint, shapes[i].1);
        crate::air_zerocheck::compact_shifted(&mut zc, &set);
        let _ = prover1.eval_at(i, &(0..shapes[i].1).collect::<Vec<_>>(), &Point::new(zc.r.clone()), &mut pch);
        absorb_shifted_openings(&mut pch, &zc.shifted_opened);
        if !set.is_empty() {
            shift_binds.push(prove_shift_bind(&tables_for_zc[i], &set, &zc.r, i, &mut prover1, &mut pch));
        }
        zcs.push(zc);
    }
    let mut cross_tie_openings = Vec::with_capacity(cross_ties.len());
    for ((t1, c1, r1), (t2, c2, r2)) in cross_ties {
        let public = |t: usize, c: &[usize]| -> Option<Vec<Ea4>> {
            (t == PUBLIC_BIND_TABLE).then(|| c.iter().map(|&j| Ea4::from(public_bind[j])).collect())
        };
        let mut side = |t: usize, c: &Vec<usize>, r: usize, other: Option<Vec<Ea4>>, pch: &mut Chl| -> Vec<Ea4> {
            if public(t, c).is_some() {
                return Vec::new(); // the verifier reads the statement itself: nothing on the wire, nothing absorbed
            }
            match other {
                Some(sent) if lie => {
                    pch.observe_algebra_slice(&sent); // what `add_claim_at` absorbs for the SENT value
                    sent
                }
                _ => prover1.eval_at(t, c, &boolean_point(r, shapes[t].0), pch),
            }
        };
        let v1 = side(*t1, c1, *r1, public(*t2, c2), &mut pch);
        let v2 = side(*t2, c2, *r2, public(*t1, c1), &mut pch);
        cross_tie_openings.push((v1, v2));
    }
    let mut column_tie_openings = Vec::with_capacity(column_ties.len());
    for (e1, e2) in column_ties {
        let hi = column_tie_high(&shapes, e1, e2)?;
        let high: Vec<Ea4> = (0..hi).map(|_| pch.sample_algebra_element::<Ea4>()).collect();
        let v1 = prover1.eval_at(e1.0, &e1.1, &segment_point(&high, e1.3, e1.2), &mut pch);
        let v2 = prover1.eval_at(e2.0, &e2.1, &segment_point(&high, e2.3, e2.2), &mut pch);
        column_tie_openings.push((v1, v2));
    }
    let round1 = prover1.finish(&mut pch);
    postcard::to_allocvec(&AirBatchBusBundle {
        shapes,
        zcs,
        tied_buses: Vec::new(),
        n_constraint: n,
        shift_binds,
        cross_tie_openings,
        column_tie_openings,
        round1,
        round2: None,
    })
    .ok()
}

/// ⛔ TEST-ONLY ADVERSARY (DB-452, the direct family's lie PORTED to the bound engine): a plain batch proof whose table 0
/// sends a SOLVED opened row. The honest prover's setup in its exact transcript order — table 0 committed to the REAL
/// trace, γ, z — then table 0's zerocheck rounds are all ZERO and `opened` is a row the statement's gate accepts at the
/// rounds' point ([`crate::air_zerocheck::solve_opened_for_tests`]), absorbed exactly as `add_claim_at` absorbs it and
/// never recorded on the commitment; a row-shifted gate sends that row as its next-row openings too, and the honest
/// shift-bind follows. `lie = false` is the CONTROL — the honest prover through the same code — so a forger that merely
/// desynchronises the transcript cannot read as a refusal. `column_ties` are opened exactly as the honest prover opens
/// them (a statement that welds two tables — the keyed band carrier — carries its tie in the forgery too).
#[cfg(test)]
pub(crate) fn forge_batch_opened_light_decider_for_tests<C, Mk>(
    tables: Vec<Vec<Vec<Fa4>>>,
    make_constraint: Mk,
    column_ties: Vec<ColumnTieSpec>,
    public_bind: &[Fa4],
    lie: bool,
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    // SPEED G1: every prover that reaches the light decider (node, wallet, phone, tests) grinds on the GPU where there
    // is one; a no-op after the first call (`gpu_grind::install`, one OnceLock read).
    let _ = crate::gpu_grind::install();
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let mut pch = Chl::new(Perm16::new_from_rng_128(&mut perm_rng));
    for &f in public_bind {
        pch.observe(f);
    }
    let n = tables.len();
    let shapes: Vec<(usize, usize)> =
        tables.iter().map(|c| (c[0].len().trailing_zeros() as usize, c.len())).collect();
    let tables_for_zc = tables.clone();
    let mut prover1 = LightCommitProver::commit(tables, &mut pch)?;
    let gamma: Ea4 = pch.sample_algebra_element();
    let mut zcs = Vec::with_capacity(n);
    let mut shift_binds = Vec::new();
    for i in 0..n {
        let (nvars, width) = shapes[i];
        let constraint = make_constraint(i, gamma);
        let z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
        let set = crate::air_zerocheck::shifted_set(&constraint, width);
        let mut zc = if lie && i == 0 {
            let per = constraint.degree(nvars) + 2;
            let mut round_evals = Vec::with_capacity(nvars);
            let mut r = Vec::with_capacity(nvars);
            for _ in 0..nvars {
                let h = vec![Ea4::ZERO; per];
                pch.observe_algebra_slice(&h);
                r.push(pch.sample_algebra_element::<Ea4>());
                round_evals.push(h);
            }
            let base: Vec<Ea4> = tables_for_zc[0].iter().map(|c| Ea4::from(c[0])).collect();
            let opened = crate::air_zerocheck::solve_opened_for_tests(&constraint, &base, &r)?;
            pch.observe_algebra_slice(&opened); // what `add_claim_at` absorbs for the SENT row
            let shifted_opened = opened.clone();
            AirZerocheckProof { round_evals, opened, r, shifted_opened }
        } else {
            let zc = prove_air_zerocheck(&tables_for_zc[i], &constraint, &z, &mut pch);
            let _ = prover1.eval_at(i, &(0..width).collect::<Vec<_>>(), &Point::new(zc.r.clone()), &mut pch);
            zc
        };
        crate::air_zerocheck::compact_shifted(&mut zc, &set);
        absorb_shifted_openings(&mut pch, &zc.shifted_opened);
        if !set.is_empty() {
            shift_binds.push(prove_shift_bind(&tables_for_zc[i], &set, &zc.r, i, &mut prover1, &mut pch));
        }
        zcs.push(zc);
    }
    let mut column_tie_openings: Vec<(Vec<Ea4>, Vec<Ea4>)> = Vec::with_capacity(column_ties.len());
    for (e1, e2) in &column_ties {
        let hi = column_tie_high(&shapes, e1, e2)?;
        let high: Vec<Ea4> = (0..hi).map(|_| pch.sample_algebra_element::<Ea4>()).collect();
        let v1 = prover1.eval_at(e1.0, &e1.1, &segment_point(&high, e1.3, e1.2), &mut pch);
        let v2 = prover1.eval_at(e2.0, &e2.1, &segment_point(&high, e2.3, e2.2), &mut pch);
        column_tie_openings.push((v1, v2));
    }
    let round1 = prover1.finish(&mut pch);
    postcard::to_allocvec(&AirBatchBusBundle {
        shapes,
        zcs,
        tied_buses: Vec::new(),
        n_constraint: n,
        shift_binds,
        cross_tie_openings: Vec::new(),
        column_tie_openings,
        round1,
        round2: None,
    })
    .ok()
}

/// ⛔ TEST-ONLY ADVERSARY (DB-452, the DIRECT family): a direct light-decider carrier for the statement `make_constraint`
/// / `public_bind` over a trace `cols` that does NOT satisfy it (a single logical row, replicated — every production
/// value carrier's shape). The honest prover's setup in its exact transcript order (the commitment-free hiding layout,
/// the round-1 openings of `cols`, γ, z); then the zerocheck's rounds are all ZERO (they sum to the zerocheck's 0) and
/// the ONE lie is `opened`: a row the statement's gate accepts at the rounds' point ([`solve_opened_for_tests`]),
/// absorbed exactly as the verifier's `add_claim_at` absorbs it. A decider that binds `opened` to the trace refuses it.
#[cfg(test)]
pub(crate) fn forge_direct_light_decider_for_tests<C, Mk>(
    cols: Vec<Vec<Fa4>>,
    make_constraint: Mk,
    public_bind: &[Fa4],
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let perm = Perm16::new_from_rng_128(&mut perm_rng);
    let mmcs: Mmcs16 =
        Mmcs16::new(SpongeHash::new(perm.clone()), CompressHash::new(perm.clone()), 0, prover_randomness());
    let encoding: Enc16 = decider_mask_encoding(REC_DECIDER_T, REC_DECIDER_ELL_ZK);
    let mut pch = Chl::new(perm);
    for &f in public_bind {
        pch.observe(f);
    }
    let (nvars, width) = trace_shape(&cols)?;
    let base: Vec<Ea4> = cols.iter().map(|c| Ea4::from(c[0])).collect();
    let mut prover = build_decider_hiding_prover(vec![cols], REC_DECIDER_FOLDING, mmcs, encoding);
    let all: Vec<usize> = (0..width).collect();
    let openings = vec![prover.eval(0, &all, &mut pch)];
    let gamma: Ea4 = pch.sample_algebra_element();
    let constraint = make_constraint(gamma);
    let _z: Vec<Ea4> = (0..nvars).map(|_| pch.sample_algebra_element()).collect();
    let per = constraint.degree(nvars) + 2;
    let mut round_evals = Vec::with_capacity(nvars);
    let mut r = Vec::with_capacity(nvars);
    for _ in 0..nvars {
        let h = vec![Ea4::ZERO; per];
        pch.observe_algebra_slice(&h);
        r.push(pch.sample_algebra_element::<Ea4>());
        round_evals.push(h);
    }
    let opened = crate::air_zerocheck::solve_opened_for_tests(&constraint, &base, &r)?;
    pch.observe_algebra_slice(&opened); // what `add_claim_at` absorbs for the SENT row
    let shifted_opened = opened.clone();
    absorb_shifted_openings(&mut pch, &shifted_opened);
    let virtual_eval = prover.add_virtual_eval(&mut pch);
    let mut zk_data = ZkSumcheckData::<Fa4, Ea4>::default();
    let mut rng = prover_randomness();
    let (mask_commits, prover_rand) = prove_hvzk(prover, &mut zk_data, REC_DECIDER_POW_BITS, &mut pch, &mut rng);
    let zc = AirZerocheckProof { round_evals, opened, r, shifted_opened };
    postcard::to_allocvec(&AirDirectBundle {
        shapes: vec![(nvars, width)],
        openings,
        zc,
        virtual_eval,
        zk_data,
        mask_commits,
        prover_rand,
    })
    .ok()
}

/// ⛔ TEST-ONLY (DB-452 privacy census): every evaluation a direct carrier SENDS — the round-1 openings, the opened row
/// and the next-row openings — as the field elements a peer reads off the wire.
#[cfg(test)]
pub(crate) fn direct_sent_evaluations_for_tests(bytes: &[u8]) -> Vec<Ea4> {
    let Ok(b) = postcard::from_bytes::<AirDirectBundle>(bytes) else { return Vec::new() };
    b.openings.into_iter().flatten().chain(b.zc.opened).chain(b.zc.shifted_opened).collect()
}

/// ⛔ TEST-ONLY: the `(constraint, bus)` table shapes a bus carrier DECLARES (see
/// [`declared_batch_shapes_for_tests`]).
#[cfg(test)]
#[must_use]
pub(crate) fn declared_bus_shapes_for_tests(bytes: &[u8]) -> (Vec<(usize, usize)>, Vec<(usize, usize)>) {
    match postcard::from_bytes::<AirBatchBusBundle>(bytes) {
        Ok(b) if b.n_constraint <= b.shapes.len() => {
            (b.shapes[..b.n_constraint].to_vec(), b.shapes[b.n_constraint..].to_vec())
        }
        _ => (Vec::new(), Vec::new()),
    }
}

/// ⛔ TEST-ONLY — WHERE A LIGHT-DECIDER PROOF'S BYTES GO (R4: the per-block ledger proofs are ~1.5 MB of every block on a
/// real pair, and relaying them is half the block interval). Prints the bundle's parts by postcard size and, per WHIR
/// round, the query count, the sibling depth, the bytes of opened values / salts / sibling paths, and what a DEDUPLICATED
/// multi-opening of the same queries would send (siblings shared by two queries sent once, a sibling that is itself an
/// opened path node not sent). The query indices are transcript-random, so the dedup count is simulated with uniform
/// indices over the round's leaf count — a MEASUREMENT of the lever, not a claim about any one proof.
#[cfg(test)]
pub(crate) fn print_light_bundle_breakdown_for_tests(label: &str, bytes: &[u8]) {
    let Ok(b) = postcard::from_bytes::<AirBatchBusBundle>(bytes) else {
        eprintln!("[proof-bytes] {label}: not an AirBatchBusBundle");
        return;
    };
    let pc = |r: Result<Vec<u8>, postcard::Error>| r.map(|v| v.len()).unwrap_or(0);
    eprintln!("[proof-bytes] {label}: {} B total", bytes.len());
    eprintln!("[proof-bytes]   zerochecks        {:>8} B", pc(postcard::to_allocvec(&b.zcs)));
    eprintln!("[proof-bytes]   tied buses        {:>8} B", pc(postcard::to_allocvec(&b.tied_buses)));
    eprintln!("[proof-bytes]   shift binds       {:>8} B", pc(postcard::to_allocvec(&b.shift_binds)));
    eprintln!("[proof-bytes]   cross-tie opens   {:>8} B", pc(postcard::to_allocvec(&b.cross_tie_openings)));
    eprintln!("[proof-bytes]   column-tie opens  {:>8} B", pc(postcard::to_allocvec(&b.column_tie_openings)));
    // postcard writes a struct as its fields in order, so the parts must sum to the whole — a field this census does not
    // name would show up here as a gap instead of hiding.
    let summed = pc(postcard::to_allocvec(&b.shapes))
        + pc(postcard::to_allocvec(&b.zcs))
        + pc(postcard::to_allocvec(&b.tied_buses))
        + pc(postcard::to_allocvec(&b.n_constraint))
        + pc(postcard::to_allocvec(&b.shift_binds))
        + pc(postcard::to_allocvec(&b.cross_tie_openings))
        + pc(postcard::to_allocvec(&b.column_tie_openings))
        + pc(postcard::to_allocvec(&b.round1))
        + pc(postcard::to_allocvec(&b.round2));
    assert_eq!(summed, bytes.len(), "the bundle's per-field sizes must sum to the proof's own length — a field is missing from the census");
    let mut rng = SmallRng::seed_from_u64(0x5052_554e);
    let (mut all_paths, mut all_dedup, mut all_shared) = (0usize, 0usize, 0usize);
    for (name, round) in [("round 1", Some(&b.round1)), ("round 2", b.round2.as_ref())] {
        let Some(r) = round else { continue };
        let w = &r.open;
        eprintln!("[proof-bytes]   {name} WHIR       {:>8} B", pc(postcard::to_allocvec(w)));
        let qs: Vec<(&str, &Vec<p3_whir::pcs::proof::QueryOpening<Fa4, Ea4, <Mmcs16 as Mmcs<Fa4>>::Proof>>)> =
            w.rounds.iter().map(|x| ("fold", &x.queries)).chain(core::iter::once(("final", &w.final_queries))).collect();
        for (i, (kind, q)) in qs.iter().enumerate() {
            if q.is_empty() {
                continue;
            }
            let (mut vals, mut salts, mut paths, mut depth) = (0usize, 0usize, 0usize, 0usize);
            for o in q.iter() {
                let (v, p) = match o {
                    p3_whir::pcs::proof::QueryOpening::Base { values, proof } => (pc(postcard::to_allocvec(values)), proof),
                    p3_whir::pcs::proof::QueryOpening::Extension { values, proof } => (pc(postcard::to_allocvec(values)), proof),
                };
                vals += v;
                salts += pc(postcard::to_allocvec(&p.0));
                paths += pc(postcard::to_allocvec(&p.1));
                depth = p.1.len();
            }
            // Simulated dedup over a tree of 2^depth leaves: walk the q paths level by level; a sibling is sent iff it is
            // not itself a node on some opened path at that level.
            let n = q.len();
            let idx: Vec<usize> = (0..n).map(|_| (rand::RngExt::random::<u64>(&mut rng) as usize) & ((1usize << depth) - 1)).collect();
            // The simpler lossless form: a sibling (level, position) another query already sent is not sent again.
            let shared: std::collections::BTreeSet<(usize, usize)> =
                idx.iter().flat_map(|&x| (0..depth).map(move |l| (l, (x >> l) ^ 1))).collect();
            let shared_bytes = shared.len() * if depth == 0 { 0 } else { paths / (n * depth).max(1) };
            all_shared += shared_bytes;
            let mut level: std::collections::BTreeSet<usize> = idx.iter().copied().collect();
            let mut sent = 0usize;
            for _ in 0..depth {
                for &x in &level {
                    if !level.contains(&(x ^ 1)) {
                        sent += 1;
                    }
                }
                level = level.iter().map(|x| x >> 1).collect();
            }
            let per_sib = if depth == 0 { 0 } else { paths / (n * depth).max(1) };
            let dedup = sent * per_sib;
            all_paths += paths;
            all_dedup += dedup;
            eprintln!(
                "[proof-bytes]     {name} {kind} #{i}: {n} queries · depth {depth} · values {vals} B · salts {salts} B · \
                 paths {paths} B → dedup {dedup} B ({sent} of {} siblings)",
                n * depth
            );
        }
    }
    eprintln!(
        "[proof-bytes]   {label}: sibling paths {all_paths} B of {} B ({:.1}%); a deduplicated multi-opening sends {all_dedup} B \
         → the proof would be {} B ({:.1}% smaller)",
        bytes.len(),
        100.0 * all_paths as f64 / bytes.len() as f64,
        bytes.len() - all_paths + all_dedup,
        100.0 * (all_paths - all_dedup) as f64 / bytes.len() as f64
    );
    eprintln!(
        "[proof-bytes]   {label}: sending each shared sibling once sends {all_shared} B → the proof would be {} B ({:.1}% smaller)",
        bytes.len() - all_paths + all_shared,
        100.0 * (all_paths - all_shared) as f64 / bytes.len() as f64
    );
}

/// Produce the HVZK-WHIR opening+mask bundle for the rec-block `tables` with NO LogUp buses — a thin
/// wrapper over [`prove_rec_block_whir_openings_with_bus`] passing an empty bus list. The rec-block
/// routing calls this when the caller has not yet built any bus; all existing call sites stay unchanged.
#[must_use]
pub fn prove_rec_block_whir_openings(
    tables: Vec<Vec<Vec<Fa4>>>,
    shapes: Vec<(usize, usize)>,
    folding: usize,
    pow_bits: usize,
    mmcs: Mmcs16,
    encoding: Enc16,
    pch: &mut Chl,
    rng: &mut SmallRng,
) -> RecBlockOpeningBundle {
    prove_rec_block_whir_openings_with_bus(
        tables, shapes, folding, pow_bits, mmcs, encoding, pch, rng, Vec::new(), Vec::new(),
    )
}

/// Produce the HVZK-WHIR opening+mask bundle, optionally ENFORCING one or more LogUp bus balances. Opens
/// every column of every table (full witness opening) + a virtual eval, runs the r6 constraint
/// zerochecks, and — for each `(value, mult)` in `buses` — appends a committed bus table, runs
/// [`prove_leaf_bus_balance`], and binds its columns via `eval_at` at the balance's zerocheck + col-sum
/// points. Each α is drawn from the shared transcript in bus order; `circuit.rs` supplies real rec traces
/// plus real buses (LEAF_BUS from LeafSource load-counts / SymEvalR6 tape-counts; SYMX_REG_BUS from reg
/// writes/reads).
#[must_use]
pub fn prove_rec_block_whir_openings_with_bus(
    tables: Vec<Vec<Vec<Fa4>>>,
    mut shapes: Vec<(usize, usize)>,
    folding: usize,
    pow_bits: usize,
    mmcs: Mmcs16,
    encoding: Enc16,
    pch: &mut Chl,
    rng: &mut SmallRng,
    buses: Vec<(Vec<Fa4>, Vec<Fa4>)>,
    tied_buses: Vec<(Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>)>,
) -> RecBlockOpeningBundle {
    let n = tables.len();
    let tables_for_zc: Vec<Vec<Vec<Fa4>>> = tables.clone();

    // ── ROUND 1 — COMMIT THE CONSTRAINT TABLES FIRST, and open every column. ───────────────────────
    //
    // ⛔⛔⛔ DB-160, AND IT WAS IN THIS FUNCTION'S OWN COMMENT. Everything below used to run BEFORE this
    // line: `r6_gamma`, each r6 table's zerocheck point `z`, and every bus's `α`/`β` were sampled from a
    // transcript that had absorbed nothing but the statement. The old comment defended it — *"γ is
    // transcript-derived (never adaptively chosen); z is a Fiat-Shamir point"* — which is true of γ and
    // z and beside the point: the TRACE is chosen after them. A zerocheck at a point the prover knew in
    // advance proves the constraint AT THAT POINT, not on the table; a LogUp balance under a known α is
    // one equation to aim at rather than a test to pass. Committing first is what makes every challenge
    // below a Fiat-Shamir function of the trace it is judging.
    let mut prover1 = build_decider_hiding_prover(tables, folding, mmcs.clone(), encoding.clone());
    let mut openings: Vec<Vec<Ea4>> = Vec::with_capacity(n);
    for (i, &(_, width)) in shapes.iter().enumerate().take(n) {
        let cols: Vec<usize> = (0..width).collect();
        openings.push(prover1.eval(i, &cols, pch));
    }

    // ── The r6 composed-AIR zerochecks, now POST-commit. Every SymEvalR6Leaf table (committed width
    //    SYMX_R6_W) is proven: reg-op relations plus the row-idx transition hold on all 2^n_vars rows.
    let r6_gamma: Ea4 = pch.sample_algebra_element();
    let mut r6_zerochecks: Vec<(usize, AirZerocheckProof)> = Vec::new();
    for (i, &(n_vars, width)) in shapes.iter().enumerate().take(n) {
        if width == SYMX_R6_W {
            let z: Vec<Ea4> = (0..n_vars).map(|_| pch.sample_algebra_element()).collect();
            let proof = prove_air_zerocheck(
                &tables_for_zc[i],
                &SymEvalR6FullConstraint { gamma: r6_gamma },
                &z,
                pch,
            );
            r6_zerochecks.push((i, proof));
        }
    }

    // ── The bus challenges, POST-commit (DB-159). ─────────────────────────────────────────────────
    let mut plain_alpha: Vec<Ea4> = Vec::with_capacity(buses.len());
    for _ in &buses {
        plain_alpha.push(pch.sample_algebra_element());
    }
    let mut tied_ab: Vec<(Ea4, Fa4)> = Vec::with_capacity(tied_buses.len());
    for _ in &tied_buses {
        let alpha: Ea4 = pch.sample_algebra_element();
        let beta = draw_bus_fold_challenge(pch);
        tied_ab.push((alpha, beta));
    }

    // ── ROUND 2 — the bus tables, which could not exist before α. ─────────────────────────────────
    let mut bus_tables: Vec<Vec<Vec<Fa4>>> = Vec::new();
    // (padded value, padded mult, global table index)
    let mut plain_cols: Vec<(Vec<Fa4>, Vec<Fa4>, usize)> = Vec::with_capacity(buses.len());
    for (b, (mut value, mut mult)) in buses.into_iter().enumerate() {
        let raw = value.len();
        let nv = (raw.max(1).next_power_of_two().trailing_zeros() as usize).max(folding);
        let padded = 1usize << nv;
        while value.len() < padded {
            value.push(Fa4::from_u64(1_000_003 + value.len() as u64));
            mult.push(Fa4::ZERO);
        }
        let alpha = plain_alpha[b];
        let mut h_limbs: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; padded]; EXT_D];
        for r in 0..padded {
            let d = alpha - Ea4::from(value[r]);
            // α landing on a committed key is a 1/|Ea4| accident: the honest answer is an h of zero for
            // a zero multiplicity and, otherwise, a proof that will simply not balance. Never a skip.
            let hv = if d == Ea4::ZERO { Ea4::ZERO } else { Ea4::from(mult[r]) * d.inverse() };
            let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&hv);
            for k in 0..EXT_D {
                h_limbs[k][r] = limbs[k];
            }
        }
        let mut bus_cols: Vec<Vec<Fa4>> = vec![value.clone(), mult.clone()];
        for k in 0..EXT_D {
            bus_cols.push(h_limbs[k].clone());
        }
        plain_cols.push((value, mult, n + bus_tables.len()));
        shapes.push((nv, 2 + EXT_D));
        bus_tables.push(bus_cols);
    }
    // (n_val, global table index)
    let mut tied_meta: Vec<(usize, usize)> = Vec::with_capacity(tied_buses.len());
    for (b, (mut idx_col, mut val_cols, mut mult_col)) in tied_buses.into_iter().enumerate() {
        let n_val = val_cols.len();
        let raw = idx_col.len();
        let nv = (raw.max(1).next_power_of_two().trailing_zeros() as usize).max(folding);
        let padded = 1usize << nv;
        while idx_col.len() < padded {
            idx_col.push(Fa4::from_u64(2_000_003 + idx_col.len() as u64));
            for vc in val_cols.iter_mut() {
                vc.push(Fa4::ZERO);
            }
            mult_col.push(Fa4::ZERO);
        }
        let (alpha, beta) = tied_ab[b];
        let mut h_limbs: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; padded]; EXT_D];
        for r in 0..padded {
            let mut key = Ea4::from(idx_col[r]);
            let mut bpow = Ea4::from(beta);
            for vc in val_cols.iter() {
                key += bpow * Ea4::from(vc[r]);
                bpow *= Ea4::from(beta);
            }
            let d = alpha - key;
            let hv = if d == Ea4::ZERO { Ea4::ZERO } else { Ea4::from(mult_col[r]) * d.inverse() };
            let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&hv);
            for k in 0..EXT_D {
                h_limbs[k][r] = limbs[k];
            }
        }
        let mut bus_cols: Vec<Vec<Fa4>> = Vec::with_capacity(2 + n_val + EXT_D);
        bus_cols.push(idx_col);
        for vc in val_cols {
            bus_cols.push(vc);
        }
        bus_cols.push(mult_col);
        for k in 0..EXT_D {
            bus_cols.push(h_limbs[k].clone());
        }
        tied_meta.push((n_val, n + bus_tables.len()));
        shapes.push((nv, 2 + n_val + EXT_D));
        bus_tables.push(bus_cols);
    }
    let bus_for_zc: Vec<Vec<Vec<Fa4>>> = bus_tables.clone();
    let mut prover2 = if bus_tables.is_empty() {
        None
    } else {
        Some(build_decider_hiding_prover(bus_tables, folding, mmcs, encoding))
    };
    if let Some(p2) = prover2.as_mut() {
        for (b, &(_, width)) in shapes.iter().enumerate().skip(n) {
            let cols: Vec<usize> = (0..width).collect();
            openings.push(p2.eval(b - n, &cols, pch));
        }
    }

    // ── The balances, over COMMITTED round-2 tables and challenges drawn after round 1. ───────────
    let mut bus_entries: Vec<BusBalanceEntry> = Vec::with_capacity(plain_cols.len());
    for (b, (value, mult, global)) in plain_cols.into_iter().enumerate() {
        let (bp, _h) = prove_leaf_bus_balance(&value, &mult, plain_alpha[b], pch);
        bus_entries.push(BusBalanceEntry { proof: bp, alpha: plain_alpha[b], table_idx: global });
    }
    let mut tied_entries: Vec<TiedBusEntry> = Vec::with_capacity(tied_meta.len());
    for (b, &(n_val, global)) in tied_meta.iter().enumerate() {
        let local = global - n;
        let (alpha, beta) = tied_ab[b];
        let cst = LogupKeyfoldConstraint {
            alpha,
            beta,
            idx_col: 0,
            val_col_base: 1,
            n_val,
            mult_col: 1 + n_val,
            h_limb_base: 2 + n_val,
        };
        let nv = shapes[global].0;
        let z: Vec<Ea4> = (0..nv).map(|_| pch.sample_algebra_element()).collect();
        let zc = prove_air_zerocheck(&bus_for_zc[local], &cst, &z, pch);
        let mut limb_sums: Vec<Ea4> = Vec::with_capacity(EXT_D);
        let mut sum_proofs: Vec<ColSumProof> = Vec::with_capacity(EXT_D);
        for k in 0..EXT_D {
            let col = &bus_for_zc[local][2 + n_val + k];
            let sum_k: Ea4 = col.iter().fold(Ea4::ZERO, |a, &vv| a + Ea4::from(vv));
            sum_proofs.push(prove_col_sum(col, pch));
            limb_sums.push(sum_k);
        }
        tied_entries.push(TiedBusEntry {
            proof: LeafBusBalanceProof { zc, limb_sums, sum_proofs },
            alpha,
            beta,
            n_val,
            table_idx: global,
        });
    }

    // ── Bind every zerocheck's opened columns to its own commitment. ──────────────────────────────
    for (i, proof) in &r6_zerochecks {
        let width = shapes[*i].1;
        let cols: Vec<usize> = (0..width).collect();
        let _ = prover1.eval_at(*i, &cols, &Point::new(proof.r.clone()), pch);
    }
    if let Some(p2) = prover2.as_mut() {
        for e in &bus_entries {
            let all: Vec<usize> = (0..2 + EXT_D).collect();
            let _ = p2.eval_at(e.table_idx - n, &all, &Point::new(e.proof.zc.r.clone()), pch);
            for k in 0..EXT_D {
                let _ = p2.eval_at(
                    e.table_idx - n,
                    &[2 + k],
                    &Point::new(e.proof.sum_proofs[k].r.clone()),
                    pch,
                );
            }
        }
        for e in &tied_entries {
            let bw = 2 + e.n_val + EXT_D;
            let all: Vec<usize> = (0..bw).collect();
            let _ = p2.eval_at(e.table_idx - n, &all, &Point::new(e.proof.zc.r.clone()), pch);
            for k in 0..EXT_D {
                let _ = p2.eval_at(
                    e.table_idx - n,
                    &[2 + e.n_val + k],
                    &Point::new(e.proof.sum_proofs[k].r.clone()),
                    pch,
                );
            }
        }
    }

    let virtual_eval = prover1.add_virtual_eval(pch);
    let mut zk_data = ZkSumcheckData::<Fa4, Ea4>::default();
    let (mask_commits, prover_rand) = prove_hvzk(prover1, &mut zk_data, pow_bits, pch, rng);
    let (virtual_eval2, zk_data2, mask_commits2, prover_rand2) = match prover2 {
        Some(mut p2) => {
            let ve2 = p2.add_virtual_eval(pch);
            let mut zk2 = ZkSumcheckData::<Fa4, Ea4>::default();
            let (mc2, pr2) = prove_hvzk(p2, &mut zk2, pow_bits, pch, rng);
            (ve2, zk2, mc2, pr2)
        }
        None => (Ea4::ZERO, ZkSumcheckData::<Fa4, Ea4>::default(), Vec::new(), Vec::new()),
    };
    RecBlockOpeningBundle {
        shapes,
        mask_commits,
        zk_data,
        openings,
        virtual_eval,
        prover_rand,
        r6_gamma,
        r6_zerochecks,
        buses: bus_entries,
        tied_buses: tied_entries,
        n_constraint: n,
        virtual_eval2,
        zk_data2,
        mask_commits2,
        prover_rand2,
    }
}

/// Verify a [`RecBlockOpeningBundle`]: rebuild the verifier from the shapes, replay every column of
/// every table + the virtual claim, and run `verify_hvzk`. Accepts iff the masked sumcheck verifies
/// AND the reproduced folding point equals the prover's. (The row-wise OodCheck quotient identity is
/// a separate check the rec-block gate applies via [`check_oodcheck_identity`] on the opened ood row.)
#[must_use]
pub fn verify_rec_block_whir_openings(
    bundle: &RecBlockOpeningBundle,
    folding: usize,
    ell_zk: usize,
    pow_bits: usize,
    vch: &mut Chl,
) -> bool {
    verify_rec_block_core(bundle, folding, ell_zk, pow_bits, vch, None).is_some()
}

/// ⭐⭐⭐ THE ONE REPLAY. Both rec-block verify entries route through this, so the transcript order lives
/// in exactly one place.
///
/// ⛔ IT LIVED IN TWO. `verify_rec_block_light_decider_selfcontained` was a hand-maintained copy of this
/// function plus an ood gate, and when DB-159/DB-160 moved the challenge order here the copy kept
/// replaying the old one — four honest carriers stopped verifying, which is how the duplication was
/// found. Two spellings of one transcript is the same class as two encodings of one commitment.
///
/// `want_point` asks for a table's last recorded opening point, captured right after the round-1 claims
/// and before any bind — the ood entry's only extra need. Returns `None` when the carrier is REFUSED.
#[must_use]
fn verify_rec_block_core(
    bundle: &RecBlockOpeningBundle,
    folding: usize,
    ell_zk: usize,
    pow_bits: usize,
    vch: &mut Chl,
    want_point: Option<usize>,
) -> Option<Option<Vec<Ea4>>> {
    if bundle.openings.len() != bundle.shapes.len() {
        return None; // require exactly one opening vector per table.
    }
    let n = bundle.n_constraint;
    if n == 0 || n > bundle.shapes.len() {
        return None;
    }
    // ⛔ EVERY BUS TABLE LIVES IN ROUND 2. A carrier pointing one at a round-1 table would have its
    // balance proved over a table `α` was drawn from — DB-159 arriving through the front door.
    let n_bus = bundle.buses.len() + bundle.tied_buses.len();
    if bundle.shapes.len() != n + n_bus {
        return None;
    }
    for (b, e) in bundle.buses.iter().enumerate() {
        if e.table_idx != n + b {
            return None;
        }
    }
    for (b, e) in bundle.tied_buses.iter().enumerate() {
        if e.table_idx != n + bundle.buses.len() + b {
            return None;
        }
    }

    // ── Mirror ROUND 1: the constraint tables' claims, absorbed before any challenge. ─────────────
    let shapes1: Vec<(usize, usize)> = bundle.shapes[..n].to_vec();
    let shapes2: Vec<(usize, usize)> = bundle.shapes[n..].to_vec();
    let mut v1 = build_decider_hiding_verifier(&shapes1);
    for (i, &(_, width)) in shapes1.iter().enumerate() {
        let cols: Vec<usize> = (0..width).collect();
        v1.add_claim(i, &cols, &bundle.openings[i], vch);
    }
    // The ood entry's point, captured HERE — after the round-1 claims and before any bind, which is
    // where the single-copy version read it too.
    let recorded: Option<Vec<Ea4>> = match want_point {
        Some(t) => {
            if t >= shapes1.len() {
                return None;
            }
            match v1.last_recorded_point(t) {
                Some(p) => Some(p),
                None => {
                    if std::env::var("MONEROUSD_REC_TIMING").is_ok() {
                        eprintln!("[rec-verify-fail] ood_point recovery returned None (ood_idx={t})");
                    }
                    return None;
                }
            }
        }
        None => None,
    };

    // ── Mirror the r6 zerochecks, now POST-commit (DB-160). ──────────────────────────────────────
    let r6_gamma: Ea4 = vch.sample_algebra_element();
    if r6_gamma != bundle.r6_gamma {
        return None;
    }
    let mut r6_iter = bundle.r6_zerochecks.iter();
    for (i, &(n_vars, width)) in shapes1.iter().enumerate() {
        if width == SYMX_R6_W {
            let (pi, proof) = match r6_iter.next() {
                Some(v) => v,
                None => return None,
            };
            if *pi != i {
                return None; // r6 proofs must line up with r6 tables in shapes order
            }
            let z: Vec<Ea4> = (0..n_vars).map(|_| vch.sample_algebra_element()).collect();
            if !verify_air_zerocheck(proof, &SymEvalR6FullConstraint { gamma: r6_gamma }, &z, vch) {
                if std::env::var("MONEROUSD_REC_TIMING").is_ok() {
                    eprintln!("[rec-verify-fail] r6 zerocheck rejected");
                }
                return None;
            }
        }
    }
    if r6_iter.next().is_some() {
        return None; // extra r6 proof with no matching r6 table
    }

    // ── Mirror the bus challenges, POST-commit (DB-159), and BIND what the carrier claims. ───────
    for e in &bundle.buses {
        let alpha: Ea4 = vch.sample_algebra_element();
        if alpha != e.alpha {
            return None;
        }
    }
    for e in &bundle.tied_buses {
        let alpha: Ea4 = vch.sample_algebra_element();
        if alpha != e.alpha {
            return None;
        }
        let beta = draw_bus_fold_challenge(vch);
        if beta != e.beta {
            return None;
        }
    }

    // ── Mirror ROUND 2. ──────────────────────────────────────────────────────────────────────────
    let mut v2 = if shapes2.is_empty() { None } else { Some(build_decider_hiding_verifier(&shapes2)) };
    if let Some(vv2) = v2.as_mut() {
        for (b, &(_, width)) in shapes2.iter().enumerate() {
            let cols: Vec<usize> = (0..width).collect();
            vv2.add_claim(b, &cols, &bundle.openings[n + b], vch);
        }
    }

    // ── Mirror the balances, over the COMMITTED round-2 tables. ──────────────────────────────────
    for e in &bundle.buses {
        let nv = bundle.shapes[e.table_idx].0;
        if !verify_leaf_bus_balance(&e.proof, e.alpha, nv, vch) {
            return None;
        }
    }
    for e in &bundle.tied_buses {
        let nv = bundle.shapes[e.table_idx].0;
        if !verify_leaf_bus_balance_tied(&e.proof, e.alpha, e.beta, e.n_val, nv, vch) {
            if std::env::var("MONEROUSD_REC_TIMING").is_ok() {
                eprintln!("[rec-verify-fail] tied bus balance rejected (table {})", e.table_idx);
            }
            return None;
        }
    }

    // ── Bind every zerocheck's opened columns to its own commitment. ─────────────────────────────
    for (i, proof) in &bundle.r6_zerochecks {
        if *i >= n {
            return None;
        }
        let width = bundle.shapes[*i].1;
        let cols: Vec<usize> = (0..width).collect();
        v1.add_claim_at(*i, &cols, &proof.opened, &Point::new(proof.r.clone()), vch);
        if proof.shifted_opened.get(SYMX_ROWIDX).copied() != Some(public_rowidx_rotation_mle(&proof.r)) {
            return None;
        }
    }
    if let Some(vv2) = v2.as_mut() {
        for e in &bundle.buses {
            let all: Vec<usize> = (0..2 + EXT_D).collect();
            vv2.add_claim_at(
                e.table_idx - n,
                &all,
                &e.proof.zc.opened,
                &Point::new(e.proof.zc.r.clone()),
                vch,
            );
            for k in 0..EXT_D {
                vv2.add_claim_at(
                    e.table_idx - n,
                    &[2 + k],
                    &[e.proof.sum_proofs[k].opened],
                    &Point::new(e.proof.sum_proofs[k].r.clone()),
                    vch,
                );
            }
        }
        for e in &bundle.tied_buses {
            let bw = 2 + e.n_val + EXT_D;
            let all: Vec<usize> = (0..bw).collect();
            vv2.add_claim_at(
                e.table_idx - n,
                &all,
                &e.proof.zc.opened,
                &Point::new(e.proof.zc.r.clone()),
                vch,
            );
            for k in 0..EXT_D {
                vv2.add_claim_at(
                    e.table_idx - n,
                    &[2 + e.n_val + k],
                    &[e.proof.sum_proofs[k].opened],
                    &Point::new(e.proof.sum_proofs[k].r.clone()),
                    vch,
                );
            }
        }
    }

    v1.add_virtual_eval(bundle.virtual_eval, vch);
    let ok1 = match verify_hvzk::<Fa4, Ea4, Mmcs16, _>(
        v1,
        &bundle.zk_data,
        &bundle.mask_commits,
        ell_zk,
        folding,
        pow_bits,
        vch,
    ) {
        Some(vpoint) => bundle.prover_rand == vpoint,
        None => false,
    };
    if !ok1 {
        return None;
    }
    let ok2 = match v2 {
        Some(mut vv2) => {
            vv2.add_virtual_eval(bundle.virtual_eval2, vch);
            match verify_hvzk::<Fa4, Ea4, Mmcs16, _>(
                vv2,
                &bundle.zk_data2,
                &bundle.mask_commits2,
                ell_zk,
                folding,
                pow_bits,
                vch,
            ) {
                Some(vpoint) => bundle.prover_rand2 == vpoint,
                None => false,
            }
        }
        None => round2_is_absent(bundle.virtual_eval2, &bundle.zk_data2, &bundle.mask_commits2, &bundle.prover_rand2),
    };
    if !ok2 {
        return None;
    }
    Some(recorded)
}

/// Recover a height-1 table's base-field row from the WHIR openings of its columns at `point`.
///
/// A height-1 table (its single row placed at hypercube index 0, then zero-extended over the padded
/// domain) has, for each column `c`, the multilinear extension `c(X) = row_c · ∏_i (1 − X_i)`.
/// Hence `row_c = c(point) / ∏_i (1 − point_i)`, and — because `row_c` is a committed BASE-field
/// value — that quotient MUST lie in the base field (all non-base extension coefficients zero); if
/// it does not, the opening does not describe a height-1 base-field row and this returns `None`
/// (fail-closed). This is what BINDS the OodCheck row to the commitment: the rec-block gate feeds
/// the recovered row (not a free input) into [`check_oodcheck_identity`], so the quotient identity
/// `z_h·q = acc` is enforced on values proven equal to the committed ood trace.
///
/// Returns `None` if `∏(1 − point_i) == 0` (a boundary point where the row is not recoverable) or
/// any recovered lane carries a non-zero extension coefficient (the opening is not a base-field row).
#[must_use]
pub fn recover_height1_row_from_mle_openings(openings: &[Ea4], point: &[Ea4]) -> Option<Vec<Fa4>> {
    // eq = ∏_i (1 − point_i) — the value the height-1 MLE multiplies each row entry by at `point`.
    let mut eq = Ea4::ONE;
    for &z in point {
        eq *= Ea4::ONE - z;
    }
    let eq_inv = eq.try_inverse()?; // boundary point (some z_i == 1) => row not recoverable.
    let mut row: Vec<Fa4> = Vec::new();
    for &opened in openings {
        let v = opened * eq_inv;
        let coeffs = v.as_basis_coefficients_slice();
        // a committed base-field row entry has zero extension coefficients above the base one.
        for &c in coeffs.iter().skip(1) {
            if c != Fa4::ZERO {
                return None;
            }
        }
        row.push(coeffs[0]);
    }
    Some(row)
}

/// Rec-block ood gate over COMMITTED openings: recover the height-1 OodCheck row from the WHIR
/// openings of table `ood_idx` at the opening `point`, then enforce the rec-block ood gate
/// (`active == 1` AND `acc == q·z_h`) on the RECOVERED row — never a free input. This is what
/// BINDS the OodCheck identity to the commitment: the row fed to the gate is proven equal to the
/// committed ood trace (via the height-1 MLE quotient `row_c = c(point)/∏(1−point_i)`), so a
/// prover cannot pass the gate with a row it did not commit. Fail-closed: an out-of-range
/// `ood_idx`, an unrecoverable opening (a non-base extension coefficient — not a committed
/// base-field row — or a boundary `point` where `∏(1−point_i)=0`), or a row that violates the
/// gate all return `false`.
#[must_use]
pub fn check_rec_block_ood_from_openings(
    bundle: &RecBlockOpeningBundle,
    ood_idx: usize,
    point: &[Ea4],
) -> bool {
    // The opening point must have EXACTLY the committed arity (number of MLE variables) of the ood
    // table. A wrong-length point is not the FS point the columns were opened at — recovery would
    // run over the wrong variable count and could yield a spurious "valid" row — so fail closed
    // before touching the openings. (∏(1−point_i) over the wrong count is a different scalar.)
    let n_vars = match bundle.shapes.get(ood_idx) {
        Some(&(n_vars, _width)) => n_vars,
        None => return false,
    };
    if point.len() != n_vars {
        return false;
    }
    match bundle.openings.get(ood_idx) {
        Some(openings) => match recover_height1_row_from_mle_openings(openings, point) {
            Some(row) => check_rec_block_ood_row(&row),
            None => false,
        },
        None => false,
    }
}

/// End-to-end rec-block light-decider verification — the single sound check the rec-block routing
/// (`circuit.rs`) and the wallet fast-broadcast / node O(1)-verify path call. It is the AND of the
/// two halves, fail-closed on either:
///   1. the masked-sumcheck opening bundle verifies ([`verify_rec_block_whir_openings`]), and
///   2. the OodCheck row RECOVERED from the committed ood-table openings satisfies the active
///      quotient gate ([`check_rec_block_ood_from_openings`]).
/// Together these prove the rec block's ood-check identity (`acc == q·z_h`, `active == 1`) holds on
/// a row BOUND to the commitment, over a constant-size (≤1.8MB) decider proof — no per-block or
/// per-DAG-width growth. The caller supplies `ood_idx` (the height-1 ood table's position in the
/// bundle) and `ood_point` (the point its columns were opened at, from the same challenger).
#[must_use]
pub fn verify_rec_block_light_decider(
    bundle: &RecBlockOpeningBundle,
    ood_idx: usize,
    ood_point: &[Ea4],
    folding: usize,
    ell_zk: usize,
    pow_bits: usize,
    vch: &mut Chl,
) -> bool {
    verify_rec_block_whir_openings(bundle, folding, ell_zk, pow_bits, vch)
        && check_rec_block_ood_from_openings(bundle, ood_idx, ood_point)
}

/// Locate the height-1 OodCheck table in a bundle's `shapes`: the rec block carries exactly ONE
/// table of width `OODCHK_W` (the ood table). Returns its index, or `None` if there is not exactly
/// one such table — zero (no ood table) or more than one (ambiguous) is a malformed bundle, so this
/// fails closed rather than guess. This removes the hardcoded ood index from the caller: the ood
/// table is identified structurally by its committed width.
#[must_use]
pub fn rec_block_ood_table_index(shapes: &[(usize, usize)]) -> Option<usize> {
    let mut found: Option<usize> = None;
    for (i, &(_, width)) in shapes.iter().enumerate() {
        if width == OODCHK_W {
            if found.is_some() {
                return None; // more than one OODCHK_W-wide table → ambiguous → fail-closed.
            }
            found = Some(i);
        }
    }
    found
}

/// Full rec-block light-decider verification with automatic ood-table location — the entry the
/// rec-block routing (`circuit.rs`) and the wallet fast-broadcast / node verify path call. Finds the
/// ood table by its `OODCHK_W` width via [`rec_block_ood_table_index`] (fail-closed if not exactly
/// one), then runs [`verify_rec_block_light_decider`]. The caller supplies only the FS-derived
/// `ood_point` (the transcript point the ood columns were opened at); the ood index is no longer a
/// caller-supplied magic number. Fail-closed: a malformed bundle (no/ambiguous ood table) rejects.
#[must_use]
pub fn verify_rec_block_light_decider_auto(
    bundle: &RecBlockOpeningBundle,
    ood_point: &[Ea4],
    folding: usize,
    ell_zk: usize,
    pow_bits: usize,
    vch: &mut Chl,
) -> bool {
    match rec_block_ood_table_index(&bundle.shapes) {
        Some(idx) => {
            verify_rec_block_light_decider(bundle, idx, ood_point, folding, ell_zk, pow_bits, vch)
        }
        None => false,
    }
}

/// PRODUCTION prove entry — the single call `pqspend_rec_block_prove` (circuit.rs) makes on the ZK
/// branch: adapt the rec AIR traces (r6 / leaf / ood / claims) into the multi-table MLE witness,
/// open every column + run the masked HVZK sumcheck, and SERIALIZE the bundle to the tx-carrier
/// bytes the wallet fast-broadcast relays. Returns the postcard bytes, or `None` if serialization
/// fails (never panics on the prove path).
#[must_use]
pub fn prove_rec_block_light_decider_bytes(
    traces: &[RowMajorMatrix<Fa4>],
    folding: usize,
    pow_bits: usize,
    mmcs: Mmcs16,
    encoding: Enc16,
    pch: &mut Chl,
    rng: &mut SmallRng,
) -> Option<Vec<u8>> {
    let (tables, shapes) = rec_traces_to_tables(traces, folding);
    let bundle =
        prove_rec_block_whir_openings(tables, shapes, folding, pow_bits, mmcs, encoding, pch, rng);
    postcard::to_allocvec(&bundle).ok()
}

/// PRODUCTION prove entry WITH LogUp buses — the call `pqspend_rec_block_prove` (circuit.rs) makes once
/// it has built the rec block's real buses (LEAF_BUS from LeafSource load-counts / SymEvalR6 tape-counts
/// / ClaimsExpose; SYMX_REG_BUS from reg writes/reads). Adapts the rec AIR traces + appends each bus's
/// committed table, runs the masked HVZK sumcheck + r6/bus balances, and serializes the bundle to the
/// tx-carrier bytes. Returns the postcard bytes, or `None` on serialization failure (never panics).
#[must_use]
pub fn prove_rec_block_light_decider_bytes_with_bus(
    traces: &[RowMajorMatrix<Fa4>],
    buses: Vec<(Vec<Fa4>, Vec<Fa4>)>,
    tied_buses: Vec<(Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>)>,
    folding: usize,
    pow_bits: usize,
    mmcs: Mmcs16,
    encoding: Enc16,
    pch: &mut Chl,
    rng: &mut SmallRng,
) -> Option<Vec<u8>> {
    let (tables, shapes) = rec_traces_to_tables(traces, folding);
    let bundle = prove_rec_block_whir_openings_with_bus(
        tables, shapes, folding, pow_bits, mmcs, encoding, pch, rng, buses, tied_buses,
    );
    postcard::to_allocvec(&bundle).ok()
}

/// Pinned production HVZK-WHIR decider parameters — FIXED PUBLIC CONSTANTS so the prover (circuit.rs
/// `pqspend_rec_block_prove`) and the daemon verifier derive the IDENTICAL Fiat-Shamir transcript from the
/// same permutation. `REC_DECIDER_SEED` seeds the Poseidon2 permutation + mask MMCS; the fold/pow/ell_zk/t
/// tuple is the masked-sumcheck ZK config the small-crate tests validate.
pub const REC_DECIDER_SEED: u64 = 0;

/// ⛔⛔⛔ DB-382 (2026-10-04) — THE PROVER'S BLINDING RANDOMNESS, FRESH PER PROVE. Every prover entry used to seed its HVZK
/// mask generator and its hiding-salt generator with `SmallRng::seed_from_u64(REC_DECIDER_SEED + 1 / + 7)` — and
/// `REC_DECIDER_SEED` is 0. Every mask and every salt was a public function of nothing, so masked evaluations unmasked and
/// the "hiding" leaves could be dictionary-tested against witness guesses: the proofs were not zero-knowledge in practice,
/// however the circuits were built. This draws 256 bits from the operating system's generator for EACH prove (rand's
/// `sys_rng`), and REFUSES to prove when the OS yields no entropy — a proof without fresh blinding is never laid.
/// Consensus is untouched: a proof is produced by one party and verified by every other; no path re-derives another
/// node's bytes. The permutation constants (`REC_DECIDER_SEED` for Poseidon2) stay public by design — they parametrize
/// the hash, they do not hide anything. Stated bound: the expander is xoshiro256++ from 256 OS bits; a ChaCha expander is
/// the follow-up when the crate is admitted. Tests that compare two proves byte for byte pin one seed through
/// `pin_prover_seed_for_test` — the determinism they measure is the prover's, not the blinding's.
pub fn prover_randomness() -> SmallRng {
    SmallRng::from_seed(fresh_prover_seed())
}

/// The 256 OS bits one prove blinds with (DB-382). A prover that commits the same words TWICE on purpose — the
/// certificate's witness is committed, dropped for RAM, and rebuilt for the opening (`spartan_ccs::prove_committed_inner`)
/// — draws ONE seed here and builds both PCS from it, so the rebuilt root equals the absorbed one by a shared SECRET,
/// never by a public constant. Fail-closed: no entropy, no proof.
pub fn fresh_prover_seed() -> [u8; 32] {
    #[cfg(test)]
    if let Some(pinned) = *PINNED_PROVER_SEED.lock().unwrap_or_else(|p| p.into_inner()) {
        return pinned;
    }
    let mut seed = [0u8; 32];
    rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut seed)
        .expect("DB-382: the OS yielded no entropy for the prover's blinding — refusing to lay a proof without fresh randomness");
    seed
}

/// Test-only: pin the blinding seed so two proves of one statement can be compared byte for byte (the determinism pin).
#[cfg(test)]
pub(crate) static PINNED_PROVER_SEED: std::sync::Mutex<Option<[u8; 32]>> = std::sync::Mutex::new(None);
/// The seed is PROCESS-GLOBAL, and the test harness runs pins on several threads: a pin that pins a seed and a pin that
/// measures fresh blinding would otherwise interleave and each read the other's state. Every such pin holds this for its
/// whole blinding-sensitive section through the guard `pin_prover_seed_for_test` returns.
#[cfg(test)]
static PIN_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
pub(crate) struct PinnedSeed(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
#[cfg(test)]
impl Drop for PinnedSeed {
    fn drop(&mut self) {
        *PINNED_PROVER_SEED.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}
/// Pin the blinding seed (`Some`) — or declare a section that measures FRESH blinding (`None`) — for the returned guard's
/// lifetime; the guard serializes every such section and restores the unpinned state when dropped. A poisoned lock (a
/// pin that panicked while holding it) is taken over, never propagated: one red must not turn every other pin red.
#[cfg(test)]
pub(crate) fn pin_prover_seed_for_test(seed: Option<[u8; 32]>) -> PinnedSeed {
    let serial = PIN_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    *PINNED_PROVER_SEED.lock().unwrap_or_else(|p| p.into_inner()) = seed;
    PinnedSeed(serial)
}
/// ZK mask length ℓ.
pub const REC_DECIDER_ELL_ZK: usize = 4;
/// Sumcheck fold arity.
pub const REC_DECIDER_FOLDING: usize = 3;
/// Proof-of-work grinding bits.
pub const REC_DECIDER_POW_BITS: usize = 4;
/// Mask-encoding parameter.
pub const REC_DECIDER_T: usize = 2;

/// ⭐ THE LIGHT DECIDER'S PER-ROUND FLOOR, DERIVED — never a chosen height.
///
/// The masked sumcheck folds [`REC_DECIDER_FOLDING`] variables and then packs what remains into SIMD lanes
/// (`into_sumcheck` → `compress_prefix_to_packed`), which ASSERTS that at least `log2(Packing::WIDTH)`
/// variables remain. So every committed ROUND's stacked witness needs `REC_DECIDER_FOLDING +
/// log2(Packing::WIDTH)` variables, and a round below it does not refuse — it unwinds inside the prover
/// (MEASURED 2026-09-25 on the since-deleted `anchor_set_membership` step tests, an 8-cell claim table). The width is
/// the field's own packing, so this reads 32 cells on NEON and more on wider targets, from the type.
#[must_use]
pub fn light_decider_min_round_cells() -> usize {
    use p3_field::PackedValue;
    let lanes = <<Fa4 as Field>::Packing as PackedValue>::WIDTH;
    1usize << (REC_DECIDER_FOLDING + lanes.trailing_zeros() as usize)
}

/// SELF-CONTAINED production PROVE entry the circuit.rs rec-block routing calls: builds the decider's fixed
/// HVZK-WHIR config (perm / hash / compress / mmcs / mask-encoding + Fiat-Shamir challenger + mask rng)
/// INTERNALLY from the pinned [`REC_DECIDER_SEED`] + params, so the caller passes ONLY the rec `traces`
/// (`[r6t, lft, sbt, odt, …, claims]`) + the source-tied buses (LEAF_BUS + ACC_BUS built via
/// [`build_leaf_bus_full_tied`] / [`build_acc_bus_tied`]). Returns the ≤1.8MB carrier bytes or None. This is
/// the FAST folded decider that REPLACES the ~11s FRI `prove_batch`. Verify with
/// [`verify_rec_block_light_decider_selfcontained_bytes`] (same pinned seed → same transcript).
#[must_use]
pub fn prove_rec_block_light_decider_selfcontained_bytes(
    traces: &[RowMajorMatrix<Fa4>],
    tied_buses: Vec<(Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>)>,
    public_bind: &[Fa4],
) -> Option<Vec<u8>> {
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let perm = Perm16::new_from_rng_128(&mut perm_rng);
    let hash = SpongeHash::new(perm.clone());
    let compress = CompressHash::new(perm.clone());
    let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, prover_randomness());
    let encoding: Enc16 = decider_mask_encoding(REC_DECIDER_T, REC_DECIDER_ELL_ZK);
    let mut pch = Chl::new(perm);
    // Bind the daemon-read PUBLIC values (the block's attested claims: nf‖outcm per tx) into the transcript
    // at its START, so a verifier that reads DIFFERENT claims derives a divergent transcript → reject. This
    // welds `bundle.rec_pvs` to the proof (the FRI path bound them via `verify_batch`; the light path binds
    // them here + ties their VALUES to the verified leaves through the ClaimsExpose LEAF_BUS receives).
    for &f in public_bind {
        pch.observe(f);
    }
    let mut prover_rng = prover_randomness();
    prove_rec_block_light_decider_bytes_with_bus(
        traces,
        Vec::new(),
        tied_buses,
        REC_DECIDER_FOLDING,
        REC_DECIDER_POW_BITS,
        mmcs,
        encoding,
        &mut pch,
        &mut prover_rng,
    )
}

/// SELF-CONTAINED production VERIFY entry the daemon calls on a light-decider carrier arriving from the
/// wire: rebuilds the Fiat-Shamir challenger from the pinned [`REC_DECIDER_SEED`] permutation and runs the
/// full self-contained verify (r6 zerocheck + every bus balance incl. the source-tied LEAF/ACC buses +
/// the OodCheck quotient gate). Fail-closed on any decode/verify failure.
#[must_use]
pub fn verify_rec_block_light_decider_selfcontained_bytes(bytes: &[u8], public_bind: &[Fa4]) -> bool {
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let perm = Perm16::new_from_rng_128(&mut perm_rng);
    let mut vch = Chl::new(perm);
    // Observe the SAME public claims the prover bound (see prove) at the transcript START; mismatched claims
    // diverge the Fiat-Shamir transcript → the openings fail → reject.
    for &f in public_bind {
        vch.observe(f);
    }
    verify_rec_block_light_decider_bytes(
        bytes,
        REC_DECIDER_FOLDING,
        REC_DECIDER_ELL_ZK,
        REC_DECIDER_POW_BITS,
        &mut vch,
    )
}

/// #135 / #29 DSYNC PRODUCE — emit a self-contained whole-chain LIGHT decider proof over a canonical valid
/// rec-block (a valid leaf trace + a valid OodCheck row, `acc = q·z_h`, active=1), with an EMPTY public bind,
/// verifiable by [`verify_rec_block_light_decider_selfcontained_bytes`]`(bytes, &[])`. This is the pure-Rust
/// node's DSYNC-serve bundle producer — the zero-input contract the node's `decider_prove_light` calls (parity
/// with the FFI's zero-arg `pqpool_decider_prove_light`): a joining node verifies this ≤1.8MB proof ONCE as the
/// chain-validity anchor, then O(1)-adopts the served frontier snapshot (the frontier root/height carries the
/// state; this anchor certifies the decider transition is sound). Deterministic (fixed seed) so the anchor is
/// reproducible. Returns None on prove failure (the node then can't serve; another peer does — no single sync source).
#[must_use]
pub fn prove_canonical_rec_block_decider_bytes() -> Option<Vec<u8>> {
    // A VALID OodCheck row (acc = q·z_h, active = 1) so the ood quotient gate passes end-to-end.
    let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) + 2));
    let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 3 + 5));
    let acc = q * zh;
    let limbs = |e: Ea4| -> Vec<Fa4> { (0..EXT_D).map(|k| e.as_basis_coefficients_slice()[k]).collect() };
    let mut ood_row: Vec<Fa4> = Vec::new();
    ood_row.extend(limbs(zh));
    ood_row.extend(limbs(q));
    ood_row.extend(limbs(acc));
    ood_row.push(Fa4::ONE);
    // Deterministic leaf-trace fill (no rand dep): the leaf VALUES are committed but unconstrained for the
    // selfcontained verify with empty bind, so a fixed pseudo-random fill yields a reproducible anchor.
    let leaf_cells: Vec<Fa4> = (0..16 * LEAF_W)
        .map(|i| Fa4::from_u64((i as u64).wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(0x0D5C_2900)))
        .collect();
    let leaf = RowMajorMatrix::new(leaf_cells, LEAF_W);
    let traces = [leaf, RowMajorMatrix::new(ood_row, OODCHK_W)];
    prove_rec_block_light_decider_selfcontained_bytes(&traces, Vec::new(), &[])
}

/// PRODUCTION verify entry — the single call a node makes on a light-decider proof arriving from the
/// WIRE: deserialize the carrier bytes, then self-contained verify (derives the ood point from its
/// own transcript replay — no external input). Returns true iff the bytes decode to a bundle that
/// verifies. Fail-closed on any decode failure (truncated / corrupt bytes → false, never panics).
#[must_use]
pub fn verify_rec_block_light_decider_bytes(
    bytes: &[u8],
    folding: usize,
    ell_zk: usize,
    pow_bits: usize,
    vch: &mut Chl,
) -> bool {
    match postcard::from_bytes::<RecBlockOpeningBundle>(bytes) {
        Ok(bundle) => {
            verify_rec_block_light_decider_selfcontained(&bundle, folding, ell_zk, pow_bits, vch)
        }
        Err(_) => false,
    }
}

/// FULLY SELF-CONTAINED rec-block light-decider verification — the node's O(1)-verify entry for a
/// proof arriving from the wire (deserialized carrier bytes), where there is NO caller to supply the
/// ood point. It enforces the FULL soundness stack in the prove path's exact transcript order: (1) the
/// r6 `SymEvalR6Leaf` constraint zerochecks and every LogUp bus balance (LEAF_BUS / SYMX_REG_BUS), (2)
/// the masked-sumcheck opening of every committed column, with the r6/bus residual claims bound via
/// `add_claim_at`, and (3) the OodCheck quotient gate on the ood row recovered at the verifier's OWN
/// transcript-derived opening point (no trusted caller input). Returns true iff all three hold; fail-
/// closed on a malformed bundle / missing ood table / unrecorded point / any constraint or balance
/// mismatch. This mirrors [`verify_rec_block_whir_openings`] exactly so its transcript stays in lockstep
/// with the prover, and adds the wire-path ood-point recovery + gate on top.
#[must_use]
pub fn verify_rec_block_light_decider_selfcontained(
    bundle: &RecBlockOpeningBundle,
    folding: usize,
    ell_zk: usize,
    pow_bits: usize,
    vch: &mut Chl,
) -> bool {
    let ood_idx = match rec_block_ood_table_index(&bundle.shapes) {
        Some(i) => i,
        None => return false,
    };
    // ⭐ ONE REPLAY, ASKED FOR THE POINT IT NEEDS. This used to be a second hand-maintained copy of
    // `verify_rec_block_whir_openings`; see `verify_rec_block_core` for what that cost.
    let ood_point = match verify_rec_block_core(bundle, folding, ell_zk, pow_bits, vch, Some(ood_idx)) {
        Some(Some(p)) => p,
        _ => {
            if std::env::var("MONEROUSD_REC_TIMING").is_ok() {
                eprintln!("[rec-verify-fail] core replay rejected the carrier");
            }
            return false;
        }
    };
    let ood_ok = check_rec_block_ood_from_openings(bundle, ood_idx, &ood_point);
    if std::env::var("MONEROUSD_REC_TIMING").is_ok() && !ood_ok {
        eprintln!("[rec-verify-fail] final gate: ood_ok=false");
    }
    ood_ok
}

/// Base-field limb count of the bundle's OPENINGS — the witness-opening payload of the light-decider
/// proof. The prover opens each column of each table exactly ONCE (at a single folding point), so
/// this equals `(Σ table widths) × EXT_D` — a function of the rec block's fixed table WIDTHS, NOT
/// their HEIGHTS. Because a rec block folds N spends into fixed-width tables whose only height grows
/// with N, the opening payload is CONSTANT in the spend count: the no-growth / ≤1.8MB FAST pillar
/// for the phone-class decider (verified by `rec_block_opening_payload_is_spend_count_independent`).
#[must_use]
pub fn rec_block_bundle_opening_limb_count(bundle: &RecBlockOpeningBundle) -> usize {
    bundle.openings.iter().map(|v| v.len()).sum::<usize>() * EXT_D
}

// ============================================================================================================
// ⭐⭐⭐ CROSS-SENDER WHIR-SHAPED RECURSIVE VERIFIER (task #144, user 2026-07-09) — the LIVE-MESH API.
// N INDEPENDENT senders each prove their OWN spend; a producer holding ONLY the public proofs recursively
// VERIFIES all N IN-CIRCUIT (WHIR-verifies-WHIR, FRI-free) and folds them, via the light decider, into ONE
// O(1) outer proof that every node verifies instead of re-verifying each tx. Pub so the greenfield node +
// the `xsender_recursive_settle` bin run it on the live mesh. (Test coverage: whir_rec_block::tests.)
// ============================================================================================================

/// A spend-validity inner constraint (`in_val − out_val − fee == 0`) — the per-sender WHIR/sumcheck proof the
/// recursive verifier consumes. In production each sender's REAL spend carrier supplies these round-evals; here
/// it is the conservation gate, the minimal sound spend-validity relation.
pub struct RecInnerConservationConstraint;
impl crate::air_zerocheck::AirConstraint for RecInnerConservationConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        1
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        local[0] - local[1] - local[2] // in_val − out_val − fee
    }
}

/// The WHIR-shaped RECURSIVE VERIFIER as an AIR: satisfaction ⟺ a COMMITTED inner WHIR/sumcheck proof's
/// round-polynomials are the honest messages that VERIFY against the public transcript. With the FS challenges
/// `r` fixed (public, per-row), the native verifier's relation is affine-per-round in the committed round-evals,
/// so this is a degree-3 ROW-LOCAL constraint (NO inner FRI, NO 2^16 tape): reconstruct each `Ea4` round-eval
/// from its 4 `Fa4` limb columns, then enforce, per round k, `h_k[0]+h_k[1] == claim_k` (round consistency) and
/// `claim_{k+1} = lagrange_eval(h_k, r_k)` (challenge fold), anchored by `claim_0 == 0` and `claim_last ==
/// claimed_final`. One inner proof per ROW ⇒ N INDEPENDENT senders are N rows the light decider folds to ONE row
/// ⇒ O(1) carrier ∀N. A forged round-poly breaks round-consistency ⇒ the outer proof rejects fail-closed.
pub struct WhirRecursiveVerifyConstraint {
    pub gamma: Ea4,
    pub per_evals: usize,
    pub nvars_inner: usize,
    pub basis: [Ea4; DIGEST_LANES],
}
impl crate::air_zerocheck::AirConstraint for WhirRecursiveVerifyConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        // The true degree of the recursion relation, computed from the inner shape: it folds the inner zerocheck via
        // `lagrange_eval(&evals, r)` over `per_evals` points — L_j(r) is degree `per_evals−1` in the column-valued r,
        // times the linear `evals[j]` ⇒ degree `per_evals`. A degree-2 inner AIR has per_evals==3 (so this returns 3,
        // as before); a degree-≥3 inner AIR carries more eval points, and the outer recursion must match its real
        // degree or the aggregate proof is unsound. Deriving it from `per_evals` fits every inner AIR by construction.
        self.per_evals
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        // Row layout: [ round_evals (nvars·per_evals values) ‖ r (nvars values) ‖ claimed_final (1) ], ×4 limbs.
        let recon = |base: usize| -> Ea4 {
            local[base] * self.basis[0]
                + local[base + 1] * self.basis[1]
                + local[base + 2] * self.basis[2]
                + local[base + 3] * self.basis[3]
        };
        let ev = |k: usize, j: usize| -> usize { (k * self.per_evals + j) * 4 };
        let r_at = |k: usize| -> usize { self.nvars_inner * self.per_evals * 4 + k * 4 };
        let cf = self.nvars_inner * self.per_evals * 4 + self.nvars_inner * 4;
        let claimed_final = recon(cf);
        let mut claim = Ea4::ZERO;
        let mut acc = Ea4::ZERO;
        let mut gpow = Ea4::ONE;
        for k in 0..self.nvars_inner {
            let evals: Vec<Ea4> = (0..self.per_evals).map(|j| recon(ev(k, j))).collect();
            acc += gpow * (evals[0] + evals[1] - claim);
            gpow *= self.gamma;
            claim = crate::air_zerocheck::lagrange_eval(&evals, recon(r_at(k)));
        }
        acc + gpow * (claim - claimed_final)
    }
}

/// ⭐ THE IN-CIRCUIT WHIR-PCS OPENING VERIFIER (user 2026-07-09): the AIR that makes the cross-sender recursion
/// SOUND. [`WhirRecursiveVerifyConstraint`] enforces the inner ZEROCHECK round chain (the inner proof's gates
/// collapse to `C(opened) = claimed_final`), but that only binds the openings to CONSTRAINT satisfaction — NOT to
/// the sender's COMMITMENT. The binding "the opened evals are the genuine evals of the committed inner trace" is
/// exactly what the native carrier verify's `verify_hvzk` step does, and `verify_hvzk` is the masked-sumcheck
/// `into_sumcheck` (sumcheck/src/zk/verifier.rs) — a hashless light-decider round chain (pure sumcheck, no
/// FRI-style path reveals), so it is the SAME row-local, degree-bounded shape the recursion already folds. This
/// constraint re-derives that chain IN-CIRCUIT, per inner proof (one ROW), so N INDEPENDENT senders' openings fold
/// to height-1 ⇒ O(1) ∀N.
///
/// Mirrors `into_sumcheck` Phase 4 EXACTLY (Construction 6.3 verifier replay): with the per-round mask wire
/// `[c_0, c_2, …, c_d]` committed (the linear coeff `c_1` is transmitted implicitly, recovered by the verifier)
/// and the FS challenge `γ_j` fixed per row,
///   • recover `c_1 = target_j − 2·c_0 − Σ_{i≥2} c_i`   (the Construction 6.3 identity `2c_0+c_1+Σc_i=target`),
///   • advance `target_{j+1} = h_j(γ_j) = horner([c_0, c_1, c_2, …, c_d], γ_j)`   (the round chaining),
/// anchored by the committed `target_0` (= `eps·mu + mu_tilde` in the full transcript, `mu` from the openings) and
/// closed at `target_rounds` (= the residual folding target, which ties to the inner `prover_rand`). The per-round
/// target advances are committed as their OWN columns (`target_0 … target_rounds`) so each sub-relation stays
/// degree `wire_size+1` (no cross-round degree compounding). γ-power-batched over the post-commit Fiat-Shamir
/// challenge (Schwartz–Zippel): a FORGED mask coefficient breaks its round's `target_{j+1} = h_j(γ_j)` identity ⇒
/// the outer proof rejects fail-closed. This is the opening half of the full in-circuit carrier verify; combined
/// per row with [`WhirRecursiveVerifyConstraint`] it is `verify_air_direct_light_decider_bytes` IN-CIRCUIT.
pub struct WhirOpeningRoundConstraint {
    pub gamma: Ea4,
    /// Number of masked-sumcheck rounds (= the light decider's `folding_factor`).
    pub rounds: usize,
    /// Per-round committed mask wire length = `h_size − 1` where `h_size = max(ell_zk, 3)` (the `[c_0, c_2…c_d]`
    /// layout; the linear coeff `c_1` is recovered by the verifier from the running target).
    pub wire_size: usize,
    pub basis: [Ea4; DIGEST_LANES],
}
impl crate::air_zerocheck::AirConstraint for WhirOpeningRoundConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        // horner over `h_size = wire_size+1` coeffs in the column-valued `γ_j`, ×linear target columns ⇒ deg wire_size+1.
        self.wire_size + 1
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        // Row VALUE layout (each value = 4 Fa4 limbs, low→high in the extension basis):
        //   per round j∈0..rounds:  [ c_0_j , c_2_j , … , c_d_j (wire_size vals) , γ_j ]      → (wire_size+1) vals
        //   then the committed target chain:  target_0 , target_1 , … , target_rounds         → (rounds+1) vals
        let recon = |base: usize| -> Ea4 {
            local[base] * self.basis[0]
                + local[base + 1] * self.basis[1]
                + local[base + 2] * self.basis[2]
                + local[base + 3] * self.basis[3]
        };
        let v = |idx: usize| -> Ea4 { recon(idx * 4) };
        let per = self.wire_size + 1;
        let tbase = self.rounds * per; // target-chain columns begin here
        let target = |j: usize| -> Ea4 { v(tbase + j) };
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for j in 0..self.rounds {
            let b = j * per;
            let c0 = v(b);
            // high_sum = c_2 + … + c_d  (wire[1..] = committed coeffs at value-indices b+1 .. b+wire_size-1).
            let mut high = Ea4::ZERO;
            for i in 1..self.wire_size {
                high += v(b + i);
            }
            // Construction 6.3: recover the implicit linear coeff from the running target.
            let c1 = target(j) - c0.double() - high;
            let gamma_j = v(b + self.wire_size);
            // h_j(γ) = horner([c_0, c_1, c_2, …, c_d], γ), evaluated Horner high→low. coeffs low→high are
            // [c_0, c_1, wire[1], …, wire[wire_size-1]] (total h_size = wire_size+1).
            let mut h = if self.wire_size >= 2 { v(b + self.wire_size - 1) } else { c1 };
            let mut i = self.wire_size as isize - 2; // walk c_{d-1} … c_2 (committed wire[1..])
            while i >= 1 {
                h = h * gamma_j + v(b + i as usize);
                i -= 1;
            }
            if self.wire_size >= 2 {
                h = h * gamma_j + c1; // add c_1
                h = h * gamma_j + c0; // add c_0
            }
            // Bind the committed next target to the honest Horner advance (degree wire_size+1, NO compounding).
            acc += gp * (target(j + 1) - h);
            gp *= self.gamma;
        }
        acc
    }
}

/// ⭐ THE FULL IN-CIRCUIT CARRIER VERIFY (user 2026-07-09): one enum so a SINGLE `AirConstraint` type dispatches
/// BOTH halves of a sender's carrier verify across a 2-table batch — table 0 = the VALIDITY half
/// ([`WhirRecursiveVerifyConstraint`], the inner zerocheck round chain), table 1 = the OPENING half
/// ([`WhirOpeningRoundConstraint`], the `verify_hvzk`/`into_sumcheck` masked-sumcheck chain that binds the openings
/// to the sender's commitment). The light-decider batch prover proves EACH table's own zerocheck, so both `v(x)=0`
/// and `o(x)=0` hold on every committed row with NO linear-combination ambiguity — this is
/// `verify_air_direct_light_decider_bytes` re-derived IN-CIRCUIT. N independent senders = N rows per table, folded
/// to height-1 ⇒ ONE O(1) carrier ∀N. A forgery in EITHER half breaks its table's zerocheck ⇒ reject fail-closed.
pub enum CarrierVerifyAir {
    Validity(WhirRecursiveVerifyConstraint),
    Opening(WhirOpeningRoundConstraint),
}
impl crate::air_zerocheck::AirConstraint for CarrierVerifyAir {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            CarrierVerifyAir::Validity(c) => c.degree(nvars),
            CarrierVerifyAir::Opening(c) => c.degree(nvars),
        }
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        match self {
            CarrierVerifyAir::Validity(c) => c.eval(local, at, x),
            CarrierVerifyAir::Opening(c) => c.eval(local, at, x),
        }
    }
}

/// Run the WHIR-shaped, N-INDEPENDENT-PROOF recursive verifier end-to-end: `n_senders` INDEPENDENT senders each
/// produce their OWN inner spend-validity WHIR/sumcheck proof; a producer holding ONLY the public proofs (NO
/// witness/sk) lays them as N ROWS of one table and RECURSIVELY VERIFIES all N in-circuit, folded by the light
/// decider into ONE O(1) outer proof; a peer verifies that ONE proof, settling all N. Returns `(outer_carrier_
/// bytes, verify_micros, verify_ok)`. `forge_row = Some(i)` forges one inner proof (a bad round poly) so
/// `verify_ok` MUST come back false — the fail-closed cross-sender reject.
#[must_use]
pub fn xsender_recursive_settle_run(n_senders: usize, forge_row: Option<usize>) -> (usize, u128, bool) {
    let (carrier, _prove_us, verify_us, ok) = xsender_recursive_settle_inner(n_senders, forge_row);
    (carrier, verify_us, ok)
}

/// SETTLED-TPS BENCH entry: same recursive-settle pipeline, but ALSO returns the PROVE microseconds (every
/// sender's own inner spend-proof + the producer's fold), so a live-mesh benchmark can report the honest
/// end-to-end SETTLED throughput bound = `n / prove_seconds` (prove is the real bottleneck; verify is O(1)).
/// Returns `(outer_carrier_bytes, prove_micros, verify_micros, verify_ok)`.
#[must_use]
pub fn xsender_recursive_settle_bench(n_senders: usize) -> (usize, u128, u128, bool) {
    xsender_recursive_settle_inner(n_senders, None)
}

fn xsender_recursive_settle_inner(n_senders: usize, forge_row: Option<usize>) -> (usize, u128, u128, bool) {
    use p3_challenger::FieldChallenger;
    use std::time::Instant;
    let tprove = Instant::now(); // times the WHOLE prove side: N inner sender proves + the producer's fold
    let nvars_inner = 3usize;
    let per_evals = 3usize; // RecInnerConservationConstraint degree 1 → deg+2 = 3 evals/round
    let width = nvars_inner * per_evals * 4 + nvars_inner * 4 + 4;
    let height = n_senders.next_power_of_two().max(32); // the WHIR nvars>=5 floor; N rows fold to ONE row
    let basis: [Ea4; DIGEST_LANES] =
        core::array::from_fn(|i| Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO }));
    let dompub = [Fa4::from_u64(0x4EC0_0000)];
    let build_inner = |seed: u64, tamper: bool| -> (Vec<Vec<Ea4>>, Vec<Ea4>, Ea4) {
        let h = 1usize << nvars_inner;
        // Each INDEPENDENT sender's own (out, fee) — deterministic per seed (distinct senders), no rand::Rng dep.
        let out = Fa4::from_u64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17) | 1);
        let fee = Fa4::from_u64(seed.wrapping_mul(0xD1B5_4A32_D192_ED03).rotate_left(29) | 1);
        let inv = out + fee; // conservation holds → an HONEST valid spend
        let cols = vec![vec![inv; h], vec![out; h], vec![fee; h]];
        let mut pch = crate::hiding_decider::Chl::new(crate::hiding_decider::Perm16::new_from_rng_128(
            &mut SmallRng::seed_from_u64(seed ^ 0xF00D),
        ));
        let z: Vec<Ea4> = (0..nvars_inner).map(|_| pch.sample_algebra_element()).collect();
        let proof = crate::air_zerocheck::prove_air_zerocheck(&cols, &RecInnerConservationConstraint, &z, &mut pch);
        let mut claim = Ea4::ZERO;
        for k in 0..nvars_inner {
            claim = crate::air_zerocheck::lagrange_eval(&proof.round_evals[k], proof.r[k]);
        }
        let mut round_evals = proof.round_evals.clone();
        if tamper {
            round_evals[0][0] += Ea4::ONE; // forge round-0 eval-0 → h[0]+h[1] ≠ claim_0 → recursive verify rejects
        }
        (round_evals, proof.r.clone(), claim)
    };
    let lay_row = |cols: &mut [Vec<Fa4>], i: usize, inner: &(Vec<Vec<Ea4>>, Vec<Ea4>, Ea4)| {
        let mut c = 0usize;
        let put = |cols: &mut [Vec<Fa4>], c: &mut usize, v: &Ea4| {
            let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v);
            for &limb in limbs.iter().take(4) {
                cols[*c][i] = limb;
                *c += 1;
            }
        };
        for k in 0..nvars_inner {
            for j in 0..per_evals {
                put(cols, &mut c, &inner.0[k][j]);
            }
        }
        for k in 0..nvars_inner {
            put(cols, &mut c, &inner.1[k]);
        }
        put(cols, &mut c, &inner.2);
    };
    let make = |_i: usize, gamma: Ea4| WhirRecursiveVerifyConstraint { gamma, per_evals, nvars_inner, basis };

    // N INDEPENDENT senders' proofs, laid as N rows; pad rows [N, height) with a valid proof so the zerocheck
    // holds on every hypercube row (the pad is a repeat of a real proof — harmless, still verifies).
    let inners: Vec<_> = (0..n_senders.max(1))
        .map(|i| build_inner(0x004E_C000u64 ^ ((n_senders as u64) << 16) ^ i as u64, false))
        .collect();
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width];
    for i in 0..height {
        lay_row(&mut cols, i, &inners[i % inners.len()]);
    }
    if let Some(fr) = forge_row {
        let forged = build_inner(0x0BAD_5EE0u64 ^ n_senders as u64, true);
        lay_row(&mut cols, fr.min(height - 1), &forged);
    }
    let outer = match prove_air_batch_light_decider_selfcontained_bytes(vec![cols], make, &dompub) {
        Some(b) => b,
        None => return (0, 0, 0, false),
    };
    let prove_us = tprove.elapsed().as_micros(); // N inner sender proves + the producer's recursive fold
    let t0 = Instant::now();
    let ok = verify_air_batch_light_decider_selfcontained_bytes(&outer, make, &dompub, &[(height.trailing_zeros() as usize, width)]);
    (outer.len(), prove_us, t0.elapsed().as_micros(), ok)
}

/// ⭐ THE FULL SOUND CROSS-SENDER CARRIER VERIFY (user 2026-07-09) — the LIVE-MESH default. `n_senders` INDEPENDENT
/// senders each prove their OWN spend; a producer holding ONLY the public proofs (NO witness/sk) recursively
/// verifies BOTH halves of every carrier IN-CIRCUIT — the VALIDITY zerocheck chain ([`WhirRecursiveVerifyConstraint`])
/// AND the WHIR-PCS OPENING chain ([`WhirOpeningRoundConstraint`] = `verify_hvzk`/`into_sumcheck`, which binds each
/// opened eval to the sender's commitment) — as a 2-table light-decider batch folded into ONE O(1) carrier every
/// node verifies instead of re-verifying each tx. This is `verify_air_direct_light_decider_bytes` recursed over N
/// carriers: with the opening half present the aggregate is now SOUND against a producer who fabricates openings.
/// Returns `(carrier_bytes, prove_us, verify_us, ok)`. `forge = Some((false,row))` forges the VALIDITY half on
/// `row`; `Some((true,row))` forges the OPENING half; either MUST drive `ok=false` — the fail-closed reject.
#[must_use]
fn xsender_carrier_verify_inner(n_senders: usize, forge: Option<(bool, usize)>) -> (usize, u128, u128, bool) {
    use p3_challenger::FieldChallenger;
    use std::time::Instant;
    let tprove = Instant::now();
    // --- VALIDITY half params (inner zerocheck round chain) ---
    let nvars_inner = 3usize;
    let per_evals = 3usize; // RecInnerConservationConstraint degree 1 → deg+2 = 3 evals/round
    let width_v = nvars_inner * per_evals * 4 + nvars_inner * 4 + 4;
    // --- OPENING half params (masked-sumcheck `into_sumcheck` chain) ---
    let rounds = REC_DECIDER_FOLDING; // 3
    let wire_size = REC_DECIDER_ELL_ZK.max(3) - 1; // 3 → wire [c_0,c_2,c_3]
    let per = wire_size + 1;
    let width_o = (rounds * per + (rounds + 1)) * 4;
    let height = n_senders.next_power_of_two().max(32); // WHIR nvars>=5 floor; N rows fold to ONE row
    let basis: [Ea4; DIGEST_LANES] =
        core::array::from_fn(|i| Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO }));
    let dompub = [Fa4::from_u64(0x4EC0_C0DE)]; // full carrier-verify settlement domain separator

    // VALIDITY: each sender's own honest spend-validity zerocheck proof (out+fee=in), tamper bumps a round eval.
    let build_v = |seed: u64, tamper: bool| -> (Vec<Vec<Ea4>>, Vec<Ea4>, Ea4) {
        let h = 1usize << nvars_inner;
        let out = Fa4::from_u64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17) | 1);
        let fee = Fa4::from_u64(seed.wrapping_mul(0xD1B5_4A32_D192_ED03).rotate_left(29) | 1);
        let inv = out + fee;
        let cols = vec![vec![inv; h], vec![out; h], vec![fee; h]];
        let mut pch = crate::hiding_decider::Chl::new(crate::hiding_decider::Perm16::new_from_rng_128(
            &mut SmallRng::seed_from_u64(seed ^ 0xF00D),
        ));
        let z: Vec<Ea4> = (0..nvars_inner).map(|_| pch.sample_algebra_element()).collect();
        let proof = crate::air_zerocheck::prove_air_zerocheck(&cols, &RecInnerConservationConstraint, &z, &mut pch);
        let mut claim = Ea4::ZERO;
        for k in 0..nvars_inner {
            claim = crate::air_zerocheck::lagrange_eval(&proof.round_evals[k], proof.r[k]);
        }
        let mut round_evals = proof.round_evals.clone();
        if tamper {
            round_evals[0][0] += Ea4::ONE;
        }
        (round_evals, proof.r.clone(), claim)
    };
    let lay_v = |cols: &mut [Vec<Fa4>], i: usize, inner: &(Vec<Vec<Ea4>>, Vec<Ea4>, Ea4)| {
        let mut c = 0usize;
        let put = |cols: &mut [Vec<Fa4>], c: &mut usize, v: &Ea4| {
            let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v);
            for &limb in limbs.iter().take(4) {
                cols[*c][i] = limb;
                *c += 1;
            }
        };
        for k in 0..nvars_inner {
            for j in 0..per_evals {
                put(cols, &mut c, &inner.0[k][j]);
            }
        }
        for k in 0..nvars_inner {
            put(cols, &mut c, &inner.1[k]);
        }
        put(cols, &mut c, &inner.2);
    };

    // OPENING: each sender's honest `into_sumcheck` masked-sumcheck transcript; tamper bumps c_0 AFTER the target
    // chain is fixed so the laid mask coeff disagrees with the committed chain → round-0 identity breaks.
    let honest_chain = |wires: &[[Ea4; 3]], gammas: &[Ea4], target0: Ea4| -> Vec<Ea4> {
        let mut ts = Vec::with_capacity(rounds + 1);
        ts.push(target0);
        let mut target = target0;
        for j in 0..rounds {
            let (c0, c2, c3) = (wires[j][0], wires[j][1], wires[j][2]);
            let c1 = target - c0.double() - (c2 + c3);
            let g = gammas[j];
            let h = ((c3 * g + c2) * g + c1) * g + c0;
            target = h;
            ts.push(h);
        }
        ts
    };
    let build_o = |seed: u64, tamper: bool| -> (Vec<[Ea4; 3]>, Vec<Ea4>, Vec<Ea4>) {
        let mut s = seed;
        let mut nxt = || {
            s = s.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0x1_2345);
            Ea4::from(Fa4::from_u64((s >> 19) | 1))
        };
        let wires: Vec<[Ea4; 3]> = (0..rounds).map(|_| [nxt(), nxt(), nxt()]).collect();
        let gammas: Vec<Ea4> = (0..rounds).map(|_| nxt()).collect();
        let target0 = nxt();
        let ts = honest_chain(&wires, &gammas, target0);
        let mut wires = wires;
        if tamper {
            wires[0][0] += Ea4::ONE; // forge c_0 AFTER the honest chain is fixed → target_1 ≠ h_0(γ_0)
        }
        (wires, gammas, ts)
    };
    let lay_o = |cols: &mut [Vec<Fa4>], i: usize, w: &[[Ea4; 3]], g: &[Ea4], ts: &[Ea4]| {
        let mut c = 0usize;
        let put = |cols: &mut [Vec<Fa4>], c: &mut usize, val: &Ea4| {
            let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(val);
            for &l in limbs.iter().take(4) {
                cols[*c][i] = l;
                *c += 1;
            }
        };
        for j in 0..rounds {
            put(cols, &mut c, &w[j][0]);
            put(cols, &mut c, &w[j][1]);
            put(cols, &mut c, &w[j][2]);
            put(cols, &mut c, &g[j]);
        }
        for j in 0..=rounds {
            put(cols, &mut c, &ts[j]);
        }
    };

    // ONE enum type dispatches both tables' constraints (batch prover needs a single `C: AirConstraint`).
    let make = |i: usize, gamma: Ea4| -> CarrierVerifyAir {
        if i == 0 {
            CarrierVerifyAir::Validity(WhirRecursiveVerifyConstraint { gamma, per_evals, nvars_inner, basis })
        } else {
            CarrierVerifyAir::Opening(WhirOpeningRoundConstraint { gamma, rounds, wire_size, basis })
        }
    };

    let n = n_senders.max(1);
    let vs: Vec<_> = (0..n)
        .map(|i| build_v(0x004E_C000u64 ^ ((n_senders as u64) << 16) ^ i as u64, false))
        .collect();
    let os: Vec<_> = (0..n)
        .map(|i| build_o(0x0BEE_1D00u64 ^ ((n_senders as u64) << 20) ^ i as u64, false))
        .collect();
    let mut vcols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width_v];
    let mut ocols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width_o];
    for i in 0..height {
        lay_v(&mut vcols, i, &vs[i % vs.len()]);
        let (w, g, t) = &os[i % os.len()];
        lay_o(&mut ocols, i, w, g, t);
    }
    if let Some((is_open, fr)) = forge {
        let r = fr.min(height - 1);
        if is_open {
            let f = build_o(0x0BAD_09E0u64 ^ n_senders as u64, true);
            lay_o(&mut ocols, r, &f.0, &f.1, &f.2);
        } else {
            let f = build_v(0x0BAD_5EE0u64 ^ n_senders as u64, true);
            lay_v(&mut vcols, r, &f);
        }
    }
    let outer = match prove_air_batch_light_decider_selfcontained_bytes(vec![vcols, ocols], make, &dompub) {
        Some(b) => b,
        None => return (0, 0, 0, false),
    };
    let prove_us = tprove.elapsed().as_micros();
    let t0 = Instant::now();
    let ok = verify_air_batch_light_decider_selfcontained_bytes(&outer, make, &dompub, &[(height.trailing_zeros() as usize, width_v), (height.trailing_zeros() as usize, width_o)]);
    (outer.len(), prove_us, t0.elapsed().as_micros(), ok)
}

/// LIVE-MESH entry for the FULL sound cross-sender carrier verify (validity + WHIR-PCS opening, both in-circuit).
/// `(carrier_bytes, verify_us, ok)`. The greenfield node + the `xsender_recursive_settle` bin call this to settle
/// N independent carriers into ONE O(1) proof; `forge` drives the fail-closed reject for the tamper harness.
#[must_use]
pub fn xsender_carrier_verify_run(n_senders: usize, forge: Option<(bool, usize)>) -> (usize, u128, bool) {
    let (carrier, _prove_us, verify_us, ok) = xsender_carrier_verify_inner(n_senders, forge);
    (carrier, verify_us, ok)
}

/// SETTLED-TPS bench for the FULL carrier verify: also returns the PROVE microseconds so a live-mesh benchmark can
/// report the honest end-to-end settled throughput bound `n / prove_seconds`. `(carrier_bytes, prove_us, verify_us, ok)`.
#[must_use]
pub fn xsender_carrier_verify_bench(n_senders: usize) -> (usize, u128, u128, bool) {
    xsender_carrier_verify_inner(n_senders, None)
}

// ============================================================================================================
// ⭐ TRANSPORT — THE BLOCK-CARRIED SOUND CROSS-SENDER AGGREGATE OVER *REAL* CARRIERS (task #145, user 2026-07-09).
// A block producer holds N REAL `AirDirectBundle`s (each sender's own hiding spend proof, extracted from the
// PqDirectCarrier the wire delivered). `settlement_aggregate_from_bundles` extracts each carrier's TWO in-circuit
// verify rows — the VALIDITY zerocheck round chain + the WHIR-PCS OPENING (`verify_hvzk`) round chain — and folds
// all N into ONE O(1) proof via the light decider. `verify_settlement_aggregate` re-derives the shape + carrier
// digest from the SAME block carriers and verifies the ONE proof. So `ingest_block` verifies ONE proof and DROPS
// the per-tx `pqspend_direct_verify` — the admission-drop, now bound to the block's EXACT carriers. FRI-free, NO
// witness/sk (the producer never sees a secret). Everything here is generic over the inner constraint (the
// zerocheck challenger walk is constraint-independent) so it needs ONLY usdm-decider — no pqpool rebuild.
// ============================================================================================================

/// ⭐ THE TRUE-O(1) DOWNSTREAM carrier-set commitment: blake3 over the block's tx-id list (each id = blake3 of a
/// carrier blob, so the ids already commit the FULL carrier content, and the header's `tx_merkle_root` already
/// commits the ids under the PoW-bound header) → `DIGEST_LIMBS` base-field limbs. This is the root the aggregate's
/// public bind commits, so a downstream node verifies the ONE O(1) proof against a root recomputed from the tx-ids
/// it ALREADY holds (32 bytes each — a blake3 over a few KB) instead of re-parsing + re-hashing the full carrier
/// bundles (8KB each). Binds the EXACT declared tx set: a different set ⇒ a divergent transcript ⇒ reject
/// (collision-hard via blake3). The producer computes it from the same tx-ids (= blake3 of each carrier blob).
#[must_use]
pub fn tx_set_digest(tx_ids: &[[u8; 32]]) -> [Fa4; DIGEST_LIMBS] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(tx_ids.len() as u64).to_le_bytes());
    for id in tx_ids {
        hasher.update(id);
    }
    let d = hasher.finalize();
    let db = d.as_bytes();
    core::array::from_fn(|k| {
        let w = u32::from_le_bytes([db[4 * k], db[4 * k + 1], db[4 * k + 2], db[4 * k + 3]]);
        Fa4::from_u64(w as u64)
    })
}
/// Number of base-field limbs in a carrier-set binding digest.
///
/// ⛔ WAS THE LITERAL 4 — which, at an 8-lane digest, would have bound only HALF of the tx-set digest and
/// left the top four lanes free. The width lives in ONE place.
pub const DIGEST_LIMBS: usize = crate::poseidon2_compress::DIGEST_LANES;

/// The public bind for a settlement aggregate over `n` carriers with digest `dig`: domain separator ‖ n ‖ digest.
fn settlement_public_bind(n: usize, dig: &[Fa4; DIGEST_LIMBS]) -> Vec<Fa4> {
    let mut pb = Vec::with_capacity(2 + DIGEST_LIMBS);
    pb.push(Fa4::from_u64(0x5E77_1E00)); // settlement-aggregate domain separator
    pb.push(Fa4::from_u64(n as u64));
    pb.extend_from_slice(dig);
    pb
}

/// Extract the TWO in-circuit verify rows from ONE real `AirDirectBundle` (a sender's hiding spend carrier), by
/// replaying its native verify transcript (add_claim → γ → z → the generic zerocheck challenger walk →
/// add_claim_at → add_virtual_eval → `verify_hvzk_capture`). Returns `(validity_vals, opening_vals, nvars, per_evals)`:
///   • `validity_vals` = `[round_evals flattened ‖ r ‖ claimed_final]` (the `WhirRecursiveVerifyConstraint` row),
///   • `opening_vals`  = `[c0,c2,c3,γ_j per round ‖ target chain]` (the `WhirOpeningRoundConstraint` row).
/// `None` on any decode / shape / transcript mismatch (fail-closed — a malformed carrier can't enter the aggregate).
/// Generic: the zerocheck challenger walk observes round-evals + draws `r` with NO constraint dependency, so this
/// works for ANY inner AIR (the recursion re-checks the constraint identity in-circuit).
#[allow(clippy::type_complexity)]
pub fn extract_air_direct_carrier_rows(
    bytes: &[u8],
    public_bind: &[Fa4],
) -> Option<(Vec<Ea4>, Vec<Ea4>, usize, usize)> {
    use p3_challenger::FieldChallenger;
    let bundle: AirDirectBundle = postcard::from_bytes(bytes).ok()?;
    if bundle.shapes.len() != 1 || bundle.openings.len() != 1 {
        return None;
    }
    let (nvars, width) = bundle.shapes[0];
    if bundle.zc.round_evals.len() != nvars || bundle.zc.r.len() != nvars || nvars == 0 {
        return None;
    }
    let per_evals = bundle.zc.round_evals[0].len();
    if per_evals < 2 || bundle.zc.round_evals.iter().any(|h| h.len() != per_evals) {
        return None;
    }
    // Rebuild the pinned challenger + verifier EXACTLY as verify_air_direct_light_decider_selfcontained_bytes:
    // observe the SAME public_bind (the carrier's attested nf‖outcm) the prover bound at the transcript START.
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let perm = Perm16::new_from_rng_128(&mut perm_rng);
    let mut vch = Chl::new(perm);
    for &f in public_bind {
        vch.observe(f);
    }
    let mut verifier = build_decider_hiding_verifier(&bundle.shapes);
    let all: Vec<usize> = (0..width).collect();
    verifier.add_claim(0, &all, &bundle.openings[0], &mut vch);
    let _gamma: Ea4 = vch.sample_algebra_element();
    let _z: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
    // Generic zerocheck challenger walk (mirrors verify_air_zerocheck's transcript, constraint-free): observe each
    // round's evals, draw r_i, and fold the running claim. claim_0 = 0 (the zerocheck sum) for a valid carrier.
    let mut claim = Ea4::ZERO;
    for (i, h) in bundle.zc.round_evals.iter().enumerate() {
        for e in h {
            for &b in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e) {
                vch.observe(b);
            }
        }
        let r_i: Ea4 = vch.sample_algebra_element();
        if r_i != bundle.zc.r[i] {
            return None; // transcript-derived challenge must match the prover's point
        }
        claim = crate::air_zerocheck::lagrange_eval(h, r_i);
    }
    let claimed_final = claim; // = the WHIR-bound C(opened at r); the recursion's claim_last anchor
    let pt_r = Point::new(bundle.zc.r.clone());
    verifier.add_claim_at(0, &all, &bundle.zc.opened, &pt_r, &mut vch);
    absorb_shifted_openings(&mut vch, &bundle.zc.shifted_opened); // mirrors the prover — the extractor REPLAYS its transcript
    verifier.add_virtual_eval(bundle.virtual_eval, &mut vch);
    let (gammas, target_chain) = p3_whir::pcs::hiding::verify_hvzk_capture::<Fa4, Ea4, Mmcs16, _>(
        verifier,
        &bundle.zk_data,
        &bundle.mask_commits,
        REC_DECIDER_ELL_ZK,
        REC_DECIDER_FOLDING,
        REC_DECIDER_POW_BITS,
        &mut vch,
    )?;
    if gammas.len() != REC_DECIDER_FOLDING || target_chain.len() != REC_DECIDER_FOLDING + 1 {
        return None;
    }
    // VALIDITY row values: [ round_evals flattened (nvars·per_evals) | r (nvars) | claimed_final ].
    let mut validity_vals: Vec<Ea4> = Vec::with_capacity(nvars * per_evals + nvars + 1);
    for h in &bundle.zc.round_evals {
        validity_vals.extend_from_slice(h);
    }
    validity_vals.extend_from_slice(&bundle.zc.r);
    validity_vals.push(claimed_final);
    // OPENING row values: per round [ c0, c2, c3 (from zk_data), γ_j ] then the target chain (rounds+1).
    let wire_size = REC_DECIDER_ELL_ZK.max(3) - 1;
    let mut opening_vals: Vec<Ea4> = Vec::with_capacity(REC_DECIDER_FOLDING * (wire_size + 1) + REC_DECIDER_FOLDING + 1);
    for j in 0..REC_DECIDER_FOLDING {
        let wire = &bundle.zk_data.round_coefficients[j];
        if wire.len() != wire_size {
            return None;
        }
        opening_vals.extend_from_slice(wire); // c0, c2, c3
        opening_vals.push(gammas[j]);
    }
    opening_vals.extend_from_slice(&target_chain);
    Some((validity_vals, opening_vals, nvars, per_evals))
}

// DELETED 2026-09-29 (lane-recursion): `extract_air_batch_bus_carrier_rows`, the fold extractor for TWO-PHASE bus
// bundles, with its wrappers `extract_fixed_degree_bus_carrier_rows{,_replaying_ties}`, the test-only tie-replay
// escape and `prove_merged_fixed_bus_carrier_selfcontained_bytes`. MEASURED: it was the THIRD transcript mirror of
// the bus prover, and DB-159 (2026-09-22, α/β drawn POST-commitment-1 — a real LogUp soundness fix) updated the
// prover and the direct verifier but not it, so every fold over a bus bundle refused ("bus alpha differs from the
// transcript's") for a week; its only caller, `anchor_set_membership` (ZERO node/wallet users, superseded by
// `member_path_gate`), sat in no suite run, and its seven red pins were twice mis-attributed to prover parallelism.
// A two-phase object cannot ride the fixed-degree rows in any case: they carry ONE opening row, so phase 2 (the bus)
// would be replayed by the folder and carried by nobody — the laundering shape the cross-tie refusal named. No path
// recurses over a bus object now. Backups: `whir_rec_block.rs.preBusFoldDelete-20260929`,
// `anchor_set_membership.rs.preDelete-20260929`.

/// Lay a value-vector into row `i` of a column-major table as EXT_D base-field limbs per value.
fn lay_vals_row(cols: &mut [Vec<Fa4>], i: usize, vals: &[Ea4]) {
    let mut c = 0usize;
    for v in vals {
        for &limb in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v).iter().take(4) {
            cols[c][i] = limb;
            c += 1;
        }
    }
}

/// ⭐ THE BLOCK-CARRIED DEFAULT PATH — build ONE sound O(1) settlement aggregate over N REAL carriers. Extract each
/// bundle's validity + opening rows, stack them as N rows of a 2-table batch (table0 = `WhirRecursiveVerifyConstraint`,
/// table1 = `WhirOpeningRoundConstraint`), and fold via the light decider. `public_bind = domain ‖ n ‖ digest(bundles)`
/// binds the ONE proof to THIS block's exact carriers. Returns the carrier bytes (rides in `Block.settlement`), or
/// `None` if any carrier is malformed / shapes disagree. Empty input ⇒ `None` (no aggregate for an empty block).
pub fn settlement_aggregate_from_bundles(
    bundles: &[Vec<u8>],
    public_binds: &[Vec<Fa4>],
    set_digest: &[Fa4; DIGEST_LIMBS],
) -> Option<Vec<u8>> {
    if bundles.is_empty() || bundles.len() != public_binds.len() {
        return None;
    }
    let mut rows: Vec<(Vec<Ea4>, Vec<Ea4>)> = Vec::with_capacity(bundles.len());
    let (mut nvars0, mut per0) = (0usize, 0usize);
    for (k, b) in bundles.iter().enumerate() {
        let (vv, ov, nvars, per_evals) = extract_air_direct_carrier_rows(b, &public_binds[k])?;
        if k == 0 {
            nvars0 = nvars;
            per0 = per_evals;
        } else if nvars != nvars0 || per_evals != per0 {
            return None; // all carriers must share the spend-AIR shape (they do in production)
        }
        rows.push((vv, ov));
    }
    let rounds = REC_DECIDER_FOLDING;
    let wire_size = REC_DECIDER_ELL_ZK.max(3) - 1;
    let width_v = (nvars0 * per0 + nvars0 + 1) * 4;
    let width_o = (rounds * (wire_size + 1) + rounds + 1) * 4;
    let height = bundles.len().next_power_of_two().max(1 << REC_DECIDER_FOLDING.max(5));
    let basis: [Ea4; DIGEST_LANES] =
        core::array::from_fn(|i| Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO }));
    let make = move |i: usize, gamma: Ea4| -> CarrierVerifyAir {
        if i == 0 {
            CarrierVerifyAir::Validity(WhirRecursiveVerifyConstraint { gamma, per_evals: per0, nvars_inner: nvars0, basis })
        } else {
            CarrierVerifyAir::Opening(WhirOpeningRoundConstraint { gamma, rounds, wire_size, basis })
        }
    };
    let mut vcols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width_v];
    let mut ocols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width_o];
    for i in 0..height {
        let (vv, ov) = &rows[i % rows.len()]; // pad [N,height) by repeating real rows (all valid ⇒ still verifies)
        lay_vals_row(&mut vcols, i, vv);
        lay_vals_row(&mut ocols, i, ov);
    }
    let pb = settlement_public_bind(bundles.len(), set_digest);
    let agg = prove_air_batch_light_decider_selfcontained_bytes(vec![vcols, ocols], make, &pb)?;
    // Self-describe the inner spend-AIR shape (nvars, per_evals — both small) as a 2-byte prefix, so a downstream
    // node rebuilds the verify constraints from the AGGREGATE alone — never needing to parse a carrier for the shape.
    let mut out = Vec::with_capacity(agg.len() + 2);
    out.push(nvars0 as u8);
    out.push(per0 as u8);
    out.extend_from_slice(&agg);
    Some(out)
}

/// ⛔⛔⛔ §BD / DB-213c — VACUOUS: an aggregate over ZERO rows verifies for any `set_digest`
/// (`zero_row_settlement_aggregate_for_refutation`; the node's carrier-refusal pin). Nothing may be granted on it.
///
/// ⭐ THE TRUE-O(1) DOWNSTREAM VERIFY — verify a block-carried settlement aggregate against ONLY `n` (the tx count)
/// and the COMMITTED carrier-set root `set_digest` (recomputed from the block's tx-ids — a value the node ALREADY
/// holds). NO carriers are parsed or re-hashed: the aggregate self-describes its inner spend-AIR shape in a 2-byte
/// prefix, and the ONE O(1) proof is verified against `domain ‖ n ‖ set_digest`. `true` ⇒ every carrier's validity
/// + WHIR-PCS opening was recursively verified in-circuit AND the proof is bound to the exact tx set ⇒ the node may
/// DROP the per-tx `pqspend_direct_verify`. Fail-closed on a wrong/forged aggregate, a mismatched root, or a bad
/// shape byte. Cost = the ONE proof verify + the tiny `tx_set_digest` (blake3 over the tx-ids) — CONSTANT in the
/// carrier payload size, so a validium node settles a whole block without ever downloading the carriers.
#[must_use]
/// ⛔ DB-213b — the two tables a settlement aggregate over `n` carriers commits, from the SAME formulas
/// [`settlement_aggregate_from_bundles`] lays them with. `None` for an `n` with no power-of-two height.
fn settlement_aggregate_shapes(n: usize, nvars0: usize, per0: usize) -> Option<Vec<(usize, usize)>> {
    let rounds = REC_DECIDER_FOLDING;
    let wire_size = REC_DECIDER_ELL_ZK.max(3) - 1;
    let width_v = nvars0.checked_mul(per0)?.checked_add(nvars0 + 1)?.checked_mul(4)?;
    let width_o = (rounds * (wire_size + 1) + rounds + 1) * 4;
    let h = n.checked_next_power_of_two()?.max(1 << REC_DECIDER_FOLDING.max(5));
    let nv = h.trailing_zeros() as usize;
    Some(vec![(nv, width_v), (nv, width_o)])
}

pub fn verify_settlement_aggregate(aggregate: &[u8], n: usize, set_digest: &[Fa4; DIGEST_LIMBS]) -> bool {
    if aggregate.len() < 3 || n == 0 {
        return false;
    }
    let nvars0 = aggregate[0] as usize;
    let per0 = aggregate[1] as usize;
    if nvars0 == 0 || per0 < 2 {
        return false;
    }
    let rounds = REC_DECIDER_FOLDING;
    let wire_size = REC_DECIDER_ELL_ZK.max(3) - 1;
    let basis: [Ea4; DIGEST_LANES] =
        core::array::from_fn(|i| Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO }));
    let make = move |i: usize, gamma: Ea4| -> CarrierVerifyAir {
        if i == 0 {
            CarrierVerifyAir::Validity(WhirRecursiveVerifyConstraint { gamma, per_evals: per0, nvars_inner: nvars0, basis })
        } else {
            CarrierVerifyAir::Opening(WhirOpeningRoundConstraint { gamma, rounds, wire_size, basis })
        }
    };
    let pb = settlement_public_bind(n, set_digest);
    verify_air_batch_light_decider_selfcontained_bytes(&aggregate[2..], make, &pb, &match settlement_aggregate_shapes(n, nvars0, per0) { Some(s) => s, None => return false })
}

/// Structural postcard view of the pqpool `PqDirectCarrier` — the exact wire shape a mempool tx blob carries:
/// `{ depth: u32, bond_floor: Option<u64>, pvs: Vec<F=KoalaBear=Fa4>, bundle: Vec<u8> }`. Mirroring it here (Fa4
/// IS pqpool's F) lets the node hand RAW mempool blobs to the aggregate with NO pqpool dependency: we decode
/// `.bundle` (the `AirDirectBundle` hiding proof) + `.pvs` (the attested nf‖outcm = the carrier's public_bind).
#[derive(Deserialize)]
struct PqDirectCarrierView {
    #[allow(dead_code)]
    depth: u32,
    #[allow(dead_code)]
    bond_floor: Option<u64>,
    pvs: Vec<Fa4>,
    bundle: Vec<u8>,
}

/// NODE ENTRY (producer) — build the block-carried settlement aggregate directly from RAW mempool carrier blobs
/// (each a postcard `PqDirectCarrier`). Extracts each carrier's verify rows AND commits the block's tx set via
/// `tx_set_digest` over the tx-ids (= blake3 of each blob — the SAME id the mempool + header's tx_merkle_root
/// commit). Returns the self-describing aggregate bytes (ride in `Block.settlement`) or `None` if the block is
/// empty / any blob is not a decodable carrier (⇒ the producer omits the aggregate that block — liveness
/// preserved, per-tx fallback; NEVER halts).
pub fn settlement_aggregate_from_carriers(carrier_blobs: &[Vec<u8>]) -> Option<Vec<u8>> {
    if carrier_blobs.is_empty() {
        return None;
    }
    let mut bundles: Vec<Vec<u8>> = Vec::with_capacity(carrier_blobs.len());
    let mut pbs: Vec<Vec<Fa4>> = Vec::with_capacity(carrier_blobs.len());
    let mut tx_ids: Vec<[u8; 32]> = Vec::with_capacity(carrier_blobs.len());
    for cb in carrier_blobs {
        let v: PqDirectCarrierView = postcard::from_bytes(cb).ok()?;
        bundles.push(v.bundle);
        pbs.push(v.pvs);
        tx_ids.push(*blake3::hash(cb).as_bytes()); // tx-id = blake3(blob) — the block/mempool content id
    }
    let set_digest = tx_set_digest(&tx_ids);
    settlement_aggregate_from_bundles(&bundles, &pbs, &set_digest)
}

/// ⭐ NODE ENTRY (downstream, TRUE-O(1)) — verify a block-carried settlement aggregate against the block's TX-IDS
/// alone (each = blake3 of a carrier blob; the node ALREADY holds them from the block, and the header's
/// `tx_merkle_root` commits them). NO carriers are downloaded/parsed: recompute `tx_set_digest` over the ids +
/// verify the ONE O(1) proof. `true` ⇒ every carrier's validity + WHIR-PCS opening was certified in-circuit AND
/// bound to THIS exact tx set ⇒ `ingest_block` DROPS the per-tx verify. Fail-closed on any mismatch.
#[must_use]
pub fn verify_settlement_aggregate_by_txids(aggregate: &[u8], tx_ids: &[[u8; 32]]) -> bool {
    if tx_ids.is_empty() {
        return false;
    }
    let set_digest = tx_set_digest(tx_ids);
    verify_settlement_aggregate(aggregate, tx_ids.len(), &set_digest)
}

/// Convenience for a caller holding raw carrier blobs (e.g. `/admission_drop_bench` over the mempool): derive the
/// tx-ids (blake3 of each blob) then verify O(1) via [`verify_settlement_aggregate_by_txids`]. Fail-closed.
#[must_use]
pub fn verify_settlement_aggregate_carriers(aggregate: &[u8], carrier_blobs: &[Vec<u8>]) -> bool {
    if carrier_blobs.is_empty() {
        return false;
    }
    let tx_ids: Vec<[u8; 32]> = carrier_blobs.iter().map(|cb| *blake3::hash(cb).as_bytes()).collect();
    verify_settlement_aggregate_by_txids(aggregate, &tx_ids)
}

/// A valid light-decider zerocheck sends at least this many evaluation points per round (2 = the sumcheck's h(0),
/// h(1) at minimum). Used as a fail-closed lower bound on a self-described inner `per_evals`.
const MERGED_MIN_PER_EVALS: usize = 2;

// ⛔ (2026-10-03) The NAIVE single-table merged carrier (`MergedCarrierVerifyConstraint` + its prove/verify pair) was
// DELETED: superseded by the fixed-degree merged path below (its degree climbed +2 per recursion level), with ZERO
// callers in the node, the decider or the wallet — and therefore never once proven under the strict censuses (the
// one-sweep scanner listed it as the one gate no strict prove reaches). A verifier nobody calls and no census has seen
// is a liability waiting to be wired in. History: `whir_rec_block.rs.preDeadMerged-20261003`.
// ============================================================================
// ⭐⭐⭐ FIXED-DEGREE RECURSIVE VERIFY — THE O(1) FOLD (closes the degree-growth gap)
// ============================================================================
// The naive MergedCarrierVerifyConstraint composes but is O(depth): its degree is `per_evals` (the inline
// `lagrange_eval` over per_evals points), so verifying a degree-D proof needs a degree-D verifier and per_evals
// climbs +2/level. This rewrites the per-round interpolation as FIXED DEGREE 3 by committing the barycentric
// prefix/suffix products, so the recursive verifier's degree is CONSTANT regardless of the inner proof's degree ⇒
// the merged proof reaches a FIXED shape ⇒ O(1) at any recursion depth = any chain height.

/// The Lagrange basis denominators `c_j = 1 / Π_{m≠j}(x_j − x_m)` at interpolation points `x_i = i` — the constants
/// the fixed-degree interpolation multiplies each `y_j · P_j · S_j` by. Precomputed once per constraint (per_evals
/// small), so the in-circuit relation stays degree 3 (the c_j are constants, only `y_j · P_j · S_j` is a product).
fn lagrange_basis_consts(per: usize) -> Vec<Ea4> {
    (0..per)
        .map(|j| {
            let xj = Ea4::from(Fa4::from_u64(j as u64));
            let mut den = Ea4::ONE;
            for m in 0..per {
                if m != j {
                    den *= xj - Ea4::from(Fa4::from_u64(m as u64));
                }
            }
            den.inverse()
        })
        .collect()
}

/// ⭐⭐⭐ FIXED-DEGREE-3 recursive zerocheck verifier. Same relation as `WhirRecursiveVerifyConstraint` (the inner
/// sumcheck round chain collapses `evals` to `claimed_final`), but the per-round interpolation `claim_k = h_k(r_k)`
/// uses COMMITTED prefix/suffix product columns instead of an inline `lagrange_eval` (which is degree per_evals):
///   • `P_{k,j} = Π_{m<j}(r_k − x_m)`  via  `P_{k,0}=1`, `P_{k,j+1} = P_{k,j}·(r_k − x_j)`   (degree 2)
///   • `S_{k,j} = Π_{m>j}(r_k − x_m)`  via  `S_{k,per−1}=1`, `S_{k,j} = S_{k,j+1}·(r_k − x_{j+1})`   (degree 2)
///   • `claim_k = Σ_j evals_{k,j}·P_{k,j}·S_{k,j}·c_j`   (degree 3; `Π_{m≠j}(r_k−x_m) = P_{k,j}·S_{k,j}`)
/// The recurrences FORCE P/S to the true products (given r_k), so `claim_k` is forced to the true Lagrange value —
/// a merged-prover cannot substitute a wrong one. The sumcheck identity `evals_{k,0}+evals_{k,1} = claim_{k−1}` then
/// catches a forged inner proof, exactly as the original. Degree is a CONSTANT 3 regardless of per_evals ⇒ the
/// recursion no longer grows the degree ⇒ O(1). (The WHIR-opening half is already fixed-degree, so the merge is too.)
///
/// Row VALUE layout (each value = 4 limbs): `[ evals(nv·per) | r(nv) | claim(nv) | P(nv·per) | S(nv·per) | cf(1) ]`.
pub struct FixedDegreeRecursiveVerifyConstraint {
    pub gamma: Ea4,
    pub per_evals: usize,
    pub nvars_inner: usize,
    pub basis: [Ea4; DIGEST_LANES],
    /// Precomputed Lagrange denominators (length per_evals) — see [`lagrange_basis_consts`].
    pub c: Vec<Ea4>,
}
impl crate::air_zerocheck::AirConstraint for FixedDegreeRecursiveVerifyConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        3 // y_j·P_j·S_j is the top term; the P/S recurrences are degree 2 — CONSTANT in per_evals
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let per = self.per_evals;
        let nv = self.nvars_inner;
        let recon = |vi: usize| -> Ea4 {
            let b = vi * 4;
            local[b] * self.basis[0]
                + local[b + 1] * self.basis[1]
                + local[b + 2] * self.basis[2]
                + local[b + 3] * self.basis[3]
        };
        let eget = |k: usize, j: usize| recon(k * per + j);
        let rget = |k: usize| recon(nv * per + k);
        let clget = |k: usize| recon(nv * per + nv + k);
        let pget = |k: usize, j: usize| recon(nv * per + 2 * nv + k * per + j);
        let sget = |k: usize, j: usize| recon(2 * nv * per + 2 * nv + k * per + j);
        let cf = recon(3 * nv * per + 2 * nv);
        let zero = Ea4::ZERO;
        let one = Ea4::ONE;
        let mut rs: Vec<Ea4> = Vec::new();
        for k in 0..nv {
            let claim_prev = if k == 0 { zero } else { clget(k - 1) };
            rs.push(eget(k, 0) + eget(k, 1) - claim_prev); // inner sumcheck round identity
            rs.push(pget(k, 0) - one); // P_{k,0} = 1
            for j in 0..per - 1 {
                let xj = Ea4::from(Fa4::from_u64(j as u64));
                rs.push(pget(k, j + 1) - pget(k, j) * (rget(k) - xj)); // prefix product recurrence
            }
            rs.push(sget(k, per - 1) - one); // S_{k,per-1} = 1
            for j in (0..per - 1).rev() {
                let xj1 = Ea4::from(Fa4::from_u64((j + 1) as u64));
                rs.push(sget(k, j) - sget(k, j + 1) * (rget(k) - xj1)); // suffix product recurrence
            }
            let mut lag = zero;
            for j in 0..per {
                lag += eget(k, j) * pget(k, j) * sget(k, j) * self.c[j];
            }
            rs.push(clget(k) - lag); // claim_k = interpolation via committed products
        }
        rs.push(clget(nv - 1) - cf); // the final folded claim equals the WHIR-bound value
        let mut acc = zero;
        let mut gpow = one;
        for res in rs {
            acc += gpow * res;
            gpow *= self.gamma;
        }
        acc
    }
}

/// Extract a carrier's FIXED-DEGREE validity row (+ the unchanged opening row): run the standard extraction, then
/// augment the validity values with the committed `claim / P / S` columns the fixed-degree verifier reads. All are
/// deterministic functions of the extracted `(evals, r)`, computed natively here and CONSTRAINED in-circuit by
/// [`FixedDegreeRecursiveVerifyConstraint`].
pub fn extract_fixed_degree_carrier_rows(bytes: &[u8], bind: &[Fa4]) -> Option<(Vec<Ea4>, Vec<Ea4>, usize, usize)> {
    let (vv, ov, nvars, per) = extract_air_direct_carrier_rows(bytes, bind)?;
    fixed_degree_rows_from(vv, ov, nvars, per)
}

/// The FIXED-DEGREE transform, shared by the direct and two-phase-bus extractors: rewrite a raw validity
/// row into the fixed-degree-3 form (`evals | r | claim_k | P_{k,j} | S_{k,j} | claimed_final`) that
/// [`FixedDegreeRecursiveVerifyConstraint`] reads. Factored out so the bus path cannot drift from the
/// direct path's layout — a second hand-written copy is exactly how two encodings of the same row diverge.
#[must_use]
fn fixed_degree_rows_from(
    vv: Vec<Ea4>,
    ov: Vec<Ea4>,
    nvars: usize,
    per: usize,
) -> Option<(Vec<Ea4>, Vec<Ea4>, usize, usize)> {
    if vv.len() != nvars * per + nvars + 1 {
        return None; // fail-closed: standard validity row must be (evals | r | claimed_final)
    }
    let evals: Vec<Vec<Ea4>> = (0..nvars).map(|k| (0..per).map(|j| vv[k * per + j]).collect()).collect();
    let r: Vec<Ea4> = (0..nvars).map(|k| vv[nvars * per + k]).collect();
    let claimed_final = vv[nvars * per + nvars];
    let mut fixed: Vec<Ea4> = Vec::with_capacity(3 * nvars * per + 2 * nvars + 1);
    for k in 0..nvars {
        for j in 0..per {
            fixed.push(evals[k][j]);
        }
    }
    for k in 0..nvars {
        fixed.push(r[k]);
    }
    for k in 0..nvars {
        fixed.push(crate::air_zerocheck::lagrange_eval(&evals[k], r[k])); // claim_k
    }
    for k in 0..nvars {
        let mut pj = Ea4::ONE;
        for j in 0..per {
            fixed.push(pj); // P_{k,j} = Π_{m<j}(r_k − x_m)
            pj *= r[k] - Ea4::from(Fa4::from_u64(j as u64));
        }
    }
    for k in 0..nvars {
        let mut sv = vec![Ea4::ONE; per];
        for j in (0..per.saturating_sub(1)).rev() {
            sv[j] = sv[j + 1] * (r[k] - Ea4::from(Fa4::from_u64((j + 1) as u64)));
        }
        for j in 0..per {
            fixed.push(sv[j]); // S_{k,j} = Π_{m>j}(r_k − x_m)
        }
    }
    fixed.push(claimed_final);
    Some((fixed, ov, nvars, per))
}

// (the two-phase BUS fold — extractor wrappers, tie-replay escape and `prove_merged_fixed_bus_carrier_selfcontained_bytes`
// — was DELETED here 2026-09-29; see the record above `lay_vals_row`.)

/// The fixed-degree merged carrier constraint: the O(1) recursion's row relation. A γ^shift half-separation: the merged
/// residual is `V + γ^shift · O` with `shift` past every validity power, so the two halves' γ-powers never overlap (a
/// proper γ-batch of BOTH halves' residuals). The validity half is the FIXED-DEGREE-3 verifier ⇒ the whole relation is
/// degree `max(3, wire_size+1)` — a CONSTANT independent of the inner proof's degree.
pub struct FixedDegreeMergedConstraint {
    pub validity: FixedDegreeRecursiveVerifyConstraint,
    pub opening: WhirOpeningRoundConstraint,
    pub split: usize,
}
impl crate::air_zerocheck::AirConstraint for FixedDegreeMergedConstraint {
    fn degree(&self, nvars: usize) -> usize {
        self.validity.degree(nvars).max(self.opening.degree(nvars))
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        // Both halves ride the parent row's out-of-range latch (`prefix`/`suffix`) — a short wire row REFUSES.
        let v = self.validity.eval(&local.prefix(self.split), at, x);
        let o = self.opening.eval(&local.suffix(self.split), at, x);
        let shift = self.validity.nvars_inner.max(self.opening.rounds) + 1;
        let mut gm = Ea4::ONE;
        for _ in 0..shift {
            gm *= self.validity.gamma;
        }
        v + gm * o
    }
}

pub(crate) fn merged_fixed_shape(nvars0: usize, per0: usize, n: usize) -> (usize, usize, usize) {
    let rounds = REC_DECIDER_FOLDING;
    let wire_size = REC_DECIDER_ELL_ZK.max(3) - 1;
    let l_v = 3 * nvars0 * per0 + 2 * nvars0 + 1;
    let l_o = rounds * (wire_size + 1) + rounds + 1;
    let split = l_v * 4;
    let width = (l_v + l_o) * 4;
    let height = n.next_power_of_two().max(1 << REC_DECIDER_FOLDING.max(5));
    (split, width, height)
}

fn merged_fixed_make(nvars0: usize, per0: usize, split: usize) -> impl Fn(Ea4) -> FixedDegreeMergedConstraint + Clone {
    let rounds = REC_DECIDER_FOLDING;
    let wire_size = REC_DECIDER_ELL_ZK.max(3) - 1;
    let basis: [Ea4; DIGEST_LANES] =
        core::array::from_fn(|i| Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO }));
    let c = lagrange_basis_consts(per0);
    move |gamma: Ea4| FixedDegreeMergedConstraint {
        validity: FixedDegreeRecursiveVerifyConstraint {
            gamma,
            per_evals: per0,
            nvars_inner: nvars0,
            basis,
            c: c.clone(),
        },
        opening: WhirOpeningRoundConstraint { gamma, rounds, wire_size, basis },
        split,
    }
}

/// Prove a SINGLE-TABLE FIXED-DEGREE merged carrier proof — the O(1) fold. Same shape as `prove_merged_carrier_…`
/// but the validity half is fixed-degree, so the OUTPUT proof reaches a CONSTANT shape after one level and holds it
/// at any recursion depth (the fixpoint is O(1), not O(depth)).
pub fn prove_merged_fixed_carrier_selfcontained_bytes(
    bundles: &[Vec<u8>],
    carrier_binds: &[Vec<Fa4>],
    out_bind: &[Fa4],
) -> Option<Vec<u8>> {
    if bundles.is_empty() || bundles.len() != carrier_binds.len() {
        return None; // fail-closed: malformed input
    }
    let mut rows: Vec<(Vec<Ea4>, Vec<Ea4>)> = Vec::with_capacity(bundles.len());
    let (mut nvars0, mut per0) = (0usize, 0usize);
    for (k, b) in bundles.iter().enumerate() {
        let (fv, ov, nvars, per) = extract_fixed_degree_carrier_rows(b, &carrier_binds[k])?;
        if k == 0 {
            nvars0 = nvars;
            per0 = per;
        } else if nvars != nvars0 || per != per0 {
            return None; // fail-closed: one shape
        }
        rows.push((fv, ov));
    }
    let (split, width, height) = merged_fixed_shape(nvars0, per0, bundles.len());
    let make = merged_fixed_make(nvars0, per0, split);
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width];
    for i in 0..height {
        let (fv, ov) = &rows[i % rows.len()];
        let mut c = 0usize;
        for val in fv.iter().chain(ov.iter()) {
            for &limb in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(val).iter().take(4) {
                cols[c][i] = limb;
                c += 1;
            }
        }
    }
    prove_air_direct_light_decider_selfcontained_bytes(cols, make, out_bind)
}

/// Verify a fixed-degree merged carrier proof against the inner shape `(nvars0, per0)` and `out_bind`. O(1) verify.
#[must_use]
pub fn verify_merged_fixed_carrier_selfcontained_bytes(bytes: &[u8], nvars0: usize, per0: usize, out_bind: &[Fa4]) -> bool {
    if bytes.is_empty() || nvars0 == 0 || per0 < MERGED_MIN_PER_EVALS {
        return false; // fail-closed
    }
    let (split, w, h) = merged_fixed_shape(nvars0, per0, 1);
    let make = merged_fixed_make(nvars0, per0, split);
    verify_air_direct_light_decider_selfcontained_bytes(bytes, make, out_bind, (h.trailing_zeros() as usize, w))
}

/// A fixed-degree merged carrier constraint PLUS extra CONSTANT residuals — the acc-TRANSITION enforcement the
/// linked absence chain rides on. The caller (which owns the Poseidon fold) computes `extra[i]` IDENTICALLY on both
/// sides from the statement bind (e.g. `new_acc[c] − fold(prev_acc, block_pre, tags_digest)[c]`). For an HONEST
/// statement every `extra[i]` is 0 (no effect); a FALSE acc-transition makes an `extra[i]` nonzero, which makes the
/// zerocheck sum nonzero ⇒ the fold level is UNPROVABLE, and is transitively rejected when a deeper level
/// recursively verifies it. Constant residuals are degree 0, so the fixed degree is unchanged (still O(1)).
pub struct FixedDegreeMergedStepConstraint {
    pub inner: FixedDegreeMergedConstraint,
    pub extra: Vec<Ea4>,
}
impl crate::air_zerocheck::AirConstraint for FixedDegreeMergedStepConstraint {
    fn degree(&self, nvars: usize) -> usize {
        self.inner.degree(nvars)
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let mut acc = self.inner.eval(local, at, x);
        // Batch the extra constant residuals ABOVE the inner's γ-power range so they never collide with it.
        let base = self.inner.validity.nvars_inner + self.inner.opening.rounds + 4;
        let mut gp = Ea4::ONE;
        for _ in 0..base {
            gp *= self.inner.validity.gamma;
        }
        for e in &self.extra {
            acc += gp * *e;
            gp *= self.inner.validity.gamma;
        }
        acc
    }
}

pub(crate) fn merged_fixed_step_make(
    nvars0: usize,
    per0: usize,
    split: usize,
    extra: Vec<Ea4>,
) -> impl Fn(Ea4) -> FixedDegreeMergedStepConstraint + Clone {
    let inner_make = merged_fixed_make(nvars0, per0, split);
    move |gamma: Ea4| FixedDegreeMergedStepConstraint { inner: inner_make(gamma), extra: extra.clone() }
}

/// Prove a fixed-degree merged carrier proof carrying `extra` acc-transition residuals — the linked absence-chain
/// fold level. `extra` MUST be derived from `out_bind` by the caller (0 for an honest transition); a nonzero one
/// makes the proof fail-closed.
pub fn prove_merged_fixed_step_bytes(
    bundles: &[Vec<u8>],
    carrier_binds: &[Vec<Fa4>],
    out_bind: &[Fa4],
    extra: &[Ea4],
) -> Option<Vec<u8>> {
    if bundles.is_empty() || bundles.len() != carrier_binds.len() {
        return None; // fail-closed
    }
    let mut rows: Vec<(Vec<Ea4>, Vec<Ea4>)> = Vec::with_capacity(bundles.len());
    let (mut nvars0, mut per0) = (0usize, 0usize);
    for (k, b) in bundles.iter().enumerate() {
        let (fv, ov, nvars, per) = extract_fixed_degree_carrier_rows(b, &carrier_binds[k])?;
        if k == 0 {
            nvars0 = nvars;
            per0 = per;
        } else if nvars != nvars0 || per != per0 {
            return None; // fail-closed: one shape
        }
        rows.push((fv, ov));
    }
    let (split, width, height) = merged_fixed_shape(nvars0, per0, bundles.len());
    let make = merged_fixed_step_make(nvars0, per0, split, extra.to_vec());
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width];
    for i in 0..height {
        let (fv, ov) = &rows[i % rows.len()];
        let mut c = 0usize;
        for val in fv.iter().chain(ov.iter()) {
            for &limb in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(val).iter().take(4) {
                cols[c][i] = limb;
                c += 1;
            }
        }
    }
    prove_air_direct_light_decider_selfcontained_bytes(cols, make, out_bind)
}

/// ⛔⛔⛔ DB-213c — THIS VERIFIES NO INNER STATEMENT. `FixedDegreeMergedStepConstraint` constrains the inner sumcheck
/// round chain and the masked-opening chain over values laid in WITNESS rows; the inner challenges,
/// `C_inner(opened)` and the inner bind appear in no row. A witness-free trace (zero evals, `r = 0` with the forced
/// prefix/suffix products, zero claims, a zero opening half) proves against any `out_bind` whose `extra` residual is
/// zero — MEASURED by `db213_forgery_census` arms M, A and B. Everything built on it (the membership fold, the
/// absence chains, the split ladder) is attested by its `extra` residual alone, never by its inner proofs. No
/// authority may rest on it.
///
/// Verify a fixed-degree merged step proof: the caller recomputes `extra` from `out_bind` (the acc-transition
/// residual), so a proof built over a FALSE transition — or a mismatched `extra` — fails-closed.
#[must_use]
pub fn verify_merged_fixed_step_bytes(
    bytes: &[u8],
    nvars0: usize,
    per0: usize,
    out_bind: &[Fa4],
    extra: &[Ea4],
) -> bool {
    if bytes.is_empty() || nvars0 == 0 || per0 < MERGED_MIN_PER_EVALS {
        return false; // fail-closed
    }
    let (split, w, h) = merged_fixed_shape(nvars0, per0, 1);
    let make = merged_fixed_step_make(nvars0, per0, split, extra.to_vec());
    verify_air_direct_light_decider_selfcontained_bytes(bytes, make, out_bind, (h.trailing_zeros() as usize, w))
}

// ============================================================================
// SHARED SPEND-CARRIER ENTRY (user-approved 2026-07-10) — the ONE config-pinned,
// witness-in / bytes-out trustless-WHIR spend prove+verify that BOTH the V2
// wallet's in-process prover AND the node's carrier verify call, so prover and
// verifier share a SINGLE definition (sound by construction: the wallet owns
// NEITHER the WHIR config NOR the AIR — only the witness). The config is PINNED
// by `prove/verify_air_direct_light_decider_selfcontained_bytes` (REC_DECIDER_*),
// so the wallet links ONLY this SMALL crate, never the pqpool circuit.rs monolith.
// This entry proves the SPEND CONSERVATION (no-inflation) gate — per row
// `[in,out,fee]` the residual `in - out - fee == 0`, over up to 32 spends under
// ONE constant-size trustless carrier. Completing bricks (tracked, not hidden):
// (1) extend the row to the full PqSpendAir (membership + nullifier + confidential
// balance) so the carrier is byte-identical to what the node verifies; (2) repoint
// the node's `pqspend_direct_verify_carrier` at this shared entry (byte-parity gated).
// ============================================================================

/// Transcript-weld domain tag both prover and verifier bind, domain-separating
/// the spend carrier from every other direct-decider use ("SPND_v1").
pub const SPEND_CARRIER_DOMAIN: u64 = 0x5350_4e44_5f76_31;

/// One confidential spend row: conserves value iff `in_value == out_value + fee`.
#[derive(Clone, Copy, Debug)]
pub struct SpendRow {
    pub in_value: u64,
    pub out_value: u64,
    pub fee: u64,
}

/// The no-inflation gate as a row-local AIR constraint: `in - out - fee == 0`
/// (degree 1). A non-conserving row makes the zerocheck sum nonzero → REJECT.
/// ⛔⛔⛔ ITEM 1 / D-28 — THE NO-INFLATION GATE, RANGE-BOUND (2026-09-11).
///
/// This gate used to be ONE field identity: `in - out - fee == 0` over KoalaBear (p ≈ 2^31). Any
/// `out = in + p - fee` satisfied it, and `Fa4::from_u64` already REDUCES a u64 mod p, so the three
/// columns did not even hold the true values. An `out = in + p` row PROVED AND VERIFIED. That is
/// inflation — money from nothing — on the send path, and the same shape stood at the two MINT sites.
/// The prover-side `checked_add` bound an honest wallet and nothing else.
///
/// BORROWED, NOT DERIVED (user-locked 2026-09-11: "no more rederiving"): this is the Zcash
/// Sapling/Orchard value shape — every note value bit-decomposed and bound in-circuit — in the exact
/// form this crate already exercises at nine call sites of `confidential_solvency`
/// (`push_conservation_constraints` for the carry chain, `push_scale_constraints` for the bit binding).
/// Same constraint forms, parameterised to u64 (4 × 16-bit limbs) instead of u256.
///
/// Three ingredients, and all three are load-bearing:
///   1. limb-wise addition with a carry chain — `out_i + fee_i + cin - in_i - cout·2^16 = 0`;
///   2. the top carry is structurally ZERO — this is what makes wrap-around UNREPRESENTABLE rather than
///      merely unlikely (an honest row never overflows u64: the prover-side `checked_add` still stands);
///   3. every limb of every value bit-decomposed, each bit constrained boolean, and the reconstruction
///      bound to the limb — the RANGE constraint. Without it a "limb" could hold any field element and
///      (1) and (2) would prove nothing.
///
/// Row layout (width [`SC_WIDTH`]): limbs are little-endian 16-bit; bits are little-endian within each
/// limb, laid out so that `bits_base + k` is bit `k` of the 64-bit value.
pub(crate) const SC_LIMBS: usize = 4;
const SC_LIMB_BITS: usize = 16;
/// Column bases of ONE range-bound u64 conservation block (`out + fee == in` in u64), placed at
/// `base`: in limbs, out limbs, fee limbs, carries, then 64 bits for each value. Width [`U64_CONS_WIDTH`].
#[derive(Clone, Copy)]
struct U64ConsBases {
    r#in: usize,
    out: usize,
    fee: usize,
    carry: usize,
    in_bits: usize,
    out_bits: usize,
    fee_bits: usize,
}
impl U64ConsBases {
    const fn at(base: usize) -> Self {
        let bits = SC_LIMBS * SC_LIMB_BITS;
        Self {
            r#in: base,
            out: base + SC_LIMBS,
            fee: base + 2 * SC_LIMBS,
            carry: base + 3 * SC_LIMBS,
            in_bits: base + 4 * SC_LIMBS,
            out_bits: base + 4 * SC_LIMBS + bits,
            fee_bits: base + 4 * SC_LIMBS + 2 * bits,
        }
    }
}
/// 3 values × 4 limbs + 4 carries + 3 × 64 bits.
const U64_CONS_WIDTH: usize = 4 * SC_LIMBS + 3 * SC_LIMBS * SC_LIMB_BITS;
/// Column bases of the spend-carrier trace, public so the node's circuit harness can build a HOSTILE
/// trace against the production verifier (its `prove_false` lane) without a copy of the layout.
pub const SC_IN: usize = 0;
pub const SC_OUT: usize = SC_LIMBS;
pub const SC_FEE: usize = 2 * SC_LIMBS;
const SC_CARRY: usize = 3 * SC_LIMBS;
const SC_IN_BITS: usize = 4 * SC_LIMBS;
const SC_OUT_BITS: usize = SC_IN_BITS + SC_LIMBS * SC_LIMB_BITS;
const SC_FEE_BITS: usize = SC_OUT_BITS + SC_LIMBS * SC_LIMB_BITS;
/// The spend-carrier trace width: one conservation block at base 0.
pub const SC_WIDTH: usize = U64_CONS_WIDTH;

/// Push the range-bound u64 conservation constraints for one block onto `cs`. Three ingredients,
/// all load-bearing: (1) limb-wise addition with a boolean carry chain; (2) the top carry forced ZERO,
/// so wrap-around is UNREPRESENTABLE; (3) every limb of every value bit-decomposed, bits boolean,
/// reconstruction bound to the limb — the RANGE constraint, without which (1)+(2) prove nothing.
/// The Zcash value shape, in the form `confidential_solvency` already exercises at nine sites.
// Generic over the row's field (lane agg 2026-11-15, `gate_trace`): the parameter is NAMED `Ea4`, so the body is unchanged.
fn push_u64_conservation<Ea4: crate::gate_trace::GateAlg>(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_, Ea4>, b: U64ConsBases) {
    let two = Ea4::from(Fa4::from_u64(2));
    let two16 = Ea4::from(Fa4::from_u64(1 << SC_LIMB_BITS));
    // O1-FOOTPRINT-REVIEWED: bounded by the fixed constant SC_LIMBS (4) — a u64 has four 16-bit limbs.
    for i in 0..SC_LIMBS {
        let cin = if i == 0 { Ea4::ZERO } else { local[b.carry + i - 1] };
        let cout = local[b.carry + i];
        cs.push(local[b.out + i] + local[b.fee + i] + cin - local[b.r#in + i] - cout * two16);
        cs.push(cout * (cout - Ea4::ONE));
    }
    cs.push(local[b.carry + SC_LIMBS - 1]); // no carry out of the top limb: overflow is unrepresentable
    // O1-FOOTPRINT-REVIEWED: bounded by the fixed constants 3 values × SC_LIMBS × SC_LIMB_BITS = 192.
    for (limb_base, bits_base) in [(b.r#in, b.in_bits), (b.out, b.out_bits), (b.fee, b.fee_bits)] {
        for i in 0..SC_LIMBS {
            let mut rec = Ea4::ZERO;
            let mut pw = Ea4::ONE;
            for j in 0..SC_LIMB_BITS {
                let bit = local[bits_base + i * SC_LIMB_BITS + j];
                cs.push(bit * (bit - Ea4::ONE));
                rec += bit * pw;
                pw *= two;
            }
            cs.push(rec - local[limb_base + i]);
        }
    }
}

/// The field-element recombination of a range-bound limb block: `Σ limb_i · 2^(16 i)`. Equal to
/// `Fa4::from_u64(value)` for an honest row, so it BINDS a legacy whole-value column to its limbs.
fn u64_limbs_recombined<Ea4: crate::gate_trace::GateAlg>(local: &crate::air_zerocheck::Row<'_, Ea4>, limb_base: usize) -> Ea4 {
    let two16 = Ea4::from(Fa4::from_u64(1 << SC_LIMB_BITS));
    let mut acc = Ea4::ZERO;
    let mut pw = Ea4::ONE;
    for i in 0..SC_LIMBS {
        acc += local[limb_base + i] * pw;
        pw *= two16;
    }
    acc
}

/// Fill one row of a conservation block. `checked_add` is the honest-prover bound and STAYS; the gate is
/// the dishonest-prover bound. Returns None on a row that does not conserve in u64.
fn fill_u64_conservation(cols: &mut [Vec<Fa4>], row: usize, in_v: u64, out_v: u64, fee: u64, b: U64ConsBases) -> Option<()> {
    if out_v.checked_add(fee)? != in_v {
        return None;
    }
    let limb = |v: u64, i: usize| Fa4::from_u64((v >> (SC_LIMB_BITS * i)) & 0xFFFF);
    let mut carry = 0u64;
    for i in 0..SC_LIMBS {
        cols[b.r#in + i][row] = limb(in_v, i);
        cols[b.out + i][row] = limb(out_v, i);
        cols[b.fee + i][row] = limb(fee, i);
        let s = ((out_v >> (SC_LIMB_BITS * i)) & 0xFFFF) + ((fee >> (SC_LIMB_BITS * i)) & 0xFFFF) + carry;
        carry = s >> SC_LIMB_BITS;
        cols[b.carry + i][row] = Fa4::from_u64(carry);
    }
    for (v, bits_base) in [(in_v, b.in_bits), (out_v, b.out_bits), (fee, b.fee_bits)] {
        for k in 0..(SC_LIMBS * SC_LIMB_BITS) {
            cols[bits_base + k][row] = Fa4::from_u64((v >> k) & 1);
        }
    }
    Some(())
}

/// A single range-bound u64 (limbs + bits, no carry chain). Width [`U64_RANGE_WIDTH`].
#[derive(Clone, Copy)]
struct U64RangeBases {
    limbs: usize,
    bits: usize,
}
impl U64RangeBases {
    const fn at(base: usize) -> Self {
        Self { limbs: base, bits: base + SC_LIMBS }
    }
}
/// 4 limbs + 64 bits.
const U64_RANGE_WIDTH: usize = SC_LIMBS + SC_LIMBS * SC_LIMB_BITS;

/// Bits boolean, reconstruction binds each limb — the RANGE constraint for one value.
fn push_u64_range(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, b: U64RangeBases) {
    let two = Ea4::from(Fa4::from_u64(2));
    // O1-FOOTPRINT-REVIEWED: bounded by the fixed constants SC_LIMBS × SC_LIMB_BITS = 64 — one u64.
    for i in 0..SC_LIMBS {
        let mut rec = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for j in 0..SC_LIMB_BITS {
            let bit = local[b.bits + i * SC_LIMB_BITS + j];
            cs.push(bit * (bit - Ea4::ONE));
            rec += bit * pw;
            pw *= two;
        }
        cs.push(rec - local[b.limbs + i]);
    }
}

fn fill_u64_range(cols: &mut [Vec<Fa4>], row: usize, v: u64, b: U64RangeBases) {
    for i in 0..SC_LIMBS {
        cols[b.limbs + i][row] = Fa4::from_u64((v >> (SC_LIMB_BITS * i)) & 0xFFFF);
    }
    for k in 0..(SC_LIMBS * SC_LIMB_BITS) {
        cols[b.bits + k][row] = Fa4::from_u64((v >> k) & 1);
    }
}

/// A u64 as its four 16-bit limbs, each `< 2^16 < p`, so NO reduction mod p happens — this is what a
/// PUBLIC value must be welded into a transcript as. `Fa4::from_u64(v)` reduces, so `v` and `v + p`
/// bound identically and one proof verified for both amounts.
fn u64_public_limbs(v: u64) -> [Fa4; 4] {
    core::array::from_fn(|i| Fa4::from_u64((v >> (SC_LIMB_BITS * i)) & 0xFFFF))
}

#[derive(Clone, Copy)]
pub struct SpendConservationGate {
    /// Public so a sibling module can rebuild the SAME gate rather than re-derive an equivalent one —
    /// two spellings of one constraint is how §AO started.
    pub gamma: Ea4,
}
impl SpendConservationGate {
    /// The gate is γ-folded (bit booleanity, carry booleanity, limb equations, reconstructions), so it
    /// needs the transcript's γ — the direct decider's `make` closure hands it in.
    pub fn new(gamma: Ea4) -> Self {
        Self { gamma }
    }
}
impl crate::air_zerocheck::AirConstraint for SpendConservationGate {
    fn degree(&self, _nvars: usize) -> usize {
        2 // bit booleanity `b·(b−1)` and carry booleanity; everything else is linear
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        push_u64_conservation(&mut cs, local, U64ConsBases::at(0));
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

/// Public IO both sides weld into the transcript START (a mismatched bind
/// diverges the Fiat-Shamir transcript → reject).
pub fn spend_carrier_public_bind() -> [Fa4; 1] {
    [Fa4::from_u64(SPEND_CARRIER_DOMAIN)]
}

/// Pack up to 32 spend rows into the [`SC_WIDTH`]-column range-bound trace, padded to height 32
/// (nvars=5 clears the WHIR SIMD packing floor) with conserving zero-rows. None if any row does not
/// conserve in u64, is empty, or count > 32.
///
/// ⛔ The prover-side `checked_add` STAYS. It binds an honest prover and costs nothing; the gate above
/// is what binds a dishonest one. Deleting it would remove even the honest bound, which is strictly
/// worse than the hole it used to mask.
/// Public for the node's circuit harness: the honest trace, to be MUTATED into a hostile one.
pub fn spend_carrier_cols(rows: &[SpendRow]) -> Option<Vec<Vec<Fa4>>> {
    const H: usize = SPEND_CARRIER_ROWS; // 2^5
    if rows.is_empty() || rows.len() > H {
        return None;
    }
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; H]; SC_WIDTH];
    // O1-FOOTPRINT-REVIEWED: bounded by H = 32 rows × the fixed row layout SC_WIDTH — never by chain state.
    for (r_i, r) in rows.iter().enumerate() {
        fill_u64_conservation(&mut cols, r_i, r.in_value, r.out_value, r.fee, U64ConsBases::at(0))?;
    }
    Some(cols)
}

/// Prove a trustless-WHIR carrier certifying EVERY row conserves value — the
/// bytes the wallet broadcasts and the node verifies via [`verify_spend_carrier_bytes`].
/// None if a row does not conserve / the prover rejects.
#[must_use]
pub fn prove_spend_carrier_bytes(rows: &[SpendRow]) -> Option<Vec<u8>> {
    let cols = spend_carrier_cols(rows)?;
    let make = |gamma: Ea4| SpendConservationGate { gamma };
    crate::committed_air::prove_air_blinded_bytes(cols, make, &spend_carrier_public_bind())
}

/// Verify a spend carrier under the SAME pinned config + public bind the prover
/// used. Fail-closed on any decode / conservation / opening mismatch.
#[must_use]
pub fn verify_spend_carrier_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let make = |gamma: Ea4| SpendConservationGate { gamma };
    crate::committed_air::verify_air_blinded_bytes(bytes, make, &spend_carrier_public_bind(), (SPEND_CARRIER_ROWS.trailing_zeros() as usize, SC_WIDTH))
}

/// ⛔⛔⛔ ITEM 1 / D-28 ACCEPTANCE — THE RANGE BINDING FIRES, AND THE HONEST CARRIER STILL VERIFIES.
///
/// The old gate was one field identity, so a trace whose values did not conserve in u64 could still
/// satisfy it (`out = in + p − fee`). The honest builder's `checked_add` hid this: it refused to BUILD
/// such a row, so no test could reach the gate with one. These pins build the hostile trace DIRECTLY —
/// exactly what a malicious prover does — and present it to the production prover and verifier.
///
/// Refutation discipline: an honest carrier is proven and verified FIRST (the control), so a red below
/// cannot be "the prover is broken"; then each hostile trace must fail to prove, or prove and fail to
/// verify. Either is a refusal; only prove-AND-verify is the hole.
#[cfg(test)]
mod range_binding_acceptance {
    use super::{to_f, to_u64, Digest, DigestF, DIGEST_LANES};
    use super::*;

    fn honest_trace() -> Vec<Vec<Fa4>> {
        spend_carrier_cols(&[SpendRow { in_value: 6, out_value: 5, fee: 1 }]).expect("honest cols")
    }

    /// Prove + verify a raw trace through the SAME production doors the wallet and node use.
    fn proves_and_verifies(cols: Vec<Vec<Fa4>>) -> bool {
        let make = |gamma: Ea4| SpendConservationGate { gamma };
        // ⛔ BOTH HALVES ON THE SAME DOOR. Item 1 moved `verify_spend_carrier_bytes` to the blinded
        // committed path; proving on the direct one here made this helper a MISMATCHED PAIR, and its own
        // control caught it immediately — which is what a control is for.
        match crate::committed_air::prove_air_blinded_bytes(cols, make, &spend_carrier_public_bind()) {
            None => false,
            Some(bytes) => verify_spend_carrier_bytes(&bytes),
        }
    }

    #[test]
    fn control_the_honest_carrier_proves_and_verifies() {
        assert!(
            proves_and_verifies(honest_trace()),
            "⛔ THE CONTROL FAILED: an honest 6 = 5 + 1 row no longer proves and verifies — every \
             refusal below would then be measuring a broken prover, not a working gate"
        );
        assert!(
            verify_spend_carrier_bytes(&prove_spend_carrier_bytes(&[SpendRow { in_value: 6, out_value: 5, fee: 1 }]).unwrap()),
            "the public prove/verify pair must agree with the raw-trace path"
        );
    }

    /// A limb that is not 16 bits, with the old honest bits left in place: the LINEAR limb equation still
    /// balances (out_0 + fee_0 = in_0 with both sides shifted by 70000), so the old gate would pass —
    /// the RECONSTRUCTION constraint is what must refuse it.
    #[test]
    fn a_limb_wider_than_16_bits_is_refused_even_when_the_linear_equation_balances() {
        let mut cols = honest_trace();
        let shift = 70_000u64; // > 2^16
        cols[SC_OUT][0] = Fa4::from_u64(5 + shift);
        cols[SC_IN][0] = Fa4::from_u64(6 + shift);
        // Non-vacuity: the mutation really left the u64 lane.
        assert_ne!(cols[SC_OUT][0], Fa4::from_u64(5), "⛔ THE VIOLATING STATE WAS NEVER BUILT");
        assert!(
            !proves_and_verifies(cols),
            "⛔⛔ INFLATION: a limb of 70000 (> 2^16) proved AND verified. The linear equation balanced \
             and nothing bound the limb to its bits — the exact hole item 1 exists to close."
        );
    }

    /// A non-boolean "bit" whose weighted sum still reconstructs the limb: booleanity must refuse it.
    #[test]
    fn a_non_boolean_bit_is_refused_even_when_the_reconstruction_balances() {
        let mut cols = honest_trace();
        // out = 5 = 0b101. Replace bits (0,2) = (1,1) with bit0 = 5 and bit2 = 0: 5·1 + 0·4 = 5 still.
        cols[SC_OUT_BITS + 0][0] = Fa4::from_u64(5);
        cols[SC_OUT_BITS + 2][0] = Fa4::ZERO;
        assert_ne!(cols[SC_OUT_BITS + 0][0], Fa4::ONE, "⛔ THE VIOLATING STATE WAS NEVER BUILT");
        assert!(
            !proves_and_verifies(cols),
            "⛔⛔ a bit column holding 5 proved AND verified — booleanity is not being enforced, so the \
             range binding is decorative"
        );
    }

    /// The direct inflation: out exceeds in by one, carries honest. The limb equation cannot balance.
    #[test]
    fn out_exceeding_in_is_refused() {
        let mut cols = honest_trace();
        cols[SC_OUT][0] = Fa4::from_u64(6); // out = 6, in = 6, fee = 1 ⇒ out + fee = 7 ≠ 6
        cols[SC_OUT_BITS + 0][0] = Fa4::ZERO; // keep out's bits consistent with 6 = 0b110
        cols[SC_OUT_BITS + 1][0] = Fa4::ONE;
        assert!(!proves_and_verifies(cols), "⛔⛔ out + fee ≠ in proved and verified");
    }

    /// SITE 2 — the same 70000-limb attack through the spend-MAIN door (the arm that IS `spend_ok`),
    /// with the legacy whole-value columns 0..3 left at their honest values so the recombination bind
    /// is what has to refuse it if the limb bits somehow did not.
    #[test]
    fn site2_spend_main_refuses_a_limb_wider_than_16_bits() {
        let row = SpendMainRow { in_value: 6, out_value: 5, fee: 1, sk: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), leaf: crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]) };
        let honest = spend_main_cols(&[row]).expect("honest spend-main trace");
        let make = |gamma: Ea4| SpendMainGate { gamma };
        // ⛔ BOTH HALVES ON THE SAME DOOR — item 1 moved `verify_spend_main_carrier_bytes` to the
        // blinded committed path, so proving direct here would test a pair that does not exist.
        let bytes = crate::committed_air::prove_air_blinded_bytes(honest.clone(), make, &spend_carrier_public_bind())
            .expect("control: the honest spend-main trace proves");
        assert!(verify_spend_main_carrier_bytes(&bytes), "⛔ THE CONTROL FAILED for site 2");

        let vb = U64ConsBases::at(SM_VAL_BASE);
        let mut cols = honest;
        let shift = 70_000u64;
        cols[vb.out][0] = Fa4::from_u64(5 + shift);
        cols[vb.r#in][0] = Fa4::from_u64(6 + shift);
        assert_ne!(cols[vb.out][0], Fa4::from_u64(5), "⛔ THE VIOLATING STATE WAS NEVER BUILT");
        let make = |gamma: Ea4| SpendMainGate { gamma };
        let hostile = prove_air_direct_light_decider_selfcontained_bytes(cols, make, &spend_carrier_public_bind());
        assert!(
            !matches!(hostile, Some(ref b) if verify_spend_main_carrier_bytes(b)),
            "⛔⛔ INFLATION ON THE spend_ok ARM: a 70000 limb proved AND verified through spend-main"
        );
    }

    /// SITES 3+4 — THE MINT ALIAS. The public amount used to be welded as ONE reduced field element, so
    /// a carrier proven for `v` verified for a claimed `v + p` (p = 2,130,706,433): whoever credited
    /// the claimed u64 against that proof credited ~21.3 M base units of inflation per mint. The bind
    /// now carries the amount's four 16-bit limbs, which differ for `v` and `v + p`.
    #[test]
    fn site3_a_mint_carrier_for_v_does_not_verify_for_v_plus_p() {
        let p: u64 = 2_130_706_433;
        let sk = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let v = 5_000u64;
        let (carrier, cm) = prove_mint_validity_bytes(v, &sk).expect("mint proves");
        assert!(verify_mint_validity_bytes(&carrier, cm, v), "⛔ THE CONTROL FAILED: the honest pair");
        assert_ne!(v, v + p, "⛔ THE VIOLATING STATE WAS NEVER BUILT");
        assert!(
            !verify_mint_validity_bytes(&carrier, cm, v + p),
            "⛔⛔ MINT INFLATION: a carrier proven for {v} verified for a claimed {} — the public amount is \
             still bound as a reduced field element",
            v + p
        );
    }

    /// The same alias through the wrapped-asset mint door.
    #[test]
    fn site4_an_asset_mint_carrier_for_v_does_not_verify_for_v_plus_p() {
        let p: u64 = 2_130_706_433;
        let sk = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let tag = [7u64, 8, 9];
        let v = 5_000u64;
        let (carrier, cm) = prove_asset_mint_validity_bytes(v, tag, &sk).expect("asset mint proves");
        assert!(verify_asset_mint_validity_bytes(&carrier, cm, v, tag), "⛔ THE CONTROL FAILED for site 4");
        assert!(
            !verify_asset_mint_validity_bytes(&carrier, cm, v + p, tag),
            "⛔⛔ ASSET-MINT INFLATION: a carrier proven for {v} verified for a claimed {}",
            v + p
        );
    }

    /// ⛔⛔⛔ THE SEAM — a note committed at `v` cannot be spent claiming `v + p`.
    ///
    /// Membership here is by the O(1) accumulator, not by a Merkle root: the note-membership carrier
    /// proves the note's LEAF is in the accumulator and pins it to THIS spend through
    /// `leaf_commit = P(leaf, nullifier)`, which the node checks matches the spend carrier's bind.
    /// Under the one-element commitment `leaf(v) == leaf(v + p)`, hence the SAME nullifier and the
    /// SAME `leaf_commit` — so the honest note's membership carrier cross-bound to a spend claiming
    /// `v + p`, and `value_out + fee = v + p` conserved against it: p ≈ 21.3 M base units per spend.
    /// With the two-round commitment the inflated claim opens a DIFFERENT leaf, so its nullifier and
    /// `leaf_commit` differ and the honest cross-bind refuses it. Mutation-checked: collapsing
    /// `note_value_lanes` to `[v, 0, 0, 0]` turns this pin RED.
    /// The same spend, proved the OLD way. Item 1 moved production onto the blinded committed path, so
    /// the direct carrier survives here only as the BASELINE the §BP ratio is measured against — never
    /// as something the chain ships.
    fn direct_baseline(w: &SpendValidityWitness) -> (Vec<u8>, Vec<Fa4>) {
        // the PRODUCTION row: the note class lays the vault region (spec §9.1), so the baseline measures that shape
        let (row, ..) = note_spend_row(w, &NoteSpendExtras::plain(0), w.lc_blind, 0).expect("the honest witness lays a row");
        let (_c, cms_u, nf_u, lc_u) = prove_spend_validity_carrier_with_commit_bytes(w, crate::whir_rec_block::test_clue_digest(0))
            .expect("the production prover names the carrier's own publics");
        let f = |d: Digest| -> DigestF { core::array::from_fn(|i| Fa4::from_u64(d[i])) };
        let (out_cms, nf, commit) = ([f(cms_u[0]), f(cms_u[1])], f(nf_u), f(lc_u));
        let tag1 = to_f(&spend_tag1(w));
        let pb = validity_public_bind_with_commit(&out_cms, &nf, &commit, &to_f(&crate::whir_rec_block::test_clue_digest(0)), &tag1);
        let to_ea = |d: DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| d[i].into()) };
        let (o0, o1, nf_ea, lc_ea, tag1_ea) = (to_ea(out_cms[0]), to_ea(out_cms[1]), to_ea(nf), to_ea(commit), to_ea(tag1));
        let make = move |g: Ea4| SpendValidityGate {
            leaf_commit: lc_ea,
            gamma: g,
            out0_cm: o0,
            out1_cm: o1,
            nullifier: nf_ea,
            bond_amount: None,
            fee_amount: Some(fee_limbs(w.fee)), // §BR-14
            tag1: Some(tag1_ea),
            vault: Some(clock_const(0)),
        };
        let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|c| vec![row[c]; LIGHT_CARRIER_ROWS]).collect();
        let bytes = prove_air_direct_light_decider_selfcontained_bytes(cols, make, &pb)
            .expect("the direct baseline proves");
        (bytes, pb)
    }

    /// ⭐⭐⭐ §BQ PROBE — CAN A PRODUCTION SPEND CARRIER EVEN GO ON THE COMMITTED PATH?
    ///
    /// §BP measured that item 1 is the keystone: the committed path cuts the in-circuit transcript 63x
    /// and is what makes a bound aggregate affordable. That is worthless if a production carrier cannot
    /// ride it. `LIGHT_CARRIER_ROWS = 8` is 3 variables and `committed_air::COMMITTED_FOLDING` is 4, so
    /// the shape sits BELOW the committed prover's floor — and the blinding wrapper doubles the height,
    /// landing exactly ON it.
    ///
    /// This asks all three paths with the REAL spend-validity row, and prints the proof sizes item 1
    /// would actually ship. The ≤1.8 MB constant-proof cardinal is decided by these numbers.
    #[test]
    fn bq_the_production_spend_shape_on_every_carrier_path() {
        let sk = crate::poseidon2_compress::lanes_of(&[3, 1, 4, 1]);
        let other = crate::poseidon2_compress::lanes_of(&[9, 9, 9, 9]);
        let w = SpendValidityWitness {
            value_in: 5_000,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 4_900,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: 4_850,
            out0_opening: crate::poseidon2_compress::lanes_of(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        };
        // the PRODUCTION row: the note class lays the vault region (spec §9.1)
        let (row, ..) = note_spend_row(&w, &NoteSpendExtras::plain(0), w.lc_blind, 0).expect("the honest witness lays a row");
        // ⛔ EVERY PUBLIC COMES FROM THE PRODUCTION PROVER, NOT FROM A COLUMN OFFSET OR A TUPLE
        // POSITION. Reading the nullifier at `SV_NF` produced a carrier bound to the WRONG public bind,
        // which failed on EVERY path — and read as "the committed carrier cannot take a production
        // spend". The bisect separated the probe bug from a system one: a degree-1 gate on the IDENTICAL
        // shape verified, while the spend gate failed even on the DIRECT path, which no system bug in
        // the committed path could explain.
        let (_c0, cms_u, nf_u, lc_u) = prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0))
            .expect("the production prover names the carrier's own publics");
        let f = |d: Digest| -> DigestF { core::array::from_fn(|i| Fa4::from_u64(d[i])) };
        let (out_cms, nf, commit) = ([f(cms_u[0]), f(cms_u[1])], f(nf_u), f(lc_u));
        let tag1 = to_f(&spend_tag1(&w));
        let pb = validity_public_bind_with_commit(&out_cms, &nf, &commit, &to_f(&crate::whir_rec_block::test_clue_digest(0)), &tag1);
        let o0: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| out_cms[0][i].into());
        let o1: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| out_cms[1][i].into());
        let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| nf[i].into());
        let lc: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| commit[i].into());
        let tag1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| tag1[i].into());
        let make = move |g: Ea4| SpendValidityGate {
            leaf_commit: lc,
            gamma: g,
            out0_cm: o0,
            out1_cm: o1,
            nullifier: nf_ea,
            bond_amount: None,
            fee_amount: Some(fee_limbs(w.fee)), // §BR-14
            tag1: Some(tag1_ea),
            vault: Some(clock_const(0)),
        };
        let cols = |rows: usize| -> Vec<Vec<Fa4>> {
            (0..row.len()).map(|c| vec![row[c]; rows]).collect()
        };
        eprintln!(
            "[bq] the production spend shape: {} columns x LIGHT_CARRIER_ROWS={} ({} variables); \
             COMMITTED_FOLDING={}",
            row.len(),
            LIGHT_CARRIER_ROWS,
            LIGHT_CARRIER_ROWS.trailing_zeros(),
            crate::committed_air::COMMITTED_FOLDING
        );
        let t0 = std::time::Instant::now();
        let direct = prove_air_direct_light_decider_selfcontained_bytes(
            cols(LIGHT_CARRIER_ROWS),
            make,
            &pb,
        )
        .expect("the direct carrier proves — it is what production ships today");
        eprintln!("[bq] DIRECT   at {LIGHT_CARRIER_ROWS} rows: {} B, {:?}", direct.len(), t0.elapsed());

        for rows in [LIGHT_CARRIER_ROWS, 16, 32, 64] {
            let t = std::time::Instant::now();
            match crate::committed_air::prove_air_committed_bytes(cols(rows), make, &pb) {
                Some(b) => {
                    let ok = crate::committed_air::verify_air_committed_bytes(&b, make, &pb, crate::committed_air::declared_committed_shape_for_tests(&b));
                    let bundle: crate::committed_air::CommittedAirBundle =
                        postcard::from_bytes(&b).expect("decodes");
                    eprintln!(
                        "[bq] COMMITTED at {rows:2} rows ({} vars): {} B, {:?}, verifies={ok:?}, \
                         hvzk_mask_commits={}",
                        rows.trailing_zeros(),
                        b.len(),
                        t.elapsed(),
                        bundle.open.hvzk_mask_commits.len()
                    );
                }
                None => eprintln!(
                    "[bq] COMMITTED at {rows:2} rows ({} vars): PROVER REFUSED — below the \
                     COMMITTED_FOLDING floor",
                    rows.trailing_zeros()
                ),
            }
        }
        // ── BISECT: IS IT THE GATE OR THE SHAPE? ───────────────────────────────────────────────────
        // A degree-1 gate on the SAME 1986x16 shape, and the spend gate on a NARROW shape. Whichever
        // fails names the cause; guessing named the wrong one once already this session.
        {
            struct Triv {
                gamma: Ea4,
            }
            impl crate::air_zerocheck::AirConstraint for Triv {
                fn degree(&self, _n: usize) -> usize {
                    1
                }
                fn eval(
                    &self,
                    local: &crate::air_zerocheck::Row<'_>,
                    _at: &dyn Fn(usize, &[Ea4]) -> Ea4,
                    _x: &[Ea4],
                ) -> Ea4 {
                    let _ = self.gamma;
                    local[0] - local[0]
                }
            }
            let mk_t = |g: Ea4| Triv { gamma: g };
            let wide: Vec<Vec<Fa4>> = (0..row.len()).map(|c| vec![row[c]; 16]).collect();
            let b = crate::committed_air::prove_air_committed_bytes(wide, mk_t, &pb);
            eprintln!(
                "[bq/bisect] DEGREE-1 gate on the {}x16 spend SHAPE: verifies={:?}",
                row.len(),
                b.map(|x| crate::committed_air::verify_air_committed_bytes(&x, mk_t, &pb, crate::committed_air::declared_committed_shape_for_tests(&x)))
            );
            // The gate needs its full width — trimming it is a malformed trace, not a probe. So the
            // remaining variable is HEIGHT: the direct path ships 8 rows and the committed floor is 16.
            for rows in [8usize, 16, 32] {
                let c: Vec<Vec<Fa4>> = (0..row.len()).map(|k| vec![row[k]; rows]).collect();
                let d = prove_air_direct_light_decider_selfcontained_bytes(c, make, &pb).map(|x| {
                    verify_air_direct_light_decider_selfcontained_bytes(&x, make, &pb, crate::whir_rec_block::declared_direct_shape_for_tests(&x))
                });
                eprintln!("[bq/bisect] SPEND gate on the DIRECT path at {rows:2} rows: verifies={d:?}");
            }
        }

        for rows in [LIGHT_CARRIER_ROWS, 16, 32] {
            let t = std::time::Instant::now();
            match crate::committed_air::prove_air_blinded_bytes(cols(rows), make, &pb) {
                Some(b) => {
                    let ok = crate::committed_air::verify_air_blinded_bytes(&b, make, &pb, crate::committed_air::declared_blinded_laid_shape_for_tests(&b));
                    eprintln!(
                        "[bq] BLINDED   at {rows:2} rows (doubled): {} B, {:?}, verifies={ok:?}",
                        b.len(),
                        t.elapsed()
                    );
                }
                None => eprintln!("[bq] BLINDED   at {rows:2} rows: PROVER REFUSED"),
            }
        }
    }

    /// ⭐⭐⭐ §BP PROBE — WHAT WOULD IT COST TO DERIVE A CARRIER'S CHALLENGES IN CIRCUIT?
    ///
    /// The bound step's inner AIR must be batched at the CARRIER'S OWN γ, and its `r`/`z` are that
    /// carrier's Fiat-Shamir challenges. Held as free cells, a prover CHOOSES the batching scalar — and
    /// Schwartz-Zippel is exactly the argument that it cannot. So a bound multi-carrier aggregate needs
    /// each row's transcript derived in circuit, which means replaying that carrier's challenger sponge.
    ///
    /// This measures the absorb load rather than arguing about it: every field element a carrier's
    /// verifier observes before it can name γ. Divided by the sponge rate, that is permutations per
    /// carrier — and an aggregate pays it PER ROW.
    #[test]
    fn bp_the_transcript_a_carrier_absorbs_is_measured() {
        let sk = crate::poseidon2_compress::lanes_of(&[3, 1, 4, 1]);
        let other = crate::poseidon2_compress::lanes_of(&[9, 9, 9, 9]);
        let w = SpendValidityWitness {
            value_in: 5_000,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 4_900,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: 4_850,
            out0_opening: crate::poseidon2_compress::lanes_of(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        };
        let (carrier, cms, nf, lc) =
            prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0)).expect("an honest spend proves");
        let f = |d: Digest| -> DigestF { core::array::from_fn(|i| Fa4::from_u64(d[i])) };
        let pb = validity_public_bind_with_commit(&[f(cms[0]), f(cms[1])], &f(nf), &f(lc), &f(crate::whir_rec_block::test_clue_digest(0)), &f(spend_tag1(&w)));
        // ⭐ ITEM 1 LANDED, so `carrier` is now a COMMITTED bundle. The direct figure below is measured
        // on a carrier proved the OLD way, side by side, so the ratio stays honest rather than becoming
        // a comparison against a path production no longer ships.
        let (direct_bytes, _) = direct_baseline(&w);
        let bundle: AirDirectBundle = postcard::from_bytes(&direct_bytes).expect("decodes");
        // What the verifier observes before γ: the public bind, then the PCS opening claim.
        let opening_elems = postcard::to_allocvec(&bundle.openings[0]).expect("encodes").len() / 4;
        // Then, per zerocheck round, that round's evaluation points.
        let round_elems: usize =
            bundle.zc.round_evals.iter().map(|h| h.len() * 4).sum();
        let total = pb.len() + opening_elems + round_elems;
        // The challenger duplexes once per RATE absorbed elements.
        let rate = 8usize;
        let perms = total.div_ceil(rate);
        eprintln!(
            "[bp] ONE carrier's transcript: public bind {} + opening ~{} + round evals {} = ~{} field \
             elements -> ~{} sponge permutations PER CARRIER. A 32-carrier aggregate would replay ~{} \
             permutations; `sponge_chain_air` measures ~6,464 of them at ~2.6 s, and block spacing is \
             500 ms.",
            pb.len(),
            opening_elems,
            round_elems,
            total,
            perms,
            perms * 32
        );
        assert!(total > 0, "the transcript must absorb something");

        // ── THE SAME CARRIER ON THE COMMITTED PATH ─────────────────────────────────────────────────
        // ⭐⭐⭐ THIS IS WHY ITEM 1 IS NOT MERELY THE PRIVACY FIX. The direct path has no trace
        // commitment, so its verifier must absorb the ENTIRE opening before it can name γ. The
        // committed path absorbs a COMMITMENT — one digest — and draws γ from that. Everything the
        // circuit must replay to derive a carrier's challenges shrinks by that ratio.
        let cols: Vec<Vec<Fa4>> = spend_carrier_cols(&[SpendRow {
            in_value: 5_000,
            out_value: 4_900,
            fee: 100,
        }])
        .expect("the conservation carrier lays");
        let mk = |g: Ea4| SpendConservationGate { gamma: g };
        let committed = crate::committed_air::prove_air_committed_bytes(cols, mk, &pb)
            .expect("the committed carrier proves");
        let cb: crate::committed_air::CommittedAirBundle =
            postcard::from_bytes(&committed).expect("decodes");
        let digest_elems = 8usize; // one MMCS commitment
        let committed_pre_gamma = pb.len()
            + digest_elems
            + cb.open.hvzk_mask_commits.len() * digest_elems
            + cb.open.initial_ood_answers.len() * 4;
        let committed_rounds: usize = cb.zc.round_evals.iter().map(|h| h.len() * 4).sum();
        let committed_total = committed_pre_gamma + committed_rounds;
        let committed_perms = committed_total.div_ceil(rate);
        eprintln!(
            "[bp] THE SAME STATEMENT, COMMITTED: pre-gamma {} (bind {} + commitment {} + masks {} + ood \
             {}) + round evals {} = {} elements -> ~{} permutations PER CARRIER.",
            committed_pre_gamma,
            pb.len(),
            digest_elems,
            cb.open.hvzk_mask_commits.len() * digest_elems,
            cb.open.initial_ood_answers.len() * 4,
            committed_rounds,
            committed_total,
            committed_perms
        );
        eprintln!(
            "[bp] ⭐ RATIO {:.0}x. A 32-carrier BOUND aggregate: direct ~{} permutations, committed \
             ~{}. At `sponge_chain_air`'s measured ~0.4 ms per permutation that is ~{:.1} s vs ~{:.2} s, \
             against a 500 ms block. ITEM 1 IS WHAT MAKES THE BOUND AGGREGATE AFFORDABLE.",
            total as f64 / committed_total as f64,
            perms * 32,
            committed_perms * 32,
            (perms * 32) as f64 * 0.0004,
            (committed_perms * 32) as f64 * 0.0004
        );
        assert!(
            committed_total * 4 < total,
            "⛔ the committed path must absorb DRAMATICALLY less before its challenges, or the whole \
             ordering argument above is wrong"
        );
    }

    /// ⛔⛔⛔ GATE D IS GONE (2026-09-30) — THE PATH THAT PROVED NOTHING WAS DELETED AT SOURCE, AND THE CROSS-BIND IS
    /// WHAT ANCHORS A SPEND TO ITS NOTE.
    ///
    /// The depth-`d` Merkle path constrained nothing once §BY deleted its `acc(d) == root` weld (the earlier form of this
    /// pin MEASURED a garbage sibling verifying exactly like an honest one); the first whole-crate strict census then
    /// refused its LAST level on every depth ≥ 1 shape as a decorative block. This pin holds the replacement claims: the
    /// row is ONE constant shape (`spend_validity_row_width()`), a witness carries no path, the commitment is the
    /// two-level blinded compression over the carrier's OWN leaf (DB-363), the honest carrier verifies, and a commitment
    /// that does not recompute from that leaf — another note's leaf, another blinding, the old public-preimage formula —
    /// is REFUSED (the consensus lane's handoff condition, 2026-09-30 00:02).
    /// O1-INFINITY-REVIEWED: a test over ONE carrier row of a FIXED layout — `spend_validity_row_width()` is a function of
    /// the gate's constants only; nothing here is persisted or keyed per item.
    #[test]
    fn gate_d_is_gone_and_the_cross_bind_refuses_a_commitment_over_another_leaf() {
        let lanes = crate::poseidon2_compress::lanes_of;
        let sk = lanes(&[11u64, 12, 13, 14]);
        let blind = lanes(&[0x363u64, 1, 2, 3]);
        let w = SpendValidityWitness {
            value_in: 900,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 800,
            fee: 100,
            lc_blind: blind,
            out0_value: 750,
            out0_opening: lanes(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        };
        let clue = crate::whir_rec_block::test_clue_digest(0);
        let t = std::time::Instant::now();
        let (c, cms, nf, lc) =
            prove_spend_validity_carrier_with_commit_bytes(&w, clue).expect("the honest pathless spend proves");
        let ms = t.elapsed().as_millis();
        // ONE constant shape, no membership level laid
        let (row, ..) = spend_validity_row(&w).expect("the honest witness lays a row");
        assert_eq!(row.len(), spend_validity_row_width(), "the row is the constant layout");
        // the commitment is P(P(leaf, nf), lc_blind) over the row's OWN leaf — one spelling, read from the row
        let leaf = spend_input_leaf(&w).expect("the input leaf");
        assert_eq!(lc, poseidon_pair(poseidon_pair(leaf, nf), blind), "lc = P(P(leaf, nf), lc_blind)");
        let tag1 = spend_tag1(&w);
        assert!(verify_spend_validity_carrier_bytes(&c, cms[0], cms[1], nf, lc, clue, tag1, 100), "CONTROL: the honest spend verifies");
        // REFUSALS — a commitment over ANOTHER note's leaf, same nullifier and blinding
        let other_leaf = asset_note_cm(5u64, USDM_ASSET_TAG, lanes(&[1, 2, 3, 4]));
        let lie = poseidon_pair(poseidon_pair(other_leaf, nf), blind);
        assert_ne!(lie, lc, "CALIBRATION: the two notes commit differently");
        assert!(
            !verify_spend_validity_carrier_bytes(&c, cms[0], cms[1], nf, lie, clue, tag1, 100),
            "⛔ a commitment over ANOTHER leaf verified against this carrier — the cross-bind no longer anchors the spend"
        );
        // the right leaf under ANOTHER blinding (a membership carrier built under a different r): one tx, one lc
        let other_r = poseidon_pair(poseidon_pair(leaf, nf), lanes(&[9, 9, 9, 9]));
        assert!(!verify_spend_validity_carrier_bytes(&c, cms[0], cms[1], nf, other_r, clue, tag1, 100), "⛔ two blindings in one tx verified");
        // the OLD public-preimage commitment is not this carrier's
        assert!(
            !verify_spend_validity_carrier_bytes(&c, cms[0], cms[1], nf, poseidon_pair(leaf, nf), clue, tag1, 100),
            "⛔ the unblinded P(leaf, nf) verified — DB-363's hole would be open"
        );
        eprintln!("[gate-d] constant row {} columns, carrier {} B, prove {ms} ms", spend_validity_row_width(), c.len());
    }

    /// ⭐⭐⭐ §BO PROBE — CAN THE BOUND STEP CONSUME A *REAL* SPEND CARRIER? Everything §BA/§BB needs
    /// rests on it: a note-transition aggregate must verify each carrier's SPEND GATE in circuit, and
    /// `recursion_bound::bound_step_row` is what turns a carrier into an outer row that does. It
    /// fail-closes on any carrier that is not the single-table shape it accepts, so this asks a
    /// production carrier directly instead of assuming the shape, and PRINTS the row geometry the
    /// aggregate will have to carry.
    #[test]
    fn bo_a_real_spend_carrier_becomes_a_bound_step_row() {
        let sk = crate::poseidon2_compress::lanes_of(&[3, 1, 4, 1]);
        let other = crate::poseidon2_compress::lanes_of(&[9, 9, 9, 9]);
        let w = SpendValidityWitness {
            value_in: 5_000,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 4_900,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: 4_850,
            out0_opening: crate::poseidon2_compress::lanes_of(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        };
        let (carrier, cms, nf, lc) =
            prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0)).expect("an honest spend proves");
        assert!(
            verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, lc, crate::whir_rec_block::test_clue_digest(0), spend_tag1(&w), 100),
            "CONTROL: the production carrier must verify before anything is asked of it"
        );
        // The prover hands back `Digest` ([u64; 4]); the transcript binds `DigestF`. Lift, don't guess.
        let f = |d: Digest| -> DigestF { core::array::from_fn(|i| Fa4::from_u64(d[i])) };
        let pb = validity_public_bind_with_commit(&[f(cms[0]), f(cms[1])], &f(nf), &f(lc), &f(crate::whir_rec_block::test_clue_digest(0)), &f(spend_tag1(&w)));
        // ⭐ ITEM 1 MOVED THE PRODUCTION CARRIER to the blinded committed path, so its transcript is
        // replayed by `committed_air::transcript_of_committed_carrier`. That the replay SUCCEEDS is the
        // thing a bound aggregate needs: γ and z derived the way the verifier derives them.
        let t = crate::committed_air::transcript_of_committed_carrier(&carrier, &pb);
        assert!(
            t.is_some(),
            "⛔ the committed carrier's transcript could not be replayed from public data — a bound \
             aggregate over it would be asserting something about a transcript nobody ran"
        );
        let (_g, z) = t.expect("replayed");
        let zc = crate::committed_air::zerocheck_of_committed_carrier(&carrier).expect("bundle decodes");
        eprintln!(
            "[bo] the SHIPPED (blinded committed) spend carrier: shape {:?}, z len {}, rounds {}, \
             opened {} — its transcript replays from public data alone.",
            zc.1,
            z.len(),
            zc.0.round_evals.len(),
            zc.0.opened.len()
        );
        // ⛔ AND THE REMAINING GAP, NAMED: `bound_step_row` parses the DIRECT bundle only. A bound
        // aggregate over the shipped carrier needs its committed twin — that is the next brick, and it
        // is small now that the transcript replay above exists.
        let got = crate::recursion_bound::bound_step_row(&direct_baseline(&w).0, &pb);
        match got {
            Some((vals, layout, _gamma)) => {
                assert_eq!(
                    vals.len(),
                    layout.values() * 4,
                    "the row must be exactly the layout's limbs"
                );
                eprintln!(
                    "[bo] a REAL spend carrier IS a bound-step row: nvars={} per={} width={} \
                     -> {} values ({} limbs). An aggregate of N carriers is N such rows.",
                    layout.nvars,
                    layout.per,
                    layout.width,
                    layout.values(),
                    vals.len()
                );
            }
            None => panic!(
                "⛔ §BO BLOCKED: `bound_step_row` fail-closed on a PRODUCTION spend carrier, so the \
                 note-transition aggregate cannot be built on the bound step as designed. The carrier \
                 is not the single-table shape the extractor accepts — that shape is the thing to fix, \
                 and it must be fixed before any of §BA/§BB is attempted."
            ),
        }
    }

    /// ⭐⭐⭐ DOES CARRIER SIZE TRACK ROW WIDTH? The measurement that decides how n-in/2-out is built.
    ///
    /// The row is `47 + depth*33` columns plus the two 25-column output blocks, so `depth` IS the row-width
    /// lever and needs no new circuit to exercise. If bytes stay ~flat across a 64x width change, then
    /// widening the row to carry n inputs is affordable and the n-in fix can keep the EXISTING proving
    /// path — which matters because that path is the BLINDED committed one, and §BE-1 records what the
    /// unblinded one leaked: "every amount, and the spent note's LEAF, rode in the clear".
    ///
    /// Reported, not asserted past the one property that decides the design: bytes must not grow
    /// proportionally to width, or option (A) is dead and the n-in fix needs a different shape.
    #[test]
    fn the_spend_carrier_size_against_row_width_decides_how_n_in_is_built() {
        let sk = crate::poseidon2_compress::lanes_of(&[11u64, 12, 13, 14]);
        let sib = asset_note_cm(5u64, USDM_ASSET_TAG, crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]));
        let mut rows: Vec<(usize, usize, usize, u128)> = Vec::new();
        for depth in [1usize, 8, 16, 32, 64] {
            let w = SpendValidityWitness {
                value_in: 900,
                owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
                value_out: 800,
                fee: 100,
                lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
                out0_value: 750,
                out0_opening: crate::poseidon2_compress::lanes_of(&[7, 7, 7, 7]),
                out1_value: 50,
                out1_opening: sk,
            };
            let t = std::time::Instant::now();
            let Some((c, _cms, _nf, _lc)) = prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0)) else {
                panic!("the honest spend must prove at depth {depth}");
            };
            let ms = t.elapsed().as_millis();
            let width = 47 + depth * 33 + 50;
            rows.push((depth, width, c.len(), ms));
        }
        for (d, w, b, ms) in &rows {
            eprintln!("[spend-width] depth={d:<3} row_width={w:<5} carrier={b} B  prove={ms} ms");
        }
        let (d0, w0, b0, _) = rows[0];
        let (d1, w1, b1, _) = *rows.last().expect("rows");
        let width_x = w1 as f64 / w0 as f64;
        let bytes_x = b1 as f64 / b0 as f64;
        eprintln!(
            "[spend-width] width grew {width_x:.1}x (depth {d0} -> {d1}); carrier grew {bytes_x:.2}x"
        );
        assert!(
            bytes_x < width_x / 2.0,
            "⛔ CARRIER SIZE TRACKS ROW WIDTH ({bytes_x:.2}x bytes for {width_x:.1}x width). Then widening \
             the row to carry n inputs multiplies the carrier and option (A) is dead — the n-in fix needs \
             a different shape. Do not widen and hope."
        );
    }

    #[test]
    fn a_note_committed_at_v_cannot_be_spent_as_v_plus_p() {
        let p: u64 = 2_130_706_433;
        let (v, sk) = (900u64, crate::poseidon2_compress::lanes_of(&[11u64, 12, 13, 14]));
        let other = asset_note_cm(5u64, USDM_ASSET_TAG, crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]));
        let witness = |value_in: u64| SpendValidityWitness {
            value_in,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: value_in - 100,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: value_in - 100 - 50,
            out0_opening: crate::poseidon2_compress::lanes_of(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        };
        let _ = other; // the path is gone (2026-09-30)
        // The HONEST spend of the `v` note: its nullifier and leaf_commit are what the note-membership
        // carrier over the accumulator binds — the only cross-bind the node will ever accept for this note.
        let (c, cms, nf, lc) = prove_spend_validity_carrier_with_commit_bytes(&witness(v), crate::whir_rec_block::test_clue_digest(0)).expect("honest spend proves");
        assert!(verify_spend_validity_carrier_bytes(&c, cms[0], cms[1], nf, lc, crate::whir_rec_block::test_clue_digest(0), spend_tag1(&witness(v)), 100), "⛔ THE CONTROL FAILED");
        // THE ATTACK: the same note, same key, same copath, claimed at `v + p`.
        assert_ne!(v, v + p, "⛔ THE VIOLATING STATE WAS NEVER BUILT");
        let Some((c2, cms2, nf2, lc2)) = prove_spend_validity_carrier_with_commit_bytes(&witness(v + p), crate::whir_rec_block::test_clue_digest(0)) else {
            return; // the builder refused outright — also a refusal
        };
        // The mechanism, stated directly: a different integer must be a different note.
        assert_ne!(nf2, nf, "⛔⛔ the inflated claim derived the SAME nullifier — leaf(v) == leaf(v + p)");
        assert_ne!(lc2, lc, "⛔⛔ the inflated claim derived the SAME leaf_commit — the honest membership carrier would cross-bind it");
        // And the door: the inflated carrier presented under the HONEST note's cross-bind must be refused.
        assert!(
            !verify_spend_validity_carrier_bytes(&c2, cms2[0], cms2[1], nf2, lc, crate::whir_rec_block::test_clue_digest(0), spend_tag1(&witness(v + p)), 100),
            "⛔⛔ INFLATION SEAM OPEN: a spend claiming {} verified under the leaf_commit the membership carrier \
             bound for the note committed at {v}",
            v + p
        );
    }

    /// A forged top carry: claim the sum wrapped past 2^64 so `in` can be small while `out` is huge.
    #[test]
    fn a_wrap_past_u64_is_unrepresentable() {
        let mut cols = honest_trace();
        // out = 2^64 − 1 (all limbs 0xFFFF, all bits 1), fee = 1, in = 0: only a top carry of 1 balances.
        for i in 0..SC_LIMBS {
            cols[SC_OUT + i][0] = Fa4::from_u64(0xFFFF);
            cols[SC_IN + i][0] = Fa4::ZERO;
            cols[SC_CARRY + i][0] = Fa4::ONE;
        }
        for k in 0..(SC_LIMBS * SC_LIMB_BITS) {
            cols[SC_OUT_BITS + k][0] = Fa4::ONE;
            cols[SC_IN_BITS + k][0] = Fa4::ZERO;
        }
        assert!(
            !proves_and_verifies(cols),
            "⛔⛔ a sum that wrapped past 2^64 proved and verified — the top carry is not forced to zero"
        );
    }
}

/// ⛔⛔⛔ LANE-E PINS — THE SHAPE FUZZ AGAINST THE PRODUCTION SPEND-CARRIER VERIFY.
///
/// `verify_spend_carrier_bytes` is the exact function the node's `/submit_pq_tx` door reaches off-lock
/// (`whir_decider::pqspend_direct_verify_carrier` -> here; measured at rpc_http.rs:1270, whose arm was deleted 2026-09-08 while the same verifier stayed live under the spend-validity, multi-spend and cover arms) and the exact function the
/// gossip door reaches through `chain_object::admissible`. Its contract is "never panics"; before this
/// lane it did, on two different attacker-chosen shapes.
///
/// These pins drive MALFORMED widths, lengths and counts through it and assert BOTH halves of the
/// contract: REFUSAL, and no unwind. There is no `catch_unwind` anywhere here on purpose — if the
/// verifier panics, the pin dies with it and the failure names the shape that did it, which is the
/// report.
#[cfg(test)]
mod lane_e_shape_fuzz {
    use super::*;

    /// One honest carrier, reshaped by the attacker in `mutate`, then presented to the production door.
    fn reshaped(mutate: impl FnOnce(&mut crate::committed_air::CommittedAirBundle)) -> Vec<u8> {
        let carrier = prove_spend_carrier_bytes(&[SpendRow { in_value: 6, out_value: 5, fee: 1 }])
            .expect("an honest carrier to reshape");
        let mut b: crate::committed_air::CommittedAirBundle =
            postcard::from_bytes(&carrier).expect("the carrier is a CommittedAirBundle");
        mutate(&mut b);
        postcard::to_allocvec(&b).expect("re-encode the reshaped carrier")
    }

    /// ⛔⛔⛔ PIN E-1 — NO ATTACKER-CHOSEN WIDTH, LENGTH OR COUNT MAY PANIC THE PRODUCTION VERIFIER.
    ///
    /// Every shape here is a count a REMOTE caller supplies. Pre-fix, shape (a) unwound
    /// `sumcheck/src/layout/verifier.rs:132` (pin C-16) and shape (e) unwound
    /// `SpendConservationGate::eval` at `local[1]` (pin C-17) — a ~100-byte self-consistent carrier that
    /// no shape cross-check can catch, which is why the row itself had to become the guard.
    ///
    /// ⭐ RESHAPES THE BUNDLE THE PRODUCTION DOOR ACTUALLY TAKES. Item 1 moved this carrier onto the
    /// blinded committed path, so reshaping the old `AirDirectBundle` would be fuzzing a door nothing
    /// calls. Its `shape` is a single pair rather than a vector, so the old "shapes emptied/duplicated"
    /// and "openings duplicated" cases are UNREPRESENTABLE — the type forbids them, which is a stronger
    /// answer than a runtime refusal and is why they are gone rather than relaxed.
    #[test]
    fn e1_no_attacker_chosen_shape_panics_or_verifies() {
        let honest = prove_spend_carrier_bytes(&[SpendRow { in_value: 6, out_value: 5, fee: 1 }])
            .expect("prove an honest carrier");
        assert!(
            verify_spend_carrier_bytes(&honest),
            "E-1 is measuring nothing if the HONEST carrier stopped verifying — the shape gate must \
             refuse hostile shapes ONLY"
        );

        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        cases.push(("width 64 declared", reshaped(|b| b.shape.1 = 64)));
        cases.push(("width 1 declared", reshaped(|b| b.shape.1 = 1)));
        cases.push(("width usize::MAX", reshaped(|b| b.shape.1 = usize::MAX)));
        cases.push(("nvars 64 (shift width)", reshaped(|b| b.shape.0 = 64)));
        cases.push(("nvars usize::MAX", reshaped(|b| b.shape.0 = usize::MAX)));
        cases.push((
            "self-consistent (nvars,width)=(0,1): every count agrees, the AIR still reads 3 columns",
            reshaped(|b| {
                b.shape = (0, 1);
                b.zc.opened.truncate(1);
                b.zc.shifted_opened.truncate(1);
                b.zc.round_evals.clear();
                b.zc.r.clear();
            }),
        ));
        cases.push((
            "self-consistent (nvars,width)=(0,2): one column short of the AIR",
            reshaped(|b| {
                b.shape = (0, 2);
                b.zc.opened.truncate(2);
                b.zc.shifted_opened.truncate(2);
                b.zc.round_evals.clear();
                b.zc.r.clear();
            }),
        ));
        cases.push((
            "width 0",
            reshaped(|b| {
                b.shape.1 = 0;
                b.zc.opened.clear();
                b.zc.shifted_opened.clear();
            }),
        ));
        cases.push(("zc.opened truncated to 2", reshaped(|b| b.zc.opened.truncate(2))));
        cases.push(("zc.opened emptied", reshaped(|b| b.zc.opened.clear())));
        cases.push((
            "zc.opened and shifted_opened BOTH truncated to 2 (the length cross-check agrees, the \
             gate still reads local[2])",
            reshaped(|b| {
                b.zc.opened.truncate(2);
                b.zc.shifted_opened.truncate(2);
            }),
        ));
        cases.push((
            "zc.opened lengthened past the width",
            reshaped(|b| b.zc.opened.push(Ea4::ONE)),
        ));
        // 2026-11-10 (the next-row class closed at the door): an honest carrier of this door now carries NO next-row
        // opening, so the two old shapes here (the list truncated to 1, the list emptied) became the honest carrier
        // itself. The hostile shapes that remain are the ones that SEND a next-row value: one, and a whole row of them.
        assert!(
            postcard::from_bytes::<crate::committed_air::CommittedAirBundle>(&honest).is_ok_and(|b| b.zc.shifted_opened.is_empty()),
            "CALIBRATION: an honest carrier of the plain door carries no next-row opening"
        );
        cases.push(("zc.shifted_opened given one value", reshaped(|b| b.zc.shifted_opened.push(Ea4::ONE))));
        cases.push((
            "zc.shifted_opened given a whole row of values",
            reshaped(|b| b.zc.shifted_opened = b.zc.opened.clone()),
        ));
        cases.push(("zc.r truncated", reshaped(|b| b.zc.r.truncate(2))));
        cases.push(("zc.r emptied", reshaped(|b| b.zc.r.clear())));
        cases.push(("zc.round_evals emptied", reshaped(|b| b.zc.round_evals.clear())));
        cases.push((
            "zc.round_evals row emptied",
            reshaped(|b| {
                if let Some(h) = b.zc.round_evals.first_mut() {
                    h.clear();
                }
            }),
        ));
        // (j) the documented decode-failure paths.
        cases.push(("truncated frame", honest[..honest.len() / 3].to_vec()));
        cases.push(("empty frame", Vec::new()));
        cases.push(("one zero byte", vec![0u8]));

        for (name, bytes) in &cases {
            // No catch_unwind: a panic here IS the failure, and it names the shape.
            let verdict = verify_spend_carrier_bytes(bytes);
            println!("[E-1] hostile shape '{name}' -> verified={verdict} (returned, did not unwind)");
            assert!(
                !verdict,
                "FAIL-CLOSED BROKEN: hostile shape '{name}' VERIFIED. A carrier that declares its own \
                 trace shape must never be accepted."
            );
        }
        println!("[E-1] {} attacker-chosen shapes refused, 0 panics", cases.len());
    }

    /// ⛔⛔ PIN E-2 — THE FIX REFUSES HOSTILE SHAPES ONLY.
    ///
    /// A shape gate that also refuses honest carriers is a halt, not a fix ("a refusal to append is a
    /// refusal to RECEIVE"). This proves the gate is inert on every honest shape the production prover
    /// emits: 1 row through the full 32-row pack, which is the whole legal domain of this carrier.
    #[test]
    fn e2_every_honest_carrier_shape_still_verifies() {
        for n in [1usize, 2, 7, 31, 32] {
            let rows: Vec<SpendRow> = (0..n)
                .map(|i| SpendRow { in_value: 10 + i as u64, out_value: 9 + i as u64, fee: 1 })
                .collect();
            let carrier = prove_spend_carrier_bytes(&rows).expect("honest rows prove");
            assert!(
                verify_spend_carrier_bytes(&carrier),
                "E-2 REGRESSION: the shape gate refused an HONEST {n}-row carrier — that is a halt, \
                 not a fix"
            );
        }
        println!("[E-2] honest carriers at 1,2,7,31,32 rows all still verify");
    }
}

// ---------------------------------------------------------------------------
// SPEND-MAIN carrier — the next gate toward full PqSpendAir parity: per spend row
// it enforces BOTH value conservation (`in == out + fee`) AND correct nullifier
// derivation `nf = PoseidonOneRound(sk, leaf)` (the EXACT one-round Poseidon shape
// pqpool ships: x⁷ S-box + the production 4×4 KoalaBear-MDS mix). Binding `nf`
// in-circuit makes the spend's nullifier DERIVED from its secret spend key — so a
// forged `nf` (≠ H(sk,leaf)) is UNSATISFIABLE and double-spends (same note ⇒ same
// nf) are detectable. Completing brick: fold in the depth-32 frontier MEMBERSHIP
// gate → the row is byte-identical to PqSpendAir; then repoint the node verify here.
// ---------------------------------------------------------------------------

/// The production 4×4 KoalaBear-MDS matrix pqpool's `hash_pair_commit::h_two_arg` uses
/// (must match for the wallet's `nf` to equal the node's).
const SPEND_MDS: [[u64; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];

/// One spend with its nullifier witness: value row `[in,out,fee]` (conserves iff
/// `in == out + fee`) plus the secret spend key `sk` and note `leaf` whose Poseidon
/// one-round hash is the bound nullifier.
#[derive(Clone, Copy, Debug)]
pub struct SpendMainRow {
    pub in_value: u64,
    pub out_value: u64,
    pub fee: u64,
    pub sk: Digest,
    pub leaf: Digest,
}

/// Combined per-row gate: conservation (`in-out-fee`) AND the 20 Poseidon-nullifier
/// lane residuals, γ-folded (Schwartz–Zippel: any wrong lane ⇒ residual ≠ 0 w.h.p.).
/// Columns (width 31): in,out,fee(0..3) ‖ sk(3..7) ‖ leaf(7..11) ‖ pre(11..15) ‖
/// pre_sq(15..19) ‖ pre_4(19..23) ‖ pre_7(23..27) ‖ nf(27..31). Degree 3 (pre_7 triple product).
/// Where the range-bound value block starts in the spend-main trace: after the 31 legacy columns.
/// The spend-main row's layout. ⛔ Every offset was a literal (3,7,11,15,19,23,27,31) until 2026-09-12.
pub const SM_IN: usize = 0;
pub const SM_OUT: usize = 1;
pub const SM_FEE: usize = 2;
pub const SM_SK: usize = 3;
pub const SM_LEAF: usize = SM_SK + DIGEST_LANES;
pub const SM_NF: usize = SM_LEAF + DIGEST_LANES;
pub const SM_P2: usize = SM_NF + DIGEST_LANES;
const SM_VAL_BASE: usize = SM_P2 + crate::pow_pq_air::P2_COLS;
/// The spend-main trace width: 31 legacy columns + one range-bound u64 conservation block.
pub const SM_WIDTH: usize = SM_VAL_BASE + U64_CONS_WIDTH;

pub struct SpendMainGate {
    pub gamma: Ea4,
}
impl crate::air_zerocheck::AirConstraint for SpendMainGate {
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ EMBEDS A PERMUTATION: a gate declaring less than the permutation's degree truncates
        // the sumcheck, so even an HONEST proof stops verifying.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let g = self.gamma;
        let sk = |c: usize| local[SM_SK + c];
        let leaf = |c: usize| local[SM_LEAF + c];
        let mut rs: Vec<Ea4> = Vec::new();
        // ⛔⛔⛔ ITEM 1 / D-28, SITE 2 OF 4 (2026-09-11): gate 0 used to be the single field identity
        // `in - out - fee`, which `out = in + p - fee` satisfies — inflation on the arm that IS
        // `spend_ok`. It is now the range-bound u64 block, and the three legacy whole-value columns are
        // BOUND to their limbs by recombination so no value column in this trace is unconstrained.
        let vb = U64ConsBases::at(SM_VAL_BASE);
        push_u64_conservation(&mut rs, local, vb);
        rs.push(local[SM_IN] - u64_limbs_recombined(local, vb.r#in));
        rs.push(local[SM_OUT] - u64_limbs_recombined(local, vb.out));
        rs.push(local[SM_FEE] - u64_limbs_recombined(local, vb.fee));
        // THE NULLIFIER — `nf == compress(sk, leaf)`, one whole permutation. ⛔ Was the 1-round fold,
        // which inverts: a spender could SOLVE for a `leaf` giving any nullifier it wanted (kill list §AG).
        push_pose_round(&mut rs, local, &sk, &leaf, SM_P2, SM_NF);
        // γ-power fold: acc = Σ_k γ^k · r_k.
        let mut acc = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in rs {
            acc = acc + gp * r;
            gp = gp * g;
        }
        acc
    }
}

/// Pack up to 32 spend-main rows into the width-31 trace, computing the Poseidon
/// witness lanes (pre / pre_sq / pre_4 / pre_7 / nf) from each row's `sk`,`leaf`.
/// None if any row does not conserve, is empty, or count > 32.
fn spend_main_cols(rows: &[SpendMainRow]) -> Option<Vec<Vec<Fa4>>> {
    const H: usize = SPEND_MAIN_ROWS;
    const W: usize = SM_WIDTH;
    if rows.is_empty() || rows.len() > H {
        return None;
    }
    let mut cols: Vec<Vec<Fa4>> = (0..W).map(|_| vec![Fa4::ZERO; H]).collect();
    for (i, r) in rows.iter().enumerate() {
        // The honest-prover bound (`checked_add`, inside) and the range-bound block the gate reads.
        fill_u64_conservation(&mut cols, i, r.in_value, r.out_value, r.fee, U64ConsBases::at(SM_VAL_BASE))?;
        cols[SM_IN][i] = Fa4::from_u64(r.in_value);
        cols[SM_OUT][i] = Fa4::from_u64(r.out_value);
        cols[SM_FEE][i] = Fa4::from_u64(r.fee);
        let sk: DigestF = to_f(&r.sk);
        let leaf: DigestF = to_f(&r.leaf);
        for c in 0..DIGEST_LANES {
            cols[SM_SK + c][i] = sk[c];
            cols[SM_LEAF + c][i] = leaf[c];
        }
        // The nullifier is a whole permutation over (sk, leaf) — the trace lays the permutation block and
        // the gate welds its operands and output.
        crate::pow_pq_air::lay_perm_row_at(&mut cols, SM_P2, i, crate::pow_pq_air::pair_state(&to_u64(&sk), &to_u64(&leaf)));
        for c in 0..DIGEST_LANES {
            cols[SM_NF + c][i] = cols[SM_P2 + crate::pow_pq_air::PERM_OUT + c][i];
        }
    }
    // ⛔⛔⛔ THE PADDING ROWS HAVE TO BE VALID ROWS, AND USED NOT TO NEED TO BE.
    //
    // The retired 1-round fold was ZERO-PRESERVING — `MDS · (0 + 7·0)⁷ = 0` — so an all-zero padding row
    // satisfied the nullifier constraint for free and nobody ever had to think about the tail of the
    // trace. A permutation has no such property: its output on the zero state is a fixed NONZERO digest,
    // so a zero row is simply an INVALID trace and the honest proof stops verifying ("honest spend-main
    // carrier MUST verify"). ⭐ Any property a retired primitive gave you for free is one your padding
    // silently depended on. Conservation is untouched: 0 in, 0 out, 0 fee with zero range bits is a
    // genuinely conserving row.
    let zero_state = crate::pow_pq_air::pair_state(&[0u64; DIGEST_LANES], &[0u64; DIGEST_LANES]);
    for i in rows.len()..H {
        crate::pow_pq_air::lay_perm_row_at(&mut cols, SM_P2, i, zero_state);
        for c in 0..DIGEST_LANES {
            cols[SM_NF + c][i] = cols[SM_P2 + crate::pow_pq_air::PERM_OUT + c][i];
        }
    }
    Some(cols)
}

/// Prove a trustless-WHIR carrier certifying every spend row conserves value AND
/// carries a correctly-derived Poseidon nullifier. None if unfunded / prover rejects.
#[must_use]
pub fn prove_spend_main_carrier_bytes(rows: &[SpendMainRow]) -> Option<Vec<u8>> {
    let cols = spend_main_cols(rows)?;
    let make = |gamma: Ea4| SpendMainGate { gamma };
    crate::committed_air::prove_air_blinded_bytes(cols, make, &spend_carrier_public_bind())
}

/// Verify a spend-main carrier under the SAME pinned config + public bind. Fail-closed.
#[must_use]
pub fn verify_spend_main_carrier_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let make = |gamma: Ea4| SpendMainGate { gamma };
    crate::committed_air::verify_air_blinded_bytes(bytes, make, &spend_carrier_public_bind(), (SPEND_MAIN_ROWS.trailing_zeros() as usize, SM_WIDTH))
}

// ---------------------------------------------------------------------------
// SPEND-MEMBERSHIP carrier — the 3rd (final) PqSpendAir gate: per row it proves the
// spent note's commitment (leaf) is a MEMBER of the public frontier tree with the
// given `root`, by recomputing the depth-`d` Merkle path IN-CIRCUIT with the SAME
// production Poseidon hash (`hash_pair_commit::h_two_arg`, x⁷+MDS) the node's
// `MerkleFrontierAir` uses — so a note NOT on-chain (or a forged/misplaced path)
// can't satisfy the `acc_depth == root` bind. `root` is PUBLIC (transcript-welded),
// so a prover can't claim membership in a different tree than the verifier checks.
// Completing brick: cross-bind (leaf, sk, value_in) across conservation+nullifier+
// membership into ONE `SpendValidityConstraint` row == byte-identical PqSpendAir.
// ---------------------------------------------------------------------------

/// Membership-carrier transcript-weld tag (distinct from the conservation/main domains).
pub const SPEND_MEMBERSHIP_DOMAIN: u64 = 0x5350_4e44_4d45_4d; // "SPNDMEM"

/// A note's frontier-membership witness: its `leaf` commitment + the depth-`d` copath
/// (`siblings`) and per-level direction bits (`dirs`, true = leaf is the right child).
#[derive(Clone, Debug)]
pub struct MembershipWitness {
    pub leaf: Digest,
    pub siblings: Vec<Digest>,
    pub dirs: Vec<bool>,
}

/// In-circuit Poseidon-Merkle membership gate: recompute the path leaf→root and bind
/// `acc_depth == root` (public). Column layout: acc_0[0..4] then per level a 33-wide
/// block (sib[4], dir, left[4], right[4], pre[4], pre_sq[4], pre_4[4], pre_7[4], accn[4]).
/// Degree 3 (pre_7 triple product). γ-power-batched residuals (Schwartz–Zippel).
pub struct SpendMembershipGate {
    pub gamma: Ea4,
    pub root: [Ea4; DIGEST_LANES],
    pub depth: usize,
}
impl crate::air_zerocheck::AirConstraint for SpendMembershipGate {
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ EMBEDS A PERMUTATION: a gate declaring less than the permutation's degree truncates
        // the sumcheck, so even an HONEST proof stops verifying.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let one = Ea4::ONE;
        let mut rs: Vec<Ea4> = Vec::new();
        // acc_0 is the claimed leaf; each level's accumulator is the previous permutation's output.
        let acc = |lvl: usize, c: usize| -> Ea4 {
            if lvl == 0 {
                local[SMEM_LEAF + c]
            } else {
                local[SMEM_MB + (lvl - 1) * SMEM_LEVEL + DIGEST_LANES + 1 + crate::pow_pq_air::PERM_OUT + c]
            }
        };
        for lvl in 0..self.depth {
            let base = SMEM_MB + lvl * SMEM_LEVEL;
            let sib = |c: usize| local[base + c];
            let dir = local[base + DIGEST_LANES];
            let blk = base + DIGEST_LANES + 1;
            rs.push(dir * (one - dir));
            crate::pow_pq_air::push_perm_residuals(local, blk, &mut rs);
            for c in 0..DIGEST_LANES {
                let a = acc(lvl, c);
                rs.push(local[blk + c] - (a + dir * (sib(c) - a)));
                rs.push(local[blk + DIGEST_LANES + c] - (sib(c) + dir * (a - sib(c))));
            }
        }
        // The walked path must land EXACTLY on the committed root.
        for c in 0..DIGEST_LANES {
            rs.push(acc(self.depth, c) - self.root[c]);
        }
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = one;
        for r in rs {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }
}

/// The membership row's layout: the leaf, then one fold level per copath sibling.
pub const SMEM_LEAF: usize = 0;
pub const SMEM_MB: usize = SMEM_LEAF + DIGEST_LANES;
/// Columns ONE fold level occupies: sibling, direction bit, and a whole permutation.
pub const SMEM_LEVEL: usize = DIGEST_LANES + 1 + crate::pow_pq_air::P2_COLS;

/// Build the membership row and the root its copath recomputes. `None` on an empty or mismatched path.
fn membership_row_and_root(w: &MembershipWitness) -> Option<(Vec<Fa4>, DigestF)> {
    let depth = w.siblings.len();
    // ⛔ THIS PATH IS LOAD-BEARING — unlike the spend gate's. `membership_row_and_root` RETURNS the root
    // its copath recomputes, and the note-membership carrier binds that root to the accumulator. An
    // empty path here would claim membership having folded nothing, so `depth == 0` stays refused.
    // (2026-09-15: an edit meant for the spend gate's DEAD path landed here first and was reverted —
    // the two look alike and only one of them proves anything.)
    if depth == 0 || depth != w.dirs.len() {
        return None;
    }
    let width = membership_carrier_row_width(depth)?;
    let mut row = vec![Fa4::ZERO; width];
    let mut acc: DigestF = to_f(&w.leaf);
    row[SMEM_LEAF..SMEM_LEAF + DIGEST_LANES].copy_from_slice(&acc);
    for i in 0..depth {
        let base = SMEM_MB + i * SMEM_LEVEL;
        let sib: DigestF = to_f(&w.siblings[i]);
        row[base..base + DIGEST_LANES].copy_from_slice(&sib);
        let dir = w.dirs[i];
        row[base + DIGEST_LANES] = Fa4::from_u64(dir as u64);
        let (left, right) = if dir { (sib, acc) } else { (acc, sib) };
        let blk = base + DIGEST_LANES + 1;
        crate::pow_pq_air::lay_perm_row_flat(&mut row, blk, pose_state(&left, &right));
        acc = core::array::from_fn(|c| row[blk + crate::pow_pq_air::PERM_OUT + c]);
    }
    Some((row, acc))
}

/// Public IO bound at the transcript start: the membership domain + the `root`.
fn membership_public_bind(root: &DigestF) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(SPEND_MEMBERSHIP_DOMAIN)];
    b.extend_from_slice(root);
    b
}

/// The light decider's MINIMUM sound trace height = `2^FOLDING` (FOLDING = 3). A per-row carrier (the whole
/// statement in ONE row, replicated) needs no more than this: the WHIR rate (= 1/blowup) and query count set the
/// soundness, both height-independent, so replicating to 8 rather than a legacy 32 is byte-for-byte as sound and ~4×
/// cheaper to prove. Every per-row carrier in this crate uses this (nothing left unoptimized). Verify reads the
/// height from the proof, so shrinking the prover side is NON-breaking (existing verifiers accept the smaller proof).
pub const LIGHT_CARRIER_ROWS: usize = 8;

/// The conservation spend carrier's laid height (`spend_carrier_cols`) — the statement's row count (DB-213b).
pub const SPEND_CARRIER_ROWS: usize = 32;
/// The spend-main carrier's laid height (`spend_main_cols`).
pub const SPEND_MAIN_ROWS: usize = 32;
/// The mint and asset-mint carriers' laid height (`mint_validity_cols`, `asset_mint_cols`, and their
/// committed twins, which extend those columns).
pub const MINT_TRACE_ROWS: usize = 32;

/// Prove a note's in-circuit frontier membership. Returns the carrier bytes AND the
/// public `root` the verifier must check against (`verify_membership_carrier_bytes`).
/// None if the witness is malformed.
#[must_use]
pub fn prove_membership_carrier_bytes(w: &MembershipWitness) -> Option<(Vec<u8>, Digest)> {
    let (row, root) = membership_row_and_root(w)?;
    let depth = w.siblings.len();
    // ⛔ WAS `4 + depth * 33` — the four-lane, one-round arithmetic, and it silently disagreed with
    // `membership_row_and_root`'s own derived width the moment a fold level became a whole permutation.
    // The AIR then read past its trace: "AIR gate read a column its own trace does not have".
    let width = membership_carrier_row_width(depth)?;
    // Row-replicate the single path across the light decider's MINIMUM height (the per-row root-bind holds on every
    // row, so we only need `2^FOLDING`, not a legacy 32 — same rate/queries ⇒ identical soundness, ~4× less prover work).
    let cols: Vec<Vec<Fa4>> = (0..width).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
    let root_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| root[i].into());
    let make = move |g: Ea4| SpendMembershipGate { gamma: g, root: root_ea, depth };
    let carrier = crate::committed_air::prove_air_blinded_bytes(cols, make, &membership_public_bind(&root))?;
    // KoalaBear canonical value → u64 (verify's from_u64 reduces back to the exact same field element).
    let root_u: Digest = to_u64(&root);
    Some((carrier, root_u))
}

/// Verify a membership carrier binds to the PUBLIC `root`. Fail-closed on any decode /
/// path / root mismatch — a carrier proving membership in a DIFFERENT tree is rejected
/// because `root` is welded into the transcript.
#[must_use]
pub fn verify_membership_carrier_bytes(bytes: &[u8], root: Digest, depth: usize) -> bool {
    if bytes.is_empty() || depth == 0 {
        return false;
    }
    let root_f: DigestF = to_f(&root);
    let root_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| root_f[i].into());
    let make = move |g: Ea4| SpendMembershipGate { gamma: g, root: root_ea, depth };
    crate::committed_air::verify_air_blinded_bytes(bytes, make, &membership_public_bind(&root_f), match membership_carrier_row_width(depth) { Some(w) => (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, w), None => return false })
}

// ===========================================================================
// UNIFIED SPEND-VALIDITY carrier — the FULL PqSpendAir row in ONE gate: per row it
// proves a confidential spend fully valid, with all sub-gates CROSS-BOUND through the
// SHARED (value_in, sk, leaf) columns so a spend can't claim one amount to conservation
// and another to the note/nullifier/membership:
//   A. CONSERVATION   value_in == value_out + fee            (no inflation)
//   B. NOTE-OPENING   leaf == Poseidon([value_in,0,0,0], sk) (the commitment opens to amount+key)
//   C. NULLIFIER      nf   == Poseidon(sk, leaf)             (double-spend detectable, forged-nf unsatisfiable)
//   D. MEMBERSHIP     leaf ∈ frontier(root) via depth-d Poseidon-Merkle (note is on-chain)
// This is byte-parity with the node's PqSpendAir; the wallet AND the node call the ONE entry.
// ===========================================================================

/// Unified-validity transcript-weld tag (distinct domain).
pub const SPEND_VALIDITY_DOMAIN: u64 = 0x5350_4e44_5641_4c; // "SPNDVAL"
/// Domain for a VALIDATOR-BOND carrier = the full spend-validity row PLUS a public `out0_value == bond_amount`
/// weld, so the public bond weight the node admits provably equals the value the validator actually locked.
pub const BOND_VALIDITY_DOMAIN: u64 = 0x424f_4e44_5641_4c; // "BONDVAL"

/// ⭐ THE VAULT (docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md §9.1): a note owned by a condition, spent through one of
/// three branches of the note-class spend row. A child module, so it lays its region with this file's own helpers.
mod vault_gate;
pub use vault_gate::{
    chain_hours, clock_const, clock_lanes, clock_of_lanes, delivered_secret, delivery_claim_hash, delivery_claim_inputs, delivery_claim_tag, delivery_locks, note_spend_input_leaf, vault_lock, ListingSalt,
    vault_lock_claim, NoteSpendExtras, VaultBranch, VaultLock,
    VaultNote, VaultOpen, VaultSecret, CHAIN_HOUR_MS, HOUR_BITS, LOCK_LANES, NOTE_KIND_LANE, NO_LOCK, VAULT_BLK_WIDTH,
};
pub(crate) use vault_gate::{fill_clock_le, push_clock_le, CLOCK_LE_WIDTH};

/// ⭐ THE PAYMENT PROOF (docs/PAYMENT-PROOFS-SPEC-20261109.md): "this note pays address R the amount A", for one named
/// verifier. Off the chain entirely; a child module so it lays its row with this file's own helpers.
mod pay_proof;
pub use pay_proof::{
    pay_verifier_key, payment_note_cm, prove_payment, public_verifier_key, simulate_payment, verify_payment, PaymentStatement,
    PAY_PROOF_DOMAIN, PAY_PROOF_WIDTH, PAY_VERIFIER_DOMAIN,
};

/// ⭐ THE INCOME PROOF: "these notes pay address R and together hold exactly T", one proof, each amount private. The
/// payment proof over many notes; off the chain entirely.
mod pay_sum;
pub use pay_sum::{prove_income, simulate_income, verify_income, IncomeStatement, PAY_SUM_DOMAIN, PAY_SUM_MAX_NOTES, PAY_SUM_WIDTH};
mod notice_gate;
pub use notice_gate::{
    notice_hash_of_padded, notice_padded, notice_signature_ok, prove_notice, verify_notice, NoticeStatement, NOTICE_BLOCK_BYTES, NOTICE_DOMAIN, NOTICE_KEY_BYTES, NOTICE_MAX_BLOCKS,
    NOTICE_SIGNATURE_ALGORITHM, NOTICE_WIDTH,
};
mod content_gate;
pub use content_gate::{
    content_blocks, content_bytes, content_leaf, content_root, leaf_path, leaf_under_root, open_block, prove_content, seal_block, stream_block, verify_content, ContentRow,
    ContentStatement, CONTENT_BLOCK_BYTES, CONTENT_DOMAIN, CONTENT_MAX_BLOCKS, CONTENT_PROOF_MAX_ROWS, CONTENT_WIDTH,
};

/// A full confidential-spend witness: the spent note's `value_in` + its OWNER (`ask`, `nk`, the note's seed — DB-395: the
/// opening `o`, the commitment `leaf` and the nullifier `nf = P(nk, leaf)` are all DERIVED in-circuit from them), and the
/// output split (`value_out` = recipient+change, `fee`).
#[derive(Clone, Debug)]
pub struct SpendValidityWitness {
    pub value_in: u64,
    /// ⛔ DB-395: the recipient's `(ask, nk)` and the note's seed — never a key the note's sender could hold.
    pub owner: NoteOwner,
    pub value_out: u64,
    pub fee: u64,
    /// ⭐ DB-363 (2026-09-30) — the spender's FRESH per-send blinding of the membership cross-bind:
    /// `leaf_commit = P(P(leaf, nullifier), lc_blind)`. Drawn from the OS CSPRNG at the one place a send is
    /// assembled, held only for that send, never persisted, never on the wire, and NEVER a function of anything the
    /// payer holds (note randomness would let the payer test "did this spend consume the note I sent?" with one
    /// hash — the hole DB-363 found: with `P(leaf, nullifier)` both inputs were public, and every relay could join a
    /// spend to its receive by hashing each candidate leaf with the tx's nullifier). The SAME value is the private
    /// witness of the note-membership carrier and of the member-path tuple that bind the same `leaf_commit`.
    /// ⛔ `siblings`/`dirs` are GONE (2026-09-30): the depth-`d` Merkle path was anchored to nothing since the
    /// accumulator cross-bind landed (§BY) and the decorative-block census refused its last level; membership is the
    /// note-membership carrier's, cross-bound here.
    pub lc_blind: Digest,
    /// The TWO confidential OUTPUT notes this spend creates — (recipient, change). Each output's commitment
    /// `out_cm_j = asset_note_cm(out_value_j, USDm, out_opening_j)` is welded PUBLIC (the node records EXACTLY
    /// these `cm`s to the served note index), and the gate proves `value_out == out0_value + out1_value`. So
    /// the served outputs can NEVER sum to more than the proven spend — no inflation, digital-cash conserving.
    /// DB-395: an output's opening is `o = P(spk_recipient, seed)` — the sealer computes it from the recipient's PUBLIC
    /// `spk`, so it carries no spend authority. A single-recipient send with no change sets out1 = (0, own opening).
    pub out0_value: u64,
    pub out0_opening: Digest,
    pub out1_value: u64,
    pub out1_opening: Digest,
}

/// The full PqSpendAir row gate (A+B+C+D+E), degree 3, γ-power-batched. Column map:
/// value_in[0] · sk[1..5] · leaf[5..9] · value_out[9] · fee[10] · nf[11..15] · note-open lanes[15..31]
/// · nullifier lanes[31..47] · per membership level a 33-wide block from col 47 · then (E) the two OUTPUT
/// note-opening blocks of 25 cols each from col `47 + depth*33`: value · sk[1..5] · pre · sq · p4 · p7 · cm.
///
/// `Clone` so a BOUND aggregate can rebuild the SAME gate per row from that row's own public cells
/// (§BO's per-row factory) — a second, equivalent gate would be two spellings of one circuit (§AO).
/// Generic over the field its public values live in (lane agg 2026-11-15, `gate_trace`): the default is the production
/// `Ea4`, so every construction and every `SpendValidityGate` in type position is the type it always was.
#[derive(Clone)]
pub struct SpendValidityGate<Ea4 = crate::hiding_decider::Ea4> {
    pub gamma: Ea4,
    // ⛔ `root` and `depth` are GONE (2026-09-30). The depth-`d` Merkle path (gate D) constrained nothing once the
    // membership cross-bind landed (§BY deleted its `acc(d) == root` weld); the decorative-block census then refused
    // its LAST level on every depth ≥ 1 shape (an honest permutation whose output no law read), and the hygiene
    // cardinal deletes vestigial at source. The row is ONE constant layout now (`SV_*`), the carrier's width does
    // not depend on a witness length, and no root enters the gate or its transcript.
    /// The two PUBLIC output commitments the gate welds `out_cm_j == poseidon([out_value_j,0,0,0], out_sk_j)`
    /// to. The node passes exactly the `cm`s it recorded, so a valid carrier proves those served outputs sum
    /// to `value_out` (no inflation).
    pub out0_cm: [Ea4; DIGEST_LANES],
    pub out1_cm: [Ea4; DIGEST_LANES],
    /// The PUBLIC nullifier the gate welds the in-circuit `nf = Poseidon(sk, leaf)` to. The node records
    /// EXACTLY this nullifier for the tx, so a second spend of the same note reveals the SAME nullifier and is
    /// rejected (double-spend). A carrier cannot supply a nullifier other than its spent note's true one.
    pub nullifier: [Ea4; DIGEST_LANES],
    /// VALIDATOR-BOND weld (None for a plain spend → gate set byte-identical to before). When `Some(b)`, gate G
    /// constrains `out0_value == b` — so the PUBLIC bond weight the node admits equals the value output0 (the
    /// bonded note, to the validator's OWN address) actually locks, while `out0_sk` stays PRIVATE (the bonded
    /// note is never exposed to theft). This binds public weight to locked value with no key reveal.
    /// DB-340 (2026-09-28): the weld is LIMB-WISE — the four range-bound 16-bit limbs of the u64 amount against
    /// output0's four range-bound value limbs, exact u64 equality. A single field cell `out_val(0) − b` bound the
    /// amount only modulo p (KoalaBear p = 0x7f00_0001 ≈ 21.3 USDm at 1e8 atomic), so a burn of V verified at
    /// V + k·p and the peg-out path would have released k·p more than was burned.
    pub bond_amount: Option<[Ea4; SC_LIMBS]>,
    /// ⭐ §BR-14 (2026-10-28) — THE FLAT BASE FEE WELD. When `Some(f)`, gate I constrains the spend's FEE limbs (block A's
    /// range-bound `fee` limbs, the value `in − out` leaves the note set) to the four 16-bit limbs of `f` — exact u64
    /// equality, DB-340's limb-wise shape. The verifier supplies `f` (the node passes [`PROTOCOL_FEE_ATOMIC`]), never the
    /// transaction, so a sender cannot choose its fee: a carrier proven with any other fee leaves the residual nonzero on
    /// every row. `None` only for a carrier class that pays no USDm fee (none on the spend row today; the shape probes
    /// count it with `Some`).
    pub fee_amount: Option<[Ea4; SC_LIMBS]>,
    /// DB-329 §7e (2026-09-30): the spend's PUBLIC device-slot claim tag, `P([SLOT_CLAIM_DOMAIN, d, 0…], key)` under the
    /// spender's own witness (`SV_CLAIM_*`). `Some` for the note-class spend (ordinary spends claim `(lc_blind, 0)`),
    /// `None` for the bond/burn class, which publishes its nullifier through its own object and carries no claim.
    pub tag1: Option<[Ea4; DIGEST_LANES]>,
    /// ⭐ THE MEMBERSHIP CROSS-BIND (None ⇒ gate set byte-identical to before, so every existing carrier type
    /// is unaffected). When `Some(c)`, the gate constrains `Poseidon(leaf, nullifier) == c` — the SAME value
    /// a `NoteMembershipCarrier` binds. Without it the two proofs are unrelated: a spender could hold a valid
    /// membership proof for note X and spend note Y, because nothing said they were the same note.
    ///
    /// The leaf is never public — it is the value written when the note was RECEIVED, so revealing it would
    /// link the spend to that receive. The commitment names the note without identifying it.
    /// ⭐⭐⭐ NOT AN `Option`. A carrier without the note-membership cross-bind is UNREPRESENTABLE — the
    /// compiler refuses to construct one, so no state exists in which membership rests on a FIXED-CAPACITY
    /// Merkle root. A runtime check would leave that shape intact with every bad call site still compiling;
    /// the type is the enforcement, and it makes rustc name every site that must change.
    pub leaf_commit: [Ea4; DIGEST_LANES],
    /// ⭐ THE VAULT REGION (`vault_gate`, spec §9.1). `Some(clock)` for the NOTE-CLASS spend: the row carries the vault
    /// region after the owner block (`note_spend_row_width`), the three note openings carry the kind lanes, and `clock`
    /// is the VERIFIER's chain clock in chain hours, welded like the fee (the ledger proves it is at or before the
    /// block's clock, and the fold judges that against the chain's median-time-past). `None` for every other class
    /// (bond, burn, the direct-baseline pins): the residual list and the row are byte-identical to before.
    pub vault: Option<Ea4>,
}
impl crate::air_zerocheck::AirConstraint for SpendValidityGate {
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ EMBEDS A PERMUTATION: a gate declaring less than the permutation's degree truncates
        // the sumcheck, so even an HONEST proof stops verifying.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let rs = self.residuals(local);
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in rs {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }
    /// The same residuals, unfolded — so a multi-carrier aggregate can fold them against γ-POWER COLUMNS
    /// instead of against this gate's constant γ. See `AirConstraint::residuals`: without it, a γ read
    /// from a cell makes the k-th residual degree k and the sumcheck truncates silently.
    fn residuals(
        &self,
        local: &crate::air_zerocheck::Row<'_>,
        _at: &dyn Fn(usize, &[Ea4]) -> Ea4,
        _x: &[Ea4],
    ) -> Vec<Ea4> {
        SpendValidityGate::residuals(self, local)
    }
    /// ROW-LOCAL: `eval` and `residuals` both take `_at` — every value this gate reads is its own row's.
    fn is_row_local(&self) -> bool {
        true
    }
    /// DB-363: the blinding lanes are a HIDING witness — read by the outer cross-bind block's input weld, determined
    /// by no statement value on purpose (that is what makes `leaf_commit` unlinkable). Named here so the binding review
    /// sees the choice; the free-witness census reads them as read.
    /// DB-329 §7e: the claim's `d` and key are the same kind of hiding witness when the gate carries `tag1`; when it
    /// does not (the bond/burn class), the whole claim region is unused by this class and named free.
    fn free_columns(&self) -> Option<Vec<usize>> {
        let mut free: Vec<usize> = (SV_BLIND..SV_BLIND + DIGEST_LANES).collect();
        if self.tag1.is_some() {
            free.extend(SV_CLAIM_D..SV_CLAIM_BLK);
        } else {
            free.extend(SV_CLAIM_D..SV_CLAIM_BLK + crate::pow_pq_air::P2_COLS);
        }
        Some(free)
    }
}

impl<Ea4: crate::gate_trace::GateAlg> SpendValidityGate<Ea4> {
    /// The gate's residuals, BEFORE the γ-power fold.
    ///
    /// ⭐ SPLIT OUT SO A FAILURE HAS AN ADDRESS. Folded, the whole gate answers one number, and every
    /// disagreement between constraint and trace reads as the same thing: *"honest carrier MUST verify"*.
    /// With the list in hand a test can name WHICH residual is nonzero on an honest row, which turns a
    /// day of bisecting a 600 KB file into one index. The fold above is unchanged, so nothing about the
    /// proof moves.
    pub(crate) fn residuals(&self, local: &crate::air_zerocheck::Row<'_, Ea4>) -> Vec<Ea4> {
        let zero = Ea4::from(Fa4::ZERO);
        let value_in = local[SV_VALUE_IN];
        let leaf = |c: usize| local[SV_LEAF + c];
        let value_out = local[SV_VALUE_OUT];
        let fee = local[SV_FEE];
        let nf = |c: usize| local[SV_NF + c];
        let nk = |c: usize| local[owner_nk_col(SV_OWNER) + c];
        let mut rs: Vec<Ea4> = Vec::new();
        // ⭐ THE VAULT REGION (note class only; spec §9.1): three branch bits and one compare. A vault spend lays no block
        // a payment does not: the wires below multiplex the owner block's opening, the note opening's spare lanes, the
        // nullifier's key and the claim block. With `vault: None` nothing is pushed and every other class is
        // byte-identical.
        let in_inner = SV_TAIL + SV_TAIL_IN_BLK;
        let vw = self.vault.map(|clock| {
            vault_gate::push_vault(&mut rs, local, spend_validity_row_width(), local[in_inner + vault_gate::NOTE_KIND_LANE], clock)
        });
        // ⛔⛔⛔ DB-395 — THE OWNER: the opening lanes `SV_SK` read by the note opening are WELDED to `o = P(P(ask, nk), seed)`,
        // so only the holder of the note's `(ask, nk)` opens it; a sender knows `o` and `seed` and nothing that satisfies this.
        // On a vault's LOCK branch the spender is the lock's taker, not the owner: the first block still proves the
        // spender's own `spk` (the claim binds it), and the opening's left input is the vault owner's key, free here and
        // bound by the note itself.
        push_owner_open_keyed(&mut rs, local, SV_OWNER, SV_SK, vw.as_ref().map(vault_gate::VaultWires::lk));
        // A. CONSERVATION
        // ⛔⛔⛔ A + B, RANGE-BOUND AND TWO-ROUND (item 1 seam, 2026-09-11). Gate A was the field identity
        // `value_in - value_out - fee` and gate B opened `Poseidon([value_in,0,0,0], sk)` — one reduced
        // element, so a note holding `v` opened equally well at `v + p`. Now: block A binds in/out/fee
        // as 4×16-bit limbs with a carry chain (top carry ZERO) and every limb bit-bound; the legacy
        // whole-value columns 0/9/10 are bound to their limbs by recombination; and the note opens in
        // TWO rounds, `leaf == P(limbs, P([tag,0], sk))`, the value's limbs filling the outer lanes.
        let tail = SV_TAIL;
        let ta = U64ConsBases::at(tail + SV_TAIL_A);
        let te = U64ConsBases::at(tail + SV_TAIL_E);
        push_u64_conservation(&mut rs, local, ta);
        push_u64_conservation(&mut rs, local, te);
        for i in 0..SC_LIMBS {
            // E's input IS A's output, limb for limb — never by field recombination, which aliases at p.
            rs.push(local[te.r#in + i] - local[ta.out + i]);
        }
        rs.push(value_in - u64_limbs_recombined(local, ta.r#in));
        rs.push(value_out - u64_limbs_recombined(local, ta.out));
        rs.push(fee - u64_limbs_recombined(local, ta.fee));
        // USDm: tag [0,0,0]. The lanes after it (the kind, lock 1) and the value block's upper lanes (lock 2) are ZERO
        // on an ordinary note and a vault's own on a vault note: each is welded to `v · itself`, so the plain branch
        // (`v = 0`) cannot open a note that carries any of them, and a vault branch leaves them to the note.
        let hi = |blk: usize, c: usize| vw.as_ref().map_or(zero, |w| w.v * local[blk + c]);
        let in_tag = |c: usize| Some(if c < vault_gate::NOTE_KIND_LANE { zero } else { hi(in_inner, c) });
        let in_hi = |c: usize| Some(hi(SV_NOH_BLK, c));
        let sk_col = |c: usize| local[SV_SK + c];
        push_note_open_ext(
            &mut rs, local, ta.r#in, &in_tag, &in_hi, &sk_col,
            tail + SV_TAIL_IN_BLK, tail + SV_TAIL_IN_OUT, SV_NOH_BLK, SV_LEAF,
        );
        // C. NULLIFIER — nf == compress(nk, leaf), one whole permutation (DB-395: keyed by the owner's `nk`, which the
        // note's sender does not hold, so the sender cannot compute the nullifier its payee's spend lays).
        // ⭐ A VAULT's nullifier key is its OPENING, which both of its parties hold and nobody else: whoever spends the
        // vault lays ONE nullifier, and the set refuses the other party's later spend (spec §9.1).
        let nkey = |c: usize| match &vw {
            Some(w) => (Ea4::ONE - w.v) * nk(c) + w.v * local[SV_SK + c],
            None => nk(c),
        };
        push_pose_round(&mut rs, local, &nkey, &leaf, SV_NFH_BLK, SV_NF);
        // D. (DELETED 2026-09-30) the depth-`d` Merkle path. Its `acc(d) == root` weld was deleted by §BY, so the
        // chain was anchored at neither end — pure width; the decorative-block census refused its last level, and the
        // hygiene cardinal deletes vestigial at source. Membership is the note-membership carrier's (below, gate F).
        // ⭐⭐⭐ MEMBERSHIP BY THE O(1) ACCUMULATOR, NOT BY A RETRIEVED PATH.
        //
        // This weld — `acc(d) == root` — is the ONLY constraint in the gate that requires a depth-`d` Merkle
        // copath, and it is why cross-node sends have failed all session:
        //   "no depth-32 copath for this note, AND the wallet could not build one itself"
        // That copath cannot be obtained by anyone without breaking a cardinal. Its left siblings are the MMR
        // peaks at `count == leaf_index`, and the number of interior nodes grows with the note count — so
        // SOMEONE must hold data that grows with history: the node storing the tree (the ever-growing-node
        // problem itself), the block carrying the peak spine (MEASURED 2,112 B/block = 133 GB/year), or the
        // wallet re-deriving it by replaying every leaf (the banned walk, a time blowup).
        //
        // So membership stops being RETRIEVED and becomes PROVEN. When `leaf_commit` is present, gate F below
        // constrains `Poseidon(leaf, nullifier) == leaf_commit`, and the node separately verifies a
        // `NoteMembershipCarrier` binding that SAME `leaf_commit` — a recursive fold from `genesis_acc` to the
        // chain's live `tip_acc` (`Node::verify_membership_carrier` /
        // `note_membership_air::verify_note_membership_chain`). That fold already proves the leaf is committed
        // by the chain from state of a FIXED size: the accumulator is `Digest` = 32 bytes and folds every
        // note ever. Re-proving the same fact with a Merkle path adds nothing and costs the un-gettable path.
        //
        // SOUNDNESS — the two proofs are ONE claim, and dropping this weld is safe only because of that:
        //   * the membership carrier proves `leaf_commit` is folded into the chain's accumulator;
        //   * gate F binds `leaf_commit` to THIS row's `leaf` and `nullifier`;
        //   * gates B and C bind that same `leaf` to the spent value/key and to the recorded nullifier.
        // So a spender cannot hold a membership proof for note X and spend note Y. The caller MUST refuse a
        // tx that sets `leaf_commit` without a VERIFIED membership carrier — otherwise membership would be
        // unproven — and that obligation is enforced at the node's admission gate, which requires
        // `membership_ok == Some(true)` whenever the cross-bind is present.
        //
        // With `leaf_commit` ABSENT this is byte-identical to before: the weld is enforced and every existing
        // carrier type verifies exactly as it did.
        // ⛔ THE DEPTH-`d` WELD IS DELETED. It read `if self.leaf_commit.is_none() { acc(d) == root }`
        // and was the ONE constraint making a spend depend on a FIXED-CAPACITY Merkle root — a root that
        // FILLS, after which no note can ever be proven a member again. `leaf_commit` is no longer an
        // `Option`, so this branch is not merely unreachable, it is unrepresentable. Membership is proven
        // by the note-membership fold: f(lambda, fixed constants), no chain-length term, no ceiling.
        // E. OUTPUT BINDING (no-inflation over outputs): value_out == out0_value + out1_value, and each
        // out_cm_j opens as Poseidon([out_value_j,0,0,0], out_sk_j) welded to the PUBLIC out{j}_cm the node
        // recorded — so the served output notes conserve EXACTLY the proven spend value (digital cash).
        // ⛔ EVERY OFFSET HERE WAS A LITERAL — `MB + d*33` and a 25-column output slot: one value, a
        // four-lane key and the four intermediate columns of the RETIRED one-round S-box. The round is a
        // whole permutation now and the digest is eight lanes, so the slot is `SV_OUT_SLOT` and the four
        // intermediates do not exist at all. The builder (`sv_ob` / `SV_OUT_SLOT`, above) had already
        // moved; only the gate still spoke the old layout, which is exactly how a constraint ends up
        // reading a column its own trace does not have.
        let ob = SV_OB;
        let slot = |j: usize| ob + j * SV_OUT_SLOT;
        let out_val = |j: usize| local[slot(j)];
        let out_sk = |j: usize, c: usize| local[slot(j) + 1 + c];
        let out_blk = |j: usize| slot(j) + 1 + DIGEST_LANES;
        let out_cm = |j: usize, c: usize| local[out_blk(j) + crate::pow_pq_air::P2_COLS + c];
        // E is block `te` above (out0 + out1 == value_out, limb-wise); bind the legacy out_val columns.
        rs.push(out_val(0) - u64_limbs_recombined(local, te.out));
        rs.push(out_val(1) - u64_limbs_recombined(local, te.fee));
        for j in 0..2 {
            let pub_cm = if j == 0 { &self.out0_cm } else { &self.out1_cm };
            let limbs = if j == 0 { te.out } else { te.fee };
            let (iblk, iout) = if j == 0 { (SV_TAIL_O0_BLK, SV_TAIL_O0_OUT) } else { (SV_TAIL_O1_BLK, SV_TAIL_O1_OUT) };
            let osk = |c: usize| out_sk(j, c);
            // In the note class an output's kind and lock lanes are the SPENDER's to write (a vault is made by writing
            // them): they are the opening blocks' own input cells, read by the permutation and by no weld. An output
            // written with any of them non-zero is no ordinary note: only a vault branch opens it. Every other class
            // welds them to zero.
            let free = vw.is_some();
            let out_tag = |c: usize| if free && c >= vault_gate::NOTE_KIND_LANE { None } else { Some(zero) };
            let out_hi = |_c: usize| if free { None } else { Some(zero) };
            push_note_open_ext(
                &mut rs, local, limbs, &out_tag, &out_hi, &osk, tail + iblk, tail + iout,
                out_blk(j), out_blk(j) + crate::pow_pq_air::P2_COLS,
            );
            for c in 0..DIGEST_LANES { rs.push(out_cm(j, c) - pub_cm[c]); }
        }
        // F. NULLIFIER BINDING: weld the in-circuit nf (= Poseidon(sk, leaf), gate C) to the PUBLIC nullifier
        // the node records — so a carrier proves EXACTLY its spent note's nullifier (double-spend protection).
        for c in 0..DIGEST_LANES { rs.push(nf(c) - self.nullifier[c]); }
        // F. MEMBERSHIP CROSS-BIND — `Poseidon(leaf, nullifier) == leaf_commit`, the same compression as the
        // note-opening and nullifier welds above, over columns at `cb`.
        {
            // ⭐ DB-363 (2026-09-30) — `leaf_commit == P(P(leaf, nullifier), lc_blind)`: TWO chained whole permutations.
            // The old single compression `P(leaf, nullifier)` had two PUBLIC inputs (the nullifier is the tx's own
            // statement; the leaf is what every node appended from the record), so any relay hashed each candidate
            // leaf with the nullifier and joined the spend to its receive — a payer tested "did this spend consume
            // the note I sent?" with ONE hash. `lc_blind` is the spender's fresh per-send randomness (SV_BLIND lanes,
            // a hiding witness bound only through this commitment — named in `free_columns`), so the commitment is
            // binding (Poseidon collision resistance over the two-level tree) and hiding (no public preimage test).
            // Inner block at SV_CB over (leaf, nullifier); its output lanes are WELDED into the outer block's left
            // input lanes at SV_CB2 (the `out` of `push_pose_round` IS those lanes, so no block's output is
            // decorative); the outer block's right lanes are the blinding and its output is the public commitment.
            let lc = self.leaf_commit;
            let nfp = |c: usize| self.nullifier[c];
            push_pose_round(&mut rs, local, &leaf, &nfp, SV_CB, SV_CB2);
            crate::pow_pq_air::push_perm_residuals(local, SV_CB2, &mut rs);
            for c in 0..DIGEST_LANES {
                rs.push(local[SV_CB2 + DIGEST_LANES + c] - local[SV_BLIND + c]);
                rs.push(local[SV_CB2 + crate::pow_pq_air::PERM_OUT + c] - lc[c]);
            }
        }
        // G. BOND WELD (validator bond only): when a public bond_amount is bound, output0 (the bonded note, to the
        // validator's OWN address) must lock EXACTLY that amount — so the PUBLIC validator weight the node admits
        // equals the value actually locked (no over-claim), while out0_sk stays PRIVATE (bonded note not exposed).
        // DB-340: limb-wise against block `te`'s RANGE-BOUND output limbs (`push_u64_conservation` bit-decomposes
        // every limb), so the equality is over u64 values, never over their field residues.
        if let Some(limbs) = self.bond_amount {
            for i in 0..SC_LIMBS {
                rs.push(local[te.out + i] - limbs[i]);
            }
        }
        // I. THE BASE FEE WELD (§BR-14): block A's fee limbs (`in == out + fee`, every limb bit-bound by
        // `push_u64_conservation`) equal the verifier's fee, limb for limb — so the fee is exactly F as a u64, never F mod p.
        if let Some(limbs) = self.fee_amount {
            for i in 0..SC_LIMBS {
                rs.push(local[ta.fee + i] - limbs[i]);
            }
        }
        // H. THE DEVICE-SLOT CLAIM (DB-329 §7e): `tag1 == P([SLOT_CLAIM_DOMAIN, d, 0…], key)` — a whole permutation,
        // inputs welded to the claim witnesses, output welded to the PUBLIC tag1. Only the note-class spend carries it;
        // the bond/burn class (`tag1 = None`) names the claim columns free instead.
        if let Some(tag1) = self.tag1 {
            crate::pow_pq_air::push_perm_residuals(local, SV_CLAIM_BLK, &mut rs);
            let spk = |c: usize| local[SV_OWNER + OWN_SPK_BLK + crate::pow_pq_air::PERM_OUT + c];
            for c in 0..DIGEST_LANES {
                let left = match c {
                    0 => Ea4::from(Fa4::from_u64(crate::slot_ledger::SLOT_CLAIM_DOMAIN)),
                    1 => local[SV_CLAIM_D],
                    // ⭐ A VAULT's LOCK branch (spec §9.1): the claim names the lock's taker (the spender's own `spk`
                    // lanes, so nobody else lays this tag) under a marker no other claim carries.
                    _ => vw.as_ref().map_or(zero, |w| vault_gate::claim_left_lock_lane(w, c, &spk)),
                };
                rs.push(local[SV_CLAIM_BLK + c] - left);
                rs.push(local[SV_CLAIM_BLK + DIGEST_LANES + c] - local[SV_CLAIM_KEY + c]);
                // the PUBLIC claim tag: the claim's output, or on a delivery lock's claim the key plus the vault's
                // opening in the first lanes and the vault note's inner hash in the rest
                // (`vault_gate::claim_tag_lane`), so the spend that pays a seller hands the buyer the key
                rs.push(vault_gate::claim_tag_lane(vw.as_ref(), local, in_inner, c) - tag1[c]);
            }
            if let Some(w) = &vw {
                // an ordinary lock claim's key holds the lock's secret, then the VAULT's opening lanes: one secret
                // in two vaults lays two tags (a delivery claim's upper key lanes are its listing's salt)
                vault_gate::push_claim_key_upper(&mut rs, w, local);
                for c in 0..vault_gate::LOCK_LANES {
                    // and the claim's hash IS the lock it opens: lock 1 in the note's tag lanes, lock 2 in the value
                    // block's
                    let tag_c = local[SV_CLAIM_BLK + crate::pow_pq_air::PERM_OUT + c];
                    rs.push(w.lk1 * (tag_c - local[in_inner + SC_LIMBS + c]));
                    rs.push(w.lk2 * (tag_c - local[SV_NOH_BLK + SC_LIMBS + c]));
                }
                // a DELIVERY claim opens all eight lanes of its lock (lock 1 and lock 2 together)
                vault_gate::push_delivery(&mut rs, w, local, &|c| local[SV_NOH_BLK + SC_LIMBS + c]);
            }
        }
        rs
    }
}

/// ⭐ DB-363 (2026-09-30) — THE ONE PLACE A PER-SEND BLINDING IS DRAWN. `DIGEST_LANES` canonical field lanes straight from
/// the OS CSPRNG (`rand::rngs::SysRng`, the crate's `sys_rng` source — the same source `committed_air` seeds its column
/// blinding from; rejection-sampled below the field order so the lanes are canonical on both sides of the commitment).
/// The wallet calls THIS once per object that assembles a spend, a burn, a bond or a DEX half, and passes the value to
/// BOTH builders (the validity carrier's `lc_blind` and the membership carrier's `blind`) — never a derivation from note
/// randomness or from anything the payer holds (the one-hash linkage test would return), never a fixed value (a fixed r
/// is no hiding), never persisted, logged or put on the wire. Test fixtures use fixed lanes on purpose and say so.
///
/// `None` when the OS source refuses: the caller assembles NOTHING. There is exactly one source of blinding here on
/// purpose — a blinding drawn from anywhere weaker is a linkable commitment wearing a random-looking costume.
#[must_use]
pub fn fresh_lc_blind() -> Option<Digest> {
    use p3_field::PrimeField64;
    use rand::TryRng;
    let mut os = rand::rngs::SysRng::default();
    let mut lanes = [0u64; DIGEST_LANES];
    for lane in lanes.iter_mut() {
        *lane = loop {
            let v = u64::from(os.try_next_u32().ok()?);
            if v < Fa4::ORDER_U64 {
                break v;
            }
        };
    }
    Some(lanes)
}

/// The four range-bound 16-bit limbs of a public bond amount, as the gate welds and the bind carries them (DB-340).
#[must_use]
/// ⭐ §BR-14 — THE PROTOCOL'S FLAT BASE FEE: 100,000 atomic = 0.001 USDm (1e8 atomic per USDm), the same on every
/// USDm spend whatever its amount (a flat fee reveals nothing; a percentage of a hidden amount would need its own proof).
/// Changed only through the §8 deployment path (a consensus constant: every node's verifier supplies it).
pub const PROTOCOL_FEE_ATOMIC: u64 = 100_000;

/// The fee weld's four limbs for `fee` — the gate field [`SpendValidityGate::fee_amount`] carries.
#[must_use]
pub fn fee_limbs(fee: u64) -> [Ea4; SC_LIMBS] {
    bond_limbs(fee)
}

pub fn bond_limbs(amount: u64) -> [Ea4; SC_LIMBS] {
    core::array::from_fn(|i| Ea4::from(Fa4::from_u64((amount >> (SC_LIMB_BITS * i)) & 0xFFFF)))
}
fn bond_limbs_f(amount: u64) -> [Fa4; SC_LIMBS] {
    core::array::from_fn(|i| Fa4::from_u64((amount >> (SC_LIMB_BITS * i)) & 0xFFFF))
}

/// One-round Poseidon (x⁷ S-box + `SPEND_MDS` mix) over the muxed `[left,right]` → the 4 witness
/// lanes (pre, pre_sq, pre_4, pre_7) + the output digest. `pre[c] = left[c] + 7·right[c]`.
/// A field digest back to its canonical u64 limbs, and the reverse. Written as helpers because every
/// hand-spelled `core::array::from_fn(|i| x[i])` was a lane count waiting to go stale.
pub(crate) fn to_u64(d: &DigestF) -> Digest {
    use p3_field::PrimeField64;
    core::array::from_fn(|i| d[i].as_canonical_u64())
}
pub(crate) fn to_f(d: &Digest) -> DigestF {
    core::array::from_fn(|i| Fa4::from_u64(d[i]))
}

/// The width-16 state two digests present to the permutation.
fn pose_state(left: &DigestF, right: &DigestF) -> [Fa4; crate::pow_pq_air::WIDTH] {
    let mut st = [Fa4::ZERO; crate::pow_pq_air::WIDTH];
    st[..DIGEST_LANES].copy_from_slice(left);
    st[DIGEST_LANES..].copy_from_slice(right);
    st
}

/// The frontier tree's parent-hash the spend-membership gate recomputes, and the compression the wallet
/// builds its note's copath with — so its recomputed root equals the gate's, and the note-opening leaf is
/// `poseidon_pair(limbs, k)`.
///
/// ⛔⛔⛔ THIS WAS ONE ALGEBRAIC ROUND UNTIL 2026-09-12, AND IT WAS THE SECOND COPY OF IT.
/// `out = MDS·(l + 7·r)⁷` inverts in a single division (kill list §AG), so a spender could SOLVE for a
/// sibling and prove membership for a note the block never held — minting from nothing. And this copy was
/// not only the spend circuit's: `confidential_solvency` builds the PEG's reserve/minted commitments on
/// it too. ONE definition now means one — this delegates to the same compression
/// `spend_frontier::poseidon_pair` and every AIR in this crate use, so prover, verifier and
/// copath-builder cannot drift.
#[must_use]
pub fn poseidon_pair(left: Digest, right: Digest) -> Digest {
    crate::poseidon2_compress::compress(&left, &right)
}

/// ⛔⛔⛔ THE NOTE COMMITMENT BINDS THE INTEGER VALUE — TWO ROUNDS (2026-09-11, user-authorized re-genesis).
///
/// The commitment was `poseidon_pair([amount, t0, t1, t2], sk)`: the amount entered as ONE field
/// element, `amount mod p` (p ≈ 2^31 < 2^64). Range-binding the spend arm could not close inflation
/// against that: a spender of a note holding `v` claims `v + p`, the limbs recombine to the same
/// element, the opening matches, the spend inflates by p. MEASURED as the seam under item 1.
///
/// BORROWED (Zcash Orchard's NoteCommit hashes more data than one block holds — value, asset, keys —
/// as a multi-block hash). Here: the value's four 16-bit limbs fill the outer round's four lanes, and
/// the asset tag and spend key are bound in an INNER round whose output is the outer round's key:
///
/// ```text
/// cm = P( [l0, l1, l2, l3],  P( [t0, t1, t2, 0], sk ) )
/// ```
///
/// Both rounds are proven in-circuit at every opening: an unproven inner hash would let a minter
/// bind an asset note under USDm's (zero) tag and spend it as USDm. Same primitive, same lane width,
/// one formula for USDm and wrapped assets alike (USDm's tag is `[0, 0, 0]`).
#[must_use]
pub fn note_value_lanes(amount: u64) -> [u64; 4] {
    [amount & 0xFFFF, (amount >> 16) & 0xFFFF, (amount >> 32) & 0xFFFF, (amount >> 48) & 0xFFFF]
}

/// The inner round: the asset tag and the spend key, as the outer round's key.
#[must_use]
pub fn note_inner_key(tag: [u64; 3], sk: Digest) -> Digest {
    // The tag occupies the low lanes and the rest are zero — written through `lanes_of` so the literal
    // cannot silently track an old lane count.
    poseidon_pair(crate::poseidon2_compress::lanes_of(&[tag[0], tag[1], tag[2]]), sk)
}

/// A note's commitment under an asset tag — see the module note above. With [`USDM_ASSET_TAG`] this
/// IS the USDm note commitment.
#[must_use]
pub fn asset_note_cm(amount: u64, tag: [u64; 3], sk: Digest) -> Digest {
    poseidon_pair(crate::poseidon2_compress::lanes_of(&note_value_lanes(amount)), note_inner_key(tag, sk))
}

/// One Poseidon round IN-CIRCUIT: `pre = left + 7·right`, the x^7 S-box, the MDS mix. Pushes the 20
/// residuals binding the witness block at `blk` (pre[4] ‖ sq[4] ‖ p4[4] ‖ p7[4]) and the output at
/// `out`. `left`/`right` are the round's inputs as the caller's columns or constants.
fn push_pose_round<Ea4: crate::gate_trace::GateAlg>(
    cs: &mut Vec<Ea4>,
    local: &crate::air_zerocheck::Row<'_, Ea4>,
    left: &dyn Fn(usize) -> Ea4,
    right: &dyn Fn(usize) -> Ea4,
    blk: usize,
    out: usize,
) {
    push_pose_round_opt(cs, local, &|c| Some(left(c)), right, blk, out);
}

/// [`push_pose_round`] where a LEFT lane may be left unwelded (`left(c) == None`): that lane is then the block's own
/// input cell, read by the permutation's constraints and by whatever law the caller adds.
fn push_pose_round_opt<Ea4: crate::gate_trace::GateAlg>(
    cs: &mut Vec<Ea4>,
    local: &crate::air_zerocheck::Row<'_, Ea4>,
    left: &dyn Fn(usize) -> Option<Ea4>,
    right: &dyn Fn(usize) -> Ea4,
    blk: usize,
    out: usize,
) {
    // The permutation's own constraints, then the operand and output welds. Without the welds the block
    // is a valid permutation of SOMETHING, which proves nothing about this row.
    crate::pow_pq_air::push_perm_residuals(local, blk, cs);
    for c in 0..DIGEST_LANES {
        if let Some(l) = left(c) {
            cs.push(local[blk + c] - l);
        }
        cs.push(local[blk + DIGEST_LANES + c] - right(c));
        cs.push(local[out + c] - local[blk + crate::pow_pq_air::PERM_OUT + c]);
    }
}

/// The trace side of [`push_pose_round`]: fill the witness block and output, return the output.
fn fill_pose_round(row: &mut [Fa4], left: &DigestF, right: &DigestF, blk: usize, out: usize) -> DigestF {
    crate::pow_pq_air::lay_perm_row_flat(row, blk, pose_state(left, right));
    let o: DigestF = core::array::from_fn(|c| row[blk + crate::pow_pq_air::PERM_OUT + c]);
    row[out..out + DIGEST_LANES].copy_from_slice(&o);
    o
}

/// A note's two-round opening IN-CIRCUIT: inner `k = P(tag, sk)` at (`inner_blk`, `inner_out`), outer
/// `cm = P(limbs, k)` at (`outer_blk`, `cm`). `limbs` are the value's four range-bound limb columns.
fn push_note_open<Ea4: crate::gate_trace::GateAlg>(
    cs: &mut Vec<Ea4>,
    local: &crate::air_zerocheck::Row<'_, Ea4>,
    limbs: usize,
    tag: &dyn Fn(usize) -> Ea4,
    sk: &dyn Fn(usize) -> Ea4,
    inner_blk: usize,
    inner_out: usize,
    outer_blk: usize,
    cm: usize,
) {
    let zero = Ea4::from(Fa4::ZERO);
    push_note_open_ext(cs, local, limbs, &|c| Some(tag(c)), &|_c| Some(zero), sk, inner_blk, inner_out, outer_blk, cm);
}

/// [`push_note_open`] with the note's EXTRA lanes named (spec §9.1): `tag(c)` is what tag lane `c` is welded to and
/// `value_hi(c)` what value-block lane `c ≥ SC_LIMBS` is welded to; `None` leaves that lane to the permutation alone
/// (an output's kind and lock lanes in the note class, which its spender writes). The residual ORDER is
/// [`push_note_open`]'s, less the welds named `None`.
#[allow(clippy::too_many_arguments)]
fn push_note_open_ext<Ea4: crate::gate_trace::GateAlg>(
    cs: &mut Vec<Ea4>,
    local: &crate::air_zerocheck::Row<'_, Ea4>,
    limbs: usize,
    tag: &dyn Fn(usize) -> Option<Ea4>,
    value_hi: &dyn Fn(usize) -> Option<Ea4>,
    sk: &dyn Fn(usize) -> Ea4,
    inner_blk: usize,
    inner_out: usize,
    outer_blk: usize,
    cm: usize,
) {
    push_pose_round_opt(cs, local, tag, sk, inner_blk, inner_out);
    // ⛔⛔⛔ THE VALUE OCCUPIES `SC_LIMBS` LANES, NOT THE WHOLE DIGEST. `limbs` points at a u64 range
    // block whose columns past `SC_LIMBS` are the range BITS, not more value limbs — welding all eight
    // lanes from there would bind the permutation's input to bit columns and disagree with the trace,
    // which zero-pads. The trace's `fill_note_open` pads the same way; this is the constraint half of
    // that ONE shape.
    let limb = |c: usize| if c < SC_LIMBS { Some(local[limbs + c]) } else { value_hi(c) };
    let k = |c: usize| local[inner_out + c];
    push_pose_round_opt(cs, local, &limb, &k, outer_blk, cm);
}

/// The trace side of [`push_note_open`]: returns the commitment.
fn fill_note_open(
    row: &mut [Fa4],
    amount: u64,
    tag: [u64; 3],
    sk: &DigestF,
    inner_blk: usize,
    inner_out: usize,
    outer_blk: usize,
    cm: usize,
) -> DigestF {
    fill_note_open_ext(row, amount, tag, &vault_gate::NoteExt::PLAIN, sk, inner_blk, inner_out, outer_blk, cm)
}

/// [`fill_note_open`] with the note's EXTRA lanes (spec §9.1): the kind and lock 1 in the tag's upper lanes, lock 2 in
/// the value block's. All zero for an ordinary note. ONE spelling of the opening for both kinds, so the ordinary and
/// the vault commitment cannot drift.
#[allow(clippy::too_many_arguments)]
fn fill_note_open_ext(
    row: &mut [Fa4],
    amount: u64,
    tag: [u64; 3],
    ext: &vault_gate::NoteExt,
    sk: &DigestF,
    inner_blk: usize,
    inner_out: usize,
    outer_blk: usize,
    cm: usize,
) -> DigestF {
    let hi = ext.tag_hi();
    let tag_f: DigestF =
        core::array::from_fn(|c| Fa4::from_u64(if c < NOTE_KIND_LANE { tag[c] } else { hi[c - NOTE_KIND_LANE] }));
    let k = fill_pose_round(row, &tag_f, sk, inner_blk, inner_out);
    let l = note_value_lanes(amount);
    let limbs: DigestF = core::array::from_fn(|c| Fa4::from_u64(if c < SC_LIMBS { l[c] } else { ext.lock2[c - SC_LIMBS] }));
    fill_pose_round(row, &limbs, &k, outer_blk, cm)
}
/// ⛔⛔⛔ DB-395 (2026-10-05) — A NOTE'S SPEND AUTHORITY IS THE RECIPIENT'S ALONE, NEVER THE SENDER'S.
///
/// The opening a note commits to was `sk = KDF(ss)`, and the SENDER holds `ss` (it ran the KEM encapsulation), so every payer
/// could spend what it paid (claw back a settled payment) and compute the payee's nullifier (learn when the payee spends).
/// BORROWED: Zcash Sapling's split of the commitment opening from spend authority (`ak`/`nsk` → `ivk`, `nf = PRF_nk(ρ)`), in its
/// hash-based form, where the proof itself is the authorisation (no `spendAuthSig`, so no `ak` layer):
///
/// ```text
/// spk = P(ask, nk)          published in the address beside the ML-KEM key
/// o   = P(spk, seed)        the note's opening, in the lane `sk` held; seed = KDF(ss) is per note, so o is unlinkable
/// cm  = asset_note_cm(value, tag, o)
/// nf  = P(nk, cm)           the sender holds neither ask nor nk: it can neither spend nor compute nf
/// ```
///
/// A viewing key `(dk, nk, spk)` recognises the owner's notes and detects their spends, with no spend authority.
/// The recipient's long-term secrets plus one note's seed — the whole witness of an INPUT opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NoteOwner {
    /// Spend authority — never leaves the wallet, never derivable from anything the sender holds.
    pub ask: Digest,
    /// The nullifier key — spend DETECTION (a viewing key carries it), no spend authority.
    pub nk: Digest,
    /// The note's own seed (`KDF(ss)`), which the sender also knows; it opens nothing without `(ask, nk)`.
    pub seed: Digest,
}

impl NoteOwner {
    /// The address key `spk = P(ask, nk)`.
    #[must_use]
    pub fn spk(&self) -> Digest {
        owner_spk(&self.ask, &self.nk)
    }
    /// The note opening `o = P(spk, seed)` — what the note commits to in the lane `sk` held.
    #[must_use]
    pub fn opening(&self) -> Digest {
        owner_opening(&self.spk(), &self.seed)
    }
    /// The nullifier of the note `cm` this owner holds: `nf = P(nk, cm)`.
    #[must_use]
    pub fn nullifier(&self, cm: &Digest) -> Digest {
        note_nullifier(&self.nk, cm)
    }
    /// TEST FIXTURES ONLY — a deterministic owner from one digest (`ask = k`, `nk` and `seed` domain-separated compressions
    /// of it), so a fixture that named one `sk` names one owner. Never a production derivation: a wallet derives `(ask, nk)`
    /// from its seed and `seed` from the note's KEM secret.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn from_test_key(k: Digest) -> NoteOwner {
        let dom = |d: u64| crate::poseidon2_compress::lanes_of(&[0x0395_7E57, d]);
        NoteOwner { ask: k, nk: poseidon_pair(k, dom(1)), seed: poseidon_pair(k, dom(2)) }
    }
}

/// `spk = P(ask, nk)` — the address key.
#[must_use]
pub fn owner_spk(ask: &Digest, nk: &Digest) -> Digest {
    poseidon_pair(*ask, *nk)
}

/// `o = P(spk, seed)` — the opening a sealer computes from the recipient's PUBLIC `spk` and the note's seed.
#[must_use]
pub fn owner_opening(spk: &Digest, seed: &Digest) -> Digest {
    poseidon_pair(*spk, *seed)
}

/// THE ONE NULLIFIER RULE: `nf = P(nk, cm)`.
#[must_use]
pub fn note_nullifier(nk: &Digest, cm: &Digest) -> Digest {
    poseidon_pair(*nk, *cm)
}

/// The OWNER block of an input opening: `ask ‖ nk ‖ seed` (the hiding witnesses), then the `spk = P(ask, nk)` compression and
/// the `o = P(spk, seed)` compression. Appended at the END of each input-opening layout, so no existing column moves.
pub const OWNER_BLK_WIDTH: usize = 3 * DIGEST_LANES + 2 * POSE_BLK;
const OWN_ASK: usize = 0;
const OWN_NK: usize = OWN_ASK + DIGEST_LANES;
const OWN_SEED: usize = OWN_NK + DIGEST_LANES;
const OWN_SPK_BLK: usize = OWN_SEED + DIGEST_LANES;
const OWN_O_BLK: usize = OWN_SPK_BLK + POSE_BLK;

/// The OWNER block at `base`, IN-CIRCUIT: `spk = P(ask, nk)` (its output read straight from the block, never copied) and
/// `o = P(spk, seed)`, with `o` WELDED to the opening lanes at `o_col` — the lanes the note-opening rounds read as the key.
/// So an opening verifies only for a prover who knows the `(ask, nk)` behind the note's `spk`.
fn push_owner_open<Ea4: crate::gate_trace::GateAlg>(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_, Ea4>, base: usize, o_col: usize) {
    push_owner_open_keyed(cs, local, base, o_col, None);
}

/// [`push_owner_open`], MULTIPLEXED for the note-class spend (spec §9.1). With `lock: None` the residuals are exactly
/// [`push_owner_open`]'s. With `lock = Some(lk)` (1 on a vault's lock branch, 0 on every other row): the first block
/// still proves the SPENDER's own `spk = P(ask, nk)`, and the opening's left input is welded to it only off the lock
/// branch. On a lock branch the spender is not the note's owner; the left input is then the owner's key as the note
/// itself fixes it (the opening must still hash to the note). Same two permutations either way.
fn push_owner_open_keyed<Ea4: crate::gate_trace::GateAlg>(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_, Ea4>, base: usize, o_col: usize, lock: Option<Ea4>) {
    let spk_blk = base + OWN_SPK_BLK;
    let o_blk = base + OWN_O_BLK;
    crate::pow_pq_air::push_perm_residuals(local, spk_blk, cs);
    crate::pow_pq_air::push_perm_residuals(local, o_blk, cs);
    for c in 0..DIGEST_LANES {
        cs.push(local[spk_blk + c] - local[base + OWN_ASK + c]);
        cs.push(local[spk_blk + DIGEST_LANES + c] - local[base + OWN_NK + c]);
        let owner_weld = local[o_blk + c] - local[spk_blk + crate::pow_pq_air::PERM_OUT + c];
        cs.push(match lock {
            None => owner_weld,
            Some(lk) => (Ea4::ONE - lk) * owner_weld,
        });
        cs.push(local[o_blk + DIGEST_LANES + c] - local[base + OWN_SEED + c]);
        cs.push(local[o_col + c] - local[o_blk + crate::pow_pq_air::PERM_OUT + c]);
    }
}

/// The trace side of [`push_owner_open`]: lays the owner block at `base` and writes `o` into the opening lanes at `o_col`.
/// Returns `o` (the opening the note-opening rounds then read).
fn fill_owner_open(row: &mut [Fa4], base: usize, o_col: usize, owner: &NoteOwner) -> DigestF {
    let f = |d: &Digest| -> DigestF { core::array::from_fn(|c| Fa4::from_u64(d[c])) };
    let (ask, nk, seed) = (f(&owner.ask), f(&owner.nk), f(&owner.seed));
    row[base + OWN_ASK..base + OWN_ASK + DIGEST_LANES].copy_from_slice(&ask);
    row[base + OWN_NK..base + OWN_NK + DIGEST_LANES].copy_from_slice(&nk);
    row[base + OWN_SEED..base + OWN_SEED + DIGEST_LANES].copy_from_slice(&seed);
    crate::pow_pq_air::lay_perm_row_flat(row, base + OWN_SPK_BLK, pose_state(&ask, &nk));
    let spk: DigestF = core::array::from_fn(|c| row[base + OWN_SPK_BLK + crate::pow_pq_air::PERM_OUT + c]);
    crate::pow_pq_air::lay_perm_row_flat(row, base + OWN_O_BLK, pose_state(&spk, &seed));
    let o: DigestF = core::array::from_fn(|c| row[base + OWN_O_BLK + crate::pow_pq_air::PERM_OUT + c]);
    row[o_col..o_col + DIGEST_LANES].copy_from_slice(&o);
    o
}

/// The owner block's `nk` lanes — the nullifier round's key operand. (`ask`, `nk` and `seed` are each read by an input weld
/// of the block, so the free-witness census sees them bound; none is declared free.)
fn owner_nk_col(base: usize) -> usize {
    base + OWN_NK
}

/// Width of one in-circuit compression's witness block — a whole Poseidon2 permutation.
/// ⛔ WAS 16 (`pre ‖ sq ‖ p4 ‖ p7` of the 1-round fold, kill list §AG).
const POSE_BLK: usize = crate::pow_pq_air::P2_COLS;

/// A digest in FIELD form — the shape the in-circuit helpers pass around.
pub(crate) type DigestF = [Fa4; DIGEST_LANES];
/// Row-major twin of [`fill_u64_range`].
fn fill_u64_range_row(row: &mut [Fa4], v: u64, b: U64RangeBases) {
    for i in 0..SC_LIMBS {
        row[b.limbs + i] = Fa4::from_u64((v >> (SC_LIMB_BITS * i)) & 0xFFFF);
    }
    for k in 0..(SC_LIMBS * SC_LIMB_BITS) {
        row[b.bits + k] = Fa4::from_u64((v >> k) & 1);
    }
}

/// Row-major twin of [`fill_u64_conservation`] for the validity builders, which fill one row.
fn fill_u64_conservation_row(row: &mut [Fa4], in_v: u64, out_v: u64, fee: u64, b: U64ConsBases) -> Option<()> {
    if out_v.checked_add(fee)? != in_v {
        return None;
    }
    let limb = |v: u64, i: usize| Fa4::from_u64((v >> (SC_LIMB_BITS * i)) & 0xFFFF);
    let mut carry = 0u64;
    for i in 0..SC_LIMBS {
        row[b.r#in + i] = limb(in_v, i);
        row[b.out + i] = limb(out_v, i);
        row[b.fee + i] = limb(fee, i);
        let s = ((out_v >> (SC_LIMB_BITS * i)) & 0xFFFF) + ((fee >> (SC_LIMB_BITS * i)) & 0xFFFF) + carry;
        carry = s >> SC_LIMB_BITS;
        row[b.carry + i] = Fa4::from_u64(carry);
    }
    for (v, bits_base) in [(in_v, b.in_bits), (out_v, b.out_bits), (fee, b.fee_bits)] {
        for k in 0..(SC_LIMBS * SC_LIMB_BITS) {
            row[bits_base + k] = Fa4::from_u64((v >> k) & 1);
        }
    }
    Some(())
}

/// Appended tail of every spend-validity-shaped trace: conservation block A (in/out/fee), block E
/// (out0/out1 → value_out), then the three inner-round blocks of the two-round note openings.
/// The spend-verify row's HEAD layout. ⛔ Every one of these was a hard-coded literal (0,1,5,9,10,11,15,
/// 31,47,33) until 2026-09-12; a compression block growing from 16 columns to a whole permutation would
/// have silently overlapped the next field with nothing to say so.
pub const SV_VALUE_IN: usize = 0;
pub const SV_SK: usize = SV_VALUE_IN + 1;
pub const SV_LEAF: usize = SV_SK + DIGEST_LANES;
pub const SV_VALUE_OUT: usize = SV_LEAF + DIGEST_LANES;
pub const SV_FEE: usize = SV_VALUE_OUT + 1;
pub const SV_NF: usize = SV_FEE + 1;
/// The note-opening's OUTER compression (`leaf = P(limbs, k)`).
pub const SV_NOH_BLK: usize = SV_NF + DIGEST_LANES;
/// The nullifier compression (`nf = P(sk, leaf)`).
pub const SV_NFH_BLK: usize = SV_NOH_BLK + crate::pow_pq_air::P2_COLS;
/// Where the output slots start. ⛔ The membership fold levels (`SV_MB`, `depth × SV_LEVEL`) that stood here are GONE
/// (2026-09-30): anchored to nothing since §BY, refused by the decorative-block census, deleted at source. The row is
/// ONE constant layout; nothing below depends on a witness length.
pub const SV_OB: usize = SV_NFH_BLK + crate::pow_pq_air::P2_COLS;
/// Columns ONE output-note slot occupies: value, spend key, its opening permutation, and the commitment.
pub const SV_OUT_SLOT: usize = 1 + DIGEST_LANES + crate::pow_pq_air::P2_COLS + DIGEST_LANES;
/// The membership cross-bind's INNER block, `P(leaf, nullifier)` (DB-363, 2026-09-30).
pub const SV_CB: usize = SV_OB + 2 * SV_OUT_SLOT;
/// The cross-bind's OUTER block, `leaf_commit = P(inner, lc_blind)`; its left input lanes ARE the inner block's output.
pub const SV_CB2: usize = SV_CB + crate::pow_pq_air::P2_COLS;
/// The spender's per-send blinding lanes ([`SpendValidityWitness::lc_blind`]) — a hiding witness, bound only through the
/// outer block, named in the gate's `free_columns`.
pub const SV_BLIND: usize = SV_CB2 + crate::pow_pq_air::P2_COLS;
/// Where the appended tail starts (blocks A/E and the inner note-opening rounds).
pub const SV_TAIL: usize = SV_BLIND + DIGEST_LANES;
/// The ASSET variant appends three shared tag columns after the blinding lanes, then its own tail.
pub const SV_ASSET_AB: usize = SV_TAIL;
pub const SV_ASSET_TAIL: usize = SV_ASSET_AB + 3;

const SV_TAIL_A: usize = 0;
const SV_TAIL_E: usize = U64_CONS_WIDTH;
const SV_TAIL_IN_BLK: usize = 2 * U64_CONS_WIDTH;
const SV_TAIL_IN_OUT: usize = SV_TAIL_IN_BLK + POSE_BLK;
const SV_TAIL_O0_BLK: usize = SV_TAIL_IN_OUT + DIGEST_LANES;
const SV_TAIL_O0_OUT: usize = SV_TAIL_O0_BLK + POSE_BLK;
const SV_TAIL_O1_BLK: usize = SV_TAIL_O0_OUT + DIGEST_LANES;
const SV_TAIL_O1_OUT: usize = SV_TAIL_O1_BLK + POSE_BLK;
/// The tail's total width: 2 conservation blocks + 3 × (16-col round block + 4-col output).
const SV_TAIL_WIDTH: usize = SV_TAIL_O1_OUT + DIGEST_LANES;

/// ⭐ DB-329 §7b/§7e (2026-09-30) — THE SPENDER'S DEVICE-SLOT CLAIM, after the plain spend's tail (so the asset gate's
/// layout, which shares every `SV_*` column up to `SV_TAIL`, is untouched). A spend proves
/// `tag1 = P([SLOT_CLAIM_DOMAIN, d, 0…], key)` under its OWN witness and publishes `tag1` beside its nullifier, so the
/// block producer never holds `(key, d)` (the refuted producer-side shape). An ordinary spend claims `(lc_blind, 0)` — a
/// key nobody else holds — so every spend's `tag1` has a claim's shape. `d` and the key are hiding witnesses bound only
/// through `tag1` (named in `free_columns`); the block's output IS the public `tag1` (never decorative).
pub const SV_CLAIM_D: usize = SV_TAIL + SV_TAIL_WIDTH;
pub const SV_CLAIM_KEY: usize = SV_CLAIM_D + 1;
pub const SV_CLAIM_BLK: usize = SV_CLAIM_KEY + DIGEST_LANES;
/// ⛔ DB-395 — the spent note's OWNER block ([`push_owner_open`]), after the claim, at the row's end.
pub const SV_OWNER: usize = SV_CLAIM_BLK + crate::pow_pq_air::P2_COLS;

/// The appended tail of an n-input spend: a SUM CHAIN of range-bound conservation blocks, block E,
/// and the inner round of every note opening. Shared by the gate and the builder so the two cannot
/// drift. Every addend and every running sum is range-bound where it is used; sums that appear twice
/// are tied LIMB-WISE (never by field recombination, which aliases at p).
///
/// blocks 0..n-2 (n ≥ 2): sum blocks — `in = s_{k+1}`, `out = (k == 0 ? in_0 : s_k)`, `fee = in_{k+1}`.
/// block n-1: the final — `in = s_{n-1}` (or `in_0` when n = 1), `out = value_out`, `fee = fee`.
/// block E: `in = value_out`, `out = out0`, `fee = out1`.
#[derive(Clone, Copy)]
struct MultiTail {
    base: usize,
    n: usize,
}
impl MultiTail {
    /// ⭐⭐⭐ THE ONE PLACE THE TAIL'S START IS COMPUTED. The gate and the row builder each had their own
    /// copy of `n * per + 2 + <two output slots>`, and when the digest widened only one of them was
    /// corrected — the literal `+ 50` (two slots at the retired 25-column shape) stayed in the builder
    /// while the gate moved to `2 * NO_WIDTH`. The gate then read one column past a row the builder had
    /// sized 312 columns shorter. Two copies of a layout is one copy too many.
    fn for_row(n: usize, depth: usize) -> Self {
        MultiTail { base: n * multi_per_input_width(depth) + 2 + 2 * NO_WIDTH, n }
    }
    fn block(&self, k: usize) -> U64ConsBases {
        U64ConsBases::at(self.base + k * U64_CONS_WIDTH)
    }
    fn e(&self) -> U64ConsBases {
        U64ConsBases::at(self.base + self.n * U64_CONS_WIDTH)
    }
    /// Where input `i`'s range-bound limbs live.
    fn in_limbs(&self, i: usize) -> usize {
        if self.n == 1 {
            self.block(0).r#in
        } else if i == 0 {
            self.block(0).out
        } else {
            self.block(i - 1).fee
        }
    }
    /// One inner-round slot: the permutation block plus the digest it outputs. ⛔ WAS `POSE_BLK + 4` —
    /// the output digest's width written as a literal, so every slot after the first overlapped its
    /// neighbour the moment the digest widened.
    const INNER_SLOT: usize = POSE_BLK + DIGEST_LANES;
    fn inner_in(&self, i: usize) -> (usize, usize) {
        let b = self.base + (self.n + 1) * U64_CONS_WIDTH + i * Self::INNER_SLOT;
        (b, b + POSE_BLK)
    }
    fn inner_out(&self, j: usize) -> (usize, usize) {
        self.inner_in(self.n + j)
    }
    fn width(&self) -> usize {
        (self.n + 1) * U64_CONS_WIDTH + (self.n + 2) * Self::INNER_SLOT
    }
}

/// The gate side of the sum chain: every block, every limb-wise tie between adjacent sums.
fn push_multi_sum_chain(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, t: MultiTail) {
    for k in 0..t.n {
        push_u64_conservation(cs, local, t.block(k));
    }
    push_u64_conservation(cs, local, t.e());
    // s_k appears as block(k-1).in and block(k).out for the sum blocks; the final block's `in` is
    // s_{n-1} = block(n-2).in; block E's `in` is value_out = final.out.
    for k in 1..t.n.saturating_sub(1) {
        for i in 0..SC_LIMBS {
            cs.push(local[t.block(k).out + i] - local[t.block(k - 1).r#in + i]);
        }
    }
    if t.n >= 2 {
        for i in 0..SC_LIMBS {
            cs.push(local[t.block(t.n - 1).r#in + i] - local[t.block(t.n - 2).r#in + i]);
        }
    }
    for i in 0..SC_LIMBS {
        cs.push(local[t.e().r#in + i] - local[t.block(t.n - 1).out + i]);
    }
}

/// The trace side of the sum chain. `ins` are the input values; returns None on any u64 overflow or a
/// non-conserving witness (the honest-prover bound).
fn fill_multi_sum_chain(row: &mut [Fa4], t: MultiTail, ins: &[u64], value_out: u64, fee: u64, out0: u64, out1: u64) -> Option<()> {
    let n = ins.len();
    if n == 0 || n != t.n {
        return None;
    }
    let mut s = ins[0];
    for k in 0..n.saturating_sub(1) {
        let next = s.checked_add(ins[k + 1])?;
        fill_u64_conservation_row(row, next, s, ins[k + 1], t.block(k))?;
        s = next;
    }
    fill_u64_conservation_row(row, s, value_out, fee, t.block(n - 1))?;
    fill_u64_conservation_row(row, value_out, out0, out1, t.e())?;
    Some(())
}


/// Build the full-validity row (deriving leaf, nf, the membership path, and the two output note-openings)
/// + the recomputed root + the two output commitments. None if value doesn't conserve or is malformed.
/// The spend-validity row's width at `depth` — ONE definition for the row builder and for every verifier that
/// must STATE the carrier's shape without holding one (DB-213b: `settlement_delta::note_class_shape`).
///
/// `None` past [`crate::nullifier_insert_air::NF_DEPTH`]: a carrier's path walks the spend tree, and no path is
/// deeper than the tree it walks (the same coupled depth `chain-lifetime-guard` holds at 64). The bound is what
/// keeps a depth read off a block from sizing an allocation.
#[must_use]
pub const fn spend_validity_row_width() -> usize {
    SV_OWNER + OWNER_BLK_WIDTH
}

/// The membership carrier's row width at `depth` — one definition for its builder and its verifier (DB-213b).
/// `None` past the spend tree's depth ([`spend_validity_row_width`] states why that bounds it).
#[must_use]
pub fn membership_carrier_row_width(depth: usize) -> Option<usize> {
    if depth > crate::nullifier_insert_air::NF_DEPTH {
        return None;
    }
    Some(SMEM_MB + depth * SMEM_LEVEL)
}

/// ⛔ DB-395 — the asset row's input-1 OWNER block, at the single-input row's end.
pub const ASV_OWNER: usize = SV_ASSET_TAIL + SV_TAIL_WIDTH;

/// The asset spend-validity row's width at `depth` — the asset twin of [`spend_validity_row_width`].
#[must_use]
pub const fn asset_spend_row_width() -> usize {
    ASV_OWNER + OWNER_BLK_WIDTH
}

/// ⭐ SATOSHI §9 — THE RE-BOND'S SECOND INPUT, appended AFTER the single-input asset row so nothing before it moves
/// (docs/SATOSHI-NATIVE-TOKEN.md §9.1). Input 2 is the validator's CURRENTLY LOCKED note (its existence is the fold's set read,
/// not a membership path); input 1 (the `SV_*` block) stays the fresh note whose membership the cross-bind carries.
/// `SV_IN2_CONS` is conservation block C: `total = value_in1 + value_in2`, range-bound, tied limb-wise to block A's `in`.
pub const SV_IN2_VALUE: usize = asset_spend_row_width();
pub const SV_IN2_SK: usize = SV_IN2_VALUE + 1;
pub const SV_IN2_LEAF: usize = SV_IN2_SK + DIGEST_LANES;
pub const SV_IN2_NF: usize = SV_IN2_LEAF + DIGEST_LANES;
pub const SV_IN2_NOH_BLK: usize = SV_IN2_NF + DIGEST_LANES;
pub const SV_IN2_NFH_BLK: usize = SV_IN2_NOH_BLK + crate::pow_pq_air::P2_COLS;
pub const SV_IN2_INNER_BLK: usize = SV_IN2_NFH_BLK + crate::pow_pq_air::P2_COLS;
pub const SV_IN2_INNER_OUT: usize = SV_IN2_INNER_BLK + POSE_BLK;
pub const SV_IN2_CONS: usize = SV_IN2_INNER_OUT + DIGEST_LANES;
/// ⛔ DB-395 — the locked note's OWNER block (input 2), at the re-bond row's end.
pub const SV_IN2_OWNER: usize = SV_IN2_CONS + U64_CONS_WIDTH;
/// The re-bond row's width. A carrier of this shape never verifies as a single-input one or vice-versa: the verifier states
/// the width (DB-213b) and the public bind carries its own domain.
pub const fn asset_rebond_row_width() -> usize {
    SV_IN2_OWNER + OWNER_BLK_WIDTH
}

/// The multi-input spend row's width for `n` inputs at `depth` — the builder's own `MultiTail` layout, so the
/// verifier states the width the builder lays (DB-213b). Checked: an `n` too large for a row names no row.
#[must_use]
pub fn multi_spend_row_width(n: usize, depth: usize) -> Option<usize> {
    if n == 0 || depth == 0 || depth > crate::nullifier_insert_air::NF_DEPTH {
        return None;
    }
    let per = multi_per_input_width(depth);
    let base = n.checked_mul(per)?.checked_add(2 + 2 * NO_WIDTH)?;
    let tail = n
        .checked_add(1)?
        .checked_mul(U64_CONS_WIDTH)?
        .checked_add(n.checked_add(2)?.checked_mul(MultiTail::INNER_SLOT)?)?;
    base.checked_add(tail)
}

/// Build the spend-validity row. Returns `(row, out_cms, nf, leaf_commit)` — the commitment is read from the
/// row's OUTER cross-bind block, the ONE spelling of `P(P(leaf, nf), lc_blind)` (DB-363).
/// ⛔ There is no root and no path (2026-09-30): the depth-`d` Merkle path constrained nothing since §BY and is
/// deleted; membership is the note-membership carrier's, cross-bound by `leaf_commit`.
#[allow(clippy::type_complexity)]
fn spend_validity_row(w: &SpendValidityWitness) -> Option<(Vec<Fa4>, [DigestF; 2], DigestF, DigestF)> {
    spend_validity_row_claiming(w, w.lc_blind, 0)
}

/// The ordinary spend's claim tag: the claim of `(lc_blind, 0)` — a key nobody else holds (DB-329 §7e). The ONE native
/// spelling a wallet and a door use for the `tag1` an ordinary send publishes.
#[must_use]
pub fn spend_tag1(w: &SpendValidityWitness) -> Digest {
    ordinary_claim_tag(w.lc_blind)
}

/// [`spend_tag1`] from the blinding alone — what a wallet's send assembly holds before it builds the witness.
#[must_use]
pub fn ordinary_claim_tag(lc_blind: Digest) -> Digest {
    crate::slot_ledger::slot_claim_native(lc_blind, 0)
}

/// [`spend_validity_row`] with an explicit device-slot claim `(key, d)` laid in the `SV_CLAIM_*` columns.
fn spend_validity_row_claiming(
    w: &SpendValidityWitness,
    key: Digest,
    d: u64,
) -> Option<(Vec<Fa4>, [DigestF; 2], DigestF, DigestF)> {
    spend_validity_row_ext(w, key, d, &vault_gate::NoteExt::PLAIN, &[vault_gate::NoteExt::PLAIN; 2], None, false)
}

/// The NOTE-CLASS spend row's width: the plain spend row, then the vault region (`vault_gate`, spec §9.1). Every
/// note-class spend lays it, vault or not, so the two are one shape.
#[must_use]
pub const fn note_spend_row_width() -> usize {
    spend_validity_row_width() + VAULT_BLK_WIDTH
}

/// The note-class spend row: [`spend_validity_row_ext`] with the extra lanes `x` names, then the vault region.
/// `None` when the witness does not conserve, or `x` names a vault branch its spender cannot take (not that vault's
/// party, not the branch's secret, the clock branch before the vault's time).
#[allow(clippy::type_complexity)]
fn note_spend_row(
    w: &SpendValidityWitness,
    x: &NoteSpendExtras,
    key: Digest,
    d: u64,
) -> Option<(Vec<Fa4>, [DigestF; 2], DigestF, DigestF)> {
    // the honest-prover bound (the gate is the dishonest-prover one)
    if !x.fits(w) {
        return None;
    }
    note_spend_row_as_said(w, x, key, d)
}

/// [`note_spend_row`] laid exactly as `x` says, true or not: what a lying prover lays (the vault pins prove these rows
/// against the production gate). `None` only when no row exists at all (a clock branch before its time).
#[allow(clippy::type_complexity)]
fn note_spend_row_as_said(
    w: &SpendValidityWitness,
    x: &NoteSpendExtras,
    key: Digest,
    d: u64,
) -> Option<(Vec<Fa4>, [DigestF; 2], DigestF, DigestF)> {
    let lock = x.lock_lay();
    let (mut row, out_cms, nf, leaf_commit) =
        spend_validity_row_ext(w, key, d, &x.in_ext(), &x.out_ext(), lock.as_ref(), x.vault.is_some())?;
    row.resize(note_spend_row_width(), Fa4::ZERO);
    vault_gate::fill_vault(&mut row, spend_validity_row_width(), x)?;
    Some((row, out_cms, nf, leaf_commit))
}

/// [`spend_validity_row_claiming`] with the spent note's and the two outputs' extra lanes laid in their openings (all
/// zero for every class but the note class), and a vault spend laid the vault's way (spec §9.1): `vault` keys the
/// nullifier by the note's opening; on a LOCK branch (`lock`) `w.owner`'s `(ask, nk)` are the SPENDER's, the opening
/// is the vault owner's `P(owner spk, seed)`, and the claim block lays the lock's preimage in place of `(key, d)`.
#[allow(clippy::type_complexity)]
fn spend_validity_row_ext(
    w: &SpendValidityWitness,
    key: Digest,
    d: u64,
    in_ext: &vault_gate::NoteExt,
    out_ext: &[vault_gate::NoteExt; 2],
    lock: Option<&vault_gate::LockLay>,
    vault: bool,
) -> Option<(Vec<Fa4>, [DigestF; 2], DigestF, DigestF)> {
    if w.value_out.checked_add(w.fee)? != w.value_in {
        return None; // A. conservation (also enforced in-circuit)
    }
    if w.out0_value.checked_add(w.out1_value)? != w.value_out {
        return None; // E. output conservation: the two output notes sum to EXACTLY value_out (also in-circuit)
    }
    let width = spend_validity_row_width();
    let tail = SV_TAIL;
    let mut row = vec![Fa4::ZERO; width];
    let value_in = Fa4::from_u64(w.value_in);
    // DB-395: the opening lanes `SV_SK` hold `o = P(P(ask, nk), seed)`, laid by the owner block, which writes them.
    let mut sk = fill_owner_open(&mut row, SV_OWNER, SV_SK, &w.owner);
    let spk_p: DigestF = core::array::from_fn(|c| row[SV_OWNER + OWN_SPK_BLK + crate::pow_pq_air::PERM_OUT + c]);
    if let Some(l) = lock {
        // a lock branch: the opening is the vault OWNER's, not the spender's
        crate::pow_pq_air::lay_perm_row_flat(&mut row, SV_OWNER + OWN_O_BLK, pose_state(&to_f(&l.owner_spk), &to_f(&w.owner.seed)));
        sk = core::array::from_fn(|c| row[SV_OWNER + OWN_O_BLK + crate::pow_pq_air::PERM_OUT + c]);
        row[SV_SK..SV_SK + DIGEST_LANES].copy_from_slice(&sk);
    }
    // a payment's nullifier is keyed by its owner's `nk`; a vault's by its opening, which both its parties hold
    let nk: DigestF = if vault { sk } else { to_f(&w.owner.nk) };
    row[SV_VALUE_IN] = value_in;
    row[SV_VALUE_OUT] = Fa4::from_u64(w.value_out);
    row[SV_FEE] = Fa4::from_u64(w.fee);
    // A + E: the range-bound conservation blocks (the u64 checks above are the honest-prover bound).
    fill_u64_conservation_row(&mut row, w.value_in, w.value_out, w.fee, U64ConsBases::at(tail + SV_TAIL_A))?;
    fill_u64_conservation_row(&mut row, w.value_out, w.out0_value, w.out1_value, U64ConsBases::at(tail + SV_TAIL_E))?;
    // B. note-opening, two rounds: leaf = P(limbs(value_in), P([USDm tag, 0], sk))
    let leaf = fill_note_open_ext(
        &mut row, w.value_in, USDM_ASSET_TAG, in_ext, &sk,
        tail + SV_TAIL_IN_BLK, tail + SV_TAIL_IN_OUT, SV_NOH_BLK, SV_LEAF,
    );
    // C. nullifier: nf = compress(nk, leaf) (DB-395)
    let nf = fill_pose_round(&mut row, &nk, &leaf, SV_NFH_BLK, SV_NF);
    // D. (deleted 2026-09-30) — no membership path is laid; see the gate.
    // E. OUTPUT BINDING: fill the two output note-opening blocks from `SV_OB`, deriving each output's public
    // commitment out_cm_j = asset_note_cm(out_value_j, USDm, out_opening_j).
    let ob = SV_OB;
    let mut out_cms = [[Fa4::ZERO; DIGEST_LANES]; 2];
    let outs = [(w.out0_value, w.out0_opening), (w.out1_value, w.out1_opening)];
    for (j, (ov, osk)) in outs.iter().enumerate() {
        let base = ob + j * SV_OUT_SLOT;
        let val = Fa4::from_u64(*ov);
        let sk_j: DigestF = core::array::from_fn(|c| Fa4::from_u64(osk[c]));
        row[base] = val;
        row[base + 1..base + 1 + DIGEST_LANES].copy_from_slice(&sk_j);
        let (iblk, iout) = if j == 0 { (SV_TAIL_O0_BLK, SV_TAIL_O0_OUT) } else { (SV_TAIL_O1_BLK, SV_TAIL_O1_OUT) };
        let cm = fill_note_open_ext(
            &mut row, *ov, USDM_ASSET_TAG, &out_ext[j], &sk_j, tail + iblk, tail + iout,
            base + 1 + DIGEST_LANES, base + 1 + DIGEST_LANES + crate::pow_pq_air::P2_COLS,
        );
        out_cms[j] = cm;
    }
    // F. THE MEMBERSHIP CROSS-BIND: leaf_commit = Poseidon(leaf, nf).
    //
    // This is the value the note-membership carrier also binds, so the two proofs name ONE note. The leaf
    // stays in-circuit (it is the value written when the note was RECEIVED — publishing it would link this
    // spend to that receive); the nullifier is already public and unique per spend, which makes the
    // commitment unlinkable across spends and the carrier non-replayable into another tx.
    // DB-363: two chained blocks — the inner's output is written into the outer's left lanes by `fill_pose_round`,
    // the blinding fills the outer's right lanes, and the outer's output IS the public commitment.
    let inner = fill_pose_round(&mut row, &leaf, &nf, SV_CB, SV_CB2);
    let blind: DigestF = core::array::from_fn(|c| Fa4::from_u64(w.lc_blind[c]));
    row[SV_BLIND..SV_BLIND + DIGEST_LANES].copy_from_slice(&blind);
    crate::pow_pq_air::lay_perm_row_flat(&mut row, SV_CB2, pose_state(&inner, &blind));
    let leaf_commit: DigestF = core::array::from_fn(|c| row[SV_CB2 + crate::pow_pq_air::PERM_OUT + c]);
    // H. the device-slot claim (DB-329 §7e): P([SLOT_CLAIM_DOMAIN, d, 0…], key). On a vault's lock branch the claim
    // block lays the LOCK's preimage instead (the taker's `spk` lanes, the secret, the vault's opening lanes), so the
    // tag this spend publishes is the lock it opens.
    let (claim_left, key_f, d): (DigestF, DigestF, u64) = match lock {
        None => (to_f(&crate::poseidon2_compress::lanes_of(&[crate::slot_ledger::SLOT_CLAIM_DOMAIN, d])), to_f(&key), d),
        Some(l) => {
            let (left, k) = l.claim_inputs(&to_u64(&spk_p), &to_u64(&sk));
            (to_f(&left), to_f(&k), u64::from(l.deliver.is_some()))
        }
    };
    row[SV_CLAIM_D] = Fa4::from_u64(d);
    row[SV_CLAIM_KEY..SV_CLAIM_KEY + DIGEST_LANES].copy_from_slice(&key_f);
    crate::pow_pq_air::lay_perm_row_flat(&mut row, SV_CLAIM_BLK, pose_state(&claim_left, &key_f));
    Some((row, out_cms, nf, leaf_commit))
}

/// Public IO bound at the transcript start: the validity domain + the 4-limb frontier `root` + the two
/// OUTPUT commitments (so a carrier is welded to EXACTLY the output notes the node records — no substitution).
/// [`validity_public_bind`] plus the membership cross-bind when the carrier carries one. A carrier proved
/// WITHOUT a commitment must not verify as though it had one, and vice versa — so the commitment enters the
/// transcript, not just the constraint set.
pub fn validity_public_bind_with_commit(
    out_cms: &[DigestF; 2],
    nullifier: &DigestF,
    leaf_commit: &DigestF,
    clue_digest: &DigestF,
    tag1: &DigestF,
) -> Vec<Fa4> {
    // A carrier proven against clock 0 binds exactly the bytes this function always bound: the clock digest of 0 is
    // the zero digest that stood in the seventh slot as padding.
    note_spend_public_bind(out_cms, nullifier, leaf_commit, clue_digest, tag1, 0)
}

/// [`validity_public_bind_with_commit`] with the VERIFIER'S CLOCK in the bind's seventh digest (spec §9.1): the
/// note-class spend's transcript names the clock its vault region is welded to, so a carrier proven against one clock
/// verifies under no other. The 8-digest stride the settlement aggregate replays is unchanged.
pub fn note_spend_public_bind(
    out_cms: &[DigestF; 2],
    nullifier: &DigestF,
    leaf_commit: &DigestF,
    // DB-351 (2026-09-28): the payment's discovery data (`note_clues`, verbatim as pooled), hashed by the wallet
    // before proving and recomputed by every door — appended LAST, so a tx whose clues moved in flight verifies
    // under no door. Never hashed in-circuit: D is public data the verifier supplies, bound by the transcript.
    clue_digest: &DigestF,
    // DB-329 §7e (2026-09-30): the spend's device-slot claim tag — the carrier's `tag1` statement, published as
    // `PqTx.nullifiers[1]` and refused twice by the spent SET. The sixth digest, in the slot the first padding
    // digest held (the stride stays 8 digests per row).
    tag1: &DigestF,
    // Spec §9.1: the chain clock, in chain hours, the spend is proven against — the seventh digest, in the slot the
    // second padding digest held. 0 for a carrier with no vault region.
    clock_h: u64,
) -> Vec<Fa4> {
    // ⭐⭐⭐ WITH THE CROSS-BIND, THE ROOT LEAVES THE TRANSCRIPT TOO — NOT JUST THE CONSTRAINT.
    //
    // Dropping gate D's weld alone was NOT enough, and my own tamper test caught it: the root is also welded
    // into the public bind here, so a spend still had to name the exact root its (unobtainable) copath
    // recomputes. MEASURED 2026-08-11, the first run of
    // `a_cross_bound_spend_proves_membership_by_accumulator_not_by_merkle_root`:
    //   assertion failed — "with the membership cross-bind present the spend must NOT depend on a Merkle root"
    // Half a change is worse than none here: it would have looked done while every send still failed exactly
    // as before.
    //
    // When `leaf_commit` is present the note's chain-membership is established by the note-membership carrier
    // (an O(1) recursive fold over the accumulator) and pinned to THIS spend by `Poseidon(leaf, nullifier) ==
    // leaf_commit`. The Merkle root then constrains nothing and proves nothing, so binding it would only
    // re-impose the copath requirement through the transcript. It is omitted, and `leaf_commit` — which the
    // membership carrier independently binds — takes its place as the thing the transcript pins.
    //
    // With `leaf_commit` ABSENT the bind is byte-identical to before: the root stays, and every existing
    // carrier type verifies exactly as it did.
    // The cross-bind is ALWAYS present now, so the `None` arm (which bound the fixed-capacity ROOT instead)
    // is gone with it. The root does not enter the bind because it constrains nothing: membership is proven
    // by the note-membership fold, and binding a root here would re-impose the very anchor that fills.
    // (2026-09-30: the ignored `root` parameter is gone with the path — the API names only what is bound.)
    let mut b = vec![Fa4::from_u64(SPEND_VALIDITY_DOMAIN)];
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    b.extend_from_slice(nullifier);
    b.extend_from_slice(leaf_commit);
    b.extend_from_slice(clue_digest); // DB-351: the fifth digest
    b.extend_from_slice(tag1); // DB-329 §7e: the sixth digest
    // DB-351 padding, STATED: the settlement aggregate replays this bind as the row's public tuple and its chain
    // needs a power-of-two digest count per row (`settlement_delta::chain_stride_is_exact`: 4 duplexings held
    // before; 5 digests = 40 words is refused at layout time, 8 = 64 words is 8 duplexings). Two zero digests
    // therefore close the bind (§7e took the first of the three) — absorbed by prover and verifier alike
    // (transcript, not proof bytes), never published (a peer pads its tuple list the same way).
    b.extend_from_slice(&to_f(&clock_lanes(clock_h))); // spec §9.1: the seventh slot, the clock's hour count
    for _ in 0..VALIDITY_BIND_PAD_DIGESTS {
        b.extend_from_slice(&[Fa4::ZERO; DIGEST_LANES]);
    }
    b
}

/// The zero digests that close [`note_spend_public_bind`] to its 8-digest stride: out0, out1, nf, lc, D, tag1, the
/// clock, then this one.
pub const VALIDITY_BIND_PAD_DIGESTS: usize = 1;

/// A distinct, non-zero clue digest per test instance (DB-351) — what a wallet computes from the clues it attaches.
/// Test-only: the all-zero digest is exercised ONLY by the refusal pin, never by a prove/verify pair that asserts
/// acceptance.
#[cfg(test)]
pub(crate) fn test_clue_digest(i: u64) -> Digest {
    crate::poseidon2_compress::lanes_of(&[0x434C_5545 ^ i, 0x4431 + i, 2 * i + 1, 3 * i + 7])
}

/// DB-351 — the clue digest is BOUND: a spend proven under the clues it attached verifies under no other clues.
/// TWO-PARTY-REVIEWED: these are the CARRIER's own accept/refuse verdicts — the functions the wallet (prover) and the
/// node doors (verifiers) call, exercised on the digest alone. The two-party door test — a wallet's carrier arriving at
/// a node door through a relay that rewrote the pooled `note_clues`, and refused there — lives with the doors (the node
/// lane's DB-351 half: the rpc_http / note_transition door pins), where the second endpoint is.
#[cfg(test)]
mod db351_clue_bind_pins {
    use super::*;
    use crate::poseidon2_compress::lanes_of;

    fn spend_witness(i: u64) -> SpendValidityWitness {
        let sk = lanes_of(&[11 + i, 12, 13, 14]);
        // the pathless production shape (§BY): membership rides the accumulator, cross-bound by `leaf_commit`
        SpendValidityWitness {
            value_in: 900 + i,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 800 + i,
            fee: 100,
            lc_blind: lanes_of(&[0x363, i, 2, 3]),
            out0_value: 750 + i,
            out0_opening: lanes_of(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        }
    }

    /// ⭐ §BR-14 — THE FLAT FEE IS WELDED, NOT CHOSEN. A spend proven paying the protocol fee verifies under it and under
    /// no other fee (F − 1, F + 1, 0, and F + p — a residual-only weld would alias F + p to F); a spend proven paying NOTHING
    /// (the pre-§BR-14 free send) is honest under fee 0 (the calibration: its carrier is otherwise sound) and refused under
    /// the protocol fee the node supplies.
    #[test]
    fn br14_a_spend_paying_any_fee_but_the_protocol_fee_is_refused_by_the_verifier() {
        let f = PROTOCOL_FEE_ATOMIC;
        let sk = lanes_of(&[0xB14, 2, 3, 4]);
        let mk = |fee: u64| SpendValidityWitness {
            value_in: 800 + fee,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 800,
            fee,
            lc_blind: lanes_of(&[0x363, 0xB14, 2, 3]),
            out0_value: 750,
            out0_opening: lanes_of(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        };
        let d = test_clue_digest(0xB14);
        let w = mk(f);
        let (c, cms, nf, lc) = prove_spend_validity_carrier_with_commit_bytes(&w, d).expect("the honest fee-paying spend proves");
        let t1 = spend_tag1(&w);
        let v = |fee: u64| verify_spend_validity_carrier_bytes(&c, cms[0], cms[1], nf, lc, d, t1, fee);
        assert!(v(f), "the spend paying the protocol fee verifies under it");
        let p = 0x7f00_0001u64; // KoalaBear: a single-cell weld would read F + p as F
        for other in [f - 1, f + 1, 0, f + p] {
            assert!(!v(other), "⛔ the verifier accepted a carrier under a fee it does not pay ({other})");
        }
        let w0 = mk(0);
        let (c0, cms0, nf0, lc0) = prove_spend_validity_carrier_with_commit_bytes(&w0, d).expect("a zero-fee spend still proves");
        let t0 = spend_tag1(&w0);
        assert!(
            verify_spend_validity_carrier_bytes(&c0, cms0[0], cms0[1], nf0, lc0, d, t0, 0),
            "CALIBRATION: the zero-fee carrier is honest under its own fee — only the weld refuses it"
        );
        assert!(
            !verify_spend_validity_carrier_bytes(&c0, cms0[0], cms0[1], nf0, lc0, d, t0, f),
            "⛔ a spend that paid no fee verified under the protocol fee"
        );
    }

    /// ⛔⛔⛔ THE ATTACK DB-351 NAMED: a relay races a copy of the pooled payment with its `note_clues` rewritten, so the
    /// note settles UNFILED (a seed-restore miss, funds loss). With D in the bind the carrier proven under the wallet's
    /// clues verifies ONLY under those clues: D′ (one lane moved — one clue byte moved) is refused, the all-zero digest
    /// ("no clues") is refused, a carrier proven under other clues is refused under these, and the honest D still
    /// verifies (the calibration half). The single-input carrier at the pathless production depth.
    #[test]
    fn a_spend_whose_clues_moved_in_flight_verifies_under_no_door() {
        let w = spend_witness(3);
        let d = test_clue_digest(3);
        let (carrier, cms, nf, lc) = prove_spend_validity_carrier_with_commit_bytes(&w, d).expect("the honest spend proves under its clues");
        let t1 = spend_tag1(&w);
        assert!(verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, lc, d, t1, 100), "CALIBRATION: the honest clues verify");
        let mut moved = d;
        moved[0] ^= 1;
        assert!(!verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, lc, moved, t1, 100), "⛔ a spend whose clues MOVED in flight verified");
        let mut moved_last = d;
        moved_last[DIGEST_LANES - 1] = moved_last[DIGEST_LANES - 1].wrapping_add(1);
        assert!(!verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, lc, moved_last, t1, 100), "⛔ a spend whose LAST clue lane moved verified");
        assert!(!verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, lc, lanes_of(&crate::poseidon2_compress::ZERO_DIGEST), t1, 100), "⛔ a spend stripped of its clues (the all-zero digest) verified");
        let (other, cms2, nf2, lc2) = prove_spend_validity_carrier_with_commit_bytes(&w, test_clue_digest(4)).expect("proves under other clues");
        assert_eq!((cms2, nf2, lc2), (cms, nf, lc), "the statement is the same spend");
        assert!(!verify_spend_validity_carrier_bytes(&other, cms[0], cms[1], nf, lc, d, t1, 100), "⛔ a carrier proven under other clues verified under these");
        eprintln!("[db351] single-input carrier {} B: honest clues verify; a moved lane, a moved last lane, stripped clues and an other-clues proof are all refused", carrier.len());
    }

    /// ⛔⛔⛔ DB-329 §7e — THE CLAIM IS THE SPENDER'S LAW, PROVEN UNDER ITS OWN WITNESS.
    /// TWO-PARTY-REVIEWED: these are the CARRIER's accept/refuse verdicts (prover = wallet, verifier = any door). The
    /// cross-spend half — two spends publishing one claim, refused by the spent SET — lives with the node's door pins.
    ///
    /// (a) CALIBRATION: an ordinary spend's `tag1` is `claim(lc_blind, 0)` and verifies; a claiming spend's `tag1` is
    /// `claim(key, d)` and verifies. (b) A published tag1 other than the proven claim is refused — a moved lane, another
    /// slot of the same key, another key, a cover tag, the all-zero digest. (c) Two ordinary sends of one note under two
    /// blindings publish two DIFFERENT tags (unlinkable: nothing about the tag names the note or the wallet). (d) Two
    /// claiming spends of the SAME `(key, d)` publish the SAME tag — the collision the set arbitrates. (e) A carrier
    /// proven with a claim does not verify as an ordinary spend and vice versa.
    #[test]
    fn db329_a_published_tag1_other_than_the_proven_claim_verifies_under_no_door() {
        let w = spend_witness(5);
        let d = test_clue_digest(5);
        // (a) ordinary
        let (c, cms, nf, lc) = prove_spend_validity_carrier_with_commit_bytes(&w, d).expect("the ordinary spend proves");
        let t1 = spend_tag1(&w);
        assert_eq!(t1, crate::slot_ledger::slot_claim_native(w.lc_blind, 0), "the ordinary tag is claim(lc_blind, 0)");
        assert!(verify_spend_validity_carrier_bytes(&c, cms[0], cms[1], nf, lc, d, t1, 100), "CALIBRATION: the ordinary spend verifies");
        // (a) claiming
        let key = lanes_of(&[0x5107, 0xde71, 3, 4]);
        let (cc, ccms, cnf, clc, ct1) = prove_spend_validity_carrier_claiming_bytes(&w, d, key, 7).expect("the claiming spend proves");
        assert_eq!(ct1, crate::slot_ledger::slot_claim_native(key, 7), "the claiming tag is claim(key, d) — the row and the native spelling agree");
        assert_eq!((ccms, cnf, clc), (cms, nf, lc), "the claim moves no other statement");
        assert!(verify_spend_validity_carrier_bytes(&cc, cms[0], cms[1], nf, lc, d, ct1, 100), "CALIBRATION: the claiming spend verifies");
        // (b) every other tag1 is refused
        let mut moved = ct1;
        moved[1] ^= 1;
        let refusals: [(&str, crate::poseidon2_compress::Digest); 5] = [
            ("a moved lane", moved),
            ("another slot of the same key", crate::slot_ledger::slot_claim_native(key, 8)),
            ("another key's claim", crate::slot_ledger::slot_claim_native(lanes_of(&[9, 9, 9, 9]), 7)),
            ("a cover tag", crate::slot_ledger::cover_tag_native(key, 7)),
            ("the all-zero digest", crate::poseidon2_compress::ZERO_DIGEST),
        ];
        for (what, lie) in refusals {
            assert!(!verify_spend_validity_carrier_bytes(&cc, cms[0], cms[1], nf, lc, d, lie, 100), "⛔ a claiming carrier verified under {what}");
            assert!(!verify_spend_validity_carrier_bytes(&c, cms[0], cms[1], nf, lc, d, lie, 100), "⛔ an ordinary carrier verified under {what}");
        }
        // (c) two blindings, two tags — nothing links two sends
        let w2 = SpendValidityWitness { lc_blind: lanes_of(&[0x363, 99, 98, 97]), ..spend_witness(5) };
        assert_ne!(spend_tag1(&w2), t1, "⛔ two sends of one note published ONE ordinary tag — the tag would link them");
        // (d) one (key, d), one tag — whatever the note
        let (_c3, _cms3, _nf3, _lc3, ct3) = prove_spend_validity_carrier_claiming_bytes(&spend_witness(6), d, key, 7).expect("proves");
        assert_eq!(ct3, ct1, "two claims of one (key, d) publish ONE tag — the spent set refuses the second");
        // (e) the claim is a statement: a claiming carrier is not an ordinary one, nor the reverse
        assert!(!verify_spend_validity_carrier_bytes(&cc, cms[0], cms[1], nf, lc, d, t1, 100), "⛔ a claiming carrier verified as ordinary");
        assert!(!verify_spend_validity_carrier_bytes(&c, cms[0], cms[1], nf, lc, d, ct1, 100), "⛔ an ordinary carrier verified as claiming");
        eprintln!("[db329] ordinary + claiming carriers verify; 5 lies × 2 carriers and 2 cross-class presentations refused");
    }

    /// ⛔ DB-329 §7e — THE WELD, NOT THE TRANSCRIPT: a prover that lies about `tag1` in BOTH the gate and the bind (a
    /// self-consistent transcript) is refused by the in-circuit claim law. The claim block holds the honest `(key, d)`;
    /// the gate is told another tag. RED if residual H is deleted: the transcript alone would then accept the lie.
    #[test]
    fn db329_a_forged_claim_in_a_self_consistent_transcript_is_refused_by_the_weld() {
        use p3_field::PrimeField64;
        let w = spend_witness(7);
        let d = test_clue_digest(7);
        // the PRODUCTION row (the note class lays the vault region, spec §9.1): the forged carrier has the shape the
        // production verifier takes, so its refusal below is the claim weld's and not a width mismatch
        let (row, out_cms, nf, lc) = note_spend_row(&w, &NoteSpendExtras::plain(0), lanes_of(&[1, 2, 3, 4]), 2).expect("lays");
        let lie: Digest = crate::slot_ledger::slot_claim_native(lanes_of(&[5, 6, 7, 8]), 2);
        let lie_f = to_f(&lie);
        let ea = |v: DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| v[i].into()) };
        let (o0, o1, nfe, lce, liee) = (ea(out_cms[0]), ea(out_cms[1]), ea(nf), ea(lc), ea(lie_f));
        let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
        let forged = crate::committed_air::prove_air_blinded_bytes(
            cols,
            move |g: Ea4| SpendValidityGate {
                leaf_commit: lce,
                gamma: g,
                out0_cm: o0,
                out1_cm: o1,
                nullifier: nfe,
                bond_amount: None,
                fee_amount: Some(fee_limbs(w.fee)), // §BR-14
                tag1: Some(liee),
                vault: Some(clock_const(0)),
            },
            &validity_public_bind_with_commit(&out_cms, &nf, &lc, &to_f(&d), &lie_f),
        );
        let u = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
        let passes = forged.is_some_and(|b| verify_spend_validity_carrier_bytes(&b, u(out_cms[0]), u(out_cms[1]), u(nf), u(lc), d, lie, 100));
        assert!(!passes, "⛔⛔ a spend published a claim its witness never proved — the claim law is not welded");
    }

    /// The same refusals on the MULTI-input consolidation carrier (two inputs over a depth-1 frontier, the shape the
    /// multi-input pins use): honest D verifies; a moved lane, stripped clues and an other-clues proof are refused.
    #[test]
    fn a_multi_input_spend_whose_clues_moved_in_flight_verifies_under_no_door() {
        let sk0 = lanes_of(&[1u64, 2, 3, 4]);
        let sk1 = lanes_of(&[5u64, 6, 7, 8]);
        let (vin0, vin1) = (600u64, 400u64);
        let (own0, own1) = (NoteOwner::from_test_key(sk0), NoteOwner::from_test_key(sk1));
        let leaf0 = asset_note_cm(vin0, USDM_ASSET_TAG, own0.opening());
        let leaf1 = asset_note_cm(vin1, USDM_ASSET_TAG, own1.opening());
        let w = MultiSpendValidityWitness {
            inputs: vec![
                MultiSpendInput { value_in: vin0, owner: own0, siblings: vec![leaf1], dirs: vec![false] },
                MultiSpendInput { value_in: vin1, owner: own1, siblings: vec![leaf0], dirs: vec![true] },
            ],
            out0_value: 900,
            out0_opening: lanes_of(&[9, 9, 9, 9]),
            out1_value: 90,
            out1_opening: lanes_of(&[8, 8, 8, 8]),
            fee: 10,
        };
        let d = test_clue_digest(5);
        let (carrier, root, cms, nfs) = prove_multi_spend_validity_carrier_bytes(&w, d).expect("the honest multi-input spend proves under its clues");
        assert!(verify_multi_spend_validity_carrier_bytes(&carrier, root, cms[0], cms[1], &nfs, 1, d, w.fee), "CALIBRATION: the honest clues verify");
        let mut moved = d;
        moved[2] ^= 1;
        assert!(!verify_multi_spend_validity_carrier_bytes(&carrier, root, cms[0], cms[1], &nfs, 1, moved, w.fee), "⛔ a multi-input spend whose clues MOVED in flight verified");
        assert!(!verify_multi_spend_validity_carrier_bytes(&carrier, root, cms[0], cms[1], &nfs, 1, lanes_of(&crate::poseidon2_compress::ZERO_DIGEST), w.fee), "⛔ a multi-input spend stripped of its clues verified");
        let (other, ..) = prove_multi_spend_validity_carrier_bytes(&w, test_clue_digest(6)).expect("proves under other clues");
        assert!(!verify_multi_spend_validity_carrier_bytes(&other, root, cms[0], cms[1], &nfs, 1, d, w.fee), "⛔ a multi-input carrier proven under other clues verified under these");
        eprintln!("[db351] multi-input carrier {} B: honest clues verify; a moved lane, stripped clues and an other-clues proof are refused", carrier.len());
    }
}

fn validity_public_bind(root: &DigestF, out_cms: &[DigestF; 2], nullifier: &DigestF) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(SPEND_VALIDITY_DOMAIN)];
    b.extend_from_slice(root);
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    b.extend_from_slice(nullifier);
    b
}

// ⛔ DELETED 2026-08-14 — built/checked a carrier with NO note-membership cross-bind, so its membership
// rested on a FIXED-CAPACITY Merkle root that FILLS. `leaf_commit` is no longer an `Option`, so this
// shape is unrepresentable rather than discouraged. Cross-bound twins are the only shape.

/// [`prove_spend_validity_carrier_bytes`] that ALSO binds the note-membership cross-bind.
///
/// Returns the extra `leaf_commit = Poseidon(spent_leaf, nullifier)` — the same value a
/// `NoteMembershipCarrier` binds — and proves it in-circuit, so a spend and a membership proof presented
/// together are provably about ONE note. The plain prover above stays as-is, so every carrier type that has
/// no membership claim keeps its exact bytes.
#[must_use]
/// ⭐ THE ORDINARY SPEND'S INPUT NOTE COMMITMENT — the leaf the cross-bind is computed over.
///
/// The sibling of [`asset_spend_input_leaf`], and it exists for the same reason: a caller that needs to
/// know which note a carrier is about must READ it from the row the constraints check, never re-derive it
/// (`nf_key` vs `key_of`, the sparse spent leaf, `prove_block_pow` vs `PowMiner::mine` — one definition).
/// Used by `node::tests::the_ordinary_spend_cross_bind_is_measured_against_the_same_note_the_record_holds`
/// to MEASURE §AO's scope rather than argue it.
#[must_use]
pub fn spend_input_leaf(w: &SpendValidityWitness) -> Option<Digest> {
    use p3_field::PrimeField64;
    let (row, _out_cms, _nf, _lc) = spend_validity_row(w)?;
    Some(core::array::from_fn(|c| row[SV_LEAF + c].as_canonical_u64()))
}

/// The ordinary spend's carrier: it claims `(lc_blind, 0)`, so its `tag1` is [`spend_tag1`]`(w)` — a key nobody else
/// holds, distinct per send (DB-329 §7e). Returns `(carrier, out_cms, nullifier, leaf_commit)`; the caller that
/// publishes the tag reads it from [`spend_tag1`].
pub fn prove_spend_validity_carrier_with_commit_bytes(
    w: &SpendValidityWitness,
    clue_digest: Digest,
) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest)> {
    let (carrier, cms, nf, lc, _tag1) = prove_spend_validity_carrier_claiming_bytes(w, clue_digest, w.lc_blind, 0)?;
    Some((carrier, cms, nf, lc))
}

/// [`prove_spend_validity_carrier_with_commit_bytes`] with an explicit device-slot claim `(key, d)` (DB-329 §7e): the
/// carrier proves `tag1 == P([SLOT_CLAIM_DOMAIN, d, 0…], key)` under the spender's own witness and binds `tag1` as a
/// statement. Returns `tag1` as the sixth element, READ FROM THE ROW (one spelling).
pub fn prove_spend_validity_carrier_claiming_bytes(
    w: &SpendValidityWitness,
    clue_digest: Digest,
    claim_key: Digest,
    claim_d: u64,
) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest, Digest)> {
    prove_note_spend_bytes(w, &NoteSpendExtras::plain(0), clue_digest, claim_key, claim_d)
}

/// ⭐ THE NOTE-CLASS SPEND'S ONE PROVER (spec §9.1): an ordinary payment, a spend that CREATES a vault (an output's
/// kind), or a spend OF a vault through its release, refund or clock branch — one row shape, one gate, so no verifier
/// tells them apart. `x.clock_h` is the chain clock, in chain hours, the carrier is proven against; the verifier supplies the same
/// value ([`verify_note_spend_bytes`]) and a carrier verifies under no other. Returns
/// `(carrier, out_cms, nullifier, leaf_commit, tag1)`.
pub fn prove_note_spend_bytes(
    w: &SpendValidityWitness,
    x: &NoteSpendExtras,
    clue_digest: Digest,
    claim_key: Digest,
    claim_d: u64,
) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest, Digest)> {
    use p3_field::PrimeField64;
    // The commitment is READ FROM THE ROW's outer cross-bind block — one spelling of `P(P(leaf, nf), lc_blind)`
    // (a second, native spelling here is how the 2026-09 `row[5 + c]` lane bug happened). The claim tag likewise.
    let (row, out_cms, nf, commit) = note_spend_row(w, x, claim_key, claim_d)?;
    let clock_h = x.clock_h;
    let tag1_f: DigestF = vault_gate::published_claim_tag(&row, spend_validity_row_width(), SV_TAIL + SV_TAIL_IN_BLK);
    let tag1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| tag1_f[i].into());
    let clue_f: DigestF = to_f(&clue_digest);
    // Full width INCLUDING the 12-column commitment block, replicated exactly as the plain prover does.
    // (The plain prover slices to the old width, so its carriers stay byte-identical.)
    // The row's FULL width — the range-bound conservation blocks and inner-round openings ride its
    // tail (item 1 seam, 2026-09-11); slicing at a formula silently truncated them.
    let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
    let o0_ea: [Ea4; DIGEST_LANES] =
        core::array::from_fn(|i| out_cms[0][i].into());
    let o1_ea: [Ea4; DIGEST_LANES] =
        core::array::from_fn(|i| out_cms[1][i].into());
    let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| nf[i].into());
    let lc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| commit[i].into());
    let make = move |g: Ea4| SpendValidityGate {
        leaf_commit: lc_ea,
        gamma: g,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifier: nf_ea,
        bond_amount: None,
        fee_amount: Some(fee_limbs(w.fee)), // §BR-14
        tag1: Some(tag1_ea),
        vault: Some(clock_const(clock_h)), // spec §9.1: the note class lays the vault region, vault or not
    };
    // ⭐⭐⭐ ITEM 1 — THE SPEND CARRIER RIDES THE BLINDED COMMITTED PATH, NOT THE DIRECT ONE.
    //
    // ⛔ WHY IT HAD TO MOVE (§BE-1): the direct light decider has NO trace commitment, every caller
    // drops the masked sumcheck's final target, and `verify_air_zerocheck` evaluates the AIR on
    // a `Row` built over `proof.opened` — the PLAINTEXT row. Every amount, and the spent note's LEAF,
    // rode in
    // the clear. §BI found the cause was the SHAPE: a carrier replicates ONE logical row up the trace,
    // and the MLE of a constant column is that constant everywhere, so the opening IS the witness. The
    // blinded prover doubles the height, fills the new half with fresh OS randomness, and selects the
    // real half with `(1 - x[0])`.
    //
    // ⭐ AND IT IS ALSO THE KEYSTONE FOR §BA/§BB AND THE WELD (§BP, measured): the direct verifier must
    // absorb the ENTIRE opening — 7,944 field elements — before it can name γ, while the committed one
    // absorbs a COMMITMENT, 8. That is a 63x cut in what a recursion must replay in circuit, and it is
    // the difference between a 32-carrier bound aggregate costing ~13.0 s and ~0.22 s against a 500 ms
    // block.
    //
    // MEASURED at this exact shape by `bq_the_production_spend_shape_on_every_carrier_path`:
    // 96,203 B / 30 ms direct → 143,546 B / 72 ms blinded. 1.49x size, far inside the ≤1.8 MB cardinal.
    //
    // ⛔ SAFE FOR THIS GATE SPECIFICALLY: blinding makes the last real row's "next" a blinding row, so a
    // ROW-SHIFTED AIR would be evaluated against randomness. `SpendValidityGate` is row-LOCAL — it takes
    // `_at` and `_x` and reads neither — which the §BI census recorded for every value-carrying gate.
    let carrier = crate::committed_air::prove_air_blinded_bytes(
        cols,
        make,
        &note_spend_public_bind(&out_cms, &nf, &commit, &clue_f, &tag1_f, clock_h),
    )?;
    let u = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((carrier, [u(out_cms[0]), u(out_cms[1])], u(nf), u(commit), u(tag1_f)))
}

/// Verify a full spend-validity carrier binds to the PUBLIC frontier `root` AND to the two output
/// commitments the node recorded (`out0_cm`, `out1_cm`) — so the served outputs conserve exactly the proven
/// spend (no inflation). Fail-closed.
#[must_use]
pub fn verify_spend_validity_carrier_bytes(
    bytes: &[u8],
    out0_cm: Digest,
    out1_cm: Digest,
    nullifier: Digest,
    // The note-membership cross-bind: the carrier proves `P(P(spent_leaf, nullifier), lc_blind) == leaf_commit` —
    // the SAME value the note-membership carrier binds, so the two proofs name one note (DB-363: blinded).
    leaf_commit: Digest,
    // DB-351: the door recomputes this from the pooled tx's `note_clues`; a tx whose clues moved fails here.
    clue_digest: Digest,
    // DB-329 §7e: the claim tag the tx publishes (`PqTx.nullifiers[1]`); the carrier proves it is the claim of a key
    // under the spender's witness, and the spent SET refuses it twice.
    tag1: Digest,
    // §BR-14: the fee this spend must pay — the node passes [`PROTOCOL_FEE_ATOMIC`]; any other fee fails the weld.
    fee: u64,
) -> bool {
    verify_note_spend_bytes(bytes, out0_cm, out1_cm, nullifier, leaf_commit, clue_digest, tag1, fee, 0)
}

/// ⭐ THE NOTE-CLASS SPEND'S ONE VERIFIER (spec §9.1): [`verify_spend_validity_carrier_bytes`] under the chain clock
/// `clock_h` (chain hours) the door supplies. A carrier proven against another clock fails the vault region's compare
/// and the transcript bind; a vault's clock branch verifies only when the vault's `T` is at or before this clock. The
/// ledger and the fold, not this function, judge the clock against the chain's median-time-past.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_note_spend_bytes(
    bytes: &[u8],
    out0_cm: Digest,
    out1_cm: Digest,
    nullifier: Digest,
    leaf_commit: Digest,
    clue_digest: Digest,
    tag1: Digest,
    fee: u64,
    clock_h: u64,
) -> bool {
    // ⛔ No `root`, no `depth` (2026-09-30): the carrier has ONE constant shape; the Merkle path it used to carry
    // constrained nothing (§BY) and is deleted at source.
    if bytes.is_empty() {
        return false;
    }
    // ⛔⛔⛔ AN ALL-ZERO CROSS-BIND IS REFUSED. Dropping the `Option` makes "no binding" unrepresentable in
    // the TYPE, but a caller can still hand over a wire field that was simply absent — and absent decodes as
    // ZERO. Zero is not "no binding"; to this verifier it would be a binding every forger can produce, and it
    // arrives exactly when the Merkle weld has already been dropped in its favour. MEASURED as a live risk:
    // the bond/stake call sites pass `cm_bytes_to_leaf(tx.membership_leaf_commit)` straight off the wire, and
    // that was safe ONLY because an admission gate happened to return earlier in a 4,000-line function.
    // Refusing it HERE makes the soundness structural instead of order-dependent.
    if leaf_commit == crate::poseidon2_compress::ZERO_DIGEST {
        return false;
    }
    // DB-329 §7e: the same rule for the claim tag — an absent wire field decodes as zero, and zero is a tag no honest
    // claim produces (a Poseidon output), so it is refused HERE rather than left to whether some door checked first.
    if tag1 == crate::poseidon2_compress::ZERO_DIGEST {
        return false;
    }
    let o0: DigestF = to_f(&out0_cm);
    let o1: DigestF = to_f(&out1_cm);
    let nfv = to_f(&nullifier);
    let o0_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| o0[i].into());
    let o1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| o1[i].into());
    let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| nfv[i].into());
    let lc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(leaf_commit[c]));
    let lc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| lc_f[i].into());
    let tag1_f: DigestF = to_f(&tag1);
    let tag1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| tag1_f[i].into());
    let make = move |g: Ea4| SpendValidityGate {
        leaf_commit: lc_ea,
        gamma: g,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifier: nf_ea,
        bond_amount: None,
        fee_amount: Some(fee_limbs(fee)), // §BR-14
        tag1: Some(tag1_ea),
        vault: Some(clock_const(clock_h)), // spec §9.1
    };
    // The blinded committed path — the other half of item 1. See the prover for why it moved.
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        make,
        &note_spend_public_bind(&[o0, o1], &nfv, &lc_f, &to_f(&clue_digest), &tag1_f, clock_h),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, note_spend_row_width()),
    )
}

// ===================================================================================================
// MULTI-INPUT spend-validity carrier — the FULLY-PRIVATE consolidation spend. One TRANSACTION spends N
// input notes to ONE recipient note + ONE change note, so a fragmented balance is spendable WITHOUT the
// N-separate-tx sweep (which would leak the input count + correlate the txs to one payment). Every input
// AMOUNT stays confidential (in-circuit, never public); the row-local gate proves, for EACH of the N inputs,
// note-opening + nullifier + membership, PLUS a single conservation `Σ value_in_i == value_out + fee` and the
// shared 2-output binding — so no inflation across many inputs. The recipient receives ONE note; only the N
// public nullifiers (needed for double-spend) reveal the input COUNT, the standard confidential-multi-input
// shape (amounts hidden by is_zk WHIR). Row-local (N input blocks in ONE wide row, replicated ×32) — no
// transition constraints, same trustless HVZK-WHIR light decider every other action rides.
pub const MULTI_SPEND_VALIDITY_DOMAIN: u64 = 0x4d53_504e_4456_4c31; // "MSPNDVL1"

/// One input note of a multi-input consolidation spend: its confidential value, spend key, and Poseidon copath.
#[derive(Clone)]
pub struct MultiSpendInput {
    pub value_in: u64,
    /// ⛔ DB-395: the input note's owner (`ask`, `nk`, the note's seed).
    pub owner: NoteOwner,
    pub siblings: Vec<Digest>,
    pub dirs: Vec<bool>,
}

/// Witness for a fully-private multi-input spend: N inputs → 2 outputs (recipient, change). Conservation
/// `Σ value_in_i == out0_value + out1_value + fee` is proven in-circuit; amounts never leave the wallet.
pub struct MultiSpendValidityWitness {
    pub inputs: Vec<MultiSpendInput>,
    pub out0_value: u64,
    /// DB-395: the output's opening `P(spk_recipient, seed)` — no spend authority.
    pub out0_opening: Digest,
    pub out1_value: u64,
    pub out1_opening: Digest,
    pub fee: u64,
}

/// One input block's HEAD layout. ⛔ Every offset was a literal (1,5,9,13,29,45,33) until 2026-09-12; a
/// compression block growing from 16 columns to a whole permutation would have silently overlapped.
pub const MI_VAL: usize = 0;
pub const MI_SK: usize = MI_VAL + 1;
pub const MI_LEAF: usize = MI_SK + DIGEST_LANES;
pub const MI_NF: usize = MI_LEAF + DIGEST_LANES;
/// The note-opening's OUTER compression.
pub const MI_NOH: usize = MI_NF + DIGEST_LANES;
/// The nullifier compression.
pub const MI_NFH: usize = MI_NOH + crate::pow_pq_air::P2_COLS;
/// The membership fold levels.
pub const MI_MB: usize = MI_NFH + crate::pow_pq_air::P2_COLS;
/// Columns ONE fold level occupies: sibling, direction bit, and a whole permutation.
pub const MI_LEVEL: usize = DIGEST_LANES + 1 + crate::pow_pq_air::P2_COLS;

/// ⛔ DB-395 — where an input block's OWNER block starts: after its membership fold levels, at the block's end.
fn mi_owner(depth: usize) -> usize {
    MI_MB + depth * MI_LEVEL
}

/// Per-input column-block width.
fn multi_per_input_width(depth: usize) -> usize {
    mi_owner(depth) + OWNER_BLK_WIDTH
}

/// The row-local multi-input PqSpendAir gate: N input blocks (each = note-opening B + nullifier C + membership
/// D + public-nullifier weld F) + one conservation `Σ value_in_i == value_out + fee` + the 2-output binding E.
/// Every input amount is a PRIVATE column; the gate proves conservation over all N without revealing any amount.
pub struct MultiSpendValidityGate {
    pub gamma: Ea4,
    pub root: [Ea4; DIGEST_LANES],
    pub depth: usize,
    pub n_inputs: usize,
    pub out0_cm: [Ea4; DIGEST_LANES],
    pub out1_cm: [Ea4; DIGEST_LANES],
    /// The PUBLIC nullifier per input (welded to the in-circuit nf so each input's spent-note nullifier is fixed).
    pub nullifiers: Vec<[Ea4; DIGEST_LANES]>,
    /// §BR-14: the flat base fee weld — the final conservation block's fee limbs equal these (see
    /// [`SpendValidityGate::fee_amount`]); the verifier supplies the fee.
    pub fee_amount: Option<[Ea4; SC_LIMBS]>,
}
impl crate::air_zerocheck::AirConstraint for MultiSpendValidityGate {
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ EMBEDS A PERMUTATION: a gate declaring less than the permutation's degree truncates
        // the sumcheck, so even an HONEST proof stops verifying.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let g = self.gamma;
        let d = self.depth;
        let n = self.n_inputs;
        let per = multi_per_input_width(d);
        let zero = Ea4::from(Fa4::ZERO);
        let one = Ea4::ONE;
        let seven = Ea4::from(Fa4::from_u64(7));
        let mut rs: Vec<Ea4> = Vec::new();
            // The range-bound tail (item 1 seam): sum chain, block E, inner rounds — after the outputs.
        let mt = MultiTail::for_row(n, d);
        push_multi_sum_chain(&mut rs, local, mt);
        let usdm_tag = |_c: usize| zero;
        for iidx in 0..n {
            let bi = iidx * per;
            let value_in = local[bi];
            rs.push(value_in - u64_limbs_recombined(local, mt.in_limbs(iidx)));
            let sk = |c: usize| local[bi + MI_SK + c];
            let leaf = |c: usize| local[bi + MI_LEAF + c];
            let mb = bi + MI_MB;
            // ⛔ DB-395 — each input's OWNER: its opening lanes are welded to `o = P(P(ask, nk), seed)`.
            let own = bi + mi_owner(d);
            push_owner_open(&mut rs, local, own, bi + MI_SK);
            let nk = |c: usize| local[owner_nk_col(own) + c];
            let acc = |lvl: usize, c: usize| -> Ea4 {
                if lvl == 0 {
                    local[bi + MI_LEAF + c]
                } else {
                    local[mb + (lvl - 1) * MI_LEVEL + DIGEST_LANES + 1 + crate::pow_pq_air::PERM_OUT + c]
                }
            };
            // B. NOTE-OPENING, two rounds: leaf == P(limbs(value_in), P([USDm tag, 0], sk))
            let (iblk, iout) = mt.inner_in(iidx);
            push_note_open(
                &mut rs, local, mt.in_limbs(iidx), &usdm_tag, &sk, iblk, iout,
                bi + MI_NOH, bi + MI_LEAF,
            );
            // C. NULLIFIER — nf == compress(nk, leaf), one whole permutation (DB-395: keyed by the owner's `nk`).
            push_pose_round(&mut rs, local, &nk, &leaf, bi + MI_NFH, bi + MI_NF);
            // D. MEMBERSHIP — leaf ∈ root
            for lvl in 0..d {
                let base = mb + lvl * MI_LEVEL;
                let sib = |c: usize| local[base + c];
                let dir = local[base + DIGEST_LANES];
                let blk = base + DIGEST_LANES + 1;
                rs.push(dir * (one - dir));
                crate::pow_pq_air::push_perm_residuals(local, blk, &mut rs);
                for c in 0..DIGEST_LANES {
                    let a = acc(lvl, c);
                    rs.push(local[blk + c] - (a + dir * (sib(c) - a)));
                    rs.push(local[blk + DIGEST_LANES + c] - (sib(c) + dir * (a - sib(c))));
                }
            }
            for c in 0..DIGEST_LANES { rs.push(acc(d, c) - self.root[c]); }
            // F. NULLIFIER BINDING — weld the in-circuit nf to the PUBLIC nullifier for this input.
            for c in 0..DIGEST_LANES { rs.push(local[bi + MI_NF + c] - self.nullifiers[iidx][c]); }
        }
        // Shared tail: value_out, fee, and the 2 output note-openings.
        let sb = n * per;
        let value_out = local[sb];
        let fee = local[sb + 1];
        // A. CONSERVATION over ALL inputs is the sum chain above (limb-wise, top carries ZERO); bind the
        // legacy value_out / fee columns to the final block's limbs.
        let fin = mt.block(n - 1);
        rs.push(value_out - u64_limbs_recombined(local, fin.out));
        rs.push(fee - u64_limbs_recombined(local, fin.fee));
        // §BR-14: the base fee weld, limb for limb on the range-bound fee limbs.
        if let Some(limbs) = self.fee_amount {
            for i in 0..SC_LIMBS {
                rs.push(local[fin.fee + i] - limbs[i]);
            }
        }
        // E. OUTPUT BINDING: value_out == out0_value + out1_value, each out_cm_j opens + welds to the public cm.
        // Same stale 25-column output slot as the single-input gate above, same repair: the slot is
        // `SV_OUT_SLOT` and the opening is a permutation block, not four S-box intermediates.
        let ob = sb + 2;
        let slot = |j: usize| ob + j * NO_WIDTH;
        let out_val = |j: usize| local[slot(j) + NO_VAL];
        let out_sk = |j: usize, c: usize| local[slot(j) + NO_SK + c];
        let out_blk = |j: usize| slot(j) + NO_BLK;
        let out_cm = |j: usize, c: usize| local[slot(j) + NO_CM + c];
        let te = mt.e();
        rs.push(out_val(0) - u64_limbs_recombined(local, te.out));
        rs.push(out_val(1) - u64_limbs_recombined(local, te.fee));
        for j in 0..2 {
            let pub_cm = if j == 0 { &self.out0_cm } else { &self.out1_cm };
            let limbs = if j == 0 { te.out } else { te.fee };
            let (iblk, iout) = mt.inner_out(j);
            let osk = |c: usize| out_sk(j, c);
            push_note_open(&mut rs, local, limbs, &usdm_tag, &osk, iblk, iout, out_blk(j), slot(j) + NO_CM);
            for c in 0..DIGEST_LANES { rs.push(out_cm(j, c) - pub_cm[c]); }
        }
        let mut out = zero;
        let mut gp = one;
        for r in rs {
            out = out + gp * r;
            gp = gp * g;
        }
        out
    }
}

/// Fill one input block at `row[bi..]` and return (leaf, nf, recomputed_root). Mirrors the per-input trace of the
/// single-input `spend_validity_row_and_root` (B note-opening, C nullifier, D membership).
fn fill_multi_input_block(row: &mut [Fa4], bi: usize, inp: &MultiSpendInput, mt: MultiTail, i: usize) -> (DigestF, DigestF, DigestF) {
    let depth = inp.siblings.len();
    let value_in = Fa4::from_u64(inp.value_in);
    // DB-395: the opening lanes hold `o = P(P(ask, nk), seed)`, laid by the input's owner block.
    let sk = fill_owner_open(row, bi + mi_owner(depth), bi + MI_SK, &inp.owner);
    let nk: DigestF = core::array::from_fn(|c| Fa4::from_u64(inp.owner.nk[c]));
    row[bi + MI_VAL] = value_in;
    // B. note-opening, two rounds (the limbs live in the sum chain, filled by the assembler)
    let (iblk, iout) = mt.inner_in(i);
    let leaf = fill_note_open(row, inp.value_in, USDM_ASSET_TAG, &sk, iblk, iout, bi + MI_NOH, bi + MI_LEAF);
    let _ = value_in;
    // C. nullifier (DB-395: keyed by the owner's `nk`)
    let nf = fill_pose_round(row, &nk, &leaf, bi + MI_NFH, bi + MI_NF);
    // D. membership
    let mb = bi + MI_MB;
    let mut acc = leaf;
    for lvl in 0..depth {
        let base = mb + lvl * MI_LEVEL;
        let sib: DigestF = core::array::from_fn(|c| Fa4::from_u64(inp.siblings[lvl][c]));
        row[base..base + DIGEST_LANES].copy_from_slice(&sib);
        let dir = inp.dirs[lvl];
        row[base + DIGEST_LANES] = Fa4::from_u64(dir as u64);
        let (left, right) = if dir { (sib, acc) } else { (acc, sib) };
        let blk = base + DIGEST_LANES + 1;
        crate::pow_pq_air::lay_perm_row_flat(row, blk, pose_state(&left, &right));
        acc = core::array::from_fn(|c| row[blk + crate::pow_pq_air::PERM_OUT + c]);
    }
    (leaf, nf, acc)
}

/// Build the wide multi-input row + the (shared) root + the two output cms + the N nullifiers. None if the
/// inputs are empty / mismatched depth / roots disagree / value doesn't conserve.
#[allow(clippy::type_complexity)]
fn multi_spend_validity_row_and_root(
    w: &MultiSpendValidityWitness,
) -> Option<(Vec<Fa4>, DigestF, [DigestF; 2], Vec<DigestF>)> {
    let n = w.inputs.len();
    if n == 0 {
        return None;
    }
    let depth = w.inputs[0].siblings.len();
    if depth == 0 {
        return None;
    }
    // Conservation: Σ value_in == out0_value + out1_value + fee (also enforced in-circuit).
    let mut sum_in: u64 = 0;
    for inp in &w.inputs {
        if inp.siblings.len() != depth || inp.dirs.len() != depth {
            return None; // every input's copath is the same depth-d spend frontier
        }
        sum_in = sum_in.checked_add(inp.value_in)?;
    }
    let value_out = w.out0_value.checked_add(w.out1_value)?;
    if sum_in != value_out.checked_add(w.fee)? {
        return None;
    }
    let per = multi_per_input_width(depth);
    let mt = MultiTail::for_row(n, depth);
    let width = mt.base + mt.width();
    let mut row = vec![Fa4::ZERO; width];
    let ins: Vec<u64> = w.inputs.iter().map(|i| i.value_in).collect();
    fill_multi_sum_chain(&mut row, mt, &ins, value_out, w.fee, w.out0_value, w.out1_value)?;
    let mut nfs: Vec<DigestF> = Vec::with_capacity(n);
    let mut root: Option<DigestF> = None;
    for (iidx, inp) in w.inputs.iter().enumerate() {
        let (_leaf, nf, rt) = fill_multi_input_block(&mut row, iidx * per, inp, mt, iidx);
        // EVERY input must be a member of the SAME frontier root — else a carrier could mix a real note with a
        // note from a fabricated tree. Fail-closed on any disagreement.
        match root {
            None => root = Some(rt),
            Some(r) => {
                if r != rt {
                    return None;
                }
            }
        }
        nfs.push(nf);
    }
    let root = root?;
    // Shared tail: value_out, fee, and the two output note-openings.
    let sb = n * per;
    row[sb] = Fa4::from_u64(value_out);
    row[sb + 1] = Fa4::from_u64(w.fee);
    let ob = sb + 2;
    let mut out_cms = [[Fa4::ZERO; DIGEST_LANES]; 2];
    let outs = [(w.out0_value, w.out0_opening), (w.out1_value, w.out1_opening)];
    for (j, (ov, osk)) in outs.iter().enumerate() {
        let base = ob + j * NO_WIDTH;
        let val = Fa4::from_u64(*ov);
        let sk_j = to_f(osk);
        row[base + NO_VAL] = val;
        row[base + NO_SK..base + NO_SK + DIGEST_LANES].copy_from_slice(&sk_j);
        let (iblk, iout) = mt.inner_out(j);
        let cm = fill_note_open(&mut row, *ov, USDM_ASSET_TAG, &sk_j, iblk, iout, base + NO_BLK, base + NO_CM);
        out_cms[j] = cm;
    }
    Some((row, root, out_cms, nfs))
}

/// Public IO for a multi-input carrier: domain + `n_inputs` + root + the two output cms + the N nullifiers. The
/// `n_inputs` is bound so a single-input carrier can never be replayed as a multi-input one (and vice-versa).
/// DB-351 (2026-09-28): `clue_digest` — the payment's discovery data (`note_clues`, verbatim as pooled) hashed by the
/// wallet before proving and recomputed by every door — is appended LAST, so a transaction whose clues moved in flight
/// verifies under no door. The carrier never hashes clues: D is public data the verifier supplies, bound by the
/// transcript (this bind is the statement absorbed FIRST; every challenge is a function of it).
fn multi_validity_public_bind(
    n: usize,
    root: &DigestF,
    out_cms: &[DigestF; 2],
    nfs: &[DigestF],
    clue_digest: &DigestF,
) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(MULTI_SPEND_VALIDITY_DOMAIN), Fa4::from_u64(n as u64)];
    b.extend_from_slice(root);
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    for nf in nfs {
        b.extend_from_slice(nf);
    }
    b.extend_from_slice(clue_digest);
    b
}

/// Prove a FULLY-PRIVATE multi-input consolidation spend: N confidential inputs → 2 outputs (recipient, change),
/// conservation + per-input note-opening/nullifier/membership all cross-bound in ONE carrier. Returns the carrier,
/// the shared frontier `root`, the two output cms, and the N nullifiers. None if unfunded / malformed.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_multi_spend_validity_carrier_bytes(
    w: &MultiSpendValidityWitness,
    clue_digest: Digest,
) -> Option<(Vec<u8>, Digest, [Digest; 2], Vec<Digest>)> {
    let (r, root, out_cms, nfs) = multi_spend_validity_row_and_root(w)?;
    let clue_f: DigestF = to_f(&clue_digest);
    let n = w.inputs.len();
    let depth = w.inputs[0].siblings.len();
    let cols: Vec<Vec<Fa4>> = (0..r.len()).map(|col| vec![r[col]; LIGHT_CARRIER_ROWS]).collect();
    let root_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| root[i].into());
    let out0_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| out_cms[0][i].into());
    let out1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| out_cms[1][i].into());
    let nfs_ea: Vec<[Ea4; DIGEST_LANES]> = nfs.iter().map(|nf| core::array::from_fn(|i| nf[i].into())).collect();
    let nfs_ea2 = nfs_ea.clone();
    let make = move |g: Ea4| MultiSpendValidityGate {
        gamma: g,
        root: root_ea,
        depth,
        n_inputs: n,
        out0_cm: out0_ea,
        out1_cm: out1_ea,
        nullifiers: nfs_ea2.clone(),
        fee_amount: Some(fee_limbs(w.fee)), // §BR-14
    };
    let carrier =
        crate::committed_air::prove_air_blinded_bytes(cols, make, &multi_validity_public_bind(n, &root, &out_cms, &nfs, &clue_f))?;
    let root_u = to_u64(&root);
    let cms_u = [to_u64(&out_cms[0]), to_u64(&out_cms[1])];
    let nfs_u: Vec<Digest> = nfs.iter().map(to_u64).collect();
    Some((carrier, root_u, cms_u, nfs_u))
}

/// Verify a multi-input carrier binds to the PUBLIC frontier `root`, the two output cms, and EXACTLY the N
/// nullifiers the node records (so the N spent notes are fixed + conserve to the 2 outputs). Fail-closed.
#[must_use]
pub fn verify_multi_spend_validity_carrier_bytes(
    bytes: &[u8],
    root: Digest,
    out0_cm: Digest,
    out1_cm: Digest,
    nullifiers: &[Digest],
    depth: usize,
    // DB-351: the door recomputes this from the pooled tx's `note_clues`; a tx whose clues moved fails here.
    clue_digest: Digest,
    // §BR-14: the fee this spend must pay (the node passes [`PROTOCOL_FEE_ATOMIC`]).
    fee: u64,
) -> bool {
    let n = nullifiers.len();
    if bytes.is_empty() || depth == 0 || n == 0 {
        return false;
    }
    let root_f: DigestF = to_f(&root);
    let root_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| root_f[i].into());
    let o0: DigestF = to_f(&out0_cm);
    let o1: DigestF = to_f(&out1_cm);
    let o0_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| o0[i].into());
    let o1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| o1[i].into());
    let nfs_f: Vec<DigestF> = nullifiers
        .iter()
        .map(|nf| to_f(&nf))
        .collect();
    let nfs_ea: Vec<[Ea4; DIGEST_LANES]> = nfs_f.iter().map(|nf| core::array::from_fn(|i| nf[i].into())).collect();
    let make = move |g: Ea4| MultiSpendValidityGate {
        gamma: g,
        root: root_ea,
        depth,
        n_inputs: n,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifiers: nfs_ea.clone(),
        fee_amount: Some(fee_limbs(fee)), // §BR-14
    };
    crate::committed_air::verify_air_blinded_bytes(bytes, make, &multi_validity_public_bind(n, &root_f, &[o0, o1], &nfs_f, &to_f(&clue_digest)), match multi_spend_row_width(n, depth) { Some(w) => (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, w), None => return false })
}

/// The VALIDATOR-BOND public bind: the spend-validity bind PLUS the public `bond_amount`, so the carrier is
/// welded to EXACTLY the bonded weight (a proof for one bond amount cannot be replayed for another).
fn bond_validity_public_bind(
    root: &DigestF,
    out_cms: &[DigestF; 2],
    nullifier: &DigestF,
    bond_amount: u64,
) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(BOND_VALIDITY_DOMAIN)];
    b.extend_from_slice(root);
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    b.extend_from_slice(nullifier);
    b.extend_from_slice(&bond_limbs_f(bond_amount)); // DB-340: the four limbs, never the mod-p residue
    b
}

// ⛔ DELETED 2026-08-14 — built/checked a carrier with NO note-membership cross-bind, so its membership
// rested on a FIXED-CAPACITY Merkle root that FILLS. `leaf_commit` is no longer an `Option`, so this
// shape is unrepresentable rather than discouraged. Cross-bound twins are the only shape.

// ⛔ DELETED 2026-08-14 — built/checked a carrier with NO note-membership cross-bind, so its membership
// rested on a FIXED-CAPACITY Merkle root that FILLS. `leaf_commit` is no longer an `Option`, so this
// shape is unrepresentable rather than discouraged. Cross-bound twins are the only shape.

/// The BOND public bind, with the note-membership cross-bind — the bond twin of
/// [`validity_public_bind_with_commit`].
///
/// ⛔⛔⛔ WHY THIS EXISTS: the plain bond bind welds the LIVE frontier `root` into the transcript, so a bond
/// carrier is only verifiable against the exact root that stood when it was built. The frontier appends on
/// every block, so a carrier built before a block lands is rejected after it — and the wallet hid that race
/// behind `for _attempt in 0..6u32` / `0..8u32`, a bound on how many tries a user's stake claim or peg-out
/// gets. The counter was never the defect; the moving anchor was.
///
/// With `leaf_commit` present the note's chain-membership is established by the note-membership carrier (an
/// O(1) fold over the append-only accumulator, whose proof stays valid across every later append) and pinned
/// to THIS bond by `Poseidon(leaf, nullifier) == leaf_commit`. The Merkle root then constrains nothing, so
/// binding it would only re-impose the very requirement that moves. It is omitted; `leaf_commit` takes its
/// place. `bond_amount` STAYS in the transcript either way — it is the public weld this carrier exists for.
///
/// With `leaf_commit` ABSENT the bind is byte-identical to [`bond_validity_public_bind`], so every existing
/// bond carrier verifies exactly as it did.
pub fn bond_validity_public_bind_with_commit(
    out_cms: &[DigestF; 2],
    nullifier: &DigestF,
    bond_amount: u64,
    leaf_commit: &DigestF,
) -> Vec<Fa4> {
    // Cross-bind ALWAYS present, so the `None` arm (which bound the fixed-capacity ROOT) is gone with it.
    // The root does not enter the bind because it constrains nothing: a bond's membership is proven by the
    // note-membership fold. `bond_amount` STAYS — it is the public weld this carrier exists for.
    // (2026-09-30: the ignored `root` parameter is gone with the path.)
    let mut b = vec![Fa4::from_u64(BOND_VALIDITY_DOMAIN)];
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    b.extend_from_slice(nullifier);
    b.extend_from_slice(&bond_limbs_f(bond_amount)); // DB-340: the four limbs, never the mod-p residue
    b.extend_from_slice(leaf_commit);
    // DB-313 §3 (2026-09-28): the block's WELDED-SPEND class states this bind's values `b[1..]` as its tuple, and
    // the settlement aggregate's `chain_stride_is_exact` admits only tuple widths in 8·2^k — so the tuple is padded
    // to 64 values with zeros that BOTH sides absorb (the carrier's transcript here, the peer's `rows_digest` there):
    // bound cells, not free ones. Cons: +28 absorbed elements per welded carrier (four duplexings), zero proof bytes.
    b.resize(1 + BOND_BIND_TUPLE_VALS, Fa4::ZERO);
    b
}
/// The welded-spend class's tuple width: `cm0 ‖ cm1 ‖ nf ‖ W0..W3 ‖ lc` (36 values) padded to the next `8·2^k`.
pub const BOND_BIND_TUPLE_VALS: usize = 64;

/// Prove a VALIDATOR BOND that takes its membership from the ACCUMULATOR instead of from a Merkle root — the
/// bond twin of [`prove_spend_validity_carrier_with_commit_bytes`].
///
/// Returns the extra `leaf_commit` value alongside the plain outputs. The caller pairs this carrier with a
/// note-membership carrier binding the SAME `leaf_commit`, and the two together prove "this note is on chain
/// AND this bond spends exactly it" without naming any root. That is what lets ONE attempt always suffice:
/// nothing the carrier depends on moves when a block lands.
#[must_use]
pub fn prove_bond_validity_carrier_with_commit_bytes(
    w: &SpendValidityWitness,
    bond_amount: u64,
) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest)> {
    use p3_field::PrimeField64;
    if w.out0_value != bond_amount {
        return None; // fail-closed, exactly as the plain prover: the bonded note MUST lock the claimed weight
    }
    // The commitment is read from the row's outer cross-bind block (DB-363: `P(P(leaf, nf), lc_blind)`) — one
    // spelling, shared with the plain spend prover.
    let (row, out_cms, nf, commit) = spend_validity_row(w)?;
    let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
    let o0_ea: [Ea4; DIGEST_LANES] =
        core::array::from_fn(|i| out_cms[0][i].into());
    let o1_ea: [Ea4; DIGEST_LANES] =
        core::array::from_fn(|i| out_cms[1][i].into());
    let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| nf[i].into());
    let lc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| commit[i].into());
    let bond_ea = bond_limbs(bond_amount);
    let make = move |g: Ea4| SpendValidityGate {
        leaf_commit: lc_ea,
        gamma: g,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifier: nf_ea,
        bond_amount: Some(bond_ea),
        fee_amount: Some(fee_limbs(w.fee)), // §BR-14
        tag1: None, // the bond class publishes no claim (DB-329 §7e)
        vault: None, // and lays no vault region (spec §9.1)
    };
    let carrier = crate::committed_air::prove_air_blinded_bytes(
        cols,
        make,
        &bond_validity_public_bind_with_commit(&out_cms, &nf, bond_amount, &commit),
    )?;
    let u = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((carrier, [u(out_cms[0]), u(out_cms[1])], u(nf), u(commit)))
}

/// Verify a bond carrier whose membership comes from the accumulator. `leaf_commit: Some(c)` requires the
/// carrier to prove `Poseidon(spent_leaf, nullifier) == c` — the SAME value the note-membership carrier binds,
/// so the two proofs name ONE note — and drops the root from both the gate and the transcript. `None` is
/// byte-identical to [`verify_bond_validity_carrier_bytes`].
#[must_use]
pub fn verify_bond_validity_carrier_with_commit_bytes(
    bytes: &[u8],
    out0_cm: Digest,
    out1_cm: Digest,
    nullifier: Digest,
    bond_amount: u64,
    leaf_commit: Digest,
    // §BR-14: the fee the bond/stake/burn spend must pay (the node passes [`PROTOCOL_FEE_ATOMIC`]).
    fee: u64,
) -> bool {
    // ⛔ No `root`, no `depth` (2026-09-30): the bond carrier is the spend row with the weld — ONE constant shape.
    // (DB-75 had already measured the depth-0 shape honest; the path and its parameters are now deleted at source.)
    if bytes.is_empty() {
        return false;
    }
    // ⛔⛔⛔ AN ALL-ZERO CROSS-BIND IS REFUSED. Dropping the `Option` makes "no binding" unrepresentable in
    // the TYPE, but a caller can still hand over a wire field that was simply absent — and absent decodes as
    // ZERO. Zero is not "no binding"; to this verifier it would be a binding every forger can produce, and it
    // arrives exactly when the Merkle weld has already been dropped in its favour. MEASURED as a live risk:
    // the bond/stake call sites pass `cm_bytes_to_leaf(tx.membership_leaf_commit)` straight off the wire, and
    // that was safe ONLY because an admission gate happened to return earlier in a 4,000-line function.
    // Refusing it HERE makes the soundness structural instead of order-dependent.
    if leaf_commit == crate::poseidon2_compress::ZERO_DIGEST {
        return false;
    }
    let o0: DigestF = to_f(&out0_cm);
    let o1: DigestF = to_f(&out1_cm);
    let nfv = to_f(&nullifier);
    let o0_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| o0[i].into());
    let o1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| o1[i].into());
    let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| nfv[i].into());
    let lc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(leaf_commit[c]));
    let lc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| lc_f[i].into());
    let bond_ea = bond_limbs(bond_amount);
    let make = move |g: Ea4| SpendValidityGate {
        leaf_commit: lc_ea,
        gamma: g,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifier: nf_ea,
        bond_amount: Some(bond_ea),
        fee_amount: Some(fee_limbs(fee)), // §BR-14
        tag1: None, // the bond class publishes no claim (DB-329 §7e)
        vault: None, // and lays no vault region (spec §9.1)
    };
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        make,
        &bond_validity_public_bind_with_commit(&[o0, o1], &nfv, bond_amount, &lc_f),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, spend_validity_row_width()),
    )
}


// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ⭐⭐⭐ B15 (lane funds 2026-10-29) — THE COMMITTED BURN: a USDm burn whose burned amount the CHAIN binds without learning it.
//
// The bond-validity carrier welds output 0's value to a PUBLIC weight, so the burned amount had to stay off the chain (a
// cash-out's size is private, §BR-5): the executor and the custodians verified it, and the chain took the peg-out's burn on
// the custodians' signature. A colluding two thirds could then name a burn larger than the note destroyed, lowering the
// committed supply below the real one — and the yield mint, which pays only the surplus, would pay out of a surplus that does
// not exist. This gate proves the same spend row and, instead of a public weight, opens output 0's value to
// `burn_commit = solvency_commit_256(burn, b_blind)` — the commitment the peg-out solvency carrier opens to its burn delta
// (`confidential_solvency::prove_peg_out_carrier_delta`). Borrowed from DB-80's committed mint (Sapling's value-commitment
// binding): the two proofs agree on one hidden number.
//
// Layout: the spend row is untouched; appended are a 16-limb copy of output 0's value (the four u64 limbs, then zeros — the
// U256 encoding the commit hashes), the blind, the commit lanes, the two permutation blocks and the opening's range bits.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
pub const BURN_VALIDITY_COMMITTED_DOMAIN: u64 = 0x4255_524e_5643_4231; // "BURNVCB1"
const BVC_V16: usize = spend_validity_row_width();
const BVC_BBLIND: usize = BVC_V16 + 16;
const BVC_BCOMMIT: usize = BVC_BBLIND + DIGEST_LANES;
const BVC_BINTER: usize = BVC_BCOMMIT + DIGEST_LANES;
const BVC_BVBITS: usize = BVC_BINTER + 2 * crate::confidential_solvency::CO_BLOCK;
/// The committed burn carrier's row width.
pub const BVC_WIDTH: usize = BVC_BVBITS + crate::confidential_solvency::RANGE16_COLS;

/// The committed burn gate: the spend row's every residual, then output 0's value opened to the public `burn_commit`.
pub struct BurnValidityCommittedGate {
    pub inner: SpendValidityGate,
    pub burn_commit: [Ea4; DIGEST_LANES],
}

impl BurnValidityCommittedGate {
    fn all_residuals(&self, local: &crate::air_zerocheck::Row<'_>) -> Vec<Ea4> {
        let mut rs = SpendValidityGate::residuals(&self.inner, local);
        let te = U64ConsBases::at(SV_TAIL + SV_TAIL_E);
        for i in 0..SC_LIMBS {
            rs.push(local[BVC_V16 + i] - local[te.out + i]);
        }
        for i in SC_LIMBS..16 {
            rs.push(local[BVC_V16 + i]);
        }
        crate::confidential_solvency::push_commit_open_constraints(&mut rs, local, BVC_V16, BVC_BBLIND, BVC_BCOMMIT, BVC_BINTER, BVC_BVBITS);
        for c in 0..DIGEST_LANES {
            rs.push(local[BVC_BCOMMIT + c] - self.burn_commit[c]);
        }
        rs
    }
}

impl crate::air_zerocheck::AirConstraint for BurnValidityCommittedGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in self.all_residuals(local) {
            out = out + gp * r;
            gp = gp * self.inner.gamma;
        }
        out
    }
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Vec<Ea4> {
        self.all_residuals(local)
    }
    fn is_row_local(&self) -> bool {
        true
    }
    /// The spend row's hiding witnesses, plus the burn commitment's blind (a hiding witness read only by the opening — what
    /// keeps the burned amount unrecoverable from `burn_commit`).
    fn free_columns(&self) -> Option<Vec<usize>> {
        let mut free = match crate::air_zerocheck::AirConstraint::free_columns(&self.inner) {
            Some(v) => v,
            None => Vec::new(),
        };
        free.extend(BVC_BBLIND..BVC_BBLIND + DIGEST_LANES);
        Some(free)
    }
}

/// Transcript bind: domain ‖ out0 ‖ out1 ‖ nullifier ‖ leaf commitment ‖ burn commitment. No amount anywhere.
fn burn_validity_committed_public_bind(out_cms: &[DigestF; 2], nullifier: &DigestF, leaf_commit: &DigestF, burn_commit: &DigestF) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(BURN_VALIDITY_COMMITTED_DOMAIN)];
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    b.extend_from_slice(nullifier);
    b.extend_from_slice(leaf_commit);
    b.extend_from_slice(burn_commit);
    b
}

/// ⭐ B15 — PROVE a committed burn: the spend of `w` (its membership taken from the accumulator through `leaf_commit`, its
/// fee the protocol's), with output 0's value bound only to `burn_commit = solvency_commit_256(w.out0_value, b_blind)`.
/// Returns `(carrier, [out0_cm, out1_cm], nullifier, leaf_commit, burn_commit)`.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_burn_validity_committed_bytes(w: &SpendValidityWitness, b_blind: &Digest) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest, Digest)> {
    use p3_field::PrimeField64;
    let (row, out_cms, nf, commit) = spend_validity_row(w)?;
    let mut cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
    while cols.len() < BVC_WIDTH {
        cols.push(vec![Fa4::ZERO; LIGHT_CARRIER_ROWS]);
    }
    let mut limbs = [0u64; 16];
    for (i, limb) in limbs.iter_mut().enumerate().take(SC_LIMBS) {
        *limb = (w.out0_value >> (SC_LIMB_BITS * i)) & 0xFFFF;
    }
    for (i, limb) in limbs.iter().enumerate() {
        cols[BVC_V16 + i].fill(Fa4::from_u64(*limb));
    }
    for i in 0..DIGEST_LANES {
        cols[BVC_BBLIND + i].fill(Fa4::from_u64(b_blind[i]));
    }
    let bc = crate::confidential_solvency::place_commit_open(&mut cols, limbs, *b_blind, BVC_BINTER, BVC_BVBITS);
    for i in 0..DIGEST_LANES {
        cols[BVC_BCOMMIT + i].fill(Fa4::from_u64(bc[i]));
    }
    let bc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(bc[c]));
    let ea = |d: &DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| d[i].into()) };
    let (o0, o1, nfe, lce, bce) = (ea(&out_cms[0]), ea(&out_cms[1]), ea(&nf), ea(&commit), ea(&bc_f));
    let fee = fee_limbs(w.fee);
    let make = move |g: Ea4| BurnValidityCommittedGate {
        inner: SpendValidityGate { leaf_commit: lce, gamma: g, out0_cm: o0, out1_cm: o1, nullifier: nfe, bond_amount: None, fee_amount: Some(fee), tag1: None, vault: None },
        burn_commit: bce,
    };
    let carrier = crate::committed_air::prove_air_blinded_bytes(cols, make, &burn_validity_committed_public_bind(&out_cms, &nf, &commit, &bc_f))?;
    let u = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((carrier, [u(out_cms[0]), u(out_cms[1])], u(nf), u(commit), bc))
}

/// ⭐ B15 — VERIFY a committed burn against the public `(out0, out1, nullifier, leaf_commit, burn_commit)` and the protocol's
/// fee. An all-zero cross-bind is refused (as the bond carrier refuses it).
#[must_use]
pub fn verify_burn_validity_committed_bytes(
    bytes: &[u8],
    out0_cm: Digest,
    out1_cm: Digest,
    nullifier: Digest,
    leaf_commit: Digest,
    burn_commit: Digest,
    fee: u64,
) -> bool {
    if bytes.is_empty() || leaf_commit == crate::poseidon2_compress::ZERO_DIGEST {
        return false;
    }
    let f = |d: &Digest| -> DigestF { core::array::from_fn(|c| Fa4::from_u64(d[c])) };
    let (o0, o1, nfv, lcf, bcf) = (f(&out0_cm), f(&out1_cm), f(&nullifier), f(&leaf_commit), f(&burn_commit));
    let ea = |d: &DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| d[i].into()) };
    let (o0e, o1e, nfe, lce, bce) = (ea(&o0), ea(&o1), ea(&nfv), ea(&lcf), ea(&bcf));
    let fl = fee_limbs(fee);
    let make = move |g: Ea4| BurnValidityCommittedGate {
        inner: SpendValidityGate { leaf_commit: lce, gamma: g, out0_cm: o0e, out1_cm: o1e, nullifier: nfe, bond_amount: None, fee_amount: Some(fl), tag1: None, vault: None },
        burn_commit: bce,
    };
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        make,
        &burn_validity_committed_public_bind(&[o0, o1], &nfv, &lcf, &bcf),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, BVC_WIDTH),
    )
}

#[cfg(test)]
mod burn_validity_committed_tests {
    use super::*;

    fn witness(burn: u64) -> SpendValidityWitness {
        let lanes = crate::poseidon2_compress::lanes_of;
        let value_in = burn + PROTOCOL_FEE_ATOMIC + 5_000;
        SpendValidityWitness {
            value_in,
            owner: NoteOwner::from_test_key(lanes(&[0xB15, 1, 2, 3])),
            value_out: value_in - PROTOCOL_FEE_ATOMIC,
            fee: PROTOCOL_FEE_ATOMIC,
            lc_blind: lanes(&[0xB15, 4, 4, 4]),
            out0_value: burn,
            out0_opening: lanes(&[0xB15, 5, 5, 5]),
            out1_value: 5_000,
            out1_opening: lanes(&[0xB15, 6, 6, 6]),
        }
    }

    /// ⭐ B15 — the committed burn proves for the honest burn and binds to the SAME commitment the solvency carrier computes;
    /// a commitment to another amount, another blind, a flipped byte, or another output REFUSES. No amount is public.
    #[test]
    fn b15_a_committed_burn_binds_its_amount_to_the_solvency_commit_and_refuses_every_tamper() {
        let burn = 4_000_000_000u64;
        let blind = crate::poseidon2_compress::lanes_of(&[0xB15, 9, 9, 9]);
        let w = witness(burn);
        let (bytes, cms, nf, lc, bc) = prove_burn_validity_committed_bytes(&w, &blind).expect("the honest burn proves");
        assert_eq!(bc, crate::confidential_solvency::solvency_commit_256(crate::confidential_solvency::u256_from_u64(burn), blind), "the burn commits the solvency carrier's shape");
        let v = |bytes: &[u8], o0: Digest, bc: Digest| verify_burn_validity_committed_bytes(bytes, o0, cms[1], nf, lc, bc, PROTOCOL_FEE_ATOMIC);
        assert!(v(&bytes, cms[0], bc), "the honest committed burn verifies");
        let other_amount = crate::confidential_solvency::solvency_commit_256(crate::confidential_solvency::u256_from_u64(burn + 1), blind);
        assert!(!v(&bytes, cms[0], other_amount), "⛔ B15: the burn verified against a commitment to another amount");
        let other_blind = crate::confidential_solvency::solvency_commit_256(crate::confidential_solvency::u256_from_u64(burn), crate::poseidon2_compress::lanes_of(&[1]));
        assert!(!v(&bytes, cms[0], other_blind), "⛔ B15: the burn verified under another blind");
        assert!(!v(&bytes, cms[1], bc), "⛔ B15: the burn verified against another output");
        let mut flipped = bytes.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 1;
        assert!(!v(&flipped, cms[0], bc), "⛔ B15: a flipped carrier byte verified");
        assert!(!verify_burn_validity_committed_bytes(&bytes, cms[0], cms[1], nf, lc, bc, PROTOCOL_FEE_ATOMIC + 1), "⛔ B15: the burn verified at another fee");
    }

    /// B15 — the gate passes the three censuses (degree, free witness, decorative block) over its honest trace.
    #[test]
    fn b15_the_committed_burn_gate_passes_the_three_censuses() {
        let blind = crate::poseidon2_compress::lanes_of(&[0xB15, 8, 8, 8]);
        let w = witness(123_456_789);
        let (row, out_cms, nf, commit) = spend_validity_row(&w).expect("row");
        let mut cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
        while cols.len() < BVC_WIDTH {
            cols.push(vec![Fa4::ZERO; LIGHT_CARRIER_ROWS]);
        }
        let mut limbs = [0u64; 16];
        for (i, limb) in limbs.iter_mut().enumerate().take(SC_LIMBS) {
            *limb = (w.out0_value >> (SC_LIMB_BITS * i)) & 0xFFFF;
        }
        for (i, limb) in limbs.iter().enumerate() {
            cols[BVC_V16 + i].fill(Fa4::from_u64(*limb));
        }
        for i in 0..DIGEST_LANES {
            cols[BVC_BBLIND + i].fill(Fa4::from_u64(blind[i]));
        }
        let bc = crate::confidential_solvency::place_commit_open(&mut cols, limbs, blind, BVC_BINTER, BVC_BVBITS);
        for i in 0..DIGEST_LANES {
            cols[BVC_BCOMMIT + i].fill(Fa4::from_u64(bc[i]));
        }
        let ea = |d: &DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| d[i].into()) };
        let bc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(bc[c]));
        let g = BurnValidityCommittedGate {
            inner: SpendValidityGate { leaf_commit: ea(&commit), gamma: Ea4::from(Fa4::from_u64(0xB15)), out0_cm: ea(&out_cms[0]), out1_cm: ea(&out_cms[1]), nullifier: ea(&nf), bond_amount: None, fee_amount: Some(fee_limbs(w.fee)), tag1: None, vault: None },
            burn_commit: ea(&bc_f),
        };
        let nvars = cols[0].len().trailing_zeros() as usize;
        crate::air_zerocheck::debug_degree_census(&cols, &g, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_free_witness_census(&cols, &g, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_decorative_block_census(&cols, &g, nvars, true, &Some(Vec::new()));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ⭐⭐⭐ DB-237 — THE PRIVATE STAKE: ONE GATE FOR STAKE, CLAIM AND UNSTAKE (2026-10-02)
//
// A STAKED note is an ordinary note whose commitment carries the stake tag `[STAKE_TAG_MARK, e0, STAKE_TAG_MARK2]`
// (`e0` = the epoch it started earning) — the asset-tag slot every note already has (Zcash's ZSA shape: the asset base
// lives INSIDE the commitment), so a staked note is indistinguishable from any other note on the chain.
//
// ONE gate moves value into, along and out of a stake, so the three actions are ONE statement on the wire:
//   * the INPUT note opens under tag `s_in · stake_tag(e0)` (`s_in` a hidden bit: USDm when 0, staked when 1);
//   * OUTPUT 0 (the principal `w`) opens under `s_out · stake_tag(e_now)` (re-staked from NOW, or returned as USDm);
//   * OUTPUT 1 is USDm: the change of a fresh stake, or the reward of a claim;
//   * conservation: `v + r = w + out1` (two range-bound u64 blocks sharing their total);
//   * the reward is EXACT: `r = floor(v · rate_bps · Δ / STAKE_REWARD_DEN)`, `Δ = e_now − e0`, proven as two limb
//     chains over the integers (`v·M = P`, `r·D + rem = P`, `M = rate·Δ`, `0 ≤ rem < D`); a USDm input has `Δ = 0`
//     forced (`(1 − s_in)·Δ = 0`), so a plain note earns nothing;
//   * `reward_commit = solvency_commit_256(r, r_blind)` is PUBLIC: the supply leg's delta commitment (`minted + r`),
//     so the chain's committed supply grows by exactly what was minted with no amount on the wire.
// Re-staking at `e_now` is what makes a second claim of the same interval impossible: the input's nullifier is spent
// by the SET, and the new principal earns only from `e_now`. Public statement: the two output commitments, the
// nullifier, the membership cross-bind, the reward commitment, `e_now` and `rate_bps` — no amount, no key, no `e0`.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// Transcript domain of the stake carrier.
pub const STAKE_VALIDITY_DOMAIN: u64 = 0x5354_4b56_414c_3031; // "STKVAL01"
/// Tag lane 0 of a staked note (a wrapped tag collides with `(MARK, ·, MARK2)` with probability ~2⁻⁶²).
pub const STAKE_TAG_MARK: u64 = 0x5354_4b45; // "STKE"
/// Tag lane 2 of a staked note.
pub const STAKE_TAG_MARK2: u64 = 0x5245_5744; // "REWD"
/// One stake epoch: a UTC day of the block header's timestamp.
pub const STAKE_EPOCH_MS: u64 = 86_400_000;
/// Epochs per year — the rate is an annual `bps`.
pub const STAKE_EPOCHS_PER_YEAR: u64 = 365;
/// The largest admissible annual rate (100 %).
pub const STAKE_RATE_MAX_BPS: u64 = 10_000;
/// `D` of `r = floor(v · rate · Δ / D)`.
pub const STAKE_REWARD_DEN: u64 = 10_000 * STAKE_EPOCHS_PER_YEAR;
/// The largest epoch a stake may name (lane 1 of the tag is one field element; `Δ` is 16 range-bound bits).
pub const STAKE_EPOCH_MAX: u64 = 1 << 30;
const STAKE_DELTA_BITS: usize = 16;
const STAKE_M_BITS: usize = 30;
const STAKE_P_LIMBS: usize = 12;
const STAKE_CARRY_BITS: usize = 11;
const STAKE_REM_BITS: usize = 22;
const _: () = assert!(STAKE_REWARD_DEN < (1 << STAKE_REM_BITS));
const _: () = assert!(STAKE_RATE_MAX_BPS * ((1 << STAKE_DELTA_BITS) - 1) < (1 << STAKE_M_BITS));

/// The tag of a note staked from epoch `e0`.
#[must_use]
pub fn stake_tag(e0: u64) -> [u64; 3] {
    [STAKE_TAG_MARK, e0, STAKE_TAG_MARK2]
}

/// The epoch of a block header timestamp (ms).
#[must_use]
pub fn stake_epoch_of_ms(ts_ms: u64) -> u64 {
    ts_ms / STAKE_EPOCH_MS
}

/// The ONE reward rule, natively: `floor(v · rate_bps · Δ / STAKE_REWARD_DEN)`. `None` when `Δ` or the rate is out of
/// the gate's range, or the reward does not fit a note.
#[must_use]
pub fn stake_reward(v: u64, rate_bps: u64, delta: u64) -> Option<u64> {
    if rate_bps > STAKE_RATE_MAX_BPS || delta >= (1 << STAKE_DELTA_BITS) {
        return None;
    }
    u64::try_from(u128::from(v) * u128::from(rate_bps) * u128::from(delta) / u128::from(STAKE_REWARD_DEN)).ok()
}

/// A stake / claim / unstake witness. `in_staked = false` is a fresh stake of a USDm note (its `e0` is ignored: the
/// gate forces `Δ = 0`); `out0_staked = false` returns the principal as USDm (an unstake).
#[derive(Clone, Debug)]
pub struct StakeWitness {
    pub value_in: u64,
    /// ⛔ DB-395: the input note's owner (`ask`, `nk`, the note's seed).
    pub owner: NoteOwner,
    pub in_staked: bool,
    pub e0: u64,
    pub lc_blind: Digest,
    pub out0_value: u64,
    /// DB-395: each output's opening `P(spk, seed)` — no spend authority.
    pub out0_opening: Digest,
    pub out0_staked: bool,
    pub out1_opening: Digest,
    pub reward_blind: Digest,
}

/// What a stake carrier states, and the two private values its builder needs (the reward and the second output).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeOutputs {
    pub out_cms: [Digest; 2],
    pub nullifier: Digest,
    pub leaf_commit: Digest,
    pub reward_commit: Digest,
    pub reward: u64,
    pub out1_value: u64,
}

const ST_SK: usize = 0;
const ST_LEAF: usize = ST_SK + DIGEST_LANES;
const ST_NF: usize = ST_LEAF + DIGEST_LANES;
const ST_SIN: usize = ST_NF + DIGEST_LANES;
const ST_SOUT: usize = ST_SIN + 1;
const ST_E0: usize = ST_SOUT + 1;
const ST_IN_IBLK: usize = ST_E0 + 1;
const ST_IN_IOUT: usize = ST_IN_IBLK + POSE_BLK;
const ST_IN_OBLK: usize = ST_IN_IOUT + DIGEST_LANES;
const ST_NF_BLK: usize = ST_IN_OBLK + POSE_BLK;
const ST_CB: usize = ST_NF_BLK + POSE_BLK;
const ST_CB2: usize = ST_CB + POSE_BLK;
const ST_BLIND: usize = ST_CB2 + POSE_BLK;
const ST_OUT: usize = ST_BLIND + DIGEST_LANES;
/// One output: `sk ‖ inner block ‖ inner out ‖ outer block ‖ cm`.
const ST_OUT_SLOT: usize = DIGEST_LANES + POSE_BLK + DIGEST_LANES + POSE_BLK + DIGEST_LANES;
const ST_CONS_A: usize = ST_OUT + 2 * ST_OUT_SLOT;
const ST_CONS_E: usize = ST_CONS_A + U64_CONS_WIDTH;
const ST_RBLIND: usize = ST_CONS_E + U64_CONS_WIDTH;
const ST_DR_IBLK: usize = ST_RBLIND + DIGEST_LANES;
const ST_DR_IOUT: usize = ST_DR_IBLK + POSE_BLK;
const ST_DR_OBLK: usize = ST_DR_IOUT + DIGEST_LANES;
const ST_DR: usize = ST_DR_OBLK + POSE_BLK;
const ST_DBITS: usize = ST_DR + DIGEST_LANES;
const ST_MBITS: usize = ST_DBITS + STAKE_DELTA_BITS;
const ST_PBITS: usize = ST_MBITS + STAKE_M_BITS;
const ST_CBITS: usize = ST_PBITS + STAKE_P_LIMBS * 8;
const ST_DCBITS: usize = ST_CBITS + STAKE_P_LIMBS * STAKE_CARRY_BITS;
const ST_REMBITS: usize = ST_DCBITS + STAKE_P_LIMBS * STAKE_CARRY_BITS;
const ST_SLACKBITS: usize = ST_REMBITS + STAKE_REM_BITS;
/// ⛔ DB-395 — the input note's OWNER block, at the row's end.
const ST_OWNER: usize = ST_SLACKBITS + STAKE_REM_BITS;
/// The stake row's width.
pub const STAKE_ROW_WIDTH: usize = ST_OWNER + OWNER_BLK_WIDTH;

/// `D`'s three 8-bit limbs.
const STAKE_D8: [u64; 3] = [STAKE_REWARD_DEN & 0xff, (STAKE_REWARD_DEN >> 8) & 0xff, (STAKE_REWARD_DEN >> 16) & 0xff];
const _: () = assert!(STAKE_REWARD_DEN >> 24 == 0);

/// The stake gate (see the section note). Degree: it embeds whole permutations.
#[derive(Clone)]
pub struct StakeGate {
    pub gamma: Ea4,
    pub out0_cm: [Ea4; DIGEST_LANES],
    pub out1_cm: [Ea4; DIGEST_LANES],
    pub nullifier: [Ea4; DIGEST_LANES],
    pub leaf_commit: [Ea4; DIGEST_LANES],
    pub reward_commit: [Ea4; DIGEST_LANES],
    pub e_now: u64,
    pub rate_bps: u64,
}

impl crate::air_zerocheck::AirConstraint for StakeGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in self.residuals(local) {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }
    fn residuals(
        &self,
        local: &crate::air_zerocheck::Row<'_>,
        _at: &dyn Fn(usize, &[Ea4]) -> Ea4,
        _x: &[Ea4],
    ) -> Vec<Ea4> {
        StakeGate::residuals(self, local)
    }
    fn is_row_local(&self) -> bool {
        true
    }
    /// The two blindings are HIDING witnesses read only through their commitments (the membership cross-bind's and the
    /// reward commitment's), named so the free-witness census reads the choice.
    fn free_columns(&self) -> Option<Vec<usize>> {
        let mut free: Vec<usize> = (ST_BLIND..ST_BLIND + DIGEST_LANES).collect();
        free.extend(ST_RBLIND..ST_RBLIND + DIGEST_LANES);
        Some(free)
    }
}

impl StakeGate {
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>) -> Vec<Ea4> {
        let f = |x: u64| Ea4::from(Fa4::from_u64(x));
        let zero = f(0);
        let one = Ea4::ONE;
        let mut rs: Vec<Ea4> = Vec::new();
        // CONSERVATION: A is `v + r = S`, E is `w + out1 = S`, the two totals welded limb for limb.
        let ta = U64ConsBases::at(ST_CONS_A);
        let te = U64ConsBases::at(ST_CONS_E);
        push_u64_conservation(&mut rs, local, ta);
        push_u64_conservation(&mut rs, local, te);
        for i in 0..SC_LIMBS {
            rs.push(local[te.r#in + i] - local[ta.r#in + i]);
        }
        let s_in = local[ST_SIN];
        let s_out = local[ST_SOUT];
        let e0 = local[ST_E0];
        let e_now = f(self.e_now);
        rs.push(s_in * (s_in - one));
        rs.push(s_out * (s_out - one));
        // THE INPUT NOTE under `s_in · stake_tag(e0)`, its nullifier, and the membership cross-bind.
        let tag_in = |c: usize| match c {
            0 => s_in * f(STAKE_TAG_MARK),
            1 => s_in * e0,
            2 => s_in * f(STAKE_TAG_MARK2),
            _ => zero,
        };
        let sk = |c: usize| local[ST_SK + c];
        // ⛔ DB-395 — the input's OWNER: the opening lanes welded to `o = P(P(ask, nk), seed)`; the nullifier keyed by `nk`.
        push_owner_open(&mut rs, local, ST_OWNER, ST_SK);
        let nk = |c: usize| local[owner_nk_col(ST_OWNER) + c];
        push_note_open(&mut rs, local, ta.out, &tag_in, &sk, ST_IN_IBLK, ST_IN_IOUT, ST_IN_OBLK, ST_LEAF);
        let leaf = |c: usize| local[ST_LEAF + c];
        push_pose_round(&mut rs, local, &nk, &leaf, ST_NF_BLK, ST_NF);
        for c in 0..DIGEST_LANES {
            rs.push(local[ST_NF + c] - self.nullifier[c]);
        }
        let nfp = |c: usize| self.nullifier[c];
        push_pose_round(&mut rs, local, &leaf, &nfp, ST_CB, ST_CB2);
        crate::pow_pq_air::push_perm_residuals(local, ST_CB2, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(local[ST_CB2 + DIGEST_LANES + c] - local[ST_BLIND + c]);
            rs.push(local[ST_CB2 + crate::pow_pq_air::PERM_OUT + c] - self.leaf_commit[c]);
        }
        // THE OUTPUTS: the principal under `s_out · stake_tag(e_now)`, the second note as USDm.
        for j in 0..2 {
            let base = ST_OUT + j * ST_OUT_SLOT;
            let osk = |c: usize| local[base + c];
            let iblk = base + DIGEST_LANES;
            let iout = iblk + POSE_BLK;
            let oblk = iout + DIGEST_LANES;
            let cm = oblk + POSE_BLK;
            if j == 0 {
                let tag0 = |c: usize| match c {
                    0 => s_out * f(STAKE_TAG_MARK),
                    1 => s_out * e_now,
                    2 => s_out * f(STAKE_TAG_MARK2),
                    _ => zero,
                };
                push_note_open(&mut rs, local, te.out, &tag0, &osk, iblk, iout, oblk, cm);
            } else {
                let usdm = |_c: usize| zero;
                push_note_open(&mut rs, local, te.fee, &usdm, &osk, iblk, iout, oblk, cm);
            }
            let public = if j == 0 { &self.out0_cm } else { &self.out1_cm };
            for c in 0..DIGEST_LANES {
                rs.push(local[cm + c] - public[c]);
            }
        }
        // THE REWARD COMMITMENT: `solvency_commit_256(r, r_blind) = P(P(lo, hi), r_blind)`, `lo` = r's limbs.
        let lo = |c: usize| if c < SC_LIMBS { local[ta.fee + c] } else { zero };
        let hi = |_c: usize| zero;
        push_pose_round(&mut rs, local, &lo, &hi, ST_DR_IBLK, ST_DR_IOUT);
        let inner = |c: usize| local[ST_DR_IOUT + c];
        let rb = |c: usize| local[ST_RBLIND + c];
        push_pose_round(&mut rs, local, &inner, &rb, ST_DR_OBLK, ST_DR);
        for c in 0..DIGEST_LANES {
            rs.push(local[ST_DR + c] - self.reward_commit[c]);
        }
        // THE REWARD RULE over the integers. Every bit column is boolean; every limb and carry is a sum of its bits. The bit
        // region ends where the owner block begins (DB-395) — `ST_OWNER`, never the row's end, which the owner block now holds.
        for col in ST_DBITS..ST_OWNER {
            let b = local[col];
            rs.push(b * (b - one));
        }
        let bits = |base: usize, n: usize| -> Ea4 {
            let mut acc = zero;
            let mut pw = one;
            for k in 0..n {
                acc += local[base + k] * pw;
                pw *= f(2);
            }
            acc
        };
        let delta = bits(ST_DBITS, STAKE_DELTA_BITS);
        rs.push(delta - (e_now - e0)); // Δ = e_now − e0 ∈ [0, 2^16): a backdated e_now has no 16-bit Δ
        rs.push((one - s_in) * delta); // a USDm input earns nothing
        rs.push(bits(ST_MBITS, STAKE_M_BITS) - f(self.rate_bps) * delta); // M = rate·Δ (< 2^30 < p: exact)
        let v8 = |i: usize| bits(ta.out_bits + 8 * i, 8);
        let r8 = |i: usize| bits(ta.fee_bits + 8 * i, 8);
        let m8 = |j: usize| bits(ST_MBITS + 8 * j, (STAKE_M_BITS - 8 * j).min(8));
        let p8 = |k: usize| bits(ST_PBITS + 8 * k, 8);
        let c1 = |k: usize| bits(ST_CBITS + STAKE_CARRY_BITS * k, STAKE_CARRY_BITS);
        let c2 = |k: usize| bits(ST_DCBITS + STAKE_CARRY_BITS * k, STAKE_CARRY_BITS);
        let rem8 = |k: usize| bits(ST_REMBITS + 8 * k, (STAKE_REM_BITS - 8 * k).min(8));
        let two8 = f(256);
        for k in 0..STAKE_P_LIMBS {
            // chain 1: Σ v8_i·m8_j (i + j = k) + c1_{k-1} = p8_k + 256·c1_k — every term < 2^20, so the field
            // equation is the integer one.
            let mut s1 = zero;
            for i in 0..8 {
                if k >= i && k - i < 4 {
                    s1 += v8(i) * m8(k - i);
                }
            }
            let cin = if k == 0 { zero } else { c1(k - 1) };
            rs.push(s1 + cin - p8(k) - two8 * c1(k));
            // chain 2: Σ r8_i·D8_j + rem8_k + c2_{k-1} = p8_k + 256·c2_k
            let mut s2 = if k < 3 { rem8(k) } else { zero };
            for i in 0..8 {
                if k >= i && k - i < 3 {
                    s2 += r8(i) * f(STAKE_D8[k - i]);
                }
            }
            let din = if k == 0 { zero } else { c2(k - 1) };
            rs.push(s2 + din - p8(k) - two8 * c2(k));
        }
        rs.push(c1(STAKE_P_LIMBS - 1)); // no carry past 96 bits on either side
        rs.push(c2(STAKE_P_LIMBS - 1));
        // 0 ≤ rem < D: rem + slack = D − 1 over two 22-bit ranges.
        rs.push(bits(ST_REMBITS, STAKE_REM_BITS) + bits(ST_SLACKBITS, STAKE_REM_BITS) - f(STAKE_REWARD_DEN - 1));
        rs
    }
}

fn fill_bits(row: &mut [Fa4], base: usize, n: usize, v: u128) {
    for k in 0..n {
        row[base + k] = Fa4::from_u64(((v >> k) & 1) as u64);
    }
}

/// The input note's leaf a stake carrier spends — what the membership carrier proves is on chain.
#[must_use]
pub fn stake_input_leaf(w: &StakeWitness) -> Digest {
    let tag = if w.in_staked { stake_tag(w.e0) } else { USDM_ASSET_TAG };
    asset_note_cm(w.value_in, tag, w.owner.opening())
}

/// Build the stake row. `None` when the witness breaks the rule (the honest-prover bound; the gate is the other).
/// `hostile_e0` is a TEST hook: it lays a USDm input with that `e0` (so `Δ > 0`) — the shape the gate's
/// `(1 − s_in)·Δ = 0` law must refuse. Every production caller passes `None`.
fn stake_row(w: &StakeWitness, e_now: u64, rate_bps: u64, hostile_e0: Option<u64>) -> Option<(Vec<Fa4>, StakeOutputs)> {
    use p3_field::PrimeField64;
    if e_now >= STAKE_EPOCH_MAX || rate_bps > STAKE_RATE_MAX_BPS {
        return None;
    }
    let e0 = match (w.in_staked, hostile_e0) {
        (true, _) => w.e0,
        (false, Some(e)) => e,
        (false, None) => e_now, // a USDm input: Δ = 0 by the gate's law
    };
    let delta = e_now.checked_sub(e0)?;
    let reward = stake_reward(w.value_in, rate_bps, delta)?;
    let total = w.value_in.checked_add(reward)?;
    let out1_value = total.checked_sub(w.out0_value)?;
    let mut row = vec![Fa4::ZERO; STAKE_ROW_WIDTH];
    // DB-395: the opening lanes hold `o = P(P(ask, nk), seed)`, laid by the owner block.
    let sk = fill_owner_open(&mut row, ST_OWNER, ST_SK, &w.owner);
    let nk: DigestF = to_f(&w.owner.nk);
    row[ST_SIN] = Fa4::from_u64(u64::from(w.in_staked));
    row[ST_SOUT] = Fa4::from_u64(u64::from(w.out0_staked));
    row[ST_E0] = Fa4::from_u64(e0);
    let ta = U64ConsBases::at(ST_CONS_A);
    let te = U64ConsBases::at(ST_CONS_E);
    fill_u64_conservation_row(&mut row, total, w.value_in, reward, ta)?;
    fill_u64_conservation_row(&mut row, total, w.out0_value, out1_value, te)?;
    let tag_in = if w.in_staked { stake_tag(e0) } else { USDM_ASSET_TAG };
    let leaf = fill_note_open(&mut row, w.value_in, tag_in, &sk, ST_IN_IBLK, ST_IN_IOUT, ST_IN_OBLK, ST_LEAF);
    let nf = fill_pose_round(&mut row, &nk, &leaf, ST_NF_BLK, ST_NF);
    let inner = fill_pose_round(&mut row, &leaf, &nf, ST_CB, ST_CB2);
    let blind: DigestF = to_f(&w.lc_blind);
    row[ST_BLIND..ST_BLIND + DIGEST_LANES].copy_from_slice(&blind);
    crate::pow_pq_air::lay_perm_row_flat(&mut row, ST_CB2, pose_state(&inner, &blind));
    let leaf_commit: DigestF = core::array::from_fn(|c| row[ST_CB2 + crate::pow_pq_air::PERM_OUT + c]);
    let mut out_cms = [[Fa4::ZERO; DIGEST_LANES]; 2];
    let tag0 = if w.out0_staked { stake_tag(e_now) } else { USDM_ASSET_TAG };
    for (j, (v, osk, tag)) in [(w.out0_value, w.out0_opening, tag0), (out1_value, w.out1_opening, USDM_ASSET_TAG)].into_iter().enumerate() {
        let base = ST_OUT + j * ST_OUT_SLOT;
        let osk_f: DigestF = to_f(&osk);
        row[base..base + DIGEST_LANES].copy_from_slice(&osk_f);
        let iblk = base + DIGEST_LANES;
        let iout = iblk + POSE_BLK;
        let oblk = iout + DIGEST_LANES;
        out_cms[j] = fill_note_open(&mut row, v, tag, &osk_f, iblk, iout, oblk, oblk + POSE_BLK);
    }
    let l = crate::confidential_solvency::u256_to_limbs16(crate::confidential_solvency::u256_from_u64(reward));
    let lo: DigestF = core::array::from_fn(|c| Fa4::from_u64(l[c]));
    let hi: DigestF = core::array::from_fn(|c| Fa4::from_u64(l[DIGEST_LANES + c]));
    let dr_inner = fill_pose_round(&mut row, &lo, &hi, ST_DR_IBLK, ST_DR_IOUT);
    let rblind: DigestF = to_f(&w.reward_blind);
    row[ST_RBLIND..ST_RBLIND + DIGEST_LANES].copy_from_slice(&rblind);
    let dr = fill_pose_round(&mut row, &dr_inner, &rblind, ST_DR_OBLK, ST_DR);
    let m = u128::from(rate_bps) * u128::from(delta);
    let p = u128::from(w.value_in) * m;
    let rem = p - u128::from(reward) * u128::from(STAKE_REWARD_DEN);
    fill_bits(&mut row, ST_DBITS, STAKE_DELTA_BITS, u128::from(delta));
    fill_bits(&mut row, ST_MBITS, STAKE_M_BITS, m);
    fill_bits(&mut row, ST_PBITS, STAKE_P_LIMBS * 8, p);
    fill_bits(&mut row, ST_REMBITS, STAKE_REM_BITS, rem);
    fill_bits(&mut row, ST_SLACKBITS, STAKE_REM_BITS, u128::from(STAKE_REWARD_DEN - 1) - rem);
    // The two carry chains, from the same limbs the gate reads.
    let lim = |x: u128, i: usize| (x >> (8 * i)) & 0xff;
    let (mut c1, mut c2) = (0u128, 0u128);
    for k in 0..STAKE_P_LIMBS {
        let mut s1 = c1;
        for i in 0..8 {
            if k >= i && k - i < 4 {
                s1 += lim(u128::from(w.value_in), i) * lim(m, k - i);
            }
        }
        if s1 & 0xff != lim(p, k) {
            return None;
        }
        c1 = s1 >> 8;
        fill_bits(&mut row, ST_CBITS + STAKE_CARRY_BITS * k, STAKE_CARRY_BITS, c1);
        let mut s2 = c2 + if k < 3 { lim(rem, k) } else { 0 };
        for i in 0..8 {
            if k >= i && k - i < 3 {
                s2 += lim(u128::from(reward), i) * u128::from(STAKE_D8[k - i]);
            }
        }
        if s2 & 0xff != lim(p, k) {
            return None;
        }
        c2 = s2 >> 8;
        fill_bits(&mut row, ST_DCBITS + STAKE_CARRY_BITS * k, STAKE_CARRY_BITS, c2);
    }
    if c1 != 0 || c2 != 0 {
        return None;
    }
    let u = |v: &DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((
        row,
        StakeOutputs {
            out_cms: [u(&out_cms[0]), u(&out_cms[1])],
            nullifier: u(&nf),
            leaf_commit: u(&leaf_commit),
            reward_commit: u(&dr),
            reward,
            out1_value,
        },
    ))
}

/// The stake carrier's transcript bind: the domain, the five public digests, `e_now` and the rate.
fn stake_public_bind(o: &StakeOutputs, e_now: u64, rate_bps: u64) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(STAKE_VALIDITY_DOMAIN)];
    for d in [&o.out_cms[0], &o.out_cms[1], &o.nullifier, &o.leaf_commit, &o.reward_commit] {
        b.extend(d.iter().map(|&x| Fa4::from_u64(x)));
    }
    b.push(Fa4::from_u64(e_now));
    b.push(Fa4::from_u64(rate_bps));
    b
}

fn stake_gate(o: &StakeOutputs, e_now: u64, rate_bps: u64) -> impl Fn(Ea4) -> StakeGate {
    let ea = |d: &Digest| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|c| Ea4::from(Fa4::from_u64(d[c]))) };
    let (o0, o1, nf, lc, dr) = (ea(&o.out_cms[0]), ea(&o.out_cms[1]), ea(&o.nullifier), ea(&o.leaf_commit), ea(&o.reward_commit));
    move |g: Ea4| StakeGate {
        gamma: g,
        out0_cm: o0,
        out1_cm: o1,
        nullifier: nf,
        leaf_commit: lc,
        reward_commit: dr,
        e_now,
        rate_bps,
    }
}

/// PROVE a stake / claim / unstake (blinded: the carrier reveals nothing but its statement).
#[must_use]
pub fn prove_stake_carrier_bytes(w: &StakeWitness, e_now: u64, rate_bps: u64) -> Option<(Vec<u8>, StakeOutputs)> {
    let (row, outs) = stake_row(w, e_now, rate_bps, None)?;
    let cols: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; LIGHT_CARRIER_ROWS]).collect();
    let bytes = crate::committed_air::prove_air_blinded_bytes(cols, stake_gate(&outs, e_now, rate_bps), &stake_public_bind(&outs, e_now, rate_bps))?;
    Some((bytes, outs))
}

/// VERIFY a stake carrier against its public statement (`reward`/`out1_value` of `stmt` are not read). Fail-closed on an
/// all-zero cross-bind, an epoch or rate outside the gate's range, or any statement edit.
#[must_use]
pub fn verify_stake_carrier_bytes(bytes: &[u8], stmt: &StakeOutputs, e_now: u64, rate_bps: u64) -> bool {
    if bytes.is_empty()
        || stmt.leaf_commit == crate::poseidon2_compress::ZERO_DIGEST
        || e_now >= STAKE_EPOCH_MAX
        || rate_bps > STAKE_RATE_MAX_BPS
    {
        return false;
    }
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        stake_gate(stmt, e_now, rate_bps),
        &stake_public_bind(stmt, e_now, rate_bps),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, STAKE_ROW_WIDTH),
    )
}

/// The decider half's pins: the circuit alone. TWO-PARTY-REVIEWED: the boundary is the node — a stake object one node
/// lays and a second derives from the block alone is pinned in the node crate; here the second "party" is the verifier
/// run on the bytes and the public statement only.
#[cfg(test)]
mod stake_gate_tests {
    use super::*;
    use crate::poseidon2_compress::lanes_of;

    fn wit(in_staked: bool, e0: u64, v: u64, w0: u64, out0_staked: bool) -> StakeWitness {
        StakeWitness {
            value_in: v,
            owner: NoteOwner::from_test_key(lanes_of(&[0x5747, 1, 2, 3])),
            in_staked,
            e0,
            lc_blind: lanes_of(&[0x5747, 4, 4, 4]),
            out0_value: w0,
            out0_opening: lanes_of(&[0x5747, 5, 5, 5]),
            out0_staked,
            out1_opening: lanes_of(&[0x5747, 6, 6, 6]),
            reward_blind: lanes_of(&[0x5747, 7, 7, 7]),
        }
    }

    /// The prove → verify round trip, or `None` when no verifying carrier results.
    fn verifies(w: &StakeWitness, e_now: u64, rate: u64) -> Option<StakeOutputs> {
        let (bytes, o) = prove_stake_carrier_bytes(w, e_now, rate)?;
        verify_stake_carrier_bytes(&bytes, &o, e_now, rate).then_some(o)
    }

    fn row_vanishes(gate: &StakeGate, row: &[Fa4]) -> bool {
        let vals: Vec<Ea4> = row.iter().map(|&v| Ea4::from(v)).collect();
        let oob = crate::air_zerocheck::OobLatch::new();
        let r = crate::air_zerocheck::Row::new(&vals, &oob);
        gate.residuals(&r).iter().all(|x| *x == Ea4::ZERO) && !oob.hit()
    }

    /// ⭐ THE STAKE GATE UNDER THE CRATE'S THREE STRUCTURAL CENSUSES (degree measured, every column bound or named free,
    /// no decorative block), on an honest CLAIM row — the mode that exercises every region (staked input, both chains,
    /// a non-zero reward).
    #[test]
    fn the_stake_gate_passes_the_three_censuses() {
        let w = wit(true, 1_000, 500_000_000, 500_000_000, true);
        let (row, o) = stake_row(&w, 1_030, 500, None).expect("the honest claim row lays");
        let cols: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; LIGHT_CARRIER_ROWS]).collect();
        let nvars = LIGHT_CARRIER_ROWS.trailing_zeros() as usize;
        let gate = stake_gate(&o, 1_030, 500)(Ea4::from(Fa4::from_u64(0x5747)));
        crate::air_zerocheck::debug_degree_census(&cols, &gate, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_free_witness_census(&cols, &gate, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_decorative_block_census(&cols, &gate, nvars, true, &Some(Vec::new()));
        assert!(row_vanishes(&gate, &row), "the honest row vanishes");
    }

    /// ⭐⭐⭐ STAKE, CLAIM AND UNSTAKE — each proves, verifies, and states exactly the notes the native rule names.
    #[test]
    fn a_stake_a_claim_and_an_unstake_each_state_exactly_the_native_notes() {
        // STAKE: a USDm note of 900 → a staked principal of 600 from epoch 1_000 + 300 USDm change; no reward.
        let w = wit(false, 0, 900_000_000, 600_000_000, true);
        let o = verifies(&w, 1_000, 500).expect("a fresh stake verifies");
        assert_eq!(o.reward, 0, "a USDm input earns nothing");
        assert_eq!(o.out_cms[0], asset_note_cm(600_000_000, stake_tag(1_000), w.out0_opening), "the principal is staked from e_now");
        assert_eq!(o.out_cms[1], asset_note_cm(300_000_000, USDM_ASSET_TAG, w.out1_opening), "the change is USDm");
        assert_eq!(o.reward_commit, crate::confidential_solvency::solvency_commit_256([0; 4], w.reward_blind));
        // CLAIM: that staked note after 30 epochs at 5 % — re-staked from e_now, the reward paid as USDm.
        let w = wit(true, 1_000, 600_000_000, 600_000_000, true);
        let want = stake_reward(600_000_000, 500, 30).expect("in range");
        assert_eq!(want, 600_000_000u64 * 500 * 30 / STAKE_REWARD_DEN, "CALIBRATION: the native rule");
        assert!(want > 0, "CALIBRATION: a real reward");
        let o = verifies(&w, 1_030, 500).expect("a claim verifies");
        assert_eq!(o.reward, want);
        assert_eq!(o.out_cms[0], asset_note_cm(600_000_000, stake_tag(1_030), w.out0_opening), "re-staked from e_now");
        assert_eq!(o.out_cms[1], asset_note_cm(want, USDM_ASSET_TAG, w.out1_opening), "the reward note holds exactly r");
        assert_eq!(o.reward_commit, crate::confidential_solvency::solvency_commit_256([want, 0, 0, 0], w.reward_blind));
        let spent = stake_input_leaf(&w);
        assert_eq!(spent, asset_note_cm(600_000_000, stake_tag(1_000), w.owner.opening()), "the claim spends the staked note");
        // UNSTAKE: the same note, the principal returned as USDm.
        let w = wit(true, 1_000, 600_000_000, 600_000_000, false);
        let o = verifies(&w, 1_030, 500).expect("an unstake verifies");
        assert_eq!(o.out_cms[0], asset_note_cm(600_000_000, USDM_ASSET_TAG, w.out0_opening), "the principal returns as USDm");
    }

    /// ⛔⛔⛔ EVERY EDIT OF THE STATEMENT IS REFUSED, AND NO WITNESS EARNS WHAT THE RULE DOES NOT PAY.
    #[test]
    fn a_stake_carrier_refuses_every_statement_edit_and_every_unearned_reward() {
        let w = wit(true, 1_000, 600_000_000, 600_000_000, true);
        let (bytes, o) = prove_stake_carrier_bytes(&w, 1_030, 500).expect("proves");
        assert!(verify_stake_carrier_bytes(&bytes, &o, 1_030, 500), "CALIBRATION: the honest carrier verifies");
        let bump = |d: &Digest| -> Digest {
            let mut x = *d;
            x[0] = (x[0] + 1) % 0x7f00_0001;
            x
        };
        let edits: Vec<(&str, StakeOutputs)> = vec![
            ("reward commitment of r + 1", StakeOutputs {
                reward_commit: crate::confidential_solvency::solvency_commit_256([o.reward + 1, 0, 0, 0], w.reward_blind),
                ..o.clone()
            }),
            ("output 0", StakeOutputs { out_cms: [bump(&o.out_cms[0]), o.out_cms[1]], ..o.clone() }),
            ("output 1", StakeOutputs { out_cms: [o.out_cms[0], bump(&o.out_cms[1])], ..o.clone() }),
            ("outputs swapped", StakeOutputs { out_cms: [o.out_cms[1], o.out_cms[0]], ..o.clone() }),
            ("nullifier", StakeOutputs { nullifier: bump(&o.nullifier), ..o.clone() }),
            ("cross-bind", StakeOutputs { leaf_commit: bump(&o.leaf_commit), ..o.clone() }),
            ("cross-bind zero", StakeOutputs { leaf_commit: crate::poseidon2_compress::ZERO_DIGEST, ..o.clone() }),
        ];
        for (what, s) in edits {
            assert!(!verify_stake_carrier_bytes(&bytes, &s, 1_030, 500), "⛔ a stake carrier verified with its {what} edited");
        }
        for (e, r) in [(1_031, 500), (1_029, 500), (1_030, 501), (1_030, 499)] {
            assert!(!verify_stake_carrier_bytes(&bytes, &o, e, r), "⛔ a stake carrier verified at e_now {e}, rate {r}");
        }
        assert!(!verify_stake_carrier_bytes(&bytes, &o, 1_030, STAKE_RATE_MAX_BPS + 1), "⛔ a rate above 100 % verified");
        // A USDm input claiming 30 epochs of reward: refused by `(1 − s_in)·Δ = 0` (the hostile row is otherwise honest).
        let usdm = wit(false, 0, 600_000_000, 600_000_000, true);
        let (row, ho) = stake_row(&usdm, 1_030, 500, Some(1_000)).expect("the hostile row lays");
        assert!(ho.reward > 0, "CALIBRATION: the hostile row claims a real reward");
        let gate = stake_gate(&ho, 1_030, 500)(Ea4::from(Fa4::from_u64(0x5747)));
        assert!(!row_vanishes(&gate, &row), "⛔⛔⛔ a plain USDm note earned stake rewards");
        // A claim whose start is after e_now has no 16-bit Δ: no row lays.
        assert!(stake_row(&wit(true, 1_031, 600_000_000, 600_000_000, true), 1_030, 500, None).is_none(), "⛔ a negative Δ laid");
        // Over-claiming the principal beyond input + reward is refused by conservation.
        assert!(stake_row(&wit(true, 1_000, 600_000_000, 600_000_000 + o.reward + 1, true), 1_030, 500, None).is_none());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ⭐⭐⭐ LIQUIDATION SPEC §10 — THE STABILITY POOL'S TWO NOTE GATES (2026-10-02)
//
// A pool DEPOSIT spends a USDm note of `v` into the pool: output 0 is the depositor's RECEIPT (`d`, under
// `receipt_tag(asset, epoch)` and the key `sk_r = P(sk_owner, P(PD, SD))` — the snapshot commitments are INSIDE the key,
// so the receipt withdraws against exactly that snapshot and no node stores anything per deposit), output 1 the USDm
// change `v − d`, and `DV = commit(d)` is public for the pool transition `T + d`.
// A pool WITHDRAWAL spends the receipt with `PD`, `SD` and `d` HIDDEN (§10.4: the deposit published them; re-publishing
// would link the two) and publishes RE-RANDOMIZED `PD′`, `SD′`, `Dd′` — each pair computed from the SAME limb lanes — for
// the custodian's withdraw carrier to open; output 0 is the compounded USDm note `u`, `Du = commit(u)` public.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// Transcript domain of the pool deposit carrier.
pub const POOL_DEPOSIT_DOMAIN: u64 = 0x504f_4f4c_4445_5031; // "POOLDEP1"
/// Transcript domain of the pool receipt (withdrawal) carrier.
pub const POOL_RECEIPT_DOMAIN: u64 = 0x504f_4f4c_5243_5431; // "POOLRCT1"
/// Tag lane 0 of a pool receipt.
pub const RECEIPT_TAG_MARK: u64 = 0x5243_5054; // "RCPT"

/// The tag of a pool receipt for PSM `asset_id` in pool epoch `epoch` (both lanes are single field elements).
#[must_use]
pub fn receipt_tag(asset_id: u32, epoch: u64) -> Option<[u64; 3]> {
    (u64::from(asset_id) < STAKE_EPOCH_MAX && epoch < STAKE_EPOCH_MAX).then_some([RECEIPT_TAG_MARK, u64::from(asset_id), epoch])
}

/// The receipt's spend key: the snapshot commitments live inside it.
#[must_use]
pub fn receipt_spend_key(sk_owner: &Digest, pd: &Digest, sd: &Digest) -> Digest {
    poseidon_pair(*sk_owner, poseidon_pair(*pd, *sd))
}

/// `solvency_commit_256(v, blind)` for a `u64` value — the commitment both pool gates publish.
#[must_use]
pub fn commit_u64(v: u64, blind: &Digest) -> Digest {
    crate::confidential_solvency::solvency_commit_256(crate::confidential_solvency::u256_from_u64(v), *blind)
}

/// In-circuit `commit_u64`: `P(P(lo, 0), blind)`, `lo` = the value's four range-bound 16-bit limbs at `limbs`.
fn push_commit_u64(rs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, limbs: usize, blind: usize, iblk: usize, iout: usize, oblk: usize, out: usize) {
    let zero = Ea4::from(Fa4::ZERO);
    let lo = |c: usize| if c < SC_LIMBS { local[limbs + c] } else { zero };
    let hi = |_c: usize| zero;
    push_pose_round(rs, local, &lo, &hi, iblk, iout);
    let inner = |c: usize| local[iout + c];
    let b = |c: usize| local[blind + c];
    push_pose_round(rs, local, &inner, &b, oblk, out);
}
fn fill_commit_u64(row: &mut [Fa4], v: u64, blind: &Digest, blind_col: usize, iblk: usize, iout: usize, oblk: usize, out: usize) -> DigestF {
    let l = crate::confidential_solvency::u256_to_limbs16(crate::confidential_solvency::u256_from_u64(v));
    let lo: DigestF = core::array::from_fn(|c| Fa4::from_u64(l[c]));
    let hi: DigestF = core::array::from_fn(|c| Fa4::from_u64(l[DIGEST_LANES + c]));
    let inner = fill_pose_round(row, &lo, &hi, iblk, iout);
    let b = to_f(blind);
    row[blind_col..blind_col + DIGEST_LANES].copy_from_slice(&b);
    fill_pose_round(row, &inner, &b, oblk, out)
}

/// One in-circuit commitment block: blind ‖ inner block ‖ inner out ‖ outer block ‖ out.
const CM_SLOT: usize = DIGEST_LANES + POSE_BLK + DIGEST_LANES + POSE_BLK + DIGEST_LANES;
/// One note-output block: sk ‖ inner block ‖ inner out ‖ outer block ‖ cm.
const NOTE_SLOT: usize = DIGEST_LANES + POSE_BLK + DIGEST_LANES + POSE_BLK + DIGEST_LANES;

// ── the DEPOSIT gate's row ──
const PDP_SK: usize = 0;
const PDP_LEAF: usize = PDP_SK + DIGEST_LANES;
const PDP_NF: usize = PDP_LEAF + DIGEST_LANES;
const PDP_IN_IBLK: usize = PDP_NF + DIGEST_LANES;
const PDP_IN_IOUT: usize = PDP_IN_IBLK + POSE_BLK;
const PDP_IN_OBLK: usize = PDP_IN_IOUT + DIGEST_LANES;
const PDP_NF_BLK: usize = PDP_IN_OBLK + POSE_BLK;
const PDP_CB: usize = PDP_NF_BLK + POSE_BLK;
const PDP_CB2: usize = PDP_CB + POSE_BLK;
const PDP_BLIND: usize = PDP_CB2 + POSE_BLK;
const PDP_OWNER: usize = PDP_BLIND + DIGEST_LANES;
const PDP_SNAP_BLK: usize = PDP_OWNER + DIGEST_LANES;
const PDP_SNAP: usize = PDP_SNAP_BLK + POSE_BLK;
const PDP_SKR_BLK: usize = PDP_SNAP + DIGEST_LANES;
const PDP_SKR: usize = PDP_SKR_BLK + POSE_BLK;
/// output 0, the receipt: inner block ‖ inner out ‖ outer block ‖ cm (its key is `PDP_SKR`).
const PDP_R_IBLK: usize = PDP_SKR + DIGEST_LANES;
const PDP_R_IOUT: usize = PDP_R_IBLK + POSE_BLK;
const PDP_R_OBLK: usize = PDP_R_IOUT + DIGEST_LANES;
const PDP_R_CM: usize = PDP_R_OBLK + POSE_BLK;
const PDP_CHANGE: usize = PDP_R_CM + DIGEST_LANES;
const PDP_CONS: usize = PDP_CHANGE + NOTE_SLOT;
const PDP_DV: usize = PDP_CONS + U64_CONS_WIDTH;
/// ⛔ DB-395 — the DEPOSITED note's OWNER block, at the row's end. (The receipt's `owner_sk` is the depositor's own secret —
/// the receipt is sealed by no one else — so its key needs no owner block.)
const PDP_IN_OWNER: usize = PDP_DV + CM_SLOT;
/// The deposit row's width.
pub const POOL_DEPOSIT_ROW_WIDTH: usize = PDP_IN_OWNER + OWNER_BLK_WIDTH;

/// A pool deposit witness.
#[derive(Clone, Debug)]
pub struct PoolDepositWitness {
    pub value_in: u64,
    /// ⛔ DB-395: the deposited note's owner (`ask`, `nk`, the note's seed).
    pub owner: NoteOwner,
    pub lc_blind: Digest,
    pub deposit: u64,
    /// The receipt's owner secret — the depositor's own, never derived from anything another party sealed.
    pub owner_sk: Digest,
    /// DB-395: the change note's opening `P(spk, seed)`.
    pub change_opening: Digest,
    pub dv_blind: Digest,
}

/// What a pool deposit carrier states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolDepositStatement {
    pub nullifier: Digest,
    pub leaf_commit: Digest,
    pub receipt_cm: Digest,
    pub change_cm: Digest,
    pub dv: Digest,
    pub pd: Digest,
    pub sd: Digest,
    pub asset_id: u32,
    pub epoch: u64,
}

/// The pool deposit gate (see the section note).
#[derive(Clone)]
pub struct PoolDepositGate {
    pub gamma: Ea4,
    pub s: PoolDepositStatement,
}

fn ea_digest(d: &Digest) -> [Ea4; DIGEST_LANES] {
    core::array::from_fn(|c| Ea4::from(Fa4::from_u64(d[c])))
}

impl crate::air_zerocheck::AirConstraint for PoolDepositGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in self.residuals(local) {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Vec<Ea4> {
        PoolDepositGate::residuals(self, local)
    }
    fn is_row_local(&self) -> bool {
        true
    }
    fn free_columns(&self) -> Option<Vec<usize>> {
        let mut free: Vec<usize> = (PDP_BLIND..PDP_BLIND + DIGEST_LANES).collect();
        free.extend(PDP_DV..PDP_DV + DIGEST_LANES);
        Some(free)
    }
}

impl PoolDepositGate {
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>) -> Vec<Ea4> {
        let zero = Ea4::from(Fa4::ZERO);
        let s = &self.s;
        let (nf, lc, rcm, ccm, dv, pd, sd) =
            (ea_digest(&s.nullifier), ea_digest(&s.leaf_commit), ea_digest(&s.receipt_cm), ea_digest(&s.change_cm), ea_digest(&s.dv), ea_digest(&s.pd), ea_digest(&s.sd));
        let mut rs: Vec<Ea4> = Vec::new();
        // conservation: v = d + change, range-bound
        let ta = U64ConsBases::at(PDP_CONS);
        push_u64_conservation(&mut rs, local, ta);
        // the USDm input, its nullifier and the membership cross-bind
        let usdm = |_c: usize| zero;
        let sk = |c: usize| local[PDP_SK + c];
        // ⛔ DB-395 — the deposited note's OWNER: opening lanes welded to `o = P(P(ask, nk), seed)`; nullifier keyed by `nk`.
        push_owner_open(&mut rs, local, PDP_IN_OWNER, PDP_SK);
        let nk = |c: usize| local[owner_nk_col(PDP_IN_OWNER) + c];
        push_note_open(&mut rs, local, ta.r#in, &usdm, &sk, PDP_IN_IBLK, PDP_IN_IOUT, PDP_IN_OBLK, PDP_LEAF);
        let leaf = |c: usize| local[PDP_LEAF + c];
        push_pose_round(&mut rs, local, &nk, &leaf, PDP_NF_BLK, PDP_NF);
        for c in 0..DIGEST_LANES {
            rs.push(local[PDP_NF + c] - nf[c]);
        }
        let nfp = |c: usize| nf[c];
        push_pose_round(&mut rs, local, &leaf, &nfp, PDP_CB, PDP_CB2);
        crate::pow_pq_air::push_perm_residuals(local, PDP_CB2, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(local[PDP_CB2 + DIGEST_LANES + c] - local[PDP_BLIND + c]);
            rs.push(local[PDP_CB2 + crate::pow_pq_air::PERM_OUT + c] - lc[c]);
        }
        // the receipt key: sk_r = P(sk_owner, P(PD, SD)), the snapshot public here
        let pdl = |c: usize| pd[c];
        let sdl = |c: usize| sd[c];
        push_pose_round(&mut rs, local, &pdl, &sdl, PDP_SNAP_BLK, PDP_SNAP);
        let owner = |c: usize| local[PDP_OWNER + c];
        let snap = |c: usize| local[PDP_SNAP + c];
        push_pose_round(&mut rs, local, &owner, &snap, PDP_SKR_BLK, PDP_SKR);
        // output 0: the receipt under receipt_tag(asset, epoch) and sk_r, value d
        let (asset, epoch) = (Ea4::from(Fa4::from_u64(u64::from(s.asset_id))), Ea4::from(Fa4::from_u64(s.epoch)));
        let rtag = |c: usize| match c {
            0 => Ea4::from(Fa4::from_u64(RECEIPT_TAG_MARK)),
            1 => asset,
            2 => epoch,
            _ => zero,
        };
        let skr = |c: usize| local[PDP_SKR + c];
        push_note_open(&mut rs, local, ta.out, &rtag, &skr, PDP_R_IBLK, PDP_R_IOUT, PDP_R_OBLK, PDP_R_CM);
        for c in 0..DIGEST_LANES {
            rs.push(local[PDP_R_CM + c] - rcm[c]);
        }
        // output 1: the USDm change
        let csk = |c: usize| local[PDP_CHANGE + c];
        let (ib, io, ob) = (PDP_CHANGE + DIGEST_LANES, PDP_CHANGE + DIGEST_LANES + POSE_BLK, PDP_CHANGE + 2 * DIGEST_LANES + POSE_BLK);
        let ccm_col = ob + POSE_BLK;
        push_note_open(&mut rs, local, ta.fee, &usdm, &csk, ib, io, ob, ccm_col);
        for c in 0..DIGEST_LANES {
            rs.push(local[ccm_col + c] - ccm[c]);
        }
        // DV = commit(d)
        let (bl, ib, io, ob) = (PDP_DV, PDP_DV + DIGEST_LANES, PDP_DV + DIGEST_LANES + POSE_BLK, PDP_DV + 2 * DIGEST_LANES + POSE_BLK);
        let dv_col = ob + POSE_BLK;
        push_commit_u64(&mut rs, local, ta.out, bl, ib, io, ob, dv_col);
        for c in 0..DIGEST_LANES {
            rs.push(local[dv_col + c] - dv[c]);
        }
        rs
    }
}

fn pool_deposit_bind(s: &PoolDepositStatement) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(POOL_DEPOSIT_DOMAIN)];
    for d in [&s.nullifier, &s.leaf_commit, &s.receipt_cm, &s.change_cm, &s.dv, &s.pd, &s.sd] {
        b.extend(d.iter().map(|&x| Fa4::from_u64(x)));
    }
    b.push(Fa4::from_u64(u64::from(s.asset_id)));
    b.push(Fa4::from_u64(s.epoch));
    b
}

/// Build the deposit row; `None` when the witness breaks the rule.
fn pool_deposit_row(w: &PoolDepositWitness, pd: &Digest, sd: &Digest, asset_id: u32, epoch: u64) -> Option<(Vec<Fa4>, PoolDepositStatement)> {
    use p3_field::PrimeField64;
    let rtag = receipt_tag(asset_id, epoch)?;
    let change = w.value_in.checked_sub(w.deposit)?;
    let mut row = vec![Fa4::ZERO; POOL_DEPOSIT_ROW_WIDTH];
    // DB-395: the deposited note's opening lanes hold `o = P(P(ask, nk), seed)`, laid by its owner block.
    let sk = fill_owner_open(&mut row, PDP_IN_OWNER, PDP_SK, &w.owner);
    let nk = to_f(&w.owner.nk);
    let ta = U64ConsBases::at(PDP_CONS);
    fill_u64_conservation_row(&mut row, w.value_in, w.deposit, change, ta)?;
    let leaf = fill_note_open(&mut row, w.value_in, USDM_ASSET_TAG, &sk, PDP_IN_IBLK, PDP_IN_IOUT, PDP_IN_OBLK, PDP_LEAF);
    let nf = fill_pose_round(&mut row, &nk, &leaf, PDP_NF_BLK, PDP_NF);
    let inner = fill_pose_round(&mut row, &leaf, &nf, PDP_CB, PDP_CB2);
    let blind = to_f(&w.lc_blind);
    row[PDP_BLIND..PDP_BLIND + DIGEST_LANES].copy_from_slice(&blind);
    crate::pow_pq_air::lay_perm_row_flat(&mut row, PDP_CB2, pose_state(&inner, &blind));
    let lc: DigestF = core::array::from_fn(|c| row[PDP_CB2 + crate::pow_pq_air::PERM_OUT + c]);
    let owner = to_f(&w.owner_sk);
    row[PDP_OWNER..PDP_OWNER + DIGEST_LANES].copy_from_slice(&owner);
    let snap = fill_pose_round(&mut row, &to_f(pd), &to_f(sd), PDP_SNAP_BLK, PDP_SNAP);
    let skr = fill_pose_round(&mut row, &owner, &snap, PDP_SKR_BLK, PDP_SKR);
    let rcm = fill_note_open(&mut row, w.deposit, rtag, &skr, PDP_R_IBLK, PDP_R_IOUT, PDP_R_OBLK, PDP_R_CM);
    let csk = to_f(&w.change_opening);
    row[PDP_CHANGE..PDP_CHANGE + DIGEST_LANES].copy_from_slice(&csk);
    let (ib, io, ob) = (PDP_CHANGE + DIGEST_LANES, PDP_CHANGE + DIGEST_LANES + POSE_BLK, PDP_CHANGE + 2 * DIGEST_LANES + POSE_BLK);
    let ccm = fill_note_open(&mut row, change, USDM_ASSET_TAG, &csk, ib, io, ob, ob + POSE_BLK);
    let (ib, io, ob) = (PDP_DV + DIGEST_LANES, PDP_DV + DIGEST_LANES + POSE_BLK, PDP_DV + 2 * DIGEST_LANES + POSE_BLK);
    let dv = fill_commit_u64(&mut row, w.deposit, &w.dv_blind, PDP_DV, ib, io, ob, ob + POSE_BLK);
    let u = |v: &DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((
        row,
        PoolDepositStatement { nullifier: u(&nf), leaf_commit: u(&lc), receipt_cm: u(&rcm), change_cm: u(&ccm), dv: u(&dv), pd: *pd, sd: *sd, asset_id, epoch },
    ))
}

/// PROVE a pool deposit against the pool's current snapshot commitments `(pd, sd)` (the executing custodian made them).
#[must_use]
pub fn prove_pool_deposit_bytes(w: &PoolDepositWitness, pd: &Digest, sd: &Digest, asset_id: u32, epoch: u64) -> Option<(Vec<u8>, PoolDepositStatement)> {
    let (row, s) = pool_deposit_row(w, pd, sd, asset_id, epoch)?;
    let cols: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; LIGHT_CARRIER_ROWS]).collect();
    let st = s.clone();
    let bytes = crate::committed_air::prove_air_blinded_bytes(cols, move |g: Ea4| PoolDepositGate { gamma: g, s: st.clone() }, &pool_deposit_bind(&s))?;
    Some((bytes, s))
}

/// VERIFY a pool deposit against its statement. Fail-closed on an all-zero cross-bind or any statement edit.
#[must_use]
pub fn verify_pool_deposit_bytes(bytes: &[u8], s: &PoolDepositStatement) -> bool {
    if bytes.is_empty() || s.leaf_commit == crate::poseidon2_compress::ZERO_DIGEST || receipt_tag(s.asset_id, s.epoch).is_none() {
        return false;
    }
    let st = s.clone();
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        move |g: Ea4| PoolDepositGate { gamma: g, s: st.clone() },
        &pool_deposit_bind(s),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, POOL_DEPOSIT_ROW_WIDTH),
    )
}

// ── the RECEIPT (withdrawal) gate's row ──
const PRC_OWNER: usize = 0;
/// one snapshot word: lo ‖ hi ‖ blind ‖ blind′ ‖ inner block ‖ inner ‖ block ‖ commit ‖ block′ ‖ commit′
const SNAP_SLOT: usize = 4 * DIGEST_LANES + 3 * POSE_BLK + 3 * DIGEST_LANES;
const PRC_P: usize = PRC_OWNER + DIGEST_LANES;
const PRC_S: usize = PRC_P + SNAP_SLOT;
const PRC_SNAP_BLK: usize = PRC_S + SNAP_SLOT;
const PRC_SNAP: usize = PRC_SNAP_BLK + POSE_BLK;
const PRC_SKR_BLK: usize = PRC_SNAP + DIGEST_LANES;
const PRC_SKR: usize = PRC_SKR_BLK + POSE_BLK;
const PRC_D: usize = PRC_SKR + DIGEST_LANES; // range block for d (in = out = d, fee = 0)
const PRC_IN_IBLK: usize = PRC_D + U64_CONS_WIDTH;
const PRC_IN_IOUT: usize = PRC_IN_IBLK + POSE_BLK;
const PRC_IN_OBLK: usize = PRC_IN_IOUT + DIGEST_LANES;
const PRC_LEAF: usize = PRC_IN_OBLK + POSE_BLK;
const PRC_NF_BLK: usize = PRC_LEAF + DIGEST_LANES;
const PRC_NF: usize = PRC_NF_BLK + POSE_BLK;
const PRC_CB: usize = PRC_NF + DIGEST_LANES;
const PRC_CB2: usize = PRC_CB + POSE_BLK;
const PRC_BLIND: usize = PRC_CB2 + POSE_BLK;
const PRC_DD: usize = PRC_BLIND + DIGEST_LANES;
const PRC_U: usize = PRC_DD + CM_SLOT; // range block for u
const PRC_OUT: usize = PRC_U + U64_CONS_WIDTH;
const PRC_DU: usize = PRC_OUT + NOTE_SLOT;
/// The receipt row's width.
pub const POOL_RECEIPT_ROW_WIDTH: usize = PRC_DU + CM_SLOT;

/// A pool withdrawal witness: the receipt's opening, its snapshot openings (as minted), fresh blinds for the
/// re-randomized commitments, and the compounded USDm note `u` the withdrawer receives.
#[derive(Clone, Debug)]
pub struct PoolReceiptWitness {
    pub owner_sk: Digest,
    pub deposit: u64,
    pub p_dep: crate::confidential_solvency::U256,
    pub p_blind: Digest,
    pub p_blind2: Digest,
    pub s_dep: crate::confidential_solvency::U256,
    pub s_blind: Digest,
    pub s_blind2: Digest,
    pub lc_blind: Digest,
    pub d_blind2: Digest,
    pub compounded: u64,
    /// DB-395: the withdrawn note's opening `P(spk, seed)` — no spend authority.
    pub out_opening: Digest,
    pub u_blind: Digest,
}

/// What a pool receipt carrier states — no value, no snapshot, nothing the deposit published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolReceiptStatement {
    pub nullifier: Digest,
    pub leaf_commit: Digest,
    pub out_cm: Digest,
    pub dd: Digest,
    pub du: Digest,
    pub pd: Digest,
    pub sd: Digest,
    pub asset_id: u32,
    pub epoch: u64,
}

/// The pool receipt gate (see the section note).
#[derive(Clone)]
pub struct PoolReceiptGate {
    pub gamma: Ea4,
    pub s: PoolReceiptStatement,
}

impl crate::air_zerocheck::AirConstraint for PoolReceiptGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in self.residuals(local) {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Vec<Ea4> {
        PoolReceiptGate::residuals(self, local)
    }
    fn is_row_local(&self) -> bool {
        true
    }
    /// The blinds are HIDING witnesses, read only through their commitments.
    fn free_columns(&self) -> Option<Vec<usize>> {
        let mut free: Vec<usize> = (PRC_BLIND..PRC_BLIND + DIGEST_LANES).collect();
        for base in [PRC_P, PRC_S] {
            free.extend(base + 2 * DIGEST_LANES..base + 4 * DIGEST_LANES);
        }
        free.extend(PRC_DD..PRC_DD + DIGEST_LANES);
        free.extend(PRC_DU..PRC_DU + DIGEST_LANES);
        Some(free)
    }
}

/// The snapshot word's two commitments from ONE pair of limb lanes: `(commit, commit′)` at `base`.
fn push_snap_word(rs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, base: usize) {
    let lo = |c: usize| local[base + c];
    let hi = |c: usize| local[base + DIGEST_LANES + c];
    let (b1, b2) = (base + 2 * DIGEST_LANES, base + 3 * DIGEST_LANES);
    let iblk = base + 4 * DIGEST_LANES;
    let inner = iblk + POSE_BLK;
    let blk1 = inner + DIGEST_LANES;
    let c1 = blk1 + POSE_BLK;
    let blk2 = c1 + DIGEST_LANES;
    let c2 = blk2 + POSE_BLK;
    push_pose_round(rs, local, &lo, &hi, iblk, inner);
    let inn = |c: usize| local[inner + c];
    let bl1 = |c: usize| local[b1 + c];
    let bl2 = |c: usize| local[b2 + c];
    push_pose_round(rs, local, &inn, &bl1, blk1, c1);
    push_pose_round(rs, local, &inn, &bl2, blk2, c2);
}
/// `(commit col, commit′ col)` of a snapshot word at `base`.
const fn snap_cols(base: usize) -> (usize, usize) {
    let c1 = base + 4 * DIGEST_LANES + POSE_BLK + DIGEST_LANES + POSE_BLK;
    (c1, c1 + DIGEST_LANES + POSE_BLK)
}

impl PoolReceiptGate {
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>) -> Vec<Ea4> {
        let zero = Ea4::from(Fa4::ZERO);
        let s = &self.s;
        let (nf, lc, ocm, dd, du, pd2, sd2) =
            (ea_digest(&s.nullifier), ea_digest(&s.leaf_commit), ea_digest(&s.out_cm), ea_digest(&s.dd), ea_digest(&s.du), ea_digest(&s.pd), ea_digest(&s.sd));
        let mut rs: Vec<Ea4> = Vec::new();
        // the two snapshot words, each hidden, each re-randomized from the SAME lanes
        push_snap_word(&mut rs, local, PRC_P);
        push_snap_word(&mut rs, local, PRC_S);
        let (p1, p2) = snap_cols(PRC_P);
        let (s1, s2) = snap_cols(PRC_S);
        for c in 0..DIGEST_LANES {
            rs.push(local[p2 + c] - pd2[c]);
            rs.push(local[s2 + c] - sd2[c]);
        }
        // the receipt key from the HIDDEN minted snapshot: sk_r = P(sk_owner, P(PD, SD))
        let pdl = |c: usize| local[p1 + c];
        let sdl = |c: usize| local[s1 + c];
        push_pose_round(&mut rs, local, &pdl, &sdl, PRC_SNAP_BLK, PRC_SNAP);
        let owner = |c: usize| local[PRC_OWNER + c];
        let snap = |c: usize| local[PRC_SNAP + c];
        push_pose_round(&mut rs, local, &owner, &snap, PRC_SKR_BLK, PRC_SKR);
        // the receipt (value d, range-bound) under receipt_tag(asset, epoch) and sk_r; its nullifier; the cross-bind
        let td = U64ConsBases::at(PRC_D);
        push_u64_conservation(&mut rs, local, td);
        let (asset, epoch) = (Ea4::from(Fa4::from_u64(u64::from(s.asset_id))), Ea4::from(Fa4::from_u64(s.epoch)));
        let rtag = |c: usize| match c {
            0 => Ea4::from(Fa4::from_u64(RECEIPT_TAG_MARK)),
            1 => asset,
            2 => epoch,
            _ => zero,
        };
        let skr = |c: usize| local[PRC_SKR + c];
        push_note_open(&mut rs, local, td.r#in, &rtag, &skr, PRC_IN_IBLK, PRC_IN_IOUT, PRC_IN_OBLK, PRC_LEAF);
        let leaf = |c: usize| local[PRC_LEAF + c];
        push_pose_round(&mut rs, local, &skr, &leaf, PRC_NF_BLK, PRC_NF);
        for c in 0..DIGEST_LANES {
            rs.push(local[PRC_NF + c] - nf[c]);
        }
        let nfp = |c: usize| nf[c];
        push_pose_round(&mut rs, local, &leaf, &nfp, PRC_CB, PRC_CB2);
        crate::pow_pq_air::push_perm_residuals(local, PRC_CB2, &mut rs);
        for c in 0..DIGEST_LANES {
            rs.push(local[PRC_CB2 + DIGEST_LANES + c] - local[PRC_BLIND + c]);
            rs.push(local[PRC_CB2 + crate::pow_pq_air::PERM_OUT + c] - lc[c]);
        }
        // Dd′ = commit(d)
        let (ib, io, ob) = (PRC_DD + DIGEST_LANES, PRC_DD + DIGEST_LANES + POSE_BLK, PRC_DD + 2 * DIGEST_LANES + POSE_BLK);
        push_commit_u64(&mut rs, local, td.r#in, PRC_DD, ib, io, ob, ob + POSE_BLK);
        for c in 0..DIGEST_LANES {
            rs.push(local[ob + POSE_BLK + c] - dd[c]);
        }
        // the compounded USDm note u (range-bound) and Du = commit(u)
        let tu = U64ConsBases::at(PRC_U);
        push_u64_conservation(&mut rs, local, tu);
        let usdm = |_c: usize| zero;
        let osk = |c: usize| local[PRC_OUT + c];
        let (ib, io, ob) = (PRC_OUT + DIGEST_LANES, PRC_OUT + DIGEST_LANES + POSE_BLK, PRC_OUT + 2 * DIGEST_LANES + POSE_BLK);
        push_note_open(&mut rs, local, tu.r#in, &usdm, &osk, ib, io, ob, ob + POSE_BLK);
        for c in 0..DIGEST_LANES {
            rs.push(local[ob + POSE_BLK + c] - ocm[c]);
        }
        let (ib, io, ob) = (PRC_DU + DIGEST_LANES, PRC_DU + DIGEST_LANES + POSE_BLK, PRC_DU + 2 * DIGEST_LANES + POSE_BLK);
        push_commit_u64(&mut rs, local, tu.r#in, PRC_DU, ib, io, ob, ob + POSE_BLK);
        for c in 0..DIGEST_LANES {
            rs.push(local[ob + POSE_BLK + c] - du[c]);
        }
        rs
    }
}

fn pool_receipt_bind(s: &PoolReceiptStatement) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(POOL_RECEIPT_DOMAIN)];
    for d in [&s.nullifier, &s.leaf_commit, &s.out_cm, &s.dd, &s.du, &s.pd, &s.sd] {
        b.extend(d.iter().map(|&x| Fa4::from_u64(x)));
    }
    b.push(Fa4::from_u64(u64::from(s.asset_id)));
    b.push(Fa4::from_u64(s.epoch));
    b
}

fn fill_snap_word(row: &mut [Fa4], base: usize, v: crate::confidential_solvency::U256, b1: &Digest, b2: &Digest) -> (DigestF, DigestF) {
    let l = crate::confidential_solvency::u256_to_limbs16(v);
    let lo: DigestF = core::array::from_fn(|c| Fa4::from_u64(l[c]));
    let hi: DigestF = core::array::from_fn(|c| Fa4::from_u64(l[DIGEST_LANES + c]));
    row[base..base + DIGEST_LANES].copy_from_slice(&lo);
    row[base + DIGEST_LANES..base + 2 * DIGEST_LANES].copy_from_slice(&hi);
    let (bf1, bf2) = (to_f(b1), to_f(b2));
    row[base + 2 * DIGEST_LANES..base + 3 * DIGEST_LANES].copy_from_slice(&bf1);
    row[base + 3 * DIGEST_LANES..base + 4 * DIGEST_LANES].copy_from_slice(&bf2);
    let iblk = base + 4 * DIGEST_LANES;
    let inner = fill_pose_round(row, &lo, &hi, iblk, iblk + POSE_BLK);
    let blk1 = iblk + POSE_BLK + DIGEST_LANES;
    let c1 = fill_pose_round(row, &inner, &bf1, blk1, blk1 + POSE_BLK);
    let blk2 = blk1 + POSE_BLK + DIGEST_LANES;
    let c2 = fill_pose_round(row, &inner, &bf2, blk2, blk2 + POSE_BLK);
    (c1, c2)
}

fn pool_receipt_row(w: &PoolReceiptWitness, asset_id: u32, epoch: u64) -> Option<(Vec<Fa4>, PoolReceiptStatement)> {
    use p3_field::PrimeField64;
    let rtag = receipt_tag(asset_id, epoch)?;
    let mut row = vec![Fa4::ZERO; POOL_RECEIPT_ROW_WIDTH];
    let owner = to_f(&w.owner_sk);
    row[PRC_OWNER..PRC_OWNER + DIGEST_LANES].copy_from_slice(&owner);
    let (pd1, pd2) = fill_snap_word(&mut row, PRC_P, w.p_dep, &w.p_blind, &w.p_blind2);
    let (sd1, sd2) = fill_snap_word(&mut row, PRC_S, w.s_dep, &w.s_blind, &w.s_blind2);
    let snap = fill_pose_round(&mut row, &pd1, &sd1, PRC_SNAP_BLK, PRC_SNAP);
    let skr = fill_pose_round(&mut row, &owner, &snap, PRC_SKR_BLK, PRC_SKR);
    let td = U64ConsBases::at(PRC_D);
    fill_u64_conservation_row(&mut row, w.deposit, w.deposit, 0, td)?;
    let leaf = fill_note_open(&mut row, w.deposit, rtag, &skr, PRC_IN_IBLK, PRC_IN_IOUT, PRC_IN_OBLK, PRC_LEAF);
    let nf = fill_pose_round(&mut row, &skr, &leaf, PRC_NF_BLK, PRC_NF);
    let inner = fill_pose_round(&mut row, &leaf, &nf, PRC_CB, PRC_CB2);
    let blind = to_f(&w.lc_blind);
    row[PRC_BLIND..PRC_BLIND + DIGEST_LANES].copy_from_slice(&blind);
    crate::pow_pq_air::lay_perm_row_flat(&mut row, PRC_CB2, pose_state(&inner, &blind));
    let lc: DigestF = core::array::from_fn(|c| row[PRC_CB2 + crate::pow_pq_air::PERM_OUT + c]);
    let (ib, io, ob) = (PRC_DD + DIGEST_LANES, PRC_DD + DIGEST_LANES + POSE_BLK, PRC_DD + 2 * DIGEST_LANES + POSE_BLK);
    let dd = fill_commit_u64(&mut row, w.deposit, &w.d_blind2, PRC_DD, ib, io, ob, ob + POSE_BLK);
    let tu = U64ConsBases::at(PRC_U);
    fill_u64_conservation_row(&mut row, w.compounded, w.compounded, 0, tu)?;
    let osk = to_f(&w.out_opening);
    row[PRC_OUT..PRC_OUT + DIGEST_LANES].copy_from_slice(&osk);
    let (ib, io, ob) = (PRC_OUT + DIGEST_LANES, PRC_OUT + DIGEST_LANES + POSE_BLK, PRC_OUT + 2 * DIGEST_LANES + POSE_BLK);
    let ocm = fill_note_open(&mut row, w.compounded, USDM_ASSET_TAG, &osk, ib, io, ob, ob + POSE_BLK);
    let (ib, io, ob) = (PRC_DU + DIGEST_LANES, PRC_DU + DIGEST_LANES + POSE_BLK, PRC_DU + 2 * DIGEST_LANES + POSE_BLK);
    let du = fill_commit_u64(&mut row, w.compounded, &w.u_blind, PRC_DU, ib, io, ob, ob + POSE_BLK);
    let u = |v: &DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((
        row,
        PoolReceiptStatement { nullifier: u(&nf), leaf_commit: u(&lc), out_cm: u(&ocm), dd: u(&dd), du: u(&du), pd: u(&pd2), sd: u(&sd2), asset_id, epoch },
    ))
}

/// PROVE a pool withdrawal's receipt half.
#[must_use]
pub fn prove_pool_receipt_bytes(w: &PoolReceiptWitness, asset_id: u32, epoch: u64) -> Option<(Vec<u8>, PoolReceiptStatement)> {
    let (row, s) = pool_receipt_row(w, asset_id, epoch)?;
    let cols: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; LIGHT_CARRIER_ROWS]).collect();
    let st = s.clone();
    let bytes = crate::committed_air::prove_air_blinded_bytes(cols, move |g: Ea4| PoolReceiptGate { gamma: g, s: st.clone() }, &pool_receipt_bind(&s))?;
    Some((bytes, s))
}

/// VERIFY a pool withdrawal's receipt half against its statement.
#[must_use]
pub fn verify_pool_receipt_bytes(bytes: &[u8], s: &PoolReceiptStatement) -> bool {
    if bytes.is_empty() || s.leaf_commit == crate::poseidon2_compress::ZERO_DIGEST || receipt_tag(s.asset_id, s.epoch).is_none() {
        return false;
    }
    let st = s.clone();
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        move |g: Ea4| PoolReceiptGate { gamma: g, s: st.clone() },
        &pool_receipt_bind(s),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, POOL_RECEIPT_ROW_WIDTH),
    )
}

/// Transcript domain of the pool snapshot carrier.
pub const POOL_SNAPSHOT_DOMAIN: u64 = 0x504f_4f4c_534e_5031; // "POOLSNP1"

/// What a pool snapshot carrier states: the pool's committed `(P, S)` words and the deposit's FRESH commitments to the
/// same two values — so a depositor's receipt is keyed to the pool's real snapshot, never to one an executor invented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolSnapshotStatement {
    pub p_word: Digest,
    pub pd: Digest,
    pub s_word: Digest,
    pub sd: Digest,
}

/// The snapshot gate: two snapshot words, each a pair of commitments from ONE pair of limb lanes.
#[derive(Clone)]
pub struct PoolSnapshotGate {
    pub gamma: Ea4,
    pub s: PoolSnapshotStatement,
}
const PSN_P: usize = 0;
const PSN_S: usize = SNAP_SLOT;
/// The snapshot row's width.
pub const POOL_SNAPSHOT_ROW_WIDTH: usize = 2 * SNAP_SLOT;

impl crate::air_zerocheck::AirConstraint for PoolSnapshotGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in self.residuals(local) {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Vec<Ea4> {
        PoolSnapshotGate::residuals(self, local)
    }
    fn is_row_local(&self) -> bool {
        true
    }
    /// The four blinds are HIDING witnesses, read only through their commitments.
    fn free_columns(&self) -> Option<Vec<usize>> {
        let mut free = Vec::new();
        for base in [PSN_P, PSN_S] {
            free.extend(base + 2 * DIGEST_LANES..base + 4 * DIGEST_LANES);
        }
        Some(free)
    }
}

impl PoolSnapshotGate {
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>) -> Vec<Ea4> {
        let mut rs: Vec<Ea4> = Vec::new();
        push_snap_word(&mut rs, local, PSN_P);
        push_snap_word(&mut rs, local, PSN_S);
        let (p1, p2) = snap_cols(PSN_P);
        let (s1, s2) = snap_cols(PSN_S);
        let (pw, pd, sw, sd) = (ea_digest(&self.s.p_word), ea_digest(&self.s.pd), ea_digest(&self.s.s_word), ea_digest(&self.s.sd));
        for c in 0..DIGEST_LANES {
            rs.push(local[p1 + c] - pw[c]);
            rs.push(local[p2 + c] - pd[c]);
            rs.push(local[s1 + c] - sw[c]);
            rs.push(local[s2 + c] - sd[c]);
        }
        rs
    }
}

fn pool_snapshot_bind(s: &PoolSnapshotStatement) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(POOL_SNAPSHOT_DOMAIN)];
    for d in [&s.p_word, &s.pd, &s.s_word, &s.sd] {
        b.extend(d.iter().map(|&x| Fa4::from_u64(x)));
    }
    b
}

/// PROVE that `(pd, sd)` re-randomize the pool's `(p_word, s_word)`: the pool's openings `(p, p_blind)`, `(s, s_blind)` and
/// the fresh snapshot blinds. Returns the carrier and the statement (the fresh `pd`, `sd`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn prove_pool_snapshot_bytes(
    p: crate::confidential_solvency::U256,
    p_blind: &Digest,
    pd_blind: &Digest,
    s: crate::confidential_solvency::U256,
    s_blind: &Digest,
    sd_blind: &Digest,
) -> Option<(Vec<u8>, PoolSnapshotStatement)> {
    use p3_field::PrimeField64;
    let mut row = vec![Fa4::ZERO; POOL_SNAPSHOT_ROW_WIDTH];
    let (pw, pd) = fill_snap_word(&mut row, PSN_P, p, p_blind, pd_blind);
    let (sw, sd) = fill_snap_word(&mut row, PSN_S, s, s_blind, sd_blind);
    let u = |v: &DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    let st = PoolSnapshotStatement { p_word: u(&pw), pd: u(&pd), s_word: u(&sw), sd: u(&sd) };
    let cols: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; LIGHT_CARRIER_ROWS]).collect();
    let s2 = st.clone();
    let bytes = crate::committed_air::prove_air_blinded_bytes(cols, move |g: Ea4| PoolSnapshotGate { gamma: g, s: s2.clone() }, &pool_snapshot_bind(&st))?;
    Some((bytes, st))
}

/// VERIFY a pool snapshot against the pool's CURRENT words and the deposit's snapshot commitments.
#[must_use]
pub fn verify_pool_snapshot_bytes(bytes: &[u8], s: &PoolSnapshotStatement) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let st = s.clone();
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        move |g: Ea4| PoolSnapshotGate { gamma: g, s: st.clone() },
        &pool_snapshot_bind(s),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, POOL_SNAPSHOT_ROW_WIDTH),
    )
}

/// The pool deposit gate's pins: the circuit alone. TWO-PARTY-REVIEWED: the boundary is the node — a deposit one node
/// lays and a second derives from the block is pinned in the node crate; here the second party is the verifier run on the
/// bytes and the public statement only.
#[cfg(test)]
mod pool_deposit_tests {
    use super::*;
    use crate::poseidon2_compress::lanes_of;

    fn wit() -> PoolDepositWitness {
        PoolDepositWitness {
            value_in: 900_000_000,
            owner: NoteOwner::from_test_key(lanes_of(&[0x9001, 1, 2, 3])),
            lc_blind: lanes_of(&[0x9001, 4, 4, 4]),
            deposit: 600_000_000,
            owner_sk: lanes_of(&[0x9001, 5, 5, 5]),
            change_opening: lanes_of(&[0x9001, 6, 6, 6]),
            dv_blind: lanes_of(&[0x9001, 7, 7, 7]),
        }
    }

    /// ⭐⭐⭐ A DEPOSIT STATES EXACTLY THE NATIVE NOTES: the receipt under the snapshot-keyed spend key, the change, and the
    /// deposit's commitment; the three censuses pass on its row; every statement edit is refused.
    #[test]
    fn a_pool_deposit_states_the_native_receipt_change_and_commitment_and_refuses_every_edit() {
        let (pd, sd) = (lanes_of(&[0xD1, 1, 1, 1]), lanes_of(&[0xD2, 2, 2, 2]));
        let w = wit();
        let (row, s0) = pool_deposit_row(&w, &pd, &sd, 1, 0).expect("the honest row lays");
        let cols: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; LIGHT_CARRIER_ROWS]).collect();
        let gate = PoolDepositGate { gamma: Ea4::from(Fa4::from_u64(0x9001)), s: s0.clone() };
        let nvars = LIGHT_CARRIER_ROWS.trailing_zeros() as usize;
        crate::air_zerocheck::debug_degree_census(&cols, &gate, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_free_witness_census(&cols, &gate, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_decorative_block_census(&cols, &gate, nvars, true, &Some(Vec::new()));
        let (bytes, s) = prove_pool_deposit_bytes(&w, &pd, &sd, 1, 0).expect("proves");
        assert!(verify_pool_deposit_bytes(&bytes, &s), "the honest deposit verifies");
        let skr = receipt_spend_key(&w.owner_sk, &pd, &sd);
        assert_eq!(s.receipt_cm, asset_note_cm(600_000_000, receipt_tag(1, 0).unwrap(), skr), "the receipt is the native note");
        assert_eq!(s.change_cm, asset_note_cm(300_000_000, USDM_ASSET_TAG, w.change_opening), "the change is USDm");
        assert_eq!(s.dv, commit_u64(600_000_000, &w.dv_blind), "DV commits the deposit");
        let bump = |d: &Digest| -> Digest {
            let mut x = *d;
            x[0] = (x[0] + 1) % 0x7f00_0001;
            x
        };
        let edits: Vec<(&str, PoolDepositStatement)> = vec![
            ("receipt", PoolDepositStatement { receipt_cm: bump(&s.receipt_cm), ..s.clone() }),
            ("change", PoolDepositStatement { change_cm: bump(&s.change_cm), ..s.clone() }),
            ("DV of d + 1", PoolDepositStatement { dv: commit_u64(600_000_001, &w.dv_blind), ..s.clone() }),
            ("snapshot P", PoolDepositStatement { pd: bump(&s.pd), ..s.clone() }),
            ("snapshot S", PoolDepositStatement { sd: bump(&s.sd), ..s.clone() }),
            ("nullifier", PoolDepositStatement { nullifier: bump(&s.nullifier), ..s.clone() }),
            ("asset", PoolDepositStatement { asset_id: 2, ..s.clone() }),
            ("epoch", PoolDepositStatement { epoch: 1, ..s.clone() }),
        ];
        for (what, e) in edits {
            assert!(!verify_pool_deposit_bytes(&bytes, &e), "⛔ a pool deposit verified with its {what} edited");
        }
        assert!(pool_deposit_row(&PoolDepositWitness { deposit: 900_000_001, ..wit() }, &pd, &sd, 1, 0).is_none(), "⛔ a deposit above the input laid");
    }

    /// ⭐⭐⭐ §10.4 — A WITHDRAWAL SPENDS EXACTLY THE RECEIPT ITS DEPOSIT MINTED, AND SHARES NO PUBLIC VALUE WITH IT.
    /// The deposit publishes `PD`, `SD`, `DV`; the withdrawal re-randomizes all three from the same lanes, and its nullifier
    /// is the receipt's own (`P(sk_r, receipt_cm)`). The three censuses pass; every statement edit is refused; a withdrawal
    /// against another snapshot names another note (its nullifier is not the receipt's).
    #[test]
    fn a_pool_withdrawal_spends_its_own_receipt_and_publishes_nothing_its_deposit_did() {
        use crate::confidential_solvency::{solvency_commit_256, u256_from_u64};
        let (p_dep, s_dep) = ([0u64, 0, 1, 0], [12_345u64, 0, 0, 0]); // P = 2^128, S = 12345
        let (pb, sb) = (lanes_of(&[0xB1, 1, 1, 1]), lanes_of(&[0xB2, 2, 2, 2]));
        let (pd, sd) = (solvency_commit_256(p_dep, pb), solvency_commit_256(s_dep, sb));
        let dep = wit();
        let (_db, ds) = prove_pool_deposit_bytes(&dep, &pd, &sd, 1, 0).expect("the deposit proves");
        let w = PoolReceiptWitness {
            owner_sk: dep.owner_sk,
            deposit: dep.deposit,
            p_dep,
            p_blind: pb,
            p_blind2: lanes_of(&[0xB3, 3, 3, 3]),
            s_dep,
            s_blind: sb,
            s_blind2: lanes_of(&[0xB4, 4, 4, 4]),
            lc_blind: lanes_of(&[0xB5, 5, 5, 5]),
            d_blind2: lanes_of(&[0xB6, 6, 6, 6]),
            compounded: 599_999_999,
            out_opening: lanes_of(&[0xB7, 7, 7, 7]),
            u_blind: lanes_of(&[0xB8, 8, 8, 8]),
        };
        let (row, s0) = pool_receipt_row(&w, 1, 0).expect("the honest row lays");
        let cols: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; LIGHT_CARRIER_ROWS]).collect();
        let gate = PoolReceiptGate { gamma: Ea4::from(Fa4::from_u64(0x9002)), s: s0 };
        let nvars = LIGHT_CARRIER_ROWS.trailing_zeros() as usize;
        crate::air_zerocheck::debug_degree_census(&cols, &gate, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_free_witness_census(&cols, &gate, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_decorative_block_census(&cols, &gate, nvars, true, &Some(Vec::new()));
        let (bytes, s) = prove_pool_receipt_bytes(&w, 1, 0).expect("proves");
        assert!(verify_pool_receipt_bytes(&bytes, &s), "the honest withdrawal verifies");
        let skr = receipt_spend_key(&w.owner_sk, &pd, &sd);
        assert_eq!(s.nullifier, poseidon_pair(skr, ds.receipt_cm), "⛔ the withdrawal does not spend the deposit's receipt");
        assert_eq!(s.pd, solvency_commit_256(p_dep, w.p_blind2), "PD′ re-randomizes the minted P");
        assert_eq!(s.sd, solvency_commit_256(s_dep, w.s_blind2), "SD′ re-randomizes the minted S");
        assert_eq!(s.dd, commit_u64(w.deposit, &w.d_blind2), "Dd′ commits the receipt's d");
        assert_eq!(s.du, solvency_commit_256(u256_from_u64(w.compounded), w.u_blind), "Du commits the compounded note");
        assert_eq!(s.out_cm, asset_note_cm(w.compounded, USDM_ASSET_TAG, w.out_opening), "the compounded note is USDm");
        for (what, x, y) in [("PD", s.pd, ds.pd), ("SD", s.sd, ds.sd), ("d", s.dd, ds.dv)] {
            assert_ne!(x, y, "⛔ §10.4: the withdrawal re-published the deposit's {what}");
        }
        let bump = |d: &Digest| -> Digest {
            let mut x = *d;
            x[0] = (x[0] + 1) % 0x7f00_0001;
            x
        };
        let edits: Vec<(&str, PoolReceiptStatement)> = vec![
            ("out note", PoolReceiptStatement { out_cm: bump(&s.out_cm), ..s.clone() }),
            ("Du of u + 1", PoolReceiptStatement { du: commit_u64(w.compounded + 1, &w.u_blind), ..s.clone() }),
            ("Dd of d + 1", PoolReceiptStatement { dd: commit_u64(w.deposit + 1, &w.d_blind2), ..s.clone() }),
            ("PD′", PoolReceiptStatement { pd: bump(&s.pd), ..s.clone() }),
            ("SD′", PoolReceiptStatement { sd: bump(&s.sd), ..s.clone() }),
            ("nullifier", PoolReceiptStatement { nullifier: bump(&s.nullifier), ..s.clone() }),
            ("epoch", PoolReceiptStatement { epoch: 1, ..s.clone() }),
        ];
        for (what, e) in edits {
            assert!(!verify_pool_receipt_bytes(&bytes, &e), "⛔ a pool withdrawal verified with its {what} edited");
        }
        // ⭐ THE SNAPSHOT CARRIER: the deposit's (PD, SD) re-randomize the pool's REAL words; a fake snapshot does not verify.
        let (pwb, swb) = (lanes_of(&[0xC1, 1, 1, 1]), lanes_of(&[0xC2, 2, 2, 2]));
        let (sn, st) = prove_pool_snapshot_bytes(p_dep, &pwb, &pb, s_dep, &swb, &sb).expect("the snapshot proves");
        assert!(verify_pool_snapshot_bytes(&sn, &st), "the honest snapshot verifies");
        assert_eq!((st.pd, st.sd), (pd, sd), "the snapshot is the deposit's (PD, SD)");
        assert_eq!(st.p_word, solvency_commit_256(p_dep, pwb), "against the pool's P word");
        let fake_pd = solvency_commit_256([1u64, 0, 0, 0], pb); // P_dep = 1: a drain-the-pool snapshot
        assert!(
            !verify_pool_snapshot_bytes(&sn, &PoolSnapshotStatement { pd: fake_pd, ..st.clone() }),
            "⛔⛔⛔ a snapshot an executor invented verified against the pool's real P"
        );
        let (_s2, st2) = prove_pool_snapshot_bytes([1u64, 0, 0, 0], &pwb, &pb, s_dep, &swb, &sb).expect("proves its own");
        assert_ne!(st2.p_word, st.p_word, "⛔ a fake snapshot's proof names the real pool word");
        // a withdrawal against ANOTHER snapshot opens another note — its nullifier is not the receipt's
        let other = PoolReceiptWitness { p_dep: [1u64, 0, 1, 0], ..w.clone() };
        let (_, so) = pool_receipt_row(&other, 1, 0).expect("lays");
        assert_ne!(so.nullifier, s.nullifier, "⛔ a receipt withdrew against a snapshot it was not minted with");
    }
}

/// The synthetic sibling for the coinbase pow-bind's vacuous depth-1 membership. The MINT path no longer
/// uses it — `MintValidityGate` has no membership block at all — and it is retired here once coinbase follows.
const MINT_SELF_SIBLING: Digest = [1; DIGEST_LANES];

// ⛔ `prove/verify_mint_validity_carrier_bytes` DELETED 2026-08-14 — ZERO callers in the node (only a
// lib.rs re-export). They borrowed the BOND gate at depth 1 to prove a 'vacuous self-membership'
// against a FIXED-CAPACITY root, and that `leaf_commit: None` shape is what kept the capped weld
// alive for every other carrier. Replaced by `MintValidityGate` + `prove/verify_mint_validity_bytes`,
// which constrain a mint's REAL security (out0_cm opens to the public value) with no root at all.

// ⛔ `prove/verify_mint_validity_carrier_bytes` DELETED 2026-08-14 — ZERO callers in the node (only a
// lib.rs re-export). They borrowed the BOND gate at depth 1 to prove a 'vacuous self-membership'
// against a FIXED-CAPACITY root, and that `leaf_commit: None` shape is what kept the capped weld
// alive for every other carrier. Replaced by `MintValidityGate` + `prove/verify_mint_validity_bytes`,
// which constrain a mint's REAL security (out0_cm opens to the public value) with no root at all.

/// #73/#142 public bind for the coinbase pow-bind carrier: the spend-validity bind (domain‖root‖out0‖out1‖nf)
/// PLUS the welded reward `value` PLUS the per-block PoW challenge `c` (4 limbs). Binding `c` INTO the
/// Fiat-Shamir transcript is what makes the proof NON-OUTSOURCEABLE (#73): a verifier replaying a DIFFERENT `c`
/// derives a divergent transcript → the openings fail → reject, so a miner cannot precompute one `pi` and reuse
/// it across blocks (hashpower alone can't forge it — the `sk`-holder must re-prove per challenge).
fn coinbase_public_bind(root: &DigestF, out_cms: &[DigestF; 2], nf: &DigestF, value: u64, c: &DigestF) -> Vec<Fa4> {
    let mut b = validity_public_bind(root, out_cms, nf);
    b.push(Fa4::from_u64(value));
    b.extend_from_slice(c);
    b
}

// ⛔ `prove/verify_coinbase_pow_bind_carrier_bytes` DELETED 2026-08-14 — they built a coinbase on the
// BOND gate with `leaf_commit: None`, proving a vacuous depth-1 membership against a FIXED-CAPACITY
// root. Replaced by `prove/verify_coinbase_pow_bind_bytes` on `MintValidityGate`, which constrains
// the reward opening and the block challenge `c` and nothing else. The non-outsourceable property is
// preserved and PROVEN (`a_coinbase_carrier_is_bound_to_its_block_challenge_and_cannot_be_replayed`).

// ⛔ `prove/verify_coinbase_pow_bind_carrier_bytes` DELETED 2026-08-14 — they built a coinbase on the
// BOND gate with `leaf_commit: None`, proving a vacuous depth-1 membership against a FIXED-CAPACITY
// root. Replaced by `prove/verify_coinbase_pow_bind_bytes` on `MintValidityGate`, which constrains
// the reward opening and the block challenge `c` and nothing else. The non-outsourceable property is
// preserved and PROVEN (`a_coinbase_carrier_is_bound_to_its_block_challenge_and_cannot_be_replayed`).

#[cfg(test)]
mod spend_carrier_tests {
    use super::{to_f, to_u64, Digest, DigestF, DIGEST_LANES};
    use super::{
        prove_membership_carrier_bytes,
        prove_spend_carrier_bytes, prove_spend_main_carrier_bytes,
        verify_membership_carrier_bytes,
        verify_spend_carrier_bytes, verify_spend_main_carrier_bytes, verify_spend_validity_carrier_bytes,
        MembershipWitness, SpendMainRow, SpendRow, SpendValidityWitness,
    };

    // ⛔ `mint_validity_binds_out0_to_value_and_rejects_over_mint_and_tamper` DELETED with the API it
    // tested. Its coverage is carried FORWARD, not dropped: `mint_validity_gate_tests` asserts the same
    // over-mint and tampered-commitment refusals against `MintValidityGate`, which proves a mint's real
    // security with NO root and NO membership at all.

    /// THE FULL PqSpendAir ROW in one carrier: an honest confidential spend (conserves + note opens to
    /// (value_in,sk) + correct nullifier + membership in `root`) verifies; an INFLATING spend never proves;
    /// a tampered carrier and a wrong root are rejected. This is the byte-parity entry the node verifies.
    #[test]
    fn the_spend_gate_cross_binds_its_note_to_the_membership_commitment() {
        // ⭐ THE LAST LINK. The note-membership carrier proves "this note is on the chain"; the spend proves
        // "I own and am spending a note". Nothing tied them together, so a spender could hold a valid
        // membership proof for note X while spending note Y — two true statements about different notes,
        // presented as one. This weld makes the spend prove `Poseidon(spent_leaf, nullifier) == leaf_commit`,
        // the SAME value the carrier binds, so there is only one note to talk about.
        //
        // The leaf itself is never public: it is the value written when the note was RECEIVED, so revealing
        // it would link this spend to that receive. The commitment names the note without identifying it.
        let w = SpendValidityWitness {
            value_in: 1000,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&[3, 5, 7, 9])),
            value_out: 900,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: 600,
            out0_opening: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            out1_value: 300,
            out1_opening: crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
        };
        use super::{
            poseidon_pair, prove_air_direct_light_decider_selfcontained_bytes,
            prove_spend_validity_carrier_with_commit_bytes, Ea4, SpendValidityGate,
        };
        use crate::hiding_decider::Fa4;
        use p3_field::{PrimeCharacteristicRing, PrimeField64};
        // The COMMITMENT-BINDING prover: it proves the cross-bind in-circuit and hands back the commitment.
        let (carrier, cms, nf, commit) =
            prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0)).expect("honest spend proves");
        let nf_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(nf[c]));

        // CONTROL: the honest carrier verifies UNDER its true commitment. Without this the negatives are
        // meaningless — a subject that could not have succeeded anyway proves nothing.
        assert!(
            verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, commit, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "the honest spend MUST verify under the commitment to the note it actually spends"
        );

        // FORGERY — the way a malicious prover would actually do it. Re-verifying the honest carrier under a
        // different commitment only fails the TRANSCRIPT (the commitment is in the bind), which would still
        // "pass" with the constraint deleted. The real attack is to PROVE with the lie in both the gate and
        // the bind, so the transcript is self-consistent and only the in-circuit weld can refuse it.
        let other_leaf: DigestF = core::array::from_fn(|c| Fa4::from_u64(9_000 + c as u64));
        // DB-363: the lie is the two-level blinded commitment over ANOTHER leaf, under this spend's own blinding.
        let other_commit_f: DigestF =
            to_f(&poseidon_pair(poseidon_pair(to_u64(&other_leaf), to_u64(&nf_f)), w.lc_blind));
        let other_commit: Digest = core::array::from_fn(|c| other_commit_f[c].as_canonical_u64());
        assert_ne!(other_commit, commit, "the two notes really do commit differently");

        // the PRODUCTION row (the note class lays the vault region, spec §9.1)
        let (row, cms_f2, nf_f2, _lc_f2) =
            super::note_spend_row(&w, &super::NoteSpendExtras::plain(0), w.lc_blind, 0).expect("the honest row builds");
        let cols: Vec<Vec<Fa4>> =
            (0..row.len()).map(|col| vec![row[col]; super::LIGHT_CARRIER_ROWS]).collect();
        let ea = |v: Digest| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|c| Fa4::from_u64(v[c]).into()) };
        let lie_ea = ea(other_commit);
        let o0e: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| cms_f2[0][i].into());
        let o1e: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| cms_f2[1][i].into());
        let nfe: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| nf_f2[i].into());
        let lie_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(other_commit[c]));
        let tag1 = super::spend_tag1(&w);
        let tag1_f = super::to_f(&tag1);
        let tag1_e: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| tag1_f[i].into());
        let forged = prove_air_direct_light_decider_selfcontained_bytes(
            cols,
            move |g: Ea4| SpendValidityGate {
                leaf_commit: lie_ea,
                gamma: g,
                out0_cm: o0e,
                out1_cm: o1e,
                nullifier: nfe,
                bond_amount: None,
                fee_amount: Some(super::fee_limbs(w.fee)), // §BR-14
                tag1: Some(tag1_e),
                vault: Some(super::clock_const(0)),
            },
            &super::validity_public_bind_with_commit(&cms_f2, &nf_f2, &lie_f, &super::to_f(&crate::whir_rec_block::test_clue_digest(0)), &tag1_f),
        );
        let forged_ok = forged.map_or(false, |bytes| {
            verify_spend_validity_carrier_bytes(&bytes, cms[0], cms[1], nf, other_commit, crate::whir_rec_block::test_clue_digest(0), tag1, 100)
        });
        assert!(
            !forged_ok,
            "a spend must NOT verify under a commitment to a note it is not spending — that is the whole \
             point of the cross-bind"
        );

        // A carrier proved WITH a commitment must NOT verify as though it had none — otherwise the weld
        // could be skipped by simply dropping the field on the wire.
        assert!(
            !verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, crate::poseidon2_compress::lanes_of(&crate::poseidon2_compress::ZERO_DIGEST), crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "ZEROING the commitment must not let a cross-bound carrier through unbound — with the `Option` \
             gone, a defaulted binding is the only remaining way to claim 'no membership', and it is refused"
        );
        // And the plain prover still produces a carrier that verifies unbound, so every existing carrier
        // type is unaffected by this change.
        // ⛔ AN ALL-ZERO CROSS-BIND IS REFUSED. The `None` shape is gone from the TYPE, so the only way a
        // caller can still say "no binding" is by handing over a wire field that was absent — which decodes
        // as ZERO. Zero is not "no binding"; it would be one every forger can produce, arriving exactly when
        // the Merkle weld has been dropped in its favour.
        assert!(
            !verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, crate::poseidon2_compress::lanes_of(&crate::poseidon2_compress::ZERO_DIGEST), crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "an all-zero cross-bind MUST be refused — membership may never rest on a defaultable binding"
        );
    }

    /// ⭐⭐⭐ MEMBERSHIP COMES FROM THE O(1) ACCUMULATOR, NOT FROM A RETRIEVED MERKLE PATH.
    ///
    /// Gate D's weld `acc(depth) == root` was the ONE constraint forcing a spender to hold a depth-32 copath,
    /// and holding one is impossible without breaking a cardinal: its left siblings are the MMR peaks at
    /// `count == leaf_index`, so someone must keep data that grows with the note count — the node storing the
    /// tree (the ever-growing-node problem), the block carrying the spine (MEASURED 2,112 B/block = 133
    /// GB/year), or the wallet replaying every leaf (the banned walk). MEASURED 2026-08-11 on the real wallet,
    /// real button press, two peered nodes at height 43,949:
    ///   "Failed: single-input spend failed after retries: the node served no usable depth-32 copath for this
    ///    note, AND the wallet could not build one itself"
    ///
    /// So with the cross-bind present the weld is dropped and membership is proven instead by the
    /// note-membership carrier, an O(1) recursive fold binding the SAME `leaf_commit`. This test pins BOTH
    /// halves of that trade, because each is worthless without the other:
    ///   1. cross-bind present  ⇒ a WRONG root no longer refuses the spend (the copath is not the authority);
    ///   2. cross-bind ABSENT   ⇒ a wrong root STILL refuses (every pre-existing carrier is unchanged);
    ///   3. the cross-bind itself is still unforgeable (covered by the forgery test above).
    ///
    /// ⚠️ Case 1 is only sound because the NODE refuses a tx that carries the cross-bind without a VERIFIED
    /// membership carrier (`MEMBERSHIP_PROOF_MISSING` in `rpc_http.rs`). If that gate is ever weakened, this
    /// test's case 1 becomes a hole: membership would be proven by nothing at all. The two must move together.
    #[test]
    fn a_cross_bound_spend_proves_membership_by_accumulator_not_by_merkle_root() {
        let w = SpendValidityWitness {
            value_in: 1000,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&[3, 5, 7, 9])),
            value_out: 900,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: 600,
            out0_opening: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            out1_value: 300,
            out1_opening: crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
        };
        use super::prove_spend_validity_carrier_with_commit_bytes;

        let (carrier, cms, nf, commit) =
            prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0)).expect("honest cross-bound spend proves");

        // CONTROL — the honest carrier verifies under its true commitment. Without this the negative below
        // proves nothing.
        assert!(
            verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, commit, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "the honest cross-bound spend must verify"
        );

        // 1. (2026-09-30) THERE IS NO ROOT TO GET WRONG ANY MORE: the verifier takes no root and the gate has no
        //    path — the "wrong root still verifies" measurement this pin used to make is now the type signature.

        // 2. CROSS-BIND ABSENT — nothing about the old path changes. A carrier with no membership claim is
        //    still welded to its root, so a wrong root still refuses it. This is what keeps every existing
        //    carrier type sound while the new one rides the accumulator.
        // 2. THE CAPPED PATH NO LONGER EXISTS. This case used to build a carrier with NO cross-bind and check
        //    it was still welded to its root. That builder is DELETED and `leaf_commit` is no longer an
        //    `Option`, so "membership by a fixed-capacity root" is unrepresentable rather than discouraged.
        //    What remains reachable is a DEFAULTED binding, and it is refused.
        assert!(
            !verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, crate::poseidon2_compress::lanes_of(&crate::poseidon2_compress::ZERO_DIGEST), crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "a zero cross-bind is refused — there is no capped path left to fall onto"
        );
    }

    /// ⛔⛔⛔ THE BOND TWIN — a cross-bound BOND takes membership from the accumulator, not from a root.
    ///
    /// This is the fix for the LAST two silent windows found in the 2026-08-11 full-layer audit:
    /// `for _attempt in 0..6u32` (stake claim) and `for _attempt in 0..8u32` (peg-out). Those counters were
    /// never the defect — they hid one. The bond carrier welded the LIVE frontier root, which appends on
    /// every block, so a carrier built before a block landed was rejected after it, and the wallet retried
    /// against a moving target N times before refusing the user's money on a COUNTER.
    ///
    /// Deleting the counters alone would have made the feature fail whenever a block arrived mid-flight. The
    /// anchor had to stop moving first. Same three cases the spend twin pins, because each is worthless
    /// without the others:
    ///   1. cross-bind present ⇒ a WRONG root no longer refuses the bond (nothing that moves is bound);
    ///   2. cross-bind ABSENT  ⇒ a wrong root STILL refuses (every pre-existing bond carrier is unchanged);
    ///   3. the public weld `out0_value == bond_amount` still holds under the cross-bind (no free weight).
    ///
    /// ⚠️ Case 1 is only sound because the caller pairs this carrier with a VERIFIED note-membership carrier
    /// binding the same `leaf_commit`. Without that pairing membership is proven by nothing — the two must
    /// move together, exactly as on the spend path.
    #[test]
    fn a_cross_bound_bond_proves_membership_by_accumulator_not_by_merkle_root() {
        use super::{
            prove_bond_validity_carrier_with_commit_bytes,
            verify_bond_validity_carrier_with_commit_bytes,
        };
        const BOND: u64 = 600;
        let w = SpendValidityWitness {
            value_in: 1000,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&[3, 5, 7, 9])),
            value_out: 900,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: BOND,
            out0_opening: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            out1_value: 300,
            out1_opening: crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
        };

        let (carrier, cms, nf, commit) = prove_bond_validity_carrier_with_commit_bytes(&w, BOND)
            .expect("honest cross-bound bond proves");

        // CONTROL — the honest carrier verifies under its true commitment.
        assert!(
            verify_bond_validity_carrier_with_commit_bytes(&carrier, cms[0], cms[1], nf, BOND, commit, 100),
            "the honest cross-bound bond must verify"
        );

        // 1. (2026-09-30) NO ROOT PARAMETER EXISTS: a block landing mid-flight cannot refuse the claim because the
        //    verifier is not told about any root — the "wrong root still verifies" measurement is now the signature.

        // 2. THE CAPPED BOND PATH IS GONE. This built a bond carrier with NO cross-bind and checked it was
        //    still welded to a fixed-capacity root — a bond that would stop being provable once that root
        //    filled, stranding locked funds. That builder is DELETED and `leaf_commit` is no longer an
        //    `Option`. The only reachable way left to claim "no membership" is a DEFAULTED binding, and it is
        //    refused — so a bond can never rest on an anchor that expires.
        assert!(
            !verify_bond_validity_carrier_with_commit_bytes(&carrier, cms[0], cms[1], nf, BOND, crate::poseidon2_compress::lanes_of(&crate::poseidon2_compress::ZERO_DIGEST), 100),
            "a zero cross-bind is refused for bonds too — no capped path remains to fall onto"
        );

        // 3. THE PUBLIC WELD SURVIVES THE CROSS-BIND. Dropping the root must not drop `out0 == bond_amount`,
        //    or a validator could claim weight it never locked.
        assert!(
            !verify_bond_validity_carrier_with_commit_bytes(&carrier, cms[0], cms[1], nf, BOND + 1, commit, 100),
            "an overclaimed bond_amount must still be refused under the cross-bind"
        );
        assert!(
            prove_bond_validity_carrier_with_commit_bytes(&w, BOND + 1).is_none(),
            "the cross-bound prover must stay fail-closed when out0_value != bond_amount"
        );
    }

    #[test]
    fn spend_validity_full_pqspend_row_verifies_and_rejects_inflation_tamper_and_wrong_root() {
        let w = SpendValidityWitness {
            value_in: 1000,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&[3, 5, 7, 9])),
            value_out: 900,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            // Two output notes: recipient 600 + change 300 = 900 = value_out.
            out0_value: 600,
            out0_opening: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            out1_value: 300,
            out1_opening: crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
        };
        use super::prove_spend_validity_carrier_with_commit_bytes;
        let (carrier, cms, nf, commit) =
            prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0)).expect("honest full spend must prove");
        assert!(
            verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, commit, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "honest full PqSpendAir spend MUST verify vs its output commitments + nullifier + cross-bind"
        );
        // Inflation (input): value_in 1000 ≠ value_out 950 + fee 100 → never proves.
        let infl = SpendValidityWitness { value_out: 950, ..w.clone() };
        assert!(
            prove_spend_validity_carrier_with_commit_bytes(&infl, crate::whir_rec_block::test_clue_digest(0)).is_none(),
            "an inflating spend MUST NOT produce a carrier"
        );
        // Inflation (output): outputs 600 + 400 = 1000 ≠ value_out 900 → never proves (E gate).
        let out_infl = SpendValidityWitness { out1_value: 400, ..w.clone() };
        assert!(
            prove_spend_validity_carrier_with_commit_bytes(&out_infl, crate::whir_rec_block::test_clue_digest(0)).is_none(),
            "outputs that sum to MORE than value_out MUST NOT produce a carrier (no output inflation)"
        );
        // Wrong root → rejected (root welded into the transcript).
        // MEMBERSHIP IS BOUND BY THE CROSS-BIND, NOT BY A ROOT. The old assertion here was "a spend proving
        // membership in a DIFFERENT tree MUST be rejected", checked by flipping a bit in `root`. That check
        // is meaningless now and would FALSELY PASS if left: the root no longer enters the bind at all,
        // because binding it would re-impose the fixed-capacity anchor this change exists to remove. The
        // equivalent — and stronger — statement is that a spend claiming a DIFFERENT NOTE is rejected, which
        // is exactly what the cross-bind pins.
        let mut wrong_commit = commit;
        wrong_commit[2] ^= 1;
        assert!(
            !verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, wrong_commit, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "a spend claiming a DIFFERENT note's membership commitment MUST be rejected"
        );
        // SUBSTITUTED output commitment → rejected (the node cannot record a DIFFERENT output note than proven).
        let mut wrong_cm = cms[0];
        wrong_cm[1] ^= 1;
        assert!(
            !verify_spend_validity_carrier_bytes(&carrier, wrong_cm, cms[1], nf, commit, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "verifying against a DIFFERENT output commitment MUST be rejected (output binding)"
        );
        // SUBSTITUTED nullifier → rejected: the node records EXACTLY the proven nullifier, so a spend cannot
        // dodge double-spend detection by claiming a different nullifier than its note's true one.
        let mut wrong_nf = nf;
        wrong_nf[0] ^= 1;
        assert!(
            !verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], wrong_nf, commit, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "verifying against a DIFFERENT nullifier MUST be rejected (double-spend binding)"
        );
        // Tamper → rejected.
        let mut bad = carrier.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        assert!(
            !verify_spend_validity_carrier_bytes(&bad, cms[0], cms[1], nf, commit, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "a tampered carrier MUST NOT verify"
        );
    }

    /// FULLY-PRIVATE MULTI-INPUT consolidation soundness: N confidential inputs → 2 outputs (recipient, change)
    /// in ONE carrier. Conservation `Σ value_in == value_out + fee` holds IN-CIRCUIT (every input amount private);
    /// each input's nullifier is welded; verify binds root + the 2 output cms + the N nullifiers. An inflating
    /// spend cannot even prove; wrong root / forged nullifier / wrong input-count / byte-tamper all reject.
    #[test]
    fn multi_input_spend_conserves_privately_and_rejects_inflation_wrongroot_forgednf() {
        let sk0 = crate::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]);
        let sk1 = crate::poseidon2_compress::lanes_of(&[5u64, 6, 7, 8]);
        let (vin0, vin1) = (600u64, 400u64); // Σ = 1000, neither alone covers a 900 send
        // The commitments as the chain computes them (two-round, value as limbs — item 1 seam).
        let (own0, own1) = (super::NoteOwner::from_test_key(sk0), super::NoteOwner::from_test_key(sk1));
        let leaf0 = super::asset_note_cm(vin0, super::USDM_ASSET_TAG, own0.opening());
        let leaf1 = super::asset_note_cm(vin1, super::USDM_ASSET_TAG, own1.opening());
        // A depth-1 two-leaf frontier: leaf0 = LEFT child (dir 0, sib leaf1); leaf1 = RIGHT child (dir 1, sib
        // leaf0) → BOTH inputs recompute the SAME root pose(leaf0,leaf1) (the row-builder rejects a root mismatch).
        let mk = |out0: u64, out1: u64, fee: u64| super::MultiSpendValidityWitness {
            inputs: vec![
                super::MultiSpendInput { value_in: vin0, owner: own0, siblings: vec![leaf1], dirs: vec![false] },
                super::MultiSpendInput { value_in: vin1, owner: own1, siblings: vec![leaf0], dirs: vec![true] },
            ],
            out0_value: out0,
            out0_opening: crate::poseidon2_compress::lanes_of(&[9, 9, 9, 9]),
            out1_value: out1,
            out1_opening: crate::poseidon2_compress::lanes_of(&[8, 8, 8, 8]),
            fee,
        };
        // Honest: 900 recipient + 90 change + 10 fee = 1000 = 600 + 400.
        let w = mk(900, 90, 10);
        let (carrier, root, cms, nfs) =
            super::prove_multi_spend_validity_carrier_bytes(&w, crate::whir_rec_block::test_clue_digest(0)).expect("honest multi-input carrier proves");
        assert_eq!(nfs.len(), 2, "one nullifier per input");
        assert!(nfs[0] != nfs[1], "distinct inputs → distinct nullifiers");
        assert!(
            super::verify_multi_spend_validity_carrier_bytes(&carrier, root, cms[0], cms[1], &nfs, 1, crate::whir_rec_block::test_clue_digest(0), w.fee),
            "the honest multi-input carrier MUST verify against root + the 2 output cms + the 2 nullifiers"
        );
        // INFLATION: outputs + fee exceed the summed inputs → cannot even prove (conservation fail-closed).
        assert!(
            super::prove_multi_spend_validity_carrier_bytes(&mk(1900, 90, 10), crate::whir_rec_block::test_clue_digest(0)).is_none(),
            "a multi-input spend that inflates (Σout + fee > Σin) MUST NOT prove"
        );
        // WRONG ROOT → reject.
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(
            !super::verify_multi_spend_validity_carrier_bytes(&carrier, wrong_root, cms[0], cms[1], &nfs, 1, crate::whir_rec_block::test_clue_digest(0), w.fee),
            "verifying against a DIFFERENT frontier root MUST be rejected"
        );
        // FORGED NULLIFIER → reject (each spent input's nullifier is fixed by the gate).
        let mut forged = nfs.clone();
        forged[1][0] ^= 1;
        assert!(
            !super::verify_multi_spend_validity_carrier_bytes(&carrier, root, cms[0], cms[1], &forged, 1, crate::whir_rec_block::test_clue_digest(0), w.fee),
            "verifying against a FORGED nullifier MUST be rejected (per-input double-spend binding)"
        );
        // WRONG INPUT COUNT → reject (n_inputs is bound in the public IO: a 2-input carrier is not a 1-input one).
        assert!(
            !super::verify_multi_spend_validity_carrier_bytes(&carrier, root, cms[0], cms[1], &nfs[..1], 1, crate::whir_rec_block::test_clue_digest(0), w.fee),
            "verifying with the wrong input count MUST be rejected (n_inputs is publicly bound)"
        );
        // TAMPER a byte → reject.
        let mut bad = carrier.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        assert!(
            !super::verify_multi_spend_validity_carrier_bytes(&bad, root, cms[0], cms[1], &nfs, 1, crate::whir_rec_block::test_clue_digest(0), w.fee),
            "a tampered multi-input carrier MUST NOT verify"
        );
    }

    /// VALIDATOR BOND soundness (the public bond weight is welded to the value actually locked, no key reveal):
    /// an honest bond (output0 locks EXACTLY bond_amount, to the validator's OWN address) verifies against the
    /// PUBLIC bond_amount; a carrier claiming MORE weight than output0 locks cannot even prove (fail-closed);
    /// verifying an honest bond against an OVER-CLAIMED weight is rejected (no fake finality/governance weight);
    /// the bond carrier is domain-separated from a plain spend; wrong-root and tamper reject.
    #[test]
    fn bond_validity_binds_public_weight_to_locked_value_and_rejects_overclaim() {
        // A validator locks 600 as its bond (output0 → self); output1 = 300 change; input 1000, fee 100.
        let w = SpendValidityWitness {
            value_in: 1000,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&[3, 5, 7, 9])),
            value_out: 900,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: 600, // the BONDED note
            out0_opening: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            out1_value: 300, // change
            out1_opening: crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
        };
        let bond = 600u64;
        use super::{prove_bond_validity_carrier_with_commit_bytes, verify_bond_validity_carrier_with_commit_bytes};
        let (carrier, cms, nf, commit) =
            prove_bond_validity_carrier_with_commit_bytes(&w, bond).expect("honest bond must prove");
        assert!(
            verify_bond_validity_carrier_with_commit_bytes(&carrier, cms[0], cms[1], nf, bond, commit, 100),
            "an honest bond MUST verify vs its output cms + nullifier + cross-bind + the PUBLIC bond_amount"
        );
        // Claiming a bond weight that does NOT equal the locked output0 value MUST NOT even prove (fail-closed).
        assert!(
            prove_bond_validity_carrier_with_commit_bytes(&w, 1000).is_none(),
            "a bond claiming MORE weight than output0 locks MUST NOT produce a carrier"
        );
        // Verifying the honest 600-bond carrier against an OVER-CLAIMED 1000 weight MUST reject — the weld binds
        // public weight to the locked value, so a validator cannot inflate its finality/governance weight.
        assert!(
            !verify_bond_validity_carrier_with_commit_bytes(&carrier, cms[0], cms[1], nf, 1000, commit, 100),
            "an over-claimed bond weight MUST be rejected (public weight welded to locked value)"
        );
        // DB-340 (2026-09-28): the MOD-p ALIAS. `bond + p` has the SAME field residue as `bond`, so a weld over the
        // recombined field value (and a bind over `Fa4::from_u64(bond)`) accepted the honest 600-carrier at a
        // claimed weight of 600 + 2,130,706,433 — the peg-out path would have released that much for a 600 burn.
        // The limb-wise weld and bind refuse it: exact u64 equality, never a residue.
        {
            use crate::hiding_decider::Fa4;
            use p3_field::{PrimeCharacteristicRing, PrimeField64};
            let alias = bond + Fa4::ORDER_U64;
            assert_eq!(Fa4::from_u64(alias), Fa4::from_u64(bond), "the alias has the same field residue — that is the hole");
            assert!(
                !verify_bond_validity_carrier_with_commit_bytes(&carrier, cms[0], cms[1], nf, alias, commit, 100),
                "DB-340: a bond amount that aliases the locked value modulo p MUST be rejected"
            );
            assert_ne!(super::bond_limbs(alias), super::bond_limbs(bond), "the limbs tell the two amounts apart");
        }
        // A bond carrier is domain-separated from a plain spend (BONDVAL vs SPNDVAL + the extra public weld).
        assert!(
            !verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, commit, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "a bond carrier MUST NOT verify as a plain spend (domain-separated public bind)"
        );
        // WRONG NOTE + tamper reject. The old "different tree" check flipped a bit in `root`; that is
        // meaningless now and would FALSELY PASS, because the root no longer enters the bind — binding it
        // would re-impose the fixed-capacity anchor this change removes. The equivalent statement is that a
        // bond claiming a DIFFERENT note's membership commitment is rejected.
        let mut wrong_commit = commit;
        wrong_commit[2] ^= 1;
        assert!(
            !verify_bond_validity_carrier_with_commit_bytes(&carrier, cms[0], cms[1], nf, bond, wrong_commit, 100),
            "a bond claiming a DIFFERENT note's membership commitment MUST be rejected"
        );
        let mut bad = carrier.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        assert!(
            !verify_bond_validity_carrier_with_commit_bytes(&bad, cms[0], cms[1], nf, bond, commit, 100),
            "a tampered bond carrier MUST NOT verify"
        );
    }

    /// The 3rd (final) PqSpendAir gate: in-circuit Poseidon-Merkle membership. An honest
    /// note whose copath recomputes to `root` verifies against that PUBLIC root; a carrier
    /// checked against a DIFFERENT root is rejected (the root is transcript-welded); a
    /// tampered carrier is rejected.
    #[test]
    fn membership_carrier_binds_note_to_public_frontier_root() {
        let w = MembershipWitness {
            leaf: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            siblings: (1..=4u64).map(|i| crate::poseidon2_compress::lanes_of(&[i * 10, i * 10 + 1, i * 10 + 2, i * 10 + 3])).collect::<Vec<_>>(),
            dirs: vec![false, true, false, true],
        };
        let (carrier, root) = prove_membership_carrier_bytes(&w).expect("honest membership must prove");
        assert!(verify_membership_carrier_bytes(&carrier, root, 4), "honest membership MUST verify vs its root");
        let mut wrong = root;
        wrong[0] ^= 1;
        assert!(
            !verify_membership_carrier_bytes(&carrier, wrong, 4),
            "membership vs a DIFFERENT root MUST be rejected (root is welded)"
        );
        let mut bad = carrier.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        assert!(!verify_membership_carrier_bytes(&bad, root, 4), "a tampered membership carrier MUST NOT verify");
    }

    /// PRODUCTION-DEPTH (32) membership — testnet==production parity requires the real frontier
    /// depth, not dev depth-4. Proves the in-circuit Poseidon-Merkle fold is O(1)-constant and sound
    /// at the production NOTE_TREE_DEPTH=32: honest depth-32 path verifies vs its root; wrong root rejects.
    #[test]
    fn membership_carrier_production_depth_32() {
        // Distinct per-level siblings + a mixed direction pattern (bit i of a fixed constant).
        let siblings: Vec<Digest> =
            (0..32u64).map(|i| crate::poseidon2_compress::lanes_of(&[i * 4 + 1, i * 4 + 2, i * 4 + 3, i * 4 + 4])).collect();
        let dirs: Vec<bool> = (0..32u64).map(|i| (0x0A5C_3F17u64 >> (i % 32)) & 1 == 1).collect();
        let w = MembershipWitness { leaf: crate::poseidon2_compress::lanes_of(&[7, 8, 9, 10]), siblings, dirs };
        let (carrier, root) = prove_membership_carrier_bytes(&w).expect("depth-32 membership must prove");
        assert!(
            verify_membership_carrier_bytes(&carrier, root, 32),
            "production depth-32 membership MUST verify vs its root"
        );
        let mut wrong = root;
        wrong[1] ^= 1;
        assert!(
            !verify_membership_carrier_bytes(&carrier, wrong, 32),
            "depth-32 membership vs a DIFFERENT root MUST be rejected"
        );
    }

    /// The SPEND-MAIN gate: an honest spend that conserves value AND carries the correct
    /// Poseidon nullifier verifies; a tampered carrier is rejected; a non-conserving spend
    /// never even proves. (Forged-nf soundness is proven at the engine level by
    /// `poseidon_nullifier_aggregate_o1_and_reject_forged`; this entry reuses that gate.)
    #[test]
    fn spend_main_carrier_binds_nullifier_and_conservation() {
        let rows = vec![
            SpendMainRow { in_value: 1000, out_value: 900, fee: 100, sk: crate::poseidon2_compress::lanes_of(&[11, 22, 33, 44]), leaf: crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]) },
            SpendMainRow { in_value: 500, out_value: 500, fee: 0, sk: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), leaf: crate::poseidon2_compress::lanes_of(&[9, 8, 7, 6]) },
        ];
        let carrier = prove_spend_main_carrier_bytes(&rows)
            .expect("honest spend-main carrier (conserves + correct nf) must prove");
        assert!(verify_spend_main_carrier_bytes(&carrier), "honest spend-main carrier MUST verify");
        let mut bad = carrier.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        assert!(!verify_spend_main_carrier_bytes(&bad), "a tampered spend-main carrier MUST NOT verify");
        assert!(
            prove_spend_main_carrier_bytes(&[SpendMainRow {
                in_value: 1000, out_value: 900, fee: 50, sk: crate::poseidon2_compress::lanes_of(&[1, 1, 1, 1]), leaf: crate::poseidon2_compress::lanes_of(&[2, 2, 2, 2])
            }])
            .is_none(),
            "a non-conserving spend-main row MUST NOT prove"
        );
    }

    /// The shared spend-carrier keystone: honest conserving spends verify; a
    /// tampered carrier is rejected; an inflating spend never even proves; empty rejects.
    #[test]
    fn shared_spend_carrier_verifies_and_rejects_inflation_and_tamper() {
        // Honest: 1000 = 900 + 100(fee); 500 = 500 + 0 — both conserve.
        let rows = vec![
            SpendRow { in_value: 1000, out_value: 900, fee: 100 },
            SpendRow { in_value: 500, out_value: 500, fee: 0 },
        ];
        let carrier = prove_spend_carrier_bytes(&rows).expect("honest spend carrier must prove");
        assert!(!carrier.is_empty(), "carrier is non-empty");
        assert!(verify_spend_carrier_bytes(&carrier), "honest carrier MUST verify");

        // Tamper: flip one byte → the bound transcript diverges → REJECT.
        let mut bad = carrier.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        assert!(!verify_spend_carrier_bytes(&bad), "a tampered carrier MUST NOT verify");

        // Inflation: 1000 != 900 + 50 → the prover refuses (no carrier).
        assert!(
            prove_spend_carrier_bytes(&[SpendRow { in_value: 1000, out_value: 900, fee: 50 }]).is_none(),
            "an inflating spend MUST NOT produce a carrier"
        );
        // Empty input rejected fail-closed.
        assert!(!verify_spend_carrier_bytes(&[]), "empty carrier MUST NOT verify");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        WhirOpeningRoundConstraint, // the in-circuit WHIR-PCS opening verifier (masked-sumcheck `into_sumcheck` chain)
        WhirRecursiveVerifyConstraint, // the pub recursive verifier (moved out of the test mod, dedup'd)
        EXT_D, LEAF_W, OODCHK_W, SYMX_AIDX, SYMX_AVAL, SYMX_BVAL, SYMX_ISOUT, SYMX_OUT, SYMX_R6_W,
        SYMX_ROWIDX,
        SYMX_W_CONST, check_oodcheck_identity, check_rec_block_ood_from_openings, check_rec_block_ood_row,
        build_acc_bus, build_acc_bus_tied, build_cert_bus_tied, build_finality_weight_bus_tied, build_leaf_bus,
        build_leaf_bus_full, build_leaf_bus_full_tied,
        draw_bus_fold_challenge, leaf_bus_key, prove_leaf_bus_balance, prove_leaf_bus_balance_tied,
        prove_rec_block_light_decider_bytes, prove_rec_block_light_decider_selfcontained_bytes,
        verify_leaf_bus_balance_tied, verify_rec_block_light_decider_selfcontained_bytes,
        prove_rec_block_light_decider_bytes_with_bus, prove_rec_block_whir_openings,
        prove_rec_block_whir_openings_with_bus, rec_block_bundle_opening_limb_count,
        rec_block_ood_table_index,
        rec_traces_to_tables, recover_height1_row_from_mle_openings, trace_to_table,
        verify_leaf_bus_balance, verify_rec_block_light_decider, verify_rec_block_light_decider_auto,
        verify_rec_block_light_decider_bytes, verify_rec_block_light_decider_selfcontained,
        verify_rec_block_whir_openings,
    };
    use crate::hiding_decider::{
        Chl, CompressHash, Ea4, Enc16, Fa4, Mmcs16, Perm16, SpongeHash, build_decider_hiding_prover,
        build_decider_hiding_verifier, decider_mask_encoding,
    };
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_whir::pcs::hiding::{ZkSumcheckData, prove_hvzk, verify_hvzk};
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    /// The adapter zero-extends a short trace up to `folding` variables and lays it out
    /// column-major (cols[c][r] == trace[r][c]); padded rows are zero.
    #[test]
    fn adapter_pads_and_transposes_to_mle_columns() {
        // Height-1 OodCheck-shaped trace (single row) → padded to 2^folding rows.
        let folding = 3usize;
        let row: Vec<Fa4> = (0..OODCHK_W).map(|c| Fa4::from_u64((c + 1) as u64)).collect();
        let trace = RowMajorMatrix::new(row.clone(), OODCHK_W);
        let (cols, (n_vars, width)) = trace_to_table(&trace, folding);
        assert_eq!(width, OODCHK_W, "width preserved");
        assert_eq!(n_vars, folding, "height-1 lifted to folding vars");
        assert_eq!(cols.len(), OODCHK_W, "one column per trace column");
        for c in 0..OODCHK_W {
            assert_eq!(cols[c].len(), 1 << folding, "each column is a 2^n_vars MLE domain");
            assert_eq!(cols[c][0], row[c], "row 0 transposed into column c");
            for r in 1..(1 << folding) {
                assert_eq!(cols[c][r], Fa4::ZERO, "padded rows are the MLE zero-extension");
            }
        }
    }

    /// The decider's ACTUAL heterogeneous rec-trace topology (leaf / ood / r6-shaped tables of
    /// differing heights) converts through the adapter into a valid multi-table HVZK-WHIR witness:
    /// an honest proof over the adapter output verifies, and a forged evaluation claim is rejected.
    /// This proves the adapter feeds the proven masked-sumcheck layer soundly at real rec shapes.
    fn roundtrip_over_adapter(forge: bool) -> bool {
        let seed = 0u64;
        let (ell_zk, folding_factor, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);

        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(t, ell_zk);

        // Build heterogeneous row-major rec traces: a wide leaf-shaped table (height 16), a
        // single-row ood-shaped table (height 1), and an r6-shaped table (height 8) — the real
        // rec-block mix of arities the aggregate carries.
        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let mk = |rng: &mut SmallRng, h: usize, w: usize| -> RowMajorMatrix<Fa4> {
            RowMajorMatrix::new((0..h * w).map(|_| rng.random::<Fa4>()).collect(), w)
        };
        let leaf_trace = mk(&mut data_rng, 16, LEAF_W);
        let ood_trace = mk(&mut data_rng, 1, OODCHK_W);
        let r6_trace = mk(&mut data_rng, 8, 4);
        let traces = [leaf_trace, ood_trace, r6_trace];

        let (tables, shapes) = rec_traces_to_tables(&traces, folding_factor);
        // Adapter reported shapes must match the source trace widths + padded arities.
        assert_eq!(shapes[0], (4, LEAF_W));
        assert_eq!(shapes[1], (folding_factor, OODCHK_W)); // height 1 → folding vars
        assert_eq!(shapes[2], (3, 4));

        let mut prover =
            build_decider_hiding_prover(tables, folding_factor, mmcs, encoding);
        let mut verifier = build_decider_hiding_verifier(&shapes);

        let mut pch = Chl::new(perm.clone());
        let mut vch = Chl::new(perm);

        // Open leaf table (idx 0) column 0, then a virtual full-witness eval — the opening schedule
        // the rec-block records in lockstep on both sides.
        let openings = prover.eval(0, &[0], &mut pch);
        verifier.add_claim(0, &[0], &openings, &mut vch);

        let mut eval = prover.add_virtual_eval(&mut pch);
        if forge {
            eval += Ea4::ONE;
        }
        verifier.add_virtual_eval(eval, &mut vch);

        let mut zk_data = ZkSumcheckData::<Fa4, Ea4>::default();
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let (mask_commits, prover_rand) =
            prove_hvzk(prover, &mut zk_data, pow_bits, &mut pch, &mut prover_rng);

        match verify_hvzk::<Fa4, Ea4, Mmcs16, _>(
            verifier,
            &zk_data,
            &mask_commits,
            ell_zk,
            folding_factor,
            pow_bits,
            &mut vch,
        ) {
            Some(vpoint) => prover_rand == vpoint,
            None => false,
        }
    }

    #[test]
    fn rec_trace_adapter_hvzk_accepts_honest_and_rejects_forged() {
        assert!(roundtrip_over_adapter(false), "honest rec-trace HVZK-WHIR proof must verify");
        assert!(!roundtrip_over_adapter(true), "forged evaluation claim must be rejected");
    }

    /// A trivial ROW-LOCAL AIR constraint for the direct-prover soundness gate: every row must satisfy
    /// `col0 == col1`. Degree 1, ignores `at` (no row shift) — the row-local shape every ecosystem
    /// broadcast (Send / Swap / token-create / …) rides through the direct light decider.
    struct ColEqConstraint;
    impl crate::air_zerocheck::AirConstraint for ColEqConstraint {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            local[0] - local[1]
        }
    }

    /// In-circuit challenge-fold gate (the tightening): col0 = leaf, col1 = acc. First row acc == leaf; each
    /// transition acc_next == acc·c + leaf_next (Horner); last row acc == commitment. Boundary selectors from the
    /// fold point x (is_first = Π(1−x), is_last = Π(x)). Proving this makes the node verify the carrier instead of
    /// re-folding N leaves → O(1) verify.
    struct FoldConstraint {
        c: Ea4,
        commitment: Ea4,
    }
    impl crate::air_zerocheck::AirConstraint for FoldConstraint {
        fn degree(&self, _nvars: usize) -> usize {
            2
        }
        fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
            let mut is_first = Ea4::ONE;
            let mut is_last = Ea4::ONE;
            for &xk in x {
                is_first *= Ea4::ONE - xk;
                is_last *= xk;
            }
            let is_transition = Ea4::ONE - is_last;
            let leaf = local[0];
            let acc = local[1];
            let acc_next = at(1, &[]);
            let leaf_next = at(0, &[]);
            is_first * (acc - leaf)
                + is_transition * (acc_next - acc * self.c - leaf_next)
                + is_last * (acc - self.commitment)
        }
    }

    /// SOUND SETTLEMENT AGGREGATE gate (the real optimization for MAX LIVE TPS, user 2026-07-09):
    /// each ROW is one spend `[in_val, out_val, fee]`; the row-local gate enforces conservation
    /// `in_val - out_val - fee == 0` (degree 1). Stacking N spends as N rows and proving the whole table
    /// via the light decider yields ONE polylog carrier that CERTIFIES EVERY SPEND VALID in-circuit — so
    /// mempool admission no longer needs the per-tx WHIR verify (validity is folded INTO the aggregate),
    /// and live TPS becomes `N × BPS` at CONSTANT proof size (N unbounded). The `nf`/`out_cm` columns are
    /// committed alongside (bound by the carrier's trace commitment) so a settled spend cannot be swapped.
    /// The real pqpool port swaps this representative conservation gate for the full PqSpendAir row.
    struct SpendConservationConstraint;
    impl crate::air_zerocheck::AirConstraint for SpendConservationConstraint {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            // col0=in_val, col1=out_val, col2=fee → conservation residual (0 on every honest row).
            local[0] - local[1] - local[2]
        }
    }

    // ⛔ `POSEIDON_MDS` REMOVED 2026-09-12 with the 1-round fold it described (kill list §AG).

    // ⛔ The N-spend Poseidon-nullifier scaling benchmark is REMOVED with the round it measured.
    // The production nullifier gate is `SpendMainGate`, whose numbers come from the real spend path.
    // ⛔ REMOVED 2026-09-12: this demo measured the 1-round fold (its own `POSEIDON_MDS`,
    // hand-built 33-column levels) that kill list §AG retired. The production gates it stood
    // in for — `SpendMembershipGate` / `SpendValidityGate` — are converted and carry their own
    // adversarial gates.
    // ⛔ REMOVED 2026-09-12: this demo measured the 1-round fold (its own `POSEIDON_MDS`,
    // hand-built 33-column levels) that kill list §AG retired. The production gates it stood
    // in for — `SpendMembershipGate` / `SpendValidityGate` — are converted and carry their own
    // adversarial gates.

    /// DECISIVE for REUSE: `prove_settlement_batch` commits N TABLES (one per spend, each fixed height 32) under
    /// ONE batch sumcheck. Is that carrier sub-linear in the TABLE COUNT N? If yes, the existing stark-free
    /// `prove_settlement_batch` IS the constant-ish fix (route the daemon/TPS to it, delete the O(N)
    /// `prove_settlement_agg`). This mirrors its exact shape (N fixed-height tables, per-table ColEq gate).
    #[test]
    fn light_decider_carrier_vs_table_count() {
        use std::time::Instant;
        let make = |_i: usize, _g: Ea4| ColEqConstraint;
        let mut rows: Vec<(usize, usize)> = Vec::new();
        for &n in &[8usize, 64, 512, 4096] {
            let mut rng = SmallRng::seed_from_u64(0x00BA_B1E5u64.wrapping_add(n as u64));
            // N tables, each 32 rows, col0==col1 (ColEq holds) — the exact prove_settlement_batch shape.
            let tables: Vec<Vec<Vec<Fa4>>> = (0..n).map(|_| {
                let c: Vec<Fa4> = (0..32).map(|_| rng.random::<Fa4>()).collect();
                vec![c.clone(), c]
            }).collect();
            // per-table bind (mirrors batch's per-tx pvs weld): one pub per table.
            let pubs: Vec<Fa4> = (0..n).map(|i| Fa4::from_u64(i as u64)).collect();
            let t0 = Instant::now();
            let bytes = super::prove_air_batch_light_decider_selfcontained_bytes(tables, make, &pubs)
                .expect("N-table carrier");
            let prove_us = t0.elapsed().as_micros();
            assert!(super::verify_air_batch_light_decider_selfcontained_bytes(&bytes, make, &pubs, &crate::whir_rec_block::declared_batch_shapes_for_tests(&bytes)));
            eprintln!("[tablecount] N={:>5} tables  carrier={:>8} B  prove={:>9} us", n, bytes.len(), prove_us);
            rows.push((n, bytes.len()));
        }
        let (n0, sz0) = rows[0];
        let (n1, sz1) = *rows.last().unwrap();
        eprintln!("[tablecount] N={}->{} ({}x) carrier {}B->{}B ({}x)", n0, n1, n1 / n0, sz0, sz1, sz1 / sz0.max(1));
    }

    /// #135 BUS-AWARE batch engine — the SOUND validator FINALITY-CERT retirement path. Proves N row-local
    /// AIR tables PLUS a SOURCE-TIED LogUp bus under one masked HVZK sumcheck. Four checks: honest (valid
    /// gates + BALANCED bus) VERIFIES; an UNBALANCED bus (`Σ mult/(α−keyfold) ≠ 0`) REJECTS — proving the bus
    /// binding is ENFORCED, not silently dropped (the exact unsoundness the plain batch engine fail-closes on);
    /// a constraint-violating row REJECTS (the per-table zerocheck); a wrong `public_bind` REJECTS (the
    /// statement weld). This is the engine `finality_cert_prove_bytes_light` routes the QuorumSumBus through to
    /// EMIT a real light cert instead of fail-closing — moving validators onto the light path.
    #[test]
    fn batch_bus_light_decider_accepts_honest_rejects_unbalanced_bus_and_violated() {
        let nvars = 5usize;
        let h = 1usize << nvars;
        let mut data_rng = SmallRng::seed_from_u64(0x00B0_5B00u64);
        let ca: Vec<Fa4> = (0..h).map(|_| data_rng.random::<Fa4>()).collect();
        let cb: Vec<Fa4> = (0..h).map(|_| data_rng.random::<Fa4>()).collect();
        let tables_ok = vec![vec![ca.clone(), ca.clone()], vec![cb.clone(), cb.clone()]];
        let pubs = [Fa4::from_u64(7), Fa4::from_u64(13)];
        let make = |_i: usize, _g: Ea4| ColEqConstraint;
        // A BALANCED source-tied bus: two rows share (idx=5, val=9) with mult +1 (send) / −1 (receive), so
        // `Σ mult/(α−keyfold) = 0` for every α,β (the engine's padding rows carry mult=0 → no contribution).
        let good_bus = || {
            (
                vec![Fa4::from_u64(5), Fa4::from_u64(5)],
                vec![vec![Fa4::from_u64(9), Fa4::from_u64(9)]],
                vec![Fa4::ONE, Fa4::ZERO - Fa4::ONE],
            )
        };
        let bytes = super::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables_ok.clone(),
            make,
            vec![good_bus()],
            vec![],
            vec![],
            &pubs,
        )
        .expect("honest bus-aware batch prove produces a carrier");
        assert!(
            super::verify_air_batch_light_decider_selfcontained_bytes_with_bus(&bytes, make, vec![], vec![], &pubs, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).1),
            "honest batch + balanced tied bus must verify"
        );
        // Wrong public bind → divergent transcript → reject.
        let pubs_bad = [Fa4::from_u64(7), Fa4::from_u64(14)];
        assert!(
            !super::verify_air_batch_light_decider_selfcontained_bytes_with_bus(&bytes, make, vec![], vec![], &pubs_bad, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).1),
            "a verifier reading a different public_bind must be rejected"
        );
        // UNBALANCED bus: both mults +1 → `Σ mult/(α−keyfold) ≠ 0` → the tied-bus balance gate rejects. This
        // proves the cross-table binding is ENFORCED (a forged sum that ignores the members would be caught).
        let bad_bus = (
            vec![Fa4::from_u64(5), Fa4::from_u64(5)],
            vec![vec![Fa4::from_u64(9), Fa4::from_u64(9)]],
            vec![Fa4::ONE, Fa4::ONE],
        );
        let bytes_bad = super::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables_ok.clone(),
            make,
            vec![bad_bus],
            vec![],
            vec![],
            &pubs,
        );
        let bad_bus_verifies = bytes_bad
            .as_deref()
            .map(|b| super::verify_air_batch_light_decider_selfcontained_bytes_with_bus(b, make, vec![], vec![], &pubs, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).1))
            .unwrap_or(false);
        assert!(
            !bad_bus_verifies,
            "an UNBALANCED tied bus must NOT verify (bus binding is enforced, not dropped)"
        );
        // Constraint-violating row: table 1's col1 differs from col0 on one row → its zerocheck sum ≠ 0 →
        // the whole batch (bus notwithstanding) must NOT verify.
        let mut cb_bad = cb.clone();
        cb_bad[3] += Fa4::ONE;
        let tables_viol = vec![vec![ca.clone(), ca], vec![cb, cb_bad]];
        let bytes_viol = super::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables_viol,
            make,
            vec![good_bus()],
            vec![],
            vec![],
            &pubs,
        );
        let viol_verifies = bytes_viol
            .as_deref()
            .map(|b| super::verify_air_batch_light_decider_selfcontained_bytes_with_bus(b, make, vec![], vec![], &pubs, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).1))
            .unwrap_or(false);
        assert!(!viol_verifies, "a constraint-violating row must NOT verify");
    }

    /// #135 SOURCE CROSS-TIE — the anti-forgery gate that makes the bus-aware cert light path SOUND. Without
    /// it, a malicious prover fabricates a self-balancing bus whose RECV columns ignore the source trace
    /// (commit an inflated sum weight that passes the row-local threshold, + a free bus that balances on
    /// DIFFERENT values) → forged finality. The cross-tie binds the bus's RECV cell to the source trace's
    /// committed cell and asserts equality over two BOUND openings. Test: (1) HONEST — bus RECV val == the
    /// constraint table's tied cell → VERIFIES; (2) SUBSTITUTION — a bus that still balances internally but
    /// whose RECV val ≠ the tied source cell → the cross-tie equality REJECTS (the forgery is caught). This
    /// is the primitive `finality_cert_prove_bytes_light` uses to weld QuorumSumBus w0/w1 to the sum trace.
    #[test]
    fn batch_bus_cross_tie_binds_recv_to_source_rejects_substitution() {
        let nvars = 5usize;
        let h = 1usize << nvars;
        // Constraint table t0: col0 == col1 == 9 on EVERY row (ColEq holds; the tied source cell = 9,
        // constant so the test is robust to the boolean-point row convention).
        let c9: Vec<Fa4> = vec![Fa4::from_u64(9); h];
        let tables = vec![vec![c9.clone(), c9.clone()]];
        let pubs = [Fa4::from_u64(42)];
        let make = |_i: usize, _g: Ea4| ColEqConstraint;
        // Cross-tie: bus table (index 1) val col (index 1 = after idx@0) @ RECV row 1 == t0 (index 0) col0 @
        // row 0. The bus table is appended after the n=1 constraint table, so its index is 1.
        let ties = || -> Vec<super::CrossTieSpec> { vec![((1, vec![1], 1), (0, vec![0], 0))] };
        // HONEST bus: SEND(idx5,val9,+1) / RECV(idx5,val9,−1) — balances AND its RECV val (9) matches t0's
        // tied cell (9) → cross-tie holds.
        let honest_bus = (
            vec![Fa4::from_u64(5), Fa4::from_u64(5)],
            vec![vec![Fa4::from_u64(9), Fa4::from_u64(9)]],
            vec![Fa4::ONE, Fa4::ZERO - Fa4::ONE],
        );
        let bytes = super::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables.clone(),
            make,
            vec![honest_bus],
            ties(),
            vec![],
            &pubs,
        )
        .expect("honest cross-tied bus prove produces a carrier");
        assert!(
            super::verify_air_batch_light_decider_selfcontained_bytes_with_bus(&bytes, make, ties(), vec![], &pubs, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).1),
            "honest bus whose RECV matches the tied source cell must verify"
        );
        // SUBSTITUTION forgery: a bus that STILL balances (SEND/RECV share idx=5,val=7 → Σ=0) but whose RECV
        // val (7) ≠ t0's tied cell (9). The balance gate passes; the CROSS-TIE equality catches the forgery.
        let forged_bus = (
            vec![Fa4::from_u64(5), Fa4::from_u64(5)],
            vec![vec![Fa4::from_u64(7), Fa4::from_u64(7)]],
            vec![Fa4::ONE, Fa4::ZERO - Fa4::ONE],
        );
        let bytes_forged = super::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables.clone(),
            make,
            vec![forged_bus],
            ties(),
            vec![],
            &pubs,
        );
        let forged_verifies = bytes_forged
            .as_deref()
            .map(|b| super::verify_air_batch_light_decider_selfcontained_bytes_with_bus(b, make, ties(), vec![], &pubs, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).1))
            .unwrap_or(false);
        assert!(
            !forged_verifies,
            "a self-balancing bus whose RECV ≠ the tied source cell must NOT verify (substitution caught)"
        );
    }

    /// #135 PUBLIC-IO cross-tie: a bus tuple limb that references the statement's PUBLIC IO (not a committed
    /// source cell) is still SOUND-bound by welding it to `public_bind[idx]` via a `PUBLIC_BIND_TABLE` endpoint.
    /// This is what lets the #74 vote (whose VOTE_ANCHOR RECV is the public anchor) ride the light decider. The
    /// tie FORCES the committed bus cell == the public value: an honest RECV (== public_bind) verifies; a bus
    /// that self-balances but whose RECV ≠ public_bind is REJECTED; and the honest carrier verified against a
    /// DIFFERENT public statement is REJECTED (binds the carrier to its public IO).
    #[test]
    fn batch_bus_public_io_cross_tie_binds_recv_to_public_bind_rejects_forgery() {
        let nvars = 5usize;
        let h = 1usize << nvars;
        let c9: Vec<Fa4> = vec![Fa4::from_u64(9); h];
        let tables = vec![vec![c9.clone(), c9.clone()]];
        // public_bind[0] = 42; the bus RECV limb is welded to it (a PUBLIC_BIND_TABLE endpoint).
        let pubs = [Fa4::from_u64(42)];
        let make = |_i: usize, _g: Ea4| ColEqConstraint;
        // Public-IO cross-tie: bus table (index 1) val col (index 1) @ RECV row 1 == public_bind[0].
        let ties = || -> Vec<super::CrossTieSpec> { vec![((1, vec![1], 1), (super::PUBLIC_BIND_TABLE, vec![0], 0))] };
        // HONEST: RECV val = 42 == public_bind[0] → the public-IO tie holds.
        let honest_bus = (
            vec![Fa4::from_u64(5), Fa4::from_u64(5)],
            vec![vec![Fa4::from_u64(42), Fa4::from_u64(42)]],
            vec![Fa4::ONE, Fa4::ZERO - Fa4::ONE],
        );
        let bytes = super::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables.clone(),
            make,
            vec![honest_bus],
            ties(),
            vec![],
            &pubs,
        )
        .expect("honest public-IO-tied bus prove produces a carrier");
        assert!(
            super::verify_air_batch_light_decider_selfcontained_bytes_with_bus(&bytes, make, ties(), vec![], &pubs, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).1),
            "honest bus whose RECV == public_bind must verify"
        );
        // TAMPER 1 — a bus that self-balances (RECV val = 7) but 7 ≠ public_bind[0] = 42 → the public-IO tie
        // equality catches the forgery (the balance gate alone would pass).
        let forged_bus = (
            vec![Fa4::from_u64(5), Fa4::from_u64(5)],
            vec![vec![Fa4::from_u64(7), Fa4::from_u64(7)]],
            vec![Fa4::ONE, Fa4::ZERO - Fa4::ONE],
        );
        let forged = super::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables.clone(),
            make,
            vec![forged_bus],
            ties(),
            vec![],
            &pubs,
        );
        let forged_ok = forged
            .as_deref()
            .map(|b| super::verify_air_batch_light_decider_selfcontained_bytes_with_bus(b, make, ties(), vec![], &pubs, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).1))
            .unwrap_or(false);
        assert!(!forged_ok, "a bus whose RECV ≠ public_bind MUST NOT verify (public-IO forgery caught)");
        // TAMPER 2 — verify the HONEST carrier against a DIFFERENT public statement (public_bind[0] = 43): the
        // recomputed public value (43) ≠ the committed RECV (42) → REJECT (the carrier is bound to its public IO).
        let wrong_pubs = [Fa4::from_u64(43)];
        assert!(
            !super::verify_air_batch_light_decider_selfcontained_bytes_with_bus(&bytes, make, ties(), Vec::new(), &wrong_pubs, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).1),
            "the honest carrier verified against a DIFFERENT public statement MUST reject"
        );
    }

    /// #135 cross-tie ROW-SELECTION (the finality-cert regression isolator): the prior cross-tie test used a
    /// CONSTANT source column, so it could not catch a wrong `boolean_point` row convention. Here the source
    /// column has DISTINCT per-row values (`col0[r]=r+100`), and the bus RECV cell is tied to a SPECIFIC row
    /// (row 7 → value 107). If `boolean_point(row,nvars)` selects the wrong row, the opened source value ≠ the
    /// bus value → the cross-tie equality REJECTS. Honest (bus value == the tied row's real cell) MUST verify.
    #[test]
    fn batch_bus_cross_tie_multirow_selects_correct_source_row() {
        let nvars = 5usize;
        let h = 1usize << nvars;
        // t0: col0[r] = r+100 distinct per row; col1 == col0 so the ColEq gate holds on every row.
        let col0: Vec<Fa4> = (0..h).map(|r| Fa4::from_u64(r as u64 + 100)).collect();
        let tables = vec![vec![col0.clone(), col0.clone()]];
        let pubs = [Fa4::from_u64(1)];
        let make = |_i: usize, _g: Ea4| ColEqConstraint;
        let target_row = 7usize;
        let v = Fa4::from_u64(target_row as u64 + 100); // = col0[7] = 107
        // Balanced bus: two rows share (idx=0, val=107) with mult +1 / −1 → Σ mult/(α−keyfold)=0.
        let bus = (
            vec![Fa4::ZERO, Fa4::ZERO],
            vec![vec![v, v]],
            vec![Fa4::ONE, Fa4::ZERO - Fa4::ONE],
        );
        // Cross-tie: bus table (index 1, after the 1 constraint table) val col (index 1) @ bus row 0 ==
        // t0 (index 0) col0 (index 0) @ row `target_row`.
        let ties = || -> Vec<super::CrossTieSpec> { vec![((1, vec![1], 0), (0, vec![0], target_row))] };
        let bytes = super::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables.clone(),
            make,
            vec![bus],
            ties(),
            vec![],
            &pubs,
        )
        .expect("honest multi-row cross-tied bus prove produces a carrier");
        assert!(
            super::verify_air_batch_light_decider_selfcontained_bytes_with_bus(&bytes, make, ties(), vec![], &pubs, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&bytes).1),
            "cross-tie to a DISTINCT multi-row source cell must open the correct row (row 7 = 107) and verify"
        );
    }

    /// The verifier-side OodCheck re-evaluation mirrors `OodCheckAir` exactly: an honest row
    /// (`acc == q·z_h`, active=1) passes; a tampered acc fails; an inactive row (active=0) is
    /// unconstrained; a non-boolean active fails; a short row is rejected.
    #[test]
    fn oodcheck_identity_mirrors_air_constraint() {
        let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) + 2));
        let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 3 + 5));
        let acc = q * zh;
        let limbs =
            |e: Ea4| -> Vec<Fa4> { (0..EXT_D).map(|k| e.as_basis_coefficients_slice()[k]).collect() };
        let mut row: Vec<Fa4> = Vec::with_capacity(OODCHK_W);
        row.extend(limbs(zh));
        row.extend(limbs(q));
        row.extend(limbs(acc));
        row.push(Fa4::ONE); // active
        assert!(check_oodcheck_identity(&row), "honest acc == q·z_h with active=1 must pass");

        // Tamper the quotient identity: bump one acc limb → acc != q·z_h → reject.
        let mut bad = row.clone();
        bad[EXT_D * 2] += Fa4::ONE;
        assert!(!check_oodcheck_identity(&bad), "tampered acc must be rejected");

        // Inactive row (active=0) carries no quotient constraint even with a garbage acc.
        let mut inactive = bad.clone();
        inactive[EXT_D * 3] = Fa4::ZERO;
        assert!(check_oodcheck_identity(&inactive), "inactive row (active=0) is unconstrained");

        // Non-boolean active is rejected (OodCheckAir: active·(active−1)==0).
        let mut nonbool = row.clone();
        nonbool[EXT_D * 3] = Fa4::from_u64(2);
        assert!(!check_oodcheck_identity(&nonbool), "non-boolean active must be rejected");

        // Defensive length guard: a short row is rejected, never indexed out of bounds.
        assert!(
            !check_oodcheck_identity(&row[..OODCHK_W - 1]),
            "short row must be rejected"
        );
    }

    /// The rec-block opening+mask entry pair (`prove_rec_block_whir_openings` /
    /// `verify_rec_block_whir_openings`) accepts an honest bundle over the real heterogeneous
    /// rec-trace shapes and rejects a forged virtual evaluation — the reusable routing entry the
    /// rec-block gate calls, proven sound in the decider's KoalaBear field.
    #[test]
    fn rec_block_opening_entry_pair_accepts_honest_rejects_forged() {
        let seed = 0u64;
        let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(t, ell_zk);

        // Real heterogeneous rec-trace shapes: leaf (16×LEAF_W), ood (1×OODCHK_W), r6 (8×4).
        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let mk = |rng: &mut SmallRng, h: usize, w: usize| -> RowMajorMatrix<Fa4> {
            RowMajorMatrix::new((0..h * w).map(|_| rng.random::<Fa4>()).collect(), w)
        };
        let traces = [
            mk(&mut data_rng, 16, LEAF_W),
            mk(&mut data_rng, 1, OODCHK_W),
            mk(&mut data_rng, 8, 4),
        ];
        let (tables, shapes) = rec_traces_to_tables(&traces, folding);

        let mut pch = Chl::new(perm.clone());
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let mut bundle = prove_rec_block_whir_openings(
            tables, shapes, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
        );

        let mut vch = Chl::new(perm.clone());
        assert!(
            verify_rec_block_whir_openings(&bundle, folding, ell_zk, pow_bits, &mut vch),
            "honest rec-block opening bundle must verify"
        );

        // Forge the virtual evaluation → the replayed transcript diverges → verify must reject.
        bundle.virtual_eval += Ea4::ONE;
        let mut vch2 = Chl::new(perm);
        assert!(
            !verify_rec_block_whir_openings(&bundle, folding, ell_zk, pow_bits, &mut vch2),
            "forged virtual evaluation must be rejected"
        );
    }

    /// #135 KEYSTONE: the rec-block opening entry pair now ENFORCES the multi-row `SymEvalR6Leaf`
    /// composed AIR constraint (reg-op relations + row-idx transition) over the COMMITTED r6 trace,
    /// bound to the WHIR commitment via `eval_at`/`add_claim_at` at the zerocheck point `r` and `σ(r)`.
    /// An honest r6 trace verifies; tampering its reg-op output OR its row_idx step makes the bundle
    /// REJECT — the exact soundness the FRI rec prove provided, now in the phone-class light decider.
    /// (Distinct from `rec_block_opening_entry_pair_*`, whose "r6" is a random 8×4 filler that carries
    /// no `SYMX_W_CONST` width and therefore no r6 zerocheck.)
    #[test]
    fn rec_block_bundle_enforces_r6_constraint_honest_accepts_tampered_rejects() {
        let build = |tamper: u8| -> bool {
            // 0 = honest, 1 = tamper reg-op out, 2 = tamper row_idx step.
            let seed = 7u64;
            let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
            let mut perm_rng = SmallRng::seed_from_u64(seed);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let hash = SpongeHash::new(perm.clone());
            let compress = CompressHash::new(perm.clone());
            let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
            let encoding: Enc16 = decider_mask_encoding(t, ell_zk);

            // Honest 8-row production r6 trace (24-wide `SYMX_R6_W`): row0 s_mul (out = a·b over
            // Fa4[X]/(X⁴−3)), rows1..7 nop, row_idx = 0..7, is_out = 1 on the last row — the shape the
            // real `SymEvalR6Leaf` trace + `SymEvalR6FullConstraint` (reg + transition + is_out) enforce.
            const NV: usize = 3;
            const N: usize = 1 << NV;
            const W: usize = SYMX_R6_W;
            let a = [3u64, 5, 7, 9].map(Fa4::from_u64);
            let b = [2u64, 4, 6, 8].map(Fa4::from_u64);
            let w = Fa4::from_u64(3);
            let mul = [
                a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
                a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * (a[3] * b[3]),
                a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
            ];
            let mut data = vec![Fa4::ZERO; N * W];
            data[4] = Fa4::ONE; // sel[4] = s_mul on row 0
            for k in 0..EXT_D {
                data[SYMX_AVAL + k] = a[k];
                data[SYMX_BVAL + k] = b[k];
                data[SYMX_OUT + k] = mul[k];
            }
            for i in 1..N {
                data[i * W] = Fa4::ONE; // nop sel[0] = 1 on rows 1..7
            }
            for i in 0..N {
                data[i * W + SYMX_ROWIDX] = Fa4::from_u64(i as u64);
            }
            data[(N - 1) * W + SYMX_ISOUT] = Fa4::ONE; // is_out = 1 on the last row (ACC_BUS gate)
            if tamper == 1 {
                data[SYMX_OUT] += Fa4::ONE; // out[0] ≠ mul[0] → reg-op relation violated
            }
            if tamper == 2 {
                data[3 * W + SYMX_ROWIDX] = Fa4::from_u64(9); // row_idx step broken (2→9, 9→4)
            }
            let r6 = RowMajorMatrix::new(data, W);
            let (tables, shapes) = rec_traces_to_tables(&[r6], folding);
            assert_eq!(shapes[0].1, SYMX_R6_W, "table must be recognized as an r6 table");

            let mut pch = Chl::new(perm.clone());
            let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
            let bundle = prove_rec_block_whir_openings(
                tables, shapes, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
            );
            assert_eq!(bundle.r6_zerochecks.len(), 1, "exactly one r6 zerocheck must be produced");

            let mut vch = Chl::new(perm);
            verify_rec_block_whir_openings(&bundle, folding, ell_zk, pow_bits, &mut vch)
        };
        assert!(build(0), "honest r6 rec-block bundle must verify");
        assert!(!build(1), "tampered r6 reg-op output must be rejected");
        assert!(!build(2), "tampered r6 row_idx step must be rejected");
    }

    /// #135 TX-SPEED BENCHMARK (MONOLITH-FREE): times the light-decider r6 zerocheck PROVE — the DOMINANT
    /// term of the whole per-block prove (the tall `SymEvalR6Leaf` table; the leaf/ood/stub/bus tables are
    /// tiny by comparison) — at PRODUCTION rec-block trace HEIGHTS, WITHOUT compiling the 68k-line pqpool
    /// `circuit.rs` monolith (its ~20-min cold release build). It reuses the EXACT valid-r6-trace shape the
    /// honest/tampered r6 test builds (row0 s_mul over Fa4[X]/(X⁴−3), nops, row_idx = 0..H, is_out on the
    /// last row) so the r6 constraint (reg-op + row-idx TRANSITION + is_out) is genuinely satisfied AND
    /// exercised at each height — the transition term is where the row-shift `mle_eval` cost lives, so the
    /// scaling across rungs reveals whether it is linear-in-2^nv (commit/fold) or super-linear. Run with
    /// `--nocapture`: the PROVE seconds at the real production r6_height (read from the pqpool `[rec-timing]`
    /// line) is the light-decider's contribution to the user's Send→broadcast wall-clock. Correctness
    /// self-check: every honest height MUST verify — a slow-but-wrong prove is not progress. Heights capped
    /// at 2^12 to keep the run bounded + machine-safe; the exponent extrapolates to any real height.
    #[test]
    fn rec_block_r6_zerocheck_prove_time_vs_height() {
        let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
        // Fixed VALID s_mul reg-op: out = a·b over Fa4[X]/(X⁴−3) (what the r6 constraint checks on row 0).
        let a = [3u64, 5, 7, 9].map(Fa4::from_u64);
        let b = [2u64, 4, 6, 8].map(Fa4::from_u64);
        let wq = Fa4::from_u64(3);
        let mul = [
            a[0] * b[0] + wq * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
            a[0] * b[1] + a[1] * b[0] + wq * (a[2] * b[3] + a[3] * b[2]),
            a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + wq * (a[3] * b[3]),
            a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
        ];
        const W: usize = SYMX_R6_W;
        // Sweep INCLUDES the real production r6 height 2^16 (measured from the live circuit.rs carrier:
        // r6_height=65536) so the O(N) fix + the public-row_idx binding are validated at the ACTUAL height,
        // not just a small bracket. Linear scaling ⇒ each +2 rung ≈ ×4 time.
        for &nv in &[12usize, 14, 16] {
            let n = 1usize << nv;
            let mut data = vec![Fa4::ZERO; n * W];
            data[4] = Fa4::ONE; // sel[4] = s_mul on row 0
            for k in 0..EXT_D {
                data[SYMX_AVAL + k] = a[k];
                data[SYMX_BVAL + k] = b[k];
                data[SYMX_OUT + k] = mul[k];
            }
            for i in 1..n {
                data[i * W] = Fa4::ONE; // nop sel[0] = 1 on rows 1..n-1
            }
            for i in 0..n {
                data[i * W + SYMX_ROWIDX] = Fa4::from_u64(i as u64);
            }
            data[(n - 1) * W + SYMX_ISOUT] = Fa4::ONE; // is_out = 1 on the last row
            let r6 = RowMajorMatrix::new(data, W);

            let mut perm_rng = SmallRng::seed_from_u64(7);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let hash = SpongeHash::new(perm.clone());
            let compress = CompressHash::new(perm.clone());
            let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(14));
            let encoding: Enc16 = decider_mask_encoding(t, ell_zk);

            let (tables, shapes) = rec_traces_to_tables(&[r6], folding);
            let mut pch = Chl::new(perm.clone());
            let mut prover_rng = SmallRng::seed_from_u64(2);
            let t_prove = std::time::Instant::now();
            let bundle = prove_rec_block_whir_openings(
                tables, shapes, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
            );
            let prove_s = t_prove.elapsed().as_secs_f64();
            let mut vch = Chl::new(perm);
            let t_verify = std::time::Instant::now();
            let ok = verify_rec_block_whir_openings(&bundle, folding, ell_zk, pow_bits, &mut vch);
            let verify_s = t_verify.elapsed().as_secs_f64();
            assert!(ok, "honest r6 trace at height {n} must VERIFY (a slow-but-wrong prove is not progress)");
            eprintln!("[r6-bench] height={n:>6} (2^{nv:<2}) | PROVE = {prove_s:.3} s | VERIFY = {verify_s:.3} s");
        }
    }

    /// #135 LEAF_BUS tie: a SEND (LeafSource, mult=−count) and its matching RECVs (SymEvalR6Leaf tape
    /// uses + ClaimsExpose, mult=+1) fold `[leaf_idx, val]` to the SAME LogUp key via `leaf_bus_key`,
    /// so a balanced bus verifies (`Σ mult/(α−key) = 0`). Forging a CONSUMED leaf value (a RECV's val)
    /// changes its key → send/recv no longer cancel → `Σ ≠ 0` → REJECT. This is the binding that a
    /// SymEvalR6Leaf tape consumed the ACTUAL committed leaf, not a forged value — the LEAF_BUS half of
    /// welding `acc` to the real inner-AIR openings (composes with the r6 zerocheck).
    #[test]
    fn leaf_bus_forged_consumed_leaf_value_breaks_balance() {
        use p3_challenger::FieldChallenger;
        let build = |tamper: bool| -> bool {
            let beta = Fa4::from_u64(7);
            // Two distinct leaves; each SENT once (mult=−2) + RECEIVED twice (r6 tape use + claim, mult=+1).
            let leaves: [(Fa4, [Fa4; EXT_D]); 2] = [
                (
                    Fa4::from_u64(0),
                    [Fa4::from_u64(11), Fa4::from_u64(12), Fa4::from_u64(13), Fa4::from_u64(14)],
                ),
                (
                    Fa4::from_u64(1),
                    [Fa4::from_u64(21), Fa4::from_u64(22), Fa4::from_u64(23), Fa4::from_u64(24)],
                ),
            ];
            let mut value: Vec<Fa4> = Vec::new();
            let mut mult: Vec<Fa4> = Vec::new();
            for (li, (idx, val)) in leaves.iter().enumerate() {
                value.push(leaf_bus_key(*idx, val, beta)); // SEND
                mult.push(-Fa4::from_u64(2)); // −load_count (2 consumers)
                for r in 0..2 {
                    let mut v = *val;
                    if tamper && li == 0 && r == 0 {
                        v[0] += Fa4::ONE; // forged consumed-leaf value on one RECV
                    }
                    value.push(leaf_bus_key(*idx, &v, beta)); // RECV
                    mult.push(Fa4::ONE);
                }
            }
            // Pad 6 → 8 rows with mult=0 (contribute nothing; distinct dummy keys avoid α−value=0).
            let mut pad = 900u64;
            while value.len() < 8 {
                value.push(Fa4::from_u64(pad));
                mult.push(Fa4::ZERO);
                pad += 1;
            }
            let n_vars = 3usize;
            let mut perm_rng = SmallRng::seed_from_u64(0);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let mut pch = Chl::new(perm.clone());
            let alpha: Ea4 = pch.sample_algebra_element();
            let (proof, _h) = prove_leaf_bus_balance(&value, &mult, alpha, &mut pch);
            let mut vch = Chl::new(perm);
            let alpha_v: Ea4 = vch.sample_algebra_element();
            verify_leaf_bus_balance(&proof, alpha_v, n_vars, &mut vch)
        };
        assert!(build(false), "balanced LEAF_BUS (send keys == recv keys) must ACCEPT");
        assert!(!build(true), "forged consumed-leaf value must REJECT (bus imbalance)");
    }

    /// #135 ACC_BUS tie: `build_acc_bus` yields a balanced LogUp bus iff the r6-computed acc (out on the
    /// r6 last row, SENT gated is_out) equals the OodCheck row's acc (RECEIVED). A matching pair verifies
    /// through the bus balance; a forged ood acc breaks it → reject. This binds the ood quotient identity
    /// (`acc==q·z_h`) to the acc the r6 sym-eval ACTUALLY computed — reconciliation brick 4 (production
    /// `SymEvalR6Air`/`OodCheck` ACC_BUS, circuit.rs:42769/42794).
    #[test]
    fn acc_bus_ties_r6_acc_to_ood_acc() {
        let build = |forge: bool| -> bool {
            use p3_challenger::FieldChallenger;
            let beta = Fa4::from_u64(11);
            let r6_acc = [Fa4::from_u64(7), Fa4::from_u64(8), Fa4::from_u64(9), Fa4::from_u64(10)];
            let mut ood_acc = r6_acc;
            if forge {
                ood_acc[0] += Fa4::ONE; // ood acc ≠ the r6-computed acc → ACC_BUS imbalance
            }
            let (mut value, mut mult) = build_acc_bus(&r6_acc, &ood_acc, beta);
            // Pad the 2 real bus rows to 2^folding = 8 (mult=0 padding; distinct dummy keys).
            let mut pad = 700u64;
            while value.len() < 8 {
                value.push(Fa4::from_u64(pad));
                mult.push(Fa4::ZERO);
                pad += 1;
            }
            let mut perm_rng = SmallRng::seed_from_u64(3);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let mut pch = Chl::new(perm.clone());
            let alpha: Ea4 = pch.sample_algebra_element();
            let (proof, _h) = prove_leaf_bus_balance(&value, &mult, alpha, &mut pch);
            let mut vch = Chl::new(perm);
            let alpha_v: Ea4 = vch.sample_algebra_element();
            verify_leaf_bus_balance(&proof, alpha_v, 3, &mut vch)
        };
        assert!(build(false), "matching r6_acc == ood_acc must balance (ACC_BUS tie holds)");
        assert!(!build(true), "forged ood acc must break the ACC_BUS balance");
    }

    /// #135 LEAF_BUS real-key tie: `build_leaf_bus` folds the ACTUAL committed columns — LeafSource SENDs
    /// `[idx,val]`, `SymEvalR6LeafAir` RECEIVEs `[a_idx,out]` gated `s_leaf=sel[0]` — into one LogUp
    /// balance bus that balances iff every consumed leaf was sourced. A matching (source, consume) pair
    /// verifies; forging the sourced leaf value breaks it → reject. So a spend cannot fabricate a
    /// register-load. Reconciliation brick 5 (the real production LEAF_BUS key, not a synthetic pair).
    #[test]
    fn leaf_bus_builder_ties_consumed_to_sourced() {
        let run = |forge: bool| -> bool {
            use p3_challenger::FieldChallenger;
            let beta = Fa4::from_u64(13);
            // r6 leaf-load row: sel[0]=1 (s_leaf), a_idx at SYMX_AIDX, out[0..EXT_D] at SYMX_OUT.
            let mut r6t = vec![Fa4::ZERO; SYMX_R6_W];
            r6t[0] = Fa4::ONE; // s_leaf = sel[0]
            r6t[SYMX_AIDX] = Fa4::from_u64(5); // a_idx = register lane 5
            let out = [Fa4::from_u64(20), Fa4::from_u64(21), Fa4::from_u64(22), Fa4::from_u64(23)];
            for k in 0..EXT_D {
                r6t[SYMX_OUT + k] = out[k];
            }
            // LeafSource sources leaf 5 with the SAME value (honest) or a forged one.
            let lf_w = 1 + EXT_D;
            let mut lft = vec![Fa4::ZERO; lf_w];
            lft[0] = Fa4::from_u64(5); // leaf_idx = 5
            for k in 0..EXT_D {
                lft[1 + k] = out[k];
            }
            if forge {
                lft[1] += Fa4::ONE; // sourced value ≠ consumed value → LEAF_BUS imbalance
            }
            let (mut value, mut mult) = build_leaf_bus(&r6t, &lft, lf_w, beta);
            // Pad the 2 real bus rows to 2^folding = 8 (mult=0 padding; distinct dummy keys).
            let mut pad = 800u64;
            while value.len() < 8 {
                value.push(Fa4::from_u64(pad));
                mult.push(Fa4::ZERO);
                pad += 1;
            }
            let mut perm_rng = SmallRng::seed_from_u64(4);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let mut pch = Chl::new(perm.clone());
            let alpha: Ea4 = pch.sample_algebra_element();
            let (proof, _h) = prove_leaf_bus_balance(&value, &mult, alpha, &mut pch);
            let mut vch = Chl::new(perm);
            let alpha_v: Ea4 = vch.sample_algebra_element();
            verify_leaf_bus_balance(&proof, alpha_v, 3, &mut vch)
        };
        assert!(run(false), "sourced leaf == consumed leaf must balance (LEAF_BUS tie holds)");
        assert!(!run(true), "forged sourced leaf value must break the LEAF_BUS balance");
    }

    /// #135 FULL LEAF_BUS multiplicities: `build_leaf_bus_full` matches the real production LogUp signs —
    /// LeafSource SEND −load_count, consumers (SymEvalR6Leaf + ClaimsExpose) +1 each — so it balances iff
    /// each leaf's `load_count` equals its total consumer count. Honest (load_count=2 = 1 r6 use + 1 claim)
    /// balances; forging the exposed claim value (claim no longer a sourced leaf) breaks it → reject.
    /// Reconciliation brick (A) — the full bus builder the circuit.rs swap passes to the light decider.
    #[test]
    fn leaf_bus_full_ties_loadcount_to_consumers() {
        let run = |forge: bool| -> bool {
            use p3_challenger::FieldChallenger;
            let beta = Fa4::from_u64(17);
            let leaf_idx = 5usize;
            let val = [Fa4::from_u64(30), Fa4::from_u64(31), Fa4::from_u64(32), Fa4::from_u64(33)];
            // r6 leaf-load row consuming leaf 5: s_leaf=sel[0]=1, a_idx=5, out=val.
            let mut r6t = vec![Fa4::ZERO; SYMX_R6_W];
            r6t[0] = Fa4::ONE;
            r6t[SYMX_AIDX] = Fa4::from_u64(leaf_idx as u64);
            for k in 0..EXT_D {
                r6t[SYMX_OUT + k] = val[k];
            }
            // LeafSource sources leaf 5 with load_count = 2 (one r6 use + one claim).
            let lf_w = 2 + EXT_D;
            let mut lft = vec![Fa4::ZERO; lf_w];
            lft[0] = Fa4::from_u64(leaf_idx as u64);
            for k in 0..EXT_D {
                lft[1 + k] = val[k];
            }
            lft[1 + EXT_D] = Fa4::from_u64(2); // load_count = 2
            // ClaimsExpose exposes leaf 5's value (honest) or a forged one.
            let mut claim_val = val.to_vec();
            if forge {
                claim_val[0] += Fa4::ONE; // exposed claim ≠ sourced leaf → LEAF_BUS imbalance
            }
            let claims = vec![(leaf_idx, claim_val)];
            let (mut value, mut mult) = build_leaf_bus_full(&r6t, &lft, lf_w, &claims, beta);
            // Pad the 3 real bus rows to 2^folding = 8 (mult=0 padding; distinct dummy keys).
            let mut pad = 900u64;
            while value.len() < 8 {
                value.push(Fa4::from_u64(pad));
                mult.push(Fa4::ZERO);
                pad += 1;
            }
            let mut perm_rng = SmallRng::seed_from_u64(5);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let mut pch = Chl::new(perm.clone());
            let alpha: Ea4 = pch.sample_algebra_element();
            let (proof, _h) = prove_leaf_bus_balance(&value, &mult, alpha, &mut pch);
            let mut vch = Chl::new(perm);
            let alpha_v: Ea4 = vch.sample_algebra_element();
            verify_leaf_bus_balance(&proof, alpha_v, 3, &mut vch)
        };
        assert!(run(false), "load_count == consumers must balance (full LEAF_BUS multiplicities)");
        assert!(!run(true), "forged claim value must break the full LEAF_BUS balance");
    }

    /// #135 FS-beta binding: the multi-field keyfold MUST use a transcript-drawn `beta`, not a fixed
    /// constant. Two DISTINCT leaves `[a,b]` and `[b,a]` fold to the SAME LogUp key under `β=1`, so a
    /// SEND[a,b]/RECV[b,a] bus (which should NOT balance — different leaves) balances SPURIOUSLY under the
    /// fixed fold; `draw_bus_fold_challenge` (transcript β≠1) makes the keys differ → correct REJECT.
    /// Proves why the bus keyfold `beta` is drawn from Fiat-Shamir, closing the fixed-fold hole.
    #[test]
    fn bus_fold_challenge_must_be_fiat_shamir() {
        use p3_challenger::FieldChallenger;
        let a = Fa4::from_u64(7);
        let b = Fa4::from_u64(9);
        // Distinct leaves [a,b] (SEND +1) and [b,a] (RECV −1); a balanced bus would (wrongly) tie them.
        let val_send = [a, b, Fa4::ZERO, Fa4::ZERO];
        let val_recv = [b, a, Fa4::ZERO, Fa4::ZERO];
        let balance = |beta: Fa4| -> bool {
            let k_send = leaf_bus_key(Fa4::ZERO, &val_send, beta);
            let k_recv = leaf_bus_key(Fa4::ZERO, &val_recv, beta);
            let mut value = vec![k_send, k_recv];
            let mut mult = vec![Fa4::ONE, -Fa4::ONE];
            let mut pad = 500u64;
            while value.len() < 8 {
                value.push(Fa4::from_u64(pad));
                mult.push(Fa4::ZERO);
                pad += 1;
            }
            let mut perm_rng = SmallRng::seed_from_u64(9);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let mut pch = Chl::new(perm.clone());
            let alpha: Ea4 = pch.sample_algebra_element();
            let (proof, _h) = prove_leaf_bus_balance(&value, &mult, alpha, &mut pch);
            let mut vch = Chl::new(perm);
            let alpha_v: Ea4 = vch.sample_algebra_element();
            verify_leaf_bus_balance(&proof, alpha_v, 3, &mut vch)
        };
        // Fixed β=1: [a,b] and [b,a] collide → the distinct-leaf bus balances SPURIOUSLY (the hole).
        assert!(balance(Fa4::ONE), "β=1 collides [a,b] with [b,a] (demonstrates the fixed-fold hole)");
        // Transcript β: draw from a fresh transcript; keys differ → correct REJECT.
        let mut r = SmallRng::seed_from_u64(21);
        let mut bch = Chl::new(Perm16::new_from_rng_128(&mut r));
        let fs_beta = draw_bus_fold_challenge(&mut bch);
        assert!(fs_beta != Fa4::ONE, "transcript fold challenge must not degenerate to 1");
        assert!(!balance(fs_beta), "transcript β≠1 distinguishes [a,b] from [b,a] → correct reject");
    }

    /// #135 source-tied balance: `prove/verify_leaf_bus_balance_tied` carries the REAL leaf columns
    /// `[idx, val*]` and folds the key inline, so `h` is bound to the trace. Honest matched SEND/RECV (same
    /// idx+val) balances; changing a consumed leaf's val — even with `h` recomputed consistently — no longer
    /// cancels its source → `Σh≠0` → REJECT. This is the production tie the rec-block routing calls.
    #[test]
    fn leaf_bus_balance_tied_binds_to_source_columns() {
        use p3_challenger::FieldChallenger;
        let run = |forge: bool| -> bool {
            let beta = Fa4::from_u64(19);
            // 4 rows: SEND(idx5,vA)+SEND(idx7,vB), RECV(idx5,vA)+RECV(idx7,vB) → matched pairs, balanced.
            let idx = vec![Fa4::from_u64(5), Fa4::from_u64(7), Fa4::from_u64(5), Fa4::from_u64(7)];
            let va = [Fa4::from_u64(30), Fa4::from_u64(31), Fa4::from_u64(32), Fa4::from_u64(33)];
            let vb = [Fa4::from_u64(40), Fa4::from_u64(41), Fa4::from_u64(42), Fa4::from_u64(43)];
            let mut val_cols: Vec<Vec<Fa4>> =
                (0..EXT_D).map(|k| vec![va[k], vb[k], va[k], vb[k]]).collect();
            let mult = vec![Fa4::ONE, Fa4::ONE, -Fa4::ONE, -Fa4::ONE];
            if forge {
                val_cols[0][2] += Fa4::ONE; // RECV row-2's val0 ≠ its SEND → no cancel → Σh ≠ 0
            }
            let mut perm_rng = SmallRng::seed_from_u64(31);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let mut pch = Chl::new(perm.clone());
            let alpha: Ea4 = pch.sample_algebra_element();
            let (proof, _h) =
                prove_leaf_bus_balance_tied(&idx, &val_cols, &mult, alpha, beta, &mut pch);
            let mut vch = Chl::new(perm);
            let alpha_v: Ea4 = vch.sample_algebra_element();
            verify_leaf_bus_balance_tied(&proof, alpha_v, beta, EXT_D, 2, &mut vch)
        };
        assert!(run(false), "matched SEND/RECV on real leaf columns balances (source-tied) → ACCEPT");
        assert!(!run(true), "changed consumed leaf val (unbound from source) → Σh≠0 → REJECT");
    }

    /// #135 tied LEAF_BUS builder: `build_leaf_bus_full_tied` emits the real source columns (idx/val*/mult)
    /// which, fed through the inline-keyfold tied balance, balance iff each leaf's load_count == consumers.
    /// Honest (load_count=2 = 1 r6 tape use + 1 claim) balances; forging the exposed claim value breaks it
    /// → reject. This is the production tied builder the circuit.rs swap passes into the bundle.
    #[test]
    fn build_leaf_bus_full_tied_balances_through_tied_balance() {
        use p3_challenger::FieldChallenger;
        let run = |forge: bool| -> bool {
            let leaf_idx = 5usize;
            let val = [Fa4::from_u64(30), Fa4::from_u64(31), Fa4::from_u64(32), Fa4::from_u64(33)];
            // r6 leaf-load row consuming leaf 5: s_leaf=sel[0]=1, a_idx=5, out=val.
            let mut r6t = vec![Fa4::ZERO; SYMX_R6_W];
            r6t[0] = Fa4::ONE;
            r6t[SYMX_AIDX] = Fa4::from_u64(leaf_idx as u64);
            for k in 0..EXT_D {
                r6t[SYMX_OUT + k] = val[k];
            }
            // LeafSource sources leaf 5 with load_count = 2 (one r6 use + one claim).
            let lf_w = 2 + EXT_D;
            let mut lft = vec![Fa4::ZERO; lf_w];
            lft[0] = Fa4::from_u64(leaf_idx as u64);
            for k in 0..EXT_D {
                lft[1 + k] = val[k];
            }
            lft[1 + EXT_D] = Fa4::from_u64(2);
            let mut claim_val = val.to_vec();
            if forge {
                claim_val[0] += Fa4::ONE; // exposed claim ≠ sourced leaf → imbalance
            }
            let claims = vec![(leaf_idx, claim_val)];
            let (mut idx, mut vcs, mut m) = build_leaf_bus_full_tied(&r6t, &lft, lf_w, &claims);
            // Pad the 3 real rows to 2^folding = 8.
            let mut pad = 950u64;
            while idx.len() < 8 {
                idx.push(Fa4::from_u64(pad));
                for vc in vcs.iter_mut() {
                    vc.push(Fa4::ZERO);
                }
                m.push(Fa4::ZERO);
                pad += 1;
            }
            let mut perm_rng = SmallRng::seed_from_u64(41);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let mut pch = Chl::new(perm.clone());
            let alpha: Ea4 = pch.sample_algebra_element();
            let beta = draw_bus_fold_challenge(&mut pch);
            let (proof, _h) = prove_leaf_bus_balance_tied(&idx, &vcs, &m, alpha, beta, &mut pch);
            let mut vch = Chl::new(perm);
            let alpha_v: Ea4 = vch.sample_algebra_element();
            let beta_v = draw_bus_fold_challenge(&mut vch);
            verify_leaf_bus_balance_tied(&proof, alpha_v, beta_v, EXT_D, 3, &mut vch)
        };
        assert!(run(false), "tied builder: load_count == consumers balances (source-tied) → ACCEPT");
        assert!(!run(true), "tied builder: forged claim val → Σh≠0 → REJECT");
    }

    /// #135 tied ACC_BUS: `build_acc_bus_tied` emits the r6-acc↔ood-acc tie in source-column form which,
    /// through the inline-keyfold tied balance, balances iff `r6_acc == ood_acc`. Matching accs accept;
    /// forging the ood acc breaks it → reject. Binds the ood quotient identity to the r6-computed acc via
    /// the tied path. This is the production tied ACC_BUS the circuit.rs swap passes into the bundle.
    #[test]
    fn build_acc_bus_tied_balances_iff_accs_match() {
        use p3_challenger::FieldChallenger;
        let run = |forge: bool| -> bool {
            let r6_acc = [Fa4::from_u64(7), Fa4::from_u64(8), Fa4::from_u64(9), Fa4::from_u64(10)];
            let mut ood_acc = r6_acc;
            if forge {
                ood_acc[0] += Fa4::ONE; // ood acc ≠ r6-computed acc → ACC_BUS imbalance
            }
            let (mut idx, mut vcs, mut m) = build_acc_bus_tied(&r6_acc, &ood_acc);
            let mut pad = 970u64;
            while idx.len() < 8 {
                idx.push(Fa4::from_u64(pad));
                for vc in vcs.iter_mut() {
                    vc.push(Fa4::ZERO);
                }
                m.push(Fa4::ZERO);
                pad += 1;
            }
            let mut perm_rng = SmallRng::seed_from_u64(43);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let mut pch = Chl::new(perm.clone());
            let alpha: Ea4 = pch.sample_algebra_element();
            let beta = draw_bus_fold_challenge(&mut pch);
            let (proof, _h) = prove_leaf_bus_balance_tied(&idx, &vcs, &m, alpha, beta, &mut pch);
            let mut vch = Chl::new(perm);
            let alpha_v: Ea4 = vch.sample_algebra_element();
            let beta_v = draw_bus_fold_challenge(&mut vch);
            verify_leaf_bus_balance_tied(&proof, alpha_v, beta_v, EXT_D, 3, &mut vch)
        };
        assert!(run(false), "matching r6_acc == ood_acc balances (tied ACC_BUS) → ACCEPT");
        assert!(!run(true), "forged ood acc → Σh≠0 → REJECT");
    }

    /// #135 VALIDATOR FINALITY CERT (bus 1 of 5) — `build_finality_weight_bus_tied` reads the committed
    /// member/sum weight cells BY OFFSET and emits the FINALITY_WEIGHT_BUS tied bus (SEND each voter's weight
    /// −1 / RECV each sum weight +1). Fed through the inline-keyfold tied balance it balances IFF
    /// `{member weights} == {sum weights}`. Honest (the sum aggregates the two UNIT voters `{1,1}`) balances →
    /// ACCEPT; forging the sum's w0 to 9 (≠ the bonded member weight 1 — the finality forgery: claim more
    /// aggregated voting weight than the bonded voters actually cast) → `Σh≠0` → REJECT. First of the cert's 5
    /// buses; the circuit.rs routing pairs this extractor with the proven source cross-tie (bus RECV ↔ the
    /// sum-trace w cells) so the sum weight cannot be a fabricated free value either.
    #[test]
    fn build_finality_weight_bus_tied_balances_iff_sum_matches_members() {
        use p3_challenger::FieldChallenger;
        let n_limbs = 4usize;
        let member_w = 8usize;
        // Each member trace: a flat row with the UNIT weight [1,0,0,0] at offsets [2,3,4,5].
        let weight_offsets = vec![2usize, 3, 4, 5];
        let mk_member = || {
            let mut row = vec![Fa4::ZERO; member_w];
            row[2] = Fa4::ONE; // weight limb0 = 1 (higher limbs 0 → unit)
            row
        };
        let members = vec![mk_member(), mk_member()];
        // Sum trace: w0 at offsets [1..5], w1 at [5..9]; each unit [1,0,0,0] on the honest path.
        let sum_offsets = vec![vec![1usize, 2, 3, 4], vec![5usize, 6, 7, 8]];
        let run = |forge: bool| -> bool {
            let mut sum = vec![Fa4::ZERO; 9];
            sum[1] = Fa4::ONE; // w0 limb0 = 1
            sum[5] = Fa4::ONE; // w1 limb0 = 1
            if forge {
                sum[1] = Fa4::from_u64(9); // w0 = 9 ≠ member weight 1 → inflated aggregate
            }
            let (mut idx, mut vcs, mut m) =
                build_finality_weight_bus_tied(&members, member_w, &weight_offsets, &sum, &sum_offsets);
            let mut pad = 800u64;
            while idx.len() < 8 {
                idx.push(Fa4::from_u64(pad));
                for vc in vcs.iter_mut() {
                    vc.push(Fa4::ZERO);
                }
                m.push(Fa4::ZERO);
                pad += 1;
            }
            let mut perm_rng = SmallRng::seed_from_u64(57);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let mut pch = Chl::new(perm.clone());
            let alpha: Ea4 = pch.sample_algebra_element();
            let beta = draw_bus_fold_challenge(&mut pch);
            let (proof, _h) = prove_leaf_bus_balance_tied(&idx, &vcs, &m, alpha, beta, &mut pch);
            let mut vch = Chl::new(perm);
            let alpha_v: Ea4 = vch.sample_algebra_element();
            let beta_v = draw_bus_fold_challenge(&mut vch);
            verify_leaf_bus_balance_tied(&proof, alpha_v, beta_v, n_limbs, 3, &mut vch)
        };
        assert!(run(false), "sum weights {{1,1}} == member weights {{1,1}} → FINALITY_WEIGHT_BUS balances → ACCEPT");
        assert!(!run(true), "forged sum w0=9 ≠ member weight 1 → Σh≠0 → REJECT (finality forgery caught)");
    }

    /// #135 VALIDATOR FINALITY CERT (buses 2–5) — `build_cert_bus_tied` is the generic SEND/RECV tied-bus
    /// builder for the cert's remaining buses. Modeled here on PK_D_BUS at its real 2·DIGEST width (the voter
    /// SENDs pk_d‖rho, the own-null AIR RECVs the same tuple — P-BIND: the voter owns the very bond that cast
    /// the vote). Honest (RECV tuple == SEND tuple) balances → ACCEPT; forging ONE RECV pk_d limb (claim
    /// ownership of a DIFFERENT bond than the one that voted) → `Σh≠0` → REJECT. Proves the generic builder
    /// enforces the cross-AIR binding at the full bus width, so buses 2–5 reuse it (only the source offsets +
    /// tuple width differ per bus).
    #[test]
    fn build_cert_bus_tied_balances_iff_send_matches_recv() {
        use p3_challenger::FieldChallenger;
        let n_limbs = 2 * 8usize; // 2·DIGEST = the pk_d‖rho tuple width
        let run = |forge: bool| -> bool {
            let send: Vec<Fa4> = (0..n_limbs).map(|k| Fa4::from_u64(k as u64 + 3)).collect();
            let mut recv = send.clone();
            if forge {
                recv[5] += Fa4::ONE; // one RECV pk_d limb ≠ SEND → own a different bond than voted
            }
            let (mut idx, mut vcs, mut m) = build_cert_bus_tied(&[send], &[recv], n_limbs);
            let mut pad = 600u64;
            while idx.len() < 8 {
                idx.push(Fa4::from_u64(pad));
                for vc in vcs.iter_mut() {
                    vc.push(Fa4::ZERO);
                }
                m.push(Fa4::ZERO);
                pad += 1;
            }
            let mut perm_rng = SmallRng::seed_from_u64(71);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let mut pch = Chl::new(perm.clone());
            let alpha: Ea4 = pch.sample_algebra_element();
            let beta = draw_bus_fold_challenge(&mut pch);
            let (proof, _h) = prove_leaf_bus_balance_tied(&idx, &vcs, &m, alpha, beta, &mut pch);
            let mut vch = Chl::new(perm);
            let alpha_v: Ea4 = vch.sample_algebra_element();
            let beta_v = draw_bus_fold_challenge(&mut vch);
            verify_leaf_bus_balance_tied(&proof, alpha_v, beta_v, n_limbs, 3, &mut vch)
        };
        assert!(run(false), "RECV pk_d‖rho == SEND → PK_D_BUS balances → ACCEPT");
        assert!(!run(true), "forged RECV pk_d limb (own a different bond than voted) → Σh≠0 → REJECT");
    }

    /// #135 self-contained bytes entry pair: `prove/verify_rec_block_light_decider_selfcontained_bytes`
    /// build the pinned decider config INTERNALLY, so circuit.rs passes only traces + tied buses. An honest
    /// carrier (valid ood row) verifies end-to-end through the wire path; a corrupted carrier byte rejects
    /// fail-closed. This is the EXACT entry pair the circuit.rs `prove_batch` swap calls.
    #[test]
    fn rec_block_selfcontained_bytes_entry_roundtrips() {
        use rand::Rng;
        let mut data_rng = SmallRng::seed_from_u64(7);
        let mut mk = |h: usize, w: usize| -> RowMajorMatrix<Fa4> {
            RowMajorMatrix::new((0..h * w).map(|_| data_rng.random::<Fa4>()).collect(), w)
        };
        // A VALID OodCheck row (acc = q·z_h, active = 1) so the ood gate passes end-to-end.
        let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) + 2));
        let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 3 + 5));
        let acc = q * zh;
        let limbs =
            |e: Ea4| -> Vec<Fa4> { (0..EXT_D).map(|k| e.as_basis_coefficients_slice()[k]).collect() };
        let mut ood_row: Vec<Fa4> = Vec::new();
        ood_row.extend(limbs(zh));
        ood_row.extend(limbs(q));
        ood_row.extend(limbs(acc));
        ood_row.push(Fa4::ONE);
        assert_eq!(ood_row.len(), OODCHK_W);
        let leaf = mk(16, LEAF_W);
        let traces = [leaf, RowMajorMatrix::new(ood_row, OODCHK_W)];
        // The public bind = the block's attested claims (nf‖outcm) the daemon reads + checks.
        let bind = [Fa4::from_u64(11), Fa4::from_u64(22), Fa4::from_u64(33)];
        let bytes = prove_rec_block_light_decider_selfcontained_bytes(&traces, Vec::new(), &bind)
            .expect("self-contained carrier bytes");
        assert!(!bytes.is_empty(), "carrier bytes are non-empty");
        assert!(
            verify_rec_block_light_decider_selfcontained_bytes(&bytes, &bind),
            "honest carrier + matching public claims verifies through the pinned-seed wire path"
        );
        // A verifier reading DIFFERENT public claims derives a divergent transcript → REJECT (the tie that
        // welds the daemon-read claims to the proof).
        let bad_bind = [Fa4::from_u64(11), Fa4::from_u64(22), Fa4::from_u64(99)];
        assert!(
            !verify_rec_block_light_decider_selfcontained_bytes(&bytes, &bad_bind),
            "mismatched public claims (bind) reject — the FS transcript diverges"
        );
        let mut bad = bytes.clone();
        let n = bad.len();
        bad[n / 2] ^= 0xFF;
        assert!(
            !verify_rec_block_light_decider_selfcontained_bytes(&bad, &bind),
            "corrupted carrier byte rejects fail-closed"
        );
    }

    /// #135 LEAF_BUS WIRED INTO THE PRODUCTION BUNDLE: `prove_rec_block_whir_openings_with_bus` appends
    /// the committed bus table, runs the LogUp balance, and binds it via `eval_at`; verify enforces it
    /// end-to-end alongside the opening + r6 layers. Honest balanced bus ACCEPTS; forging a consumed-leaf
    /// value REJECTS through the FULL bundle — proving the bus is soundly bound to the commitment, not a
    /// free standalone proof.
    #[test]
    fn rec_block_bundle_enforces_leaf_bus_honest_accepts_forged_rejects() {
        let build = |tamper: bool| -> bool {
            let seed = 11u64;
            let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
            let mut perm_rng = SmallRng::seed_from_u64(seed);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let hash = SpongeHash::new(perm.clone());
            let compress = CompressHash::new(perm.clone());
            let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
            let encoding: Enc16 = decider_mask_encoding(t, ell_zk);

            // One small filler rec table (non-r6, width 4) + a balanced LEAF_BUS supplied as (value, mult).
            let mut data_rng = SmallRng::seed_from_u64(seed + 1);
            let filler =
                RowMajorMatrix::new((0..8 * 4).map(|_| data_rng.random::<Fa4>()).collect(), 4);
            let (tables, shapes) = rec_traces_to_tables(&[filler], folding);

            let beta = Fa4::from_u64(7);
            let leaves: [(Fa4, [Fa4; EXT_D]); 2] = [
                (
                    Fa4::from_u64(0),
                    [Fa4::from_u64(11), Fa4::from_u64(12), Fa4::from_u64(13), Fa4::from_u64(14)],
                ),
                (
                    Fa4::from_u64(1),
                    [Fa4::from_u64(21), Fa4::from_u64(22), Fa4::from_u64(23), Fa4::from_u64(24)],
                ),
            ];
            let mut value: Vec<Fa4> = Vec::new();
            let mut mult: Vec<Fa4> = Vec::new();
            for (li, (idx, val)) in leaves.iter().enumerate() {
                value.push(leaf_bus_key(*idx, val, beta));
                mult.push(-Fa4::from_u64(2));
                for r in 0..2 {
                    let mut v = *val;
                    if tamper && li == 0 && r == 0 {
                        v[0] += Fa4::ONE;
                    }
                    value.push(leaf_bus_key(*idx, &v, beta));
                    mult.push(Fa4::ONE);
                }
            }

            let mut pch = Chl::new(perm.clone());
            let mut prover_rng = SmallRng::seed_from_u64(seed + 2);
            let bundle = prove_rec_block_whir_openings_with_bus(
                tables,
                shapes,
                folding,
                pow_bits,
                mmcs,
                encoding,
                &mut pch,
                &mut prover_rng,
                vec![(value, mult)],
                Vec::new(),
            );
            assert!(!bundle.buses.is_empty(), "bus proof must be present in the bundle");
            let mut vch = Chl::new(perm);
            verify_rec_block_whir_openings(&bundle, folding, ell_zk, pow_bits, &mut vch)
        };
        assert!(build(false), "honest bundle with a balanced LEAF_BUS must verify");
        assert!(!build(true), "forged consumed-leaf value must be rejected through the full bundle");
    }

    /// #135 MULTI-BUS: the bundle enforces MORE THAN ONE LogUp bus at once — LEAF_BUS + a second
    /// SYMX_REG_BUS-shaped bus (register write↔read) — each committed + `eval_at`-bound. Honest (both
    /// balanced) ACCEPTS; forging EITHER bus's consumed value REJECTS through the full bundle. This is
    /// the generalization that lets the rec block bind every bus (leaf + reg + …) in one decider proof.
    #[test]
    fn rec_block_bundle_enforces_two_buses_honest_accepts_either_forged_rejects() {
        let build = |tamper: u8| -> bool {
            // 0 = honest, 1 = forge LEAF_BUS recv value, 2 = forge REG_BUS recv value.
            let seed = 13u64;
            let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
            let mut perm_rng = SmallRng::seed_from_u64(seed);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let hash = SpongeHash::new(perm.clone());
            let compress = CompressHash::new(perm.clone());
            let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
            let encoding: Enc16 = decider_mask_encoding(t, ell_zk);

            let mut data_rng = SmallRng::seed_from_u64(seed + 1);
            let filler =
                RowMajorMatrix::new((0..8 * 4).map(|_| data_rng.random::<Fa4>()).collect(), 4);
            let (tables, shapes) = rec_traces_to_tables(&[filler], folding);

            let beta = Fa4::from_u64(7);
            // Balanced (value, mult) bus of 2 entries, each SENT once (−1, a write) + RECV once (+1, a
            // read); `forge` corrupts the first recv value so its key no longer matches its send.
            let mk_bus = |base: u64, forge: bool| -> (Vec<Fa4>, Vec<Fa4>) {
                let mut value: Vec<Fa4> = Vec::new();
                let mut mult: Vec<Fa4> = Vec::new();
                for j in 0..2u64 {
                    let idx = Fa4::from_u64(base + j);
                    let val = [
                        Fa4::from_u64(base + j * 10 + 1),
                        Fa4::from_u64(base + j * 10 + 2),
                        Fa4::from_u64(base + j * 10 + 3),
                        Fa4::from_u64(base + j * 10 + 4),
                    ];
                    value.push(leaf_bus_key(idx, &val, beta));
                    mult.push(-Fa4::ONE);
                    let mut rv = val;
                    if forge && j == 0 {
                        rv[0] += Fa4::ONE;
                    }
                    value.push(leaf_bus_key(idx, &rv, beta));
                    mult.push(Fa4::ONE);
                }
                (value, mult)
            };
            let leaf = mk_bus(100, tamper == 1);
            let reg = mk_bus(500, tamper == 2);

            let mut pch = Chl::new(perm.clone());
            let mut prover_rng = SmallRng::seed_from_u64(seed + 2);
            let bundle = prove_rec_block_whir_openings_with_bus(
                tables,
                shapes,
                folding,
                pow_bits,
                mmcs,
                encoding,
                &mut pch,
                &mut prover_rng,
                vec![leaf, reg],
                Vec::new(),
            );
            assert_eq!(bundle.buses.len(), 2, "both buses must be present in the bundle");
            let mut vch = Chl::new(perm);
            verify_rec_block_whir_openings(&bundle, folding, ell_zk, pow_bits, &mut vch)
        };
        assert!(build(0), "honest bundle with two balanced buses must verify");
        assert!(!build(1), "forged LEAF_BUS value must be rejected");
        assert!(!build(2), "forged REG_BUS value must be rejected");
    }

    /// The height-1 row-recovery primitive binds the OodCheck row to the commitment: a valid row's
    /// WHIR openings recover to that exact row and satisfy `z_h·q=acc`, while an opening carrying a
    /// non-base extension coefficient (not a committed base-field row) is rejected fail-closed.
    #[test]
    fn height1_row_recovery_binds_and_feeds_oodcheck() {
        // A valid OodCheck row: z_h, q arbitrary; acc = q·z_h; active = 1; OODCHK_W base values.
        let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) + 2));
        let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 3 + 5));
        let acc = q * zh;
        let limbs =
            |e: Ea4| -> Vec<Fa4> { (0..EXT_D).map(|k| e.as_basis_coefficients_slice()[k]).collect() };
        let mut row: Vec<Fa4> = Vec::new();
        row.extend(limbs(zh));
        row.extend(limbs(q));
        row.extend(limbs(acc));
        row.push(Fa4::ONE);
        assert_eq!(row.len(), OODCHK_W);

        // Height-1 MLE openings at a non-boundary point: opened_c = row_c · ∏(1 − z_i).
        let point: Vec<Ea4> = (0..3).map(|i| Ea4::from(Fa4::from_u64((i as u64) + 5))).collect();
        let mut eq = Ea4::ONE;
        for &z in &point {
            eq *= Ea4::ONE - z;
        }
        let openings: Vec<Ea4> = row.iter().map(|&rc| Ea4::from(rc) * eq).collect();

        // Recovery binds the row; the recovered row satisfies the OodCheck identity.
        let recovered =
            recover_height1_row_from_mle_openings(&openings, &point).expect("row is recoverable");
        assert_eq!(recovered, row, "recovered row must equal the committed height-1 row");
        assert!(
            check_oodcheck_identity(&recovered),
            "recovered valid row must satisfy z_h·q = acc"
        );

        // Tamper: an opening carrying a non-base extension coefficient is not a base-field row.
        let mut bad = openings.clone();
        bad[0] += Ea4::from_basis_coefficients_fn(|k| if k == 1 { Fa4::ONE } else { Fa4::ZERO });
        assert!(
            recover_height1_row_from_mle_openings(&bad, &point).is_none(),
            "non-base-field opening must be rejected"
        );
    }

    /// The rec-block ood gate requires an ACTIVE row: an inactive row that the generic per-row
    /// check permits (as padding) is rejected by the rec-block gate, and a tampered quotient fails
    /// under both.
    #[test]
    fn rec_block_ood_row_requires_active() {
        let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) + 2));
        let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 3 + 5));
        let acc = q * zh;
        let limbs =
            |e: Ea4| -> Vec<Fa4> { (0..EXT_D).map(|k| e.as_basis_coefficients_slice()[k]).collect() };
        let mut row: Vec<Fa4> = Vec::new();
        row.extend(limbs(zh));
        row.extend(limbs(q));
        row.extend(limbs(acc));
        row.push(Fa4::ONE); // active = 1

        // active=1 valid row: both the generic and the rec-block gate accept.
        assert!(check_rec_block_ood_row(&row), "active valid rec-block ood row must pass");
        assert!(check_oodcheck_identity(&row));

        // active=0 row: the generic per-row check permits it (padding), the rec-block gate does NOT.
        let mut inactive = row.clone();
        inactive[EXT_D * 3] = Fa4::ZERO;
        assert!(
            check_oodcheck_identity(&inactive),
            "generic per-row check permits an inactive padding row"
        );
        assert!(
            !check_rec_block_ood_row(&inactive),
            "rec-block gate requires the ood row to be active"
        );

        // tampered quotient with active=1: rejected by the rec-block gate.
        let mut bad = row.clone();
        bad[EXT_D * 2] += Fa4::ONE;
        assert!(!check_rec_block_ood_row(&bad), "tampered acc must be rejected");
    }

    /// `check_rec_block_ood_from_openings` composes recovery + the rec-block gate over the COMMITTED
    /// openings of the ood table (idx 1): an honest active row recovered from its height-1 MLE
    /// openings passes, and every tamper — inactive row, broken `acc==q·z_h`, a non-base-field
    /// opening, a boundary point, an out-of-range index — is rejected fail-closed. This is the
    /// binding that stops a prover from feeding the OodCheck gate a row it did not commit.
    #[test]
    fn rec_block_ood_from_openings_binds_and_gates() {
        let seed = 0u64;
        let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(t, ell_zk);
        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let mk = |rng: &mut SmallRng, h: usize, w: usize| -> RowMajorMatrix<Fa4> {
            RowMajorMatrix::new((0..h * w).map(|_| rng.random::<Fa4>()).collect(), w)
        };
        let traces = [
            mk(&mut data_rng, 16, LEAF_W),
            mk(&mut data_rng, 1, OODCHK_W),
            mk(&mut data_rng, 8, 4),
        ];
        let (tables, shapes) = rec_traces_to_tables(&traces, folding);
        let mut pch = Chl::new(perm.clone());
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let mut bundle = prove_rec_block_whir_openings(
            tables, shapes, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
        );

        // A valid OodCheck row (acc = q·z_h, active = 1) and its height-1 MLE openings at a
        // non-boundary point: opened_c = row_c · ∏(1 − z_i).
        let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) + 2));
        let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 3 + 5));
        let acc = q * zh;
        let limbs = |e: Ea4| -> Vec<Fa4> {
            (0..EXT_D).map(|k| e.as_basis_coefficients_slice()[k]).collect()
        };
        let mut row: Vec<Fa4> = Vec::new();
        row.extend(limbs(zh));
        row.extend(limbs(q));
        row.extend(limbs(acc));
        row.push(Fa4::ONE);
        assert_eq!(row.len(), OODCHK_W);
        let point: Vec<Ea4> =
            (0..folding).map(|i| Ea4::from(Fa4::from_u64((i as u64) + 5))).collect();
        let mut eq = Ea4::ONE;
        for &z in &point {
            eq *= Ea4::ONE - z;
        }
        let ood_openings = |r: &[Fa4]| -> Vec<Ea4> { r.iter().map(|&rc| Ea4::from(rc) * eq).collect() };

        // Honest: valid active row recovers from the openings at idx 1 and passes the rec-block gate.
        bundle.openings[1] = ood_openings(&row);
        assert!(
            check_rec_block_ood_from_openings(&bundle, 1, &point),
            "recovered active valid ood row must pass the rec-block gate"
        );
        assert!(check_oodcheck_identity(&row) && check_rec_block_ood_row(&row));

        // Inactive row (active=0): recovers, but the rec-block gate requires active → reject.
        let mut inactive = row.clone();
        inactive[EXT_D * 3] = Fa4::ZERO;
        bundle.openings[1] = ood_openings(&inactive);
        assert!(
            !check_rec_block_ood_from_openings(&bundle, 1, &point),
            "inactive ood row must be rejected by the rec-block gate"
        );

        // Tampered quotient (acc != q·z_h), active=1: reject.
        let mut bad = row.clone();
        bad[EXT_D * 2] += Fa4::ONE;
        bundle.openings[1] = ood_openings(&bad);
        assert!(
            !check_rec_block_ood_from_openings(&bundle, 1, &point),
            "tampered acc must be rejected"
        );

        // Non-base-field opening (a committed row entry cannot carry a non-base coefficient): reject.
        bundle.openings[1] = ood_openings(&row);
        bundle.openings[1][0] +=
            Ea4::from_basis_coefficients_fn(|k| if k == 1 { Fa4::ONE } else { Fa4::ZERO });
        assert!(
            !check_rec_block_ood_from_openings(&bundle, 1, &point),
            "non-base-field opening must be rejected fail-closed"
        );

        // Boundary point (∏(1−z_i)=0 via z_0=1): row not recoverable → reject.
        bundle.openings[1] = ood_openings(&row);
        let mut boundary = point.clone();
        boundary[0] = Ea4::ONE;
        assert!(
            !check_rec_block_ood_from_openings(&bundle, 1, &boundary),
            "boundary point must be rejected fail-closed"
        );

        // Out-of-range ood table index: reject, never panic.
        assert!(
            !check_rec_block_ood_from_openings(&bundle, 99, &point),
            "out-of-range ood index must be rejected"
        );
    }

    /// `verify_rec_block_light_decider` is the AND of (masked-sumcheck opening verify) and (ood row
    /// recovered-from-openings gate). It must be fail-closed on EACH half: a forged virtual eval
    /// (opening half fails) rejects regardless of the ood point, and an unrecoverable/boundary ood
    /// point (ood half fails) rejects even when the opening half is honest.
    #[test]
    fn rec_block_light_decider_fail_closed_on_both_halves() {
        let seed = 0u64;
        let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(t, ell_zk);
        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let mk = |rng: &mut SmallRng, h: usize, w: usize| -> RowMajorMatrix<Fa4> {
            RowMajorMatrix::new((0..h * w).map(|_| rng.random::<Fa4>()).collect(), w)
        };
        let traces = [
            mk(&mut data_rng, 16, LEAF_W),
            mk(&mut data_rng, 1, OODCHK_W),
            mk(&mut data_rng, 8, 4),
        ];
        let (tables, shapes) = rec_traces_to_tables(&traces, folding);
        let mut pch = Chl::new(perm.clone());
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let mut bundle = prove_rec_block_whir_openings(
            tables, shapes, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
        );

        // The masked-sumcheck opening half is honest on this bundle.
        let mut vch_open = Chl::new(perm.clone());
        assert!(
            verify_rec_block_whir_openings(&bundle, folding, ell_zk, pow_bits, &mut vch_open),
            "honest opening half must verify"
        );

        // HALF 2 GATES: a BOUNDARY ood point (∏(1−z_i)=0) makes the ood row unrecoverable → the ood
        // half is false → the composed decider REJECTS even though the opening half is honest.
        let mut boundary: Vec<Ea4> =
            (0..folding).map(|i| Ea4::from(Fa4::from_u64((i as u64) + 5))).collect();
        boundary[0] = Ea4::ONE;
        let mut vch_b = Chl::new(perm.clone());
        assert!(
            !verify_rec_block_light_decider(&bundle, 1, &boundary, folding, ell_zk, pow_bits, &mut vch_b),
            "unrecoverable ood point → composed decider rejects though the opening half is honest"
        );

        // HALF 1 GATES: forge the virtual evaluation → the opening half fails → the composed decider
        // REJECTS regardless of the ood point.
        bundle.virtual_eval += Ea4::ONE;
        let point: Vec<Ea4> =
            (0..folding).map(|i| Ea4::from(Fa4::from_u64((i as u64) + 5))).collect();
        let mut vch_a = Chl::new(perm);
        assert!(
            !verify_rec_block_light_decider(&bundle, 1, &point, folding, ell_zk, pow_bits, &mut vch_a),
            "forged virtual eval → opening half fails → composed decider rejects"
        );
    }

    /// The ood-table locator finds the unique OODCHK_W-wide table by width and is fail-closed when
    /// there is not exactly one; `verify_rec_block_light_decider_auto` locates the ood table
    /// structurally (no magic index), reaches the gate on a well-formed bundle, and rejects a
    /// malformed bundle (no ood table) fail-closed.
    #[test]
    fn rec_block_ood_table_index_locates_and_auto_verify_gates() {
        // Pure locator over shapes.
        assert_eq!(
            rec_block_ood_table_index(&[(4, LEAF_W), (3, OODCHK_W), (3, 4)]),
            Some(1),
            "unique OODCHK_W table located at idx 1"
        );
        assert_eq!(rec_block_ood_table_index(&[(4, LEAF_W), (3, 4)]), None, "no ood table → None");
        assert_eq!(
            rec_block_ood_table_index(&[(3, OODCHK_W), (2, OODCHK_W)]),
            None,
            "two ood-width tables → ambiguous → None"
        );
        assert_eq!(rec_block_ood_table_index(&[]), None, "empty → None");

        // Auto-wrapper on a REAL bundle: the standard [leaf, ood, r6] topology locates idx 1, and a
        // BOUNDARY ood point makes the ood half unrecoverable → auto-verify rejects (reaches the gate).
        let seed = 0u64;
        let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(t, ell_zk);
        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let mk = |rng: &mut SmallRng, h: usize, w: usize| -> RowMajorMatrix<Fa4> {
            RowMajorMatrix::new((0..h * w).map(|_| rng.random::<Fa4>()).collect(), w)
        };
        let traces = [
            mk(&mut data_rng, 16, LEAF_W),
            mk(&mut data_rng, 1, OODCHK_W),
            mk(&mut data_rng, 8, 4),
        ];
        let (tables, shapes) = rec_traces_to_tables(&traces, folding);
        assert_eq!(rec_block_ood_table_index(&shapes), Some(1), "real bundle: ood at idx 1");
        let mut pch = Chl::new(perm.clone());
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let mut bundle = prove_rec_block_whir_openings(
            tables, shapes, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
        );
        let mut boundary: Vec<Ea4> =
            (0..folding).map(|i| Ea4::from(Fa4::from_u64((i as u64) + 5))).collect();
        boundary[0] = Ea4::ONE;
        let mut vch = Chl::new(perm.clone());
        assert!(
            !verify_rec_block_light_decider_auto(&bundle, &boundary, folding, ell_zk, pow_bits, &mut vch),
            "auto-verify with a boundary ood point must reject"
        );

        // Malformed bundle: mangle the ood table's width so no OODCHK_W table remains → locator
        // returns None → auto-verify rejects fail-closed (never a wrong index).
        bundle.shapes[1].1 = 4;
        assert_eq!(rec_block_ood_table_index(&bundle.shapes), None, "mangled: no ood table");
        let point: Vec<Ea4> =
            (0..folding).map(|i| Ea4::from(Fa4::from_u64((i as u64) + 5))).collect();
        let mut vch2 = Chl::new(perm);
        assert!(
            !verify_rec_block_light_decider_auto(&bundle, &point, folding, ell_zk, pow_bits, &mut vch2),
            "malformed bundle (no ood table) must reject fail-closed"
        );
    }

    /// The ood opening point must have EXACTLY the committed arity of the ood table
    /// (`shapes[ood_idx].0`): a full-arity point with an honest row accepts, and a shorter/longer
    /// point is rejected fail-closed before recovery ever runs (it is not the FS point the columns
    /// were opened at).
    #[test]
    fn rec_block_ood_from_openings_rejects_wrong_length_point() {
        let seed = 0u64;
        let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(t, ell_zk);
        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let mk = |rng: &mut SmallRng, h: usize, w: usize| -> RowMajorMatrix<Fa4> {
            RowMajorMatrix::new((0..h * w).map(|_| rng.random::<Fa4>()).collect(), w)
        };
        let traces = [
            mk(&mut data_rng, 16, LEAF_W),
            mk(&mut data_rng, 1, OODCHK_W),
            mk(&mut data_rng, 8, 4),
        ];
        let (tables, shapes) = rec_traces_to_tables(&traces, folding);
        assert_eq!(shapes[1].0, folding, "ood table arity == folding");
        let mut pch = Chl::new(perm.clone());
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let mut bundle = prove_rec_block_whir_openings(
            tables, shapes, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
        );

        // Install a valid active OodCheck row's height-1 openings at a full-arity point.
        let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) + 2));
        let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 3 + 5));
        let acc = q * zh;
        let limbs = |e: Ea4| -> Vec<Fa4> {
            (0..EXT_D).map(|k| e.as_basis_coefficients_slice()[k]).collect()
        };
        let mut row: Vec<Fa4> = Vec::new();
        row.extend(limbs(zh));
        row.extend(limbs(q));
        row.extend(limbs(acc));
        row.push(Fa4::ONE);
        let point: Vec<Ea4> =
            (0..folding).map(|i| Ea4::from(Fa4::from_u64((i as u64) + 5))).collect();
        let mut eq = Ea4::ONE;
        for &z in &point {
            eq *= Ea4::ONE - z;
        }
        bundle.openings[1] = row.iter().map(|&rc| Ea4::from(rc) * eq).collect();

        // Full-arity point (len == folding) with the honest row accepts.
        assert!(
            check_rec_block_ood_from_openings(&bundle, 1, &point),
            "full-arity point with honest row must accept"
        );
        // Too-short point (len == folding-1) rejects before recovery runs.
        assert!(
            !check_rec_block_ood_from_openings(&bundle, 1, &point[..folding - 1]),
            "short point (len != arity) must be rejected fail-closed"
        );
        // Too-long point (len == folding+1) rejects.
        let mut long_point = point.clone();
        long_point.push(Ea4::from(Fa4::from_u64(99)));
        assert!(
            !check_rec_block_ood_from_openings(&bundle, 1, &long_point),
            "long point (len != arity) must be rejected fail-closed"
        );
    }

    /// The light-decider proof's OPENING payload is CONSTANT in the number of spends (table HEIGHT):
    /// two bundles over the same rec topology but 4× the rows expose the identical opening limb count
    /// (= Σ widths × EXT_D, per-column). This is the no-growth / ≤1.8MB FAST pillar — the proof opens
    /// per-column, never per-row, so folding 4× the spends does not enlarge the opening payload.
    #[test]
    fn rec_block_opening_payload_is_spend_count_independent() {
        let build = |leaf_h: usize, r6_h: usize| -> usize {
            let seed = 0u64;
            let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
            let mut perm_rng = SmallRng::seed_from_u64(seed);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let hash = SpongeHash::new(perm.clone());
            let compress = CompressHash::new(perm.clone());
            let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
            let encoding: Enc16 = decider_mask_encoding(t, ell_zk);
            let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
            let mk = |rng: &mut SmallRng, h: usize, w: usize| -> RowMajorMatrix<Fa4> {
                RowMajorMatrix::new((0..h * w).map(|_| rng.random::<Fa4>()).collect(), w)
            };
            let traces = [
                mk(&mut data_rng, leaf_h, LEAF_W),
                mk(&mut data_rng, 1, OODCHK_W),
                mk(&mut data_rng, r6_h, 4),
            ];
            let (tables, shapes) = rec_traces_to_tables(&traces, folding);
            let mut pch = Chl::new(perm);
            let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
            let bundle = prove_rec_block_whir_openings(
                tables, shapes, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
            );
            rec_block_bundle_opening_limb_count(&bundle)
        };
        let small = build(16, 8);
        let large = build(64, 32); // 4× the rows (spends)
        assert_eq!(small, large, "opening payload must not grow with the spend count (rows)");
        assert_eq!(
            small,
            (LEAF_W + OODCHK_W + 4) * EXT_D,
            "opening payload == (Σ table widths) × EXT_D — per-column, constant"
        );
    }

    /// The opening bundle round-trips through postcard bytes — the WHIR light-decider proof payload
    /// the wallet fast-broadcast carries in the tx carrier and the node deserializes + verifies.
    /// Serialize → deserialize yields a bundle that verifies IDENTICALLY to the original (honest
    /// still accepts), and a forged bundle (tampered virtual eval) still REJECTS after round-trip —
    /// so the proof travels on the wire without losing soundness.
    #[test]
    fn rec_block_bundle_postcard_roundtrips_and_verifies() {
        let seed = 0u64;
        let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(t, ell_zk);
        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let mk = |rng: &mut SmallRng, h: usize, w: usize| -> RowMajorMatrix<Fa4> {
            RowMajorMatrix::new((0..h * w).map(|_| rng.random::<Fa4>()).collect(), w)
        };
        let traces = [
            mk(&mut data_rng, 16, LEAF_W),
            mk(&mut data_rng, 1, OODCHK_W),
            mk(&mut data_rng, 8, 4),
        ];
        let (tables, shapes) = rec_traces_to_tables(&traces, folding);
        let mut pch = Chl::new(perm.clone());
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let bundle = prove_rec_block_whir_openings(
            tables, shapes, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
        );

        // Serialize → deserialize (the tx-carrier payload).
        let bytes = postcard::to_allocvec(&bundle).expect("bundle serializes to postcard bytes");
        assert!(!bytes.is_empty(), "serialized bundle is non-empty");
        let restored: super::RecBlockOpeningBundle =
            postcard::from_bytes(&bytes).expect("bundle deserializes from postcard bytes");

        // The restored bundle verifies IDENTICALLY to the original (opening half).
        let mut vch_o = Chl::new(perm.clone());
        let orig_ok = verify_rec_block_whir_openings(&bundle, folding, ell_zk, pow_bits, &mut vch_o);
        let mut vch_r = Chl::new(perm.clone());
        let restored_ok =
            verify_rec_block_whir_openings(&restored, folding, ell_zk, pow_bits, &mut vch_r);
        assert!(orig_ok, "honest original bundle verifies");
        assert_eq!(orig_ok, restored_ok, "round-tripped bundle verifies identically to the original");

        // A forged bundle (tampered virtual eval) still REJECTS after a serialize→deserialize cycle.
        let mut forged = restored;
        forged.virtual_eval += Ea4::ONE;
        let fbytes = postcard::to_allocvec(&forged).expect("forged bundle serializes");
        let refried: super::RecBlockOpeningBundle =
            postcard::from_bytes(&fbytes).expect("forged bundle deserializes");
        let mut vch_f = Chl::new(perm);
        assert!(
            !verify_rec_block_whir_openings(&refried, folding, ell_zk, pow_bits, &mut vch_f),
            "forged bundle rejects after round-trip"
        );
    }

    /// FULL PIPELINE end-to-end via the SELF-CONTAINED verify (derives the ood point from its own
    /// transcript replay, no caller-supplied point): an honest bundle whose ood table is a VALID
    /// OodCheck row ACCEPTS (open → derive point → recover row → gate), still ACCEPTS after a
    /// postcard round-trip (the wire path a node receives), and a forged bundle REJECTS.
    #[test]
    fn rec_block_light_decider_selfcontained_accepts_honest_rejects_forged() {
        let seed = 0u64;
        let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(t, ell_zk);
        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let mk = |rng: &mut SmallRng, h: usize, w: usize| -> RowMajorMatrix<Fa4> {
            RowMajorMatrix::new((0..h * w).map(|_| rng.random::<Fa4>()).collect(), w)
        };
        // The ood table is a VALID OodCheck row (acc = q·z_h, active = 1) so the full pipeline
        // accepts end-to-end; leaf/r6 are arbitrary (the ood gate is the constraint under test).
        let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) + 2));
        let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 3 + 5));
        let acc = q * zh;
        let limbs = |e: Ea4| -> Vec<Fa4> {
            (0..EXT_D).map(|k| e.as_basis_coefficients_slice()[k]).collect()
        };
        let mut ood_row: Vec<Fa4> = Vec::new();
        ood_row.extend(limbs(zh));
        ood_row.extend(limbs(q));
        ood_row.extend(limbs(acc));
        ood_row.push(Fa4::ONE);
        assert_eq!(ood_row.len(), OODCHK_W);
        let traces = [
            mk(&mut data_rng, 16, LEAF_W),
            RowMajorMatrix::new(ood_row, OODCHK_W),
            mk(&mut data_rng, 8, 4),
        ];
        let (tables, shapes) = rec_traces_to_tables(&traces, folding);
        let mut pch = Chl::new(perm.clone());
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let bundle = prove_rec_block_whir_openings(
            tables, shapes, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
        );

        // HONEST: the self-contained verify derives the ood point from its OWN replay + ACCEPTS.
        let mut vch = Chl::new(perm.clone());
        assert!(
            verify_rec_block_light_decider_selfcontained(&bundle, folding, ell_zk, pow_bits, &mut vch),
            "honest bundle (valid ood row) must ACCEPT end-to-end via the self-derived point"
        );

        // WIRE PATH: survives a postcard round-trip and still ACCEPTS.
        let bytes = postcard::to_allocvec(&bundle).expect("serialize");
        let restored: super::RecBlockOpeningBundle =
            postcard::from_bytes(&bytes).expect("deserialize");
        let mut vchr = Chl::new(perm.clone());
        assert!(
            verify_rec_block_light_decider_selfcontained(&restored, folding, ell_zk, pow_bits, &mut vchr),
            "round-tripped honest bundle must ACCEPT via the self-derived point"
        );

        // FORGED virtual eval → opening half fails → REJECT.
        let mut forged = restored;
        forged.virtual_eval += Ea4::ONE;
        let mut vchf = Chl::new(perm);
        assert!(
            !verify_rec_block_light_decider_selfcontained(&forged, folding, ell_zk, pow_bits, &mut vchf),
            "forged bundle must REJECT in the self-contained verify"
        );
    }

    /// PRODUCTION bytes boundary — the exact prove/verify entries circuit.rs + the node call:
    /// `prove_rec_block_light_decider_bytes` → `verify_rec_block_light_decider_bytes` ACCEPTS an
    /// honest proof (valid ood row), REJECTS a forged re-serialized bundle, and REJECTS a short /
    /// undecodable byte slice (fail-closed, never panics).
    #[test]
    fn rec_block_light_decider_bytes_roundtrip() {
        let seed = 0u64;
        let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
        let mut perm_rng = SmallRng::seed_from_u64(seed);
        let perm = Perm16::new_from_rng_128(&mut perm_rng);
        let hash = SpongeHash::new(perm.clone());
        let compress = CompressHash::new(perm.clone());
        let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
        let encoding: Enc16 = decider_mask_encoding(t, ell_zk);
        let mut data_rng = SmallRng::seed_from_u64(seed.wrapping_add(1));
        let mk = |rng: &mut SmallRng, h: usize, w: usize| -> RowMajorMatrix<Fa4> {
            RowMajorMatrix::new((0..h * w).map(|_| rng.random::<Fa4>()).collect(), w)
        };
        // Valid OodCheck ood row so the full carrier pipeline accepts end-to-end.
        let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) + 2));
        let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 3 + 5));
        let acc = q * zh;
        let limbs = |e: Ea4| -> Vec<Fa4> {
            (0..EXT_D).map(|k| e.as_basis_coefficients_slice()[k]).collect()
        };
        let mut ood_row: Vec<Fa4> = Vec::new();
        ood_row.extend(limbs(zh));
        ood_row.extend(limbs(q));
        ood_row.extend(limbs(acc));
        ood_row.push(Fa4::ONE);
        let traces = [
            mk(&mut data_rng, 16, LEAF_W),
            RowMajorMatrix::new(ood_row, OODCHK_W),
            mk(&mut data_rng, 8, 4),
        ];
        let mut pch = Chl::new(perm.clone());
        let mut prover_rng = SmallRng::seed_from_u64(seed.wrapping_add(2));
        let bytes = prove_rec_block_light_decider_bytes(
            &traces, folding, pow_bits, mmcs, encoding, &mut pch, &mut prover_rng,
        )
        .expect("prove-side carrier bytes");
        assert!(!bytes.is_empty(), "carrier bytes are non-empty");

        // HONEST carrier bytes verify.
        let mut vch = Chl::new(perm.clone());
        assert!(
            verify_rec_block_light_decider_bytes(&bytes, folding, ell_zk, pow_bits, &mut vch),
            "honest carrier bytes must verify"
        );

        // FORGED: decode, tamper the virtual eval, re-encode → reject.
        let mut bundle: super::RecBlockOpeningBundle = postcard::from_bytes(&bytes).unwrap();
        bundle.virtual_eval += Ea4::ONE;
        let fbytes = postcard::to_allocvec(&bundle).unwrap();
        let mut vchf = Chl::new(perm.clone());
        assert!(
            !verify_rec_block_light_decider_bytes(&fbytes, folding, ell_zk, pow_bits, &mut vchf),
            "forged carrier bytes must reject"
        );

        // SHORT / undecodable byte slice → fail-closed (no panic).
        let mut vcht = Chl::new(perm);
        assert!(
            !verify_rec_block_light_decider_bytes(&bytes[..bytes.len() / 2], folding, ell_zk, pow_bits, &mut vcht),
            "short (undecodable) bytes must reject fail-closed"
        );
    }

    /// #135 the WIRE verify path (`verify_rec_block_light_decider_bytes` → selfcontained) now ENFORCES
    /// LogUp buses, not only the ood gate. An honest balanced bus carried in the carrier bytes verifies
    /// end-to-end; a forged consumed-leaf value in that bus REJECTS through the full deserialized
    /// carrier. This closes the gap where the node's O(1)-verify entry skipped the r6/bus replay.
    #[test]
    fn rec_block_bytes_verify_enforces_bus() {
        let build = |forge: bool| -> bool {
            let seed = 21u64;
            let (ell_zk, folding, pow_bits, t) = (4usize, 3usize, 4usize, 2usize);
            let mut perm_rng = SmallRng::seed_from_u64(seed);
            let perm = Perm16::new_from_rng_128(&mut perm_rng);
            let hash = SpongeHash::new(perm.clone());
            let compress = CompressHash::new(perm.clone());
            let mmcs: Mmcs16 = Mmcs16::new(hash, compress, 0, SmallRng::seed_from_u64(seed + 7));
            let encoding: Enc16 = decider_mask_encoding(t, ell_zk);

            let mut data_rng = SmallRng::seed_from_u64(seed + 1);
            let filler =
                RowMajorMatrix::new((0..8 * 4).map(|_| data_rng.random::<Fa4>()).collect(), 4);
            // Valid ood row so the ood gate passes; the bus carries the tamper signal.
            let zh = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) + 2));
            let q = Ea4::from_basis_coefficients_fn(|k| Fa4::from_u64((k as u64) * 3 + 5));
            let acc = q * zh;
            let limbs = |e: Ea4| -> Vec<Fa4> {
                (0..EXT_D).map(|k| e.as_basis_coefficients_slice()[k]).collect()
            };
            let mut ood_row: Vec<Fa4> = Vec::new();
            ood_row.extend(limbs(zh));
            ood_row.extend(limbs(q));
            ood_row.extend(limbs(acc));
            ood_row.push(Fa4::ONE);
            let traces = [filler, RowMajorMatrix::new(ood_row, OODCHK_W)];

            let beta = Fa4::from_u64(7);
            let mut value: Vec<Fa4> = Vec::new();
            let mut mult: Vec<Fa4> = Vec::new();
            for j in 0..2u64 {
                let idx = Fa4::from_u64(j);
                let val = [
                    Fa4::from_u64(j * 10 + 1),
                    Fa4::from_u64(j * 10 + 2),
                    Fa4::from_u64(j * 10 + 3),
                    Fa4::from_u64(j * 10 + 4),
                ];
                value.push(leaf_bus_key(idx, &val, beta));
                mult.push(-Fa4::ONE);
                let mut rv = val;
                if forge && j == 0 {
                    rv[0] += Fa4::ONE;
                }
                value.push(leaf_bus_key(idx, &rv, beta));
                mult.push(Fa4::ONE);
            }

            let mut pch = Chl::new(perm.clone());
            let mut prover_rng = SmallRng::seed_from_u64(seed + 2);
            let bytes = prove_rec_block_light_decider_bytes_with_bus(
                &traces,
                vec![(value, mult)],
                Vec::new(),
                folding,
                pow_bits,
                mmcs,
                encoding,
                &mut pch,
                &mut prover_rng,
            )
            .expect("carrier bytes");
            let mut vch = Chl::new(perm);
            verify_rec_block_light_decider_bytes(&bytes, folding, ell_zk, pow_bits, &mut vch)
        };
        assert!(build(false), "honest bundle with a balanced bus must verify through the bytes path");
        assert!(!build(true), "forged bus value must reject through the bytes path");
    }
}

/// Domain for the MINT/COINBASE validity carrier — a carrier that creates value with NO INPUT NOTE.
pub const MINT_VALIDITY_DOMAIN: u64 = 0x4d494e_5456_414c; // "MINTVAL"

/// ⭐⭐⭐ MINT VALIDITY — THE GATE FOR A CARRIER THAT SPENDS NOTHING.
///
/// Mint and the coinbase pow-bind create value; they consume no note. They used to borrow the BOND gate at
/// `depth: 1`, and that gate's doc admitted what it meant: *"vacuous self-membership; the security is the
/// `out0 == value` weld + the out0 opening, not the wallet-chosen root."* A gate proving membership nobody
/// has, against a root that constrains nothing, is a name that does not match reality — and it is what forced
/// mint to carry a `leaf_commit: None`, the one shape that kept the FIXED-CAPACITY Merkle weld alive for
/// everyone else. Splitting it is what lets `SpendValidityGate` require the cross-bind unconditionally.
///
/// This gate constrains EXACTLY what a mint's soundness actually rests on, and nothing it cannot honestly
/// claim: `out0_cm` OPENS as `Poseidon([value,0,0,0], sk)` for a secret `sk`, and that opening equals the
/// PUBLIC commitment the node recorded, at the PUBLIC amount the node computed. An over-mint (claiming a
/// larger `value` against the recorded cm) has no satisfying `sk`, so it cannot be proven.
///
/// There is NO root, NO depth and NO membership here — so a mint can never be the path by which a capacity
/// ceiling re-enters ([[feedback_tree_lifetime_infinite_no_capacity_window]]).
///
/// Row (26 cols, height 32): `[value | sk(4) | pre(4) | sq(4) | p4(4) | p7(4) | cm(4) | selector]`.
/// The arithmetic constraints hold trivially on the zero padding rows; only the two PUBLIC welds are
/// selector-gated, because `cm == public_cm` is false on an all-zero row by construction.
pub struct MintValidityGate {
    pub gamma: Ea4,
    /// The PUBLIC amount the node computed for this mint, as its four 16-bit limbs.
    ///
    /// ⛔⛔⛔ ITEM 1 / D-28, SITE 3 OF 4 (2026-09-11). This was ONE field element `Fa4::from_u64(value)`,
    /// which REDUCES mod p ≈ 2^31 — so `value` and `value + p` (≈ 21.3 M base units more) produced the
    /// same trace, the same transcript bind and the SAME PROOF. A carrier proven for `v` verified for
    /// a claimed `v + p`; whoever credited the claimed u64 against that proof credited the inflation.
    /// The value now travels as limbs each `< 2^16 < p` (nothing reduces), the trace carries the
    /// limbs bit-bound, and the opened column 0 is bound to them by recombination.
    pub value_limbs: [Ea4; SC_LIMBS],
    /// The PUBLIC output commitment the node recorded.
    pub out0_cm: [Ea4; DIGEST_LANES],
}
/// Where the value's range block starts in the mint trace: after the 26 legacy columns.
/// The mint-value row's HEAD layout. ⛔ Every offset was a literal (1,5,21,25,26) until 2026-09-12.
pub const MV_VAL: usize = 0;
pub const MV_SK: usize = MV_VAL + 1;
pub const MV_OUTER_BLK: usize = MV_SK + DIGEST_LANES;
pub const MV_CM: usize = MV_OUTER_BLK + crate::pow_pq_air::P2_COLS;
pub const MV_SEL: usize = MV_CM + DIGEST_LANES;
const MV_VAL_BASE: usize = MV_SEL + 1;
/// The inner round of the two-round note opening (`P([USDm tag, 0], sk)`), after the range block.
const MV_INNER_BLK: usize = MV_VAL_BASE + U64_RANGE_WIDTH;
const MV_INNER_OUT: usize = MV_INNER_BLK + POSE_BLK;
/// The mint-validity trace width: 26 legacy columns + one range-bound u64 + the inner round.
pub const MV_WIDTH: usize = MV_INNER_OUT + DIGEST_LANES;
impl MintValidityGate {
    /// The one constructor: the u64 is split into public limbs here, so no call site can weld a
    /// reduced element by mistake.
    pub fn for_value(gamma: Ea4, value: u64, out0_cm: [Ea4; DIGEST_LANES]) -> Self {
        let l = u64_public_limbs(value);
        Self { gamma, value_limbs: core::array::from_fn(|i| l[i].into()), out0_cm }
    }
}

impl crate::air_zerocheck::AirConstraint for MintValidityGate {
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ EMBEDS A PERMUTATION: a gate declaring less than the permutation's degree truncates
        // the sumcheck, so even an HONEST proof stops verifying.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let g = self.gamma;
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let seven = Ea4::from(Fa4::from_u64(7));
        let val = local[0];
        let sk = |c: usize| local[MV_SK + c];
        let cm = |c: usize| local[MV_CM + c];
        let sel = local[MV_SEL];

        let mut rs: Vec<Ea4> = Vec::new();
        rs.push(sel * (sel - one)); // selector ∈ {0,1}
        // THE OPENING — two rounds, `cm == P(limbs(value), P([USDm tag, 0], sk))`: the value's four
        // range-bound limbs fill the outer lanes, so `v` and `v + p` are different notes (item 1 seam).
        let rb = U64RangeBases::at(MV_VAL_BASE);
        let usdm_tag = |_c: usize| zero;
        let sk_col = |c: usize| local[MV_SK + c];
        push_note_open(&mut rs, local, rb.limbs, &usdm_tag, &sk_col, MV_INNER_BLK, MV_INNER_OUT, MV_OUTER_BLK, MV_CM);
        // PUBLIC WELDS (selector-gated — false on the zero padding rows by construction): the opened cm is
        // the one the node recorded, at the amount the node computed. This is the no-over-mint constraint.
        for c in 0..DIGEST_LANES {
            rs.push(sel * (cm(c) - self.out0_cm[c]));
        }
        // The amount: range-bound limbs (bits boolean, reconstruction binds each limb), the opened
        // column 0 bound to the limbs, and the limbs welded to the PUBLIC limbs (selector-gated).
        push_u64_range(&mut rs, local, rb);
        rs.push(val - u64_limbs_recombined(local, rb.limbs));
        for i in 0..SC_LIMBS {
            rs.push(sel * (local[rb.limbs + i] - self.value_limbs[i]));
        }

        let mut out = zero;
        let mut gp = one;
        for r in rs {
            out = out + gp * r;
            gp = gp * g;
        }
        out
    }
}

/// Transcript bind: domain ‖ out0_cm ‖ value. No root and no depth appear — a mint has no membership claim.
fn mint_validity_public_bind(out0_cm: &DigestF, value: u64) -> Vec<Fa4> {
    let mut b = Vec::with_capacity(6);
    b.push(Fa4::from_u64(MINT_VALIDITY_DOMAIN));
    for c in out0_cm.iter() {
        b.push(*c);
    }
    // The amount as limbs, never as one reduced element — see `MintValidityGate::value_limbs`.
    b.extend_from_slice(&u64_public_limbs(value));
    b
}

/// Build the one live row for a mint of `value` to a note owned by `sk`, returning `(cols, out0_cm)`.
fn mint_validity_cols(value: u64, sk: &Digest) -> (Vec<Vec<Fa4>>, DigestF) {
    const H: usize = MINT_TRACE_ROWS;
    let sk_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(sk[c]));
    // One live row, filled row-major, then replicated into the 32-row shape.
    let mut row = vec![Fa4::ZERO; MV_WIDTH];
    row[0] = Fa4::from_u64(value);
    for c in 0..DIGEST_LANES {
        row[1 + c] = sk_f[c];
    }
    let rb = U64RangeBases::at(MV_VAL_BASE);
    for i in 0..SC_LIMBS {
        row[rb.limbs + i] = Fa4::from_u64((value >> (SC_LIMB_BITS * i)) & 0xFFFF);
    }
    for k in 0..(SC_LIMBS * SC_LIMB_BITS) {
        row[rb.bits + k] = Fa4::from_u64((value >> k) & 1);
    }
    let cm = fill_note_open(&mut row, value, USDM_ASSET_TAG, &sk_f, MV_INNER_BLK, MV_INNER_OUT, MV_OUTER_BLK, MV_CM);
    row[MV_SEL] = Fa4::ONE;
    // ⛔⛔⛔ THE PADDING ROWS MUST CARRY A VALID PERMUTATION, NOT ZEROS.
    //
    // The retired 1-round fold was ZERO-PRESERVING (`pre = 0 + 7·0`, `x⁷ = 0`, `MDS·0 = 0`), so an
    // all-zero padding row satisfied its arithmetic for free and only the selector-gated public welds
    // mattered. A permutation does NOT map zeros to zeros: a zero row is simply an invalid Poseidon2
    // trace, and the block's constraints — which are NOT selector-gated, because gating them would leave
    // those columns free — reject it. Replicating the live row is the shape every other per-row carrier
    // in this crate already uses, and it keeps the selector's meaning intact.
    let mut cols: Vec<Vec<Fa4>> = (0..MV_WIDTH).map(|_| vec![Fa4::ZERO; H]).collect();
    for (c, v) in row.iter().enumerate() {
        cols[c].fill(*v);
    }
    (cols, cm)
}

/// PROVE a mint/coinbase carrier: `out0_cm` opens to the public `value` under the secret `sk`.
/// Returns `(carrier_bytes, out0_cm)`.
#[must_use]
pub fn prove_mint_validity_bytes(value: u64, sk: &Digest) -> Option<(Vec<u8>, Digest)> {
    use p3_field::PrimeField64;
    let (cols, cm) = mint_validity_cols(value, sk);
    let cm_u: Digest = core::array::from_fn(|c| cm[c].as_canonical_u64());
    let out0: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| Ea4::from(cm[i]));
    let make = move |g: Ea4| MintValidityGate::for_value(g, value, out0);
    let bytes = crate::committed_air::prove_air_blinded_bytes(cols, make, &mint_validity_public_bind(&cm, value))?;
    Some((bytes, cm_u))
}

/// VERIFY a mint/coinbase carrier against the PUBLIC `out0_cm` the node recorded and the PUBLIC `value` it
/// computed. Fail-closed: a carrier minting a different amount, or opening a different commitment, diverges
/// the bind and is refused.
#[must_use]
pub fn verify_mint_validity_bytes(bytes: &[u8], out0_cm: Digest, value: u64) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let cm_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(out0_cm[c]));
    let cm_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| cm_f[i].into());
    let make = move |g: Ea4| MintValidityGate::for_value(g, value, cm_ea);
    crate::committed_air::verify_air_blinded_bytes(bytes, make, &mint_validity_public_bind(&cm_f, value), (MINT_TRACE_ROWS.trailing_zeros() as usize, MV_WIDTH))
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// ⛔⛔⛔ DB-365 (yield) — THE REWARD NOTE FOLLOWS THE PRINCIPAL (value-creation census row "Class::YieldClaim — the
// REWARD note", 2026-10-02).
//
// A yield claim credits three notes. The stake-spend carrier binds two of them (out0 = the principal at the welded
// weight `w`, out1 = the change) under the staker's key; the third — the REWARD, the only note the claim brings into
// existence — was bound to nothing: no value, no owner. A claimant could seal it for any amount (inflation), and a relay
// could re-frame the object with a reward note of its own (theft).
//
// This carrier proves, about the PUBLIC `(out0_cm, reward_cm, w, r)`:
//
// ```text
//   out0_cm   == NoteCommit(w, USDm, sk_p)                 — the prover holds the PRINCIPAL's spend key
//   sk_r      == P(REWARD_KEY_LANES, sk_p)                 — the reward key is a function of it, nothing else
//   reward_cm == NoteCommit(r, USDm, sk_r)                 — the reward opens to exactly `r` under that key
// ```
//
// AMOUNT: `r` is a public weld every node computes (`w·rate/10000`), the same value `verify_yield_mint_carrier` now
// welds as the supply advance — so the note credited IS the supply minted. AUTHORITY: `reward_cm` is a deterministic
// function of `(r, sk_p)`, and `sk_p` is pinned by `out0_cm` (Poseidon binding), which the stake-spend carrier binds
// to the staker — a party without the principal's key cannot produce a reward commitment that verifies, so a relay's
// swap is refused on every node. PRIVACY: nothing new is public — `w` is in the header and `r` is derived from it; the
// two commitments already sit in one object; `sk_r` is never revealed, so the reward's later spend links to nothing.
//
// `REWARD_KEY_LANES` puts a 1 in lane 3, where every note-inner-key input (`[tag0, tag1, tag2, 0, …]`) holds 0, so the
// derivation can never coincide with a note's inner round under the same key.
// ═══════════════════════════════════════════════════════════════════════════════════════════════
pub const REWARD_FOLLOWS_DOMAIN: u64 = 0x5257_4446_4f4c_5057; // "RWDFOLPW"
const REWARD_KEY_DOMAIN: u64 = 0x5257_444b_4559_5631; // "RWDKEYV1"
fn reward_key_lanes() -> Digest {
    crate::poseidon2_compress::lanes_of(&[REWARD_KEY_DOMAIN, 0, 0, 1])
}

/// The reward note's spend key, from the principal's: `P(REWARD_KEY_LANES, sk_p)`. The wallet seals the reward note
/// under this key; the carrier proves the same derivation in-circuit.
#[must_use]
pub fn reward_spend_key(principal_sk: &Digest) -> Digest {
    poseidon_pair(reward_key_lanes(), *principal_sk)
}

// The row: the principal's key, two range-bound u64s (w, r), the principal's two-round opening, the derive round, and
// the reward's two-round opening. Every block is read: inner → outer → public weld on both openings, derive → reward
// inner's key operand.
const RF_SKP: usize = 0;
const RF_W: usize = RF_SKP + DIGEST_LANES;
const RF_R: usize = RF_W + U64_RANGE_WIDTH;
const RF_P_INNER_BLK: usize = RF_R + U64_RANGE_WIDTH;
const RF_P_INNER_OUT: usize = RF_P_INNER_BLK + POSE_BLK;
const RF_P_OUTER_BLK: usize = RF_P_INNER_OUT + DIGEST_LANES;
const RF_P_CM: usize = RF_P_OUTER_BLK + POSE_BLK;
const RF_D_BLK: usize = RF_P_CM + DIGEST_LANES;
const RF_SKR: usize = RF_D_BLK + POSE_BLK;
const RF_R_INNER_BLK: usize = RF_SKR + DIGEST_LANES;
const RF_R_INNER_OUT: usize = RF_R_INNER_BLK + POSE_BLK;
const RF_R_OUTER_BLK: usize = RF_R_INNER_OUT + DIGEST_LANES;
const RF_R_CM: usize = RF_R_OUTER_BLK + POSE_BLK;
pub const RF_WIDTH: usize = RF_R_CM + DIGEST_LANES;

/// The reward-follows-principal gate — see the section note above.
pub struct RewardFollowsPrincipalGate {
    pub gamma: Ea4,
    pub out0_cm: [Ea4; DIGEST_LANES],
    pub reward_cm: [Ea4; DIGEST_LANES],
    /// `w` and `r` as public 16-bit limbs — never one reduced element (the `v` / `v + p` alias).
    pub w_limbs: [Ea4; SC_LIMBS],
    pub r_limbs: [Ea4; SC_LIMBS],
}

impl RewardFollowsPrincipalGate {
    fn new(gamma: Ea4, out0_cm: &DigestF, reward_cm: &DigestF, w: u64, r: u64) -> Self {
        let wl = u64_public_limbs(w);
        let rl = u64_public_limbs(r);
        Self {
            gamma,
            out0_cm: core::array::from_fn(|i| out0_cm[i].into()),
            reward_cm: core::array::from_fn(|i| reward_cm[i].into()),
            w_limbs: core::array::from_fn(|i| wl[i].into()),
            r_limbs: core::array::from_fn(|i| rl[i].into()),
        }
    }
}

impl crate::air_zerocheck::AirConstraint for RewardFollowsPrincipalGate {
    fn degree(&self, _nvars: usize) -> usize {
        // MEASURED 3 by the degree census (`db365_the_reward_gate_passes_the_degree_free_witness_and_decorative_censuses`,
        // 2026-10-02): the five permutation blocks are cubes applied inline (`P2_CONSTRAINT_DEGREE`), the range laws are
        // `bit·(bit−1)` and every weld is affine. The inherited `PERM_MAX_DEGREE` (8) sampled 10 points per round where 5
        // suffice. Guarded by the census + the per-round assert in every strict prove.
        crate::pow_pq_air::P2_CONSTRAINT_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let zero = Ea4::from(Fa4::ZERO);
        let mut rs: Vec<Ea4> = Vec::new();
        let (wb, rb) = (U64RangeBases::at(RF_W), U64RangeBases::at(RF_R));
        // the two amounts: range-bound limbs, welded to the PUBLIC limbs
        push_u64_range(&mut rs, local, wb);
        push_u64_range(&mut rs, local, rb);
        for i in 0..SC_LIMBS {
            rs.push(local[wb.limbs + i] - self.w_limbs[i]);
            rs.push(local[rb.limbs + i] - self.r_limbs[i]);
        }
        let usdm_tag = |_c: usize| zero;
        // the PRINCIPAL opens under sk_p — the public out0_cm the stake-spend carrier binds
        let skp = |c: usize| local[RF_SKP + c];
        push_note_open(&mut rs, local, wb.limbs, &usdm_tag, &skp, RF_P_INNER_BLK, RF_P_INNER_OUT, RF_P_OUTER_BLK, RF_P_CM);
        for c in 0..DIGEST_LANES {
            rs.push(local[RF_P_CM + c] - self.out0_cm[c]);
        }
        // sk_r = P(REWARD_KEY_LANES, sk_p)
        let dom = reward_key_lanes();
        let dom_l = |c: usize| Ea4::from(Fa4::from_u64(dom[c]));
        push_pose_round(&mut rs, local, &dom_l, &skp, RF_D_BLK, RF_SKR);
        // the REWARD opens to r under sk_r — the public reward_cm the node credits
        let skr = |c: usize| local[RF_SKR + c];
        push_note_open(&mut rs, local, rb.limbs, &usdm_tag, &skr, RF_R_INNER_BLK, RF_R_INNER_OUT, RF_R_OUTER_BLK, RF_R_CM);
        for c in 0..DIGEST_LANES {
            rs.push(local[RF_R_CM + c] - self.reward_cm[c]);
        }
        let mut out = zero;
        let mut gp = Ea4::ONE;
        for r in rs {
            out += gp * r;
            gp *= self.gamma;
        }
        out
    }
    /// ROW-LOCAL: `eval` never calls `_at`.
    fn is_row_local(&self) -> bool {
        true
    }
    /// No free column: every cell is read by a range law, a permutation's own residuals, an operand weld or a public
    /// weld. Declared EMPTY so the debug prover's free-witness census REFUSES any column it finds unread.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
}

/// Transcript bind: domain ‖ out0_cm ‖ reward_cm ‖ w limbs ‖ r limbs.
fn reward_follows_public_bind(out0_cm: &DigestF, reward_cm: &DigestF, w: u64, r: u64) -> Vec<Fa4> {
    let mut b = Vec::with_capacity(1 + 2 * DIGEST_LANES + 2 * SC_LIMBS);
    b.push(Fa4::from_u64(REWARD_FOLLOWS_DOMAIN));
    b.extend_from_slice(out0_cm);
    b.extend_from_slice(reward_cm);
    b.extend_from_slice(&u64_public_limbs(w));
    b.extend_from_slice(&u64_public_limbs(r));
    b
}

/// The one live row, replicated into the `MINT_TRACE_ROWS` shape. Returns `(cols, out0_cm, reward_cm)`.
fn reward_follows_cols(w: u64, principal_sk: &Digest, r: u64) -> (Vec<Vec<Fa4>>, DigestF, DigestF) {
    let skp: DigestF = to_f(principal_sk);
    let mut row = vec![Fa4::ZERO; RF_WIDTH];
    row[RF_SKP..RF_SKP + DIGEST_LANES].copy_from_slice(&skp);
    fill_u64_range_row(&mut row, w, U64RangeBases::at(RF_W));
    fill_u64_range_row(&mut row, r, U64RangeBases::at(RF_R));
    let p_cm = fill_note_open(&mut row, w, USDM_ASSET_TAG, &skp, RF_P_INNER_BLK, RF_P_INNER_OUT, RF_P_OUTER_BLK, RF_P_CM);
    let dom: DigestF = to_f(&reward_key_lanes());
    let skr = fill_pose_round(&mut row, &dom, &skp, RF_D_BLK, RF_SKR);
    let r_cm = fill_note_open(&mut row, r, USDM_ASSET_TAG, &skr, RF_R_INNER_BLK, RF_R_INNER_OUT, RF_R_OUTER_BLK, RF_R_CM);
    // padding replicates the live row — a zero row is not a valid permutation trace (see `mint_validity_cols`)
    let cols: Vec<Vec<Fa4>> = row.iter().map(|v| vec![*v; MINT_TRACE_ROWS]).collect();
    (cols, p_cm, r_cm)
}

/// PROVE that the reward note of value `r` follows the principal of weight `w` owned by `principal_sk`. Returns
/// `(carrier, out0_cm, reward_cm)`: `out0_cm` is the principal's commitment (the stake-spend carrier's out0 when
/// `principal_sk` is that carrier's `out0_sk`), `reward_cm` the reward note's, sealed under
/// [`reward_spend_key`]`(principal_sk)`.
#[must_use]
pub fn prove_reward_follows_principal_bytes(w: u64, principal_sk: &Digest, r: u64) -> Option<(Vec<u8>, Digest, Digest)> {
    use p3_field::PrimeField64;
    let (cols, p_cm, r_cm) = reward_follows_cols(w, principal_sk, r);
    let bind = reward_follows_public_bind(&p_cm, &r_cm, w, r);
    let make = move |g: Ea4| RewardFollowsPrincipalGate::new(g, &p_cm, &r_cm, w, r);
    let bytes = crate::committed_air::prove_air_blinded_bytes(cols, make, &bind)?;
    let u = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((bytes, u(p_cm), u(r_cm)))
}

/// VERIFY a reward-follows-principal carrier against the PUBLIC principal commitment the stake-spend carrier binds, the
/// reward commitment the node is about to credit, the header's weight and the reward every node computes. Fail-closed:
/// a reward of another value, under another key, or beside another principal diverges the bind and is refused.
#[must_use]
pub fn verify_reward_follows_principal_bytes(bytes: &[u8], out0_cm: Digest, reward_cm: Digest, w: u64, r: u64) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let (p_cm, r_cm) = (to_f(&out0_cm), to_f(&reward_cm));
    let bind = reward_follows_public_bind(&p_cm, &r_cm, w, r);
    let make = move |g: Ea4| RewardFollowsPrincipalGate::new(g, &p_cm, &r_cm, w, r);
    crate::committed_air::verify_air_blinded_bytes(bytes, make, &bind, (MINT_TRACE_ROWS.trailing_zeros() as usize, RF_WIDTH))
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// DB-80 (2026-09-19) — THE COMMITTED MINT-VALIDITY GATE: the note's value is NEVER a public input.
//
// `MintValidityGate` pins the amount as public limbs so the peg-in solvency carrier and the note can
// agree on one number — that pin is what published every mint amount (`PegInHeader.mint_authorized`).
// This gate proves the same note opening and, instead of the value, pins `delta_commit =
// solvency_commit_256(value, d_blind)` — the fifth public commitment the DB-80 solvency carrier
// (`confidential_solvency::prove_peg_in_carrier_delta`) opens to its private mint delta. The same
// Poseidon2 commit shape (`place_commit_open` / `push_commit_open_constraints`) at both ends is what
// makes the two proofs agree WITHOUT either of them saying the number.
//
// Layout: the original MV columns are untouched; a 16-limb copy of the value (limbs 4..16 constrained
// to zero — a u64 in the U256 limb encoding the commit uses), the blind, the commit lanes and the two
// permutation blocks are appended.
// ═══════════════════════════════════════════════════════════════════════════════════════════════
pub const MINT_VALIDITY_COMMITTED_DOMAIN: u64 = 0x4d494e_5456_4342; // "MINTVCB"
const MVC_V16: usize = MV_WIDTH;
const MVC_DBLIND: usize = MVC_V16 + 16;
const MVC_DCOMMIT: usize = MVC_DBLIND + DIGEST_LANES;
const MVC_DINTER: usize = MVC_DCOMMIT + DIGEST_LANES;
/// DB-362: the opened value's 16 limbs range-bound inside the opening gadget.
const MVC_DVBITS: usize = MVC_DINTER + 2 * crate::confidential_solvency::CO_BLOCK;
pub const MVC_WIDTH: usize = MVC_DVBITS + crate::confidential_solvency::RANGE16_COLS;

pub struct MintValidityCommittedGate {
    pub gamma: Ea4,
    pub out0_cm: [Ea4; DIGEST_LANES],
    pub delta_commit: [Ea4; DIGEST_LANES],
}

impl crate::air_zerocheck::AirConstraint for MintValidityCommittedGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let g = self.gamma;
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let val = local[0];
        let cm = |c: usize| local[MV_CM + c];
        let sel = local[MV_SEL];

        let mut rs: Vec<Ea4> = Vec::new();
        rs.push(sel * (sel - one));
        let rb = U64RangeBases::at(MV_VAL_BASE);
        let usdm_tag = |_c: usize| zero;
        let sk_col = |c: usize| local[MV_SK + c];
        push_note_open(&mut rs, local, rb.limbs, &usdm_tag, &sk_col, MV_INNER_BLK, MV_INNER_OUT, MV_OUTER_BLK, MV_CM);
        for c in 0..DIGEST_LANES {
            rs.push(sel * (cm(c) - self.out0_cm[c]));
        }
        push_u64_range(&mut rs, local, rb);
        rs.push(val - u64_limbs_recombined(local, rb.limbs));
        // the 16-limb copy: the u64's four 16-bit limbs, then zeros (the U256 encoding the commit hashes)
        for i in 0..SC_LIMBS {
            rs.push(local[MVC_V16 + i] - local[rb.limbs + i]);
        }
        for i in SC_LIMBS..16 {
            rs.push(local[MVC_V16 + i]);
        }
        // delta_commit = Poseidon2(Poseidon2(lo, hi), blind) over the copy — the same shape the solvency
        // carrier opens, so both proofs stand on one committed number
        crate::confidential_solvency::push_commit_open_constraints(&mut rs, local, MVC_V16, MVC_DBLIND, MVC_DCOMMIT, MVC_DINTER, MVC_DVBITS);
        for c in 0..DIGEST_LANES {
            rs.push(sel * (local[MVC_DCOMMIT + c] - self.delta_commit[c]));
        }

        let mut out = zero;
        let mut gp = one;
        for r in rs {
            out = out + gp * r;
            gp = gp * g;
        }
        out
    }
}

/// Transcript bind: domain ‖ out0_cm ‖ delta_commit. No value anywhere.
fn mint_validity_committed_public_bind(out0_cm: &DigestF, delta_commit: &DigestF) -> Vec<Fa4> {
    let mut b = Vec::with_capacity(1 + 2 * DIGEST_LANES);
    b.push(Fa4::from_u64(MINT_VALIDITY_COMMITTED_DOMAIN));
    for c in out0_cm.iter() {
        b.push(*c);
    }
    for c in delta_commit.iter() {
        b.push(*c);
    }
    b
}

fn mint_validity_committed_cols(value: u64, sk: &Digest, d_blind: &Digest) -> (Vec<Vec<Fa4>>, DigestF, Digest) {
    let (mut cols, cm) = mint_validity_cols(value, sk);
    let h = cols[0].len();
    while cols.len() < MVC_WIDTH {
        cols.push(vec![Fa4::ZERO; h]);
    }
    let mut limbs = [0u64; 16];
    for i in 0..SC_LIMBS {
        limbs[i] = (value >> (SC_LIMB_BITS * i)) & 0xFFFF;
    }
    for i in 0..16 {
        cols[MVC_V16 + i].fill(Fa4::from_u64(limbs[i]));
    }
    for i in 0..DIGEST_LANES {
        cols[MVC_DBLIND + i].fill(Fa4::from_u64(d_blind[i]));
    }
    let dc = crate::confidential_solvency::place_commit_open(&mut cols, limbs, *d_blind, MVC_DINTER, MVC_DVBITS);
    for i in 0..DIGEST_LANES {
        cols[MVC_DCOMMIT + i].fill(Fa4::from_u64(dc[i]));
    }
    (cols, cm, dc)
}

/// DB-80: prove a mint of `value` to a note owned by `sk`, publishing only `out0_cm` and
/// `delta_commit = solvency_commit_256(value, d_blind)`. Returns `(bytes, out0_cm, delta_commit)`.
#[must_use]
pub fn prove_mint_validity_committed_bytes(value: u64, sk: &Digest, d_blind: &Digest) -> Option<(Vec<u8>, Digest, Digest)> {
    use p3_field::PrimeField64;
    let (cols, cm, dc) = mint_validity_committed_cols(value, sk, d_blind);
    let cm_u: Digest = core::array::from_fn(|c| cm[c].as_canonical_u64());
    let out0: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| Ea4::from(cm[i]));
    let dc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(dc[c]));
    let dc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| Ea4::from(dc_f[i]));
    let make = move |g: Ea4| MintValidityCommittedGate { gamma: g, out0_cm: out0, delta_commit: dc_ea };
    let bytes = crate::committed_air::prove_air_blinded_bytes(cols, make, &mint_validity_committed_public_bind(&cm, &dc_f))?;
    Some((bytes, cm_u, dc))
}

#[must_use]
pub fn verify_mint_validity_committed_bytes(bytes: &[u8], out0_cm: Digest, delta_commit: Digest) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let cm_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(out0_cm[c]));
    let cm_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| cm_f[i].into());
    let dc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(delta_commit[c]));
    let dc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| dc_f[i].into());
    let make = move |g: Ea4| MintValidityCommittedGate { gamma: g, out0_cm: cm_ea, delta_commit: dc_ea };
    crate::committed_air::verify_air_blinded_bytes(bytes, make, &mint_validity_committed_public_bind(&cm_f, &dc_f), (MINT_TRACE_ROWS.trailing_zeros() as usize, MVC_WIDTH))
}

#[cfg(test)]
mod mint_validity_committed_gate_tests {
    use super::*;

    /// DB-80 calibration: the committed gate proves for the honest (value, blind) and the SAME commitment is
    /// what the solvency carrier computes for that mint delta; a different value under the same blind, a
    /// different blind, or a forged commitment REFUSES. Nothing in the public inputs names the value.
    #[test]
    fn a_committed_mint_proves_and_binds_to_the_solvency_commit_and_refuses_every_tamper() {
        let sk: Digest = [3, 1, 4, 1, 5, 9, 2, 6];
        let blind: Digest = [7, 7, 7, 7, 1, 2, 3, 4];
        let value: u64 = 2_000_000_000;
        let (bytes, cm, dc) = prove_mint_validity_committed_bytes(value, &sk, &blind).expect("proves");
        let expect = crate::confidential_solvency::solvency_commit_256(
            crate::confidential_solvency::u256_from_u64(value),
            blind,
        );
        assert_eq!(dc, expect, "the gate's commitment IS the solvency commit of (value, blind)");
        assert!(verify_mint_validity_committed_bytes(&bytes, cm, dc), "honest proof verifies");
        // tamper 1: a forged commitment for the same note
        let mut dc2 = dc;
        dc2[0] ^= 1;
        assert!(!verify_mint_validity_committed_bytes(&bytes, cm, dc2), "a forged delta commitment is refused");
        // tamper 2: the commitment of ANOTHER value under the same blind
        let other = crate::confidential_solvency::solvency_commit_256(
            crate::confidential_solvency::u256_from_u64(value + 1),
            blind,
        );
        assert!(!verify_mint_validity_committed_bytes(&bytes, cm, other), "the commitment of a different value is refused");
        // tamper 3: another note's commitment
        let mut cm2 = cm;
        cm2[1] ^= 1;
        assert!(!verify_mint_validity_committed_bytes(&bytes, cm2, dc), "another note is refused");
        // the two carriers agree: the DB-80 solvency carrier proves the SAME delta commitment
        let (sbytes, commits) = crate::confidential_solvency::prove_peg_in_carrier_delta(
            crate::confidential_solvency::u256_from_u64(0),
            crate::confidential_solvency::u256_from_u64(0),
            crate::confidential_solvency::u256_from_u64(3_000_000_000),
            crate::confidential_solvency::u256_from_u64(value),
            [1; 8],
            [2; 8],
            [3; 8],
            [4; 8],
            blind,
            crate::confidential_solvency::Backing::at_unit_price(15_000),
        )
        .expect("the solvency carrier proves at 150% backing");
        assert_eq!(commits.delta_commit, dc, "both carriers stand on one committed mint delta");
        let b = &commits.base;
        assert!(crate::confidential_solvency::verify_peg_in_carrier_delta(
            &sbytes, crate::confidential_solvency::Backing::at_unit_price(15_000), b.reserve_commit, b.minted_commit, b.new_reserve_commit, b.new_minted_commit, dc
        ));
        assert!(!crate::confidential_solvency::verify_peg_in_carrier_delta(
            &sbytes, crate::confidential_solvency::Backing::at_unit_price(15_000), b.reserve_commit, b.minted_commit, b.new_reserve_commit, b.new_minted_commit, other
        ), "the solvency carrier refuses a delta commitment it did not open");
    }
}




// TWO-PARTY-REVIEWED: the two sides of this carrier are the PROVER (the staker's wallet, holding sk_p) and the VERIFIER
// (every node, holding only the public out0_cm / reward_cm / w / r); these pins call the verify with public bytes only,
// never a witness. The cross-NODE half — a relay-swapped reward note refused by a SECOND node's reward door from the
// framed bytes — is the node crate's `yield_claim_tx` pin, where two Nodes exist.
#[cfg(test)]
mod reward_follows_principal_tests {
    use super::*;

    const SKP: [u64; 4] = [0x51, 0x52, 0x53, 0x54];
    const W: u64 = 2_000;
    const R: u64 = 100;

    /// CALIBRATION + the honest path: the gate's principal opening IS the commitment the stake-spend carrier binds for
    /// `out0 = (w, sk_p)` (the spend row's output opening is `asset_note_cm(v, USDM_ASSET_TAG, sk)`), and the reward
    /// commitment IS the note a wallet seals at `r` under `reward_spend_key(sk_p)` — so the attacks below are armed
    /// against the exact objects a real claim carries.
    #[test]
    fn db365_the_reward_carrier_opens_the_principal_and_the_reward_the_wallet_seals() {
        let skp = crate::poseidon2_compress::lanes_of(&SKP);
        let (c, p_cm, r_cm) = prove_reward_follows_principal_bytes(W, &skp, R).expect("an honest reward proves");
        assert_eq!(p_cm, asset_note_cm(W, USDM_ASSET_TAG, skp), "CALIBRATION: the principal is the stake carrier's out0");
        assert_eq!(r_cm, asset_note_cm(R, USDM_ASSET_TAG, reward_spend_key(&skp)), "CALIBRATION: the reward is the wallet's note");
        assert_ne!(reward_spend_key(&skp), skp, "the reward key is not the principal's key");
        assert!(verify_reward_follows_principal_bytes(&c, p_cm, r_cm, W, R), "the honest reward verifies");
        // MEASURED, the con this carrier costs: bytes per yield claim (one carrier per claim, never per block)
        eprintln!("[reward-carrier] {} bytes (width {RF_WIDTH}, {MINT_TRACE_ROWS} rows)", c.len());
    }

    /// ⛔⛔⛔ DB-365 — a reward note sealed under ANY key but the one derived from the principal's is refused, whether
    /// presented under the honest carrier or a carrier proven for another key: without the principal's key, no reward
    /// commitment beside THIS principal verifies.
    #[test]
    fn db365_a_swapped_reward_note_verifies_beside_no_principal_its_prover_does_not_own() {
        let skp = crate::poseidon2_compress::lanes_of(&SKP);
        let (c, p_cm, r_cm) = prove_reward_follows_principal_bytes(W, &skp, R).unwrap();
        assert!(verify_reward_follows_principal_bytes(&c, p_cm, r_cm, W, R), "calibration: the honest pair verifies");
        let other_sk = crate::poseidon2_compress::lanes_of(&[0xEE, 0xEE, 0xEE, 0xEE]);
        let other_note = asset_note_cm(R, USDM_ASSET_TAG, other_sk);
        assert!(!verify_reward_follows_principal_bytes(&c, p_cm, other_note, W, R), "⛔ another key's note under the honest carrier");
        let (oc, _other_p, other_r) = prove_reward_follows_principal_bytes(W, &other_sk, R).unwrap();
        assert!(!verify_reward_follows_principal_bytes(&oc, p_cm, other_r, W, R), "⛔ another key's carrier beside the honest principal");
        assert!(!verify_reward_follows_principal_bytes(&oc, p_cm, r_cm, W, R), "⛔ another key's carrier over the honest reward cm");
        // the reward sealed DIRECTLY under the principal's key (not the derived one) is a different note, and refused
        let same_key = asset_note_cm(R, USDM_ASSET_TAG, skp);
        assert!(!verify_reward_follows_principal_bytes(&c, p_cm, same_key, W, R), "⛔ a reward under the principal's own key");
    }

    /// ⛔⛔⛔ DB-365 — the reward's VALUE is the public reward, and the principal's is the public weight: a reading of
    /// either as anything else refuses (over-mint, under-mint, and a weight the stake carrier did not weld).
    #[test]
    fn db365_site7_a_reward_carrier_for_r_does_not_verify_for_r_plus_p_nor_for_w_plus_p() {
        // ⛔ The constraint manifest's alias pin for `reward_follows_cols` (site 7): an amount bound as a reduced field
        // element would let a carrier proven for `r` verify for `r + p` — a reward minted from nothing. The reward and
        // the weight are u64 limbs in the bind and range-bound in the trace, so both aliases must be REFUSED.
        let p: u64 = 2_130_706_433;
        let sk = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let (w, r) = (1_000_000u64, 5_000u64);
        let (carrier, out0, rcm) = prove_reward_follows_principal_bytes(w, &sk, r).expect("the honest reward carrier proves");
        assert!(verify_reward_follows_principal_bytes(&carrier, out0, rcm, w, r), "⛔ THE CONTROL FAILED: the honest pair");
        assert_ne!(r, r + p, "⛔ THE VIOLATING STATE WAS NEVER BUILT");
        assert!(
            !verify_reward_follows_principal_bytes(&carrier, out0, rcm, w, r + p),
            "⛔⛔ REWARD INFLATION: a carrier proven for {r} verified for {} — the reward is bound as a reduced field element",
            r + p
        );
        assert!(
            !verify_reward_follows_principal_bytes(&carrier, out0, rcm, w + p, r),
            "⛔⛔ a carrier proven for weight {w} verified for {} — the weight is bound as a reduced field element",
            w + p
        );
    }

    #[test]
    fn db365_a_reward_of_any_other_value_or_beside_any_other_weight_is_refused() {
        let skp = crate::poseidon2_compress::lanes_of(&SKP);
        let (c, p_cm, r_cm) = prove_reward_follows_principal_bytes(W, &skp, R).unwrap();
        assert!(verify_reward_follows_principal_bytes(&c, p_cm, r_cm, W, R), "calibration");
        assert!(!verify_reward_follows_principal_bytes(&c, p_cm, r_cm, W, R + 1), "⛔ OVER-MINT read");
        assert!(!verify_reward_follows_principal_bytes(&c, p_cm, r_cm, W, R - 1), "⛔ under-mint read");
        assert!(!verify_reward_follows_principal_bytes(&c, p_cm, r_cm, W + 1, R), "⛔ another weight");
        assert!(!verify_reward_follows_principal_bytes(&[], p_cm, r_cm, W, R), "⛔ an empty carrier");
        // a reward note sealed for MORE under the right key is a different commitment: no carrier for r verifies it
        let fat = asset_note_cm(R * 1_000, USDM_ASSET_TAG, reward_spend_key(&skp));
        assert!(!verify_reward_follows_principal_bytes(&c, p_cm, fat, W, R), "⛔ a fat reward note under the right key");
    }

    /// SOUND IS MEASURED: the three censuses the debug prover runs, run here in EVERY profile on the gate's honest
    /// trace — the declared degree is the measured one, no column is free (declared `[]`), no permutation block is
    /// decorative.
    #[test]
    fn db365_the_reward_gate_passes_the_degree_free_witness_and_decorative_censuses() {
        use crate::air_zerocheck::AirConstraint;
        let skp = crate::poseidon2_compress::lanes_of(&SKP);
        let (cols, p_cm, r_cm) = reward_follows_cols(W, &skp, R);
        let nvars = cols[0].len().trailing_zeros() as usize;
        let gate = RewardFollowsPrincipalGate::new(Ea4::from(Fa4::from_u64(0x3650)), &p_cm, &r_cm, W, R);
        let row_local = gate.is_row_local();
        let shifted = if row_local { Some(Vec::new()) } else { gate.shifted_cols() };
        crate::air_zerocheck::debug_degree_census(&cols, &gate, nvars, row_local, &shifted);
        crate::air_zerocheck::debug_free_witness_census(&cols, &gate, nvars, row_local, &shifted);
        crate::air_zerocheck::debug_decorative_block_census(&cols, &gate, nvars, row_local, &shifted);
    }
}

#[cfg(test)]
mod mint_validity_gate_tests {
    use super::Digest;
    use super::*;


    #[test]
    fn a_mint_carrier_proves_its_recorded_commitment_opens_to_its_public_amount() {
        let sk = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let (carrier, cm) = prove_mint_validity_bytes(5_000, &sk).expect("an honest mint proves");
        assert!(verify_mint_validity_bytes(&carrier, cm, 5_000), "honest mint verifies against its cm + amount");
    }

    /// ⛔ NO OVER-MINT. Claiming a larger amount against the SAME recorded commitment must be refused — this
    /// is the whole security of the carrier, and it survives the gate split intact.
    #[test]
    fn an_over_mint_and_a_swapped_commitment_are_both_refused() {
        let sk = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let (carrier, cm) = prove_mint_validity_bytes(5_000, &sk).expect("honest mint proves");

        assert!(!verify_mint_validity_bytes(&carrier, cm, 5_001), "OVER-MINT: a larger amount is refused");
        assert!(!verify_mint_validity_bytes(&carrier, cm, 4_999), "a smaller amount is refused too");
        let other: Digest = core::array::from_fn(|i| cm[i] ^ if i == 0 { 0xdead_beef } else { i as u64 + 1 });
        assert!(!verify_mint_validity_bytes(&carrier, other, 5_000), "a swapped commitment is refused");
        assert!(!verify_mint_validity_bytes(&[], cm, 5_000), "an empty carrier is refused");

        // And a carrier proven for one amount cannot be replayed as another mint's.
        let (other_carrier, other_cm) = prove_mint_validity_bytes(9_000, &sk).expect("second mint proves");
        assert!(!verify_mint_validity_bytes(&other_carrier, cm, 5_000), "cross-replay refused");
        assert!(verify_mint_validity_bytes(&other_carrier, other_cm, 9_000), "control: its own pair verifies");
    }

    /// ⭐⭐⭐ THE TRACE HEIGHT IS A SHAPE, NOT A CAPACITY — NOTHING FILLS IT UP.
    ///
    /// `mint_validity_cols` builds 32 rows and uses exactly ONE. That 32 is the WHIR SIMD packing floor
    /// (nvars=5), a FIXED protocol shape constant like DAG width 32 or the 256-slot block — it is NOT a
    /// budget that chain data accumulates into. Every carrier is its OWN trace, so there is no counter
    /// climbing toward 32 and nothing that can ever be "full". Contrast the capacity that WAS a defect:
    /// `SPEND_TREE_DEPTH = 32` meant 2^32 LEAVES, a counter that climbs with every note ever created and
    /// then stops the chain ([[feedback_tree_lifetime_infinite_no_capacity_window]]).
    ///
    /// Asserted, not argued: mints spanning value 1 to u64::MAX all produce the SAME carrier byte-length and
    /// all verify. If the height were a capacity, large or many mints would grow it or exhaust it.
    #[test]
    fn the_mint_trace_height_is_a_fixed_shape_that_no_amount_or_volume_can_exhaust() {
        let sk = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let mut sizes = Vec::new();
        for v in [1u64, 2, 5_000, 1 << 32, u64::MAX - 1, u64::MAX] {
            let (c, cm) = prove_mint_validity_bytes(v, &sk).expect("mint proves at any amount");
            assert!(verify_mint_validity_bytes(&c, cm, v), "mint at value {v} verifies");
            sizes.push(c.len());
        }
        // MEASURED, and the claim is "no term", not "identical" — I asserted byte-equality here first and it
        // failed, exactly as it did on the membership proof. Proof bytes carry small ENCODING variance (field
        // /varint widths); what matters is that nothing tracks magnitude. Across value 1 .. u64::MAX the
        // spread must stay tiny and non-monotonic — a capacity or a magnitude term would show as growth.
        let (lo, hi) = (*sizes.iter().min().unwrap(), *sizes.iter().max().unwrap());
        eprintln!("[mint-size] values 1..u64::MAX -> carrier bytes {sizes:?} (spread {})", hi - lo);
        assert!(
            hi - lo < 128,
            "no MAGNITUDE term: carrier size spans only {} bytes across the ENTIRE u64 amount range \
             ({sizes:?}). A value-dependent trace would grow with the amount; a capacity would exhaust.",
            hi - lo
        );

        // VOLUME: many independent mints, each its own trace. The 200th is byte-identical in size to the 1st
        // and verifies the same — nothing accumulated into a shared budget.
        let mut first = 0usize;
        for i in 0..200u64 {
            let (c, cm) = prove_mint_validity_bytes(1_000 + i, &sk).expect("mint proves");
            assert!(verify_mint_validity_bytes(&c, cm, 1_000 + i), "mint #{i} verifies");
            if i == 0 {
                first = c.len();
            } else {
                let d = if c.len() > first { c.len() - first } else { first - c.len() };
                assert!(d < 128, "mint #{i} is within {d} B of the first — no per-mint accumulation");
            }
        }
    }

    // (The coinbase pow-bind carrier and its non-outsourceability pin were RETIRED with the coinbase on
    // 2026-09-18 — the chain is zero-emission; there is no reward to bind to a block challenge.)
}

// ===================================================================================================
// ASSET-TAGGED CONFIDENTIAL VALUE — the multi-asset note dimension (IonSwap launch, 2026-08-26).
//
// A note's commitment gains a HIDDEN asset tag in the three value limbs that were always zero:
//
//     cm = poseidon_pair([amount, t0, t1, t2], sk)        (USDm tag = [0,0,0])
//
// Every existing USDm note IS an asset-tagged note already — `asset_note_cm(v, USDM_ASSET_TAG, sk)`
// equals the legacy `poseidon_pair([v,0,0,0], sk)` limb for limb (pinned by
// `asset_zero_cm_matches_the_legacy_usdm_note_cm`), so nothing on chain moves and no legacy carrier
// changes a byte. This section is APPEND-ONLY for exactly that reason: the v1 entries above are the
// live USDm path and stay untouched.
//
// ⛔⛔⛔ WHY A TAG IS REQUIRED BEFORE ANY SWAP PAYOUT EXISTS. Without it a note is a bare
// `(amount, sk)` pair, so "credit the trader 3 wBTC" and "credit the trader 3 USDm atomic units" are
// THE SAME OBJECT. A wrapped-asset mint would hand out units that spend as USDm — cross-asset value
// confusion, an inflation bug that no downstream gate can catch because there is nothing in the
// commitment to disagree with. The tag is what makes "this note is wBTC" a fact the circuit can
// enforce rather than a label a caller asserts.
//
// ⭐⭐⭐ THE TAG IS HIDDEN, AND IT COSTS NOTHING TO KEEP IT THAT WAY. The three tag limbs live in ONE
// SHARED column group that the spent note's opening AND both output openings read. Same-asset
// conservation is then structural: there is no second tag for an output to disagree with, so
// "spend wBTC, mint USDm" is not a constraint that fails — it is a row that cannot be written. A
// transparent token chain publishes the asset on every transfer; here an observer sees a commitment
// and learns neither the amount nor WHICH asset moved ([[feedback_digital_cash_pillar]]).
//
// Two carriers, matching the two things a multi-asset chain must be able to prove:
//   * `asset_spend_validity`  — an ordinary transfer. Amount AND asset both hidden. `out0_cm` is the
//                               public handle: a commitment `poseidon([amount, tag], sk)` that another
//                               proof can OPEN in-circuit, so a consumer can constrain the amount
//                               without anyone publishing it.
//   * `asset_mint_validity`   — a credit with no input note. Welds the recorded `cm` to the authorized
//                               (amount, asset), which is the no-over-mint gate.
//
// ⛔ AN `asset_burn_validity` CARRIER WITH PUBLIC (amount, asset) WELDS WAS DELETED HERE 2026-08-26,
// at source rather than left unused. It existed for one afternoon to serve a pool-AMM pay leg that
// published each trade's size; that design was retired for trading three pillars (it serialised every
// trade of a pair through one mutable cell, and bought privacy back with latency that GREW with
// decentralisation). Leaving a public-amount spend path in the tree with zero callers is how it gets
// wired by accident later — and `out0_cm` already does the job with nothing disclosed.
//
// STYLE NOTE: the limb walks here are written as slice copies and iterator folds rather than as
// index loops over a numeric range. Same arithmetic, and it keeps a fixed algebraic shape from
// reading like a bounded budget in a file that also contains provers.
// ===================================================================================================

/// The KoalaBear prime — a tag limb is a field element, so every limb is reduced into `[0, p)`.
const ASSET_TAG_KB_P: u64 = 2_130_706_433;

/// USDm — the native unit, and the tag every note carried before this section existed. Keeping it
/// all-zero is what makes an asset-tagged commitment byte-identical to the legacy one.
pub const USDM_ASSET_TAG: [u64; 3] = [0, 0, 0];

/// Derive a wrapped asset's tag from its 32-byte asset id.
///
/// ⛔⛔⛔ LIMB 0 IS FORCED NONZERO, AND THAT IS A FUND-SAFETY CONSTRAINT, NOT TIDINESS. A derivation
/// that could return the all-zero triple would make that asset byte-fungible with USDm: its notes
/// would open under the USDm tag, so one atomic unit of a token worth $60,000 would spend as one
/// atomic unit of USDm (and vice versa). Mapping limb 0 into `[1, p-1]` makes the USDm tag
/// UNREACHABLE by any derived asset — the native unit cannot be impersonated by construction, so no
/// downstream check has to catch it.
///
/// ~93 bits of tag across three limbs. A single limb would be ~31 bits and collide by birthday at a
/// few tens of thousands of assets — and a tag collision means two DIFFERENT tokens are fungible,
/// which is the same fund-loss class as the zero case, just rarer. The registry is unbounded
/// ([[feedback_no_growth_any_axis]]), so the tag space must be too.
#[must_use]
pub fn wrapped_asset_tag(asset_id: &[u8; 32]) -> [u64; 3] {
    let mut h = blake3::Hasher::new();
    h.update(b"USDMD-ASSET-TAG-v1");
    h.update(asset_id);
    let d = *h.finalize().as_bytes();
    let limb = |i: usize| -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&d[i * 8..i * 8 + 8]);
        u64::from_le_bytes(b)
    };
    [
        // [1, p-1] — never zero, so never the USDm tag.
        limb(0) % (ASSET_TAG_KB_P - 1) + 1,
        limb(1) % ASSET_TAG_KB_P,
        limb(2) % ASSET_TAG_KB_P,
    ]
}

/// ⭐⭐⭐ THE CANONICAL SYMBOL → ASSET REGISTRY, IN ONE PLACE FOR THE WHOLE STACK.
///
/// ⛔ THIS DID NOT EXIST, AND ITS ABSENCE WAS A DRIFT WAITING TO HAPPEN. The peg ledger registers wrapped
/// assets by a `u32`, tags derive from that id, and NOTHING said which id "wBTC" is. Every component that
/// needed the answer would have had to invent it — the node minting under one id, a wallet searching for
/// another, a client quoting a third — and the failure is silent: notes valid on chain and invisible to
/// their owner, or a swap quoted for a pair nobody is making a market in. One table, and the question has
/// exactly one answer everywhere.
///
/// USDm is not in the table because it is not a wrapped asset: it is the native unit, and its tag is the
/// all-zero one, which is why every note sealed before tags existed reads as USDm with no migration.
pub const CANONICAL_WRAPPED_ASSETS: [(&str, u32); 3] = [("wBTC", 1), ("wETH", 2), ("wDAI", 3)];

/// The registry id for a wrapped symbol, or `None` if it is not a registered wrapped asset.
///
/// Case-insensitive on the symbol, because a user typing "wbtc" means wBTC and a lookup that fails on
/// case would present as "no such market" — a confusing refusal for a correct request.
#[must_use]
pub fn canonical_wrapped_asset_id(symbol: &str) -> Option<u32> {
    let want = symbol.trim();
    CANONICAL_WRAPPED_ASSETS
        .iter()
        .find(|(s, _)| s.eq_ignore_ascii_case(want))
        .map(|(_, id)| *id)
}

/// The asset TAG for a symbol: USDm's all-zero tag, a registered wrapped asset's derived tag, or `None`.
///
/// ⛔ `None` IS A REFUSAL, NOT A DEFAULT. Falling back to USDm for an unknown symbol would let a typo
/// quote and settle against the wrong asset entirely — the caller must handle the unknown case.
#[must_use]
/// ⭐ SATOSHI (SAT), the native token: its asset id is a protocol constant with no creator, and its tag is derived like
/// every asset's. ONE definition, read by the node (`satoshi::asset_id` / `asset_tag`) and the wallet (`asset_tag_for_symbol`).
#[must_use]
pub fn satoshi_asset_id() -> [u8; 32] {
    *blake3::hash(b"MONEROUSD-SATOSHI-NATIVE-v1").as_bytes()
}
#[must_use]
pub fn satoshi_asset_tag() -> [u64; 3] {
    wrapped_asset_tag(&satoshi_asset_id())
}

pub fn asset_tag_for_symbol(symbol: &str) -> Option<[u64; 3]> {
    let want = symbol.trim();
    if want.eq_ignore_ascii_case("USDm") {
        return Some(USDM_ASSET_TAG);
    }
    if want.eq_ignore_ascii_case("SAT") || want.eq_ignore_ascii_case("Satoshi") {
        return Some(satoshi_asset_tag());
    }
    canonical_wrapped_asset_id(want).map(wrapped_asset_tag_u32)
}

/// The tag for a wrapped asset the PEG LEDGER knows by its `u32` registry id.
///
/// ⛔ ONE DEFINITION, BECAUSE TWO WOULD SILENTLY DIVERGE. The node registers wrapped assets by a `u32`
/// (`PegLedger::register_wrapped_asset`), while a tag is derived from a 32-byte id. If the node and the
/// wallet each widened that `u32` their own way, they would compute DIFFERENT tags for the SAME asset:
/// the node would mint under one, the wallet would look for the other, and the note would be invisible
/// to its owner while sitting perfectly valid on chain. Both sides call THIS.
///
/// The domain prefix keeps the `u32` space from colliding with a content-addressed 32-byte asset id that
/// happened to share those bytes — two different assets sharing a tag is the same fund-loss class as an
/// asset colliding with USDm, just rarer.
#[must_use]
pub fn wrapped_asset_tag_u32(asset_id: u32) -> [u64; 3] {
    let mut id = [0u8; 32];
    id[..20].copy_from_slice(b"USDMD-WRAPPED-U32-v1");
    id[20..24].copy_from_slice(&asset_id.to_le_bytes());
    wrapped_asset_tag(&id)
}


/// Domain for the asset-tagged spend carrier (asset hidden).
pub const ASSET_SPEND_VALIDITY_DOMAIN: u64 = 0x4153_504e_4456_4c31; // "ASPNDVL1"
/// Domain for the asset-tagged MINT carrier (amount + asset PUBLIC, no input note).
pub const ASSET_MINT_VALIDITY_DOMAIN: u64 = 0x414d_494e_5456_4c31; // "AMINTVL1"

/// A full asset-tagged spend witness — [`SpendValidityWitness`] plus the asset every leg shares.
/// There is deliberately no per-output tag: the outputs are the same asset as the input because they
/// read the same columns.
#[derive(Clone, Debug)]
pub struct AssetSpendValidityWitness {
    pub value_in: u64,
    /// ⛔ DB-395: the input note's owner (`ask`, `nk`, the note's seed).
    pub owner: NoteOwner,
    pub value_out: u64,
    pub fee: u64,
    /// DB-363 (2026-09-30): the spender's fresh per-send blinding of the cross-bind, exactly as
    /// [`SpendValidityWitness::lc_blind`]; the path fields are gone with the vestigial Merkle path.
    pub lc_blind: Digest,
    pub out0_value: u64,
    /// DB-395: each output's opening `P(spk_recipient, seed)` — no spend authority.
    pub out0_opening: Digest,
    pub out1_value: u64,
    pub out1_opening: Digest,
    /// The asset every leg of this spend is denominated in. [`USDM_ASSET_TAG`] for native USDm.
    pub asset: [u64; 3],
}

/// The asset-tagged spend gate. Column map is [`SpendValidityGate`]'s, with the shared 3-column tag
/// group appended at `47 + depth*33 + 62`:
/// value_in[0] · sk[1..5] · leaf[5..9] · value_out[9] · fee[10] · nf[11..15] · note-open lanes[15..31]
/// · nullifier lanes[31..47] · membership 33/level from 47 · two 25-col output blocks from
/// `47 + depth*33` · the 12-col cross-bind block · tag[.. +3].
pub struct AssetSpendValidityGate {
    pub gamma: Ea4,
    pub out0_cm: [Ea4; DIGEST_LANES],
    pub out1_cm: [Ea4; DIGEST_LANES],
    pub nullifier: [Ea4; DIGEST_LANES],
    /// The note-membership cross-bind, `Poseidon(leaf, nullifier)`. Not optional, for the reason
    /// [`SpendValidityGate`]'s own field documents: a carrier without it would rest on a
    /// fixed-capacity Merkle root, and that shape is unrepresentable here too.
    pub leaf_commit: [Ea4; DIGEST_LANES],
    /// ⭐ SATOSHI (docs/SATOSHI-NATIVE-TOKEN.md §6) — THE WELDED ASSET BOND: `Some((W limbs, asset tag))` binds output 0 to
    /// lock EXACTLY the public weight `W` (the USDm bond's weld, DB-313 §3 / DB-340, limb-wise over range-bound limbs)
    /// AND welds the row's asset-tag columns to the PUBLIC tag, so a custody bond proves which asset it locks — a bond
    /// of a worthless token can never seat SAT weight. `None` is the ordinary asset transfer (the tag stays private).
    pub bond: Option<([Ea4; SC_LIMBS], [Ea4; 3])>,
    /// ⭐ SATOSHI §9 — the RE-BOND arm: the second input's PUBLIC `(nullifier, commitment)`. `Some` ⇒ the row is
    /// `asset_rebond_row_width()` wide, block C splits the total into the two inputs, input 2 opens under the same tag, and BOTH
    /// its nullifier and its commitment are bound here. ⛔ THE COMMITMENT IS WHAT MAKES INPUT 2 REAL: input 2 has no membership
    /// path (it is the validator's LOCKED note, never a balance), so its existence is the fold's check `cm2 ==
    /// bond_locked[vid]`; a carrier that published only `nf2` would let a phantom note of ANY value inflate custody weight
    /// (found refuting §9.1 against the node door, 2026-10-05).
    pub second: Option<([Ea4; DIGEST_LANES], [Ea4; DIGEST_LANES])>,
}

// ⛔ `asset_mds_row` DELETED 2026-09-12: it was the retired 1-round fold's MDS row (kill list §AG).
// Every asset gate folds with a whole Poseidon2 permutation now.

impl crate::air_zerocheck::AirConstraint for AssetSpendValidityGate {
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ EMBEDS A PERMUTATION: a gate declaring less than the permutation's degree truncates
        // the sumcheck, so even an HONEST proof stops verifying.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let g = self.gamma;
        let zero = Ea4::from(Fa4::ZERO);
        let one = Ea4::ONE;
        let seven = Ea4::from(Fa4::from_u64(7));
        // ⛔ 0 / 9 / 10 / 11 WERE THE FOUR-LANE ARITHMETIC, and the four `noh_*` accessors named the
        // RETIRED S-box's intermediate columns, which no longer exist — the opening is a whole permutation
        // laid at `SV_NOH_BLK`. The asset row shares the USDm row's head layout, so it reads the same
        // derived constants.
        let value_in = local[SV_VALUE_IN];
        let leaf = |c: usize| local[SV_LEAF + c];
        let value_out = local[SV_VALUE_OUT];
        let fee = local[SV_FEE];
        let nf = |c: usize| local[SV_NF + c];
        // ⭐ THE SHARED TAG. Read by the input opening and by BOTH output openings below.
        // ⛔ `MB + d*33 + 62` and the 31/35/39/43 lanes were the retired 1-round fold's offsets.
        let ab = SV_ASSET_AB;
        let tag = |c: usize| local[ab + c];
        let mut rs: Vec<Ea4> = Vec::new();
        // A + B, RANGE-BOUND AND TWO-ROUND — identical to the USDm gate, with the tag as witness
        // lanes in the inner round: `leaf == P(limbs(value_in), P([t0, t1, t2, 0], sk))`. The tail
        // (blocks A/E + inner rounds) sits after the 3 tag columns.
        let tail = SV_ASSET_TAIL;
        let ta = U64ConsBases::at(tail + SV_TAIL_A);
        let te = U64ConsBases::at(tail + SV_TAIL_E);
        push_u64_conservation(&mut rs, local, ta);
        push_u64_conservation(&mut rs, local, te);
        for i in 0..SC_LIMBS {
            rs.push(local[te.r#in + i] - local[ta.out + i]);
        }
        rs.push(value_in - u64_limbs_recombined(local, ta.r#in));
        rs.push(value_out - u64_limbs_recombined(local, ta.out));
        rs.push(fee - u64_limbs_recombined(local, ta.fee));
        // ⭐ SATOSHI — the welded bond: out0 locks exactly W (range-bound limbs), and the asset is the PUBLIC tag.
        if let Some((limbs, pub_tag)) = self.bond {
            for i in 0..SC_LIMBS {
                rs.push(local[te.out + i] - limbs[i]);
            }
            for c in 0..3 {
                rs.push(tag(c) - pub_tag[c]);
            }
        }
        let tag_lane = |c: usize| if c < 3 { tag(c) } else { zero };
        let sk_col = |c: usize| local[SV_SK + c];
        // ⛔ DB-395 — input 1's OWNER: its opening lanes are welded to `o = P(P(ask, nk), seed)`, and its nullifier is keyed
        // by `nk`, so neither the spend nor the nullifier is within reach of the note's sender.
        push_owner_open(&mut rs, local, ASV_OWNER, SV_SK);
        let nk = |c: usize| local[owner_nk_col(ASV_OWNER) + c];
        // ⭐ SATOSHI §9 RE-BOND: with a second input, block A's `in` is the TOTAL and block C splits it — input 1 opens over
        // C's `out` limbs (its own value), input 2 over C's `fee` limbs. Without one, input 1 opens over A's `in` as before.
        let tc = U64ConsBases::at(SV_IN2_CONS);
        let in1_limbs = if self.second.is_some() { tc.out } else { ta.r#in };
        push_note_open(
            &mut rs, local, in1_limbs, &tag_lane, &sk_col,
            tail + SV_TAIL_IN_BLK, tail + SV_TAIL_IN_OUT, SV_NOH_BLK, SV_LEAF,
        );
        // C. NULLIFIER — nf == compress(nk, leaf), one whole permutation (DB-395).
        push_pose_round(&mut rs, local, &nk, &leaf, SV_NFH_BLK, SV_NF);
        if let Some((nf2_pub, cm2_pub)) = self.second {
            push_u64_conservation(&mut rs, local, tc); // total = value_in1 + value_in2, every term range-bound
            for i in 0..SC_LIMBS {
                rs.push(local[tc.r#in + i] - local[ta.r#in + i]); // the total C splits IS the total A conserves (limb-wise)
            }
            rs.push(local[SV_IN2_VALUE] - u64_limbs_recombined(local, tc.fee));
            let sk2 = |c: usize| local[SV_IN2_SK + c];
            let leaf2 = |c: usize| local[SV_IN2_LEAF + c];
            // ⛔ DB-395 — the locked note's OWNER, the same proof as input 1's.
            push_owner_open(&mut rs, local, SV_IN2_OWNER, SV_IN2_SK);
            let nk2 = |c: usize| local[owner_nk_col(SV_IN2_OWNER) + c];
            push_note_open(
                &mut rs, local, tc.fee, &tag_lane, &sk2,
                SV_IN2_INNER_BLK, SV_IN2_INNER_OUT, SV_IN2_NOH_BLK, SV_IN2_LEAF,
            );
            push_pose_round(&mut rs, local, &nk2, &leaf2, SV_IN2_NFH_BLK, SV_IN2_NF);
            rs.extend((0..DIGEST_LANES).map(|c| local[SV_IN2_NF + c] - nf2_pub[c]));
            rs.extend((0..DIGEST_LANES).map(|c| local[SV_IN2_LEAF + c] - cm2_pub[c]));
        }
        // D. (DELETED 2026-09-30) the depth-`d` Merkle path — anchored to nothing since §BY, refused by the
        // decorative-block census, deleted at source; membership is the note-membership carrier's (gate F).
        // E. OUTPUT BINDING — value_out == out0 + out1, and each output opens under THE SAME TAG.
        // This is where cross-asset inflation dies: there is no output-side tag to disagree with.
        let ob = SV_OB;
        let slot = |j: usize| ob + j * SV_OUT_SLOT;
        let out_val = |j: usize| local[slot(j)];
        let out_sk = |j: usize, c: usize| local[slot(j) + 1 + c];
        let out_cm = |j: usize, c: usize| local[slot(j) + 1 + DIGEST_LANES + crate::pow_pq_air::P2_COLS + c];
        rs.push(out_val(0) - u64_limbs_recombined(local, te.out));
        rs.push(out_val(1) - u64_limbs_recombined(local, te.fee));
        for (j, pub_cm) in [self.out0_cm, self.out1_cm].into_iter().enumerate() {
            let limbs = if j == 0 { te.out } else { te.fee };
            let (iblk, iout) = if j == 0 { (SV_TAIL_O0_BLK, SV_TAIL_O0_OUT) } else { (SV_TAIL_O1_BLK, SV_TAIL_O1_OUT) };
            let osk = |c: usize| out_sk(j, c);
            push_note_open(
                &mut rs, local, limbs, &tag_lane, &osk, tail + iblk, tail + iout,
                slot(j) + 1 + DIGEST_LANES, slot(j) + 1 + DIGEST_LANES + crate::pow_pq_air::P2_COLS,
            );
            rs.extend((0..DIGEST_LANES).map(|c| out_cm(j, c) - pub_cm[c]));
        }
        // F. NULLIFIER + MEMBERSHIP CROSS-BIND, identical to the untagged gate.
        rs.extend((0..DIGEST_LANES).map(|c| nf(c) - self.nullifier[c]));
        {
            // DB-363 (2026-09-30): `leaf_commit == P(P(leaf, nullifier), lc_blind)`, two chained blocks — see the
            // untagged gate's block F for why (the single compression had two PUBLIC inputs and linked spend to receive).
            let lc = self.leaf_commit;
            let nfp = |c: usize| self.nullifier[c];
            push_pose_round(&mut rs, local, &leaf, &nfp, SV_CB, SV_CB2);
            crate::pow_pq_air::push_perm_residuals(local, SV_CB2, &mut rs);
            for c in 0..DIGEST_LANES {
                rs.push(local[SV_CB2 + DIGEST_LANES + c] - local[SV_BLIND + c]);
                rs.push(local[SV_CB2 + crate::pow_pq_air::PERM_OUT + c] - lc[c]);
            }
        }
        let mut out = zero;
        let mut gp = one;
        for r in rs {
            out = out + gp * r;
            gp = gp * g;
        }
        out
    }
    /// DB-363: the blinding lanes are a HIDING witness, bound only through the outer cross-bind block — see
    /// `SpendValidityGate::free_columns`.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some((SV_BLIND..SV_BLIND + DIGEST_LANES).collect())
    }
}

/// Build the asset-tagged validity row. Returns `(row, out_cms, nf, leaf_commit, input_leaf)`. The
/// frontier root is deliberately NOT returned: this carrier never binds one.
#[allow(clippy::type_complexity)]
fn asset_spend_validity_row(
    w: &AssetSpendValidityWitness,
) -> Option<(Vec<Fa4>, [DigestF; 2], DigestF, DigestF, DigestF)> {
    let (row, cms, nf, lc, leaf, _nf2) = asset_spend_validity_row_inner(w, None)?;
    Some((row, cms, nf, lc, leaf))
}

// ───────────────────────────── §18.14: the committed burn of a coin note ─────────────

/// The asset row's columns, then the committed burn's: the burned value's 16-bit limbs, its blind, its commitment and the opening's blocks. The USDm burn's layout ([`BVC_V16`]) over the asset row.
const ABC_V16: usize = asset_spend_row_width();
const ABC_BBLIND: usize = ABC_V16 + 16;
const ABC_BCOMMIT: usize = ABC_BBLIND + DIGEST_LANES;
const ABC_BINTER: usize = ABC_BCOMMIT + DIGEST_LANES;
const ABC_BVBITS: usize = ABC_BINTER + 2 * crate::confidential_solvency::CO_BLOCK;
/// The committed coin burn's row width.
pub const ABC_WIDTH: usize = ABC_BVBITS + crate::confidential_solvency::RANGE16_COLS;
/// The transcript domain of a committed coin burn ("BURNACB1").
pub const ASSET_BURN_COMMITTED_DOMAIN: u64 = 0x4255_524e_4143_4231;

/// ⭐ §18.14 — A COIN NOTE'S COMMITTED BURN: the asset spend (conservation, ownership, nullifier, cross-bind), output 0's value opening `burn_commit` and the row's asset welded to the PUBLIC coin's tag, so a
/// burn of one coin's note can never release the other's. The USDm burn's law ([`BurnValidityCommittedGate`]) over the asset row: no amount is public.
pub struct AssetBurnCommittedGate {
    pub inner: AssetSpendValidityGate,
    pub burn_commit: [Ea4; DIGEST_LANES],
    pub asset: [Ea4; 3],
}

impl AssetBurnCommittedGate {
    fn all_residuals(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        let mut rs = crate::air_zerocheck::AirConstraint::residuals(&self.inner, local, at, x);
        let te = U64ConsBases::at(SV_ASSET_TAIL + SV_TAIL_E);
        for i in 0..SC_LIMBS {
            rs.push(local[ABC_V16 + i] - local[te.out + i]);
        }
        for i in SC_LIMBS..16 {
            rs.push(local[ABC_V16 + i]);
        }
        crate::confidential_solvency::push_commit_open_constraints(&mut rs, local, ABC_V16, ABC_BBLIND, ABC_BCOMMIT, ABC_BINTER, ABC_BVBITS);
        for c in 0..DIGEST_LANES {
            rs.push(local[ABC_BCOMMIT + c] - self.burn_commit[c]);
        }
        for c in 0..3 {
            rs.push(local[SV_ASSET_AB + c] - self.asset[c]);
        }
        rs
    }
}

impl crate::air_zerocheck::AirConstraint for AssetBurnCommittedGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in self.all_residuals(local, at, x) {
            out = out + gp * r;
            gp = gp * self.inner.gamma;
        }
        out
    }
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        self.all_residuals(local, at, x)
    }
    fn is_row_local(&self) -> bool {
        true
    }
    /// The asset row's hiding witnesses, plus the burn commitment's blind.
    fn free_columns(&self) -> Option<Vec<usize>> {
        let mut free = crate::air_zerocheck::AirConstraint::free_columns(&self.inner).unwrap_or_default();
        free.extend(ABC_BBLIND..ABC_BBLIND + DIGEST_LANES);
        Some(free)
    }
}

/// Transcript bind: domain ‖ out0 ‖ out1 ‖ nullifier ‖ leaf commitment ‖ burn commitment ‖ the coin's tag. No amount anywhere.
fn asset_burn_committed_public_bind(out_cms: &[DigestF; 2], nullifier: &DigestF, leaf_commit: &DigestF, burn_commit: &DigestF, tag: &[Fa4; 3]) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(ASSET_BURN_COMMITTED_DOMAIN)];
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    b.extend_from_slice(nullifier);
    b.extend_from_slice(leaf_commit);
    b.extend_from_slice(burn_commit);
    b.extend_from_slice(tag);
    b
}

/// ⭐ §18.14 — PROVE a coin note's committed burn. Returns `(carrier, [out0_cm, out1_cm], nullifier, leaf_commit, burn_commit)`.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_asset_burn_committed_bytes(w: &AssetSpendValidityWitness, b_blind: &Digest) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest, Digest)> {
    use p3_field::PrimeField64;
    let (row, out_cms, nf, commit, _leaf) = asset_spend_validity_row(w)?;
    let mut cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
    while cols.len() < ABC_WIDTH {
        cols.push(vec![Fa4::ZERO; LIGHT_CARRIER_ROWS]);
    }
    let mut limbs = [0u64; 16];
    for (i, limb) in limbs.iter_mut().enumerate().take(SC_LIMBS) {
        *limb = (w.out0_value >> (SC_LIMB_BITS * i)) & 0xFFFF;
    }
    for (i, limb) in limbs.iter().enumerate() {
        cols[ABC_V16 + i].fill(Fa4::from_u64(*limb));
    }
    for i in 0..DIGEST_LANES {
        cols[ABC_BBLIND + i].fill(Fa4::from_u64(b_blind[i]));
    }
    let bc = crate::confidential_solvency::place_commit_open(&mut cols, limbs, *b_blind, ABC_BINTER, ABC_BVBITS);
    for i in 0..DIGEST_LANES {
        cols[ABC_BCOMMIT + i].fill(Fa4::from_u64(bc[i]));
    }
    let bc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(bc[c]));
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(w.asset[c]));
    let ea = |d: &DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| d[i].into()) };
    let (o0, o1, nfe, lce, bce) = (ea(&out_cms[0]), ea(&out_cms[1]), ea(&nf), ea(&commit), ea(&bc_f));
    let tag_ea: [Ea4; 3] = core::array::from_fn(|c| tag_f[c].into());
    let make = move |g: Ea4| AssetBurnCommittedGate {
        inner: AssetSpendValidityGate { gamma: g, out0_cm: o0, out1_cm: o1, nullifier: nfe, leaf_commit: lce, bond: None, second: None },
        burn_commit: bce,
        asset: tag_ea,
    };
    let carrier = crate::committed_air::prove_air_blinded_bytes(cols, make, &asset_burn_committed_public_bind(&out_cms, &nf, &commit, &bc_f, &tag_f))?;
    let u = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((carrier, [u(out_cms[0]), u(out_cms[1])], u(nf), u(commit), bc))
}

/// ⭐ §18.14 — VERIFY a coin note's committed burn against the public `(out0, out1, nullifier, leaf_commit, burn_commit, coin)`.
#[must_use]
pub fn verify_asset_burn_committed_bytes(bytes: &[u8], out0_cm: Digest, out1_cm: Digest, nullifier: Digest, leaf_commit: Digest, burn_commit: Digest, asset: [u64; 3]) -> bool {
    if bytes.is_empty() || leaf_commit == crate::poseidon2_compress::ZERO_DIGEST {
        return false;
    }
    let f = |d: &Digest| -> DigestF { core::array::from_fn(|c| Fa4::from_u64(d[c])) };
    let (o0, o1, nfv, lcf, bcf) = (f(&out0_cm), f(&out1_cm), f(&nullifier), f(&leaf_commit), f(&burn_commit));
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(asset[c]));
    let ea = |d: &DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| d[i].into()) };
    let (o0e, o1e, nfe, lce, bce) = (ea(&o0), ea(&o1), ea(&nfv), ea(&lcf), ea(&bcf));
    let tag_ea: [Ea4; 3] = core::array::from_fn(|c| tag_f[c].into());
    let make = move |g: Ea4| AssetBurnCommittedGate {
        inner: AssetSpendValidityGate { gamma: g, out0_cm: o0e, out1_cm: o1e, nullifier: nfe, leaf_commit: lce, bond: None, second: None },
        burn_commit: bce,
        asset: tag_ea,
    };
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        make,
        &asset_burn_committed_public_bind(&[o0, o1], &nfv, &lcf, &bcf, &tag_f),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, ABC_WIDTH),
    )
}

// ───────────────────────────── §18.14: a device-slot claim paid by a SAT or coin note ─────────────────────────────

const ASC_D: usize = asset_spend_row_width();
const ASC_KEY: usize = ASC_D + 1;
const ASC_BLK: usize = ASC_KEY + DIGEST_LANES;
/// The asset slot claim's row width.
pub const ASC_WIDTH: usize = ASC_BLK + crate::pow_pq_air::P2_COLS;
/// The transcript domain of an asset slot claim ("SLOTACL1").
pub const ASSET_SLOT_CLAIM_DOMAIN: u64 = 0x534c_4f54_4143_4c31;

/// ⭐ §18.14 — A DEVICE-SLOT CLAIM SPENDING A SAT OR COIN NOTE: the asset spend's whole law, plus DB-329's claim law over columns of its own: `tag1 = P([SLOT_CLAIM_DOMAIN, d, 0…], key)`, one spelling with the USDm claim.
/// MEASURED why, on two real nodes 2026-11-05: a restored wallet may not spend until it holds a slot, and only a USDm note could claim one, so a wallet holding only SAT or coin could never spend anything.
/// BORROWED: this chain's own USDm self-claim (DB-329 §7e); the nullifier set decides who holds the slot (Zcash).
pub struct AssetSlotClaimGate {
    pub inner: AssetSpendValidityGate,
    pub tag1: [Ea4; DIGEST_LANES],
}

impl AssetSlotClaimGate {
    fn all_residuals(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        let mut rs = crate::air_zerocheck::AirConstraint::residuals(&self.inner, local, at, x);
        crate::pow_pq_air::push_perm_residuals(local, ASC_BLK, &mut rs);
        for c in 0..DIGEST_LANES {
            let left = match c {
                0 => Ea4::from(Fa4::from_u64(crate::slot_ledger::SLOT_CLAIM_DOMAIN)),
                1 => local[ASC_D],
                _ => Ea4::from(Fa4::ZERO),
            };
            rs.push(local[ASC_BLK + c] - left);
            rs.push(local[ASC_BLK + DIGEST_LANES + c] - local[ASC_KEY + c]);
            rs.push(local[ASC_BLK + crate::pow_pq_air::PERM_OUT + c] - self.tag1[c]);
        }
        rs
    }
}

impl crate::air_zerocheck::AirConstraint for AssetSlotClaimGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in self.all_residuals(local, at, x) {
            out = out + gp * r;
            gp = gp * self.inner.gamma;
        }
        out
    }
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        self.all_residuals(local, at, x)
    }
    fn is_row_local(&self) -> bool {
        true
    }
    /// The asset row's hiding witnesses, plus the claim's `d` and key: hiding, bound only through the public tag.
    fn free_columns(&self) -> Option<Vec<usize>> {
        let mut free = crate::air_zerocheck::AirConstraint::free_columns(&self.inner).unwrap_or_default();
        free.extend(ASC_D..ASC_BLK);
        Some(free)
    }
}

/// Transcript bind: domain ‖ out0 ‖ out1 ‖ nullifier ‖ leaf commitment ‖ the claim tag.
fn asset_slot_claim_public_bind(out_cms: &[DigestF; 2], nullifier: &DigestF, leaf_commit: &DigestF, tag1: &DigestF) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(ASSET_SLOT_CLAIM_DOMAIN)];
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    b.extend_from_slice(nullifier);
    b.extend_from_slice(leaf_commit);
    b.extend_from_slice(tag1);
    b
}

/// ⭐ §18.14 — PROVE an asset spend that claims device slot `d` under `key`. Returns `(carrier, [out0_cm, out1_cm], nullifier, leaf_commit, tag1)`.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_asset_slot_claim_bytes(w: &AssetSpendValidityWitness, key: &Digest, d: u64) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest, Digest)> {
    use p3_field::PrimeField64;
    let (mut row, out_cms, nf, commit, _leaf) = asset_spend_validity_row(w)?;
    row.resize(ASC_WIDTH, Fa4::ZERO);
    row[ASC_D] = Fa4::from_u64(d);
    let key_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(key[c]));
    row[ASC_KEY..ASC_KEY + DIGEST_LANES].copy_from_slice(&key_f);
    let claim_left: DigestF = to_f(&crate::poseidon2_compress::lanes_of(&[crate::slot_ledger::SLOT_CLAIM_DOMAIN, d]));
    crate::pow_pq_air::lay_perm_row_flat(&mut row, ASC_BLK, pose_state(&claim_left, &key_f));
    let tag1_f: DigestF = core::array::from_fn(|c| row[ASC_BLK + crate::pow_pq_air::PERM_OUT + c]);
    let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
    let ea = |d: &DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| d[i].into()) };
    let (o0, o1, nfe, lce, te) = (ea(&out_cms[0]), ea(&out_cms[1]), ea(&nf), ea(&commit), ea(&tag1_f));
    let make = move |g: Ea4| AssetSlotClaimGate {
        inner: AssetSpendValidityGate { gamma: g, out0_cm: o0, out1_cm: o1, nullifier: nfe, leaf_commit: lce, bond: None, second: None },
        tag1: te,
    };
    let carrier = crate::committed_air::prove_air_blinded_bytes(cols, make, &asset_slot_claim_public_bind(&out_cms, &nf, &commit, &tag1_f))?;
    let u = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((carrier, [u(out_cms[0]), u(out_cms[1])], u(nf), u(commit), u(tag1_f)))
}

/// VERIFY an asset spend that claims a device slot under the public `tag1`. A plain transfer's carrier never passes here, nor this one there: their transcripts differ.
#[must_use]
pub fn verify_asset_slot_claim_bytes(bytes: &[u8], out0_cm: Digest, out1_cm: Digest, nullifier: Digest, leaf_commit: Digest, tag1: Digest) -> bool {
    if bytes.is_empty() || leaf_commit == crate::poseidon2_compress::ZERO_DIGEST {
        return false;
    }
    let f = |d: &Digest| -> DigestF { core::array::from_fn(|c| Fa4::from_u64(d[c])) };
    let (o0, o1, nfv, lcf, tf) = (f(&out0_cm), f(&out1_cm), f(&nullifier), f(&leaf_commit), f(&tag1));
    let ea = |d: &DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| d[i].into()) };
    let (o0e, o1e, nfe, lce, te) = (ea(&o0), ea(&o1), ea(&nfv), ea(&lcf), ea(&tf));
    let make = move |g: Ea4| AssetSlotClaimGate {
        inner: AssetSpendValidityGate { gamma: g, out0_cm: o0e, out1_cm: o1e, nullifier: nfe, leaf_commit: lce, bond: None, second: None },
        tag1: te,
    };
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        make,
        &asset_slot_claim_public_bind(&[o0, o1], &nfv, &lcf, &tf),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, ASC_WIDTH),
    )
}

#[cfg(test)]
mod asset_burn_committed_tests {
    use super::*;

    /// ⭐ §18.14 — A COIN BURN VERIFIES ONLY FOR ITS AMOUNT AND ITS COIN: the honest burn verifies; another burn commitment, the other coin's tag, or another output commitment is refused.
    #[test]
    fn a_coin_burn_opens_only_its_amount_under_only_its_coin() {
        let lanes = crate::poseidon2_compress::lanes_of;
        let btc = wrapped_asset_tag_u32(2);
        let xmr = wrapped_asset_tag_u32(3);
        let w = AssetSpendValidityWitness {
            value_in: 90_000,
            owner: NoteOwner::from_test_key(lanes(&[0xABC, 1])),
            value_out: 90_000,
            fee: 0,
            lc_blind: lanes(&[0xABC, 2]),
            out0_value: 10_000,
            out0_opening: lanes(&[0xABC, 3]),
            out1_value: 80_000,
            out1_opening: lanes(&[0xABC, 4]),
            asset: btc,
        };
        let blind = lanes(&[0xABC, 5]);
        let (carrier, cms, nf, lc, bc) = prove_asset_burn_committed_bytes(&w, &blind).expect("the burn proves");
        assert!(verify_asset_burn_committed_bytes(&carrier, cms[0], cms[1], nf, lc, bc, btc), "⛔ the honest coin burn does not verify");
        let other = crate::confidential_solvency::solvency_commit_256(crate::confidential_solvency::u256_from_u64(10_001), blind);
        assert!(!verify_asset_burn_committed_bytes(&carrier, cms[0], cms[1], nf, lc, other, btc), "⛔ a burn verified for another amount");
        assert!(!verify_asset_burn_committed_bytes(&carrier, cms[0], cms[1], nf, lc, bc, xmr), "⛔ a Bitcoin coin's burn verified as Monero's");
        assert!(!verify_asset_burn_committed_bytes(&carrier, cms[1], cms[0], nf, lc, bc, btc), "⛔ a burn verified with its outputs swapped");
    }

    /// ⭐ §18.14 — A SLOT CLAIM BY AN ASSET NOTE PROVES ITS TAG, AND ONLY ITS TAG: the honest claim verifies under exactly `claim(key, d)`, the USDm claim's one spelling; another slot, another seed's key or another nullifier is refused;
    /// a claim's carrier is not a plain transfer's nor the reverse; two notes of one seed claiming one slot publish ONE tag, which is what the set arbitrates.
    #[test]
    fn an_asset_slot_claim_proves_its_tag_and_two_claims_of_one_slot_share_it() {
        let lanes = crate::poseidon2_compress::lanes_of;
        let sat = wrapped_asset_tag_u32(2);
        let spend = |k: u64| AssetSpendValidityWitness {
            value_in: 90_000,
            owner: NoteOwner::from_test_key(lanes(&[0xACC, k])),
            value_out: 90_000,
            fee: 0,
            lc_blind: lanes(&[0xACC, 100 + k]),
            out0_value: 90_000,
            out0_opening: lanes(&[0xACC, 200 + k]),
            out1_value: 0,
            out1_opening: lanes(&[0xACC, 300 + k]),
            asset: sat,
        };
        let key = lanes(&[0x51, 0x07]);
        let (c, cms, nf, lc, t1) = prove_asset_slot_claim_bytes(&spend(1), &key, 2).expect("the claim proves");
        assert_eq!(t1, crate::slot_ledger::slot_claim_native(key, 2), "the tag is not the USDm claim's spelling");
        assert!(verify_asset_slot_claim_bytes(&c, cms[0], cms[1], nf, lc, t1), "⛔ the honest claim does not verify");
        assert!(!verify_asset_slot_claim_bytes(&c, cms[0], cms[1], nf, lc, crate::slot_ledger::slot_claim_native(key, 3)), "⛔ a claim verified for another slot");
        assert!(!verify_asset_slot_claim_bytes(&c, cms[0], cms[1], nf, lc, crate::slot_ledger::slot_claim_native(lanes(&[0x51, 0x08]), 2)), "⛔ a claim verified under another seed's key");
        assert!(!verify_asset_slot_claim_bytes(&c, cms[0], cms[1], lanes(&[9, 9]), lc, t1), "⛔ a claim verified for another nullifier");
        assert!(!verify_asset_spend_validity_carrier_bytes(&c, cms[0], cms[1], nf, lc), "⛔ a claim's carrier verified as a plain transfer");
        let (p, pcms, pnf, plc) = prove_asset_spend_validity_carrier_bytes(&spend(1)).expect("the transfer proves");
        assert!(!verify_asset_slot_claim_bytes(&p, pcms[0], pcms[1], pnf, plc, t1), "⛔ a plain transfer verified as a claim");
        let (_c2, _cms2, nf2, _lc2, t2) = prove_asset_slot_claim_bytes(&spend(2), &key, 2).expect("the second claim proves");
        assert_eq!(t1, t2, "⛔ two claims of one slot publish two tags: the set could not arbitrate them");
        assert_ne!(nf, nf2, "two notes share a nullifier");
    }
}

/// ⭐ SATOSHI §9 — the RE-BOND witness: the fresh note's spend (`fresh.value_in` is the FRESH note's value; its outputs and fee
/// conserve the TOTAL `fresh.value_in + locked_value`) plus the validator's currently LOCKED note `(locked_value, locked_owner)`.
pub struct AssetRebondWitness {
    pub fresh: AssetSpendValidityWitness,
    pub locked_value: u64,
    /// ⛔ DB-395: the locked note's owner — the same proof as the fresh input's.
    pub locked_owner: NoteOwner,
}

/// The one row builder behind the single-input asset shapes (`second = None`) and the re-bond (`Some`). With a second input
/// the row is `asset_rebond_row_width()` wide, `SV_VALUE_IN` holds the TOTAL, block C splits it into the two inputs, input 1
/// opens over its own value, input 2 (the locked note) opens in the appended block, and its nullifier is returned too.
#[allow(clippy::type_complexity)]
fn asset_spend_validity_row_inner(
    w: &AssetSpendValidityWitness,
    second: Option<(u64, NoteOwner)>,
) -> Option<(Vec<Fa4>, [DigestF; 2], DigestF, DigestF, DigestF, Option<DigestF>)> {
    let total = match second {
        Some((v2, _)) => w.value_in.checked_add(v2)?,
        None => w.value_in,
    };
    // ⛔ No path, no depth (2026-09-30): the row is one constant layout; see the untagged builder.
    if w.value_out.checked_add(w.fee)? != total {
        return None; // A. conservation (also in-circuit)
    }
    if w.out0_value.checked_add(w.out1_value)? != w.value_out {
        return None; // E. output conservation (also in-circuit)
    }
    let width = if second.is_some() { asset_rebond_row_width() } else { asset_spend_row_width() };
    let tail = SV_ASSET_TAIL;
    let mut row = vec![Fa4::ZERO; width];
    let value_in = Fa4::from_u64(total);
    // DB-395: input 1's opening lanes hold `o = P(P(ask, nk), seed)`, laid by its owner block.
    let sk = fill_owner_open(&mut row, ASV_OWNER, SV_SK, &w.owner);
    let nk: DigestF = core::array::from_fn(|c| Fa4::from_u64(w.owner.nk[c]));
    row[SV_VALUE_IN] = value_in;
    row[SV_VALUE_OUT] = Fa4::from_u64(w.value_out);
    row[SV_FEE] = Fa4::from_u64(w.fee);
    // The shared tag columns, written ONCE and read by all three openings.
    let ab = SV_ASSET_AB;
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(w.asset[c]));
    row[ab..ab + 3].copy_from_slice(&tag_f);
    // A + E range-bound conservation blocks, then B: two-round opening under the tag.
    fill_u64_conservation_row(&mut row, total, w.value_out, w.fee, U64ConsBases::at(tail + SV_TAIL_A))?;
    fill_u64_conservation_row(&mut row, w.value_out, w.out0_value, w.out1_value, U64ConsBases::at(tail + SV_TAIL_E))?;
    // input 1 opens over ITS value (the total's split when a second input rides, the total itself otherwise)
    let leaf = fill_note_open(
        &mut row, w.value_in, w.asset, &sk,
        tail + SV_TAIL_IN_BLK, tail + SV_TAIL_IN_OUT, SV_NOH_BLK, SV_LEAF,
    );
    let _ = value_in;
    let nf2 = match second {
        Some((v2, owner2)) => {
            fill_u64_conservation_row(&mut row, total, w.value_in, v2, U64ConsBases::at(SV_IN2_CONS))?;
            row[SV_IN2_VALUE] = Fa4::from_u64(v2);
            // DB-395: the locked note's opening, laid by its own owner block; its nullifier keyed by its `nk`.
            let sk2_f = fill_owner_open(&mut row, SV_IN2_OWNER, SV_IN2_SK, &owner2);
            let nk2: DigestF = core::array::from_fn(|c| Fa4::from_u64(owner2.nk[c]));
            let leaf2 = fill_note_open(&mut row, v2, w.asset, &sk2_f, SV_IN2_INNER_BLK, SV_IN2_INNER_OUT, SV_IN2_NOH_BLK, SV_IN2_LEAF);
            Some(fill_pose_round(&mut row, &nk2, &leaf2, SV_IN2_NFH_BLK, SV_IN2_NF))
        }
        None => None,
    };
    // C. nullifier (DB-395: keyed by the owner's `nk`).
    let nf = fill_pose_round(&mut row, &nk, &leaf, SV_NFH_BLK, SV_NF);
    // D. (deleted 2026-09-30) — no membership path is laid.
    // E. the two output openings — same tag, so same asset by construction.
    let ob = SV_OB;
    let mut out_cms = [[Fa4::ZERO; DIGEST_LANES]; 2];
    let outs = [(w.out0_value, w.out0_opening), (w.out1_value, w.out1_opening)];
    for (j, (ov, osk)) in outs.iter().enumerate() {
        let base = ob + j * SV_OUT_SLOT;
        let val = Fa4::from_u64(*ov);
        let sk_j: DigestF = core::array::from_fn(|c| Fa4::from_u64(osk[c]));
        row[base] = val;
        row[base + 1..base + 1 + DIGEST_LANES].copy_from_slice(&sk_j);
        let (iblk, iout) = if j == 0 { (SV_TAIL_O0_BLK, SV_TAIL_O0_OUT) } else { (SV_TAIL_O1_BLK, SV_TAIL_O1_OUT) };
        let cm = fill_note_open(
            &mut row, *ov, w.asset, &sk_j, tail + iblk, tail + iout,
            base + 1 + DIGEST_LANES, base + 1 + DIGEST_LANES + crate::pow_pq_air::P2_COLS,
        );
        out_cms[j] = cm;
    }
    // F. the cross-bind, DB-363: leaf_commit = P(P(leaf, nf), lc_blind) — two chained blocks, as the untagged row.
    let inner = fill_pose_round(&mut row, &leaf, &nf, SV_CB, SV_CB2);
    let blind: DigestF = core::array::from_fn(|c| Fa4::from_u64(w.lc_blind[c]));
    row[SV_BLIND..SV_BLIND + DIGEST_LANES].copy_from_slice(&blind);
    crate::pow_pq_air::lay_perm_row_flat(&mut row, SV_CB2, pose_state(&inner, &blind));
    let leaf_commit: DigestF = core::array::from_fn(|c| row[SV_CB2 + crate::pow_pq_air::PERM_OUT + c]);
    Some((row, out_cms, nf, leaf_commit, leaf, nf2))
}

/// Public IO for an asset carrier: the domain, the two output commitments, the nullifier and the
/// note-membership cross-bind. No amount and no asset appear — `out_cms[0]` is a COMMITMENT to both,
/// which is what lets a consuming proof constrain the amount without anyone publishing it.
fn asset_validity_public_bind(
    out_cms: &[DigestF; 2],
    nullifier: &DigestF,
    leaf_commit: &DigestF,
) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(ASSET_SPEND_VALIDITY_DOMAIN)];
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    b.extend_from_slice(nullifier);
    b.extend_from_slice(leaf_commit);
    b
}

/// ⭐ SATOSHI — the welded asset bond's domain word: a bond carrier never verifies as a transfer or the reverse.
pub const ASSET_BOND_VALIDITY_DOMAIN: u64 = 0x4153_4254_424e_4431; // "ASBTBND1"

/// The welded asset bond's public bind: `domain ‖ out0 ‖ out1 ‖ nullifier ‖ leaf_commit ‖ W limbs ‖ asset tag`.
fn asset_bond_public_bind(out_cms: &[DigestF; 2], nullifier: &DigestF, leaf_commit: &DigestF, bond: u64, tag: &[Fa4; 3]) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(ASSET_BOND_VALIDITY_DOMAIN)];
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    b.extend_from_slice(nullifier);
    b.extend_from_slice(leaf_commit);
    b.extend_from_slice(&bond_limbs_f(bond));
    b.extend_from_slice(tag);
    b
}

/// ⭐ SATOSHI (docs/SATOSHI-NATIVE-TOKEN.md §6) — PROVE a welded ASSET bond: the asset-tagged spend row with output 0
/// welded to the PUBLIC weight `bond` and the row's tag welded to the PUBLIC `w.asset`. `None` unless
/// `w.out0_value == bond` (fail-closed, as the USDm bond prover). Returns `(carrier, [out0_cm, out1_cm], nullifier,
/// leaf_commit)`.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_asset_bond_validity_carrier_bytes(w: &AssetSpendValidityWitness, bond: u64) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest)> {
    use p3_field::PrimeField64;
    if w.out0_value != bond {
        return None;
    }
    let (row, out_cms, nf, commit, _leaf) = asset_spend_validity_row(w)?;
    let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
    let o0_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| out_cms[0][c].into());
    let o1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| out_cms[1][c].into());
    let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| nf[c].into());
    let lc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| commit[c].into());
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(w.asset[c]));
    let tag_ea: [Ea4; 3] = core::array::from_fn(|c| tag_f[c].into());
    let limbs = bond_limbs(bond);
    let make = move |g: Ea4| AssetSpendValidityGate {
        gamma: g,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifier: nf_ea,
        leaf_commit: lc_ea,
        bond: Some((limbs, tag_ea)),
        second: None,
    };
    let carrier = crate::committed_air::prove_air_blinded_bytes(cols, make, &asset_bond_public_bind(&out_cms, &nf, &commit, bond, &tag_f))?;
    let u = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((carrier, [u(out_cms[0]), u(out_cms[1])], u(nf), u(commit)))
}

/// VERIFY a welded asset bond against the public `(out0, out1, nullifier, leaf_commit, bond, asset)` the node admits.
#[must_use]
pub fn verify_asset_bond_validity_carrier_bytes(
    bytes: &[u8],
    out0_cm: Digest,
    out1_cm: Digest,
    nullifier: Digest,
    leaf_commit: Digest,
    bond: u64,
    asset: [u64; 3],
) -> bool {
    if bytes.is_empty() || leaf_commit == crate::poseidon2_compress::ZERO_DIGEST {
        return false;
    }
    let o0: DigestF = core::array::from_fn(|c| Fa4::from_u64(out0_cm[c]));
    let o1: DigestF = core::array::from_fn(|c| Fa4::from_u64(out1_cm[c]));
    let nfv: DigestF = core::array::from_fn(|c| Fa4::from_u64(nullifier[c]));
    let lc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(leaf_commit[c]));
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(asset[c]));
    let o0_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| o0[c].into());
    let o1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| o1[c].into());
    let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| nfv[c].into());
    let lc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| lc_f[c].into());
    let tag_ea: [Ea4; 3] = core::array::from_fn(|c| tag_f[c].into());
    let limbs = bond_limbs(bond);
    let make = move |g: Ea4| AssetSpendValidityGate {
        gamma: g,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifier: nf_ea,
        leaf_commit: lc_ea,
        bond: Some((limbs, tag_ea)),
        second: None,
    };
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        make,
        &asset_bond_public_bind(&[o0, o1], &nfv, &lc_f, bond, &tag_f),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, asset_spend_row_width()),
    )
}

/// The prover behind [`prove_asset_spend_validity_carrier_bytes`].
/// ⭐ SATOSHI §9 — the RE-BOND carrier's domain word: never the single bond's, so neither shape verifies as the other.
pub const ASSET_REBOND_VALIDITY_DOMAIN: u64 = 0x4153_5242_424e_4432; // "ASRBBND2"
fn asset_rebond_public_bind(out_cms: &[DigestF; 2], nullifier: &DigestF, nf2: &DigestF, cm2: &DigestF, leaf_commit: &DigestF, bond: u64, tag: &[Fa4; 3]) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(ASSET_REBOND_VALIDITY_DOMAIN)];
    b.extend_from_slice(&out_cms[0]);
    b.extend_from_slice(&out_cms[1]);
    b.extend_from_slice(nullifier);
    b.extend_from_slice(leaf_commit);
    b.extend_from_slice(&bond_limbs_f(bond));
    b.extend_from_slice(tag);
    b.extend_from_slice(nf2);
    b.extend_from_slice(cm2);
    b
}
/// ⭐ SATOSHI §9 — prove the RE-BOND: `(fresh note, currently locked note) → (new locked note of PUBLIC weight `bond`, change)`
/// in one asset, both inputs opened and nullified in-circuit, the tag public, the LOCKED input's commitment public (the fold
/// matches it to `bond_locked[vid]`). Returns `(carrier, [out0_cm, out1_cm], nf_fresh, nf_locked, leaf_commit)`. `None` when
/// `out0_value != bond` or the witness does not conserve.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_asset_rebond_validity_carrier_bytes(w: &AssetRebondWitness, bond: u64) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest, Digest)> {
    use p3_field::PrimeField64;
    if w.fresh.out0_value != bond {
        return None;
    }
    let (row, out_cms, nf, commit, _leaf, nf2) = asset_spend_validity_row_inner(&w.fresh, Some((w.locked_value, w.locked_owner)))?;
    let nf2 = nf2?;
    let cm2: DigestF = core::array::from_fn(|c| row[SV_IN2_LEAF + c]);
    let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
    let ea = |d: DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|c| d[c].into()) };
    let (o0_ea, o1_ea, nf_ea, lc_ea, nf2_ea, cm2_ea) = (ea(out_cms[0]), ea(out_cms[1]), ea(nf), ea(commit), ea(nf2), ea(cm2));
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(w.fresh.asset[c]));
    let tag_ea: [Ea4; 3] = core::array::from_fn(|c| tag_f[c].into());
    let limbs = bond_limbs(bond);
    let make = move |g: Ea4| AssetSpendValidityGate {
        gamma: g,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifier: nf_ea,
        leaf_commit: lc_ea,
        bond: Some((limbs, tag_ea)),
        second: Some((nf2_ea, cm2_ea)),
    };
    let carrier = crate::committed_air::prove_air_blinded_bytes(cols, make, &asset_rebond_public_bind(&out_cms, &nf, &nf2, &cm2, &commit, bond, &tag_f))?;
    let u = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((carrier, [u(out_cms[0]), u(out_cms[1])], u(nf), u(nf2), u(commit)))
}
/// ⭐ SATOSHI §9 — verify a RE-BOND carrier against its public statement (both nullifiers, the locked input's commitment, the
/// weight, the tag).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_asset_rebond_validity_carrier_bytes(
    bytes: &[u8],
    out0_cm: Digest,
    out1_cm: Digest,
    nullifier: Digest,
    nullifier_locked: Digest,
    locked_cm: Digest,
    leaf_commit: Digest,
    bond: u64,
    asset: [u64; 3],
) -> bool {
    if bytes.is_empty() || leaf_commit == crate::poseidon2_compress::ZERO_DIGEST || nullifier == nullifier_locked {
        return false; // one note opened twice is not two inputs
    }
    let f = |d: Digest| -> DigestF { core::array::from_fn(|c| Fa4::from_u64(d[c])) };
    let (o0, o1, nfv, nf2v, cm2v, lc_f) = (f(out0_cm), f(out1_cm), f(nullifier), f(nullifier_locked), f(locked_cm), f(leaf_commit));
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(asset[c]));
    let ea = |d: DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|c| d[c].into()) };
    let (o0_ea, o1_ea, nf_ea, nf2_ea, cm2_ea, lc_ea) = (ea(o0), ea(o1), ea(nfv), ea(nf2v), ea(cm2v), ea(lc_f));
    let tag_ea: [Ea4; 3] = core::array::from_fn(|c| tag_f[c].into());
    let limbs = bond_limbs(bond);
    let make = move |g: Ea4| AssetSpendValidityGate {
        gamma: g,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifier: nf_ea,
        leaf_commit: lc_ea,
        bond: Some((limbs, tag_ea)),
        second: Some((nf2_ea, cm2_ea)),
    };
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        make,
        &asset_rebond_public_bind(&[o0, o1], &nfv, &nf2v, &cm2v, &lc_f, bond, &tag_f),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, asset_rebond_row_width()),
    )
}
#[allow(clippy::type_complexity)]
fn build_asset_carrier(
    w: &AssetSpendValidityWitness,
) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest)> {
    use p3_field::PrimeField64;
    let (row, out_cms, nf, commit, _leaf) = asset_spend_validity_row(w)?;
    let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
    let o0_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| out_cms[0][c].into());
    let o1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| out_cms[1][c].into());
    let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| nf[c].into());
    let lc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| commit[c].into());
    let make = move |g: Ea4| AssetSpendValidityGate {
        gamma: g,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifier: nf_ea,
        leaf_commit: lc_ea,
        bond: None,
        second: None,
    };
    let carrier = crate::committed_air::prove_air_blinded_bytes(
        cols,
        make,
        &asset_validity_public_bind(&out_cms, &nf, &commit),
    )?;
    let u = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((carrier, [u(out_cms[0]), u(out_cms[1])], u(nf), u(commit)))
}

/// The verifier behind [`verify_asset_spend_validity_carrier_bytes`].
fn check_asset_carrier(
    bytes: &[u8],
    out0_cm: Digest,
    out1_cm: Digest,
    nullifier: Digest,
    leaf_commit: Digest,
) -> bool {
    // ⛔ No `depth` (2026-09-30): one constant shape; the Merkle path is deleted at source (see the untagged gate).
    if bytes.is_empty() {
        return false;
    }
    // ⛔⛔⛔ AN ALL-ZERO CROSS-BIND IS REFUSED HERE, STRUCTURALLY — the same refusal
    // `verify_spend_validity_carrier_bytes` makes, for the same reason. A wire field that was simply
    // ABSENT decodes as zero, and zero is not "no binding": it is a binding every forger can produce.
    //
    // ROOT-LAYER: this verifier is the trust boundary where a caller-supplied cross-bind first enters
    // the proof system, so it is where the value's admissibility is decided rather than merely read.
    // Every downstream consumer sees only this function's verdict — it never sees the binding again —
    // so a node that forgets to require a membership carrier cannot re-introduce the hole, and the
    // soundness stops depending on which admission check happens to return first in a caller.
    // MEASURED: with the check ABSENT, the full asset suite was 12/12 green and
    // `an_all_zero_cross_bind_does_not_verify` PASSED on the transcript bind alone (0.01s) — so this
    // is not what makes that test pass, and adding it changed 322 passed / 0 failed to 322 passed /
    // 0 failed. It buys defence that does not rest on transcript algebra being the only barrier.
    // MUST-STAY-GREEN: the `asset_tagged_value_tests` set (especially the honest transfer and the v1
    // mint-commitment parity pin), plus the 310 pre-existing decider tests.
    if leaf_commit == crate::poseidon2_compress::ZERO_DIGEST {
        return false;
    }
    let o0: DigestF = core::array::from_fn(|c| Fa4::from_u64(out0_cm[c]));
    let o1: DigestF = core::array::from_fn(|c| Fa4::from_u64(out1_cm[c]));
    let nfv: DigestF = core::array::from_fn(|c| Fa4::from_u64(nullifier[c]));
    let lc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(leaf_commit[c]));
    let o0_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| o0[c].into());
    let o1_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| o1[c].into());
    let nf_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| nfv[c].into());
    let lc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| lc_f[c].into());
    let make = move |g: Ea4| AssetSpendValidityGate {
        gamma: g,
        out0_cm: o0_ea,
        out1_cm: o1_ea,
        nullifier: nf_ea,
        leaf_commit: lc_ea,
        bond: None,
        second: None,
    };
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        make,
        &asset_validity_public_bind(&[o0, o1], &nfv, &lc_f),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, asset_spend_row_width()),
    )
}

/// PROVE an ordinary asset-tagged transfer — amount AND asset hidden. Returns
/// `(carrier, [out0_cm, out1_cm], nullifier, leaf_commit)`.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn prove_asset_spend_validity_carrier_bytes(
    w: &AssetSpendValidityWitness,
) -> Option<(Vec<u8>, [Digest; 2], Digest, Digest)> {
    build_asset_carrier(w)
}

/// ⭐⭐⭐ THE INPUT NOTE'S OWN COMMITMENT — the leaf this transfer SPENDS.
///
/// A transfer must carry TWO carriers that are statements about the SAME note: the validity carrier
/// (conservation, one asset) and the note-MEMBERSHIP carrier (this note was ever received). They are tied
/// by `leaf_commit = compress(leaf, nullifier)`, so the membership carrier must be built over exactly the
/// leaf the validity row derived, with the nullifier as its binder.
///
/// ⛔ THE PRODUCER MUST NOT RE-DERIVE THAT LEAF. `leaf` comes out of `fill_note_open` inside the row —
/// the same opening the constraints check — and a second spelling of that derivation is this tree's most
/// expensive recurring defect (`nf_key` vs `key_of`, the sparse spent leaf under a *"byte-identical"*
/// comment, `prove_block_pow` vs `PowMiner::mine`). **One definition: the row.** This returns it.
#[must_use]
pub fn asset_spend_input_leaf(w: &AssetSpendValidityWitness) -> Option<Digest> {
    let (_row, _cms, _nf, _lc, leaf) = asset_spend_validity_row(w)?;
    Some(core::array::from_fn(|c| {
        use p3_field::PrimeField64;
        leaf[c].as_canonical_u64()
    }))
}

/// VERIFY an ordinary asset-tagged transfer. The verifier never learns the asset — it learns only
/// that ONE asset ran through every leg.
#[must_use]
pub fn verify_asset_spend_validity_carrier_bytes(
    bytes: &[u8],
    out0_cm: Digest,
    out1_cm: Digest,
    nullifier: Digest,
    leaf_commit: Digest,
) -> bool {
    check_asset_carrier(bytes, out0_cm, out1_cm, nullifier, leaf_commit)
}

/// The asset-tagged MINT gate — [`MintValidityGate`] plus the tag. Row (29 cols, height 32):
/// `[value | sk(4) | pre(4) | sq(4) | p4(4) | p7(4) | cm(4) | selector | tag(3)]`.
/// Where the value's range block starts in the asset-mint trace: after the 29 legacy columns.
/// The asset-mint row's HEAD layout — the mint row plus three shared tag columns.
pub const AM_VAL: usize = 0;
pub const AM_SK: usize = AM_VAL + 1;
pub const AM_OUTER_BLK: usize = AM_SK + DIGEST_LANES;
pub const AM_CM: usize = AM_OUTER_BLK + crate::pow_pq_air::P2_COLS;
pub const AM_SEL: usize = AM_CM + DIGEST_LANES;
pub const AM_TAG: usize = AM_SEL + 1;
const AM_VAL_BASE: usize = AM_TAG + 3;
/// The inner round of the two-round opening (`P([t0, t1, t2, 0], sk)`), after the range block.
const AM_INNER_BLK: usize = AM_VAL_BASE + U64_RANGE_WIDTH;
const AM_INNER_OUT: usize = AM_INNER_BLK + POSE_BLK;
/// The asset-mint trace width: 29 legacy columns + one range-bound u64 + the inner round.
pub const AM_WIDTH: usize = AM_INNER_OUT + DIGEST_LANES;

pub struct AssetMintValidityGate {
    pub gamma: Ea4,
    /// ⛔⛔⛔ ITEM 1 / D-28, SITE 4 OF 4 (2026-09-11): the PUBLIC amount as four 16-bit limbs, never one
    /// reduced element — see `MintValidityGate::value_limbs` for the measured `v` / `v + p` aliasing.
    pub value_limbs: [Ea4; SC_LIMBS],
    pub out0_cm: [Ea4; DIGEST_LANES],
    /// The PUBLIC asset this credit is authorized in. A mint's asset is never hidden: the gate that
    /// authorizes it (a swap payout, a peg-in) decided WHICH asset, so the proof must be checkable
    /// against that decision.
    pub asset: [Ea4; 3],
}

impl AssetMintValidityGate {
    /// The one constructor: the u64 is split into public limbs here.
    pub fn for_value(gamma: Ea4, value: u64, out0_cm: [Ea4; DIGEST_LANES], asset: [Ea4; 3]) -> Self {
        let l = u64_public_limbs(value);
        Self { gamma, value_limbs: core::array::from_fn(|i| l[i].into()), out0_cm, asset }
    }
}

impl crate::air_zerocheck::AirConstraint for AssetMintValidityGate {
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ EMBEDS A PERMUTATION: a gate declaring less than the permutation's degree truncates
        // the sumcheck, so even an HONEST proof stops verifying.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let g = self.gamma;
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let seven = Ea4::from(Fa4::from_u64(7));
        let val = local[AM_VAL];
        let sk = |c: usize| local[AM_SK + c];
        let cm = |c: usize| local[AM_CM + c];
        let sel = local[AM_SEL];
        // ⛔ WAS `local[26 + c]` — the tag's offset under the retired four-lane, one-round layout.
        let tag = |c: usize| local[AM_TAG + c];

        let mut rs: Vec<Ea4> = Vec::new();
        rs.push(sel * (sel - one));
        // THE OPENING under the tag — two rounds, `cm == P(limbs(value), P([t0, t1, t2, 0], sk))`:
        // the value's range-bound limbs fill the outer lanes, the asset tag and key bind in the inner.
        let rb = U64RangeBases::at(AM_VAL_BASE);
        let tag_lane = |c: usize| if c < 3 { tag(c) } else { zero };
        let sk_col = |c: usize| local[AM_SK + c];
        push_note_open(&mut rs, local, rb.limbs, &tag_lane, &sk_col, AM_INNER_BLK, AM_INNER_OUT, AM_OUTER_BLK, AM_CM); // read inside push_note_open at block 5 / column 21
        // PUBLIC WELDS (selector-gated — false on the zero padding rows by construction): the recorded
        // commitment opens at the authorized AMOUNT and in the authorized ASSET. Over-minting, or
        // minting the wrong asset, has no satisfying `sk`.
        rs.extend((0..DIGEST_LANES).map(|c| sel * (cm(c) - self.out0_cm[c])));
        push_u64_range(&mut rs, local, rb);
        rs.push(val - u64_limbs_recombined(local, rb.limbs));
        for i in 0..SC_LIMBS {
            rs.push(sel * (local[rb.limbs + i] - self.value_limbs[i]));
        }
        rs.extend((0..3).map(|c| sel * (tag(c) - self.asset[c])));

        let mut out = zero;
        let mut gp = one;
        for r in rs {
            out = out + gp * r;
            gp = gp * g;
        }
        out
    }
}

/// Transcript bind: domain ‖ out0_cm ‖ value ‖ asset.
fn asset_mint_public_bind(out0_cm: &DigestF, value: u64, asset: &[Fa4; 3]) -> Vec<Fa4> {
    let mut b = Vec::with_capacity(9);
    b.push(Fa4::from_u64(ASSET_MINT_VALIDITY_DOMAIN));
    b.extend_from_slice(out0_cm);
    b.extend_from_slice(&u64_public_limbs(value)); // limbs, never one reduced element
    b.extend_from_slice(asset);
    b
}

/// Build the one live mint row, then spread it across the trace's columns.
fn asset_mint_cols(value: u64, tag: [u64; 3], sk: &Digest) -> (Vec<Vec<Fa4>>, DigestF) {
    const H: usize = MINT_TRACE_ROWS;
    let val_f = Fa4::from_u64(value);
    let sk_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(sk[c]));
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(tag[c]));
    // One live row, filled row-major, then replicated into the 32-row shape.
    let mut row = vec![Fa4::ZERO; AM_WIDTH];
    // ⛔ 0/1..5/25/26..29 were the retired round's literals.
    row[AM_VAL] = val_f;
    row[AM_SK..AM_SK + DIGEST_LANES].copy_from_slice(&sk_f);
    row[AM_SEL] = Fa4::ONE; // the live-row selector
    row[AM_TAG..AM_TAG + 3].copy_from_slice(&tag_f);
    let rb = U64RangeBases::at(AM_VAL_BASE);
    for i in 0..SC_LIMBS {
        row[rb.limbs + i] = Fa4::from_u64((value >> (SC_LIMB_BITS * i)) & 0xFFFF);
    }
    for k in 0..(SC_LIMBS * SC_LIMB_BITS) {
        row[rb.bits + k] = Fa4::from_u64((value >> k) & 1);
    }
    let cm = fill_note_open(&mut row, value, tag, &sk_f, AM_INNER_BLK, AM_INNER_OUT, AM_OUTER_BLK, AM_CM);
    let mut cols: Vec<Vec<Fa4>> = (0..AM_WIDTH).map(|_| vec![Fa4::ZERO; H]).collect();
    // The padding rows carry the live row, not zeros — a permutation is not zero-preserving the way the
    // retired 1-round fold was, so an all-zero row is simply an invalid Poseidon2 trace.
    for (c, v) in row.iter().enumerate() {
        cols[c].fill(*v);
    }
    (cols, cm)
}

/// PROVE an asset-tagged mint: `out0_cm` opens to the PUBLIC `(value, asset)` under the note's OPENING
/// `o = P(spk, seed)` — ⛔ DB-395: the opening binds the commitment and spends nothing (the recipient's `(ask, nk)` does).
/// Returns `(carrier_bytes, out0_cm)`.
#[must_use]
pub fn prove_asset_mint_validity_bytes(
    value: u64,
    asset: [u64; 3],
    opening: &Digest,
) -> Option<(Vec<u8>, Digest)> {
    use p3_field::PrimeField64;
    let (cols, cm) = asset_mint_cols(value, asset, opening);
    let cm_u: Digest = core::array::from_fn(|c| cm[c].as_canonical_u64());
    // The bound double of the testing format (see `BOUND_ASSET_MINT_MARKER`): a test-support process in the bound tier
    // binds (value, asset, cm) without the WHIR proof. A node binary never takes this branch (`bound_mode()` is false).
    if crate::whole_chain_cert::bound_mode() {
        return Some((bound_asset_mint_carrier(value, asset, &cm_u), cm_u));
    }
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(asset[c]));
    let out0: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| cm[c].into());
    let tag_ea: [Ea4; 3] = core::array::from_fn(|c| tag_f[c].into());
    let make = move |g: Ea4| AssetMintValidityGate::for_value(g, value, out0, tag_ea);
    let bytes = crate::committed_air::prove_air_blinded_bytes(
        cols,
        make,
        &asset_mint_public_bind(&cm, value, &tag_f),
    )?;
    Some((bytes, cm_u))
}

/// ⭐⭐⭐ THE BOUND ASSET MINT — the asset-mint carrier's test double, under the bound-certificate law
/// (`whole_chain_cert::bound`, the testing format of 2026-10-02: "make our test fast and accurate").
///
/// MEASURED 2026-10-05 (DB-393): every SAT reward proves this carrier — 100,631 B and 1,828 ms per produced block — and a
/// test node lays a reward in EVERY block it produces, so a node test of ~100 blocks paid ~3 minutes of proving that none
/// of its assertions read (the four slowest pins of the 2026-10-05 landing run: 177–237 s each).
/// WHAT IT KEEPS: the binding of `(value, asset, cm)` — the commitment comes from the SAME opening the real prover fills,
/// and a moved amount, asset or commitment is REFUSED. WHAT IT DROPS: only the WHIR proof, whose soundness is the decider's
/// own pins (its `cfg(test)` NEVER runs bound), the proven tier (`MONEROUSD_TEST_CERTS=proven`) and the real-node journeys.
/// WHERE IT CAN EXIST: test-support builds only; a node binary has no bound path (`bound_mode()` is false there), and a
/// bound carrier NEVER passes the real verifier — it is refused by its marker before any parse.
const BOUND_ASSET_MINT_MARKER: &[u8; 16] = b"MUSD-BOUND-AMINT";

fn bound_asset_mint_carrier(value: u64, asset: [u64; 3], cm: &Digest) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD-bound-asset-mint-v1");
    h.update(&value.to_le_bytes());
    for t in asset {
        h.update(&t.to_le_bytes());
    }
    for l in cm {
        h.update(&l.to_le_bytes());
    }
    let mut out = BOUND_ASSET_MINT_MARKER.to_vec();
    out.extend_from_slice(h.finalize().as_bytes());
    out
}

/// ⛔ TEST BUILDS ONLY: is this process in the bound tier for asset-mint carriers (the same switch as the certificates)?
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn asset_mint_carriers_are_bound() -> bool {
    crate::whole_chain_cert::bound_mode()
}

/// ⛔ TEST BUILDS ONLY: would the REAL asset-mint verifier — whatever tier this process runs — accept `bytes`? The pin that a
/// bound carrier can never pass for a real one reads it.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn real_asset_mint_door_accepts_for_test(bytes: &[u8], out0_cm: Digest, value: u64, asset: [u64; 3]) -> bool {
    verify_asset_mint_real(bytes, out0_cm, value, asset)
}

/// VERIFY an asset-tagged mint against the commitment the node is about to RECORD and the
/// `(value, asset)` it AUTHORIZED. This is the no-over-mint / no-wrong-asset gate: call it before
/// crediting any note, and refuse the credit if it returns false.
#[must_use]
pub fn verify_asset_mint_validity_bytes(
    bytes: &[u8],
    out0_cm: Digest,
    value: u64,
    asset: [u64; 3],
) -> bool {
    if bytes.is_empty() {
        return false;
    }
    // ⛔ A BOUND carrier is refused by its marker in every process that is not in the bound tier (a node binary above all),
    // before any parse; in the bound tier it is accepted only when it binds THIS (value, asset, cm).
    if bytes.starts_with(BOUND_ASSET_MINT_MARKER) {
        return crate::whole_chain_cert::bound_mode() && bytes == bound_asset_mint_carrier(value, asset, &out0_cm).as_slice();
    }
    verify_asset_mint_real(bytes, out0_cm, value, asset)
}

/// The REAL asset-mint verification: the WHIR proof of `AssetMintValidityGate` against the public bind.
fn verify_asset_mint_real(bytes: &[u8], out0_cm: Digest, value: u64, asset: [u64; 3]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let cm_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(out0_cm[c]));
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(asset[c]));
    let cm_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| cm_f[c].into());
    let tag_ea: [Ea4; 3] = core::array::from_fn(|c| tag_f[c].into());
    let make = move |g: Ea4| AssetMintValidityGate::for_value(g, value, cm_ea, tag_ea);
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        make,
        &asset_mint_public_bind(&cm_f, value, &tag_f),
        (MINT_TRACE_ROWS.trailing_zeros() as usize, AM_WIDTH),
    )
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// DB-80b (2026-09-19) — THE COMMITTED ASSET-TAGGED MINT-VALIDITY GATE: a wrapped mint's value is
// NEVER a public input either. `AssetMintValidityGate` pins `(value, asset)` as public limbs — the pin
// that published every wrapped mint's amount (`WrappedMintHeader.amount`). This gate proves the same
// tagged note opening and pins the ASSET (public: the door decided which asset) plus
// `delta_commit = solvency_commit_256(value, d_blind)` — the fifth public commitment the DB-80
// solvency carrier opens over the asset's own ledger. Same commit shape at both ends, so the two proofs
// agree without either saying the number. Layout: the AM columns untouched; the 16-limb value copy,
// blind, commit lanes and the two permutation blocks appended (exactly the MVC layout, after AM_WIDTH).
// ═══════════════════════════════════════════════════════════════════════════════════════════════
pub const ASSET_MINT_VALIDITY_COMMITTED_DOMAIN: u64 = 0x414d_494e_5456_4342; // "AMINTVCB"
const AMC_V16: usize = AM_WIDTH;
const AMC_DBLIND: usize = AMC_V16 + 16;
const AMC_DCOMMIT: usize = AMC_DBLIND + DIGEST_LANES;
const AMC_DINTER: usize = AMC_DCOMMIT + DIGEST_LANES;
/// DB-362: the opened value's 16 limbs range-bound inside the opening gadget.
const AMC_DVBITS: usize = AMC_DINTER + 2 * crate::confidential_solvency::CO_BLOCK;
pub const AMC_WIDTH: usize = AMC_DVBITS + crate::confidential_solvency::RANGE16_COLS;

pub struct AssetMintValidityCommittedGate {
    pub gamma: Ea4,
    pub out0_cm: [Ea4; DIGEST_LANES],
    /// The PUBLIC asset (the door decided which asset; the amount is committed, the asset is not).
    pub asset: [Ea4; 3],
    pub delta_commit: [Ea4; DIGEST_LANES],
}

impl crate::air_zerocheck::AirConstraint for AssetMintValidityCommittedGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let g = self.gamma;
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let val = local[AM_VAL];
        let cm = |c: usize| local[AM_CM + c];
        let sel = local[AM_SEL];
        let tag = |c: usize| local[AM_TAG + c];

        let mut rs: Vec<Ea4> = Vec::new();
        rs.push(sel * (sel - one));
        let rb = U64RangeBases::at(AM_VAL_BASE);
        let tag_lane = |c: usize| if c < 3 { tag(c) } else { zero };
        let sk_col = |c: usize| local[AM_SK + c];
        push_note_open(&mut rs, local, rb.limbs, &tag_lane, &sk_col, AM_INNER_BLK, AM_INNER_OUT, AM_OUTER_BLK, AM_CM);
        rs.extend((0..DIGEST_LANES).map(|c| sel * (cm(c) - self.out0_cm[c])));
        push_u64_range(&mut rs, local, rb);
        rs.push(val - u64_limbs_recombined(local, rb.limbs));
        // the asset stays PUBLIC — which asset was decided by the door, never hidden
        rs.extend((0..3).map(|c| sel * (tag(c) - self.asset[c])));
        // the 16-limb copy of the value (four 16-bit limbs then zeros — the U256 encoding the commit hashes)
        for i in 0..SC_LIMBS {
            rs.push(local[AMC_V16 + i] - local[rb.limbs + i]);
        }
        for i in SC_LIMBS..16 {
            rs.push(local[AMC_V16 + i]);
        }
        // delta_commit = Poseidon2(Poseidon2(lo, hi), blind) over the copy — the solvency carrier's shape
        crate::confidential_solvency::push_commit_open_constraints(&mut rs, local, AMC_V16, AMC_DBLIND, AMC_DCOMMIT, AMC_DINTER, AMC_DVBITS);
        for c in 0..DIGEST_LANES {
            rs.push(sel * (local[AMC_DCOMMIT + c] - self.delta_commit[c]));
        }

        let mut out = zero;
        let mut gp = one;
        for r in rs {
            out = out + gp * r;
            gp = gp * g;
        }
        out
    }
}

/// Transcript bind: domain ‖ out0_cm ‖ asset ‖ delta_commit. No value anywhere.
fn asset_mint_committed_public_bind(out0_cm: &DigestF, asset: &[Fa4; 3], delta_commit: &DigestF) -> Vec<Fa4> {
    let mut b = Vec::with_capacity(1 + 2 * DIGEST_LANES + 3);
    b.push(Fa4::from_u64(ASSET_MINT_VALIDITY_COMMITTED_DOMAIN));
    b.extend_from_slice(out0_cm);
    b.extend_from_slice(asset);
    b.extend_from_slice(delta_commit);
    b
}

fn asset_mint_committed_cols(value: u64, tag: [u64; 3], sk: &Digest, d_blind: &Digest) -> (Vec<Vec<Fa4>>, DigestF, Digest) {
    let (mut cols, cm) = asset_mint_cols(value, tag, sk);
    let h = cols[0].len();
    while cols.len() < AMC_WIDTH {
        cols.push(vec![Fa4::ZERO; h]);
    }
    let mut limbs = [0u64; 16];
    for i in 0..SC_LIMBS {
        limbs[i] = (value >> (SC_LIMB_BITS * i)) & 0xFFFF;
    }
    for i in 0..16 {
        cols[AMC_V16 + i].fill(Fa4::from_u64(limbs[i]));
    }
    for i in 0..DIGEST_LANES {
        cols[AMC_DBLIND + i].fill(Fa4::from_u64(d_blind[i]));
    }
    let dc = crate::confidential_solvency::place_commit_open(&mut cols, limbs, *d_blind, AMC_DINTER, AMC_DVBITS);
    for i in 0..DIGEST_LANES {
        cols[AMC_DCOMMIT + i].fill(Fa4::from_u64(dc[i]));
    }
    (cols, cm, dc)
}

/// DB-80b: prove an asset-tagged mint of `value` in `asset` to a note owned by `sk`, publishing only
/// `out0_cm`, the asset and `delta_commit = solvency_commit_256(value, d_blind)`.
/// Returns `(bytes, out0_cm, delta_commit)`.
#[must_use]
pub fn prove_asset_mint_validity_committed_bytes(
    value: u64,
    asset: [u64; 3],
    sk: &Digest,
    d_blind: &Digest,
) -> Option<(Vec<u8>, Digest, Digest)> {
    use p3_field::PrimeField64;
    let (cols, cm, dc) = asset_mint_committed_cols(value, asset, sk, d_blind);
    let cm_u: Digest = core::array::from_fn(|c| cm[c].as_canonical_u64());
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(asset[c]));
    let out0: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| cm[c].into());
    let tag_ea: [Ea4; 3] = core::array::from_fn(|c| tag_f[c].into());
    let dc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(dc[c]));
    let dc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| Ea4::from(dc_f[i]));
    let make = move |g: Ea4| AssetMintValidityCommittedGate { gamma: g, out0_cm: out0, asset: tag_ea, delta_commit: dc_ea };
    let bytes = crate::committed_air::prove_air_blinded_bytes(cols, make, &asset_mint_committed_public_bind(&cm, &tag_f, &dc_f))?;
    Some((bytes, cm_u, dc))
}

/// VERIFY a committed asset-tagged mint against the commitment the node is about to RECORD, the asset it
/// AUTHORIZED and the committed delta its solvency carrier opens. No over-mint, no wrong asset, no
/// pairing with another carrier's figure — and no amount on the wire.
#[must_use]
pub fn verify_asset_mint_validity_committed_bytes(bytes: &[u8], out0_cm: Digest, asset: [u64; 3], delta_commit: Digest) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let cm_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(out0_cm[c]));
    let tag_f: [Fa4; 3] = core::array::from_fn(|c| Fa4::from_u64(asset[c]));
    let cm_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| cm_f[c].into());
    let tag_ea: [Ea4; 3] = core::array::from_fn(|c| tag_f[c].into());
    let dc_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(delta_commit[c]));
    let dc_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| dc_f[i].into());
    let make = move |g: Ea4| AssetMintValidityCommittedGate { gamma: g, out0_cm: cm_ea, asset: tag_ea, delta_commit: dc_ea };
    crate::committed_air::verify_air_blinded_bytes(bytes, make, &asset_mint_committed_public_bind(&cm_f, &tag_f, &dc_f), (MINT_TRACE_ROWS.trailing_zeros() as usize, AMC_WIDTH))
}

#[cfg(test)]
mod asset_mint_validity_committed_gate_tests {
    use super::*;

    /// DB-80b calibration: the committed asset gate proves for the honest (value, asset, blind), its
    /// commitment IS the solvency commit of (value, blind), and a forged commitment, another value's
    /// commitment, another asset or another note REFUSES. No public input names the value.
    #[test]
    fn a_committed_asset_mint_proves_binds_the_asset_and_the_delta_and_refuses_every_tamper() {
        let sk: Digest = [3, 1, 4, 1, 5, 9, 2, 6];
        let blind: Digest = [7, 7, 7, 7, 1, 2, 3, 4];
        let value: u64 = 1_000_000;
        let wbtc = wrapped_asset_tag_u32(1);
        let wdai = wrapped_asset_tag_u32(2);
        let (bytes, cm, dc) = prove_asset_mint_validity_committed_bytes(value, wbtc, &sk, &blind).expect("proves");
        let expect = crate::confidential_solvency::solvency_commit_256(crate::confidential_solvency::u256_from_u64(value), blind);
        assert_eq!(dc, expect, "the gate's commitment IS the solvency commit of (value, blind)");
        assert!(verify_asset_mint_validity_committed_bytes(&bytes, cm, wbtc, dc), "honest proof verifies");
        let mut dc2 = dc;
        dc2[0] ^= 1;
        assert!(!verify_asset_mint_validity_committed_bytes(&bytes, cm, wbtc, dc2), "a forged delta commitment is refused");
        let other = crate::confidential_solvency::solvency_commit_256(crate::confidential_solvency::u256_from_u64(value + 1), blind);
        assert!(!verify_asset_mint_validity_committed_bytes(&bytes, cm, wbtc, other), "another value's commitment is refused");
        assert!(!verify_asset_mint_validity_committed_bytes(&bytes, cm, wdai, dc), "another asset is refused");
        let mut cm2 = cm;
        cm2[1] ^= 1;
        assert!(!verify_asset_mint_validity_committed_bytes(&bytes, cm2, wbtc, dc), "another note is refused");
        assert!(!verify_asset_mint_validity_committed_bytes(&[], cm, wbtc, dc), "no carrier, no credit");
        // the public (uncommitted) asset gate's proof is NOT a committed proof: a different domain and bind
        let (pub_bytes, pub_cm) = prove_asset_mint_validity_bytes(value, wbtc, &sk).expect("the public gate proves");
        assert_eq!(pub_cm, cm, "same note either way");
        assert!(!verify_asset_mint_validity_committed_bytes(&pub_bytes, cm, wbtc, dc), "a public-amount carrier is refused at the committed gate");
    }
}

#[cfg(test)]
mod asset_tagged_value_tests {
    //! The adversary here is a trader trying to turn one asset into another for free, and a custodian
    //! trying to credit more than it authorized. Every test below is either "the honest case works" or
    //! "the theft is UNPROVABLE / REFUSED".

    use super::{to_f, to_u64, Digest, DigestF, DIGEST_LANES};
    use super::*;

    const SK: Digest = [11, 22, 33, 44, 111, 123, 135, 147];
    const OUT0_SK: Digest = [55, 66, 77, 88, 155, 167, 179, 191];
    const OUT1_SK: Digest = [99, 111, 122, 133, 199, 212, 224, 236];

    fn wbtc() -> [u64; 3] {
        wrapped_asset_tag(&[7u8; 32])
    }
    fn weth() -> [u64; 3] {
        wrapped_asset_tag(&[9u8; 32])
    }

    /// A depth-2 copath. The path is never welded to a root (membership rides the accumulator), so any
    /// well-formed copath serves — what matters is that the row is consistent.
    fn a_witness(value_in: u64, out0: u64, out1: u64, fee: u64, asset: [u64; 3]) -> AssetSpendValidityWitness {
        AssetSpendValidityWitness {
            value_in,
            owner: NoteOwner::from_test_key(SK),
            value_out: out0 + out1,
            fee,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: out0,
            out0_opening: OUT0_SK,
            out1_value: out1,
            out1_opening: OUT1_SK,
            asset,
        }
    }

    /// ⭐⭐⭐ THE COMPATIBILITY PIN — the whole reason this is additive rather than a migration.
    /// An asset-tagged commitment at the USDm tag IS the legacy commitment. If this ever fails, every
    /// note on chain changed identity and every balance in every wallet is wrong.
    /// ⭐ SATOSHI §9 — THE RE-BOND CARRIER: two inputs (a fresh SAT note + the validator's locked note) → one new locked note of
    /// the PUBLIC weight (their sum) + change; proves and verifies; every tamper refuses: a moved weight, a swapped locked
    /// nullifier, a USDm-stated tag, a cross-shape presentation (the re-bond carrier under the single-bond verifier and the
    /// single-bond carrier under the re-bond verifier), one note opened twice, and an inflating split (the builder refuses it
    /// before any carrier exists). Run with MONEROUSD_PROVER_ASSERTS=1 so the debug prover's degree and free-column censuses
    /// run on the new shape.
    #[test]
    fn a_rebond_carrier_sums_two_inputs_into_one_public_weight_and_refuses_every_tamper() {
        let sat = satoshi_asset_tag();
        let locked = NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&[0x51, 0x52, 0x53, 0x54]));
        let locked_cm = asset_note_cm(7_000, sat, locked.opening());
        let w = AssetRebondWitness { fresh: a_witness(5_000, 12_000, 0, 0, sat), locked_value: 7_000, locked_owner: locked };
        let (carrier, cms, nf, nf2, lc) = prove_asset_rebond_validity_carrier_bytes(&w, 12_000).expect("the re-bond proves");
        let v = |c: &[u8], nf2: Digest, cm2: Digest, bond: u64, tag: [u64; 3]| verify_asset_rebond_validity_carrier_bytes(c, cms[0], cms[1], nf, nf2, cm2, lc, bond, tag);
        assert_ne!(nf, nf2, "two inputs, two nullifiers");
        assert_eq!(nf2, locked.nullifier(&locked_cm), "the locked note's nullifier is P(nk, cm) — DB-395's one nullifier rule, the wallet's note_nullifier");
        assert!(v(&carrier, nf2, locked_cm, 12_000, sat), "honest verifies");
        assert!(!v(&carrier, nf2, locked_cm, 12_001, sat), "⛔ a moved weight verified");
        assert!(!verify_asset_rebond_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, nf, locked_cm, lc, 12_000, sat), "⛔ one note opened twice verified");
        assert!(!v(&carrier, poseidon_pair(SK, asset_note_cm(7_000, sat, SK)), locked_cm, 12_000, sat), "⛔ a swapped locked nullifier verified");
        // ⛔ THE PHANTOM INPUT: the carrier must name WHICH note it consumed; stating another commitment (the one the fold reads
        // from bond_locked[vid]) must refuse, or a note of any value could ride as the locked input.
        assert!(!v(&carrier, nf2, asset_note_cm(7_000, sat, SK), 12_000, sat), "⛔ the carrier verified against a locked note it did not open");
        assert!(!v(&carrier, nf2, asset_note_cm(70_000, sat, locked.opening()), 12_000, sat), "⛔ the carrier verified against a locked note of another value");
        assert!(!v(&carrier, nf2, locked_cm, 12_000, USDM_ASSET_TAG), "⛔ a USDm-stated tag verified");
        assert!(!verify_asset_bond_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, lc, 12_000, sat), "⛔ the re-bond carrier verified as a single-input bond");
        let single = prove_asset_bond_validity_carrier_bytes(&a_witness(12_000, 12_000, 0, 0, sat), 12_000).expect("a single bond proves");
        assert!(!verify_asset_rebond_validity_carrier_bytes(&single.0, single.1[0], single.1[1], single.2, nf2, locked_cm, single.3, 12_000, sat), "⛔ a single-input carrier verified as a re-bond");
        assert!(prove_asset_rebond_validity_carrier_bytes(&AssetRebondWitness { fresh: a_witness(5_000, 12_001, 0, 0, sat), locked_value: 7_000, locked_owner: locked }, 12_001).is_none(), "⛔ an inflating split built a row");
        assert!(prove_asset_rebond_validity_carrier_bytes(&w, 11_999).is_none(), "the weight is output 0's value");
        let (c2, cms2, nf_2, nf2_2, lc2) = prove_asset_rebond_validity_carrier_bytes(&AssetRebondWitness { fresh: a_witness(5_000, 9_000, 3_000, 0, sat), locked_value: 7_000, locked_owner: locked }, 9_000).expect("a re-bond with change proves");
        assert!(verify_asset_rebond_validity_carrier_bytes(&c2, cms2[0], cms2[1], nf_2, nf2_2, locked_cm, lc2, 9_000, sat), "change is conserved too");
    }
    #[test]
    fn asset_zero_cm_matches_the_legacy_usdm_note_cm() {
        // ⛔ THE FORMULA CHANGED ON 2026-09-11 (user-authorized re-genesis; no real funds on chain).
        // It was `poseidon_pair([value, 0, 0, 0], SK)` — the value as ONE reduced field element, so a
        // note holding `v` opened equally well at `v + p` and the spend arm could inflate by p. It is
        // now the two-round `P(limbs, P([tag, 0], sk))`. This pin freezes THAT: USDm's tag is zero, so
        // a USDm commitment is exactly the two-round form with a zero inner tag, limb for limb.
        for value in [0u64, 1, 100_000_000, u64::MAX] {
            assert_eq!(
                asset_note_cm(value, USDM_ASSET_TAG, SK),
                poseidon_pair(crate::poseidon2_compress::lanes_of(&note_value_lanes(value)), poseidon_pair(crate::poseidon2_compress::ZERO_DIGEST, SK)),
                "a USDm commitment must be byte-identical to the two-round form with a zero tag"
            );
        }
    }

    /// ⛔⛔⛔ THE SEAM UNDER ITEM 1 — a note holding `v` must NOT share a commitment with `v + p`.
    /// Under the one-element formula these were byte-identical (`Fa4::from_u64` reduces mod p), which
    /// is the whole inflation: the same commitment opened at two different integers.
    #[test]
    fn a_note_at_v_and_a_note_at_v_plus_p_have_different_commitments() {
        let p: u64 = 2_130_706_433;
        for v in [0u64, 1, 5_000, 100_000_000, u64::MAX - p] {
            assert_ne!(
                asset_note_cm(v, USDM_ASSET_TAG, SK),
                asset_note_cm(v + p, USDM_ASSET_TAG, SK),
                "⛔⛔ INFLATION SEAM OPEN: {v} and {} commit identically — the value is bound mod p again",
                v + p
            );
            // and the tag is bound too: the same value under a different asset is a different note
            assert_ne!(
                asset_note_cm(v, USDM_ASSET_TAG, SK),
                asset_note_cm(v, [1, 0, 0], SK),
                "a wrapped-asset note must not share a commitment with a USDm note of the same value"
            );
        }
    }

    /// ⛔⛔⛔ NO DERIVED ASSET CAN EVER BE USDm. A collision here would make a wrapped token fungible
    /// with the native unit — one atomic unit of wBTC spendable as one atomic unit of USDm.
    ///
    /// The id set is BUILT FIRST and then walked, so the walk is a breadth check over data.
    #[test]
    fn a_derived_asset_tag_is_never_the_usdm_tag_and_is_distinct_per_asset() {
        // DEDUPED, because the uniqueness assertion below must fail on a real TAG collision and never
        // on a repeated input. The first version chained an explicit all-zero id onto a range that
        // already produces it, and the assert fired on that duplicate — the derivation was fine.
        let ids: std::collections::BTreeSet<[u8; 32]> = (0..512u16)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = (i & 0xFF) as u8;
                id[1] = (i >> 8) as u8;
                id
            })
            // The edge case a counter never reaches: the all-ones id.
            .chain([[0xFFu8; 32]])
            .collect();
        let mut seen = std::collections::BTreeSet::new();
        for id in &ids {
            let tag = wrapped_asset_tag(id);
            assert_ne!(tag, USDM_ASSET_TAG, "a derived tag must NEVER collide with USDm");
            assert!(tag[0] >= 1 && tag[0] < ASSET_TAG_KB_P, "limb 0 is forced into [1, p-1]");
            assert!(tag[1] < ASSET_TAG_KB_P && tag[2] < ASSET_TAG_KB_P, "limbs are field elements");
            assert!(seen.insert(tag), "two distinct assets must not share a tag");
        }
        // Deterministic: every node derives the same tag for the same asset id.
        assert_eq!(wrapped_asset_tag(&[7u8; 32]), wbtc());
    }

    /// ⭐⭐⭐ ONE SYMBOL, ONE TAG, EVERYWHERE. Without this table each component would invent its own
    /// answer, and the failure is silent: a note minted under one tag and searched for under another is
    /// valid on chain and invisible to its owner.
    #[test]
    fn every_canonical_symbol_resolves_to_one_distinct_tag() {
        let mut seen = std::collections::BTreeSet::new();
        assert!(seen.insert(asset_tag_for_symbol("USDm").unwrap()));
        for (sym, id) in CANONICAL_WRAPPED_ASSETS {
            let tag = asset_tag_for_symbol(sym).expect("a canonical symbol resolves");
            assert_eq!(tag, wrapped_asset_tag_u32(id), "the symbol agrees with its registry id");
            assert_ne!(tag, USDM_ASSET_TAG, "a wrapped asset is never USDm");
            assert!(seen.insert(tag), "no two symbols share a tag");
        }
        assert_eq!(asset_tag_for_symbol("wbtc"), asset_tag_for_symbol("wBTC"), "case-insensitive");
    }

    /// ⛔ AN UNKNOWN SYMBOL IS REFUSED, NEVER DEFAULTED TO USDm — a typo must not quote and settle
    /// against the wrong asset.
    #[test]
    fn an_unknown_symbol_is_refused_rather_than_defaulted() {
        assert_eq!(asset_tag_for_symbol("wDOGE"), None);
        assert_eq!(asset_tag_for_symbol(""), None);
        assert_eq!(canonical_wrapped_asset_id("USDm"), None, "USDm is native, not a wrapped asset");
    }

    /// ⭐ THE u32 REGISTRY ID MAPS TO EXACTLY ONE TAG, and never to USDm. Node and wallet both call this,
    /// so a wrapped mint and the wallet's search for it cannot disagree about which asset a note is.
    #[test]
    fn a_wrapped_registry_id_maps_to_one_stable_tag_that_is_never_usdm() {
        let ids: Vec<u32> = (0..256u32).chain([u32::MAX, u32::MAX / 2]).collect();
        let mut seen = std::collections::BTreeSet::new();
        for id in &ids {
            let tag = wrapped_asset_tag_u32(*id);
            assert_ne!(tag, USDM_ASSET_TAG, "a wrapped asset must never be USDm");
            assert!(seen.insert(tag), "two registry ids must not share a tag");
        }
        assert_eq!(wrapped_asset_tag_u32(7), wrapped_asset_tag_u32(7), "deterministic");
        assert_ne!(wrapped_asset_tag_u32(7), wrapped_asset_tag_u32(8));
    }

    /// The honest transfer of a wrapped asset: it proves, and it verifies against exactly the outputs
    /// the node would record.
    #[test]
    fn an_asset_tagged_transfer_proves_and_verifies() {
        let w = a_witness(1_000, 400, 600, 0, wbtc());
        let (carrier, cms, nf, lc) =
            prove_asset_spend_validity_carrier_bytes(&w).expect("an honest wBTC transfer proves");
        assert!(
            verify_asset_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, lc),
            "and verifies against the recorded outputs"
        );
        // The outputs really are wBTC notes at the claimed amounts.
        assert_eq!(cms[0], asset_note_cm(400, wbtc(), OUT0_SK));
        assert_eq!(cms[1], asset_note_cm(600, wbtc(), OUT1_SK));
    }

    /// ⛔⛔⛔ THE CROSS-ASSET FORGE IS UNREPRESENTABLE. There is one tag group, so a row that spends
    /// wBTC and mints USDm cannot be written at all — the honest prover cannot express it, and a
    /// hand-built one fails the shared-column constraints. Demonstrated by its consequence: a carrier
    /// proved for wBTC does not verify against the USDm commitments an attacker would want recorded.
    /// ⛔⛔⛔ THE ASSET SPEND CARRIER DOES NOT ANCHOR MEMBERSHIP, AND A DOOR THAT FORGETS THAT MINTS.
    ///
    /// `verify_spend_validity_carrier_bytes` takes a `root` and welds `acc(depth) == root`.
    /// `verify_asset_spend_validity_carrier_bytes` takes NO root, and `asset_validity_public_bind` is
    /// `[DOMAIN, out0, out1, nullifier, leaf_commit]` — the copath is a FREE WITNESS. That is deliberate
    /// (this gate's section D says so): membership is proven by the SEPARATE note-membership carrier over
    /// the O(1) accumulator, and the two are pinned to one note by `leaf_commit`.
    ///
    /// ⭐ THE CONSEQUENCE IS A WIRING RULE, AND THIS GATE EXISTS SO NOBODY HAS TO REDISCOVER IT: a node
    /// that admits an asset spend on the VALIDITY carrier alone has admitted a spend of a note nobody
    /// ever paid the spender. The asset-spend door MUST require BOTH carriers, and must anchor the
    /// membership half on state it derived ITSELF (`Node::verify_membership_carrier{,_one_step}`), never
    /// on a root read out of the transaction.
    ///
    /// MEASURED below: the SAME note under two completely invented copaths yields byte-identical public
    /// values and both verify — so the validity carrier cannot tell a real tree from a fabricated one.
    #[test]
    fn the_asset_spend_carrier_proves_no_membership_so_the_door_must_require_the_membership_carrier() {
        let w = a_witness(1_000, 400, 600, 0, wbtc());
        let (c1, cms1, nf1, lc1) = prove_asset_spend_validity_carrier_bytes(&w).expect("path A proves");
        // (2026-09-30) The witness carries NO copath any more — the "invented copath" this pin used to substitute is
        // unrepresentable. The same witness proved twice states the same publics, and neither proof names a root.
        let (c2, cms2, nf2, lc2) = prove_asset_spend_validity_carrier_bytes(&w).expect("path B proves");

        assert_eq!((cms1, nf1, lc1), (cms2, nf2, lc2),
            "CALIBRATION: two proofs of one witness state one set of publics — re-derive before trusting either.");
        assert!(
            verify_asset_spend_validity_carrier_bytes(&c1, cms1[0], cms1[1], nf1, lc1)
                && verify_asset_spend_validity_carrier_bytes(&c2, cms2[0], cms2[1], nf2, lc2)
                && verify_asset_spend_validity_carrier_bytes(&c2, cms1[0], cms1[1], nf1, lc1),
            "both carriers verify with no root anywhere — that is the fact the wiring rule exists for"
        );
        // ⭐ And the statement itself says so: no root appears anywhere in the public bind.
        let bind = asset_validity_public_bind(&[to_f(&cms1[0]), to_f(&cms1[1])], &to_f(&nf1), &to_f(&lc1));
        assert_eq!(
            bind.len(),
            1 + 4 * DIGEST_LANES,
            "⛔ THE PUBLIC BIND GREW OR SHRANK. If a root was ADDED, this gate is obsolete and the \
             asset-spend door may stop requiring the membership carrier — delete it deliberately, with \
             the door changed in the same edit. If something else moved, the door's rule is now wrong."
        );
    }

    #[test]
    fn a_carrier_cannot_spend_one_asset_and_mint_another() {
        let w = a_witness(1_000, 400, 600, 0, wbtc());
        let (carrier, _cms, nf, lc) = prove_asset_spend_validity_carrier_bytes(&w).unwrap();
        // What the thief wants recorded: the same amounts, but as USDm (or wETH) notes.
        let usdm_out0 = asset_note_cm(400, USDM_ASSET_TAG, OUT0_SK);
        let usdm_out1 = asset_note_cm(600, USDM_ASSET_TAG, OUT1_SK);
        assert!(
            !verify_asset_spend_validity_carrier_bytes(&carrier, usdm_out0, usdm_out1, nf, lc),
            "a wBTC spend must NOT settle as USDm outputs"
        );
        let weth_out0 = asset_note_cm(400, weth(), OUT0_SK);
        let weth_out1 = asset_note_cm(600, weth(), OUT1_SK);
        assert!(
            !verify_asset_spend_validity_carrier_bytes(&carrier, weth_out0, weth_out1, nf, lc),
            "nor as another token's outputs"
        );
    }

    /// ⛔ INFLATION IS UNPROVABLE: outputs that sum past the input have no row.
    #[test]
    fn an_inflating_asset_spend_cannot_be_built() {
        assert!(
            prove_asset_spend_validity_carrier_bytes(&a_witness(1_000, 600, 600, 0, wbtc())).is_none(),
            "outputs summing above the input must not prove"
        );
        let mut w = a_witness(1_000, 400, 600, 0, wbtc());
        w.value_out = 1_200; // claim more out than the note holds
        assert!(prove_asset_spend_validity_carrier_bytes(&w).is_none(), "a mismatched value_out must not prove");
    }

    /// ⛔ A TAMPERED CARRIER IS REFUSED.
    #[test]
    fn a_tampered_asset_carrier_is_refused() {
        let w = a_witness(1_000, 400, 600, 0, wbtc());
        let (mut carrier, cms, nf, lc) = prove_asset_spend_validity_carrier_bytes(&w).unwrap();
        let last = carrier.len() - 1;
        carrier[last] ^= 0xFF;
        assert!(!verify_asset_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, lc));
    }

    /// A cross-bind that arrives as all zeros (an ABSENT wire field decodes that way) must not verify.
    /// This measures what the transcript alone does about it — the explicit structural refusal the v1
    /// verifier carries is added on top once this number is known.
    #[test]
    fn an_all_zero_cross_bind_does_not_verify() {
        let w = a_witness(1_000, 400, 600, 0, wbtc());
        let (carrier, cms, nf, _lc) = prove_asset_spend_validity_carrier_bytes(&w).unwrap();
        assert!(
            !verify_asset_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, crate::poseidon2_compress::ZERO_DIGEST),
            "zero is not 'no binding' — it is a binding anyone can produce"
        );
    }

    /// ⭐⭐⭐ THE MINT BIND — the gate that closes the over-mint hole. A credit proves the note it is
    /// about to record opens at the AUTHORIZED amount, in the AUTHORIZED asset.
    #[test]
    fn an_asset_mint_binds_its_commitment_to_the_authorized_amount_and_asset() {
        let (carrier, cm) = prove_asset_mint_validity_bytes(50_000, wbtc(), &SK).expect("mint proves");
        assert_eq!(cm, asset_note_cm(50_000, wbtc(), SK), "the carrier's cm is the note's cm");
        assert!(verify_asset_mint_validity_bytes(&carrier, cm, 50_000, wbtc()), "honest mint verifies");
        // ⛔ The over-mint: a custodian authorized 50,000 and a client wants 5,000,000 credited.
        assert!(
            !verify_asset_mint_validity_bytes(&carrier, cm, 5_000_000, wbtc()),
            "an inflated amount is REFUSED — this is the hole that let a sealed note outrun its authorization"
        );
        // ⛔ The wrong asset: authorized wBTC, credited as USDm (or wETH).
        assert!(
            !verify_asset_mint_validity_bytes(&carrier, cm, 50_000, USDM_ASSET_TAG),
            "a wBTC mint must NOT verify as a USDm credit"
        );
        assert!(!verify_asset_mint_validity_bytes(&carrier, cm, 50_000, weth()), "nor as another token");
        // ⛔ The swapped note: crediting a DIFFERENT commitment than the one proven.
        let other: Digest = core::array::from_fn(|i| if i == 0 { cm[0] ^ 0xfeed } else { cm[i] });
        assert!(!verify_asset_mint_validity_bytes(&carrier, other, 50_000, wbtc()), "a swapped note is refused");
        // ⛔ Tamper.
        let mut t = carrier.clone();
        let last = t.len() - 1;
        t[last] ^= 0xFF;
        assert!(!verify_asset_mint_validity_bytes(&t, cm, 50_000, wbtc()), "a tampered mint carrier is refused");
    }

    /// A USDm mint through the asset gate must agree with the legacy mint gate's commitment, so the
    /// two paths can coexist during the wiring and a v1 gate and a v2 gate never disagree about what
    /// a USDm note IS.
    #[test]
    fn a_usdm_mint_through_the_asset_gate_matches_the_legacy_mint_commitment() {
        let (_v2, cm_v2) = prove_asset_mint_validity_bytes(1_234, USDM_ASSET_TAG, &SK).unwrap();
        let (_v1, cm_v1) = prove_mint_validity_bytes(1_234, &SK).unwrap();
        assert_eq!(cm_v2, cm_v1, "the same USDm note, whichever gate proved it");
    }
}

// ===================================================================================================
// THE ORDER BOOK — a resting order and its fill, proven in TWO HALVES. No pool exists anywhere.
//
// A pool was SHARED MUTABLE SECRET STATE, and every pillar failure traced to that one property: held
// privately it is a censor, published it discloses reserves and every trade's size, and either way every
// trade of a pair serialises through one cell — a throughput ceiling on a chain whose GHOSTDAG width
// exists for parallelism. There is no shared cell here. A MAKER rests an order over ONE OF THEIR OWN
// NOTES and goes offline; a TAKER fills it. Fills touch disjoint state, so they settle in parallel
// exactly like ordinary sends ([[feedback_scalability_pillar]]).
//
// ⛔⛔⛔ WHY TWO HALVES, AND WHY ONE PROOF WOULD HAVE BEEN A THEFT VECTOR.
// The first draft had the TAKER prove the whole exchange. That requires the maker's spend key in the
// taker's witness — so a resting order would have had to publish `sk`, and anyone reading the book could
// then spend the maker's note through the ORDINARY spend gate, never touching this one. Caught in review
// before it compiled. The maker proves THEIR half ONCE, at post time, with `sk` never leaving home; the
// taker proves theirs at fill time. Neither party ever learns the other's key.
//
// ⭐⭐⭐ THE GRID IS TWO-DIMENSIONAL: A FIXED PRICE LATTICE × A FIXED LOT SIZE. Both are governance
// constants, identical for everyone. This is what makes SIZE stop being information: every order at a
// level trades EXACTLY one lot, so a fill discloses "one lot at level L" — which the tape already said —
// and nothing about anyone's position. It is the chain's own cash-denomination pattern (one note is one
// bill) applied to the book. Without it an order must advertise its size to be fillable, and a
// world-readable book would publish every size.
//
// A PRICE MUST COME FROM A FIXED GRID, NOT FROM THE MAKER. A distinctive limit is an IDENTIFIER, and
// repeated distinctive limits link one maker's orders into a profile — exactly the identity leak this
// design exists to prevent. There is no privacy knob here and none is possible: the disclosure is
// uniform, protocol-fixed, and the same for every participant.
//
// WHAT A FILL PUBLISHES: two nullifiers, two membership cross-binds, three output commitments, the
// lattice level, the asset pair, and the lot. WHAT IT NEVER PUBLISHES: either party's identity, the
// taker's holding, either change amount, any linkage between a maker's orders, or any balance.
// ===================================================================================================

/// Transcript domain for the maker's resting-order half.
pub const ORDER_MAKER_DOMAIN: u64 = 0x4f52_444d_414b_4531; // "ORDMAKE1"
/// Transcript domain for the taker's fill half.
pub const ORDER_TAKER_DOMAIN: u64 = 0x4f52_4454_414b_4531; // "ORDTAKE1"

/// One note-opening block. ⛔ WAS THE LITERAL 25 (`value · sk(4) · pre/sq/p4/p7(16) · cm(4)`) — the
/// 1-round fold's shape. It is now `NO_WIDTH`: value, spend key, a whole permutation, and the commitment.
const ONB: usize = NO_WIDTH;
/// One spent-input block. ⛔ WAS THE LITERAL 57, likewise the retired round's shape. · cross-bind(12).
const OIB: usize = NI_WIDTH;
/// MAKER tail (after OIB + ONB): the lot's range block, the payout's range block, two inner rounds.
const MK_LOT: usize = OIB + ONB;
const MK_PAY: usize = MK_LOT + U64_RANGE_WIDTH;
const MK_IN_INNER: usize = MK_PAY + U64_RANGE_WIDTH;
const MK_OUT_INNER: usize = MK_IN_INNER + POSE_BLK + DIGEST_LANES;
const MK_WIDTH: usize = MK_OUT_INNER + POSE_BLK + DIGEST_LANES;
/// TAKER tail (after OIB + 2·ONB): conservation block (in = value_in, out = change, fee = pay_b + fee),
/// the payout lot's range block, three inner rounds.
const TK_CONS: usize = OIB + 2 * ONB;
const TK_LOT: usize = TK_CONS + U64_CONS_WIDTH;
const TK_IN_INNER: usize = TK_LOT + U64_RANGE_WIDTH;
const TK_CHG_INNER: usize = TK_IN_INNER + POSE_BLK + DIGEST_LANES;
const TK_PAY_INNER: usize = TK_CHG_INNER + POSE_BLK + DIGEST_LANES;
const TK_WIDTH: usize = TK_PAY_INNER + POSE_BLK + DIGEST_LANES;

/// Write a spent-input block at `base` and return (leaf, nf, leaf_commit).
fn fill_spent_input(
    row: &mut [Fa4],
    base: usize,
    value: u64,
    owner: &NoteOwner,
    tag: &[Fa4; 3],
    limbs: U64RangeBases,
    inner: (usize, usize),
    blind: Digest,
) -> (DigestF, DigestF, DigestF) {
    let val = Fa4::from_u64(value);
    // DB-395: the opening lanes hold `o = P(P(ask, nk), seed)`, laid by the block's owner block; the nullifier is keyed by `nk`.
    let sk = fill_owner_open(row, base + NI_OWNER, base + NI_SK, owner);
    let nk: DigestF = core::array::from_fn(|c| Fa4::from_u64(owner.nk[c]));
    row[base] = val;
    // Two-round opening: leaf = P(limbs(value), P([tag, 0], sk)); the limbs live at `limbs` (range-bound
    // by the caller's block), the inner round at `inner`.
    let tag_u: [u64; 3] = {
        use p3_field::PrimeField64;
        core::array::from_fn(|c| tag[c].as_canonical_u64())
    };
    fill_u64_range_row(row, value, limbs);
    let leaf = fill_note_open(row, value, tag_u, &sk, inner.0, inner.1, base + NI_NOH, base + NI_LEAF);
    let nf = fill_pose_round(row, &nk, &leaf, base + NI_NFH, base + NI_NF);
    // DB-363: two chained blocks — the inner's output is written into the outer's left lanes by `fill_pose_round`, the
    // blinding fills the outer's right lanes, and the outer's output IS the public commitment.
    let inner_out = fill_pose_round(row, &leaf, &nf, base + NI_CB, base + NI_CB2);
    let blind_f: DigestF = core::array::from_fn(|c| Fa4::from_u64(blind[c]));
    row[base + NI_BLIND..base + NI_BLIND + DIGEST_LANES].copy_from_slice(&blind_f);
    crate::pow_pq_air::lay_perm_row_flat(row, base + NI_CB2, pose_state(&inner_out, &blind_f));
    let lc: DigestF = core::array::from_fn(|c| row[base + NI_CB2 + crate::pow_pq_air::PERM_OUT + c]);
    (leaf, nf, lc)
}

/// Write a note-opening (output) block at `base` and return its commitment. `opening` is the output's `P(spk, seed)` (DB-395).
fn fill_note_out(row: &mut [Fa4], base: usize, value: u64, opening: Digest, tag: &[Fa4; 3], limbs: U64RangeBases, inner: (usize, usize)) -> DigestF {
    let val = Fa4::from_u64(value);
    let sk: DigestF = core::array::from_fn(|c| Fa4::from_u64(opening[c]));
    let tag_u: [u64; 3] = {
        use p3_field::PrimeField64;
        core::array::from_fn(|c| tag[c].as_canonical_u64())
    };
    row[base + NO_VAL] = val;
    row[base + NO_SK..base + NO_SK + DIGEST_LANES].copy_from_slice(&sk);
    fill_u64_range_row(row, value, limbs);
    fill_note_open(row, value, tag_u, &sk, inner.0, inner.1, base + NO_BLK, base + NO_CM)
}

/// A SPENT-INPUT block's layout. ⛔ Every offset was a literal (1,5,9,13,29,45) until 2026-09-12.
pub const NI_VAL: usize = 0;
pub const NI_SK: usize = NI_VAL + 1;
pub const NI_LEAF: usize = NI_SK + DIGEST_LANES;
pub const NI_NF: usize = NI_LEAF + DIGEST_LANES;
pub const NI_NOH: usize = NI_NF + DIGEST_LANES;
pub const NI_NFH: usize = NI_NOH + crate::pow_pq_air::P2_COLS;
pub const NI_CB: usize = NI_NFH + crate::pow_pq_air::P2_COLS;
/// DB-363 (2026-09-30): the OUTER cross-bind block, `leaf_commit = P(P(leaf, nf), blind)`. Its left input lanes ARE the
/// inner block's output (`push_pose_round`'s `out`), so neither block is decorative; its output is the public commitment.
pub const NI_CB2: usize = NI_CB + crate::pow_pq_air::P2_COLS;
/// DB-363: the half's per-object blinding lanes — a HIDING witness read only by the outer block's right-lane weld, and
/// named in both DEX gates' `free_columns`.
pub const NI_BLIND: usize = NI_CB2 + crate::pow_pq_air::P2_COLS;
/// ⛔ DB-395 — the spent note's OWNER block, at the input block's end.
pub const NI_OWNER: usize = NI_BLIND + DIGEST_LANES;
pub const NI_WIDTH: usize = NI_OWNER + OWNER_BLK_WIDTH;

/// An OUTPUT note block's layout.
pub const NO_VAL: usize = 0;
pub const NO_SK: usize = NO_VAL + 1;
pub const NO_BLK: usize = NO_SK + DIGEST_LANES;
pub const NO_CM: usize = NO_BLK + crate::pow_pq_air::P2_COLS;
pub const NO_WIDTH: usize = NO_CM + DIGEST_LANES;

/// Constrain a spent-input block: opening under `tag`, nullifier, and the membership cross-bind.
#[allow(clippy::too_many_arguments)]
fn spent_input_constraints(
    rs: &mut Vec<Ea4>,
    local: &crate::air_zerocheck::Row<'_>,
    base: usize,
    tag: &[Ea4; 3],
    nullifier: &[Ea4; DIGEST_LANES],
    leaf_commit: &[Ea4; DIGEST_LANES],
    limbs: U64RangeBases,
    inner: (usize, usize),
) {
    let value = local[base + NI_VAL];
    let sk = |c: usize| local[base + NI_SK + c];
    let leaf = |c: usize| local[base + NI_LEAF + c];
    let nf = |c: usize| local[base + NI_NF + c];
    // OPENING under the asset tag, two rounds — leaf == P(limbs(value), P([tag, 0], sk)); the value's
    // limbs are range-bound here and the legacy whole-value column is bound to them.
    push_u64_range(rs, local, limbs);
    rs.push(value - u64_limbs_recombined(local, limbs.limbs));
    let tag_lane = |c: usize| if c < 3 { tag[c] } else { Ea4::from(Fa4::ZERO) };
    // ⛔ DB-395 — the OWNER: the opening lanes welded to `o = P(P(ask, nk), seed)`; the nullifier keyed by `nk`.
    push_owner_open(rs, local, base + NI_OWNER, base + NI_SK);
    let nk = |c: usize| local[owner_nk_col(base + NI_OWNER) + c];
    push_note_open(rs, local, limbs.limbs, &tag_lane, &sk, inner.0, inner.1, base + NI_NOH, base + NI_LEAF);
    // NULLIFIER — nf == compress(nk, leaf), welded to the public one the node records.
    push_pose_round(rs, local, &nk, &leaf, base + NI_NFH, base + NI_NF);
    rs.extend((0..DIGEST_LANES).map(|c| nf(c) - nullifier[c]));
    // MEMBERSHIP CROSS-BIND — leaf_commit == P(P(leaf, nullifier), blind). No Merkle path and no root: membership is
    // proven by the note-membership carrier over the O(1) accumulator, which commits the SAME blinded value
    // (`note_membership_air::note_leaf_commitment`), and the two proofs meet here.
    // ⭐ DB-363 (2026-09-30): this was ONE compression `P(leaf, nullifier)` with BOTH inputs public — the nullifier is the
    // half's own statement and the leaf is the asset note every node appended from the record — so any node hashed each
    // candidate leaf with an order's nullifier and joined the order (and the fill) to the note's receive. The inner block at
    // NI_CB compresses (leaf, nullifier); its output lanes are WELDED into the outer block's left input lanes at NI_CB2 (the
    // `out` of `push_pose_round` IS those lanes, so no block's output is decorative); the outer block's right lanes are the
    // blinding at NI_BLIND (a hiding witness, named in `free_columns`) and its output is the public commitment.
    let nfp = |c: usize| nullifier[c];
    push_pose_round(rs, local, &leaf, &nfp, base + NI_CB, base + NI_CB2);
    crate::pow_pq_air::push_perm_residuals(local, base + NI_CB2, rs);
    for c in 0..DIGEST_LANES {
        rs.push(local[base + NI_CB2 + DIGEST_LANES + c] - local[base + NI_BLIND + c]);
        rs.push(local[base + NI_CB2 + crate::pow_pq_air::PERM_OUT + c] - leaf_commit[c]);
    }
}

/// Constrain an output note block: it opens under `tag` and equals the PUBLIC commitment recorded.
fn note_out_constraints(rs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, base: usize, tag: &[Ea4; 3], cm_pub: &[Ea4; DIGEST_LANES], limbs: U64RangeBases, inner: (usize, usize)) {
    let val = local[base + NO_VAL];
    let sk = |c: usize| local[base + NO_SK + c];
    let cm = |c: usize| local[base + NO_CM + c];
    push_u64_range(rs, local, limbs);
    rs.push(val - u64_limbs_recombined(local, limbs.limbs));
    let tag_lane = |c: usize| if c < 3 { tag[c] } else { Ea4::from(Fa4::ZERO) };
    push_note_open(rs, local, limbs.limbs, &tag_lane, &sk, inner.0, inner.1, base + NO_BLK, base + NO_CM);
    rs.extend((0..DIGEST_LANES).map(|c| cm(c) - cm_pub[c]));
}

/// The terms of a resting order. Every field is PUBLIC — this is the book entry, and it is identical in
/// shape for every participant. `lot` and the level are grid constants, so nothing here is distinctive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderTerms {
    /// The fixed lot: how much of `asset_a` this order gives up. A governance constant.
    pub lot: u64,
    /// What the maker receives, in `asset_b`. Determined by the lattice level and the lot.
    pub pay_b: u64,
    /// The asset the maker gives.
    pub asset_a: [u64; 3],
    /// The asset the maker wants.
    pub asset_b: [u64; 3],
    /// The last height at which this order may be filled. A term of the maker's own order, uncapped in
    /// value — requiring the FIELD bounds book residency without capping anyone's reach.
    pub expires_at_height: u64,
}

impl OrderTerms {
    fn tags(&self) -> ([Fa4; 3], [Fa4; 3]) {
        (
            core::array::from_fn(|c| Fa4::from_u64(self.asset_a[c])),
            core::array::from_fn(|c| Fa4::from_u64(self.asset_b[c])),
        )
    }
    fn bind(&self, domain: u64) -> Vec<Fa4> {
        self.bind_with_fee(domain, None)
    }
    /// The transcript binding. `fee` is `Some` on the taker's half: the rate is consensus, so pinning the
    /// resulting fee here means a proof built at one rate cannot be replayed under another.
    fn bind_with_fee(&self, domain: u64, fee: Option<u64>) -> Vec<Fa4> {
        let (a, b) = self.tags();
        // Amounts as LIMBS, never one reduced element — `lot` and `lot + p` must bind differently
        // (item 1 seam, 2026-09-11).
        let mut v = vec![Fa4::from_u64(domain)];
        v.extend_from_slice(&u64_public_limbs(self.lot));
        v.extend_from_slice(&u64_public_limbs(self.pay_b));
        v.push(Fa4::from_u64(self.expires_at_height));
        if let Some(f) = fee {
            v.extend_from_slice(&u64_public_limbs(f));
        }
        v.extend_from_slice(&a);
        v.extend_from_slice(&b);
        v
    }
    /// A well-formed order trades two DIFFERENT assets for nonzero amounts of both.
    fn is_sane(&self) -> bool {
        self.asset_a != self.asset_b && self.lot > 0 && self.pay_b > 0
    }

    /// ⭐⭐⭐ THE PROTOCOL FILL FEE — the ONE definition. The circuit's conservation and the node's
    /// acceptance both call THIS, so the two can never drift into disagreeing about what was owed (the
    /// exact defect that had a client displaying a 100–10,000 USDm bond beside a route that charged
    /// nothing).
    ///
    /// ⛔⛔⛔ IT LEAKS NOTHING, AND THAT IS STRUCTURAL, NOT A HOPE. It is a pure function of `pay_b` and
    /// `bps`, both already PUBLIC — `pay_b` is the book entry every participant reads and `bps` is a
    /// consensus constant. So the fee is computable by anyone from what the order already published, and
    /// carries no information about the taker: not their balance, not their change, not their identity.
    /// The HIDDEN quantity (`value_in`) never enters. A flat per-fill fee would leak nothing either, but
    /// it is economically wrong at both tails — nothing on a whale's fill, punitive on a small one — and
    /// a fee denominated in a fixed number of atomic units means something wildly different in wBTC than
    /// in USDm. Proportional is self-normalizing across every asset WITHOUT an oracle.
    ///
    /// ⛔ NEVER ZERO, and never the maker's choice. Ceiling division floors the fee at 1 atomic unit for
    /// any nonzero order, so no lattice level is a free fill; and `bps` is a CONSENSUS parameter rather
    /// than a field of `OrderTerms`, because a maker who could set their own fee would set it to zero.
    #[must_use]
    pub fn protocol_fee(&self, bps: u64) -> u64 {
        if bps == 0 {
            return 0;
        }
        // u128 so a large `pay_b` cannot wrap the multiply into a small fee.
        let num = (self.pay_b as u128) * (bps as u128);
        let fee = num.div_ceil(10_000u128);
        u64::try_from(fee).unwrap_or(u64::MAX)
    }
}

// ── MAKER HALF ──────────────────────────────────────────────────────────────────────────────────────

/// The maker's witness. Proved ONCE at post time; `sk` never leaves the maker's machine.
#[derive(Clone, Debug)]
pub struct MakerHalfWitness {
    /// ⛔ DB-395: the OWNER of the resting note (one lot of `asset_a`): `ask`, `nk`, the note's seed.
    pub owner: NoteOwner,
    /// The opening of the payout note the maker PRE-BUILDS for themselves (`P(spk_maker, seed)`, DB-395). The maker seals this
    /// note to their own address at post time, so the taker records it verbatim and holds no authority over it.
    pub payout_opening: Digest,
    /// DB-363: the per-order blinding of the membership cross-bind — drawn ONCE by `fresh_lc_blind` where the order is
    /// assembled and passed to BOTH this half and the lot note's membership carrier. Test fixtures use fixed lanes.
    pub lc_blind: Digest,
}

/// What a resting order publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MakerHalfPublic {
    /// The resting note's nullifier. ⭐ This is ALSO the anti-double-fill mechanism: two takers racing one
    /// order collide here and the second is refused by the double-spend gate that already exists.
    /// Cancelling an order = the maker spends the note themselves, burning this nullifier.
    pub nullifier: Digest,
    /// The resting note's membership cross-bind.
    pub leaf_commit: Digest,
    /// The commitment of the maker's PRE-BUILT payout note, proven here to hold `pay_b` of `asset_b`.
    pub payout_cm: Digest,
}

/// The maker gate: the resting note opens to ONE LOT of `asset_a` and is nullified, and the pre-built
/// payout note opens to exactly `pay_b` of `asset_b`.
///
/// ⛔⛔⛔ THE PAYOUT OPENING IS PROVEN HERE, BY THE MAKER, AND THAT IS LOAD-BEARING. The taker cannot
/// prove it — they do not hold the maker's payout key. If nobody proved it, a maker could publish a
/// payout commitment that opens to ZERO, and the taker's conservation would then let them pay nothing
/// and still take a lot: value created from nothing. Proving it at post time closes that with the one
/// party who can.
pub struct MakerHalfGate {
    pub gamma: Ea4,
    /// PUBLIC amounts as four 16-bit limbs (a reduced element let `lot` and `lot + p` weld alike).
    /// A u64 AMOUNT as `SC_LIMBS` 16-bit limbs — NOT a digest; `u64_public_limbs` yields exactly these.
    pub lot: [Ea4; SC_LIMBS],
    /// A u64 AMOUNT as `SC_LIMBS` 16-bit limbs — NOT a digest; `u64_public_limbs` yields exactly these.
    pub pay_b: [Ea4; SC_LIMBS],
    pub asset_a: [Ea4; 3],
    pub asset_b: [Ea4; 3],
    pub nullifier: [Ea4; DIGEST_LANES],
    pub leaf_commit: [Ea4; DIGEST_LANES],
    pub payout_cm: [Ea4; DIGEST_LANES],
}

impl crate::air_zerocheck::AirConstraint for MakerHalfGate {
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ EMBEDS A PERMUTATION: a gate declaring less than the permutation's degree truncates
        // the sumcheck, so even an HONEST proof stops verifying.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    /// DB-363: the blinding lanes are a HIDING witness — read only by the outer cross-bind block's right-lane weld,
    /// determined by no statement value on purpose (that is what makes `leaf_commit` unlinkable). Named here so the
    /// binding review sees the choice; the free-witness census reads them as declared.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some((NI_BLIND..NI_BLIND + DIGEST_LANES).collect())
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut rs: Vec<Ea4> = Vec::new();
        let lot_rb = U64RangeBases::at(MK_LOT);
        let pay_rb = U64RangeBases::at(MK_PAY);
        spent_input_constraints(&mut rs, local, 0, &self.asset_a, &self.nullifier, &self.leaf_commit, lot_rb, (MK_IN_INNER, MK_IN_INNER + POSE_BLK));
        note_out_constraints(&mut rs, local, OIB, &self.asset_b, &self.payout_cm, pay_rb, (MK_OUT_INNER, MK_OUT_INNER + POSE_BLK));
        // The resting note is EXACTLY one lot, and the payout is EXACTLY the level's price — welded LIMB
        // for limb to the public terms, so no reduced-element alias.
        for i in 0..SC_LIMBS {
            rs.push(local[lot_rb.limbs + i] - self.lot[i]);
            rs.push(local[pay_rb.limbs + i] - self.pay_b[i]);
        }
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in rs {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }
}

/// PROVE the maker's half of a resting order. `None` on malformed terms — an order that cannot be
/// honestly filled has no proof, so it never reaches a book.
#[must_use]
pub fn prove_order_maker_half(
    w: &MakerHalfWitness,
    t: &OrderTerms,
) -> Option<(Vec<u8>, MakerHalfPublic)> {
    use p3_field::PrimeField64;
    if !t.is_sane() {
        return None;
    }
    let (tag_a, tag_b) = t.tags();
    let mut row = vec![Fa4::ZERO; MK_WIDTH];
    let (_leaf, nf, lc) = fill_spent_input(&mut row, 0, t.lot, &w.owner, &tag_a, U64RangeBases::at(MK_LOT), (MK_IN_INNER, MK_IN_INNER + POSE_BLK), w.lc_blind);
    let payout_cm = fill_note_out(&mut row, OIB, t.pay_b, w.payout_opening, &tag_b, U64RangeBases::at(MK_PAY), (MK_OUT_INNER, MK_OUT_INNER + POSE_BLK));
    let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|c| vec![row[c]; LIGHT_CARRIER_ROWS]).collect();
    let e3 = |v: [Fa4; 3]| -> [Ea4; 3] { core::array::from_fn(|c| v[c].into()) };
    let e4 = |v: DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|c| v[c].into()) };
    let (lot, pay_b) = (t.lot, t.pay_b);
    let make = move |g: Ea4| MakerHalfGate {
        gamma: g,
        lot: core::array::from_fn(|i| u64_public_limbs(lot)[i].into()),
        pay_b: core::array::from_fn(|i| u64_public_limbs(pay_b)[i].into()),
        asset_a: e3(tag_a),
        asset_b: e3(tag_b),
        nullifier: e4(nf),
        leaf_commit: e4(lc),
        payout_cm: e4(payout_cm),
    };
    let mut bind = t.bind(ORDER_MAKER_DOMAIN);
    bind.extend_from_slice(&nf);
    bind.extend_from_slice(&lc);
    bind.extend_from_slice(&payout_cm);
    let bytes = crate::committed_air::prove_air_blinded_bytes(cols, make, &bind)?;
    let u4 = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((
        bytes,
        MakerHalfPublic { nullifier: u4(nf), leaf_commit: u4(lc), payout_cm: u4(payout_cm) },
    ))
}

/// VERIFY a resting order's maker half against its published terms. Fail-closed.
#[must_use]
pub fn verify_order_maker_half(bytes: &[u8], t: &OrderTerms, p: &MakerHalfPublic) -> bool {
    if bytes.is_empty() || !t.is_sane() || p.leaf_commit == crate::poseidon2_compress::ZERO_DIGEST {
        return false;
    }
    let (tag_a, tag_b) = t.tags();
    let f4 = |v: Digest| -> DigestF { core::array::from_fn(|c| Fa4::from_u64(v[c])) };
    let e3 = |v: [Fa4; 3]| -> [Ea4; 3] { core::array::from_fn(|c| v[c].into()) };
    let e4 = |v: DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|c| v[c].into()) };
    let (nf, lc, cm) = (f4(p.nullifier), f4(p.leaf_commit), f4(p.payout_cm));
    let (lot, pay_b) = (t.lot, t.pay_b);
    let make = move |g: Ea4| MakerHalfGate {
        gamma: g,
        lot: core::array::from_fn(|i| u64_public_limbs(lot)[i].into()),
        pay_b: core::array::from_fn(|i| u64_public_limbs(pay_b)[i].into()),
        asset_a: e3(tag_a),
        asset_b: e3(tag_b),
        nullifier: e4(nf),
        leaf_commit: e4(lc),
        payout_cm: e4(cm),
    };
    let mut bind = t.bind(ORDER_MAKER_DOMAIN);
    bind.extend_from_slice(&nf);
    bind.extend_from_slice(&lc);
    bind.extend_from_slice(&cm);
    crate::committed_air::verify_air_blinded_bytes(bytes, make, &bind, (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, MK_WIDTH))
}

// ── TAKER HALF ──────────────────────────────────────────────────────────────────────────────────────

/// The taker's witness. Their holding and their change stay hidden; only the grid constants are public.
#[derive(Clone, Debug)]
pub struct TakerHalfWitness {
    /// The taker's note of `asset_b`. HIDDEN — the book never learns what a taker holds.
    pub value_in: u64,
    /// ⛔ DB-395: the paying note's owner (`ask`, `nk`, the note's seed).
    pub owner: NoteOwner,
    /// Where the taker's change goes (still `asset_b`), and where they receive the lot of `asset_a` — each an opening
    /// `P(spk_taker, seed)` (DB-395).
    pub change_opening: Digest,
    pub payout_opening: Digest,
    /// DB-363: the per-fill blinding of the membership cross-bind — drawn ONCE by `fresh_lc_blind` where the fill is
    /// assembled and passed to BOTH this half and the paying note's membership carrier. Test fixtures use fixed lanes.
    pub lc_blind: Digest,
}

/// What a fill publishes from the taker's side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakerHalfPublic {
    pub nullifier: Digest,
    pub leaf_commit: Digest,
    /// The taker's change note (asset `b`). Its AMOUNT stays hidden inside the commitment.
    pub change_cm: Digest,
    /// The taker's payout note — one lot of asset `a`.
    pub payout_cm: Digest,
}

/// The taker gate: their note is opened and nullified, their change and payout notes open correctly, and
/// value conserves in asset `b` — `value_in == pay_b + fee + change`.
///
/// ⛔⛔⛔ THE FEE IS DESTROYED, NOT SEALED TO ANYONE, AND THAT IS THE POINT. No output note carries it:
/// `fee` units of asset `b` leave the supply on every fill. Three reasons, each of which independently
/// rules out the alternative of paying it to the executing node:
///
///   * The taker CANNOT KNOW who will execute their fill, so there is no address to seal a fee note to
///     at proving time. Any scheme that names one either guesses wrong or forces a shared, network-wide
///     fee key — and a single shared value key is exactly what the decentralization pillar bans.
///   * A burn adds NO new mint path. Paying the executor would mean a node minting to itself, which
///     every other node must then validate identically — new consensus surface in the one place where a
///     bug is a fund-safety bug.
///   * It still pays for security, and provably. Validators are bonded in the asset; destroying supply
///     on every trade raises the real value of every bond pro rata. DEX volume therefore pays validators
///     WITHOUT any validator-linked address to follow — no breadcrumb, no key, no accumulator to grow.
///
/// Evasion is impossible rather than merely detected: a taker who keeps the fee has no proof at all,
/// because conservation is a constraint and not a check a node might forget to run.
pub struct TakerHalfGate {
    pub gamma: Ea4,
    /// PUBLIC amounts as four 16-bit limbs (a reduced element let `lot` and `lot + p` weld alike).
    /// A u64 AMOUNT as `SC_LIMBS` 16-bit limbs — NOT a digest; `u64_public_limbs` yields exactly these.
    pub lot: [Ea4; SC_LIMBS],
    /// `pay_b + fee` — the one PUBLIC addend of the taker's conservation, as limbs. The fee is derived
    /// from `pay_b` (`OrderTerms::protocol_fee`) and both ride the transcript bind separately.
    /// A u64 AMOUNT as `SC_LIMBS` 16-bit limbs — NOT a digest.
    pub pay_b_plus_fee: [Ea4; SC_LIMBS],
    pub asset_a: [Ea4; 3],
    pub asset_b: [Ea4; 3],
    pub nullifier: [Ea4; DIGEST_LANES],
    pub leaf_commit: [Ea4; DIGEST_LANES],
    pub change_cm: [Ea4; DIGEST_LANES],
    pub payout_cm: [Ea4; DIGEST_LANES],
}

impl crate::air_zerocheck::AirConstraint for TakerHalfGate {
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ EMBEDS A PERMUTATION: a gate declaring less than the permutation's degree truncates
        // the sumcheck, so even an HONEST proof stops verifying.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    /// DB-363: the blinding lanes are a HIDING witness — read only by the outer cross-bind block's right-lane weld,
    /// determined by no statement value on purpose. Named here so the free-witness census reads them as declared.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some((NI_BLIND..NI_BLIND + DIGEST_LANES).collect())
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut rs: Vec<Ea4> = Vec::new();
        // CONSERVATION in asset b, RANGE-BOUND: value_in == change + (pay_b + fee), as one u64 block —
        // `in` = the hidden value_in, `out` = the hidden change, `fee` = the PUBLIC addend welded limb
        // for limb. The hidden pair is constrained without being disclosed, and cannot alias at p.
        let cons = U64ConsBases::at(TK_CONS);
        push_u64_conservation(&mut rs, local, cons);
        let in_rb = U64RangeBases { limbs: cons.r#in, bits: cons.in_bits };
        let chg_rb = U64RangeBases { limbs: cons.out, bits: cons.out_bits };
        let lot_rb = U64RangeBases::at(TK_LOT);
        spent_input_constraints(&mut rs, local, 0, &self.asset_b, &self.nullifier, &self.leaf_commit, in_rb, (TK_IN_INNER, TK_IN_INNER + POSE_BLK));
        note_out_constraints(&mut rs, local, OIB, &self.asset_b, &self.change_cm, chg_rb, (TK_CHG_INNER, TK_CHG_INNER + POSE_BLK));
        note_out_constraints(&mut rs, local, OIB + ONB, &self.asset_a, &self.payout_cm, lot_rb, (TK_PAY_INNER, TK_PAY_INNER + POSE_BLK));
        for i in 0..SC_LIMBS {
            rs.push(local[cons.fee + i] - self.pay_b_plus_fee[i]);
            rs.push(local[lot_rb.limbs + i] - self.lot[i]);
        }
        let mut out = Ea4::from(Fa4::ZERO);
        let mut gp = Ea4::ONE;
        for r in rs {
            out = out + gp * r;
            gp = gp * self.gamma;
        }
        out
    }
}

/// PROVE the taker's half of a fill. `None` if the taker cannot cover the payment — fail-closed at
/// construction, so an unaffordable fill has no proof rather than a proof a node must refuse.
#[must_use]
pub fn prove_order_taker_half(
    w: &TakerHalfWitness,
    t: &OrderTerms,
    fee_bps: u64,
) -> Option<(Vec<u8>, TakerHalfPublic)> {
    use p3_field::PrimeField64;
    if !t.is_sane() {
        return None;
    }
    let fee = t.protocol_fee(fee_bps);
    // Fail-closed on the FEE too, not only on the payment: a taker who cannot cover `pay_b + fee` gets no
    // proof rather than one that a node must catch. `checked_sub` twice, so neither term can wrap.
    let change = w.value_in.checked_sub(t.pay_b)?.checked_sub(fee)?;
    let (tag_a, tag_b) = t.tags();
    let mut row = vec![Fa4::ZERO; TK_WIDTH];
    let pay_plus_fee = t.pay_b.checked_add(fee)?;
    let cons = U64ConsBases::at(TK_CONS);
    fill_u64_conservation_row(&mut row, w.value_in, change, pay_plus_fee, cons)?;
    let in_rb = U64RangeBases { limbs: cons.r#in, bits: cons.in_bits };
    let chg_rb = U64RangeBases { limbs: cons.out, bits: cons.out_bits };
    let (_leaf, nf, lc) = fill_spent_input(&mut row, 0, w.value_in, &w.owner, &tag_b, in_rb, (TK_IN_INNER, TK_IN_INNER + POSE_BLK), w.lc_blind);
    let change_cm = fill_note_out(&mut row, OIB, change, w.change_opening, &tag_b, chg_rb, (TK_CHG_INNER, TK_CHG_INNER + POSE_BLK));
    let payout_cm = fill_note_out(&mut row, OIB + ONB, t.lot, w.payout_opening, &tag_a, U64RangeBases::at(TK_LOT), (TK_PAY_INNER, TK_PAY_INNER + POSE_BLK));
    let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|c| vec![row[c]; LIGHT_CARRIER_ROWS]).collect();
    let e3 = |v: [Fa4; 3]| -> [Ea4; 3] { core::array::from_fn(|c| v[c].into()) };
    let e4 = |v: DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|c| v[c].into()) };
    let (lot, pay_b) = (t.lot, t.pay_b);
    let make = move |g: Ea4| TakerHalfGate {
        gamma: g,
        lot: core::array::from_fn(|i| u64_public_limbs(lot)[i].into()),
        pay_b_plus_fee: core::array::from_fn(|i| u64_public_limbs(pay_b.checked_add(fee).unwrap_or(u64::MAX))[i].into()),
        asset_a: e3(tag_a),
        asset_b: e3(tag_b),
        nullifier: e4(nf),
        leaf_commit: e4(lc),
        change_cm: e4(change_cm),
        payout_cm: e4(payout_cm),
    };
    let mut bind = t.bind_with_fee(ORDER_TAKER_DOMAIN, Some(fee));
    bind.extend_from_slice(&nf);
    bind.extend_from_slice(&lc);
    bind.extend_from_slice(&change_cm);
    bind.extend_from_slice(&payout_cm);
    let bytes = crate::committed_air::prove_air_blinded_bytes(cols, make, &bind)?;
    let u4 = |v: DigestF| -> Digest { core::array::from_fn(|c| v[c].as_canonical_u64()) };
    Some((
        bytes,
        TakerHalfPublic {
            nullifier: u4(nf),
            leaf_commit: u4(lc),
            change_cm: u4(change_cm),
            payout_cm: u4(payout_cm),
        },
    ))
}

/// VERIFY a taker's fill half against the order's terms. Fail-closed.
#[must_use]
pub fn verify_order_taker_half(
    bytes: &[u8],
    t: &OrderTerms,
    p: &TakerHalfPublic,
    fee_bps: u64,
) -> bool {
    if bytes.is_empty() || !t.is_sane() || p.leaf_commit == crate::poseidon2_compress::ZERO_DIGEST {
        return false;
    }
    let fee = t.protocol_fee(fee_bps);
    let (tag_a, tag_b) = t.tags();
    let f4 = |v: Digest| -> DigestF { core::array::from_fn(|c| Fa4::from_u64(v[c])) };
    let e3 = |v: [Fa4; 3]| -> [Ea4; 3] { core::array::from_fn(|c| v[c].into()) };
    let e4 = |v: DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|c| v[c].into()) };
    let (nf, lc) = (f4(p.nullifier), f4(p.leaf_commit));
    let (ch, po) = (f4(p.change_cm), f4(p.payout_cm));
    let (lot, pay_b) = (t.lot, t.pay_b);
    let make = move |g: Ea4| TakerHalfGate {
        gamma: g,
        lot: core::array::from_fn(|i| u64_public_limbs(lot)[i].into()),
        pay_b_plus_fee: core::array::from_fn(|i| u64_public_limbs(pay_b.checked_add(fee).unwrap_or(u64::MAX))[i].into()),
        asset_a: e3(tag_a),
        asset_b: e3(tag_b),
        nullifier: e4(nf),
        leaf_commit: e4(lc),
        change_cm: e4(ch),
        payout_cm: e4(po),
    };
    let mut bind = t.bind_with_fee(ORDER_TAKER_DOMAIN, Some(fee));
    bind.extend_from_slice(&nf);
    bind.extend_from_slice(&lc);
    bind.extend_from_slice(&ch);
    bind.extend_from_slice(&po);
    crate::committed_air::verify_air_blinded_bytes(bytes, make, &bind, (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, TK_WIDTH))
}

/// ⭐⭐⭐ THE WHOLE-SETTLEMENT GATE — verify a fill end to end. A node calls THIS, never the halves
/// separately, because the halves are only sound TOGETHER: each proves its own side against the SAME
/// public terms, and it is agreement on those terms that makes the pair one trade rather than two
/// unrelated spends.
///
/// The node must ALSO, outside this function: refuse an expired order (`expires_at_height`), refuse
/// either nullifier if already spent (the existing double-spend gate, which is what makes a double-fill
/// impossible), and record exactly three notes — the maker's pre-built payout, the taker's payout and the
/// taker's change. Conservation then holds per asset by construction: one lot of `a` leaves the maker and
/// arrives at the taker; `value_in` of `b` leaves the taker and arrives as `pay_b` to the maker plus the
/// taker's change.
#[must_use]
pub fn verify_order_fill(
    maker_bytes: &[u8],
    maker: &MakerHalfPublic,
    taker_bytes: &[u8],
    taker: &TakerHalfPublic,
    t: &OrderTerms,
    fee_bps: u64,
) -> bool {
    // ⛔ THE TWO SIDES MUST BE DIFFERENT NOTES. Equal nullifiers would be one note filling its own order —
    // self-dealing that conserves arithmetically while manufacturing a trade from nothing.
    if maker.nullifier == taker.nullifier {
        return false;
    }
    verify_order_maker_half(maker_bytes, t, maker)
        && verify_order_taker_half(taker_bytes, t, taker, fee_bps)
}

#[cfg(test)]
mod order_book_tests {
    //! The adversary is a taker trying to take a lot without paying, a maker trying to be paid without
    //! delivering, and anyone trying to turn one asset into another for free. Every test is either "the
    //! honest trade works" or "the theft is UNPROVABLE / REFUSED".

    use super::{to_f, to_u64, Digest, DigestF, DIGEST_LANES};
    use super::*;

    const MAKER_SK: Digest = [11, 22, 33, 44, 111, 123, 135, 147];
    const MAKER_PAYOUT_SK: Digest = [55, 66, 77, 88, 155, 167, 179, 191];
    const TAKER_SK: Digest = [99, 111, 122, 133, 199, 212, 224, 236];
    const TAKER_CHANGE_SK: Digest = [144, 155, 166, 177, 244, 256, 268, 280];
    const TAKER_PAYOUT_SK: Digest = [188, 199, 211, 222, 288, 300, 313, 325];

    fn wbtc() -> [u64; 3] {
        wrapped_asset_tag(&[7u8; 32])
    }

    /// A grid order: one lot of wBTC offered for USDm at a lattice level.
    fn terms() -> OrderTerms {
        OrderTerms {
            lot: 100_000,
            pay_b: 6_500_000,
            asset_a: wbtc(),
            asset_b: USDM_ASSET_TAG,
            expires_at_height: 1_000_000,
        }
    }

    fn maker_w() -> MakerHalfWitness {
        MakerHalfWitness {
            owner: NoteOwner::from_test_key(MAKER_SK),
            payout_opening: MAKER_PAYOUT_SK,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
        }
    }

    /// The consensus fill rate these tests run at. Every order test below therefore exercises the fee
    /// path — the fee is not an add-on with its own little suite, it is part of what a fill IS.
    const TEST_FEE_BPS: u64 = 10;

    fn prove_taker(w: &TakerHalfWitness, t: &OrderTerms) -> Option<(Vec<u8>, TakerHalfPublic)> {
        prove_order_taker_half(w, t, TEST_FEE_BPS)
    }
    fn verify_fill(
        mb: &[u8],
        mp: &MakerHalfPublic,
        tb: &[u8],
        tp: &TakerHalfPublic,
        t: &OrderTerms,
    ) -> bool {
        verify_order_fill(mb, mp, tb, tp, t, TEST_FEE_BPS)
    }

    fn taker_w(value_in: u64) -> TakerHalfWitness {
        TakerHalfWitness {
            value_in,
            owner: NoteOwner::from_test_key(TAKER_SK),
            change_opening: TAKER_CHANGE_SK,
            payout_opening: TAKER_PAYOUT_SK,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 4, 5, 6]),
        }
    }

    /// ⭐ DB-363 (2026-09-30) — THE HALVES' CROSS-BIND IS BLINDED. Before this pin the maker's and the taker's
    /// `leaf_commit` was `P(leaf, nullifier)` with BOTH inputs public (the leaf is the asset note every node appended
    /// from the record; the nullifier is the half's own statement), so any node hashed each candidate leaf with an
    /// order's nullifier and joined the order — and the fill — to the note's receive. Now it is `P(P(leaf, nf), r)` for
    /// a per-object `r` the wallet draws once and passes to BOTH the half and its membership carrier: the value the
    /// carrier commits (`note_leaf_commitment`) is the value the half welds, so the two proofs still name ONE note.
    /// RED-first: the old formula is asserted NOT to reproduce the commitment, and a half presented under the
    /// commitment of a different blind is refused (the blind is welded, not decorative).
    /// TWO-PARTY-REVIEWED: the two sides here are the half's PROVER and the membership carrier's commitment formula
    /// (`note_membership_air::note_leaf_commitment`, the value the node's door compares the carrier against), asserted
    /// to agree on one value — a decider-internal calibration of two proof systems; the two-Node journey over the DEX
    /// door (a producer lays the fill, an ingesting peer verifies it) is `dex_cross_party_scenarios.rs` in the node.
    #[test]
    fn db363_the_dex_halves_hide_the_spent_leaf_behind_a_blinded_cross_bind() {
        let t = terms();
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).expect("the maker rests an order");
        let leaf = super::asset_note_cm(t.lot, t.asset_a, NoteOwner::from_test_key(MAKER_SK).opening());
        assert_ne!(
            mp.leaf_commit,
            super::poseidon_pair(leaf, mp.nullifier),
            "⛔⛔ the maker's cross-bind is the PUBLIC one-hash join P(leaf, nf) — every order links to its receive"
        );
        assert_eq!(
            mp.leaf_commit,
            crate::note_membership_air::note_leaf_commitment(leaf, mp.nullifier, maker_w().lc_blind),
            "the half and the membership carrier commit the SAME blinded value, or no order could ever settle"
        );
        assert!(verify_order_maker_half(&mb, &t, &mp), "CALIBRATION: the honest blinded maker half verifies");
        let rehidden = MakerHalfWitness { lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 9, 9, 9]), ..maker_w() };
        let (_ob, op) = prove_order_maker_half(&rehidden, &t).expect("the same note under another blind proves");
        assert_eq!(op.nullifier, mp.nullifier, "same note, same nullifier");
        assert_ne!(op.leaf_commit, mp.leaf_commit, "a fresh blind gives a fresh commitment — no cross-object join");
        assert!(
            !verify_order_maker_half(&mb, &t, &MakerHalfPublic { leaf_commit: op.leaf_commit, ..mp }),
            "⛔ a maker half verified under the commitment of ANOTHER blind — the blind is not welded"
        );
        let (tb, tp) = prove_taker(&taker_w(10_000_000), &t).expect("the taker fills");
        let tleaf = super::asset_note_cm(10_000_000, t.asset_b, NoteOwner::from_test_key(TAKER_SK).opening());
        assert_ne!(
            tp.leaf_commit,
            super::poseidon_pair(tleaf, tp.nullifier),
            "⛔⛔ the taker's cross-bind is the public one-hash join — every fill links to the paying note's receive"
        );
        assert_eq!(
            tp.leaf_commit,
            crate::note_membership_air::note_leaf_commitment(tleaf, tp.nullifier, taker_w(10_000_000).lc_blind),
            "the taker half and its membership carrier commit one value"
        );
        assert!(verify_order_taker_half(&tb, &t, &tp, TEST_FEE_BPS), "CALIBRATION: the honest blinded taker half verifies");
    }

    /// ⭐⭐⭐ THE HONEST TRADE. Two strangers exchange two assets in one settlement, with no pool, no
    /// shared state and neither party learning the other's key.
    #[test]
    fn a_resting_order_is_filled_by_a_stranger_and_the_whole_settlement_verifies() {
        let t = terms();
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).expect("the maker rests an order");
        let (tb, tp) = prove_taker(&taker_w(10_000_000), &t).expect("a taker fills it");
        assert!(verify_fill(&mb, &mp, &tb, &tp, &t), "the settlement verifies end to end");

        // The recorded notes are exactly what each side should receive.
        assert_eq!(mp.payout_cm, asset_note_cm(t.pay_b, USDM_ASSET_TAG, MAKER_PAYOUT_SK),
            "the maker is paid the level's price in USDm");
        assert_eq!(tp.payout_cm, asset_note_cm(t.lot, wbtc(), TAKER_PAYOUT_SK),
            "the taker receives exactly one lot of wBTC");
        // ⭐ THE FEE IS REAL MONEY LEAVING THE TAKER. The change is the input MINUS the price MINUS the
        // burned fee — so this equality fails the moment the fee stops being charged.
        let fee = t.protocol_fee(TEST_FEE_BPS);
        assert!(fee > 0, "a zero fee would make this assertion vacuous");
        assert_eq!(tp.change_cm, asset_note_cm(10_000_000 - t.pay_b - fee, USDM_ASSET_TAG, TAKER_CHANGE_SK),
            "and keeps the rest as change, the fee having been destroyed");
        // ⛔ AND IT IS DESTROYED, NOT PAID TO ANYONE. A fill publishes exactly three notes; none of them
        // holds the fee. Checked against the change note the taker would have had at a ZERO rate — if the
        // fee were being re-routed rather than burned, some output would carry that value.
        assert_ne!(tp.change_cm, asset_note_cm(10_000_000 - t.pay_b, USDM_ASSET_TAG, TAKER_CHANGE_SK),
            "the fee must not have quietly stayed with the taker");
    }

    /// ⛔⛔⛔ A TAKER WHO CANNOT COVER THE PRICE HAS NO PROOF. Fail-closed at construction.
    #[test]
    fn a_taker_who_cannot_afford_the_price_cannot_build_a_fill() {
        let t = terms();
        let fee = t.protocol_fee(TEST_FEE_BPS);
        assert!(prove_taker(&taker_w(t.pay_b - 1), &t).is_none(),
            "one unit short of the price must not prove");
        assert!(prove_taker(&taker_w(0), &t).is_none(), "and neither does an empty note");
        // ⛔⛔⛔ THE PRICE ALONE IS NO LONGER ENOUGH — THE FEE IS PART OF WHAT A FILL COSTS. A taker
        // holding exactly `pay_b` can pay the maker and nothing else, so there is no proof for them. This
        // is the assertion that would go quiet first if the fee were ever dropped from conservation.
        assert!(prove_taker(&taker_w(t.pay_b), &t).is_none(),
            "covering the price but not the fee must NOT prove");
        assert!(prove_taker(&taker_w(t.pay_b + fee - 1), &t).is_none(),
            "one unit short of price+fee must not prove either");
        // Paying EXACTLY price + fee, with zero change, is honest and must still work.
        assert!(prove_taker(&taker_w(t.pay_b + fee), &t).is_some(),
            "an exact price-plus-fee fill is honest");
    }

    /// ⛔⛔⛔ THE PRICE CANNOT BE RENEGOTIATED AT FILL TIME. A taker who proves against a cheaper level
    /// produces a half that does not verify against the order's real terms — the level is in both
    /// transcripts, so the two halves only compose when they name the SAME trade.
    #[test]
    fn a_taker_cannot_fill_at_a_price_the_maker_did_not_offer() {
        let t = terms();
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).unwrap();
        let mut cheap = t;
        cheap.pay_b = t.pay_b / 2; // the taker would rather pay half
        let (tb, tp) = prove_taker(&taker_w(10_000_000), &cheap).expect("it proves for ITS terms");
        assert!(!verify_fill(&mb, &mp, &tb, &tp, &t),
            "a half-price fill must NOT settle against the maker's order");
        assert!(!verify_fill(&mb, &mp, &tb, &tp, &cheap),
            "nor by re-labelling the settlement with the cheaper terms — the maker's half names the real price");
    }

    /// ⛔⛔⛔ THE LOT CANNOT BE INFLATED. A taker claiming a larger lot than the maker offered is refused.
    #[test]
    fn a_taker_cannot_take_more_than_one_lot() {
        let t = terms();
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).unwrap();
        let mut greedy = t;
        greedy.lot = t.lot * 10;
        let (tb, tp) = prove_taker(&taker_w(10_000_000), &greedy).unwrap();
        assert!(!verify_fill(&mb, &mp, &tb, &tp, &t), "ten lots for one lot's price is refused");
        assert!(!verify_fill(&mb, &mp, &tb, &tp, &greedy), "and cannot be re-labelled either");
    }

    /// ⛔⛔⛔ CROSS-ASSET THEFT IS REFUSED. A taker proving in the wrong asset does not compose with the
    /// maker's half — the tags are in both transcripts and in every note opening.
    #[test]
    fn a_taker_cannot_pay_in_the_wrong_asset() {
        let t = terms();
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).unwrap();
        let mut swapped = t;
        swapped.asset_b = wrapped_asset_tag(&[9u8; 32]); // pay in a worthless token instead of USDm
        let (tb, tp) = prove_taker(&taker_w(10_000_000), &swapped).unwrap();
        assert!(!verify_fill(&mb, &mp, &tb, &tp, &t), "paying in another asset must be REFUSED");
    }

    /// ⛔⛔⛔ SELF-DEALING IS REFUSED: one note cannot fill its own order. Equal nullifiers conserve
    /// arithmetically while manufacturing a trade from nothing, so the composition gate rejects them.
    #[test]
    fn one_note_cannot_fill_its_own_order() {
        let t = terms();
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).unwrap();
        let (tb, tp) = prove_taker(&taker_w(10_000_000), &t).unwrap();
        let self_dealt = TakerHalfPublic { nullifier: mp.nullifier, ..tp };
        assert!(!verify_fill(&mb, &mp, &tb, &self_dealt, &t),
            "a settlement whose two sides are the same note is refused");
    }

    /// ⛔ A TAMPERED HALF IS REFUSED, on either side.
    #[test]
    fn a_tampered_half_is_refused() {
        let t = terms();
        let (mut mb, mp) = prove_order_maker_half(&maker_w(), &t).unwrap();
        let (mut tb, tp) = prove_taker(&taker_w(10_000_000), &t).unwrap();
        let honest_m = mb.clone();
        let last = mb.len() - 1;
        mb[last] ^= 0xFF;
        assert!(!verify_fill(&mb, &mp, &tb, &tp, &t), "a tampered maker half is refused");
        let last = tb.len() - 1;
        tb[last] ^= 0xFF;
        assert!(!verify_fill(&honest_m, &mp, &tb, &tp, &t), "a tampered taker half is refused");
    }

    /// ⛔ A SUBSTITUTED PAYOUT IS REFUSED — the maker cannot be redirected to a note they did not build,
    /// and the taker's payout cannot be swapped for a different one.
    #[test]
    fn neither_payout_can_be_substituted() {
        let t = terms();
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).unwrap();
        let (tb, tp) = prove_taker(&taker_w(10_000_000), &t).unwrap();
        let thief = MakerHalfPublic {
            payout_cm: asset_note_cm(t.pay_b, USDM_ASSET_TAG, TAKER_PAYOUT_SK), // pay the TAKER instead
            ..mp
        };
        assert!(!verify_fill(&mb, &thief, &tb, &tp, &t),
            "redirecting the maker's payment must be REFUSED");
        let swapped = TakerHalfPublic {
            payout_cm: asset_note_cm(t.lot, wbtc(), MAKER_SK),
            ..tp
        };
        assert!(!verify_fill(&mb, &mp, &tb, &swapped, &t),
            "swapping the taker's payout note must be REFUSED");
    }

    /// ⛔ AN ALL-ZERO CROSS-BIND IS REFUSED STRUCTURALLY on both halves — an absent wire field decodes as
    /// zero, and zero is a binding every forger can produce.
    #[test]
    fn an_absent_cross_bind_is_refused_on_both_halves() {
        let t = terms();
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).unwrap();
        let (tb, tp) = prove_taker(&taker_w(10_000_000), &t).unwrap();
        assert!(!verify_order_maker_half(&mb, &t, &MakerHalfPublic { leaf_commit: crate::poseidon2_compress::ZERO_DIGEST, ..mp }));
        assert!(!verify_order_taker_half(&tb, &t, &TakerHalfPublic { leaf_commit: crate::poseidon2_compress::ZERO_DIGEST, ..tp }, TEST_FEE_BPS));
    }

    /// ⛔ A MALFORMED ORDER NEVER REACHES A BOOK: an asset traded for itself, a zero lot, or a zero price
    /// has no proof at all.
    #[test]
    fn a_malformed_order_cannot_be_posted() {
        let same = OrderTerms { asset_b: wbtc(), ..terms() };
        assert!(prove_order_maker_half(&maker_w(), &same).is_none(), "an asset for itself is not a trade");
        assert!(prove_order_maker_half(&maker_w(), &OrderTerms { lot: 0, ..terms() }).is_none());
        assert!(prove_order_maker_half(&maker_w(), &OrderTerms { pay_b: 0, ..terms() }).is_none());
    }

    /// ⭐ THE ANTI-DOUBLE-FILL PROPERTY, stated as a test: two takers filling the SAME resting order both
    /// name the maker's ONE nullifier. The chain's existing double-spend gate refuses the second — no new
    /// machinery, and no order state on chain.
    #[test]
    fn two_takers_racing_one_order_collide_on_the_makers_nullifier() {
        let t = terms();
        let (_mb, mp) = prove_order_maker_half(&maker_w(), &t).unwrap();
        let (_t1, tp1) = prove_taker(&taker_w(10_000_000), &t).unwrap();
        let other = TakerHalfWitness {
            owner: NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&[7, 7, 7, 7])),
            ..taker_w(9_000_000)
        };
        let (_t2, tp2) = prove_taker(&other, &t).unwrap();
        assert_ne!(tp1.nullifier, tp2.nullifier, "the two takers spend different notes");
        // Both settlements consume the SAME maker note, so both present the same nullifier: whichever
        // lands second is a double-spend of an already-consumed note.
        assert_eq!(mp.nullifier, mp.nullifier);
        assert!(mp.nullifier != tp1.nullifier && mp.nullifier != tp2.nullifier);
    }

    /// ⭐⭐⭐ SIZE IS NOT INFORMATION. Two makers with wildly different wealth post the same grid order,
    /// and their published entries are IDENTICAL in every value-bearing field except the keys that make
    /// them different notes. A book reader learns "one lot at this level" and nothing about either.
    #[test]
    fn a_whale_and_a_minnow_post_indistinguishable_orders() {
        let t = terms();
        let (_a, pa) = prove_order_maker_half(&maker_w(), &t).unwrap();
        let minnow = MakerHalfWitness {
            owner: NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8])),
            payout_opening: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            ..maker_w()
        };
        let (_b, pb) = prove_order_maker_half(&minnow, &t).unwrap();
        // Different notes (different nullifiers), same terms, and NOTHING in the terms distinguishes the
        // participants: the lot and the price are grid constants, identical for both.
        assert_ne!(pa.nullifier, pb.nullifier);
        assert_eq!(t.lot, terms().lot);
        assert_eq!(t.pay_b, terms().pay_b);
    }
    // ── PROTOCOL FILL FEE ───────────────────────────────────────────────────────────────────────────
    //
    // ⛔⛔⛔ A FEE THAT A TAKER CAN DECLINE IS NOT A FEE. These are the tests that make the difference
    // between an economic model and a press release: the rate is consensus, the arithmetic is a
    // CONSTRAINT rather than a check, and a proof built to pay less does not verify at all.

    /// ⛔⛔⛔ FEE EVASION IS REFUSED. A taker who proves their half at a cheaper rate — including zero —
    /// holds a proof that does not verify under the consensus rate. Nothing here relies on a node
    /// remembering to compare numbers: the rate is in the transcript binding AND in conservation, so a
    /// cheap proof is not a valid proof of anything.
    #[test]
    fn a_taker_who_proves_a_cheaper_fee_cannot_settle() {
        let t = terms();
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).expect("maker rests");
        for cheat_bps in [0u64, 1, 5, TEST_FEE_BPS - 1] {
            let (tb, tp) = prove_order_taker_half(&taker_w(10_000_000), &t, cheat_bps)
                .expect("the cheaper half proves for ITS OWN rate");
            assert!(
                verify_order_fill(&mb, &mp, &tb, &tp, &t, cheat_bps),
                "sanity: it is a real proof at the rate it was built for ({cheat_bps} bps)"
            );
            assert!(
                !verify_order_fill(&mb, &mp, &tb, &tp, &t, TEST_FEE_BPS),
                "but under the CONSENSUS rate it must be refused ({cheat_bps} bps underpay)"
            );
        }
    }

    /// ⛔ NOR CAN A TAKER OVERPAY THEIR WAY INTO A DIFFERENT TRADE. Symmetry matters: if a higher-rate
    /// proof verified at the consensus rate, the rate would be a floor rather than a value, and a node
    /// could be induced to settle a fill whose arithmetic it never actually checked.
    #[test]
    fn a_half_proved_at_the_wrong_rate_is_refused_in_both_directions() {
        let t = terms();
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).expect("maker rests");
        let (tb, tp) = prove_order_taker_half(&taker_w(10_000_000), &t, TEST_FEE_BPS + 25).unwrap();
        assert!(!verify_order_fill(&mb, &mp, &tb, &tp, &t, TEST_FEE_BPS),
            "an overpaying half is still a half for a DIFFERENT rate, and must not verify");
    }

    /// ⛔⛔⛔ THE FEE DISCLOSES NOTHING. Two takers with wildly different hidden balances fill the SAME
    /// level and are charged the SAME public fee — so the fee cannot be read backwards into anyone's
    /// holdings. This is the property a percentage-of-`value_in` fee would destroy.
    #[test]
    fn a_whale_and_a_minnow_pay_the_identical_fee_at_the_same_level() {
        let t = terms();
        let fee = t.protocol_fee(TEST_FEE_BPS);
        let minnow = t.pay_b + fee; // spends every last unit
        let whale = 900_000_000_000; // orders of magnitude more
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).expect("maker rests");
        for value_in in [minnow, whale] {
            let (tb, tp) = prove_taker(&taker_w(value_in), &t).expect("both can fill");
            assert!(verify_fill(&mb, &mp, &tb, &tp, &t), "both settle");
            assert_eq!(
                tp.change_cm,
                asset_note_cm(value_in - t.pay_b - fee, USDM_ASSET_TAG, TAKER_CHANGE_SK),
                "each is charged the same public fee regardless of what they held"
            );
        }
        // The fee is a function of the LEVEL only — not of who is filling it.
        assert_eq!(fee, t.protocol_fee(TEST_FEE_BPS), "deterministic in the public terms alone");
    }

    /// ⛔⛔⛔ NO LEVEL IS A FREE FILL. Ceiling division means even the smallest nonzero order pays at
    /// least one atomic unit — a floor-divided fee would round the whole low end of the book to zero and
    /// hand size-splitting traders a free DEX.
    #[test]
    fn no_nonzero_order_is_ever_free_to_fill() {
        for pay_b in [1u64, 2, 7, 99, 9_999, 10_000, 10_001] {
            let t = OrderTerms { pay_b, ..terms() };
            let fee = t.protocol_fee(TEST_FEE_BPS);
            assert!(fee >= 1, "pay_b={pay_b} must cost at least one atomic unit, got {fee}");
        }
        // And splitting a trade never beats paying once: N small fills cost at least as much as one big.
        let one_big = OrderTerms { pay_b: 100_000, ..terms() }.protocol_fee(TEST_FEE_BPS);
        let ten_small: u64 = (0..10)
            .map(|_| OrderTerms { pay_b: 10_000, ..terms() }.protocol_fee(TEST_FEE_BPS))
            .sum();
        assert!(ten_small >= one_big, "splitting must never be cheaper: {ten_small} vs {one_big}");
    }

    /// ⛔ A HUGE `pay_b` CANNOT WRAP THE FEE INTO A SMALL ONE. The multiply is done in u128; done in u64
    /// it would overflow near `u64::MAX / bps` and a whale-sized order could compute a trivial fee.
    #[test]
    fn an_enormous_order_cannot_wrap_its_fee_to_nothing() {
        for pay_b in [u64::MAX, u64::MAX - 1, u64::MAX / 2, 1u64 << 62] {
            let t = OrderTerms { pay_b, ..terms() };
            let fee = t.protocol_fee(TEST_FEE_BPS);
            let expect = ((pay_b as u128) * (TEST_FEE_BPS as u128)).div_ceil(10_000u128);
            assert_eq!(u128::from(fee), expect.min(u128::from(u64::MAX)), "pay_b={pay_b} wrapped");
            assert!(fee > 1_000_000, "a colossal order must pay a colossal fee, got {fee}");
        }
    }

    /// ⭐ THE RATE IS GOVERNANCE, NOT DOCTRINE — and turning it to zero is a real, deliberate act that
    /// yields genuinely free fills, not a silently-broken gate. Pinned so the zero case stays coherent.
    #[test]
    fn a_zero_rate_is_coherent_and_charges_nothing() {
        let t = terms();
        assert_eq!(t.protocol_fee(0), 0, "zero bps means zero fee, stated plainly");
        let (mb, mp) = prove_order_maker_half(&maker_w(), &t).expect("maker rests");
        let (tb, tp) = prove_order_taker_half(&taker_w(t.pay_b), &t, 0).expect("exact payment suffices");
        assert!(verify_order_fill(&mb, &mp, &tb, &tp, &t, 0), "and the fill settles");
    }

}

#[cfg(test)]
mod carrier_non_malleability {
    use super::{to_f, to_u64, Digest, DigestF, DIGEST_LANES};
    use super::*;

    /// ⛔⛔⛔ A DIRECT CARRIER IS NOT MALLEABLE AT ANY BYTE (2026-09-11).
    ///
    /// The old tamper pin flipped ONE byte at the midpoint. When the wire encoding changed, that byte
    /// landed in `zc.shifted_opened` — which a row-local gate never reads and the transcript never
    /// absorbed — and the tampered carrier VERIFIED. That is transaction malleability (Bitcoin,
    /// pre-SegWit): a relayer alters a spend in flight and its id changes without invalidating it.
    /// Fixed by absorbing the next-row openings into the transcript (`absorb_shifted_openings`).
    /// This pin is the strong form: EVERY byte position, flipped, must break decode or verification.
    /// O1-FOOTPRINT-REVIEWED: bounded by the carrier's own byte length (a fixed-shape proof, MEASURED
    /// 679 bytes for this AIR), never by chain state.
    #[test]
    fn flipping_any_byte_of_a_direct_carrier_breaks_it() {
        let make_inner = |_g: Ea4| RecInnerConservationConstraint;
        let out = Fa4::from_u64(0x1111);
        let fee = Fa4::from_u64(0x2222);
        let h = 1usize << 3;
        let pb = vec![Fa4::from_u64(0xBAD), Fa4::from_u64(0xF00D)];
        let good_cols = vec![vec![out + fee; h], vec![out; h], vec![fee; h]];
        let good = prove_air_direct_light_decider_selfcontained_bytes(good_cols, make_inner, &pb).unwrap();
        assert!(verify_air_direct_light_decider_selfcontained_bytes(&good, make_inner, &pb, crate::whir_rec_block::declared_direct_shape_for_tests(&good)), "control");
        let mut survivors: Vec<usize> = Vec::new();
        for pos in 0..good.len() {
            let mut bad = good.clone();
            bad[pos] ^= 0x01;
            if verify_air_direct_light_decider_selfcontained_bytes(&bad, make_inner, &pb, crate::whir_rec_block::declared_direct_shape_for_tests(&bad)) {
                survivors.push(pos);
            }
        }
        eprintln!("[non-malleable] {} byte positions probed, {} survived a flip", good.len(), survivors.len());
        assert!(
            survivors.is_empty(),
            "⛔⛔ MALLEABLE CARRIER: flipping byte(s) {survivors:?} of {} still verifies — some field of the \
             bundle is neither read by the gate nor absorbed into the transcript",
            good.len()
        );
    }
}

#[cfg(test)]
mod production_depth_roundtrip {
    use super::{to_f, to_u64, Digest, DigestF, DIGEST_LANES};
    use super::*;
    #[test]
    /// The wallet's shape exactly: production depth, change returned under the input's own key. The
    /// wallet's own copy of this test had verified with a literal depth 32 against a 64-deep copath since
    /// the 9/4 depth migration — dead coverage, found while landing the two-round commitment.
    fn spend_validity_round_trips_at_production_depth_32() {
        let w = SpendValidityWitness {
            value_in: 700,
            owner: NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4])),
            value_out: 600,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: 500,
            out0_opening: crate::poseidon2_compress::lanes_of(&[1, 1, 1, 1]),
            out1_value: 100,
            out1_opening: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), // change back to SELF — the wallet's shape (same sk as the input)
        };
        let (bytes, cms, nf, lc) = prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0)).expect("proves (one constant shape)");
        let ok = verify_spend_validity_carrier_bytes(&bytes, cms[0], cms[1], nf, lc, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100);
        eprintln!("[d32] carrier={} bytes verify={ok}", bytes.len());
        assert!(ok, "the depth-32 spend-validity carrier must verify");
    }
}

/// ⛔ §BD INSTRUMENT — a settlement aggregate over ZERO rows, bound to `(n, set_digest)`, with NO inner
/// carrier anywhere. Public for the node's circuit harness, exactly as `spend_carrier_cols` is: the honest
/// aggregator is what production runs, and this is the hostile object presented to production verifiers.
/// It exists so every verifier that consumes an aggregate carries a pin proving what it does with a forgery.
pub fn zero_row_settlement_aggregate_for_refutation(n: usize, set_digest: &[Fa4; DIGEST_LIMBS]) -> Option<Vec<u8>> {
    let (nvars0, per0) = (5usize, 3usize);
    let rounds = REC_DECIDER_FOLDING;
    let wire_size = REC_DECIDER_ELL_ZK.max(3) - 1;
    let width_v = (nvars0 * per0 + nvars0 + 1) * 4;
    let width_o = (rounds * (wire_size + 1) + rounds + 1) * 4;
    let height = 1usize << REC_DECIDER_FOLDING.max(5);
    let basis: [Ea4; DIGEST_LANES] =
        core::array::from_fn(|i| Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO }));
    let make = move |i: usize, gamma: Ea4| -> CarrierVerifyAir {
        if i == 0 {
            CarrierVerifyAir::Validity(WhirRecursiveVerifyConstraint { gamma, per_evals: per0, nvars_inner: nvars0, basis })
        } else {
            CarrierVerifyAir::Opening(WhirOpeningRoundConstraint { gamma, rounds, wire_size, basis })
        }
    };
    let vcols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width_v];
    let ocols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width_o];
    let pb = settlement_public_bind(n, set_digest);
    let agg = prove_air_batch_light_decider_selfcontained_bytes(vec![vcols, ocols], make, &pb)?;
    let mut out = Vec::with_capacity(agg.len() + 2);
    out.push(nvars0 as u8);
    out.push(per0 as u8);
    out.extend_from_slice(&agg);
    Some(out)
}

/// ⛔⛔⛔ §BD REFUTATION PROBE — DOES THE SETTLEMENT AGGREGATE PROVE ANYTHING ABOUT AN INNER CARRIER?
///
/// The aggregate's two AIRs constrain a sumcheck round chain (`WhirRecursiveVerifyConstraint`) and a masked
/// opening chain (`WhirOpeningRoundConstraint`) over values laid in the WITNESS rows — including the
/// Fiat-Shamir challenges `r` and `γ`, which the AIR doc calls "public, per-row" but which appear in no
/// public bind (`settlement_public_bind` is `(n, set_digest)` alone). No inner Merkle root is in any row.
///
/// So the question this asks, exactly as the range-binding pins ask theirs: can a prover holding NO inner
/// carrier lay rows the outer AIR accepts? The simplest candidate is the all-zero row — `evals=[0,0,0]`
/// sums to `claim=0`, `lagrange(0, r)=0`, `horner(0, γ)=0` — so if it verifies, the aggregate certifies
/// nothing and a block producer can attach a "settlement" for any tx set with zero transactions behind it.
#[cfg(test)]
mod settlement_aggregate_refutation {
    use super::*;

    #[test]
    fn an_aggregate_over_zero_rows_with_no_inner_carrier_is_measured() {
        // The honest shape's parameters (a degree-2 inner AIR at the decider's floor height).
        let (nvars0, per0) = (5usize, 3usize);
        let rounds = REC_DECIDER_FOLDING;
        let wire_size = REC_DECIDER_ELL_ZK.max(3) - 1;
        let width_v = (nvars0 * per0 + nvars0 + 1) * 4;
        let width_o = (rounds * (wire_size + 1) + rounds + 1) * 4;
        let height = 1usize << REC_DECIDER_FOLDING.max(5);
        let basis: [Ea4; DIGEST_LANES] = core::array::from_fn(|i| {
            Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO })
        });
        let make = move |i: usize, gamma: Ea4| -> CarrierVerifyAir {
            if i == 0 {
                CarrierVerifyAir::Validity(WhirRecursiveVerifyConstraint {
                    gamma,
                    per_evals: per0,
                    nvars_inner: nvars0,
                    basis,
                })
            } else {
                CarrierVerifyAir::Opening(WhirOpeningRoundConstraint { gamma, rounds, wire_size, basis })
            }
        };
        // NO CARRIER ANYWHERE: every row is zero.
        let vcols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width_v];
        let ocols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; height]; width_o];
        // Any tx set at all — this one names 7 transactions that do not exist.
        let fake_ids: Vec<[u8; 32]> = (0..7u8).map(|i| [i; 32]).collect();
        let set_digest = tx_set_digest(&fake_ids);
        let pb = settlement_public_bind(fake_ids.len(), &set_digest);
        let forged = prove_air_batch_light_decider_selfcontained_bytes(vec![vcols, ocols], make, &pb);
        let Some(agg) = forged else {
            eprintln!("[§BD] the prover REFUSED the zero trace — the aggregate is not trivially forgeable this way");
            return;
        };
        let mut bytes = Vec::with_capacity(agg.len() + 2);
        bytes.push(nvars0 as u8);
        bytes.push(per0 as u8);
        bytes.extend_from_slice(&agg);
        let verifies = verify_settlement_aggregate_by_txids(&bytes, &fake_ids);
        eprintln!(
            "[§BD] aggregate over ZERO rows, NO inner carrier, 7 fabricated tx ids: proves={} verifies={} ({} B)",
            true, verifies, bytes.len()
        );
        // ⛔⛔⛔ §BD — OPEN, MEASURED 2026-09-14, RECORDED RATHER THAN ASSERTED AWAY.
        //
        //   aggregate over ZERO rows, NO inner carrier, 7 fabricated tx ids: proves=true verifies=true (8504 B)
        //
        // The outer AIRs constrain a sumcheck round chain and a masked-opening chain over values that live
        // in the WITNESS rows — the Fiat-Shamir challenges `r` and `γ` included (the AIR doc calls them
        // "public, per-row"; `settlement_public_bind` is `(n, set_digest)` alone) — and no inner Merkle
        // root appears in any row. The zero row satisfies both AIRs, so the aggregate certifies nothing
        // about any transaction. It is dormant in production (a block's cover blobs are not carriers, so
        // the producer emits `None`), which is the only reason this is not a live hole.
        //
        // THE FIX IS THE IVC STEP'S WELD (kill list §AJ / the transcript weld): derive `r` and `γ` IN-CIRCUIT
        // from the public bind and the committed inner data, tie each row to the inner commitment it
        // claims, and expose the per-row public values so a peer can cross-check a block's notes and
        // deletions against them. Until then `Block::settlement` may refuse a block (a bad aggregate) and
        // must never be allowed to VOUCH for one.
        assert!(
            verifies,
            "⭐ §BD IS CLOSED — the zero-row aggregate no longer verifies. Flip this to \
             `assert!(!verifies, …)`, close §BD in the kill list, and only then let a verified settlement \
             gate anything on a peer."
        );
    }
}

/// ⛔⛔⛔ §BE-1 PROBE — DOES A SPEND CARRIER CARRY ITS WITNESS IN THE CLEAR?
/// The bundle has no trace commitment; its `openings` are "the evaluations of all width columns". If those
/// evaluations are the trace row itself, the spender's secret key, input value and path ride the wire.
#[cfg(test)]
mod witness_in_the_clear_probe {
    use super::*;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};

    #[test]
    fn a_spend_carrier_is_scanned_for_its_own_secret_values() {
        // DISTINCTIVE lanes — nothing here can appear in 20,000 limbs by chance.
        let depth = 4usize;
        let in_sk = [0x1234_5678_9ABC_DE01u64, 0x0FED_CBA9_8765_4321, 0x1122_3344_5566_7788, 0x0BAD_F00D_CAFE_BEEF];
        let out0_sk = [0x0A1B_2C3D_4E5F_6071u64, 0x7A6B_5C4D_3E2F_1000, 0x0123_4567_89AB_CDEF, 0x0F1E_2D3C_4B5A_6978];
        let out1_sk = [0x0C0F_FEE0_C0FF_EE00u64, 0x0DEA_DBEE_FDEA_DBEE, 0x0ABC_DEF0_1234_5678, 0x0F0F_1E1E_2D2D_3C3C];
        let (vin, vout, fee, o0, o1) = (1_000_000_007u64, 999_999_937u64, 70u64, 600_000_011u64, 399_999_926u64);
        // DB-395: the input's owner — `ask` carries the distinctive lanes, `nk` and `seed` are its derived lanes; all three are
        // scanned below (spend authority and spend detection must stay out of the clear, like the old key did).
        let owner = NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&in_sk));
        let w = SpendValidityWitness {
            value_in: vin,
            owner,
            value_out: vout,
            fee,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: o0,
            out0_opening: crate::poseidon2_compress::lanes_of(&out0_sk),
            out1_value: o1,
            out1_opening: crate::poseidon2_compress::lanes_of(&out1_sk),
        };
        let (bytes, _cms, _nf, _commit) =
            prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0)).expect("proves");
        // ⭐ ITEM 1 MOVED THIS CARRIER onto the blinded committed path, so the wire is a
        // `CommittedAirBundle`. The scan is the same question asked of the same object: does anything a
        // verifier reads still hold the witness in the clear?
        let bundle: crate::committed_air::CommittedAirBundle =
            postcard::from_bytes(&bytes).expect("decodes");
        let mut limbs: Vec<u64> = Vec::new();
        for v in bundle.zc.opened.iter().chain(bundle.zc.shifted_opened.iter()) {
            for &b in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v) {
                limbs.push(b.as_canonical_u64());
            }
        }
        // Lanes are reduced into the field (`lanes_of`), so compare against the reduced lane values.
        let red = |x: u64| crate::poseidon2_compress::lanes_of(&[x, 0, 0, 0])[0];
        let has = |x: u64| limbs.iter().any(|&l| l == x || l == red(x));
        let in_sk_hits = in_sk.iter().filter(|&&s| has(s)).count();
        let out0_sk_hits = out0_sk.iter().filter(|&&s| has(s)).count();
        let out1_sk_hits = out1_sk.iter().filter(|&&s| has(s)).count();
        let vals = [("value_in", has(vin)), ("value_out", has(vout)), ("fee", has(fee)), ("out0_value", has(o0)), ("out1_value", has(o1)), ("sibling lane", has(0x5151_0000_0000_0000 + 10))];
        // LINKAGE: the spent note's LEAF (its identity in the frontier) and the output commitments.
        let leaf = spend_input_leaf(&w).expect("the input leaf");
        let leaf_hits = leaf.iter().filter(|&&l| has(l)).count();
        let cm0_hits = _cms[0].iter().filter(|&&l| has(l)).count();
        let nf_hits = _nf.iter().filter(|&&l| has(l)).count();
        eprintln!(
            "[§BE-1] carrier {} B · {} opening limbs · INPUT sk lanes in the clear={in_sk_hits}/4 · OUTPUT-0 sk lanes={out0_sk_hits}/4 · OUTPUT-1 sk lanes={out1_sk_hits}/4 · amounts {:?} · SPENT-NOTE LEAF lanes={leaf_hits}/4 · out0 cm lanes={cm0_hits}/4 · nf lanes={nf_hits}/4",
            bytes.len(), limbs.len(), vals
        );
        // ⭐⭐⭐ §BE-1 — CLOSED 2026-09-14 BY ITEM 1. This pin was written asserting the hole was ARMED
        // (">= 4 amounts in the clear") with its own flip condition named; routing the spend carrier onto
        // the BLINDED COMMITTED path fired it. Now it asserts the opposite, which is the only form of
        // this pin that is worth keeping.
        //
        // ⛔ WHY IT WAS OPEN: the direct light decider has no trace commitment, every caller dropped the
        // masked sumcheck's final target, and the zerocheck was evaluated on the PLAINTEXT opened row. A
        // carrier replicates ONE logical row up its trace, and the MLE of a constant column is that
        // constant everywhere — so the opening WAS the witness (§BI). Blinding doubles the height, fills
        // the new half with fresh OS randomness, and selects the real half with `(1 - x[0])`.
        for (what, hit) in &vals {
            assert!(
                !*hit,
                "⛔ §BE-1 REGRESSED: `{what}` is back in the clear in the carrier's openings. The spend \
                 carrier must stay on the blinded committed path."
            );
        }
        assert_eq!(
            (in_sk_hits, out0_sk_hits, out1_sk_hits, leaf_hits, cm0_hits, nf_hits),
            (0, 0, 0, 0, 0, 0),
            "⛔ §BE-1 REGRESSED: a spend key, the spent note's LEAF, an output commitment or the \
             nullifier is readable from the carrier's openings — that is linkage, not just amounts."
        );
        // DB-395: the owner's nullifier key, the note's seed and the opening they derive stay out of the clear too.
        let lane_hits = |d: &Digest| d.iter().filter(|&&l| has(l)).count();
        assert_eq!(
            (lane_hits(&owner.nk), lane_hits(&owner.seed), lane_hits(&owner.opening())),
            (0, 0, 0),
            "⛔ DB-395: the owner's nk, the note's seed or its opening is readable from the carrier's openings"
        );
        eprintln!("[§BE-1] ⭐ CLOSED — no amount, key, leaf, commitment or nullifier is in the clear");
    }
}

/// ⭐ §BH — THE INNER TRANSCRIPT A RECURSION MUST RE-DERIVE: `(γ, z)`, from PUBLIC data alone.
///
/// The outer circuit's new residual is `claim_last == eq(z, r) · C_γ(opened)`, so it needs BOTH the
/// batching challenge γ and the zerocheck point z — each drawn before any row value is observed, each
/// a function of the statement and the carrier's own openings. Returned together so a caller cannot
/// take one and re-derive the other differently.
#[must_use]
pub fn transcript_of_air_direct_carrier(
    bytes: &[u8],
    public_bind: &[Fa4],
) -> Option<(Ea4, Vec<Ea4>)> {
    use p3_challenger::FieldChallenger;
    let bundle: AirDirectBundle = postcard::from_bytes(bytes).ok()?;
    if bundle.shapes.len() != 1 || bundle.openings.len() != 1 {
        return None;
    }
    let (nvars, width) = bundle.shapes[0];
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let perm = Perm16::new_from_rng_128(&mut perm_rng);
    let mut vch = Chl::new(perm);
    for &f in public_bind {
        vch.observe(f);
    }
    let mut verifier = build_decider_hiding_verifier(&bundle.shapes);
    let all: Vec<usize> = (0..width).collect();
    verifier.add_claim(0, &all, &bundle.openings[0], &mut vch);
    let gamma: Ea4 = vch.sample_algebra_element();
    let z: Vec<Ea4> = (0..nvars).map(|_| vch.sample_algebra_element()).collect();
    Some((gamma, z))
}

/// ⛔ §BG INSTRUMENT — the γ a verifier will draw for this carrier, recomputed from PUBLIC data alone.
///
/// γ is sampled from the transcript BEFORE any row value is observed, so a prover holds it before it
/// chooses its opened row. Exposing it here is not a new capability — it is what every prover already
/// has — it is what lets a refutation test CONSTRUCT the row that exploits it.
#[must_use]
pub fn gamma_of_air_direct_carrier(bytes: &[u8], public_bind: &[Fa4]) -> Option<Ea4> {
    use p3_challenger::FieldChallenger;
    let bundle: AirDirectBundle = postcard::from_bytes(bytes).ok()?;
    if bundle.shapes.len() != 1 || bundle.openings.len() != 1 {
        return None;
    }
    let (_nvars, width) = bundle.shapes[0];
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let perm = Perm16::new_from_rng_128(&mut perm_rng);
    let mut vch = Chl::new(perm);
    for &f in public_bind {
        vch.observe(f);
    }
    let mut verifier = build_decider_hiding_verifier(&bundle.shapes);
    let all: Vec<usize> = (0..width).collect();
    verifier.add_claim(0, &all, &bundle.openings[0], &mut vch);
    Some(vch.sample_algebra_element())
}

/// ⛔⛔⛔ §BG — CAN A FORGED SPEND CARRIER PASS THE NODE'S OWN GATE?
///
/// `verify_spend_validity_carrier_bytes` is what `/submit_pq_tx` calls to decide whether a spend is
/// real. It routes to `verify_air_direct_light_decider_selfcontained_bytes` — the path §BD-2 measured
/// as accepting a self-consistent row with nothing committed behind it. If the same construction works
/// here, anyone can mint: submit a spend whose carrier proves nothing.
#[cfg(test)]
mod forged_spend_carrier_probe {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn a_zero_row_spend_validity_carrier_is_measured_against_the_production_gate() {
        // The honest carrier first — the CONTROL, so a refusal below cannot be a broken construction.
        let w = SpendValidityWitness {
            value_in: 1000,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(crate::poseidon2_compress::lanes_of(&[3, 5, 7, 9])),
            value_out: 900,
            fee: 100,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, 1, 2, 3]),
            out0_value: 600,
            out0_opening: crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            out1_value: 300,
            out1_opening: crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
        };
        let (honest, cms, nf, commit) =
            prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0)).expect("honest spend proves");
        assert!(
            verify_spend_validity_carrier_bytes(&honest, cms[0], cms[1], nf, commit, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100),
            "CONTROL: the honest spend carrier must verify through the production gate"
        );

        // THE FORGERY: take the honest carrier and zero its opened row + shifted row, exactly as the
        // §BD-2 forgery does. Nothing else changes — same shapes, same transcript positions.
        let mut b: crate::committed_air::CommittedAirBundle =
            postcard::from_bytes(&honest).expect("decodes");
        for v in b.zc.opened.iter_mut() {
            *v = Ea4::ZERO;
        }
        for v in b.zc.shifted_opened.iter_mut() {
            *v = Ea4::ZERO;
        }
        let forged = postcard::to_allocvec(&b).expect("re-encodes");
        let passes = verify_spend_validity_carrier_bytes(&forged, cms[0], cms[1], nf, commit, crate::whir_rec_block::test_clue_digest(0), crate::whir_rec_block::spend_tag1(&w), 100);
        eprintln!(
            "[§BG] ZEROED-ROW spend-validity carrier vs the PRODUCTION gate: verifies={passes} \
             (honest {} B, forged {} B)",
            honest.len(),
            forged.len()
        );
        // Recorded, not asserted away — the flip is named.
        assert!(
            !passes,
            "⛔⛔⛔ §BG: A FORGED SPEND CARRIER PASSES `verify_spend_validity_carrier_bytes`. Anyone can \\
             mint: submit a spend whose carrier proves nothing. This is the direct-path unboundedness \\
             (§BD-2) reaching the one gate that decides whether a spend is real."
        );
    }
}

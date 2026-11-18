// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ THE ONE-STEP NOTE MEMBERSHIP CARRIER ON THE BLINDED COMMITTED PATH — row-local, hiding, binding.
//!
//! ## Why this exists (soundness lead, 2026-09-27, lane-db224-carriage → lane-dsol-zkvm)
//! `note_membership_air::verify_note_membership_one_step` — the production gate DB-213c moved membership onto —
//! verified on the DIRECT light decider. That engine has NO trace commitment and evaluates the gate on the
//! PLAINTEXT opened row (`whir_rec_block.rs`, item 1), which is exactly why the SPEND carrier moved to
//! `committed_air::prove_air_blinded_bytes`. Membership never made that move: a spend's input note was admitted
//! on a carrier whose witness rode in the clear and whose openings were bound to no committed trace.
//!
//! ## Why a NEW gate and not the old one behind a new prover
//! `NoteMemberStepGate` is ROW-SHIFTED: its accumulator carries from row `k` to row `k+1` through `σ`. Blinding
//! doubles the trace and fills the top half with OS randomness, so the last real row's "next" is a random row
//! and the carry residual there reads noise — `Blinded` is safe exactly for row-LOCAL gates and says so. The
//! spend carrier's membership (`SpendMembershipGate`) is already row-local: every level of the path sits in ONE
//! row. This gate is the same shape for the record tree, plus the cross-bind the one-step statement carries.
//!
//! ## The relation, exactly (mirrors `NoteMemberStepGate` residual for residual, laid horizontally)
//! One row holds `IN_BLOCK_DEPTH` levels. Level `k` carries a Poseidon2-16 permutation block `FOLD_k`, the
//! sibling `SIB_k`, the accumulator entering it `ACC_k`, a direction bit `DIR_k` and an `ACTIVE_k` selector;
//! after the last level sits `ACC_D`; then the commitment permutation `COMMIT` and the witnessed leaf `WLEAF`.
//!   * both permutation blocks are constrained on every row (the shared `Poseidon2Air`, one definition);
//!   * `ACTIVE_k ∈ {0,1}`, `ACTIVE_k·DIR_k·(DIR_k−1) = 0`;
//!   * active: `FOLD_k.in = (ACC_k ‖ SIB_k)` ordered by `DIR_k`, `ACC_{k+1} = FOLD_k.out`;
//!     inactive: `ACC_{k+1} = ACC_k` (a padding level is a NO-OP on the running value);
//!   * `ACC_0 = WLEAF`, `ACC_D = block_root` (public);
//!   * `COMMIT.in = (WLEAF ‖ binder)`, `COMMIT.out = leaf_commit` (public) — the cross-bind that says THIS note.
//! A shorter walk that still lands on `block_root` is a Poseidon2 collision, never a shortcut, so `ACTIVE` needs
//! no monotonicity — the same argument the step gate rests on.
//!
//! ## Shape and privacy
//! The row is replicated `LIGHT_CARRIER_ROWS` times and blinded (height ×2, random top half), the shape the
//! spend carrier ships. Width and height are CONSTANT for every record size ≤ `IN_BLOCK_DEPTH` levels: a
//! carrier reveals neither how many levels were walked nor the record's size. The transcript binds only
//! `domain ‖ leaf_commit ‖ block_root` (`note_member_step_bind`, reused): never a slot, never a sibling.
//!
//! ## Cons, quantified
//! Bytes per membership carrier rise by about the spend carrier's measured blinded/direct ratio (1.49×) — a
//! wire change, so node and wallet roll together. Prove time ~2×. Nothing else moves.

use crate::air_zerocheck::{AirConstraint, Row};
use crate::hiding_decider::{Ea4, Fa4};
use crate::note_membership_air::{note_leaf_commitment, note_member_step_bind, refold_in_block, IN_BLOCK_DEPTH};
use crate::nullifier_insert_air::poseidon_pair_native;
use crate::poseidon2_compress::Digest;
use crate::pow_pq_air::{lay_perm_row_flat, push_perm_residuals, P2_COLS, WIDTH};
use p3_field::PrimeCharacteristicRing;

/// One digest is `DIGEST_LANES` base-field limbs — the same alias `note_membership_air` uses.
const DIGEST_LIMBS: usize = crate::poseidon2_compress::DIGEST_LANES;

/// The permutation output starts here inside a `P2_COLS` block (the last `WIDTH` cells are the final state).
const PERM_OUT: usize = P2_COLS - WIDTH;
/// Per-level block: permutation, sibling, accumulator in, direction, active.
const LEVEL_COLS: usize = P2_COLS + 2 * DIGEST_LIMBS + 2;
const fn level_base(k: usize) -> usize {
    k * LEVEL_COLS
}
const fn fold_at(k: usize) -> usize {
    level_base(k)
}
const fn sib_at(k: usize) -> usize {
    level_base(k) + P2_COLS
}
/// `ACC_k` for k in 0..=IN_BLOCK_DEPTH: the accumulator entering level k; `ACC_D` is the final one.
const fn acc_at(k: usize) -> usize {
    if k < IN_BLOCK_DEPTH { level_base(k) + P2_COLS + DIGEST_LIMBS } else { ACC_FINAL }
}
const fn dir_at(k: usize) -> usize {
    level_base(k) + P2_COLS + 2 * DIGEST_LIMBS
}
const fn active_at(k: usize) -> usize {
    level_base(k) + P2_COLS + 2 * DIGEST_LIMBS + 1
}
const ACC_FINAL: usize = IN_BLOCK_DEPTH * LEVEL_COLS;
const COMMIT: usize = ACC_FINAL + DIGEST_LIMBS;
const WLEAF: usize = COMMIT + P2_COLS;
/// DB-363 (2026-09-30): the cross-bind's OUTER block, `leaf_commit = P(inner, blind)`, chained to `COMMIT`'s output.
const COMMIT2: usize = WLEAF + DIGEST_LIMBS;
/// The spender's per-send blinding lanes — the hiding witness of the commitment (named in `free_columns`).
const BLIND: usize = COMMIT2 + P2_COLS;
/// The row width — a protocol constant, never a chain quantity.
pub const MEMBER_ROW_COLS: usize = BLIND + DIGEST_LIMBS;
/// The trace the caller lays before blinding: `LIGHT_CARRIER_ROWS` copies of the one row.
pub const MEMBER_ROW_SHAPE: (usize, usize) =
    (crate::whir_rec_block::LIGHT_CARRIER_ROWS.trailing_zeros() as usize, MEMBER_ROW_COLS);

pub struct NoteMemberRowGate {
    pub gamma: Ea4,
    pub leaf_commit: [Ea4; DIGEST_LIMBS],
    pub binder: [Ea4; DIGEST_LIMBS],
    pub block_root: [Ea4; DIGEST_LIMBS],
}

impl NoteMemberRowGate {
    fn all_residuals(&self, local: &Row<'_>) -> Vec<Ea4> {
        let one = Ea4::ONE;
        let mut rs: Vec<Ea4> = Vec::new();
        for k in 0..IN_BLOCK_DEPTH {
            push_perm_residuals(local, fold_at(k), &mut rs);
        }
        push_perm_residuals(local, COMMIT, &mut rs);
        push_perm_residuals(local, COMMIT2, &mut rs); // DB-363: the outer cross-bind block
        for k in 0..IN_BLOCK_DEPTH {
            let dir = local[dir_at(k)];
            let active = local[active_at(k)];
            rs.push(active * (active - one));
            rs.push(active * dir * (dir - one));
            for c in 0..DIGEST_LIMBS {
                let a = local[acc_at(k) + c];
                let s = local[sib_at(k) + c];
                let next = local[acc_at(k + 1) + c];
                // dir = 1 ⇒ the accumulator is the RIGHT child
                rs.push(active * (local[fold_at(k) + c] - (a + dir * (s - a))));
                rs.push(active * (local[fold_at(k) + DIGEST_LIMBS + c] - (s + dir * (a - s))));
                rs.push(active * (next - local[fold_at(k) + PERM_OUT + c]));
                rs.push((one - active) * (next - a));
            }
        }
        for c in 0..DIGEST_LIMBS {
            // boundaries: the walk starts at the witnessed leaf and ends exactly on the public root
            rs.push(local[acc_at(0) + c] - local[WLEAF + c]);
            rs.push(local[ACC_FINAL + c] - self.block_root[c]);
            // the cross-bind, DB-363: leaf_commit == P(P(wleaf, binder), blind) — the inner block's output lanes are
            // welded into the outer block's left lanes, the outer's right lanes are the blinding, its output is public
            rs.push(local[COMMIT + c] - local[WLEAF + c]);
            rs.push(local[COMMIT + DIGEST_LIMBS + c] - self.binder[c]);
            rs.push(local[COMMIT2 + c] - local[COMMIT + PERM_OUT + c]);
            rs.push(local[COMMIT2 + DIGEST_LIMBS + c] - local[BLIND + c]);
            rs.push(local[COMMIT2 + PERM_OUT + c] - self.leaf_commit[c]);
        }
        rs
    }
}

impl AirConstraint for NoteMemberRowGate {
    /// DB-363: the blinding lanes are a HIDING witness — read by the outer cross-bind block's input weld, determined by no
    /// statement value on purpose. Named so the binding review sees the choice.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some((BLIND..BLIND + DIGEST_LIMBS).collect())
    }
    fn degree(&self, _nvars: usize) -> usize {
        // MEASURED 3 by the debug prover's degree census (2026-09-29): the permutation block is a cube applied inline
        // (`P2_CONSTRAINT_DEGREE`), and every weld here is `active · dir · (dir − 1)` or `active · (cell − affine)` — 3.
        // The literal 8 sampled 11 points per round (blinded) where 6 suffice. Guarded by the census + per-round assert.
        crate::pow_pq_air::P2_CONSTRAINT_DEGREE
    }
    fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut out = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for r in self.all_residuals(local) {
            out += pw * r;
            pw *= self.gamma;
        }
        out
    }
    fn residuals(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Vec<Ea4> {
        self.all_residuals(local)
    }
    fn is_row_local(&self) -> bool {
        true
    }
}

fn digest_ea(d: Digest) -> [Ea4; DIGEST_LIMBS] {
    core::array::from_fn(|c| Fa4::from_u64(d[c]).into())
}

/// The honest row for `leaf` under `block_root` via `(siblings, dirs)`, bound to `binder`. Levels past the
/// walked depth are inactive and pass the accumulator through, exactly as the step trace's padding rows do.
pub fn member_row(leaf: Digest, siblings: &[Digest], dirs: &[bool], binder: Digest, blind: Digest) -> Vec<Fa4> {
    let mut row = vec![Fa4::ZERO; MEMBER_ROW_COLS];
    let lanes = |l: &Digest, r: &Digest| -> [Fa4; WIDTH] {
        let mut st = [Fa4::ZERO; WIDTH];
        for i in 0..DIGEST_LIMBS {
            st[i] = Fa4::from_u64(l[i]);
            st[DIGEST_LIMBS + i] = Fa4::from_u64(r[i]);
        }
        st
    };
    let mut acc = leaf;
    for k in 0..IN_BLOCK_DEPTH {
        let walking = k < siblings.len();
        let (l, r) = if walking {
            if dirs[k] { (siblings[k], acc) } else { (acc, siblings[k]) }
        } else {
            (acc, acc)
        };
        lay_perm_row_flat(&mut row, fold_at(k), lanes(&l, &r));
        let next = if walking { poseidon_pair_native(l, r) } else { acc };
        for c in 0..DIGEST_LIMBS {
            row[sib_at(k) + c] = Fa4::from_u64(if walking { siblings[k][c] } else { 0 });
            row[acc_at(k) + c] = Fa4::from_u64(acc[c]);
        }
        row[dir_at(k)] = if walking && dirs[k] { Fa4::ONE } else { Fa4::ZERO };
        row[active_at(k)] = if walking { Fa4::ONE } else { Fa4::ZERO };
        acc = next;
    }
    for c in 0..DIGEST_LIMBS {
        row[ACC_FINAL + c] = Fa4::from_u64(acc[c]);
        row[WLEAF + c] = Fa4::from_u64(leaf[c]);
        row[BLIND + c] = Fa4::from_u64(blind[c]);
    }
    lay_perm_row_flat(&mut row, COMMIT, lanes(&leaf, &binder));
    // DB-363: the outer block over (inner, blind); the inner IS the COMMIT block's output, `P(leaf, binder)`
    let inner = poseidon_pair_native(leaf, binder);
    lay_perm_row_flat(&mut row, COMMIT2, lanes(&inner, &blind));
    row
}

fn replicate(row: &[Fa4]) -> Vec<Vec<Fa4>> {
    (0..MEMBER_ROW_COLS).map(|c| vec![row[c]; crate::whir_rec_block::LIGHT_CARRIER_ROWS]).collect()
}

/// Prove one-step note membership on the blinded committed path. Same statement, same refusals as the step
/// prover: the path must match its bits, fit the in-block bound, and refold to the claimed root.
#[must_use]
pub fn prove_note_member_row_bytes(
    leaf: Digest,
    siblings: &[Digest],
    dirs: &[bool],
    block_root: Digest,
    binder: Digest,
    blind: Digest,
) -> Option<Vec<u8>> {
    if dirs.len() != siblings.len() || siblings.len() > IN_BLOCK_DEPTH {
        eprintln!(
            "[member-row] refused: {} sibling(s) against {} direction bit(s), upper bound {}",
            siblings.len(),
            dirs.len(),
            IN_BLOCK_DEPTH
        );
        return None;
    }
    if refold_in_block(leaf, siblings, dirs) != block_root {
        eprintln!("[member-row] the copath does NOT refold to the claimed block root — the claim is false");
        return None;
    }
    let leaf_commit = note_leaf_commitment(leaf, binder, blind);
    prove_row_bytes(&member_row(leaf, siblings, dirs, binder, blind), leaf_commit, binder, block_root)
}

/// The production prover on an ALREADY-LAID row. Split out so a tamper test can present a hostile row to the
/// exact prover and verifier a spender uses — the trace builder's own refusals are not the soundness.
#[must_use]
pub fn prove_row_bytes(row: &[Fa4], leaf_commit: Digest, binder: Digest, block_root: Digest) -> Option<Vec<u8>> {
    if row.len() != MEMBER_ROW_COLS {
        return None;
    }
    let (lc, bd, rt) = (digest_ea(leaf_commit), digest_ea(binder), digest_ea(block_root));
    let make = move |gamma: Ea4| NoteMemberRowGate { gamma, leaf_commit: lc, binder: bd, block_root: rt };
    crate::committed_air::prove_air_blinded_bytes(replicate(row), make, &note_member_step_bind(leaf_commit, block_root))
}

/// Verify a one-step note membership carrier: `leaf_commit` is a member of the record whose root is
/// `block_root`, bound to `binder`. Fail-closed on an empty proof, a zero public, or any decode / shape /
/// zerocheck / opening mismatch.
#[must_use]
pub fn verify_note_member_row_bytes(proof: &[u8], leaf_commit: Digest, binder: Digest, block_root: Digest) -> bool {
    if proof.is_empty()
        || leaf_commit.iter().all(|b| *b == 0)
        || binder.iter().all(|b| *b == 0)
        || block_root.iter().all(|b| *b == 0)
    {
        return false;
    }
    let (lc, bd, rt) = (digest_ea(leaf_commit), digest_ea(binder), digest_ea(block_root));
    let make = move |gamma: Ea4| NoteMemberRowGate { gamma, leaf_commit: lc, binder: bd, block_root: rt };
    crate::committed_air::verify_air_blinded_bytes(
        proof,
        make,
        &note_member_step_bind(leaf_commit, block_root),
        MEMBER_ROW_SHAPE,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(seed: u64) -> Digest {
        core::array::from_fn(|c| (seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (c as u64 + 1).wrapping_mul(0xD1B5_4A32_D192_ED03)) >> 3)
    }

    /// The fixture's per-send blinding (DB-363) — one value for the whole module, as one send has one.
    fn blind() -> Digest {
        d(9)
    }

    fn honest(depth: usize) -> (Digest, Vec<Digest>, Vec<bool>, Digest, Digest, Digest) {
        let leaf = d(1);
        let siblings: Vec<Digest> = (0..depth).map(|k| d(100 + k as u64)).collect();
        let dirs: Vec<bool> = (0..depth).map(|k| k % 3 == 1).collect();
        let binder = d(7);
        let root = refold_in_block(leaf, &siblings, &dirs);
        let lc = note_leaf_commitment(leaf, binder, blind());
        (leaf, siblings, dirs, binder, root, lc)
    }

    #[test]
    fn the_row_local_membership_carrier_verifies_at_every_depth_the_record_can_have() {
        for depth in [0usize, 1, 3, IN_BLOCK_DEPTH] {
            let (leaf, sib, dirs, binder, root, lc) = honest(depth);
            let bytes = prove_note_member_row_bytes(leaf, &sib, &dirs, root, binder, blind())
                .unwrap_or_else(|| panic!("the honest depth-{depth} membership proves on the blinded path"));
            assert!(
                verify_note_member_row_bytes(&bytes, lc, binder, root),
                "CONTROL: the honest depth-{depth} carrier must verify"
            );
            eprintln!("[member-row] depth {depth}: {} carrier bytes, {} columns", bytes.len(), MEMBER_ROW_COLS);
        }
    }

    /// Every public the statement names is bound: moving any one of them refuses the honest carrier.
    #[test]
    fn a_carrier_is_refused_under_any_other_root_binder_or_commitment() {
        let (leaf, sib, dirs, binder, root, lc) = honest(3);
        let bytes = prove_note_member_row_bytes(leaf, &sib, &dirs, root, binder, blind()).expect("proves");
        assert!(verify_note_member_row_bytes(&bytes, lc, binder, root), "CONTROL");
        assert!(!verify_note_member_row_bytes(&bytes, lc, binder, d(999)), "another root must be refused");
        assert!(!verify_note_member_row_bytes(&bytes, lc, d(998), root), "another binder must be refused");
        assert!(!verify_note_member_row_bytes(&bytes, d(997), binder, root), "another commitment must be refused");
        assert!(!verify_note_member_row_bytes(&[], lc, binder, root), "an empty proof is refused");
        let mut cut = bytes.clone();
        cut.truncate(cut.len() / 2);
        assert!(!verify_note_member_row_bytes(&cut, lc, binder, root), "a truncated carrier is refused");
    }

    /// TAMPER, built directly against the production prover and verifier: a walked level marked inactive so the
    /// running value skips a compression. The row's own final accumulator then differs from the public root, and
    /// the carrier must not verify — whether the prover refuses it or the verifier does.
    #[test]
    fn a_row_that_skips_a_walked_level_is_refused() {
        let (leaf, sib, dirs, binder, root, lc) = honest(3);
        let mut row = member_row(leaf, &sib, &dirs, binder, blind());
        // level 1 inactive, accumulator passed through, everything downstream re-laid consistently
        row[active_at(1)] = Fa4::ZERO;
        row[dir_at(1)] = Fa4::ZERO;
        // …and its sibling zeroed, as an inactive level's is on an honest row: left live it is a value no law reads, and
        // the strict build's free-witness census stops the prover on that before the tamper is ever judged (MEASURED
        // 2026-11-10: this pin panicked there in the strict profile and never reached its assertion).
        for c in 0..DIGEST_LIMBS {
            row[sib_at(1) + c] = Fa4::ZERO;
        }
        let acc1: Digest = core::array::from_fn(|c| {
            use p3_field::PrimeField64;
            row[acc_at(1) + c].as_canonical_u64()
        });
        for c in 0..DIGEST_LIMBS {
            row[acc_at(2) + c] = Fa4::from_u64(acc1[c]);
        }
        let l2 = if dirs[2] { (sib[2], acc1) } else { (acc1, sib[2]) };
        let mut st = [Fa4::ZERO; WIDTH];
        for i in 0..DIGEST_LIMBS {
            st[i] = Fa4::from_u64(l2.0[i]);
            st[DIGEST_LIMBS + i] = Fa4::from_u64(l2.1[i]);
        }
        lay_perm_row_flat(&mut row, fold_at(2), st);
        let acc3 = poseidon_pair_native(l2.0, l2.1);
        for k in 3..=IN_BLOCK_DEPTH {
            for c in 0..DIGEST_LIMBS {
                row[acc_at(k) + c] = Fa4::from_u64(acc3[c]);
            }
        }
        assert_ne!(acc3, root, "the skipped level changes the root, or this tamper measures nothing");
        let verdict = prove_row_bytes(&row, lc, binder, root).map(|b| verify_note_member_row_bytes(&b, lc, binder, root));
        assert_ne!(verdict, Some(true), "a carrier whose walk skips a level must never verify against the root");
        // and the SAME hostile row presented as if its own end were the root: the cross-bind and the claimed
        // root are different publics, so the honest commitment under a WRONG root is refused too
        let verdict2 = prove_row_bytes(&row, lc, binder, acc3).map(|b| verify_note_member_row_bytes(&b, lc, binder, root));
        assert_ne!(verdict2, Some(true));
    }
}

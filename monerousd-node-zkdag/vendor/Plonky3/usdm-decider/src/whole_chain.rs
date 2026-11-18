// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! THE canonical whole-chain adopt-gate decider (#29 DSYNC / #135 WHIR light) — ONE implementation
//! every MonerousD build links, so a proof produced by ANY node verifies on EVERY node (daemon,
//! desktop wallet, iPhone in-process node) byte-identically. This module exists because the daemon's
//! FFI light decider and the phone's pure-Rust verifier previously spoke DIFFERENT proofs, so a phone
//! could gossip with a daemon yet never adopt its heavier chain (cross-implementation DSYNC was
//! broken by construction). The construction is the balanced CRT-sound SIS-opening AIR
//! ([`TallSisOpenAir`]) proven/verified through the self-contained WHIR light-decider batch entries
//! ([`crate::whir_rec_block`]) — hashless, transparent, ≤1.8 MB, O(1) at any chain length.
//!
//! Cross-implementation compatibility is pinned by tests here (prove→verify round-trip + tamper
//! rejection) and by the node crate's FFI-parity test (an FFI-produced proof verifies under THIS
//! verifier), so the two build flavors can never drift apart silently again.

use p3_air::symbolic::{AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression, SymbolicVariable};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::symbolic::get_symbolic_constraints;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::logup::LogUpGadget;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::air_zerocheck::AirConstraint;
use crate::hiding_decider::{Ea4, Fa4};

type F = Fa4;
type Challenge = Ea4;

/// The pinned whole-chain decider column split `t` — EVERY node proves and verifies at this exact
/// shape (32×33 balanced split of the SW_M=1024 SIS randomness), so the committed trace layout and
/// therefore the Fiat-Shamir transcript are identical network-wide.
pub const WHOLE_CHAIN_T: usize = 32;

// ── The balanced CRT-sound SisOpen constants (byte-pinned: any change is a NEW proof format and a
//    network-wide upgrade, never a per-build drift). Same values as the pqpool circuit's construction.
const SW_N: usize = 1; // SIS output coords
pub const SW_M: usize = 1024; // randomness dim — large enough that the inner product overflows p
const SW_Q: u64 = 8380417; // ~2^23 SIS modulus (Dilithium q)
const SW_P2: u64 = 128; // CRT aux modulus: power of 2, coprime to odd p
const SW_KBITS: usize = 11; // quotient k = inner/Q < (M+L) < 2^11
const SW_CMBITS: usize = 23; // commitment-coord bits (cm < Q < 2^23)
const SW_P2BITS: usize = 7; // residue width (mod 128 = low 7 bits)
const SW_QXBITS: usize = 11; // LHS-residue quotient
const SW_QTBITS: usize = 7; // RHS-residue quotient
const SCC_W: usize = SW_KBITS + SW_CMBITS + SW_QXBITS + SW_P2BITS + SW_QTBITS + SW_P2BITS; // 66

/// The deterministic public SIS matrix entry — identical on every node by construction.
fn sw_a(i: usize, j: usize) -> u64 {
    (0x9E37_79B1u64.wrapping_mul((i * SW_M + j + 1) as u64).wrapping_add(0x1_2345)) % SW_Q
}

/// Balanced CRT-sound SisOpen in ONE AIR: dual-accumulator inner over rows + CRT/cm boundary gated
/// to the LAST row. Main: [r_0..r_{t-1}, acc_inner, acc_x2, k(11), cm(23), qx(11), rx(7), qt(7),
/// ry(7)] width t+68. Preprocessed: [A(t), A mod 128(t)] width 2t. Public: cm (SW_N).
#[derive(Clone)]
pub struct TallSisOpenAir {
    pub t: usize,
}

impl BaseAir<F> for TallSisOpenAir {
    fn width(&self) -> usize {
        self.t + 2 + SCC_W
    }
    fn preprocessed_width(&self) -> usize {
        2 * self.t
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let rows = SW_M / self.t;
        let mut data: Vec<F> = Vec::with_capacity(rows * 2 * self.t);
        for row in 0..rows {
            for c in 0..self.t {
                data.push(F::from_u64(sw_a(0, row * self.t + c)));
            }
            for c in 0..self.t {
                data.push(F::from_u64(sw_a(0, row * self.t + c) % SW_P2));
            }
        }
        Some(RowMajorMatrix::new(data, 2 * self.t))
    }
    fn num_public_values(&self) -> usize {
        SW_N
    }
}

impl<AB> Air<AB> for TallSisOpenAir
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let t = self.t;
        let w = t + 2 + SCC_W;
        let (ml, mn, pl, pn, pis): (
            Vec<AB::Var>,
            Vec<AB::Var>,
            Vec<AB::Var>,
            Vec<AB::Var>,
            Vec<AB::PublicVar>,
        ) = {
            let main = builder.main();
            let prep = builder.preprocessed();
            (
                main.current_slice()[..w].to_vec(),
                main.next_slice()[..w].to_vec(),
                prep.current_slice()[..2 * t].to_vec(),
                prep.next_slice()[..2 * t].to_vec(),
                builder.public_values().to_vec(),
            )
        };
        // r-bits boolean (every row).
        for c in 0..t {
            builder.assert_zero(ml[c].into() * (ml[c].into() - AB::Expr::ONE));
        }
        // dual accumulator: first row + transition.
        {
            let mut f = builder.when_first_row();
            let mut si = AB::Expr::ZERO;
            let mut sx = AB::Expr::ZERO;
            for c in 0..t {
                si = si + pl[c].into() * ml[c].into();
                sx = sx + pl[t + c].into() * ml[c].into();
            }
            f.assert_eq(ml[t], si);
            f.assert_eq(ml[t + 1], sx);
        }
        {
            let mut tr = builder.when_transition();
            let mut ri = ml[t].into();
            let mut rx2 = ml[t + 1].into();
            for c in 0..t {
                ri = ri + pn[c].into() * mn[c].into();
                rx2 = rx2 + pn[t + c].into() * mn[c].into();
            }
            tr.assert_eq(mn[t], ri);
            tr.assert_eq(mn[t + 1], rx2);
        }
        // LAST ROW: CRT + cm boundary using the complete acc_inner / acc_x2.
        {
            let ck = t + 2;
            let qmodp2 = SW_Q % SW_P2;
            let mut l = builder.when_last_row();
            // k bits -> ki, rk
            let mut ki = AB::Expr::ZERO;
            let mut rk = AB::Expr::ZERO;
            for tt in 0..SW_KBITS {
                let b = ml[ck + tt];
                l.assert_zero(b.into() * (b.into() - AB::Expr::ONE));
                ki = ki + b.into() * AB::Expr::from_u64(1u64 << tt);
                if tt < SW_P2BITS {
                    rk = rk + b.into() * AB::Expr::from_u64(1u64 << tt);
                }
            }
            // cm bits -> cmi, rc
            let mut cmi = AB::Expr::ZERO;
            let mut rc = AB::Expr::ZERO;
            for tt in 0..SW_CMBITS {
                let b = ml[ck + SW_KBITS + tt];
                l.assert_zero(b.into() * (b.into() - AB::Expr::ONE));
                cmi = cmi + b.into() * AB::Expr::from_u64(1u64 << tt);
                if tt < SW_P2BITS {
                    rc = rc + b.into() * AB::Expr::from_u64(1u64 << tt);
                }
            }
            // check-1: acc_inner == cmi + ki*Q ; cm == public.
            l.assert_eq(ml[t], cmi.clone() + ki * AB::Expr::from_u64(SW_Q));
            l.assert_eq(pis[0], cmi);
            // check-2 LHS: acc_x2 == qx*128 + rx.
            let c2 = ck + SW_KBITS + SW_CMBITS;
            let mut qx = AB::Expr::ZERO;
            for tt in 0..SW_QXBITS {
                let b = ml[c2 + tt];
                l.assert_zero(b.into() * (b.into() - AB::Expr::ONE));
                qx = qx + b.into() * AB::Expr::from_u64(1u64 << tt);
            }
            let mut rx = AB::Expr::ZERO;
            for tt in 0..SW_P2BITS {
                let b = ml[c2 + SW_QXBITS + tt];
                l.assert_zero(b.into() * (b.into() - AB::Expr::ONE));
                rx = rx + b.into() * AB::Expr::from_u64(1u64 << tt);
            }
            l.assert_eq(ml[t + 1], qx * AB::Expr::from_u64(SW_P2) + rx.clone());
            // check-2 RHS: t1 = rc + rk*(Q mod128) == qt*128 + ry ; rx == ry.
            let t1 = rc + rk * AB::Expr::from_u64(qmodp2);
            let mut qt = AB::Expr::ZERO;
            for tt in 0..SW_QTBITS {
                let b = ml[c2 + SW_QXBITS + SW_P2BITS + tt];
                l.assert_zero(b.into() * (b.into() - AB::Expr::ONE));
                qt = qt + b.into() * AB::Expr::from_u64(1u64 << tt);
            }
            let mut ry = AB::Expr::ZERO;
            for tt in 0..SW_P2BITS {
                let b = ml[c2 + SW_QXBITS + SW_P2BITS + SW_QTBITS + tt];
                l.assert_zero(b.into() * (b.into() - AB::Expr::ONE));
                ry = ry + b.into() * AB::Expr::from_u64(1u64 << tt);
            }
            l.assert_eq(t1, qt * AB::Expr::from_u64(SW_P2) + ry.clone());
            l.assert_eq(rx, ry);
        }
    }
}

/// Committed-leaf layout for evaluating flattened symbolic constraints over the light-decider
/// openings: [main_local(w) | main_next(w) | preproc_local(pw) | preproc_next(pw) | publics(np) |
/// is_first | is_last | is_transition].
#[derive(Clone, Debug)]
pub struct SymLeafLayout {
    pub w: usize,
    pub preproc_w: usize,
    pub npub: usize,
}
impl SymLeafLayout {
    fn is_first(&self) -> usize {
        2 * self.w + 2 * self.preproc_w + self.npub
    }
    fn is_last(&self) -> usize {
        self.is_first() + 1
    }
    fn is_trans(&self) -> usize {
        self.is_first() + 2
    }
    fn var_idx(&self, v: &SymbolicVariable<F>) -> usize {
        match v.entry {
            BaseEntry::Main { offset } => {
                if offset == 0 {
                    v.index
                } else {
                    self.w + v.index
                }
            }
            BaseEntry::Preprocessed { offset } => {
                if offset == 0 {
                    2 * self.w + v.index
                } else {
                    2 * self.w + self.preproc_w + v.index
                }
            }
            BaseEntry::Public => 2 * self.w + 2 * self.preproc_w + v.index,
            BaseEntry::Periodic => panic!("periodic columns not supported in the whole-chain decider"),
        }
    }
}

/// ⭐⭐⭐ THE COMPILED CONSTRAINT TAPE — the symbolic DAG flattened ONCE into a straight-line program.
///
/// ## Why this exists (measured, 2026-09-12)
///
/// [`eval_base_expr_lifted`] below is the reference evaluator: it walks an `Arc` expression DAG with a
/// pointer-keyed `HashMap` memo, and it allocates a FRESH MAP PER CONSTRAINT, per evaluation. The
/// Poseidon2 AIR carries hundreds of constraints that share most of their sub-expressions, so that shape
/// paid for hundreds of map allocations per `eval()` AND recomputed every shared node once per
/// constraint. MEASURED on the PoUW hash chain: **55.5 ms per 164-column row** in release, which put one
/// PoUW hash (34,817 rows) at ~32 minutes to prove and made the provable-work design marginal.
///
/// ## What it does instead
///
/// Compile once, at constraint construction — which happens ONCE PER PROOF, not per row: walk every
/// constraint's DAG, deduplicate shared nodes ACROSS ALL CONSTRAINTS by `Arc` pointer, resolve every
/// variable to its final `bl` index, pre-lift every constant into the challenge field, and emit a
/// topologically-ordered [`TapeOp`] list. Evaluation is then a flat loop over a scratch vector: no
/// hashing, no recursion, no pointer chasing, one allocation.
///
/// ## FOOTPRINT — why this is not a store that can grow
///
/// Both fields are `Box<[T]>`, not `Vec`: a boxed slice has no `push` and no `reserve`, so after
/// [`CompiledTape::compile`] returns, the tape's length is FIXED by construction and no operation the
/// node ever performs can extend it. Its size is the node count of the AIR's own constraint DAG —
/// f(WIDTH, round counts, S-box degree), a compile-time circuit shape. Chain height, block count, note
/// count, spends, peers and DAG width appear in it nowhere, and it is dropped when the proof completes.
///
/// ⛔ IT MUST COMPUTE EXACTLY THE SAME VALUE. A faster evaluator that is subtly different is a soundness
/// bug that surfaces as a prover and verifier disagreeing about a valid proof.
/// `the_tape_agrees_with_the_reference_evaluator` is the differential gate: a REAL Poseidon2 AIR's
/// constraints, random openings, both evaluators, exact equality. The reference walker is kept for
/// exactly that purpose and must never be deleted "because nothing calls it".
#[derive(Clone, Debug)]
pub enum TapeOp {
    /// Read `bl[i]` — the variable index is resolved at COMPILE time, never per evaluation.
    Load(u32),
    /// A constant already lifted into the challenge field.
    /// A constant of the AIR — always a BASE-field value (every Poseidon2 round constant is) — carried both as the base
    /// value (the base-field round 0 reads it directly) and pre-lifted into the extension (the extension path reads it
    /// without a per-evaluation lift: MEASURED 2026-09-29, lifting per evaluation cost the DSOL zerocheck 290 → 567 ms).
    Const(F, Challenge),
    Add(u32, u32),
    Sub(u32, u32),
    Mul(u32, u32),
    Neg(u32),
}

/// A whole batch of constraints as one straight-line program, plus the slot each constraint lands in.
#[derive(Clone, Debug)]
pub struct CompiledTape {
    /// FIXED-LENGTH by type: a boxed slice cannot be pushed to or reserved into.
    ops: Box<[TapeOp]>,
    /// FIXED-LENGTH by type: one entry per constraint in the batch, set at compile time.
    roots: Box<[u32]>,
    /// ⭐ SPEED R8 — the SAME program as `ops` + `roots`, laid out for evaluation: registers handed on at a value's
    /// last read, a base constant multiplied as the algebra's scalar, a square taken as a square
    /// ([`crate::tape_program`] names the measurement and the rewrites). Derived from `ops` and `roots` in
    /// [`Self::compile`] and nowhere else, so the two cannot describe different constraints; FIXED-LENGTH like them.
    prog: crate::tape_program::RegProgram,
}

/// TEST BUILDS ONLY — route every evaluation through the reference slot interpreter, so a pin can make one REAL proof
/// with each engine and compare the bytes. Both engines lay the same values, so a test running beside the pin that
/// flips this sees no difference in any result.
#[cfg(test)]
pub(crate) static REFERENCE_ENGINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl CompiledTape {
    /// Flatten `base` against `ll`. Shared sub-expressions are emitted ONCE for the whole batch.
    #[must_use]
    pub fn compile(base: &[SymbolicExpression<F>], ll: &SymLeafLayout) -> Self {
        let mut ops: Vec<TapeOp> = Vec::new();
        let mut memo: std::collections::HashMap<*const SymbolicExpression<F>, u32> =
            std::collections::HashMap::new();
        let roots: Vec<u32> =
            base.iter().map(|c| emit_expr(c, ll, &mut ops, &mut memo)).collect();
        let prog = crate::tape_program::RegProgram::compile(&ops, &roots);
        Self { ops: ops.into_boxed_slice(), roots: roots.into_boxed_slice(), prog }
    }

    /// TEST BUILDS ONLY — the reference op list and the slots its constraints land in.
    #[cfg(test)]
    pub(crate) fn parts(&self) -> (&[TapeOp], &[u32]) {
        (&self.ops, &self.roots)
    }

    /// TEST BUILDS ONLY — a tape laid by hand (a pin that must take every arm of the program's compiler).
    #[cfg(test)]
    pub(crate) fn from_parts(ops: Vec<TapeOp>, roots: Vec<u32>) -> Self {
        let prog = crate::tape_program::RegProgram::compile(&ops, &roots);
        Self { ops: ops.into_boxed_slice(), roots: roots.into_boxed_slice(), prog }
    }

    /// ⭐⭐⭐ THE `bl` SLOTS THIS PROGRAM ACTUALLY READS — the one derived answer to "what does this AIR
    /// depend on", taken from the compiled tape rather than from anyone's reading of the source.
    ///
    /// ROOT-FIX-VERIFIED: `TapeOp::Load(i)` is the ONLY way a value enters the program, and every index
    /// is resolved at compile time by `var_idx`. Scanning the ops is therefore exact and total: a
    /// constraint cannot read a slot outside this set, and a constraint that grows a new read grows this
    /// set with it. That is what makes the shifted-column declaration underivable by hand — and why
    /// `WholeChainMainConstraint::shifted_cols` is computed from this rather than written.
    #[must_use]
    pub fn loaded_slots(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .ops
            .iter()
            .filter_map(|op| match op {
                TapeOp::Load(i) => Some(*i),
                _ => None,
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Ops in the tape — the footprint figure, and what the differential gate reports.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// True when the batch carries no constraint at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Evaluate every constraint over `bl` and γ-batch them by Horner, in the SAME order
    /// [`WholeChainMainConstraint::eval`] always used — the batching order is part of the statement.
    #[must_use]
    /// Evaluate the tape and push EACH constraint's value, unfolded, into `out`.
    ///
    /// [`Self::eval`] Horner-folds the roots with γ, which is what a standalone AIR wants. An AIR that
    /// EMBEDS this block alongside its own residuals must not do that: it needs every constraint to get
    /// its own γ power in the OUTER fold. Folding twice with the same γ makes the total a polynomial whose
    /// coefficients mix residuals, so a nonzero set could cancel — the soundness the batching argument
    /// rests on is "each residual has its own power", and this is how an embedded block keeps it.
    pub fn eval_into(&self, bl: &[Challenge], out: &mut Vec<Challenge>) {
        self.eval_into_in(bl, out);
    }

    /// [`Self::eval_into`] generic over the field the inputs live in — the base field for a zerocheck's round 0 (the
    /// folded rows are base-field at the integer sample points), the extension otherwise. Same constraints, same
    /// order, same values: the constants are base-field and act as the algebra's scalars.
    ///
    /// ⭐ SPEED R8: runs the register program ([`crate::tape_program`]); the slot interpreter it replaced is
    /// [`Self::eval_into_in_reference`], kept as the reference the program is held to.
    /// How many constraints the tape evaluates (lane agg: a circuit sizing its residual list).
    #[must_use]
    pub fn roots_len(&self) -> usize {
        self.roots.len()
    }

    // Ring operations only (lane agg 2026-11-15): `gate_trace::Sym` runs the permutation's tape too.
    pub fn eval_into_in<G: p3_field::Algebra<F> + Copy>(&self, bl: &[G], out: &mut Vec<G>) {
        #[cfg(test)]
        if REFERENCE_ENGINE.load(std::sync::atomic::Ordering::Relaxed) {
            return self.eval_into_in_reference(bl, out);
        }
        let mut regs = vec![G::ZERO; self.prog.registers()];
        self.prog.run(bl, &mut regs);
        out.extend((0..self.prog.roots()).map(|j| self.prog.root(j, &regs)));
    }

    /// ⛔ THE REFERENCE SLOT INTERPRETER — one slot per op, every product a general product, exactly as every proof
    /// before 2026-11-10 was evaluated. No prover or verifier path calls it; it exists so
    /// `tape_program::tests::speed_r8_the_register_program_gives_the_reference_values_in_both_fields` can demand
    /// exact equality, and must never be deleted "because nothing calls it".
    pub fn eval_into_in_reference<G: p3_field::PrimeCharacteristicRing + Copy + From<F>>(&self, bl: &[G], out: &mut Vec<G>) {
        let mut slots: Vec<G> = Vec::with_capacity(self.ops.len());
        for op in self.ops.iter() {
            let v = match *op {
                TapeOp::Load(i) => bl[i as usize],
                TapeOp::Const(c, _) => G::from(c),
                TapeOp::Add(a, b) => slots[a as usize] + slots[b as usize],
                TapeOp::Sub(a, b) => slots[a as usize] - slots[b as usize],
                TapeOp::Mul(a, b) => slots[a as usize] * slots[b as usize],
                TapeOp::Neg(a) => -slots[a as usize],
            };
            slots.push(v);
        }
        out.extend(self.roots.iter().map(|&r| slots[r as usize]));
    }

    pub fn eval(&self, bl: &[Challenge], gamma: Challenge) -> Challenge {
        #[cfg(test)]
        if REFERENCE_ENGINE.load(std::sync::atomic::Ordering::Relaxed) {
            let mut roots = Vec::with_capacity(self.roots.len());
            self.eval_into_in_reference(bl, &mut roots);
            return roots.into_iter().fold(Challenge::ZERO, |acc, r| acc * gamma + r);
        }
        // SPEED R8: the register program, then the same Horner fold over the constraints in the same order.
        let mut regs = vec![Challenge::ZERO; self.prog.registers()];
        self.prog.run(bl, &mut regs);
        let mut acc = Challenge::ZERO;
        for j in 0..self.prog.roots() {
            acc = acc * gamma + self.prog.root(j, &regs);
        }
        acc
    }
}

/// Emit one expression, returning the slot its value lands in.
fn emit_expr(
    e: &SymbolicExpression<F>,
    ll: &SymLeafLayout,
    ops: &mut Vec<TapeOp>,
    memo: &mut std::collections::HashMap<*const SymbolicExpression<F>, u32>,
) -> u32 {
    let op = match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => TapeOp::Load(ll.var_idx(v) as u32),
        SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => TapeOp::Load(ll.is_first() as u32),
        SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => TapeOp::Load(ll.is_last() as u32),
        SymbolicExpr::Leaf(BaseLeaf::IsTransition) => TapeOp::Load(ll.is_trans() as u32),
        SymbolicExpr::Leaf(BaseLeaf::Constant(c)) => TapeOp::Const(*c, Challenge::from(*c)),
        SymbolicExpr::Add { x, y, .. } => {
            let (a, b) = (emit_arc(x, ll, ops, memo), emit_arc(y, ll, ops, memo));
            TapeOp::Add(a, b)
        }
        SymbolicExpr::Sub { x, y, .. } => {
            let (a, b) = (emit_arc(x, ll, ops, memo), emit_arc(y, ll, ops, memo));
            TapeOp::Sub(a, b)
        }
        SymbolicExpr::Mul { x, y, .. } => {
            let (a, b) = (emit_arc(x, ll, ops, memo), emit_arc(y, ll, ops, memo));
            TapeOp::Mul(a, b)
        }
        SymbolicExpr::Neg { x, .. } => TapeOp::Neg(emit_arc(x, ll, ops, memo)),
    };
    ops.push(op);
    (ops.len() - 1) as u32
}

/// Emit a shared child ONCE. The pointer key is what makes the dedup cross constraint boundaries, which
/// the reference evaluator's per-constraint memo could never do.
fn emit_arc(
    e: &std::sync::Arc<SymbolicExpression<F>>,
    ll: &SymLeafLayout,
    ops: &mut Vec<TapeOp>,
    memo: &mut std::collections::HashMap<*const SymbolicExpression<F>, u32>,
) -> u32 {
    let key = std::sync::Arc::as_ptr(e);
    if let Some(&slot) = memo.get(&key) {
        return slot;
    }
    let slot = emit_expr(e, ll, ops, memo);
    memo.insert(key, slot);
    slot
}

/// THE REFERENCE EVALUATOR. No longer on the hot path — [`CompiledTape`] is — but kept because it is what
/// the differential gate checks the tape against. Deleting it would remove the only independent statement
/// of what a constraint MEANS.
#[must_use]
pub fn eval_base_expr_lifted(e: &SymbolicExpression<F>, bl: &[Challenge], ll: &SymLeafLayout) -> Challenge {
    let mut memo: std::collections::HashMap<*const SymbolicExpression<F>, Challenge> =
        std::collections::HashMap::new();
    eval_base_memo(e, bl, ll, &mut memo)
}
fn eval_base_memo(
    e: &SymbolicExpression<F>,
    bl: &[Challenge],
    ll: &SymLeafLayout,
    memo: &mut std::collections::HashMap<*const SymbolicExpression<F>, Challenge>,
) -> Challenge {
    match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => bl[ll.var_idx(v)],
        SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => bl[ll.is_first()],
        SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => bl[ll.is_last()],
        SymbolicExpr::Leaf(BaseLeaf::IsTransition) => bl[ll.is_trans()],
        SymbolicExpr::Leaf(BaseLeaf::Constant(c)) => Challenge::from(*c),
        SymbolicExpr::Add { x, y, .. } => eval_base_arc(x, bl, ll, memo) + eval_base_arc(y, bl, ll, memo),
        SymbolicExpr::Sub { x, y, .. } => eval_base_arc(x, bl, ll, memo) - eval_base_arc(y, bl, ll, memo),
        SymbolicExpr::Mul { x, y, .. } => eval_base_arc(x, bl, ll, memo) * eval_base_arc(y, bl, ll, memo),
        SymbolicExpr::Neg { x, .. } => -eval_base_arc(x, bl, ll, memo),
    }
}
fn eval_base_arc(
    e: &std::sync::Arc<SymbolicExpression<F>>,
    bl: &[Challenge],
    ll: &SymLeafLayout,
    memo: &mut std::collections::HashMap<*const SymbolicExpression<F>, Challenge>,
) -> Challenge {
    let key = std::sync::Arc::as_ptr(e);
    if let Some(&v) = memo.get(&key) {
        return v;
    }
    let v = eval_base_memo(e, bl, ll, memo);
    memo.insert(key, v);
    v
}

/// γ-batched row-local main constraint over the light-decider openings — the shared prover/verifier
/// evaluator both sides reconstruct from the PUBLIC AIR + public values (nothing about it is served,
/// so nothing about it can be forged).
#[derive(Clone)]
pub struct WholeChainMainConstraint {
    pub base: Vec<SymbolicExpression<F>>,
    pub ll: SymLeafLayout,
    pub w: usize,
    pub pw: usize,
    pub np: usize,
    pub pubs: Vec<Challenge>,
    pub gamma: Challenge,
    pub max_deg: usize,
    /// Single-row AIR replicated to the WHIR floor: force is_first = is_last = 1, is_transition = 0
    /// on every replicated row. `false` for a genuinely multi-row trace (the whole-chain AIR).
    pub single_row: bool,
    /// The straight-line program `eval` actually runs. Built ONCE per constraint construction, which is
    /// once per proof — never per row and never per sumcheck point. Shared by `Arc` so the per-γ clone
    /// the factories perform is a refcount bump rather than a recompile.
    pub tape: std::sync::Arc<CompiledTape>,
    /// ⭐⭐⭐ THE NEXT-ROW READS, DERIVED ONCE: `(bl slot, trace column)` for every shifted value the
    /// tape loads. ONE source of truth for BOTH the `at` calls in `eval` and the set `shifted_cols`
    /// declares — precisely the invariant whose absence made the declaration wrong. Built in
    /// [`Self::new`] from [`CompiledTape::loaded_slots`]; an `Arc` so `with_gamma` is a refcount bump.
    pub shifted: std::sync::Arc<Vec<(usize, usize)>>,
}

impl WholeChainMainConstraint {
    /// Build the constraint and COMPILE its tape. Every call site goes through here so no construction
    /// can accidentally ship without one.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base: Vec<SymbolicExpression<F>>,
        ll: SymLeafLayout,
        w: usize,
        pw: usize,
        np: usize,
        pubs: Vec<Challenge>,
        gamma: Challenge,
        max_deg: usize,
        single_row: bool,
    ) -> Self {
        let tape = std::sync::Arc::new(CompiledTape::compile(&base, &ll));
        // The `bl` block layout `eval` fills is
        // `[main_local(w) | main_next(w) | preproc_local(pw) | preproc_next(pw) | pubs(np) | sel(3)]`
        // (see `SymLeafLayout::var_idx`, which resolved every `TapeOp::Load` index). So a loaded slot in
        // `w..2w` is main column `slot - w` of the NEXT row, and one in `2w+pw..2w+2pw` is preprocessed
        // column `slot - 2w - pw` — read by this gate as trace column `w + that`, exactly as the local
        // half is (`bl[2w + c] = local[w + c]`).
        let shifted: Vec<(usize, usize)> = tape
            .loaded_slots()
            .into_iter()
            .filter_map(|slot| {
                let slot = slot as usize;
                if slot >= w && slot < 2 * w {
                    Some((slot, slot - w))
                } else if slot >= 2 * w + pw && slot < 2 * w + 2 * pw {
                    Some((slot, w + (slot - 2 * w - pw)))
                } else {
                    None
                }
            })
            .collect();
        Self {
            base,
            ll,
            w,
            pw,
            np,
            pubs,
            gamma,
            max_deg,
            single_row,
            tape,
            shifted: std::sync::Arc::new(shifted),
        }
    }

    /// Rebuild the SAME constraint at a different γ without recompiling the tape — the batching scalar is
    /// the only thing that changes between a prover's and a verifier's view of one statement.
    #[must_use]
    pub fn with_gamma(&self, gamma: Challenge) -> Self {
        Self {
            base: self.base.clone(),
            ll: self.ll.clone(),
            w: self.w,
            pw: self.pw,
            np: self.np,
            pubs: self.pubs.clone(),
            gamma,
            max_deg: self.max_deg,
            single_row: self.single_row,
            tape: std::sync::Arc::clone(&self.tape),
            shifted: std::sync::Arc::clone(&self.shifted),
        }
    }
}

impl WholeChainMainConstraint {
    /// The tape's input row, in whichever field the row lives (the ONE fill both `eval` and `eval_base` read): trace_local,
    /// the next-row slots the tape loads, the public values, and the boundary selectors from the fold point.
    fn fill_row<G: p3_field::PrimeCharacteristicRing + Copy>(
        &self,
        bl: &mut [G],
        local: &crate::air_zerocheck::Row<'_, G>,
        at: &dyn Fn(usize) -> G,
        x: &[G],
        public: &dyn Fn(usize) -> G,
    ) {
        let (w, pw, np) = (self.w, self.pw, self.np);
        for c in 0..w {
            bl[c] = local[c];
        }
        for c in 0..pw {
            bl[2 * w + c] = local[w + c];
        }
        for &(slot, col) in self.shifted.iter() {
            bl[slot] = at(col);
        }
        for k in 0..np {
            bl[2 * w + 2 * pw + k] = public(k);
        }
        // Boundary selectors from the fold point x (MSB-first, row0 = all-zero, lastrow = all-one).
        let mut is_first = G::ONE;
        let mut is_last = G::ONE;
        for &xk in x {
            is_first *= G::ONE - xk;
            is_last *= xk;
        }
        if self.single_row {
            bl[2 * w + 2 * pw + np] = G::ONE;
            bl[2 * w + 2 * pw + np + 1] = G::ONE;
            bl[2 * w + 2 * pw + np + 2] = G::ZERO;
        } else {
            bl[2 * w + 2 * pw + np] = is_first;
            bl[2 * w + 2 * pw + np + 1] = is_last;
            bl[2 * w + 2 * pw + np + 2] = G::ONE - is_last;
        }
    }
}

impl WholeChainMainConstraint {
    /// ⭐ V2 (b) PIECE 3 — the tape's residuals (its roots, in the order `eval` Horner-folds them), generic over the field
    /// the row lives in: the same `fill_row` and the same compiled tape `eval` and `eval_base` run. `public(k)` answers the
    /// AIR's public value `k` in the row's field (a caller tracing with `gate_trace::Sym` passes its public inputs).
    pub fn residuals_generic<G: crate::gate_trace::GateAlg>(
        &self,
        local: &crate::air_zerocheck::Row<'_, G>,
        at: &dyn Fn(usize) -> G,
        x: &[G],
        public: &dyn Fn(usize) -> G,
    ) -> Vec<G> {
        let mut bl = vec![G::ZERO; 2 * self.w + 2 * self.pw + self.np + 3];
        self.fill_row(&mut bl, local, at, x, public);
        let mut out = Vec::with_capacity(self.tape.roots.len());
        self.tape.eval_into_in(&bl, &mut out);
        out
    }
}

impl AirConstraint for WholeChainMainConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        self.max_deg
    }
    /// ⭐ ROUND 0 IN THE BASE FIELD, for every gate on a base-field statement. MEASURED 2026-11-03 (`sample`, the real joined ledger):
    /// this tape was 25-50 % of a block's on-CPU prove, in extension arithmetic even where every input is a base-field integer.
    fn has_base_eval(&self) -> bool {
        self.pubs.iter().all(|p| {
            <Challenge as p3_field::BasedVectorSpace<F>>::as_basis_coefficients_slice(p)[1..].iter().all(|c| *c == F::ZERO)
        })
    }
    fn eval_base(&self, local: &crate::air_zerocheck::Row<'_, F>, at: &dyn Fn(usize) -> F, x: &[F]) -> Challenge {
        let mut bl = vec![F::ZERO; 2 * self.w + 2 * self.pw + self.np + 3];
        let public = |k: usize| <Challenge as p3_field::BasedVectorSpace<F>>::as_basis_coefficients_slice(&self.pubs[k])[0];
        self.fill_row(&mut bl, local, at, x, &public);
        let mut residuals = Vec::with_capacity(self.tape.roots.len());
        self.tape.eval_into_in(&bl, &mut residuals);
        let mut acc = Challenge::ZERO;
        for r in residuals {
            acc = acc * self.gamma + Challenge::from(r);
        }
        acc
    }
    /// ⭐⭐⭐ THE NEXT-ROW CELLS THIS GATE ACTUALLY CONSUMES — derived from the compiled tape, never from
    /// the shape of the loops that fill the buffer.
    ///
    /// ROOT-FIX-VERIFIED: `self.shifted` is built in [`Self::new`] from [`CompiledTape::loaded_slots`],
    /// and `eval` calls `at` for exactly those slots. Declaration and reads are the SAME list, so they
    /// cannot drift; a constraint that grows a next-row read grows both together, and one that drops a
    /// read drops both.
    ///
    /// ⛔⛔⛔ WHAT WAS WRONG BEFORE, STATED AS MEASURED AND NOT AS FIRST DIAGNOSED. `eval` used to call
    /// `at(c)` for EVERY `c in 0..w` and `at(w + c)` for every `c in 0..pw`, filling the whole
    /// `trace_next` block whether or not the tape ever loaded those slots — and this gate had no
    /// `shifted_cols` of its own, so it fell to the trait default `None`. A COMPOSER
    /// (`SpongeChainConstraint::shifted_cols`) then hand-listed 35 of 196 columns read off its OWN
    /// `at(...)` calls, never counting the ones this gate's fill loop requested. MEASURED 2026-09-16
    /// (debug build, backtrace): `SettlementDeltaAir::eval → SpongeChainConstraint::eval →
    /// WholeChainMainConstraint::eval` hitting *"⛔ shifted column 16 was read but not declared by
    /// `shifted_cols()`"* at `air_zerocheck.rs:583`, failing 16 tests across THREE unrelated families
    /// (`harness::fuzz::*`, `harness::vacuity::*`, `da_seed_regen_tests::*`) from this ONE cause.
    ///
    /// ⛔ AND THE FIRST DIAGNOSIS OF THAT FAILURE WAS WRONG — recorded because the correction is the
    /// useful part. It read as "cells the proof did not constrain", on the reasoning that an undeclared
    /// column stays at `air_zerocheck`'s `Ea4::ZERO` initialiser on both the prove and the verify side.
    /// It does — but `self.tape.eval(&bl, self.gamma)` is the ONLY consumer of `bl`, and a slot no
    /// `TapeOp::Load` names is never read, so those fetched values were DISCARDED rather than folded
    /// into a residual. MEASURED by the pin
    /// `the_sponge_chains_shifted_declaration_covers_the_gate_it_forwards_into`: for the sponge's own
    /// `p2` this set is EMPTY — the gate consumes no next-row cell at all, and column 16 was requested
    /// by the fill loop, never by a constraint. The defect was therefore a false declaration plus a
    /// full-width rotation fold nobody read — a throughput cost and a broken invariant, NOT a proof
    /// standing over a stale value. ⛔ A `⛔⛔⛔` in an assertion string is that assertion's author's
    /// claim about consequences; the consequence still has to be measured separately.
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        let mut v: Vec<usize> = self.shifted.iter().map(|&(_, col)| col).collect();
        v.sort_unstable();
        v.dedup();
        Some(v)
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Challenge]) -> Challenge, x: &[Challenge]) -> Challenge {
        // trace_local | trace_next (rot-fold `at`, point ignored) — main + committed preproc columns.
        //
        // ⛔⛔⛔ THE NEXT-ROW HALF IS REQUESTED ONLY WHERE THE TAPE LOADS IT, AND THAT IS THE SAME SET
        // `shifted_cols` DECLARES. This used to call `at` for EVERY column of both halves whether or not
        // the tape ever read the slot, so a gate consuming no next-row cell still asked the prover for
        // the whole width — and a caller composing this gate (`SpongeChainConstraint::shifted_cols`,
        // which forwards its `at` into `self.p2.eval` on its first line) hand-listed 35 of 196 columns
        // while this loop requested all 196. MEASURED 2026-09-16 (debug build, backtrace): *"⛔ shifted
        // column 16 was read but not declared by `shifted_cols()`"* at `air_zerocheck.rs:583`, failing 16
        // tests across THREE unrelated families from this ONE cause.
        //
        // ⛔ THE CONSEQUENCE, MEASURED RATHER THAN INFERRED: `self.tape.eval(&bl, self.gamma)` below is
        // the ONLY consumer of `bl`, so a slot no `TapeOp::Load` names was fetched and DISCARDED. The
        // first diagnosis called those "cells the proof did not constrain"; they were not folded into
        // any residual at all. The cost was a full-width rotation nobody read, plus a declaration that
        // no longer described the gate — a throughput and invariant defect, not a stale-value proof.
        //
        // ROOT-FIX-VERIFIED: requests and declaration are now the SAME derived list (`self.shifted`,
        // built in `new` from `CompiledTape::loaded_slots`). A slot the tape never loads is never
        // requested, so leaving it at `Ea4::ZERO` changes no evaluated value; a slot that IS loaded is
        // both folded and declared. The two cannot drift because neither is written by hand.
        let mut bl = vec![Challenge::ZERO; 2 * self.w + 2 * self.pw + self.np + 3];
        self.fill_row(&mut bl, local, &|c| at(c, &[]), x, &|k| self.pubs[k]);
        // γ-batch every base constraint (Horner) over the trace columns — through the COMPILED TAPE, whose
        // equality with the reference walker above is the differential gate's whole subject.
        self.tape.eval(&bl, self.gamma)
    }
}

/// Build the whole-chain AIR + its deterministic honest trace + public values (`cm`). Deterministic
/// from `t` alone, so prover and verifier on ANY device derive the identical statement.
pub fn build_whole_chain_artifacts(t: usize) -> (TallSisOpenAir, RowMajorMatrix<F>, Vec<F>) {
    assert_eq!(SW_M % t, 0);
    let rows = SW_M / t;
    let mut inner_int = 0u64;
    let mut x2_int = 0u64;
    for j in 0..SW_M {
        inner_int += sw_a(0, j);
        x2_int += sw_a(0, j) % SW_P2;
    }
    let cm = inner_int % SW_Q;
    let k = inner_int / SW_Q;
    let w = t + 2 + SCC_W;
    let mut data: Vec<F> = Vec::with_capacity(rows * w);
    let mut acc_i = 0u64;
    let mut acc_x = 0u64;
    for row in 0..rows {
        for c in 0..t {
            let j = row * t + c;
            acc_i += sw_a(0, j);
            acc_x += sw_a(0, j) % SW_P2;
        }
        let mut rowv = vec![F::ONE; t];
        rowv.push(F::from_u64(acc_i));
        rowv.push(F::from_u64(acc_x));
        let mut chk = vec![F::ZERO; SCC_W];
        if row == rows - 1 {
            for tt in 0..SW_KBITS {
                chk[tt] = F::from_u64((k >> tt) & 1);
            }
            for tt in 0..SW_CMBITS {
                chk[SW_KBITS + tt] = F::from_u64((cm >> tt) & 1);
            }
            let c2 = SW_KBITS + SW_CMBITS;
            let qx = x2_int / SW_P2;
            let rx = x2_int % SW_P2;
            for tt in 0..SW_QXBITS {
                chk[c2 + tt] = F::from_u64((qx >> tt) & 1);
            }
            for tt in 0..SW_P2BITS {
                chk[c2 + SW_QXBITS + tt] = F::from_u64((rx >> tt) & 1);
            }
            let rc = cm % SW_P2;
            let rk = k % SW_P2;
            let t1 = rc + rk * (SW_Q % SW_P2);
            let qt = t1 / SW_P2;
            let ry = t1 % SW_P2;
            for tt in 0..SW_QTBITS {
                chk[c2 + SW_QXBITS + SW_P2BITS + tt] = F::from_u64((qt >> tt) & 1);
            }
            for tt in 0..SW_P2BITS {
                chk[c2 + SW_QXBITS + SW_P2BITS + SW_QTBITS + tt] = F::from_u64((ry >> tt) & 1);
            }
        }
        rowv.extend_from_slice(&chk);
        data.extend_from_slice(&rowv);
    }
    let trace = RowMajorMatrix::new(data, w);
    let air = TallSisOpenAir { t };
    let pis = vec![F::from_u64(cm)];
    (air, trace, pis)
}

/// Reconstruct the γ-batched whole-chain constraint from the PUBLIC AIR + public values — the SAME
/// constructor on the prove and verify side, on every device.
pub fn build_whole_chain_constraint(air: &TallSisOpenAir, pvs: &[F], gamma: Challenge) -> WholeChainMainConstraint {
    let w = <TallSisOpenAir as BaseAir<F>>::width(air);
    // The whole-chain AIR carries a PREPROCESSED trace (the public SIS matrix columns, width 2t):
    // the layout + the constraint's `pw` MUST reflect it, and the committed trace appends those
    // columns (see `prove_whole_chain_light_decider_bytes`) so the gates resolve `local[w+c]`.
    let pw = <TallSisOpenAir as BaseAir<F>>::preprocessed_width(air);
    let np = <TallSisOpenAir as BaseAir<F>>::num_public_values(air);
    let npc = <TallSisOpenAir as BaseAir<F>>::num_periodic_columns(air);
    let layout = AirLayout {
        preprocessed_width: pw,
        main_width: w,
        num_public_values: np,
        num_periodic_columns: npc,
        ..Default::default()
    };
    let lg = LogUpGadget::new();
    let (base, _ext) = get_symbolic_constraints::<F, Challenge, _, _>(air, layout, &[], &lg);
    let ll = SymLeafLayout { w, preproc_w: pw, npub: np };
    let pubs: Vec<Challenge> = pvs.iter().map(|&v| Challenge::from(v)).collect();
    WholeChainMainConstraint::new(base, ll, w, pw, np, pubs, gamma, 8, false)
}

/// THE WHOLE CHAIN, FOLDED INTO THE PROOF (user 2026-07-22). `chain_acc` is the 16-byte O(1) accumulator that
/// already commits the ENTIRE chain state — tip, blue-score, note-frontier root, nullifier root, SPARSE nullifier
/// root, and the genesis identity (`sync::sync_binding`). Folding it in as a TRANSCRIPT-BOUND statement input is
/// what makes the adopt gate SOUND: before this, the proof was STATE-INDEPENDENT (it took no arguments), so the
/// same bytes verified against ANY chain and a peer could serve a forged tip / frontier / nullifier root under a
/// perfectly valid proof — the `chain_acc` equality check in `adopt_sync_bundle` compared the peer's hash against
/// the peer's OWN claims, which is self-consistency, not soundness.
///
/// NO GROWTH ON ANY AXIS — including TIME. These limbs are absorbed into the Fiat-Shamir challenger; they add ZERO
/// trace rows, ZERO committed columns, ZERO proof bytes, and ZERO proving work. The binding is free, and it holds
/// at any chain length: `chain_acc` is a FIXED 16 bytes whether the chain is 1 block or 10^18.
///
/// One byte per limb so every value is trivially below the field modulus on every device (identical packing on
/// daemon, desktop wallet, and the iPhone in-process node — cross-implementation proofs stay byte-compatible).
fn chain_acc_bind(pis: &[F], chain_acc: &[u8; 16]) -> Vec<F> {
    let mut bind = pis.to_vec();
    bind.extend(chain_acc.iter().map(|&b| F::from_u64(b as u64)));
    bind
}

/// PROVE the whole-chain adopt-gate light-decider proof (the #29 DSYNC serve side). Pinned `t` — identical
/// bytes-in on every device, so identical verification everywhere — and BOUND to `chain_acc`, so the proof
/// certifies THIS chain's state and no other (see [`chain_acc_bind`]).
pub fn prove_whole_chain_light_decider_bytes(chain_acc: &[u8; 16]) -> Option<Vec<u8>> {
    let t = WHOLE_CHAIN_T;
    let (air, trace, pis) = build_whole_chain_artifacts(t);
    let w = trace.width();
    if w == 0 || trace.values.is_empty() {
        return None;
    }
    let h = trace.values.len() / w;
    if !h.is_power_of_two() {
        return None;
    }
    // The committed light-decider trace is [main(w) | preproc(pw)] so the row-local gates resolve
    // preproc via `local[w+c]`. Same height.
    let preproc = <TallSisOpenAir as BaseAir<F>>::preprocessed_trace(&air)?;
    let pw = preproc.width();
    if pw == 0 || preproc.values.len() != h * pw {
        return None;
    }
    let total_w = w + pw;
    // Row-major (main + preproc) → column-major cols (the light decider commits per column).
    let mut cols: Vec<Vec<F>> = vec![Vec::with_capacity(h); total_w];
    for row in 0..h {
        let mb = row * w;
        for c in 0..w {
            cols[c].push(trace.values[mb + c]);
        }
        let pb = row * pw;
        for c in 0..pw {
            cols[w + c].push(preproc.values[pb + c]);
        }
    }
    let make = |_i: usize, gamma: Challenge| build_whole_chain_constraint(&air, &pis, gamma);
    // The chain state rides the Fiat-Shamir transcript (free), so this proof certifies THIS chain only.
    crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes(
        vec![cols],
        make,
        &chain_acc_bind(&pis, chain_acc),
    )
}

/// ⛔ DB-213b — the ONE table the whole-chain proof commits: `[main | preprocessed]` at the public trace's
/// height, from the same artifacts the prover lays it from.
fn whole_chain_table_shape(air: &TallSisOpenAir, trace: &p3_matrix::dense::RowMajorMatrix<F>) -> Option<(usize, usize)> {
    use p3_matrix::Matrix;
    let w = trace.width();
    if w == 0 || trace.values.is_empty() {
        return None;
    }
    let h = trace.values.len() / w;
    if !h.is_power_of_two() {
        return None;
    }
    let pw = <TallSisOpenAir as BaseAir<F>>::preprocessed_trace(air)?.width();
    Some((h.trailing_zeros() as usize, w + pw))
}

/// VERIFY the whole-chain adopt-gate light-decider proof (the node's O(1) adopt gate): rebuild the
/// PUBLIC AIR + its `cm` public input (deterministic), reconstruct the SAME batch constraint, verify.
/// Fail-closed on any decode / shape / zerocheck / opening mismatch.
pub fn verify_whole_chain_light_decider_bytes(proof_bytes: &[u8], chain_acc: &[u8; 16]) -> bool {
    if proof_bytes.is_empty() {
        return false;
    }
    let t = WHOLE_CHAIN_T;
    let (air, _trace, pis) = build_whole_chain_artifacts(t);
    let make = |_i: usize, gamma: Challenge| build_whole_chain_constraint(&air, &pis, gamma);
    // FAIL-CLOSED on a state mismatch: the transcript was seeded with the PROVER's `chain_acc`, so a proof minted
    // for a different chain state (a forged tip / frontier / nullifier root) derives different challenges and the
    // openings do not check out. This is what upgrades the adopt gate from self-consistency to soundness.
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes(
        proof_bytes,
        make,
        &chain_acc_bind(&pis, chain_acc),
        &match whole_chain_table_shape(&air, &_trace) { Some(s) => vec![s], None => return false },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_chain_light_decider_round_trips_and_rejects_tamper() {
        let acc = [0x3Cu8; 16];
        let proof = prove_whole_chain_light_decider_bytes(&acc).expect("honest whole-chain prove succeeds");
        assert!(
            proof.len() <= 1_800_000,
            "no-blowup: whole-chain proof stays under the constant cap ({} B)",
            proof.len()
        );
        assert!(verify_whole_chain_light_decider_bytes(&proof, &acc), "honest proof verifies");

        // Tamper: a single flipped byte diverges the transcript → reject (try several offsets so a
        // flip landing in slack bytes cannot produce a false green).
        let mut rejected_flip = false;
        for off in [7usize, proof.len() / 2, proof.len() - 3] {
            let mut bad = proof.clone();
            bad[off] ^= 0x5A;
            if !verify_whole_chain_light_decider_bytes(&bad, &acc) {
                rejected_flip = true;
                break;
            }
        }
        assert!(rejected_flip, "a flipped byte is rejected");

        // Tamper: truncation is rejected fail-closed.
        assert!(!verify_whole_chain_light_decider_bytes(&proof[..proof.len() / 2], &acc), "truncated proof rejected");
        // Empty is rejected fail-closed.
        assert!(!verify_whole_chain_light_decider_bytes(&[], &acc), "empty proof rejected");
    }
}

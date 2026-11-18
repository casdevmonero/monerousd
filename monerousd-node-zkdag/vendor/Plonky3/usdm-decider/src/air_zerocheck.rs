// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! Production multilinear AIR→sumcheck constraint reduction (the WHIR light decider's
//! constraint-verify layer). This PROMOTES the proven `whir_pcs_research::a4_pcs_whir`
//! A4.5.1 composed-AIR zerocheck (row-local degree-d + row-shifted cyclic transition,
//! γ-batched, tamper-tested) from `#[cfg(test)]` research into a GENERIC production API
//! that any set of AIR constraints (incl. the rec-block `SymEvalR6Leaf`/`LeafSource`/
//! `OodInput`/`OodCheck`) can be driven through.
//!
//! # What it proves
//! Given committed MLE trace columns `cols[0..w]` (each `2^n` base-field evaluations) and a
//! γ-batched AIR constraint polynomial `C` (row-local AND row-shifted, degree ≥ 2 allowed),
//! the zerocheck proves the identity holds on EVERY row:
//! ```text
//!     Σ_{x ∈ {0,1}^n} eq(z, x) · C(cols(x), cols(σ(x))) == 0        (z Fiat-Shamir random)
//! ```
//! by a per-variable sumcheck whose per-round univariate has degree `= deg(C) + 1`. The final
//! reduced claim is checked against `C` evaluated on the column values at the sumcheck point
//! `r` — those column values are exactly what the WHIR PCS opens (the binding to the
//! commitment). Row-shifted (`next()`) access is the `+1` cyclic shift `σ`: the constraint
//! closure re-evaluates the ORIGINAL committed column MLE at `σ(x)` (in-substitution), so a
//! single committed column serves both `local` and `next` — no separate rotation commitment.
//!
//! This is the FAST replacement for the ~11s FRI `prove_batch` rec prove: the verifier work is
//! `n` rounds of a constant-degree univariate check + one constraint eval on the opened row —
//! hashless (WHIR), phone-class, and constant-size in the spend count.
//!
//! Soundness: a violated constraint makes the zerocheck sum ≠ 0 or the final reduced claim ≠
//! `C(opened)` at the random `r`, caught with probability `1 − deg·n/|EF|` (Schwartz–Zippel over
//! `KoalaBear⁴`). Proven by the adversarial tamper tests below (honest accept / tampered reject).

extern crate alloc;
use rayon::prelude::*;
use alloc::vec;
use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{Field, PrimeCharacteristicRing, BasedVectorSpace};

use crate::hiding_decider::{Chl, Ea4, Fa4};

/// The equality-weight table `eq(z, ·)` over the boolean hypercube `{0,1}^n`, as `2^n`
/// extension-field evaluations in standard (low-bit-first) order. `eq(z, x) = Π_k (z_k·x_k +
/// (1−z_k)(1−x_k))`.
#[must_use]
/// Recombine four folded limb columns into the value they encode: `l0 + X·l1 + X²·l2 + X³·l3`.
///
/// ⭐⭐⭐ THIS IS THE DECIDER'S HOTTEST LINE, AND IT WAS FOUR FULL EXTENSION MULTIPLIES.
///
/// Every `Ea4` value a recursion carries is committed as FOUR base-field columns, so a constraint that
/// reads one must recombine it. During the sumcheck each of those columns is itself an `Ea4` (the folded
/// value), and the obvious spelling — `l0*basis[0] + l1*basis[1] + l2*basis[2] + l3*basis[3]` — hands
/// four schoolbook `Ea4 × Ea4` products to a generic `Mul`. MEASURED: the bound step calls this ~3,900
/// times per evaluation (1,986 opened values + a 1,835-cell γ ladder + the round evals), which is most
/// of its 391 µs.
///
/// But `basis[k]` is `X^k`, and multiplying by a monomial is a COORDINATE SHIFT, not a multiplication.
/// With `X^4 = W` (`W = 3` for KoalaBear's degree-4 extension, `mul_w(a) = a.double() + a`):
///
/// ```text
///   X·(a0 + a1X + a2X² + a3X³) = W·a3 + a0X + a1X² + a2X³
/// ```
///
/// so the whole recombination is 16 additions and 6 triples. ⛔ IT IS ALSO EXACTLY THE KIND OF HAND
/// ALGEBRA THAT IS WRONG UNTIL PROVEN: `pack_limbs_equals_the_basis_sum` checks it against the naive
/// form it replaces, on values drawn across the field, every run.
#[inline]
#[must_use]
pub fn pack_limbs(l0: Ea4, l1: Ea4, l2: Ea4, l3: Ea4) -> Ea4 {
    let c = |v: &Ea4| -> [Fa4; 4] {
        let s = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v);
        [s[0], s[1], s[2], s[3]]
    };
    let (a, b, d, e) = (c(&l0), c(&l1), c(&l2), c(&l3));
    // ×W for KoalaBear's degree-4 extension, spelled the same way the field itself spells it.
    let w = |x: Fa4| x.double() + x;
    Ea4::from_basis_coefficients_fn(|j| match j {
        0 => a[0] + w(b[3]) + w(d[2]) + w(e[1]),
        1 => a[1] + b[0] + w(d[3]) + w(e[2]),
        2 => a[2] + b[1] + d[0] + w(e[3]),
        _ => a[3] + b[2] + d[1] + e[0],
    })
}

pub fn eq_z_hypercube(z: &[Ea4]) -> Vec<Ea4> {
    // Variable convention: `z[0]` is the HIGH bit (bit n-1), matching `fold_one_var`/`mle_eval`
    // which bind high-bit-first (round k binds bit n-1-k with challenge r[k]). Each new variable is
    // interleaved as the LOW bit so the earliest-processed `z[0]` ends up highest — so `r[k]` binds
    // the variable `z[k]` and `eq(z,r) = Π(z[k]·r[k] + (1-z[k])(1-r[k]))` pairs correctly.
    let mut table = vec![Ea4::ONE];
    for &zk in z {
        let mut next = vec![Ea4::ZERO; table.len() * 2];
        let one_m_zk = Ea4::ONE - zk;
        for (j, &e) in table.iter().enumerate() {
            next[2 * j] = e * one_m_zk; // x_this = 0 (this var = new LOW bit)
            next[2 * j + 1] = e * zk; // x_this = 1
        }
        table = next;
    }
    table
}

/// Fold one variable of an MLE evaluation table at challenge `r`: `out[i] = v[i]·(1−r) +
/// v[half+i]·r`, halving the table (binds the high variable — matches A4.5.1's fold order).
#[must_use]
pub fn fold_one_var(v: &[Ea4], r: Ea4) -> Vec<Ea4> {
    let half = v.len() / 2;
    let omr = Ea4::ONE - r;
    (0..half).map(|i| v[i] * omr + v[half + i] * r).collect()
}

/// Evaluate a univariate polynomial given its evaluations at `0,1,…,d` (`evals.len()=d+1`) at
/// an arbitrary point `r`, via Lagrange interpolation on the integer nodes.
#[must_use]
pub fn lagrange_eval(evals: &[Ea4], r: Ea4) -> Ea4 {
    let d = evals.len();
    let mut acc = Ea4::ZERO;
    for (j, &yj) in evals.iter().enumerate() {
        let xj = Ea4::from(Fa4::from_u64(j as u64));
        let mut num = Ea4::ONE;
        let mut den = Ea4::ONE;
        for m in 0..d {
            if m == j {
                continue;
            }
            let xm = Ea4::from(Fa4::from_u64(m as u64));
            num *= r - xm;
            den *= xj - xm;
        }
        acc += yj * num * den.inverse();
    }
    acc
}

/// Evaluate the multilinear extension of base-field evaluations `vals` (length `2^n`, low-bit
/// first) at an extension point `point` (`point.len()=n`): `Σ_x vals[x]·eq(point, x)`.
#[must_use]
pub fn mle_eval(vals: &[Fa4], point: &[Ea4]) -> Ea4 {
    let mut cur: Vec<Ea4> = vals.iter().map(|&v| Ea4::from(v)).collect();
    for &rk in point {
        cur = fold_one_var(&cur, rk);
    }
    debug_assert_eq!(cur.len(), 1);
    cur[0]
}

/// The `+1` cyclic-shift point map `σ` for a length-`2^n` hypercube: the multilinear point at
/// which evaluating a column's MLE yields its next-row (`i+1 mod 2^n`) values. Implemented as
/// the binary increment carry chain lifted to the extension field: for bit `k`, `σ(x)_k = x_k +
/// carry_{k}·(1 − 2·x_k)` where `carry` ripples from the low bit. Matches A4.5.1's
/// `cyclic_shift_sigma_at`.
#[must_use]
pub fn cyclic_shift_sigma<G: PrimeCharacteristicRing + Copy>(x: &[G]) -> Vec<G> {
    // σ = the +1 binary increment (add one) of the row index. Point convention is HIGH-bit-first
    // (`x[0]` = the high bit, matching `eq_z_hypercube`/`fold_one_var`/`mle_eval`), so the carry must
    // ripple from the LOW bit = `x[last]` up to the high bit = `x[0]`. Per bit: `new = x XOR carry`,
    // `carry' = x AND carry`, arithmetized over EF as XOR(a,c)=a+c−2ac, AND(a,c)=a·c (exact for
    // boolean a,c; the multilinear extension since σ is applied at boolean-or-folded coordinates).
    // Generic over the field (2026-09-29): a gate's base-field round 0 shifts a base-field point.
    let n = x.len();
    let mut out = vec![G::ZERO; n];
    let mut carry = G::ONE;
    let two = G::from_u64(2);
    for k in (0..n).rev() {
        let xk = x[k];
        out[k] = xk + carry - two * xk * carry;
        carry = xk * carry;
    }
    out
}

/// A γ-batched AIR constraint evaluator. Given, at a hypercube-or-folded point `x`:
///   * `local`  — each committed column's MLE value at `x`,
///   * `at`     — a closure to evaluate ANY committed column's MLE at an arbitrary point
///                (used for row-shifted `next()` access via [`cyclic_shift_sigma`]),
///   * `x`      — the current point (extension coordinates),
/// returns the single γ-batched constraint value `Σ_f γ^f · C_f(...)`. Honest trace ⇒ 0 at
/// every hypercube `x`.
pub trait AirConstraint {
    /// Max total degree of the batched constraint in the sumcheck variables (sets the per-round
    /// univariate degree, so `degree(nvars)+2` evaluation points per round). Row-LOCAL constraints
    /// return a constant; ROW-SHIFTED constraints (that call `at` with [`cyclic_shift_sigma`]) must
    /// return `nvars + 1` — the +1 cyclic-shift carry chain raises the per-round degree to `nvars+1`.
    fn degree(&self, nvars: usize) -> usize;
    /// Evaluate the γ-batched constraint at point `x`. `local[c]` is column `c`'s value at `x`;
    /// `at(c, p)` evaluates column `c`'s MLE at point `p`.
    ///
    /// `local` is a [`Row`], not a bare slice, and the difference is a SECURITY property rather than
    /// a style choice: on a carrier arriving from the wire the row's length is whatever the SENDER
    /// declared, so `local[c]` on a bare slice let an unauthenticated remote party choose whether an
    /// index inside the verifier is in range. [`Row`] turns every out-of-range read into a RECORDED
    /// REFUSAL instead of an unwind — see that type's doc for the measurement, and for why the value
    /// it substitutes is never allowed to reach a verdict.
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4;

    /// The UNBATCHED residuals, before the γ-power fold [`eval`] applies.
    ///
    /// ⭐⭐⭐ WHY THIS EXISTS, AND IT IS A PILLAR, NOT A CONVENIENCE. A gate folds its residuals with
    /// `acc += gp * res; gp *= gamma`. When γ is a CONSTANT that fold is free. When a recursion needs
    /// γ to be a committed CELL — because it is verifying many carriers at once and each has its own γ
    /// — the k-th residual becomes degree k in committed cells, for k in the hundreds, and the sumcheck
    /// is silently truncated: the proof PROVES and does not VERIFY. MEASURED (§BV).
    ///
    /// Handing the residuals out lets the caller fold them against γ-POWER COLUMNS (`γ^{k+1} == γ^k·γ`,
    /// row-local), so every residual multiplies a degree-1 cell and the total degree is `deg(res) + 1`
    /// no matter how many there are. That is what lets `BLOCK_FIXED_TX_COUNT` carriers be ROWS of ONE
    /// table instead of one table each — and a per-block proof whose size does not move with how many
    /// spends were real is a PRIVACY requirement before it is a scalability one (`cover.rs`: a per-block
    /// count that varies with real activity lets an observer count real outputs).
    ///
    /// The default is the already-folded value as a single residual: correct for every gate, and exact
    /// for one whose γ is a constant. A gate meant to be an INNER AIR of a multi-carrier aggregate must
    /// override it, or its γ never leaves the circuit's constants.
    fn residuals(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        vec![self.eval(local, at, x)]
    }

    /// Does this gate evaluate on a BASE-field row ([`Self::eval_base`])? Round 0 of the zerocheck folds the committed
    /// (base-field) columns at integer sample points, so every cell, every next-row cell and every coordinate of the
    /// point is base-field there; a gate whose laws are generic over the field batches its residuals with
    /// extension-by-base products and skips the extension arithmetic entirely. `false` (the default) keeps the prover
    /// on `eval` with lifted rows — exactly the old path.
    fn has_base_eval(&self) -> bool {
        false
    }

    /// The gate on a base-field row — the SAME γ-batched value `eval` returns on that row lifted to the extension
    /// (byte-identical proofs either way). Called by the prover only when [`Self::has_base_eval`] is true.
    fn eval_base(&self, _local: &Row<'_, Fa4>, _at: &dyn Fn(usize) -> Fa4, _x: &[Fa4]) -> Ea4 {
        unreachable!("eval_base is called only when has_base_eval() is true")
    }

    /// ⛔ THE FREE-WITNESS DECLARATION (the security pillar, 2026-09-29). The DEBUG prover runs a free-witness census on
    /// every gate it proves ([`debug_free_witness_census`]): for each column, the first LIVE cell of the honest trace is
    /// nudged and the laws that read that row and the row before it are re-evaluated; a column no law notices is a FREE
    /// WITNESS at a value the prover chose — the class behind the bond delta, the peg-in deposit and the reserve carrier
    /// found this month, each with a passing tamper pin. `None` (the default) makes the census REPORT such columns by
    /// index; `Some(list)` names the columns a gate knowingly leaves unread on some traces (padding lanes, a selector's
    /// scratch) and turns the census into a REFUSAL of any free column outside the list. Every new gate declares.
    fn free_columns(&self) -> Option<Vec<usize>> {
        None
    }

    /// Does this constraint read ONLY its own row — never `at`?
    ///
    /// ⭐⭐⭐ IT IS A SPEED PROPERTY WORTH A MEASUREMENT. The sumcheck prover folds a SECOND copy of every
    /// committed column (the row-shifted `rot`) at every sample point of every round, and folds it again
    /// between rounds. For a row-LOCAL constraint that work is pure waste: nothing ever reads it. On the
    /// §BA/§BB aggregate's 7,856-column step table it is half the fold.
    ///
    /// ⛔ A FALSE CLAIM HERE IS LOUD, NOT SILENT. When this returns `true` the prover hands the
    /// constraint an `at` that PANICS, so a gate that claims row-locality and then reads a shifted
    /// column aborts the prove instead of quietly producing a proof over stale values. That is why the
    /// default is `false`: a gate opts IN, and the opt-in is checked the first time it is exercised.
    ///
    /// The test is mechanical — a gate is row-local exactly when its `eval` takes `_at`.
    fn is_row_local(&self) -> bool {
        false
    }

    /// Which columns this constraint reads through `at` — `None` meaning "assume all of them".
    ///
    /// ⭐ THE PROVER FOLDS A SECOND COPY OF EVERY COLUMN AT EVERY SAMPLE POINT so that `at` can answer.
    /// A row-SHIFTED constraint usually reads a handful: the sponge chain reads 35 of its 196 columns.
    /// Naming them turns that second fold from the table's full width into those few.
    ///
    /// ⛔ AN INCOMPLETE LIST IS LOUD, NOT SILENT: the prover's `at` panics on a column outside the
    /// declared set, so a constraint that grows a new shifted read and forgets to declare it aborts the
    /// prove rather than standing over a stale value. Default `None` keeps every existing gate correct.
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        None
    }
}

/// ⛔⛔⛔ THE TRACE ROW A GATE READS — AND THE ONE PLACE AN ATTACKER-CHOSEN WIDTH IS DISARMED.
///
/// THE BREAK THIS TYPE EXISTS FOR (lane E, MEASURED 2026-09-08). Every gate's [`AirConstraint::eval`]
/// indexes its row directly (`local[0] - local[1] - local[2]` is the whole production send gate), and
/// the row handed to it is `AirZerocheckProof::opened`, whose length is declared by whoever sent the
/// carrier. `pqspend_direct_verify_carrier` — documented "never panics" — therefore UNWOUND on two
/// different attacker-chosen shapes, both reachable off-lock at `/submit_pq_tx` (the submit RPC, rpc_http.rs:1270 until that arm was deleted 2026-09-08; the same verifier still rides the spend-validity, multi-spend and cover arms the door now asks) and
/// on the gossip path through `chain_object::admissible`:
///   * pin C-16: `shapes[0].1 = 64` against three shipped openings, killing the node inside
///     `sumcheck/src/layout/verifier.rs:132` (`assertion left == right failed  left: 64  right: 3`);
///   * pin C-17: a SELF-CONSISTENT `(nvars, width) = (0, 1)` carrier of ~100 bytes — every declared
///     count agreeing with every shipped vector, so no shape cross-check can catch it — killing the
///     node inside `SpendConservationGate::eval` itself at `local[1]`.
///
/// WHY THE FIX IS HERE AND NOT IN THE GATES. C-17 is not "one more shape to reject": the row really is
/// shorter than the gate reads, and only the AIR knows how wide it should be. Patching the ~60 gates
/// one at a time is exactly the per-panic-site patch this class refuses; putting the check on the ROW
/// puts it on the ONE object every gate touches, so a gate added tomorrow is covered without its
/// author ever knowing this break existed.
///
/// THE CONTRACT. An in-range read returns the column value, exactly as a slice did. An OUT-OF-RANGE
/// read returns a ZERO placeholder AND latches [`Row::out_of_range`]. The placeholder is never allowed
/// to decide anything: [`verify_air_zerocheck`] tests the latch after evaluating and REFUSES the
/// carrier, so a short row is a rejection and never an acceptance. That distinction is the whole
/// soundness argument — zero-padding a short row and then USING the value would let a party satisfy a
/// gate (a mint gate, say) with columns it never committed, which is a strictly worse break than the
/// panic. The latch is shared by sub-rows ([`Row::prefix`] / [`Row::suffix`]) so a composed gate's
/// halves report through the same channel.
///
/// COST — cons: none. 0 B persisted, 0 B added to any carrier, 0 B on the wire, 0 allocation: the
/// bundle's fields are untouched. The verifier gains ONE stack `Cell<bool>` (1 B) per zerocheck
/// evaluation and one predictable in-range branch per column read — 3 branches for the production send
/// gate, against the 3 KoalaBear⁴ multiplications on the same line. That is f(fixed trace width) and
/// never f(chain height, records, notes, blocks or peers), so it is 1 B of stack per verify forever,
/// with no per-block, per-record or per-peer term of any kind.
/// The out-of-range latch a [`Row`] writes to, and the ADDRESS of the first read that missed.
///
/// ⛔⛔⛔ A BARE `Cell<bool>` TOLD YOU A GATE AND ITS TRACE DISAGREE AND NOTHING ELSE. On a 600-column
/// row that is a day of bisection, and this tree hit the same message a dozen times in one session while
/// the digest widened: every stale hand-computed column offset surfaces here. The first out-of-range
/// index plus the row's real width name the constant that is stale, usually on sight — `column 62 of a
/// 58-column row` is a layout that stopped one field short.
///
/// COST: two extra `usize` cells of STACK per zerocheck evaluation and one predictable branch on a path
/// that is already taken only when something is wrong. Nothing persisted, nothing on the wire.
#[derive(Default)]
pub struct OobLatch {
    hit: core::cell::Cell<bool>,
    at: core::cell::Cell<usize>,
    width: core::cell::Cell<usize>,
}

impl OobLatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Record an out-of-range read. The FIRST one is kept: later ones are usually its consequence.
    pub fn record(&self, index: usize, width: usize) {
        if !self.hit.get() {
            self.at.set(index);
            self.width.set(width);
        }
        self.hit.set(true);
    }
    /// Did any read fall outside a row under this latch?
    #[must_use]
    pub fn hit(&self) -> bool {
        self.hit.get()
    }
    /// The address of the first miss, for a failure message.
    #[must_use]
    pub fn report(&self) -> String {
        if self.hit.get() {
            format!("column {} of a {}-column row", self.at.get(), self.width.get())
        } else {
            "no out-of-range read".to_string()
        }
    }
}

/// A trace row as a gate reads it. Generic over the field the cells live in (2026-09-29): the extension `Ea4` by default
/// — every existing gate reads `Row<'_>` unchanged — or the BASE field `Fa4` for a zerocheck's round 0, where the folded
/// rows are base-field at the integer sample points and a gate with a base path evaluates its laws sixteen times cheaper.
pub struct Row<'a, F = Ea4> {
    vals: &'a [F],
    oob: &'a OobLatch,
    /// The placeholder an out-of-range read borrows. Held by value so `Index` can hand out a
    /// reference tied to `&self` — never a promoted constant, so no lifetime games.
    zero: F,
}

impl<'a, F: Copy + PrimeCharacteristicRing> Row<'a, F> {
    /// Wrap one trace row with the out-of-range latch the caller will test afterwards.
    #[must_use]
    pub fn new(vals: &'a [F], oob: &'a OobLatch) -> Self {
        Self { vals, oob, zero: F::ZERO }
    }
    /// The latch this row records out-of-range reads on — for a gate that must build a sibling row (a lifted copy of
    /// a region, say) under the SAME latch, so no read escapes the caller's check.
    #[must_use]
    pub fn latch(&self) -> &'a OobLatch {
        self.oob
    }
    /// Columns actually present in this row.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vals.len()
    }
    /// True when the row carries no column at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vals.is_empty()
    }
    /// Did ANY read (here or in a sub-row) fall outside the row? A `true` means the carrier declared a
    /// narrower trace than its own AIR reads, and the caller must REFUSE it.
    #[must_use]
    pub fn out_of_range(&self) -> bool {
        self.oob.hit()
    }
    /// The first `n` columns — a composed gate's left half. A short row latches and yields what
    /// exists, so the composition refuses rather than unwinding on the split.
    #[must_use]
    pub fn prefix(&self, n: usize) -> Row<'a, F> {
        if n > self.vals.len() {
            self.oob.record(n, self.vals.len());
            return Row { vals: self.vals, oob: self.oob, zero: self.zero };
        }
        Row { vals: &self.vals[..n], oob: self.oob, zero: self.zero }
    }
    /// The columns from `n` on — a composed gate's right half. Same latching rule as [`Row::prefix`].
    #[must_use]
    pub fn suffix(&self, n: usize) -> Row<'a, F> {
        if n > self.vals.len() {
            self.oob.record(n, self.vals.len());
            return Row { vals: &self.vals[self.vals.len()..], oob: self.oob, zero: self.zero };
        }
        Row { vals: &self.vals[n..], oob: self.oob, zero: self.zero }
    }
}

/// Owns a [`Row`]'s out-of-range latch, for callers that build a row from LOCAL data (prover-side
/// helpers, gate unit tests) and have nowhere to keep the `Cell`. The latch is still readable, so a
/// caller that wants the loud behaviour asserts on [`RowGuard::out_of_range`] — it is not a way to
/// ignore the signal, only a way to own it.
#[derive(Default)]
pub struct RowGuard {
    oob: OobLatch,
}

impl RowGuard {
    #[must_use]
    pub fn new() -> Self {
        Self { oob: OobLatch::new() }
    }
    /// Borrow `vals` as a checked row under this guard's latch.
    #[must_use]
    pub fn row<'a>(&'a self, vals: &'a [Ea4]) -> Row<'a> {
        Row::new(vals, &self.oob)
    }
    /// Did any read fall outside the row?
    #[must_use]
    pub fn out_of_range(&self) -> bool {
        self.oob.hit()
    }
    /// Where it fell outside — see [`OobLatch::report`].
    #[must_use]
    pub fn report(&self) -> String {
        self.oob.report()
    }
}

impl<F> core::ops::Index<usize> for Row<'_, F> {
    type Output = F;
    fn index(&self, i: usize) -> &F {
        match self.vals.get(i) {
            Some(v) => v,
            // NEVER a panic on a wire-declared width, and NEVER a usable value either: the latch makes
            // the caller throw the whole evaluation away.
            None => {
                self.oob.record(i, self.vals.len());
                &self.zero
            }
        }
    }
}

/// The zerocheck proof: the per-round univariate evaluation vectors (each length `deg+2`) plus
/// the final folded column values at the sumcheck point `r` (the openings the WHIR PCS binds).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AirZerocheckProof {
    /// `round_evals[k]` = the round-`k` univariate evaluated at `0,1,…,deg+1`.
    pub round_evals: Vec<Vec<Ea4>>,
    /// Each committed column's MLE value at the final sumcheck point `r` (bound by WHIR opening).
    /// O1-FOOTPRINT-REVIEWED: by construction — one per column, at most AIR_DIRECT_MAX_WIDTH columns
    /// (the shape gate refuses wider); every field element is 4 wire bytes, so never f(witness).
    pub opened: Vec<Ea4>,
    /// The sumcheck point `r` the columns are opened at (Fiat-Shamir derived; recomputed by verify).
    pub r: Vec<Ea4>,
    /// Each committed column's next-row (`+1` row-ROTATION) MLE value at the sumcheck point `r`, i.e.
    /// `mle(rot, r)` where `rot[i] = col[(i+1) mod N]` — the next-row values a row-shifted (transition)
    /// constraint needs, folded in lockstep with the columns (the O(N) rot-fold, replacing the old
    /// O(2^{2n}) per-point `σ(x)` MLE eval). Row-local constraints leave these unused. MUST be WHIR-
    /// bound (the caller opens the committed rotation at `r`, mirroring `opened` at `r`) so a prover
    /// cannot forge the next-row values.
    /// O1-FOOTPRINT-REVIEWED: by construction — one per column, at most AIR_DIRECT_MAX_WIDTH columns.
    pub shifted_opened: Vec<Ea4>,
}

/// The trace-independent degree census a DEBUG prove runs on every gate (see [`prove_air_zerocheck`]): the gate along a
/// random line through two pseudo-random rows (and two pseudo-random next rows), the point's first coordinate `t`, the
/// other coordinates pseudo-random — so `is_first / is_last / is_trans` count as the degree-1 factors they are in a
/// sumcheck round. `degree(nvars) + 4` points; the (degree+1)-th forward differences of a polynomial within the
/// declaration vanish. A gate that reads past `width` columns is refused, loudly. Deterministic: the rows are a fixed
/// mix of the table's shape, so a refusal reproduces run to run.
///
/// ROOT-LAYER: the declaration `degree()` is consumed HERE, by the prover that sizes every round polynomial from it — so
///   this is where a wrong declaration is caught, before it shapes a proof; a per-AIR pin would check one gate, this
///   checks every gate the crate ever proves.
/// MEASURED: the DSOL CPU relation carried a degree-11 law declared 8 through every pin (the excess vanished on the traces
///   proven) until the continuations pin's continued segment failed to verify; the per-law census then measured 11.
/// MUST-STAY-GREEN: every debug prove in the crate (the census asserts ≤ declared for each gate proven in debug).
pub(crate) fn debug_degree_census<C: AirConstraint>(cols: &[Vec<Fa4>], constraint: &C, nvars: usize, row_local: bool, shifted: &Option<Vec<usize>>) {
    let width = cols.len();
    let declared = constraint.degree(nvars);
    let pts = declared + 4;
    let mix = |seed: u64, i: usize| -> u64 {
        (seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add((i as u64).wrapping_add(1).wrapping_mul(0x632b_e59b_d9b4_e019))).wrapping_mul(0xbf58_476d_1ce4_e5b9) >> 33
    };
    let rnd = |seed: u64, n: usize| -> Vec<Ea4> { (0..n).map(|i| Ea4::from_u64(mix(seed, i))).collect() };
    let (a, b, a2, b2) = (rnd(11, width), rnd(12, width), rnd(13, width), rnd(14, width));
    let xr = rnd(15, nvars);
    let oob = OobLatch::new();
    let mut vals: Vec<Ea4> = Vec::with_capacity(pts);
    // the gate's per-law residual lists at every point, when it exposes them (`residuals()` beyond the default one)
    let mut per_law: Vec<Vec<Ea4>> = Vec::with_capacity(pts);
    for tt in 0..pts {
        // consecutive integers from 2, so neither `is_first` (t = 1) nor `is_last` (t = 0) vanishes at a sample
        let tv = Ea4::from_u64(tt as u64 + 2);
        let local: Vec<Ea4> = (0..width).map(|c| a[c] + tv * (b[c] - a[c])).collect();
        let next: Vec<Ea4> = (0..width).map(|c| a2[c] + tv * (b2[c] - a2[c])).collect();
        let mut x = xr.clone();
        x[0] = tv;
        let at = |c: usize, _p: &[Ea4]| -> Ea4 {
            assert!(!row_local, "⛔ a constraint claiming `is_row_local()` read shifted column {c}");
            assert!(
                shifted.as_ref().is_none_or(|cs| cs.contains(&c)),
                "⛔ shifted column {c} was read but not declared by `shifted_cols()`"
            );
            *next.get(c).expect("⛔ the gate read a shifted column past its declared width during the degree census")
        };
        let row = Row::new(&local, &oob);
        vals.push(constraint.eval(&row, &at, &x));
        per_law.push(constraint.residuals(&row, &at, &x));
    }
    assert!(!oob.hit(), "⛔ the gate read past its declared width during the degree census — see `OobLatch`");
    // the first level of forward differences that vanishes names the degree
    let degree_of = |vals: &[Ea4]| -> usize {
        let mut d: Vec<Ea4> = vals.to_vec();
        for level in 0..pts {
            if d.iter().all(|v| *v == Ea4::ZERO) {
                return level.saturating_sub(1);
            }
            d = d.windows(2).map(|w| w[1] - w[0]).collect();
        }
        pts // never vanished ⇒ at least pts − 1
    };
    let measured = degree_of(&vals);
    // an OVER-declaration is not a defect but a cost: the zerocheck samples declared + 2 points per round on every row,
    // so a gate declaring 17 with a measured 6 pays 19 evaluations where 8 would do — reported so it can be lowered
    if measured < declared {
        eprintln!(
            "[degree-census] {}: declared degree {declared}, MEASURED {measured} (width {width}, {nvars} vars) — {} sample points per round where {} would do",
            core::any::type_name::<C>(),
            declared + 2,
            measured + 2
        );
    }
    assert!(
        measured <= declared,
        "⛔ DEGREE CENSUS: the gate's per-variable degree measures {measured} against its declared `degree()` = {declared} \
         (width {width}, {nvars} variables) — the zerocheck samples degree + 2 points per round, so an honest proof of this \
         gate mis-interpolates on some traces; count every factor of the offending law, commit a product as a column or \
         raise the declaration"
    );
    // PER LAW, for a gate that lists its residuals: each law within the declaration (asserted — a law above it is a defect
    // whatever the statement), and the laws that are the zero polynomial along this line REPORTED by index (not refused:
    // a statement-gated law can be zero by design under one gate instance and live under another — the DSOL relation's
    // fresh/continued mirrors are exactly that; a law zero under EVERY instance constrains nothing and is a hole).
    let n_laws = per_law[0].len();
    if n_laws > 1 && per_law.iter().all(|v| v.len() == n_laws) {
        let mut zero_laws: Vec<usize> = Vec::new();
        for j in 0..n_laws {
            let lv: Vec<Ea4> = per_law.iter().map(|v| v[j]).collect();
            if lv.iter().all(|v| *v == Ea4::ZERO) {
                zero_laws.push(j);
                continue;
            }
            let dj = degree_of(&lv);
            assert!(
                dj <= declared,
                "⛔ DEGREE CENSUS: law #{j} of {n_laws} ({}) measures degree {dj} against the declared {declared}",
                core::any::type_name::<C>()
            );
        }
        if !zero_laws.is_empty() {
            eprintln!(
                "[degree-census] {}: {} of {n_laws} listed laws are the zero polynomial along the census line (indices {:?}) — zero by a gate of this statement, or constraining nothing; the gate's own pins decide which",
                core::any::type_name::<C>(),
                zero_laws.len(),
                &zero_laws[..zero_laws.len().min(24)]
            );
        }
    }
}

/// ⛔ THE FREE-WITNESS CENSUS a DEBUG prove runs on every gate (the security pillar, 2026-09-29): for each column, take
/// the first row where the honest trace holds a non-zero value (a LIVE cell — a value the prover actually computed),
/// nudge it by one, and re-evaluate the gate on that row and on the row before it (the two rows whose laws can read the
/// cell, locally or as a next-row read). If neither residual moves, the value was never constrained: a FREE WITNESS the
/// prover could have set to anything. That is the class behind the bond transition delta, the peg-in deposit and the
/// unbound reserve carrier found this month — each had a passing tamper pin, because a tamper pin refutes the attacks
/// its author imagined and a census asks about every column. Rows whose honest residual is already non-zero are
/// skipped (forgery pins prove unsatisfied traces on purpose; the census is not a satisfaction check). All-zero columns
/// are not tested (nothing live to nudge) and are counted. Reported by index; REFUSED when the gate declares its free
/// columns ([`AirConstraint::free_columns`]) and a free column is not among them.
///
/// LIMIT, STATED: this census asks whether some law READS the cell, not whether the laws DETERMINE it. A column a law
/// constrains but leaves a free choice — a boolean the prover picks (the sparse carriers' key bits `dir`, bound to no
/// statement value), a value bound only modulo p (DB-362's carries) — passes here. That class is the statement-binding
/// review (§9.6 questions 2 and 3: what verifies this value, and on THIS path) and the range/alias rule; it is the next
/// census to build when a mechanical form exists.
///
/// ROOT-LAYER: the prover is where every committed column becomes a witness the verifier will trust through a
///   commitment; a value no law binds is decided here and nowhere later. MEASURED: three free-witness holes in one
///   month, each found by a hand census after its tamper pin passed. MUST-STAY-GREEN: every debug prove in the crate.
pub(crate) fn debug_free_witness_census<C: AirConstraint + Sync>(cols: &[Vec<Fa4>], constraint: &C, nvars: usize, row_local: bool, shifted: &Option<Vec<usize>>) {
    let width = cols.len();
    if width == 0 || cols[0].is_empty() {
        return;
    }
    let n_rows = cols[0].len();
    // ⛔ THE CENSUS IS O(width²) — MEASURED 2026-10-03: NullifierBlockGate (46,095 columns) ran 10+ min single-threaded
    // inside the one-sweep scanner's circuit pass (4 full gate evaluations per column, each rebuilding two width-wide
    // rows). Two changes, the verdict unchanged:
    //   (1) the HONEST evaluation at a row depends only on the row, so it is computed once per row (`honest`), not
    //       twice per column;
    //   (2) columns are independent, so they run in parallel, each with its own out-of-range latch (the latch is a
    //       `Cell`), and every latch hit is still reported.
    // ROOT-LAYER: the census is the instrument; the gate and the prover are untouched.
    // MEASURED: the 46,095-column NullifierBlockGate census before → 10+ min on one core.
    // MUST-STAY-GREEN: every census pin (a free column is still found, a declared one still allowed, an OOB read still
    // refused).
    // the gate at row `r` of `cols` with cell (c0, r0) nudged by one wherever it is read (locally or as the next row)
    let eval_at = |r: usize, nudge: Option<(usize, usize)>, oob: &OobLatch| -> Ea4 {
        let cell = |c: usize, row: usize| -> Ea4 {
            let v = Ea4::from(cols[c][row]);
            match nudge {
                Some((c0, r0)) if c0 == c && r0 == row => v + Ea4::ONE,
                _ => v,
            }
        };
        let local: Vec<Ea4> = (0..width).map(|c| cell(c, r)).collect();
        let nxt = (r + 1) % n_rows;
        let next: Vec<Ea4> = (0..width).map(|c| cell(c, nxt)).collect();
        let x: Vec<Ea4> = (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }).collect();
        let at = |c: usize, _p: &[Ea4]| -> Ea4 {
            assert!(!row_local, "⛔ a constraint claiming `is_row_local()` read shifted column {c}");
            assert!(shifted.as_ref().is_none_or(|cs| cs.contains(&c)), "⛔ shifted column {c} was read but not declared by `shifted_cols()`");
            *next.get(c).expect("⛔ the gate read a shifted column past its declared width during the free-witness census")
        };
        constraint.eval(&Row::new(&local, oob), &at, &x)
    };
    // (1) the honest verdict per row — (satisfied, read out of range) — computed at most once
    let honest: Vec<std::sync::OnceLock<(bool, bool)>> = (0..n_rows).map(|_| std::sync::OnceLock::new()).collect();
    let honest_ok = |r: usize| -> (bool, bool) {
        *honest[r].get_or_init(|| {
            let oob = OobLatch::new();
            let zero = eval_at(r, None, &oob) == Ea4::ZERO;
            (zero, oob.hit())
        })
    };
    // the live cell is looked for in the FIRST HALF of the table first: a blinded carrier keeps its data in the half
    // where the wrapper's selector is on and random masks in the other, and padding replicates at the end — a column
    // live only in the upper half is not tested here (nothing the gate is asked about lives there) and is counted
    let half = n_rows / 2;
    // per column: (free?, untested?, upper-only?, read out of range?)
    let verdicts: Vec<(bool, bool, bool, bool)> = (0..width)
        .into_par_iter()
        .map(|c| {
            let first_live = cols[c].iter().position(|v| *v != Fa4::ZERO);
            let Some(r_any) = first_live else {
                return (false, true, false, false);
            };
            if r_any >= half.max(1) {
                return (false, false, true, false);
            }
            let r0 = r_any;
            let prev = (r0 + n_rows - 1) % n_rows;
            // only a row the honest trace satisfies can witness a free cell
            let (ok_r0, oob_r0) = honest_ok(r0);
            let (ok_prev, oob_prev) = honest_ok(prev);
            if !ok_r0 || !ok_prev {
                return (false, false, false, oob_r0 || oob_prev);
            }
            let oob = OobLatch::new();
            let nudged = Some((c, r0));
            let free = eval_at(r0, nudged, &oob) == Ea4::ZERO && eval_at(prev, nudged, &oob) == Ea4::ZERO;
            (free, false, false, oob_r0 || oob_prev || oob.hit())
        })
        .collect();
    let free: Vec<usize> = verdicts.iter().enumerate().filter(|(_, v)| v.0).map(|(c, _)| c).collect();
    let untested = verdicts.iter().filter(|v| v.1).count();
    let upper_only = verdicts.iter().filter(|v| v.2).count();
    let oob_hit = verdicts.iter().any(|v| v.3);
    assert!(!oob_hit, "⛔ the gate read past its declared width during the free-witness census — see `OobLatch`");
    if free.is_empty() {
        return;
    }
    match constraint.free_columns() {
        Some(declared) => {
            let undeclared: Vec<usize> = free.iter().copied().filter(|c| !declared.contains(c)).collect();
            assert!(
                undeclared.is_empty(),
                "⛔ FREE-WITNESS CENSUS: {} ({} columns, {} rows): {} column(s) hold a live value no law reads — a witness the prover chose — and the gate does not declare them free: {:?}",
                core::any::type_name::<C>(),
                width,
                n_rows,
                undeclared.len(),
                &undeclared[..undeclared.len().min(32)]
            );
        }
        None => {
            // the report names the test whose trace produced it (a test runs on a thread named after it)
            let who = match std::thread::current().name() {
                Some(n) => n.to_owned(),
                None => String::from("(unnamed thread)"),
            };
            eprintln!(
                "[free-witness-census] {} ({} columns, {} rows; {} all-zero columns and {} upper-half-only columns untested) in `{who}`: {} column(s) hold a live value no law reads on this trace — declare them in `free_columns()` or bind them: {:?}",
                core::any::type_name::<C>(),
                width,
                n_rows,
                untested,
                upper_only,
                free.len(),
                &free[..free.len().min(48)]
            );
        }
    }
}

/// ⛔ THE DECORATIVE-BLOCK CENSUS (2026-09-29 21:0x) — a third class the other two censuses cannot see. The sparse
/// nullifier chains laid honest Poseidon2 blocks whose OUTPUT no law read: the input welds held, the permutation inside
/// was valid, and `acc_out` — read by the chain and boundary laws, so never "free" to the free-witness census — was a
/// cell the prover chose. Both chains were decorative and any transition proved
/// (`nf_sparse_air::db353_a_forged_accumulator_beside_an_honest_permutation_is_refused`, measured RED first).
///
/// The question here is STRUCTURAL and needs no trace row: record the base of every permutation block the gate
/// evaluates (`pow_pq_air::census_record_perm_blocks`), then, with the permutation's own constraints MASKED
/// (`census_with_perm_tape_masked`), evaluate the gate at a random row, random next row and random point, and nudge each
/// block's output lanes in the row and in the next row. A law that reads the lane has a non-zero generic coefficient at
/// a random point (Schwartz–Zippel), so the value moves; a lane only the permutation reads leaves it unchanged, and the
/// block is decorative — REFUSED with its base and lanes. Every `DIGEST_LANES` output lane must be read: a compression
/// consumes exactly those, a sponge all of them. Coverage: blocks evaluated through `pow_pq_air::push_perm_residuals`
/// (every AIR in this crate but the DSOL relation's symbolic block, which welds its output in its own law census).
pub(crate) fn debug_decorative_block_census<C: AirConstraint>(cols: &[Vec<Fa4>], constraint: &C, nvars: usize, row_local: bool, shifted: &Option<Vec<usize>>) {
    let width = cols.len();
    if width == 0 {
        return;
    }
    let mix = |seed: u64, i: usize| -> u64 {
        (seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add((i as u64).wrapping_add(1).wrapping_mul(0x632b_e59b_d9b4_e019))).wrapping_mul(0xbf58_476d_1ce4_e5b9) >> 33
    };
    let rnd = |seed: u64, n: usize| -> Vec<Ea4> { (0..n).map(|i| Ea4::from_u64(mix(seed, i))).collect() };
    let local0 = rnd(21, width);
    let next0 = rnd(22, width);
    let x = rnd(23, nvars);
    let oob = OobLatch::new();
    let eval = |local: &[Ea4], next: &[Ea4]| -> Ea4 {
        let at = |c: usize, _p: &[Ea4]| -> Ea4 {
            assert!(!row_local, "⛔ a constraint claiming `is_row_local()` read shifted column {c}");
            assert!(shifted.as_ref().is_none_or(|cs| cs.contains(&c)), "⛔ shifted column {c} was read but not declared by `shifted_cols()`");
            *next.get(c).expect("⛔ the gate read a shifted column past its declared width during the decorative-block census")
        };
        constraint.eval(&Row::new(local, &oob), &at, &x)
    };
    // 1. the blocks this gate evaluates, from one plain evaluation — each with its output-lane columns in THIS table's
    //    coordinates (an embedded gate's blocks arrive mapped through `pow_pq_air::census_with_frame`)
    let (_, mut blocks) = crate::pow_pq_air::census_record_perm_blocks(|| eval(&local0, &next0));
    blocks.sort_unstable();
    blocks.dedup();
    if blocks.is_empty() {
        return;
    }
    // 2. with the permutation constraints masked, does any other law read each block's output lanes?
    let decorative: Vec<(usize, Vec<usize>)> = crate::pow_pq_air::census_with_perm_tape_masked(|| {
        let base_v = eval(&local0, &next0);
        let mut found = Vec::new();
        for (b, lanes) in &blocks {
            let b = *b;
            let mut unread = Vec::new();
            for (c, &col) in lanes.iter().enumerate() {
                if col >= width {
                    unread.push(c);
                    continue;
                }
                let mut l = local0.clone();
                l[col] += Ea4::ONE;
                let mut n = next0.clone();
                n[col] += Ea4::ONE;
                if eval(&l, &next0) == base_v && eval(&local0, &n) == base_v {
                    unread.push(c);
                }
            }
            if !unread.is_empty() {
                found.push((b, unread));
            }
        }
        found
    });
    assert!(!oob.hit(), "⛔ the gate read past its declared width during the decorative-block census — see `OobLatch`");
    assert!(
        decorative.is_empty(),
        "⛔ DECORATIVE-BLOCK CENSUS: {} ({} columns): {} permutation block(s) whose OUTPUT lanes no law outside the permutation reads — an honest permutation with a FREE result, the class that let the sparse nullifier chains prove any transition (2026-09-29). (block base, unread output lanes): {:?}. Weld the block's output to the cell the gate's laws read, as `push_chain_residuals` does.",
        core::any::type_name::<C>(),
        width,
        decorative.len(),
        decorative
    );
}

/// ⛔ TEST BUILDS ONLY — the reference prover: every round sampled at every point, in the extension (no eq factor, no base round 0,
/// no skipped hypercube points). Byte-identity with it is what the eq factor and the base paths are pinned against.
#[cfg(test)]
pub(crate) static DIRECT_SAMPLING_FOR_TEST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
fn direct_sampling() -> bool {
    DIRECT_SAMPLING_FOR_TEST.load(std::sync::atomic::Ordering::SeqCst)
}
#[cfg(not(test))]
const fn direct_sampling() -> bool {
    false
}

/// PROVE the AIR zerocheck `Σ_x eq(z,x)·C(cols(x),cols(σx)) = 0`. `cols` are the committed MLE
/// columns (base-field evals, length `2^n`). `z` is the FS zerocheck point (drawn from `ch`).
/// Returns the round polynomials + the reduced openings. Fiat-Shamir challenges are drawn from
/// `ch` so the transcript binds prover→verifier (no trusted point).
#[must_use]
pub fn prove_air_zerocheck<C: AirConstraint + Sync>(
    cols: &[Vec<Fa4>],
    constraint: &C,
    z: &[Ea4],
    ch: &mut Chl,
) -> AirZerocheckProof {
    // Test-only, env-gated: the free-cell census sees the exact trace and gate every prover proves.
    #[cfg(test)]
    crate::free_cell_census::observe(cols, constraint);
    #[cfg(test)]
    crate::mutation_census::observe(cols, constraint);
    let nvars = z.len();
    let per_evals = constraint.degree(nvars) + 2; // univariate degree deg+1 ⇒ deg+2 sample points.
    // Working (folded) EF copies of eq, each column, and each column's +1 ROW-ROTATION.
    //
    // ROT-FOLD — fixes the O(2^{2n}) TIME blowup (a blowup on the time axis violates the O(1)/no-blowup
    // decider pillar). A row-shifted (transition) constraint reads the "next row" value via `at`. The old
    // code returned it as `mle_eval(orig[c], σ(x))` — re-evaluating the FULL 2^n-entry MLE at the point-
    // shift σ(x) for EVERY hypercube point, EVERY round → 2^n · 2^n = O(2^{2n}), quadratic in trace
    // height (measured: ×4 height ⇒ ×16 time). It also forced the per-round degree to nvars+1 (the σ
    // carry-chain).
    //
    // The next row is simply the +1 row-ROTATION of each column: rot[c][i] = col[c][(i+1) mod N]. On the
    // hypercube this AGREES with `col(σ(x))` (`cyclic_shift_sigma` maps row i's point → row i+1's, MSB-
    // first +1 carry), but rot is a PLAIN MULTILINEAR table, so it folds in lockstep with the columns:
    // `at` becomes an O(1) folded-table read instead of an O(2^n) MLE eval, and the whole zerocheck is
    // O(N). The row-shift term is now a genuine multilinear column (degree 1), not the degree-(nvars+1)
    // point-shift. `shifted_opened = mle(rot, r)`; the caller binds it by opening the committed rotation
    // at r (mirrors `opened = mle(col, r)`).
    // ⭐ link 80 (2026-10-21): the lift into the extension, the rotation and every round's fold below run one column per
    // worker. A column's lift and fold read only that column, and an indexed `collect` keeps column order, so the tables
    // are the serial tables value for value (`a_parallel_prove_is_byte_identical_to_a_one_thread_prove`). MEASURED
    // (`sample`, the 256-insert band slice): these serial per-column loops were the zerocheck's single-threaded share
    // (~320 of its 2,059 samples, the rest already parallel).
    let mut eq_curr = eq_z_hypercube(z);
    let mut col_curr: Vec<Vec<Ea4>> = cols
        .par_iter()
        .map(|c| c.iter().map(|&v| Ea4::from(v)).collect())
        .collect();
    let mut rot_curr: Vec<Vec<Ea4>> = cols
        .par_iter()
        .map(|c| {
            let n = c.len();
            (0..n).map(|i| Ea4::from(c[(i + 1) % n])).collect()
        })
        .collect();

    // The prove-side out-of-range latch (see [`Row`]). It must stay FALSE for the whole prove: the
    // rows here are built from `cols`, so a gate reading past the trace is a local programming error,
    // and it is asserted below rather than silently zero-filled.
    let oob = OobLatch::new();
    let mut round_evals: Vec<Vec<Ea4>> = Vec::with_capacity(nvars);
    let mut r_vec: Vec<Ea4> = Vec::with_capacity(nvars);
    // The round polynomial's known sum: zero at round 0, then the last polynomial at the last challenge (the eq factor below).
    let mut claim = Ea4::ZERO;
    // ⭐⭐⭐ THE ROUND BUFFERS ARE HOISTED, AND THAT IS A MEASURED 10-SECOND PROBLEM, NOT A STYLE POINT.
    //
    // These three vectors used to be built INSIDE the `(j, i)` loop — one `collect()` each, per sample
    // point, per row. `local` and `next` are each one `Ea4` per committed COLUMN, and the §BA/§BB
    // aggregate's step table is 7,856 columns wide: ~125 KB allocated, filled and dropped per inner
    // iteration, `28 x 255 = 7,140` times for that table alone. The allocator, not the field
    // arithmetic, was a large part of the 10.8 s the 256-slot aggregate took to prove.
    //
    // Refilling in place changes no value the prover computes — same reads, same order, same sums.
    // ⭐ ROW-LOCAL ⇒ THE ROTATION IS NEVER FOLDED AT A SAMPLE POINT. See `AirConstraint::is_row_local`.
    //
    // ⛔ THE ROTATION COLUMNS THEMSELVES STAY. They are folded once per ROUND and their final values are
    // the proof's `shifted_opened`, which the verifier re-binds — dropping them changes the wire shape,
    // and a first cut that cleared them turned two aggregate gates red. What is skipped is the per-SAMPLE
    // -POINT refill: `per_evals x half` fills of a `width`-wide buffer per round, against `nvars` folds
    // of the same columns. The inner fill is the dominant term, and for a row-local gate nothing reads it.
    let row_local = constraint.is_row_local();
    // Which shifted columns must actually be folded at each sample point. `None` ⇒ all of them.
    let shifted: Option<Vec<usize>> = if row_local { Some(Vec::new()) } else { constraint.shifted_cols() };
    // Round 0 in the base field, for a gate that has that path (see the round loop).
    let use_base = constraint.has_base_eval() && !direct_sampling();
    // ⛔ THE DECLARED DEGREE IS MEASURED GENERICALLY (DEBUG builds, 2026-09-29): the per-round assert below sees only the
    // excess a particular trace exposes (the DSOL relation carried a degree-11 law declared 8 through every pin until one
    // trace showed it). This check is trace-independent: the gate is evaluated along a random line — the row, its next row
    // and the point all move linearly in `t` — and the univariate's degree is read off its forward differences; a gate
    // above its declaration is refused here, at the first debug prove of ANY AIR in the crate, with the measured number.
    // ⭐ STRICT MODE IN ANY PROFILE (2026-09-29): the two censuses, the per-round degree assert, the undeclared-shifted-read
    // assert and the un-skipped round-0 hypercube points are the DEBUG profile's checks; `MONEROUSD_PROVER_ASSERTS` turns
    // them on in a release build too. MEASURED why: a debug prove of the 2^16-row keyed nullifier carrier took 186 s
    // against ~4 s in release (a 45× split), and a debug census pin spent 579 of its 583 s building its fixture — the
    // instruments themselves are seconds. With strict release, the debug profile is no longer needed to run them.
    let strict = cfg!(debug_assertions) || std::env::var_os("MONEROUSD_PROVER_ASSERTS").is_some();
    // ⭐ THE EQ FACTOR (2026-11-03, BORROWED: Gruen, eprint 2024/108 §3, also Dao–Thaler). `eq(z,·)` is linear in the round's variable, so
    // the round polynomial is `h(X) = l(X)·q(X)` with `l(X) = (1−z_k)(1−X) + z_k·X` and `q(X) = Σ_i w_i·C(row_i(X))`,
    // `w_i = eq[i] + eq[half+i]`. `q` has degree `deg`, and `h(0) + h(1) = claim` hands us `q(1)`, so a round samples `q` at `deg`
    // points instead of `h` at `deg + 2`. The polynomial is the same polynomial, so the transcript and the proof are the same bytes
    // (pin `the_eq_factor_prover_lays_the_bytes_of_direct_sampling`). Strict builds keep sampling directly: they are the reference.
    let eq_factor = !strict && !direct_sampling();
    // ⛔ THE SWEEP'S ONCE-PER-SHAPE MODE (user 2026-10-03: the whole ecosystem "checked quickly and ceaply"). A strict run
    // of the crate's 602 tests re-ran the three censuses on EVERY prove. `MONEROUSD_CENSUS_ONCE_PER_SHAPE` censuses each
    // (gate type, column count, nvars) ONCE per process, and the sweep states exactly that claim ("every gate censused on
    // at least one honest trace"). Unset, every prove is censused (the thorough mode). The per-round asserts below run on
    // every prove either way.
    // ROOT-LAYER: the census call site is the one place every prove of every gate passes through; the de-duplication
    //   lives with it, so no gate can be proven without at least its first census.
    // MEASURED: 2026-10-03 strict run — 520 censuses of LogupKeyfoldConstraint, 32 of 602 tests in 28 min (~9 h suite).
    // MUST-STAY-GREEN: every strict pin (unset ⇒ unchanged behaviour); a poisoned lock censuses (never skips).
    let census_now = strict && {
        if std::env::var_os("MONEROUSD_CENSUS_ONCE_PER_SHAPE").is_some() {
            static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
            let key = format!("{}|{}|{}", std::any::type_name::<C>(), cols.len(), nvars);
            match SEEN.get_or_init(Default::default).lock() {
                Ok(mut seen) => seen.insert(key),
                Err(_poisoned) => true,
            }
        } else {
            true
        }
    };
    if census_now {
        debug_degree_census(cols, constraint, nvars, row_local, &shifted);
        debug_free_witness_census(cols, constraint, nvars, row_local, &shifted);
        debug_decorative_block_census(cols, constraint, nvars, row_local, &shifted);
        // ⛔⛔⛔ THE ONE-SWEEP HOLE SCANNER (user 2026-10-03): name the gate the three censuses just passed, so
        // `scratchpad/holes.sh` can compare the gates CENSUSED in a strict run against every `AirConstraint` in the crate.
        // A gate no strict run ever proves is a circuit hole that no census looked at. An instrument line only.
        eprintln!("[gate-census] PASSED degree + free-witness + decorative: {}", std::any::type_name::<C>());
    }
    let _t_zc = std::time::Instant::now();
    let _dbg = std::env::var("MONEROUSD_ZC_PROFILE").is_ok();
    // `MONEROUSD_PROVE_PROGRESS`: a long (debug-profile) prove is never SILENT — the test-progress watchdog reaps a test
    // that prints nothing for nine minutes (user 2026-07-29), and a 2^16-row debug zerocheck legitimately runs longer than
    // that. One line per round once this prove has run `PROGRESS_EVERY_MS`, at most one per `PROGRESS_EVERY_MS` after:
    // ≥ 54 lines inside the watchdog's window, and nothing from a sub-second prove. MEASURED (link 23): one line per round
    // of EVERY prove printed 120,058 lines into one 7-seed simulator log — noise burying the journey's own lines.
    // Output only; no value the prover computes changes.
    const PROGRESS_EVERY_MS: u128 = 10_000;
    let progress = std::env::var_os("MONEROUSD_PROVE_PROGRESS").is_some();
    let mut last_progress_ms: u128 = 0;
    for round in 0..nvars {
        let half = eq_curr.len() / 2;
        if progress && _t_zc.elapsed().as_millis() >= last_progress_ms + PROGRESS_EVERY_MS {
            last_progress_ms = _t_zc.elapsed().as_millis();
            eprintln!("[zerocheck-progress] round {round}/{nvars} at {last_progress_ms} ms (rows {})", 2 * half);
        }
        // DEBUG builds sample ONE extra point per round and assert the declared degree below.
        let mut h = vec![Ea4::ZERO; per_evals + usize::from(strict)];
        // the eq factor: `q(1)` comes from the claim unless `z_k` is zero (then `l(1)` is, and the sample is taken)
        let z_k = z[round];
        let derive_one = eq_factor && round > 0 && z_k != Ea4::ZERO;
        // ⭐⭐ ONE PASS PER ROW FOR EVERY SAMPLE POINT (speed lane, 2026-11-09). The per-point loop below folds EVERY column of
        // EVERY row afresh at each sample point — `c[i]·(1−x) + c[half+i]·x`, two extension multiplies per column — so a round
        // costs `points × width × 2` multiplies before the gate is even read. MEASURED (real producer, round 18 binaries, 2026-11-09,
        // `[light-zc]`): the joined ledger's zerocheck is its prove's largest phase (7.2–7.4 s of 13.9–15.9 s), and its short wide
        // tables cost 6–13× more per cell than the band's tall narrow one (2^7 × 3,726 cols: 1.6 µs/cell; 2^14 × 437: 0.12 µs/cell).
        // Here each row is read ONCE per round: its point-0 value `c[i]` and its step `c[half+i] − c[i]`, then each next point
        // is one addition per column (`c[i] + x·Δ` is `c[i]·(1−x) + c[half+i]·x`, exactly, in the field). The same points are
        // sampled and every sum is the same field sum, so the round polynomials — the transcript and the proof — are the same
        // bytes (pin `the_eq_factor_prover_lays_the_bytes_of_direct_sampling`, whose reference is the per-point loop below).
        // BORROWED: the one-pass round evaluation of sumcheck provers (Plonky3's and Jolt's sumcheck evaluate all of a round's
        // points from one read of each pair of rows). Only the eq-factor (release) path takes it: strict and direct-sampling
        // builds keep the per-point loop as the reference, and round 0's base-field path keeps its own loop.
        // MEASURED on real nodes 2026-11-10 (lane speed, rig localnet-v, one chain, a restart between windows, 480 s each, the
        // two nodes using 1.37 and 1.35 cores): this one-pass round against the per-point loop — the ledger's zerocheck 24.0 s
        // against 46.2 s of wall time per proof, 44 against 54 core-seconds per block, 1.9 against 1.5 blocks a minute.
        let one_pass = eq_factor && !(round == 0 && use_base);
        if one_pass {
            let pts: Vec<usize> = (0..per_evals).filter(|&j| !(j + 1 == per_evals || (j == 1 && derive_one) || (round == 0 && j < 2))).collect();
            let width = col_curr.len();
            let rot_w = rot_curr.len();
            let head: Vec<Ea4> = r_vec[..round].to_vec();
            let sums: Vec<Ea4> = (0..half)
                .into_par_iter()
                .fold(
                    || {
                        let mut xp = vec![Ea4::ZERO; nvars];
                        xp[..round].copy_from_slice(&head);
                        (vec![Ea4::ZERO; width], vec![Ea4::ZERO; width], vec![Ea4::ZERO; rot_w], vec![Ea4::ZERO; rot_w], xp, OobLatch::new(), vec![Ea4::ZERO; per_evals])
                    },
                    |(mut cur, mut step, mut ncur, mut nstep, mut x_pt, oob, mut acc), i| {
                        // the eq factor's weight is the row pair's, the same at every point (Gruen §3)
                        let eq_at = eq_curr[i] + eq_curr[half + i];
                        for ((b, s), c) in cur.iter_mut().zip(step.iter_mut()).zip(col_curr.iter()) {
                            *b = c[i];
                            *s = c[half + i] - c[i];
                        }
                        match &shifted {
                            Some(cs) => {
                                for &c in cs {
                                    ncur[c] = rot_curr[c][i];
                                    nstep[c] = rot_curr[c][half + i] - rot_curr[c][i];
                                }
                            }
                            None => {
                                for ((b, s), c) in ncur.iter_mut().zip(nstep.iter_mut()).zip(rot_curr.iter()) {
                                    *b = c[i];
                                    *s = c[half + i] - c[i];
                                }
                            }
                        }
                        for k in (round + 1)..nvars {
                            let bit = (i >> (nvars - 1 - k)) & 1;
                            x_pt[k] = if bit == 1 { Ea4::ONE } else { Ea4::ZERO };
                        }
                        let mut at_j = 0usize;
                        for &j in &pts {
                            while at_j < j {
                                for (b, s) in cur.iter_mut().zip(step.iter()) {
                                    *b += *s;
                                }
                                match &shifted {
                                    Some(cs) => {
                                        for &c in cs {
                                            ncur[c] += nstep[c];
                                        }
                                    }
                                    None => {
                                        for (b, s) in ncur.iter_mut().zip(nstep.iter()) {
                                            *b += *s;
                                        }
                                    }
                                }
                                at_j += 1;
                            }
                            x_pt[round] = Ea4::from(Fa4::from_u64(j as u64));
                            let next: &[Ea4] = &ncur;
                            let at = |c: usize, _p: &[Ea4]| -> Ea4 {
                                assert!(
                                    !row_local,
                                    "⛔ a constraint claiming `is_row_local()` read shifted column {c} — the \
                                     rotation was not built, so this proof would have stood over stale values"
                                );
                                next[c]
                            };
                            let v = constraint.eval(&Row::new(&cur, &oob), &at, &x_pt);
                            assert!(!oob.hit(), "⛔ a gate read past its own trace during prove — see `OobLatch`");
                            acc[j] += eq_at * v;
                        }
                        (cur, step, ncur, nstep, x_pt, oob, acc)
                    },
                )
                .map(|t| t.6)
                .reduce(
                    || vec![Ea4::ZERO; per_evals],
                    |mut a, b| {
                        for (x, y) in a.iter_mut().zip(b) {
                            *x += y;
                        }
                        a
                    },
                );
            for &j in &pts {
                h[j] = sums[j];
            }
        }
        for (j, hj) in h.iter_mut().enumerate() {
            if one_pass {
                break;
            }
            if eq_factor && (j + 1 == per_evals || (j == 1 && derive_one)) {
                continue;
            }
            // ⭐ ROUND 0, SAMPLE POINTS 0 AND 1 ARE THE HYPERCUBE ITSELF (2026-09-29): the fold `c[i]·(1−x) + c[half+i]·x`
            // at x = 0 is row i and at x = 1 row half+i, and the rotation is each row's true successor — so the
            // constraint there is the constraint ON THE TRACE, zero on every row of a satisfied trace by the very claim
            // the zerocheck proves. An honest prover's h[0] and h[1] are therefore exactly zero and need no evaluation:
            // two of the deg+2 points, a quarter of round 0, an eighth of the whole zerocheck (MEASURED on the DSOL CPU
            // table: 535 → ~470 ms). A forger gains nothing — a trace that violates a law has non-zero true values
            // here, the claimed zeros make round 0's polynomial wrong, and round 1's honest sum no longer matches it;
            // the verifier refuses exactly as before. DEBUG builds keep evaluating these two points (no skip), so the
            // debug prover stays the exact reference the pins compare forged traces against.
            if round == 0 && j < 2 && !strict && !direct_sampling() {
                *hj = Ea4::ZERO;
                continue;
            }
            let xj = Ea4::from(Fa4::from_u64(j as u64));
            let omx = Ea4::ONE - xj;
            // ⭐ ROUND 0 IN THE BASE FIELD (2026-09-29): before any challenge is folded in, the sample rows are base-field
            // (`c[i]·(1−j) + c[half+i]·j` with `j` a small integer), their rotations too, and the point is bits and `j`. A
            // gate with a base path evaluates its laws in `Fa4` and batches into `Ea4` with extension-by-base products;
            // only `eq` is extension arithmetic. MEASURED on the DSOL CPU table: the relation's evaluation is 16× cheaper
            // per field multiply, and round 0 is 43 % of the zerocheck's evaluations after the two hypercube points above.
            if round == 0 && use_base {
                let xj_f = Fa4::from_u64(j as u64);
                let omx_f = Fa4::ONE - xj_f;
                let n_rows = cols[0].len();
                let width = cols.len();
                let s: Ea4 = (0..half)
                    .into_par_iter()
                    .map_init(
                        || (vec![Fa4::ZERO; width], vec![Fa4::ZERO; width], vec![Fa4::ZERO; nvars], OobLatch::new()),
                        |(local_f, next_f, x_f, oob), i| {
                            let eq_at = if eq_factor { eq_curr[i] + eq_curr[half + i] } else { eq_curr[i] * omx + eq_curr[half + i] * xj };
                            for (b, c) in local_f.iter_mut().zip(cols.iter()) {
                                *b = c[i] * omx_f + c[half + i] * xj_f;
                            }
                            // the rotation folded at the same point, straight from the committed columns
                            let rot_at = |c: &Vec<Fa4>| c[(i + 1) % n_rows] * omx_f + c[(half + i + 1) % n_rows] * xj_f;
                            match &shifted {
                                Some(cs) => {
                                    for &c in cs {
                                        next_f[c] = rot_at(&cols[c]);
                                    }
                                }
                                None => {
                                    for (b, c) in next_f.iter_mut().zip(cols.iter()) {
                                        *b = rot_at(c);
                                    }
                                }
                            }
                            x_f[0] = xj_f;
                            for k in 1..nvars {
                                let bit = (i >> (nvars - 1 - k)) & 1;
                                x_f[k] = if bit == 1 { Fa4::ONE } else { Fa4::ZERO };
                            }
                            let next: &[Fa4] = next_f;
                            let at = |c: usize| -> Fa4 {
                                assert!(!row_local, "⛔ a constraint claiming `is_row_local()` read shifted column {c}");
                                if strict {
                                    assert!(
                                        shifted.as_ref().is_none_or(|cs| cs.contains(&c)),
                                        "⛔ shifted column {c} was read but not declared by `shifted_cols()`"
                                    );
                                }
                                next[c]
                            };
                            let v = eq_at * constraint.eval_base(&Row::new(local_f, oob), &at, x_f);
                            assert!(!oob.hit(), "⛔ a gate read past its own trace during prove (base path) — see `OobLatch`");
                            v
                        },
                    )
                    .sum();
                *hj = s;
                continue;
            }
            // ⭐⭐⭐ THE ROW LOOP RUNS IN PARALLEL — it is the decider's hot path and it was serial.
            //
            // Every `i` is independent: it folds its own row at this sample point and contributes ONE
            // term to the sum. The only shared state was the scratch buffers, so each worker keeps its
            // own via `map_init`. MEASURED before this: the 256-slot §BA/§BB aggregate spent 8.2 s here
            // on a 10-core machine with nine cores idle.
            //
            // ⛔ BYTE-IDENTICAL OUTPUT. Field addition is exactly associative and commutative — there is
            // no floating point anywhere in this crate — so the sum does not depend on completion order
            // and two nodes still produce the same proof. The suites check that.
            let width = col_curr.len();
            let rot_w = rot_curr.len();
            let head: Vec<Ea4> = r_vec[..round].to_vec();
            let s: Ea4 = (0..half)
                .into_par_iter()
                .map_init(
                    || {
                        let mut xp = vec![Ea4::ZERO; nvars];
                        xp[..round].copy_from_slice(&head);
                        xp[round] = xj;
                        (
                            vec![Ea4::ZERO; width],
                            vec![Ea4::ZERO; rot_w],
                            xp,
                            OobLatch::new(),
                        )
                    },
                    |(local_buf, next_buf, x_pt, oob), i| {
                        let eq_at = if eq_factor { eq_curr[i] + eq_curr[half + i] } else { eq_curr[i] * omx + eq_curr[half + i] * xj };
                        for (b, c) in local_buf.iter_mut().zip(col_curr.iter()) {
                            *b = c[i] * omx + c[half + i] * xj;
                        }
                        // Folded rotation here = the next-row values (O(1) reads, not O(2^n) mle_eval).
                        match &shifted {
                            // Only the declared columns — see `AirConstraint::shifted_cols`.
                            Some(cs) => {
                                for &c in cs {
                                    next_buf[c] = rot_curr[c][i] * omx + rot_curr[c][half + i] * xj;
                                }
                            }
                            None => {
                                for (b, c) in next_buf.iter_mut().zip(rot_curr.iter()) {
                                    *b = c[i] * omx + c[half + i] * xj;
                                }
                            }
                        }
                        let next: &[Ea4] = next_buf;
                        // Full x point: (r_<round, xj, low bits of i for x_>round). Kept for row-LOCAL
                        // constraints that read `x`; row-shifted ones read `next` via `at`.
                        for k in (round + 1)..nvars {
                            let bit = (i >> (nvars - 1 - k)) & 1;
                            x_pt[k] = if bit == 1 { Ea4::ONE } else { Ea4::ZERO };
                        }
                        // ⛔ A row-local claim is ENFORCED here: reading a shifted column aborts the prove.
                        let at = |c: usize, _p: &[Ea4]| -> Ea4 {
                            assert!(
                                !row_local,
                                "⛔ a constraint claiming `is_row_local()` read shifted column {c} — the \
                                 rotation was not built, so this proof would have stood over stale values"
                            );
                            if strict {
                                assert!(
                                    shifted.as_ref().is_none_or(|cs| cs.contains(&c)),
                                    "⛔ shifted column {c} was read but not declared by `shifted_cols()` — it \
                                     was never folded, so this proof would have stood over a stale value"
                                );
                            }
                            next[c]
                        };
                        // PROVE side: the row is this node's OWN folded trace, never a wire value, so a
                        // short row is a gate/trace mismatch in our own code. Each worker carries its own
                        // latch and asserts on it here, so the miss stays as LOUD as the index panic it
                        // replaces rather than being lost between threads.
                        let v = eq_at * constraint.eval(&Row::new(local_buf, oob), &at, x_pt);
                        assert!(
                            !oob.hit(),
                            "⛔ a gate read past its own trace during prove — see `OobLatch`"
                        );
                        v
                    },
                )
                // `.sum()` is a tree reduction whose SHAPE depends on how the workers split — and that
                // is fine HERE and nowhere near a licence to assume it generally: these are field
                // elements, so addition is exactly associative and commutative and every tree lands on
                // the same value. An index-ordered `collect()` was tried first and made no difference to
                // determinism, which is how the nondeterminism was traced OUT of this loop and into
                // Plonky3's own parallel paths (§CA). `two_identical_proves_are_byte_identical` holds
                // this claim to the byte.
                .sum();
            *hj = s;
        }
        if eq_factor {
            // `h` holds `q` so far: complete it, then multiply the linear factor back in.
            let one_minus = Ea4::ONE - z_k;
            if derive_one {
                h[1] = (claim - one_minus * h[0]) * z_k.inverse();
            }
            let top = per_evals - 1;
            h[top] = lagrange_eval(&h[..top], Ea4::from(Fa4::from_u64(top as u64)));
            for (j, hj) in h.iter_mut().enumerate() {
                let x = Ea4::from(Fa4::from_u64(j as u64));
                *hj *= one_minus * (Ea4::ONE - x) + z_k * x;
            }
        }
        // ⛔ THE DECLARED DEGREE IS ASSERTED, NOT TRUSTED (2026-09-29, DEBUG builds). A law whose per-variable degree
        // exceeds `degree()` makes the honest round polynomial MIS-INTERPOLATE from its deg+2 samples, and whether the
        // verifier then refuses is TRACE-DEPENDENT — the excess coefficient vanishes on some traces and not others.
        // MEASURED: a degree-9 law declared 8 in the DSOL CPU relation; the continuations pin's first segment verified,
        // its continued segment did not, and the row-level diagnostic (which never sees a degree) was clean on both.
        // Here the deg+2-point interpolation must predict the extra sample; a miss names the round and the bound. The
        // extra sample is popped BEFORE the transcript sees `h`, so debug and release proofs stay byte-identical.
        if strict {
            let extra = h.pop().expect("the extra degree sample");
            let predicted = lagrange_eval(&h, Ea4::from(Fa4::from_u64(per_evals as u64)));
            assert!(
                predicted == extra,
                "⛔ zerocheck round {round}: the constraint's univariate degree exceeds its declared `degree()` = {} — a law \
                 has more factors than the bound (count every column, selector and `is_first/is_last/is_trans` factor); \
                 lower the law (commit the product as a column) or raise the declaration",
                constraint.degree(nvars)
            );
        }
        // Bind the round poly into the transcript, then draw the round challenge from it.
        for e in &h {
            for &b in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e) {
                ch.observe(b);
            }
        }
        let r_i: Ea4 = ch.sample_algebra_element();
        r_vec.push(r_i);
        claim = lagrange_eval(&h, r_i);
        round_evals.push(h);
        eq_curr = fold_one_var(&eq_curr, r_i);
        col_curr.par_iter_mut().for_each(|c| *c = fold_one_var(c, r_i));
        rot_curr.par_iter_mut().for_each(|c| *c = fold_one_var(c, r_i));
    }
    if _dbg {
        eprintln!(
            "[zc] nvars={nvars} width={} per_evals={per_evals} row_local={row_local} evals={} — {} ms",
            cols.len(),
            (per_evals as u64) * ((1u64 << nvars) - 1),
            _t_zc.elapsed().as_millis()
        );
    }
    // A gate that read past its OWN trace would silently get zeros and produce a proof nothing can
    // verify. That is a local defect, not a hostile input, so it stays as loud here as the index
    // panic it replaces.
    assert!(
        !oob.hit(),
        "AIR gate read a column its own trace does not have — the constraint and `cols` disagree: \
         it read {}. A column offset written as a literal is a layout that cannot move; this is the \
         address of the one that did not.",
        oob.report()
    );
    let opened: Vec<Ea4> = col_curr.iter().map(|c| c[0]).collect();
    // shifted_opened = mle(rot, r): each column's next-row (rotation) MLE at the sumcheck point, folded
    // in lockstep above. Bound by the caller opening the committed rotation at r (row-local constraints
    // ignore these). Replaces the O(2^n)-per-point σ(r) MLE eval.
    let shifted_opened: Vec<Ea4> = rot_curr.iter().map(|c| c[0]).collect();
    AirZerocheckProof { round_evals, opened, r: r_vec, shifted_opened }
}

/// VERIFY the AIR zerocheck. Replays the Fiat-Shamir transcript from `ch` (same `z`), checks
/// each round's `h(0)+h(1) == claim` and folds the claim via the round challenge, then checks
/// the final reduced claim equals `eq(z,r)·C(opened, opened-via-σ)` at the sumcheck point `r`.
/// The `opened` column values MUST be the ones the WHIR PCS bound to the commitment (the caller
/// enforces that); here we check they satisfy the constraint at `r`. Fail-closed on any mismatch.
#[must_use]
pub fn verify_air_zerocheck<C: AirConstraint + Sync>(
    proof: &AirZerocheckProof,
    constraint: &C,
    z: &[Ea4],
    ch: &mut Chl,
) -> bool {
    verify_air_zerocheck_with(proof, constraint, z, ch)
}

/// The SAME verification, generic over the challenger.
///
/// ⭐ WHY IT IS GENERIC. A recursion has to know the exact absorb/squeeze walk this function performs, so
/// it can lay that walk as sponge rows and weld the challenges to cells. §BS measured what happens when
/// that walk is transcribed by reading instead of recorded by running: 0 of 6 challenges reproduced. So
/// `committed_air::Recording` wraps the real challenger and runs the REAL verification — which is only
/// possible if the verification will accept a wrapped one. One body, so the recording cannot describe a
/// walk the verifier does not take.
pub fn verify_air_zerocheck_with<C: AirConstraint, Ch>(
    proof: &AirZerocheckProof,
    constraint: &C,
    z: &[Ea4],
    ch: &mut Ch,
) -> bool
where
    Ch: p3_challenger::FieldChallenger<Fa4>,
{
    // Row-shifted proofs carry a next-row opening per column; if present it must cover every column.
    if !proof.shifted_opened.is_empty() && proof.shifted_opened.len() != proof.opened.len() {
        return false;
    }
    verify_air_zerocheck_inner(proof, constraint, z, ch, None)
}

/// ⭐ C2 (SPEED, 2026-11-12) — THE COLUMNS A ROW-SHIFTED GATE'S NEXT-ROW OPENINGS ARE SENT FOR: the gate's own declared
/// [`AirConstraint::shifted_cols`] (in range, sorted, once each), every column when it declares none, and none for a
/// row-local gate. A function of the PUBLIC constraint and the table's width alone, so prover and verifier derive the
/// same set and a carrier has exactly one admissible length (pin E-1's rule, `len == |S|`).
/// MEASURED why (`member_ledger` r4 bytes-by-part, 2026-11-12): 42 % of a block's member-ledger proof was opened column
/// values, the next-row half of them sent for every column though the gate reads a handful at the next row.
#[must_use]
pub fn shifted_set<C: AirConstraint + ?Sized>(constraint: &C, width: usize) -> Vec<usize> {
    if constraint.is_row_local() {
        return Vec::new();
    }
    match constraint.shifted_cols() {
        None => (0..width).collect(),
        Some(mut cols) => {
            cols.retain(|&c| c < width);
            cols.sort_unstable();
            cols.dedup();
            cols
        }
    }
}

/// ⭐ C2 — keep only `set`'s next-row openings, in `set`'s order (the prover folds every column's rotation; the wire
/// carries the ones the gate reads).
pub fn compact_shifted(zc: &mut AirZerocheckProof, set: &[usize]) {
    let full = std::mem::take(&mut zc.shifted_opened);
    zc.shifted_opened = set.iter().filter_map(|&c| full.get(c).copied()).collect();
}

/// ⭐ C2 — [`verify_air_zerocheck`] for a proof whose next-row openings are `set`'s alone ([`compact_shifted`]):
/// `shifted_opened` must hold exactly `|set|` values, and the gate's next-row read of column `c` is answered by `c`'s
/// position in `set`. A read of a column OUTSIDE `set` is an out-of-range read: the verdict is `false`, exactly as for a
/// short vector before (the gate is scored against nothing the carrier committed).
#[must_use]
pub fn verify_air_zerocheck_over<C: AirConstraint>(
    proof: &AirZerocheckProof,
    constraint: &C,
    z: &[Ea4],
    ch: &mut Chl,
    set: &[usize],
) -> bool {
    if proof.shifted_opened.len() != set.len() {
        return false;
    }
    verify_air_zerocheck_inner(proof, constraint, z, ch, Some(set))
}

fn verify_air_zerocheck_inner<C: AirConstraint, Ch>(
    proof: &AirZerocheckProof,
    constraint: &C,
    z: &[Ea4],
    ch: &mut Ch,
    set: Option<&[usize]>,
) -> bool
where
    Ch: p3_challenger::FieldChallenger<Fa4>,
{
    let nvars = z.len();
    if proof.round_evals.len() != nvars || proof.r.len() != nvars {
        return false;
    }
    let per_evals = constraint.degree(nvars) + 2;
    let mut claim = Ea4::ZERO; // zerocheck: total sum must be 0.
    let mut r_vec: Vec<Ea4> = Vec::with_capacity(nvars);
    for h in &proof.round_evals {
        if h.len() != per_evals {
            return false;
        }
        if h[0] + h[1] != claim {
            return false; // Σ over the bound variable must equal the incoming claim.
        }
        for e in h {
            for &b in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e) {
                ch.observe(b);
            }
        }
        let r_i: Ea4 = ch.sample_algebra_element();
        if r_i != proof.r[r_vec.len()] {
            return false; // transcript-derived challenge must match the prover's point.
        }
        claim = lagrange_eval(h, r_i);
        r_vec.push(r_i);
    }
    // Final: claim == eq(z, r) · C(opened at r, rotation opened at r). `opened` are the WHIR-bound
    // column evals at r; `shifted_opened` are the WHIR-bound next-row (rotation) evals at r (the O(N)
    // rot-fold's next row). A row-shifted (transition) constraint reads next-row values through `at`
    // (below); row-LOCAL constraints ignore `at`.
    let eq_zr = {
        // eq(z, r) = Π (z_k r_k + (1−z_k)(1−r_k)).
        let mut e = Ea4::ONE;
        for k in 0..nvars {
            e *= z[k] * proof.r[k] + (Ea4::ONE - z[k]) * (Ea4::ONE - proof.r[k]);
        }
        e
    };
    // ⛔⛔⛔ THE ONE UNTRUSTED GATE EVALUATION IN THE WHOLE DECIDER — see [`Row`].
    //
    // `proof.opened` and `proof.shifted_opened` are WIRE values: their LENGTHS are chosen by whoever
    // sent the carrier, and every gate indexes them directly. Before this latch a self-consistent
    // `(nvars, width) = (0, 1)` carrier killed the node inside `SpendConservationGate` at `local[1]`
    // (pin C-17), off-lock at `/submit_pq_tx`. Both channels the gate can read through — the row and
    // the next-row `at` — now record an out-of-range read instead of unwinding, and the carrier is
    // REFUSED on that record. The substituted zero never reaches the verdict: a short row can only
    // make this function return `false`, never `true`, so no gate can be satisfied with columns the
    // sender never committed.
    let oob = OobLatch::new();
    let at = |c: usize, _p: &[Ea4]| -> Ea4 {
        // C2: a compact proof answers column `c` from its position in the public set; the full form by `c` itself.
        let pos = match set {
            Some(s) => s.binary_search(&c).ok(),
            None => Some(c),
        };
        match pos.and_then(|i| proof.shifted_opened.get(i)) {
            Some(v) => *v,
            None => {
                // A row-LOCAL gate never calls `at`, so an honest carrier cannot reach this arm; a
                // row-SHIFTED gate whose carrier ships no rotation opening for column `c` is asking
                // to be scored against a value nobody committed.
                oob.record(c, proof.shifted_opened.len());
                Ea4::ZERO
            }
        }
    };
    let row = Row::new(&proof.opened, &oob);
    let c_at_r = constraint.eval(&row, &at, &proof.r);
    if oob.hit() {
        return false; // the carrier declared a narrower trace than its own AIR reads — REFUSE.
    }
    eq_zr * c_at_r == claim
}

/// Extension degree of `Ea4` (KoalaBear⁴). LogUp's helper column is extension-valued (it depends on
/// the extension challenge α), so it is stored as this many base-field limb columns.
const EA4_D: usize = 4;

/// A plain multilinear SUMCHECK proof: proves `Σ_{x∈{0,1}^n} col(x) == claimed`. `col` is a single
/// committed base-field column; each round polynomial is LINEAR (`col` is multilinear ⇒ 2 evals).
/// `opened` = the column's MLE at the sumcheck point `r` (WHIR-bound, like the zerocheck openings).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ColSumProof {
    /// Per-round linear polynomial `[h(0), h(1)]`.
    pub round_evals: Vec<Vec<Ea4>>,
    /// The column's MLE value at the final point `r`.
    pub opened: Ea4,
    /// The sumcheck point `r` (Fiat-Shamir derived; recomputed by verify).
    pub r: Vec<Ea4>,
}

/// PROVE `Σ_x col(x) == <returned sum>` (the caller reads the honest sum separately; verify checks a
/// claimed sum against this proof). Fiat-Shamir challenges drawn from `ch`.
#[must_use]
pub fn prove_col_sum(col: &[Fa4], ch: &mut Chl) -> ColSumProof {
    let nvars = col.len().trailing_zeros() as usize;
    let mut cur: Vec<Ea4> = col.iter().map(|&v| Ea4::from(v)).collect();
    let mut round_evals = Vec::with_capacity(nvars);
    let mut r_vec = Vec::with_capacity(nvars);
    for _ in 0..nvars {
        let half = cur.len() / 2;
        let mut h0 = Ea4::ZERO;
        let mut h1 = Ea4::ZERO;
        for i in 0..half {
            h0 += cur[i];
            h1 += cur[half + i];
        }
        let h = vec![h0, h1];
        for e in &h {
            for &b in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e) {
                ch.observe(b);
            }
        }
        let r_i: Ea4 = ch.sample_algebra_element();
        r_vec.push(r_i);
        round_evals.push(h);
        cur = fold_one_var(&cur, r_i);
    }
    ColSumProof { round_evals, opened: cur[0], r: r_vec }
}

/// VERIFY `Σ_x col(x) == claimed_sum`. Replays the transcript, checks each round's `h(0)+h(1)==claim`
/// and folds by the linear interpolation `h(r)=h(0)(1−r)+h(1)r`, then the final claim against the
/// WHIR-bound `opened` (`col(r)`). Fail-closed on any mismatch.
#[must_use]
pub fn verify_col_sum(claimed_sum: Ea4, proof: &ColSumProof, ch: &mut Chl) -> bool {
    let mut claim = claimed_sum;
    for (k, h) in proof.round_evals.iter().enumerate() {
        if h.len() != 2 {
            return false;
        }
        if h[0] + h[1] != claim {
            return false;
        }
        for e in h {
            for &b in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e) {
                ch.observe(b);
            }
        }
        let r_i: Ea4 = ch.sample_algebra_element();
        if k >= proof.r.len() || r_i != proof.r[k] {
            return false;
        }
        claim = h[0] * (Ea4::ONE - r_i) + h[1] * r_i;
    }
    claim == proof.opened
}

/// LogUp helper-column constraint (row-local, degree 2): reconstructs the extension-valued helper
/// `h(x) = Σ_k h_limb_k(x)·Xᵏ` and enforces `h·(α − value) − mult == 0` on every row — i.e. `h` is
/// the correct rational bus term `mult/(α − value)`. Combined with `Σ_x h(x) == 0` (via
/// [`prove_col_sum`] per limb + the extension basis), this is the standard LogUp bus-balance: a
/// send/receive multiset equality (the SYMX_REG_BUS reg write↔read + LEAF_BUS leaf↔claim ties).
/// `value`/`mult` are base columns; `h` is `EA4_D` limb columns starting at `h_limb_base`.
pub struct LogupHConstraint {
    /// The extension bus challenge α (drawn AFTER the trace + h are committed).
    pub alpha: Ea4,
    /// Column index of the bus VALUE (base field).
    pub val_col: usize,
    /// Column index of the signed MULTIPLICITY (+send / −receive, base field).
    pub mult_col: usize,
    /// First of the `EA4_D` limb columns of the extension helper `h`.
    pub h_limb_base: usize,
}
impl AirConstraint for LogupHConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        2
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut h = Ea4::ZERO;
        for i in 0..EA4_D {
            let xi = Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO });
            h += local[self.h_limb_base + i] * xi;
        }
        h * (self.alpha - local[self.val_col]) - local[self.mult_col]
    }
}

/// Like [`LogupHConstraint`] but the bus KEY is folded INLINE from the real source columns
/// `keyfold = idx_col + Σᵢ β^{i+1}·val_col[i]` (matching `crate::whir_rec_block::leaf_bus_key`) instead of
/// read from a single free `val_col`. SOUNDNESS: this ties the LogUp helper `h` to the ACTUAL committed
/// leaf columns (`a_idx`/`out` on a SymEvalR6Leaf row, `idx`/`val` on a LeafSource row, `leaf_idx`/`claim`
/// on a ClaimsExpose row) — the prover cannot commit an independently-balanced value column divorced from
/// the trace, because the fold is a function of the very columns the zerocheck opens. `β` is the
/// transcript-drawn fold challenge (`draw_bus_fold_challenge`); `α` the bus challenge. Enforces
/// `h·(α − keyfold) − mult == 0` on every row. Degree 2 (h × key, both linear in the columns).
pub struct LogupKeyfoldConstraint {
    /// The extension bus challenge α (drawn after the trace + h are committed).
    pub alpha: Ea4,
    /// The base-field keyfold challenge β (transcript-drawn), matching `leaf_bus_key`.
    pub beta: Fa4,
    /// Column index of the leaf index (the `idx` term of the fold).
    pub idx_col: usize,
    /// First of the `n_val` value columns folded as `Σᵢ β^{i+1}·val[i]`.
    pub val_col_base: usize,
    /// How many value columns participate in the fold (`EXT_D` for a leaf tuple).
    pub n_val: usize,
    /// Column index of the signed MULTIPLICITY (+send / −receive, base field).
    pub mult_col: usize,
    /// First of the `EA4_D` limb columns of the extension helper `h`.
    pub h_limb_base: usize,
}
impl AirConstraint for LogupKeyfoldConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        2
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut h = Ea4::ZERO;
        for i in 0..EA4_D {
            let xi = Ea4::from_basis_coefficients_fn(|k| if k == i { Fa4::ONE } else { Fa4::ZERO });
            h += local[self.h_limb_base + i] * xi;
        }
        // keyfold = idx + Σᵢ β^{i+1}·val[i]  (matches leaf_bus_key: idx + β·val0 + β²·val1 + …).
        let mut key = local[self.idx_col];
        let mut bpow = Ea4::from(self.beta);
        for i in 0..self.n_val {
            key += bpow * local[self.val_col_base + i];
            bpow *= Ea4::from(self.beta);
        }
        h * (self.alpha - key) - local[self.mult_col]
    }
    /// DB-452: the bus gate reads its own row only — so a light round sends no next-row openings for it.
    fn is_row_local(&self) -> bool {
        true
    }
}

/// ⛔⛔⛔ THE RISK THIS LANE'S OWN FIX CREATED, PINNED.
///
/// [`Row`] replaces an out-of-range PANIC with a ZERO plus a latch. That is only safe while EVERY
/// caller reads the latch. A future caller who builds a `Row` and ignores [`Row::out_of_range`] would
/// silently evaluate a gate against columns nobody committed — and USING that value is a SOUNDNESS
/// break, strictly worse than the denial-of-service it replaced (a party could satisfy a mint gate
/// with a trace it never had).
///
/// So the sanctioned construction sites are enumerated here and checked against the sources at COMPILE
/// time. Adding a `Row::new` without also inspecting the latch turns this pin red, and the failure text
/// says what to do.
///
/// TWO-PARTY-REVIEWED, BY CONSTRUCTION: this pin's inputs are `include_str!` of this crate's own
/// source files — fixed strings baked in at compile time. It opens no socket, builds no `Node`, and
/// moves no value, so there is no boundary for a second endpoint to sit on. The boundary this
/// invariant protects is measured where it exists: the wallet PROVES carriers through this same crate
/// (`monerousd-wallet-v2/src-tauri/Cargo.toml:61` links it by the path
/// `../../monerousd-node-zkdag/vendor/Plonky3/usdm-decider`, so prover and verifier are one build by
/// construction) and the node VERIFIES them at its doors, which node pins C-17/C-18 drive.
#[cfg(test)]
mod row_latch_discipline {
    /// PIN E-3 — every `Row` built in this crate has its latch inspected.
    #[test]
    fn e3_every_row_construction_inspects_the_out_of_range_latch() {
        // (file label, source, expected `Row::new(` count, what inspects the latch there)
        let sites: &[(&str, &str, usize, &str)] = &[
            (
                "air_zerocheck.rs",
                include_str!("air_zerocheck.rs"),
                8,
                "RowGuard::row (the owner exposes `out_of_range`); prove_air_zerocheck's three evaluation sites — the \
                 base-field round-0 path, the per-point extension path and the one-pass extension path (speed lane, \
                 2026-11-09: one latch per worker, asserted `!oob.hit()` after every point's evaluation; inspected before \
                 the count moved 7 → 8) — (each asserts `!oob.hit()` right after its \
                 evaluation); verify_air_zerocheck (returns false on `oob.hit()`); and the three strict-mode censuses \
                 added 2026-09-29 — debug_degree_census, debug_free_witness_census, debug_decorative_block_census — \
                 each of which builds its rows on its own latch and asserts `!oob.hit()` after its last evaluation \
                 (MEASURED by the first whole-crate strict run, 2026-09-30 00:0x: this pin read 7, not 3, and every \
                 one of the four new sites was inspected before the count moved)",
            ),
            (
                "nf_sparse_air.rs",
                include_str!("nf_sparse_air.rs"),
                4,
                "four test fixtures, each asserting `!oob.hit()` on the row it builds (a gate that read past its own \
                 row would score the chain against substituted zeros and still look satisfied): \
                 `every_row_is_residual_free_and_the_gate_folds_on_gamma` (the SparseChainGate fixture, the original), \
                 `sparse_block_gate_residuals_vanish_iff_valid_chain`, \
                 `db353_keyed_block_gate_binds_every_insert_to_the_public_key_list` (the keyed carrier, 2026-09-29) and \
                 `db353_a_forged_accumulator_beside_an_honest_permutation_is_refused` (the decorative-block RED-first \
                 pin, 2026-09-29) — MEASURED by the second chunked strict census, 2026-09-30 02:2x: this pin read 4, \
                 not 2, and each new site was inspected before the count moved",
            ),
            (
                "whir_rec_block.rs",
                include_str!("whir_rec_block.rs"),
                1,
                "one test fixture, `row_vanishes` in the DB-237 stake-gate tests (landed 2026-10-02), which returns \
                 `residuals vanish && !oob.hit()` on the row it builds — MEASURED by the one-sweep scanner's strict \
                 circuit pass, 2026-10-03: this pin read 1 where 0 was required (the file was on the must-not-build \
                 list), and the site was inspected before the file moved to this list",
            ),
        ];
        let mut total = 0usize;
        for (label, src, expected, inspected_by) in sites {
            // ⛔ A SELF-REFERENTIAL CHECK MUST NOT COUNT ITSELF.
            //
            // ROOT-LAYER: the miscount is PRODUCED here, by the choice of scan region — this pin's own
            // body contains the literal `Row::new(` (it is the needle), and `include_str!` hands back
            // the whole file including the pin. Excluding the pin's own text is the region definition,
            // not a patch on the number it produced; nothing downstream is adjusted to compensate.
            // MEASURED: before -> `left: 6  right: 3` (FAILED, 0 passed; 1 failed) on the first run of
            // this pin, the 3 extra being the needle written inside the pin itself; after -> `[E-3] 4
            // sanctioned Row construction(s), every latch inspected`, test result ok.
            // MUST-STAY-GREEN: the pin still fails on a genuinely NEW `Row::new(` anywhere above it,
            // and still fails when any other file in the crate constructs one — the loop below and the
            // named `verify_air_zerocheck` assertion are untouched by this region choice.
            let scanned = match src.split_once("mod row_latch_discipline") {
                // air_zerocheck.rs — everything above this pin is the code under audit.
                Some((above_the_pin, _this_pin)) => above_the_pin,
                // Every other scanned file contains no pin, so the whole file is the region.
                None => src,
            };
            let n = scanned.matches("Row::new(").count();
            assert_eq!(
                n, *expected,
                "ROW LATCH DISCIPLINE: {label} now builds {n} Row(s), not {expected}. Every `Row` \
                 MUST have its `out_of_range()` latch inspected by its owner — a zero substituted for \
                 an out-of-range column and then USED is a soundness break, not a convenience. \
                 Inspect the new site, then update this pin. Sanctioned here: {inspected_by}."
            );
            total += n;
        }
        // Nothing else in the crate may build one.
        for (label, src) in [
            ("note_membership_air.rs", include_str!("note_membership_air.rs")),
            ("nullifier_insert_air.rs", include_str!("nullifier_insert_air.rs")),
            ("confidential_solvency.rs", include_str!("confidential_solvency.rs")),
            ("whole_chain.rs", include_str!("whole_chain.rs")),
            ("split_ladder_air.rs", include_str!("split_ladder_air.rs")),
            ("limb_gadgets.rs", include_str!("limb_gadgets.rs")),
        ] {
            assert_eq!(
                src.matches("Row::new(").count(),
                0,
                "ROW LATCH DISCIPLINE: {label} builds a Row. Gates RECEIVE rows and pass sub-rows on \
                 (`Row::prefix`/`Row::suffix` share the parent's latch); a gate that CONSTRUCTS one \
                 has made itself the latch's owner without saying who inspects it."
            );
        }
        // `verify_air_zerocheck` is the ONE untrusted evaluation, so its latch check is named
        // explicitly rather than left to the count above.
        let az = include_str!("air_zerocheck.rs");
        assert!(
            az.contains("let c_at_r = constraint.eval(&row, &at, &proof.r);")
                && az.contains("if oob.hit() {"),
            "ROW LATCH DISCIPLINE: `verify_air_zerocheck` no longer evaluates the gate through a \
             latched Row and refuses on the latch. That check is what makes a short wire row a \
             REJECTION instead of an acceptance — restore it before this crate ships."
        );
        println!("[E-3] {total} sanctioned Row construction(s), every latch inspected");
    }
}

#[cfg(test)]
mod tests {

    /// ⛔ THE HAND ALGEBRA IS CHECKED AGAINST THE FORM IT REPLACES, not trusted.
    ///
    /// `pack_limbs` replaces `l0*X^0 + l1*X^1 + l2*X^2 + l3*X^3` with a coordinate shift and six
    /// triples. A wrong `W`, a transposed index or an off-by-one in the wrap would still produce a
    /// plausible-looking field element and every proof in the tree would silently stand over the wrong
    /// value — so this compares the two forms directly, on values spread across the field.
    #[test]
    fn pack_limbs_equals_the_basis_sum() {
        let basis: [Ea4; 4] = core::array::from_fn(|i| {
            <Ea4 as BasedVectorSpace<Fa4>>::ith_basis_element(i).expect("4 basis elements")
        });
        let mk = |seed: u64| -> Ea4 {
            Ea4::from_basis_coefficients_fn(|j| {
                Fa4::from_u64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(j as u64 * 7))
            })
        };
        for s in 0..64u64 {
            let (l0, l1, l2, l3) = (mk(s), mk(s + 101), mk(s + 202), mk(s + 303));
            let naive = l0 * basis[0] + l1 * basis[1] + l2 * basis[2] + l3 * basis[3];
            assert_eq!(
                super::pack_limbs(l0, l1, l2, l3),
                naive,
                "⛔ `pack_limbs` disagrees with the basis sum at seed {s} — the monomial shift or W is \
                 wrong, and every recursion in this crate reads its values through it"
            );
        }
        // And the degenerate cases the shift is easiest to get wrong on.
        assert_eq!(super::pack_limbs(Ea4::ONE, Ea4::ZERO, Ea4::ZERO, Ea4::ZERO), Ea4::ONE);
        assert_eq!(super::pack_limbs(Ea4::ZERO, Ea4::ONE, Ea4::ZERO, Ea4::ZERO), basis[1]);
        assert_eq!(super::pack_limbs(Ea4::ZERO, Ea4::ZERO, Ea4::ONE, Ea4::ZERO), basis[2]);
        assert_eq!(super::pack_limbs(Ea4::ZERO, Ea4::ZERO, Ea4::ZERO, Ea4::ONE), basis[3]);
    }
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;
    use crate::hiding_decider::{Chl, Perm16};

    fn mk_ch() -> Chl {
        let mut rng = SmallRng::seed_from_u64(0xA4_2C_0DEu64);
        Chl::new(Perm16::new_from_rng_128(&mut rng))
    }

    /// #135 source-tie: `LogupKeyfoldConstraint` folds the bus key INLINE from the real source columns, so
    /// the helper `h` is tied to those columns — tampering a `val` column (leaving `h`/`mult`) breaks the
    /// per-row `h·(α−keyfold)−mult==0` → REJECT. Proves the LogUp key is NOT a free committed value the
    /// prover controls; it is a function of the committed leaf columns the zerocheck opens.
    #[test]
    fn logup_keyfold_ties_key_to_source_columns() {
        use p3_field::BasedVectorSpace;
        let run = |tamper: bool| -> bool {
            let beta = Fa4::from_u64(13);
            let idx = [Fa4::from_u64(2), Fa4::from_u64(5), Fa4::from_u64(2), Fa4::from_u64(5)];
            let vals = [
                [Fa4::from_u64(10), Fa4::from_u64(11), Fa4::from_u64(12), Fa4::from_u64(13)],
                [Fa4::from_u64(20), Fa4::from_u64(21), Fa4::from_u64(22), Fa4::from_u64(23)],
                [Fa4::from_u64(10), Fa4::from_u64(11), Fa4::from_u64(12), Fa4::from_u64(13)],
                [Fa4::from_u64(20), Fa4::from_u64(21), Fa4::from_u64(22), Fa4::from_u64(23)],
            ];
            // SEND rows 0,1 (mult +1); RECV rows 2,3 (mult −1) with matching (idx,val) → keys pair up.
            let mult = [Fa4::ONE, Fa4::ONE, -Fa4::ONE, -Fa4::ONE];
            let keyfold = |ix: Fa4, v: &[Fa4; 4]| -> Ea4 {
                let mut k = Ea4::from(ix);
                let mut bpow = Ea4::from(beta);
                for i in 0..4 {
                    k += bpow * Ea4::from(v[i]);
                    bpow *= Ea4::from(beta);
                }
                k
            };
            let mut pch = mk_ch();
            let alpha: Ea4 = pch.sample_algebra_element();
            // cols: idx(0) | val0..val3 (1..5) | mult(5) | h0..h3 (6..10). width=10, 4 rows.
            let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 4]; 10];
            for r in 0..4 {
                cols[0][r] = idx[r];
                for i in 0..4 {
                    cols[1 + i][r] = vals[r][i];
                }
                cols[5][r] = mult[r];
                let key = keyfold(idx[r], &vals[r]);
                let h = Ea4::from(mult[r]) * (alpha - key).inverse();
                let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&h);
                for i in 0..EA4_D {
                    cols[6 + i][r] = limbs[i];
                }
            }
            if tamper {
                cols[1][2] += Fa4::ONE; // change a RECV val WITHOUT updating h → key ≠ h's key → row ≠ 0
            }
            let cst = LogupKeyfoldConstraint {
                alpha,
                beta,
                idx_col: 0,
                val_col_base: 1,
                n_val: 4,
                mult_col: 5,
                h_limb_base: 6,
            };
            let z: Vec<Ea4> = (0..2).map(|_| pch.sample_algebra_element()).collect();
            let proof = prove_air_zerocheck(&cols, &cst, &z, &mut pch);
            let mut vch = mk_ch();
            let alpha_v: Ea4 = vch.sample_algebra_element();
            let cst_v = LogupKeyfoldConstraint {
                alpha: alpha_v,
                beta,
                idx_col: 0,
                val_col_base: 1,
                n_val: 4,
                mult_col: 5,
                h_limb_base: 6,
            };
            let zv: Vec<Ea4> = (0..2).map(|_| vch.sample_algebra_element()).collect();
            verify_air_zerocheck(&proof, &cst_v, &zv, &mut vch)
        };
        assert!(run(false), "honest inline-keyfold h correct on every row → ACCEPT");
        assert!(!run(true), "tampered source val (h unchanged) breaks h·(α−keyfold)−mult=0 → REJECT");
    }

    // Degree-2 (NON-LINEAR) row-local constraint c[i] = a[i]·b[i] — the exact relation that
    // A4.0/A4.1's at-z trick CANNOT do (the multilinear ceiling). deg = 2.
    struct ProdConstraint;
    impl AirConstraint for ProdConstraint {
        fn degree(&self, _nvars: usize) -> usize { 2 }
        fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            local[2] - local[0] * local[1] // c - a·b
        }
    }

    fn run_prod(tamper: bool) -> bool {
        const NV: usize = 6;
        const N: usize = 1 << NV;
        let a: Vec<Fa4> = (0..N).map(|i| Fa4::from_u64((i as u64) + 1)).collect();
        let b: Vec<Fa4> = (0..N).map(|i| Fa4::from_u64((i as u64) * 3 + 2)).collect();
        let mut c: Vec<Fa4> = (0..N).map(|i| a[i] * b[i]).collect();
        if tamper { c[5] = c[5] + Fa4::ONE; }
        let cols = vec![a, b, c];
        let cst = ProdConstraint;
        // FS zerocheck point z drawn from the prover transcript.
        let mut pch = mk_ch();
        let z: Vec<Ea4> = (0..NV).map(|_| pch.sample_algebra_element()).collect();
        let proof = prove_air_zerocheck(&cols, &cst, &z, &mut pch);
        let mut vch = mk_ch();
        let zv: Vec<Ea4> = (0..NV).map(|_| vch.sample_algebra_element()).collect();
        assert_eq!(z, zv, "FS z must be transcript-deterministic");
        // Bind: the opened values MUST equal the true column MLEs at r (the WHIR PCS enforces
        // this on-chain; here we assert the prover reported honest openings).
        for (ci, col) in cols.iter().enumerate() {
            let true_at_r = mle_eval(col, &proof.r);
            if proof.opened[ci] != true_at_r { return false; }
        }
        verify_air_zerocheck(&proof, &cst, &zv, &mut vch)
    }

    #[test]
    fn a4_2_prod_zerocheck_honest_accepts_tampered_rejects() {
        assert!(run_prod(false), "A4.2 honest degree-2 product zerocheck must ACCEPT");
        assert!(!run_prod(true), "A4.2 tampered product zerocheck must REJECT (Schwartz-Zippel)");
    }

    // ROW-SHIFTED (transition) constraint through the engine: `col0(σx) − col0(x) == 0`, σ = the +1
    // cyclic shift. Exercises the shifted-opening mechanism (proof.shifted_opened + verify's σ(r)
    // `at`) — the infrastructure every AIR `next()`/transition constraint (e.g. SymEvalR6's row_idx
    // increment) rides on. A constant column is periodic under σ (accepts); a single tampered cell
    // breaks the shift relation somewhere on the hypercube (rejects). degree = nvars+1 (carry chain).
    struct RowShiftConsistencyConstraint;
    impl AirConstraint for RowShiftConsistencyConstraint {
        fn degree(&self, nvars: usize) -> usize { nvars + 1 }
        fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
            let sigma = cyclic_shift_sigma(x);
            at(0, &sigma) - local[0] // col0(σx) − col0(x)
        }
    }

    fn run_shift(tamper: bool) -> bool {
        const NV: usize = 4;
        const N: usize = 1 << NV;
        let c = Fa4::from_u64(0x51ba);
        let mut col: Vec<Fa4> = vec![c; N]; // constant ⇒ periodic under σ ⇒ col(σx)=col(x)
        if tamper {
            col[5] = c + Fa4::ONE;
        }
        let cols = vec![col.clone()];
        let cst = RowShiftConsistencyConstraint;
        let mut pch = mk_ch();
        let z: Vec<Ea4> = (0..NV).map(|_| pch.sample_algebra_element()).collect();
        let proof = prove_air_zerocheck(&cols, &cst, &z, &mut pch);
        // Bind: shifted_opened MUST be the column's MLE at σ(r) (WHIR enforces this on-chain).
        let sigma_r = cyclic_shift_sigma(&proof.r);
        if proof.shifted_opened[0] != mle_eval(&col, &sigma_r) {
            return false;
        }
        let mut vch = mk_ch();
        let zv: Vec<Ea4> = (0..NV).map(|_| vch.sample_algebra_element()).collect();
        verify_air_zerocheck(&proof, &cst, &zv, &mut vch)
    }

    #[test]
    fn row_shifted_transition_via_zerocheck_engine_honest_accepts_tampered_rejects() {
        assert!(run_shift(false), "honest row-shifted (constant col ⇒ col(σx)=col(x)) must ACCEPT");
        assert!(!run_shift(true), "tampered column (breaks the shift relation) must REJECT");
    }

    /// A short, wide, degree-4 gate the shape of the joined ledger's costliest tables: `w` laws `c = a³·b` on their own columns,
    /// plus (unless row-local) one transition `s(next) = t` — declared, or left to the all-columns default.
    struct WideGate {
        w: usize,
        gamma: Ea4,
        row_local: bool,
        declare: bool,
    }
    impl AirConstraint for WideGate {
        fn degree(&self, _nvars: usize) -> usize {
            4
        }
        fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let mut acc = Ea4::ZERO;
            let mut g = Ea4::ONE;
            for k in 0..self.w {
                let (a, b, c) = (local[3 * k], local[3 * k + 1], local[3 * k + 2]);
                acc += g * (c - a * a * a * b);
                g *= self.gamma;
            }
            if !self.row_local {
                acc += g * (at(3 * self.w, &[]) - local[3 * self.w + 1]);
            }
            acc
        }
        fn is_row_local(&self) -> bool {
            self.row_local
        }
        fn shifted_cols(&self) -> Option<Vec<usize>> {
            if self.row_local {
                Some(Vec::new())
            } else if self.declare {
                Some(vec![3 * self.w])
            } else {
                None
            }
        }
    }

    /// ⭐ SPEED LANE (2026-11-09): the one-pass round evaluation lays EXACTLY the bytes of the per-point reference (every point
    /// sampled directly, in the extension), on the gate shapes it was built for — short and wide (2^7 rows), tall and narrow,
    /// row-shifted with the shift declared or defaulted, and row-local — and the fast path's proof verifies.
    /// TWO-PARTY-REVIEWED: two sides here — the prover, and a verifier that rebuilds its own transcript from nothing and must
    /// accept the fast path's proof; the cross-NODE side (a peer verifying the producer's block proof) is the real-node profile
    /// run on this build (`scratchpad/speed-profile.sh`: two usdmd-node processes, a payment spent across them).
    #[test]
    fn the_one_pass_round_lays_the_bytes_of_the_per_point_reference_on_every_gate_shape() {
        use std::sync::atomic::Ordering::SeqCst;
        for &(nv, w, row_local, declare) in &[(7usize, 400usize, false, true), (7, 400, false, false), (7, 400, true, false), (10, 12, false, true), (5, 3, false, false)] {
            let n = 1usize << nv;
            let f = |s: u64| Fa4::from_u64(s.wrapping_mul(0x9E37_79B9).wrapping_add(17) % 2_000_003 + 1);
            let mut cols: Vec<Vec<Fa4>> = Vec::with_capacity(3 * w + 2);
            for k in 0..w {
                let a: Vec<Fa4> = (0..n).map(|i| f((k * 1000 + i) as u64)).collect();
                let b: Vec<Fa4> = (0..n).map(|i| f((k * 1000 + i) as u64 + 7_777)).collect();
                let c: Vec<Fa4> = (0..n).map(|i| a[i] * a[i] * a[i] * b[i]).collect();
                cols.push(a);
                cols.push(b);
                cols.push(c);
            }
            let s: Vec<Fa4> = (0..n).map(|i| f(i as u64 + 99_999)).collect();
            let t: Vec<Fa4> = (0..n).map(|i| s[(i + 1) % n]).collect();
            cols.push(s);
            cols.push(t);
            let gate = WideGate { w, gamma: Ea4::from(Fa4::from_u64(987_654_321)) + Ea4::GENERATOR, row_local, declare };
            let prove = |direct: bool| {
                DIRECT_SAMPLING_FOR_TEST.store(direct, SeqCst);
                let mut ch = mk_ch();
                let z: Vec<Ea4> = (0..nv).map(|_| ch.sample_algebra_element()).collect();
                let p = prove_air_zerocheck(&cols, &gate, &z, &mut ch);
                DIRECT_SAMPLING_FOR_TEST.store(false, SeqCst);
                (postcard::to_allocvec(&p).expect("the proof encodes"), p)
            };
            let (fast, proof) = prove(false);
            let (reference, _) = prove(true);
            assert_eq!(fast, reference, "⛔ the one-pass round's bytes differ from the per-point reference: nvars {nv}, {w} laws, row-local {row_local}, declared {declare}");
            let mut vch = mk_ch();
            let zv: Vec<Ea4> = (0..nv).map(|_| vch.sample_algebra_element()).collect();
            assert!(verify_air_zerocheck(&proof, &gate, &zv, &mut vch), "⛔ the one-pass proof does not verify: nvars {nv}, {w} laws");
        }
    }

    // LogUp BUS BALANCE: a balanced send/receive multiset satisfies Σ_x mult(x)/(α−value(x)) = 0.
    // Part (a): zerocheck `h·(α−value)−mult == 0` (h = the rational term, EA4_D limb cols). Part (b):
    // `Σ_x h(x) == 0`, via per-limb prove_col_sum recombined by the extension basis. A balanced bus
    // accepts; dropping a receive (imbalance) leaves Σ h ≠ 0 → part (b) rejects. This is the shape of
    // the SYMX_REG_BUS (reg write↔read) and LEAF_BUS (leaf↔claim) ties.
    #[test]
    fn logup_bus_balance_honest_accepts_imbalance_rejects() {
        let run_bus = |tamper: bool| -> bool {
            const NV: usize = 2;
            const N: usize = 1 << NV; // 4 rows: 2 sends + 2 receives
            let v = [Fa4::from_u64(11), Fa4::from_u64(23)];
            let value = vec![v[0], v[1], v[0], v[1]];
            let mut mult = vec![Fa4::ONE, Fa4::ONE, -Fa4::ONE, -Fa4::ONE]; // +send / −receive
            if tamper {
                mult[2] = Fa4::ZERO; // drop a receive → multiset imbalance
            }
            // α from the transcript (prover + verifier derive the same).
            let mut ach = mk_ch();
            let alpha: Ea4 = ach.sample_algebra_element();
            // h[i] = mult[i]/(α − value[i]); decompose into EA4_D base limbs.
            let h_ext: Vec<Ea4> = (0..N)
                .map(|i| Ea4::from(mult[i]) * (alpha - Ea4::from(value[i])).inverse())
                .collect();
            let mut h_limbs: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; N]; EA4_D];
            for i in 0..N {
                let limbs = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&h_ext[i]);
                for k in 0..EA4_D {
                    h_limbs[k][i] = limbs[k];
                }
            }
            // cols = [value, mult, h_limb0..3]
            let mut cols: Vec<Vec<Fa4>> = vec![value.clone(), mult.clone()];
            for k in 0..EA4_D {
                cols.push(h_limbs[k].clone());
            }
            let cst = LogupHConstraint { alpha, val_col: 0, mult_col: 1, h_limb_base: 2 };
            // Part (a): zerocheck h·(α−value)−mult == 0.
            let mut pch = mk_ch();
            let z: Vec<Ea4> = (0..NV).map(|_| pch.sample_algebra_element()).collect();
            let za = prove_air_zerocheck(&cols, &cst, &z, &mut pch);
            let mut vch = mk_ch();
            let zv: Vec<Ea4> = (0..NV).map(|_| vch.sample_algebra_element()).collect();
            let part_a = verify_air_zerocheck(&za, &cst, &zv, &mut vch);
            // Part (b): Σ_x h(x) == 0 ⟺ Σ_k Xᵏ·(Σ_x h_limb_k(x)) == 0. Each per-limb sum is BOUND by
            // prove/verify_col_sum (a malicious prover cannot fake the limb sum).
            let mut sum_ext = Ea4::ZERO;
            let mut part_b = true;
            for k in 0..EA4_D {
                let sum_k: Ea4 = h_limbs[k].iter().fold(Ea4::ZERO, |a, &vv| a + Ea4::from(vv));
                let mut sch = mk_ch();
                let sp = prove_col_sum(&h_limbs[k], &mut sch);
                let mut svch = mk_ch();
                if !verify_col_sum(sum_k, &sp, &mut svch) {
                    part_b = false;
                }
                let xk = Ea4::from_basis_coefficients_fn(|j| if j == k { Fa4::ONE } else { Fa4::ZERO });
                sum_ext += xk * sum_k;
            }
            part_a && part_b && sum_ext == Ea4::ZERO
        };
        assert!(run_bus(false), "balanced LogUp bus must ACCEPT (Σ mult/(α−value) = 0)");
        assert!(!run_bus(true), "imbalanced bus (dropped receive) must REJECT");
    }
}

/// ⛔ TEST-ONLY (A-F57): [`solve_opened_for_tests`] with the gate's next-row reads answered by `next` (not by the row
/// itself), moving ONE coordinate of the row (`move_next = false`) or of `next` (`move_next = true`, only coordinates in
/// `allowed`, the gate's public next-row set) until the gate is zero at `x`. The lying prover's "false in one place":
/// every other value it sends is the committed table's own. `None` when no single coordinate is affine in the gate.
#[cfg(test)]
pub(crate) fn solve_one_coordinate_for_tests<C: AirConstraint>(
    constraint: &C,
    row: &[Ea4],
    next: &[Ea4],
    x: &[Ea4],
    move_next: bool,
    allowed: &[usize],
) -> Option<(Vec<Ea4>, Vec<Ea4>)> {
    let eval = |rw: &[Ea4], nx: &[Ea4]| -> Ea4 {
        let oob = OobLatch::new();
        let at = |c: usize, _p: &[Ea4]| -> Ea4 { nx.get(c).copied().unwrap_or(Ea4::ZERO) };
        constraint.eval(&Row::new(rw, &oob), &at, x)
    };
    let (mut rw, mut nx) = (row.to_vec(), next.to_vec());
    let f0 = eval(&rw, &nx);
    if f0 == Ea4::ZERO {
        return Some((rw, nx));
    }
    let coords: Vec<usize> = if move_next { allowed.to_vec() } else { (0..row.len()).collect() };
    let put = |rw: &mut Vec<Ea4>, nx: &mut Vec<Ea4>, j: usize, v: Ea4| {
        if move_next {
            nx[j] = v;
        } else {
            rw[j] = v;
        }
    };
    for j in coords {
        if (move_next && j >= nx.len()) || (!move_next && j >= rw.len()) {
            continue;
        }
        let base = if move_next { nx[j] } else { rw[j] };
        let mut f = [f0; 4];
        for t in 1..4u64 {
            put(&mut rw, &mut nx, j, base + Ea4::from(Fa4::from_u64(t)));
            f[t as usize] = eval(&rw, &nx);
        }
        put(&mut rw, &mut nx, j, base);
        let s = f[1] - f[0];
        if s == Ea4::ZERO || f[2] - f[1] != s || f[3] - f[2] != s {
            continue;
        }
        put(&mut rw, &mut nx, j, base - f0 * s.inverse());
        if eval(&rw, &nx) == Ea4::ZERO {
            return Some((rw, nx));
        }
        put(&mut rw, &mut nx, j, base);
    }
    None
}

/// ⛔ TEST-ONLY ADVERSARY TOOL (DB-452, the direct family): a row `opened` with `constraint(opened, x) == 0`, found from
/// `base` by moving ONE column along which the γ-batched gate is affine with a nonzero slope (the first such column; a
/// gate pinning a committed cell to a public digest is affine in that cell). A decider that never binds `opened` to a
/// committed trace accepts a zerocheck whose rounds are all zero once this row is sent: the final check reads
/// `0 == eq(z, r)·C(opened)`. `at` reads `opened` itself — a row-local gate never calls it. `None` when no column moves
/// the gate affinely.
#[cfg(test)]
pub(crate) fn solve_opened_for_tests<C: AirConstraint>(constraint: &C, base: &[Ea4], x: &[Ea4]) -> Option<Vec<Ea4>> {
    let eval = |v: &[Ea4]| -> Ea4 {
        let oob = OobLatch::new();
        let at = |c: usize, _p: &[Ea4]| -> Ea4 { v.get(c).copied().unwrap_or(Ea4::ZERO) };
        constraint.eval(&Row::new(v, &oob), &at, x)
    };
    let f0 = eval(base);
    if f0 == Ea4::ZERO {
        return Some(base.to_vec());
    }
    let mut v = base.to_vec();
    for j in 0..base.len() {
        let mut f = [f0; 4];
        for t in 1..4u64 {
            v[j] = base[j] + Ea4::from(Fa4::from_u64(t));
            f[t as usize] = eval(&v);
        }
        v[j] = base[j];
        let s = f[1] - f[0];
        if s == Ea4::ZERO || f[2] - f[1] != s || f[3] - f[2] != s {
            continue;
        }
        v[j] = base[j] - f0 * s.inverse();
        if eval(&v) == Ea4::ZERO {
            return Some(v);
        }
        v[j] = base[j];
    }
    None
}

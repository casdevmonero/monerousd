// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ WELDING THE CONSTRAINED SPONGE TO A REAL PROOF'S TRANSCRIPT — the step that turns
//! `whir_rec_block`'s NATIVE Fiat-Shamir replay into a CONSTRAINED one.
//!
//! ## The hole this closes, restated exactly
//!
//! `whole_chain_cert`'s own STATUS section measures it: the recursion replays the inner proof's
//! transcript natively (`extract_air_direct_carrier_rows` observes the inner `public_bind`, walks the
//! zerocheck challenger, and exports only the resulting values as committed columns), so the inner
//! STATEMENT is a prover-chosen witness the outer verifier never sees. An n-step certificate over a real
//! chain and a one-step certificate over a fabricated state are the same object to a verifier — which is
//! why a party holding NO chain minted a certificate for an accumulator it invented and it verified.
//!
//! The fix is not a bigger check at the reader. It is to make the inner challenges UNCHOOSABLE: put the
//! sponge that derives them INSIDE the circuit ([`crate::sponge_chain_air`]) and WELD its squeezed cells
//! to the carrier's committed challenge cells. Then `r` is provably `Poseidon(statement)`, a prover that
//! wants different challenges must change the statement, and changing the statement changes `r`.
//!
//! ## What this module proves, and what it does not
//!
//! Six gates, all measured, in the order a build actually needs them:
//!   1. [`transcript_schedule`] derives the absorb/sample schedule of a REAL production carrier, and the
//!      CONSTRAINED path (`sponge_chain_air::replay` + `build_trace`) is shown to hold that carrier's
//!      actual `zc.r` challenges AT NAMED TRACE CELLS. The parity module proved the clear-text replay
//!      matches; this proves the cells a weld would grab hold the right values.
//!   2. The weld MECHANISM: a two-table batch (the sponge, plus a register standing in for the carrier's
//!      committed challenge columns) proved with `CrossTieSpec` entries binding sponge output cells to
//!      register cells. Honest verifies; a register carrying ANY other challenge is REFUSED, and the
//!      calibration half proves the SAME substitution verifies with no ties at all.
//!   3. The BOUND RECURSION STEP: [`prove_bound_merged_fixed_step_bytes`] proves the very step
//!      `whole_chain_cert` folds with — the merged-fixed carrier table — with the sponge that derives
//!      its challenges beside it and welded to it. MEASURED on a real production carrier: nvars=5,
//!      per=4, 101 cross-ties, a 31709-byte step.
//!   4. ⭐ THE REFUTATION GATE, the only one that cannot be passed by accident. A prover declares the
//!      honest inner statement, builds the merged table from the REAL carrier for it, and raises its
//!      sponge over a DIFFERENT statement of the same shape. Both tables satisfy their own gates and the
//!      public transcript is byte-identical, so every Fiat-Shamir challenge of the outer proof is
//!      unchanged and nothing in the system can notice — except the ties. MEASURED: it VERIFIES unwelded
//!      (28275 bytes) and is REFUSED welded. That is the join door's own attack, armed and then refused.
//!
//!   5. THE WHOLE IVC STEP: [`prove_ivc_step_bytes`] proves all THREE tables in one object — the
//!      merged-fixed carrier, the transcript sponge, and [`crate::acc_step_air`]'s accumulator/work
//!      recurrence — and welds the sponge cells that ABSORBED the inner statement into the recurrence
//!      that consumes them. That is `inner.acc_out == outer.acc_in`, in circuit, with the inherited
//!      accumulator and work never becoming public. MEASURED over a REAL previous step: nvars=5, per=10,
//!      237 cross-ties, a 67,663-byte step, work 2^70 → 2^70 + 2^30.
//!   6. ⭐ THE IVC REFUTATION GATE: a prover holding a real proof for one chain, whose accumulator table
//!      inherits a DIFFERENT chain with far more work. Every table satisfies its own gates and the public
//!      bind is the prover's own, so nothing diverges — except the ties. MEASURED: VERIFIES unwelded
//!      (58,964 bytes), REFUSED welded. That is `pin_d2b`'s attacker in its final form.
//!
//! ⛔⛔⛔ WHAT IS STILL NOT DONE, and saying so here is deliberate — the certificate module once carried
//! a header describing a property its code did not have, and that is the failure this tree pays most for:
//!   * ⛔⛔⛔ **THIS STEP HAS NO INDUCTION, AND IT CANNOT BE GIVEN ONE.** Gates 5 and 6 prove the weld
//!     MECHANISM against a SINGLE-TABLE stand-in that any party can mint for any accumulator and any
//!     work total; step i cannot consume step i-1's actual output (gate 7), and the weld itself does
//!     not survive a recursion level (the tie-carry gate: an outer proof stands over an object whose
//!     cross-ties are broken and whose own verifier refuses it). A cross-tie is checked by a READER of
//!     that proof and by nothing above it.
//!     ⭐ The one-table step (`ivc_one_table`: the same three parts in ONE table, every tie a row-local
//!     residual at a public row, a constant 135,315 bytes) was the answer to THIS gate — and then measured
//!     to have no fixpoint (a step of the certificate's own shape did not fit the certificate, 2026-09-27);
//!     it is deleted at source. The certificate is built on [`crate::certificate_door`] (Spartan-committed
//!     universal rows, WHIR openings: 178,093 B per step, a proven fixpoint at T = 2^14) — not on this module.
//!   * `whole_chain_cert` still folds with its own COMMUTATIVE accumulator and does not call any of this;
//!   * the NODE WIRING into `adopt_sync_bundle` behind the frozen-door law, and the adopter's fork choice
//!     reading the certificate's work total rather than a header's claim.
//! Until those land, `family_d_door_audit_tests::pin_d2b` stays RED and the join door stays open.
//!
//! ROOT-LAYER: the binding is made where the challenge is PRODUCED (the sponge's output cell), not where
//! it is later read. A reader-side check sees only numbers a prover chose; a cross-tie at the production
//! cell makes the number a function of the committed statement.
//!
//! MUST-STAY-GREEN: `sponge_chain_air`'s four gates (this module reuses its trace builder unchanged) and
//! `poseidon2_air_parity`'s five (the schedule below is the same walk its third gate pins).

use crate::hiding_decider::{Ea4, Fa4};
use crate::sponge_chain_air::{build_trace, pop_slot, replay, SpongeStep, OUTPUT_OFF};
pub use crate::whir_rec_block::{AirDirectBundle, CrossTieSpec};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

/// Base-field limbs in one `Ea4` challenge — `sample_algebra_element` draws exactly this many base
/// samples and assembles them as basis coefficients. Not a count of anything chain-sized.
pub const EXT_LIMBS: usize = 4;

/// Where one squeezed base limb lives in a sponge trace: `(row, column)`. This is the cell a cross-tie
/// welds, so it is returned rather than recomputed by each caller.
pub type LimbCell = (usize, usize);

/// Derive the EXACT absorb/sample schedule a verifier walks for one `AirDirectBundle`, in the form
/// [`crate::sponge_chain_air::replay`] consumes. Mirrors `verify_air_direct_light_decider_bytes` and
/// `extract_air_direct_carrier_rows`:
///   observe `public_bind` → `add_claim` (SAMPLE the opening point FIRST, then observe the evals)
///   → sample `gamma` → sample `z` (`nvars` of them) → per zerocheck round: observe that round's evals,
///   then sample `r_i`.
/// Returns `(absorb groups, samples after each group)`. `None` if the bundle is not the single-table
/// shape the extractor accepts — fail-closed, so a malformed carrier yields no schedule rather than a
/// plausible wrong one.
#[must_use]
pub fn transcript_schedule(
    bundle: &AirDirectBundle,
    public_bind: &[Fa4],
) -> Option<(Vec<Vec<Fa4>>, Vec<usize>)> {
    if bundle.shapes.len() != 1 || bundle.openings.len() != 1 {
        return None;
    }
    let (nvars, _width) = bundle.shapes[0];
    if nvars == 0 || bundle.zc.round_evals.len() != nvars || bundle.zc.r.len() != nvars {
        return None;
    }
    let limbs = |e: &Ea4| -> Vec<Fa4> {
        <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e).to_vec()
    };
    let mut absorbs: Vec<Vec<Fa4>> = Vec::new();
    let mut samples: Vec<usize> = Vec::new();

    // 1) the statement's public bind, then the opening point drawn BEFORE the evals are observed.
    absorbs.push(public_bind.to_vec());
    samples.push(EXT_LIMBS);
    // 2) the openings, then gamma and the zerocheck point z.
    absorbs.push(bundle.openings[0].iter().flat_map(|e| limbs(e)).collect());
    samples.push(EXT_LIMBS * (1 + nvars));
    // 3) the zerocheck round chain: this round's evals, then this round's challenge.
    for h in &bundle.zc.round_evals {
        absorbs.push(h.iter().flat_map(|e| limbs(e)).collect());
        samples.push(EXT_LIMBS);
    }
    Some((absorbs, samples))
}

/// Walk the recorded steps in pop order and report, for every squeezed base limb, the trace cell that
/// holds it. The k-th pop of a duplexing reads output slot [`pop_slot`], so the cell is
/// `(row, OUTPUT_OFF + pop_slot(k))` — the SAME cell the constraint folds and a cross-tie welds.
#[must_use]
pub fn squeezed_limb_cells(steps: &[SpongeStep]) -> Vec<LimbCell> {
    let mut out = Vec::new();
    for (row, st) in steps.iter().enumerate() {
        for k in 0..st.pops {
            out.push((row, OUTPUT_OFF + pop_slot(k)));
        }
    }
    out
}

/// Reassemble consecutive base limbs into the `Ea4` challenges a verifier would have sampled. The limb
/// ORDER is `sample_algebra_element`'s: basis coefficients in draw order.
#[must_use]
pub fn challenges_from_limbs(limbs: &[Fa4]) -> Vec<Ea4> {
    limbs
        .chunks_exact(EXT_LIMBS)
        .filter_map(|c| <Ea4 as BasedVectorSpace<Fa4>>::from_basis_coefficients_slice(c))
        .collect()
}

/// A REGISTER table: one row repeated, holding the challenge limbs a consumer circuit uses. It stands in
/// for the recursive carrier's committed `r` columns — same property that matters here, which is that
/// the value is a COMMITTED cell of a DIFFERENT table, reachable only through a cross-tie.
#[must_use]
pub fn register_trace(limbs: &[Fa4], rows: usize) -> Vec<Vec<Fa4>> {
    limbs.iter().map(|&v| vec![v; rows]).collect()
}

/// The register's own gate: every column is CONSTANT down the table. Without it a prover could put the
/// welded value in row 0 and anything it liked in the rows the consumer actually reads.
pub struct RegisterConstraint {
    pub width: usize,
    pub gamma: Ea4,
}

impl crate::air_zerocheck::AirConstraint for RegisterConstraint {
    fn degree(&self, _nvars: usize) -> usize {
        // The residual is a difference of two degree-1 openings; 8 matches the sponge table's declared
        // degree so both tables of the batch are evaluated at one shape. Over-declaring costs points and
        // is sound; under-declaring is not.
        8
    }
    fn eval(
        &self,
        local: &crate::air_zerocheck::Row<'_>,
        at: &dyn Fn(usize, &[Ea4]) -> Ea4,
        x: &[Ea4],
    ) -> Ea4 {
        let mut is_last = Ea4::ONE;
        for &xk in x {
            is_last *= xk;
        }
        let is_trans = Ea4::ONE - is_last;
        let mut acc = Ea4::ZERO;
        for c in 0..self.width {
            acc = acc * self.gamma + is_trans * (at(c, &[]) - local[c]);
        }
        acc
    }
}

/// The two-table batch's constraint: table 0 is the sponge, table 1 the register. One enum because the
/// batch prover takes ONE constraint type for every table it proves.
pub enum TieConstraint {
    Sponge(crate::sponge_chain_air::SpongeChainConstraint),
    Register(RegisterConstraint),
}

impl crate::air_zerocheck::AirConstraint for TieConstraint {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            Self::Sponge(c) => c.degree(nvars),
            Self::Register(c) => c.degree(nvars),
        }
    }
    fn eval(
        &self,
        local: &crate::air_zerocheck::Row<'_>,
        at: &dyn Fn(usize, &[Ea4]) -> Ea4,
        x: &[Ea4],
    ) -> Ea4 {
        match self {
            Self::Sponge(c) => c.eval(local, at, x),
            Self::Register(c) => c.eval(local, at, x),
        }
    }
}

/// The cross-ties that weld each register column to the sponge cell that PRODUCED its value. One tie per
/// base limb: the four limbs of an `Ea4` challenge usually share a row, but a duplexing may fall between
/// them, so nothing here assumes they do.
#[must_use]
pub fn weld(cells: &[LimbCell]) -> Vec<CrossTieSpec> {
    cells
        .iter()
        .enumerate()
        .map(|(i, &(row, col))| ((0usize, vec![col], row), (1usize, vec![i], 0usize)))
        .collect()
}

/// Build both tables for a schedule, padded to `rows`, plus the challenge the sponge folds to and the
/// cells its limbs live in. One place, so prover and verifier cannot lay them out differently.
#[must_use]
pub fn tie_tables(
    absorbs: &[Vec<Fa4>],
    samples: &[usize],
    rows: usize,
) -> (Vec<Vec<Vec<Fa4>>>, Fa4, Vec<LimbCell>, Vec<Fa4>) {
    let steps = replay(absorbs, samples);
    let cells = squeezed_limb_cells(&steps);
    let (sponge, chal) = build_trace(&steps, rows);
    let limbs: Vec<Fa4> = cells.iter().map(|&(r, c)| sponge[c][r]).collect();
    let register = register_trace(&limbs, rows);
    (vec![sponge, register], chal, cells, limbs)
}

/// The factory both sides derive independently: table 0 gets the sponge circuit bound to `expected_chal`,
/// table 1 the register gate at `reg_width`.
#[must_use]
pub fn make_tie_constraint(
    expected_chal: Fa4,
    reg_width: usize,
) -> impl Fn(usize, Ea4) -> TieConstraint + Clone {
    let sponge = crate::sponge_chain_air::make_constraint(expected_chal);
    move |table: usize, gamma: Ea4| match table {
        0 => TieConstraint::Sponge(sponge(gamma)),
        _ => TieConstraint::Register(RegisterConstraint { width: reg_width, gamma }),
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE BOUND RECURSION STEP — the same merged-fixed step the certificate folds with, plus the sponge
// that DERIVES its challenges, welded together.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The absorb-group lengths and sample counts a verifier walks for an inner carrier of PUBLIC shape
/// `(nvars, per, width)` under a bind of `pb_len` field elements. Lengths ONLY — no values — because the
/// cross-tie positions must be reconstructible by a verifier that holds the outer proof and nothing else.
/// This is the same walk [`transcript_schedule`] builds values for; sharing the shape here is what stops
/// the two from drifting. Every quantity is a FIXED PROOF SHAPE: nothing here counts blocks or notes.
#[must_use]
pub fn schedule_lens(nvars: usize, per: usize, width: usize, pb_len: usize) -> (Vec<usize>, Vec<usize>) {
    let mut lens = vec![pb_len, width * EXT_LIMBS];
    let mut samples = vec![EXT_LIMBS, EXT_LIMBS * (1 + nvars)];
    lens.extend(core::iter::repeat(per * EXT_LIMBS).take(nvars));
    samples.extend(core::iter::repeat(EXT_LIMBS).take(nvars));
    (lens, samples)
}

/// Simulate the challenger's buffer logic over absorb/sample COUNTS and report which trace cell every
/// absorbed element and every squeezed limb lands in, plus how many duplexings the schedule performs.
/// Mirrors [`crate::sponge_chain_air::replay`] step for step; it must, or the cells a verifier derives
/// are not the cells the prover filled. `None` when the schedule ends with buffered elements that never
/// reached a permutation — those live in no row, and silently dropping them would leave part of the
/// statement unbound.
#[must_use]
pub fn plan(absorb_lens: &[usize], samples_after: &[usize]) -> Option<(Vec<LimbCell>, Vec<LimbCell>, usize)> {
    use crate::sponge_chain_air::{ABSORB_OFF, RATE};
    if absorb_lens.len() != samples_after.len() {
        return None;
    }
    let (mut steps, mut buf_len, mut out_len) = (0usize, 0usize, 0usize);
    let mut pending: Vec<usize> = Vec::new();
    let (mut absorbed, mut squeezed): (Vec<LimbCell>, Vec<LimbCell>) = (Vec::new(), Vec::new());
    for (n_abs, n_samp) in absorb_lens.iter().zip(samples_after.iter()) {
        for _ in 0..*n_abs {
            out_len = 0;
            pending.push(buf_len);
            buf_len += 1;
            if buf_len == RATE {
                pending.drain(..).for_each(|slot| absorbed.push((steps, ABSORB_OFF + slot)));
                steps += 1;
                buf_len = 0;
                out_len = RATE;
            }
        }
        for _ in 0..*n_samp {
            if buf_len > 0 || out_len == 0 {
                pending.drain(..).for_each(|slot| absorbed.push((steps, ABSORB_OFF + slot)));
                steps += 1;
                buf_len = 0;
                out_len = RATE;
            }
            out_len -= 1;
            squeezed.push((steps - 1, OUTPUT_OFF + out_len));
        }
    }
    if !pending.is_empty() {
        return None; // fail-closed: trailing absorbs that never duplexed are in no row
    }
    Some((absorbed, squeezed, steps))
}

/// The cross-ties for one bound step, derived from PUBLIC shape alone so a remote verifier rebuilds them
/// byte-identically:
///   * every limb of the INNER BIND ↔ the outer statement's public IO (the verifier's own value);
///   * every limb of every zerocheck ROUND EVAL ↔ the merged table's committed eval column;
///   * every limb of every zerocheck CHALLENGE ↔ the merged table's committed `r` column.
///
/// The inner OPENINGS are absorbed but tied to nothing, and that is the standard Fiat-Shamir position
/// rather than an omission: they are committed cells of this same proof, so they are fixed before the
/// challenges are determined, and any change to them changes every challenge that follows. What must not
/// be free is the STATEMENT and the CHALLENGES, and both are welded.
#[must_use]
pub fn bound_step_ties(
    nvars: usize,
    per: usize,
    width: usize,
    bind_off: usize,
    pb_len: usize,
) -> Option<Vec<CrossTieSpec>> {
    let (lens, samples) = schedule_lens(nvars, per, width, pb_len);
    let (absorbed, squeezed, _steps) = plan(&lens, &samples)?;
    if absorbed.len() != lens.iter().sum::<usize>() || squeezed.len() != samples.iter().sum::<usize>() {
        return None; // fail-closed: the plan did not account for every element
    }
    let mut ties: Vec<CrossTieSpec> = Vec::new();
    // 1) the inner bind, welded to the outer statement's public IO.
    absorbed.iter().take(pb_len).enumerate().for_each(|(i, &(row, col))| {
        ties.push((
            (1usize, vec![col], row),
            (crate::whir_rec_block::PUBLIC_BIND_TABLE, vec![bind_off + i], 0usize),
        ));
    });
    // 2) the round evals, welded to the merged table's own committed eval columns. `fv`'s first
    //    `nvars*per` extension values ARE those evals, four base limbs each, in this order.
    let evals_off = pb_len + width * EXT_LIMBS;
    absorbed
        .iter()
        .skip(evals_off)
        .take(nvars * per * EXT_LIMBS)
        .enumerate()
        .for_each(|(i, &(row, col))| {
            ties.push(((1usize, vec![col], row), (0usize, vec![i], 0usize)));
        });
    // 3) the challenges: the LAST `nvars` extension samples of the walk are the round challenges, and
    //    `fv[nvars*per + k]` is where the merged table holds `r_k`.
    let tail = squeezed.len().checked_sub(EXT_LIMBS * nvars)?;
    let r_off = EXT_LIMBS * nvars * per;
    squeezed.iter().skip(tail).enumerate().for_each(|(i, &(row, col))| {
        ties.push(((1usize, vec![col], row), (0usize, vec![r_off + i], 0usize)));
    });
    Some(ties)
}

/// The batch's constraint: table 0 is the merged-fixed recursion step, table 1 the sponge that derives
/// its challenges. One enum because the batch prover takes ONE constraint type for every table.
pub enum BoundStepConstraint {
    Merged(crate::whir_rec_block::FixedDegreeMergedStepConstraint),
    Sponge(crate::sponge_chain_air::SpongeChainConstraint),
}

impl crate::air_zerocheck::AirConstraint for BoundStepConstraint {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            Self::Merged(c) => c.degree(nvars),
            Self::Sponge(c) => c.degree(nvars),
        }
    }
    fn eval(
        &self,
        local: &crate::air_zerocheck::Row<'_>,
        at: &dyn Fn(usize, &[Ea4]) -> Ea4,
        x: &[Ea4],
    ) -> Ea4 {
        match self {
            Self::Merged(c) => c.eval(local, at, x),
            Self::Sponge(c) => c.eval(local, at, x),
        }
    }
}

/// The factory both sides derive from PUBLIC parameters alone.
#[must_use]
pub fn make_bound_step_constraint(
    nvars0: usize,
    per0: usize,
    extra: Vec<Ea4>,
    chal_fold: Fa4,
) -> impl Fn(usize, Ea4) -> BoundStepConstraint + Clone {
    let (split, _w, _h) = crate::whir_rec_block::merged_fixed_shape(nvars0, per0, 1);
    let merged = crate::whir_rec_block::merged_fixed_step_make(nvars0, per0, split, extra);
    let sponge = crate::sponge_chain_air::make_constraint(chal_fold);
    move |table: usize, gamma: Ea4| match table {
        0 => BoundStepConstraint::Merged(merged(gamma)),
        _ => BoundStepConstraint::Sponge(sponge(gamma)),
    }
}

/// The outer statement of a bound step: the caller's own bind, then the INNER bind the recursion
/// verified, then the challenge fold the inner transcript produced. All three are what a verifier needs
/// and nothing more; laying them out in one place is what keeps prover and verifier byte-identical.
#[must_use]
pub fn bound_step_bind(out_bind: &[Fa4], carrier_bind: &[Fa4], chal_fold: Fa4) -> Vec<Fa4> {
    let mut b = out_bind.to_vec();
    b.extend_from_slice(carrier_bind);
    b.push(chal_fold);
    b
}

/// Build both tables of a bound step. `sponge_bind` is the statement the SPONGE absorbs; the public
/// entry always passes the real `carrier_bind`, and it is a separate parameter ONLY so the refutation
/// gate below can build the one forgery that matters — a sponge raised over a different statement than
/// the step declares, with the public transcript left untouched so nothing but the weld can catch it.
/// Module-private: a caller outside this file cannot reach the knob.
#[must_use]
#[allow(clippy::type_complexity)]
fn bound_step_tables(
    bundle_bytes: &[u8],
    carrier_bind: &[Fa4],
    sponge_bind: &[Fa4],
) -> Option<(Vec<Vec<Vec<Fa4>>>, Fa4, usize, usize, usize)> {
    let bundle: AirDirectBundle = postcard::from_bytes(bundle_bytes).ok()?;
    let (fv, ov, nvars0, per0) =
        crate::whir_rec_block::extract_fixed_degree_carrier_rows(bundle_bytes, carrier_bind)?;
    let (_nv, width) = *bundle.shapes.first()?;
    if sponge_bind.len() != carrier_bind.len() {
        return None; // fail-closed: the schedule SHAPE is public, so the two must agree on length
    }
    let (absorbs, samples) = transcript_schedule(&bundle, sponge_bind)?;
    let steps = replay(&absorbs, &samples);

    // The verifier derives the SAME cells from lengths alone; if the two ever disagreed the weld would
    // bind cells the prover never filled, so the agreement is CHECKED here rather than assumed.
    let (lens, samp2) = schedule_lens(nvars0, per0, width, carrier_bind.len());
    let (_ac, _sc, planned) = plan(&lens, &samp2)?;
    let real_lens: Vec<usize> = absorbs.iter().map(Vec::len).collect();
    if planned != steps.len() || samp2 != samples || lens != real_lens {
        return None; // fail-closed: the public plan and the real walk must be the same walk
    }

    // The merged step's trace is ONE row replicated to the decider's height — the crate's own carrier
    // shape (`LIGHT_CARRIER_ROWS`), built column-wise so no per-row pass exists at all.
    let (_split, _width_m, height) = crate::whir_rec_block::merged_fixed_shape(nvars0, per0, 1);
    let row: Vec<Fa4> = fv
        .iter()
        .chain(ov.iter())
        .flat_map(|val| {
            <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(val)[..EXT_LIMBS].to_vec()
        })
        .collect();
    let merged: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; height]).collect();

    let sponge_rows = steps.len().next_power_of_two().max(1 << 5);
    let (sponge, chal) = build_trace(&steps, sponge_rows);
    Some((vec![merged, sponge], chal, nvars0, per0, width))
}

/// PROVE a fixed-degree merged recursion step whose inner CHALLENGES are welded to a constrained sponge.
/// Identical in content to [`crate::whir_rec_block::prove_merged_fixed_step_bytes`] for one bundle, with
/// the sponge table and its cross-ties added — so the inner statement is no longer a witness the outer
/// verifier never sees. Returns the proof plus the PUBLIC values a verifier needs: the challenge fold and
/// the inner shape. Fail-closed on any shape mismatch.
#[must_use]
pub fn prove_bound_merged_fixed_step_bytes(
    bundle_bytes: &[u8],
    carrier_bind: &[Fa4],
    out_bind: &[Fa4],
    extra: &[Ea4],
) -> Option<(Vec<u8>, Fa4, usize, usize)> {
    let (tables, chal, nvars0, per0, width) =
        bound_step_tables(bundle_bytes, carrier_bind, carrier_bind)?;
    let ties = bound_step_ties(nvars0, per0, width, out_bind.len(), carrier_bind.len())?;
    let bind = bound_step_bind(out_bind, carrier_bind, chal);
    let bytes = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        tables,
        make_bound_step_constraint(nvars0, per0, extra.to_vec(), chal),
        Vec::new(),
        ties,
        Vec::new(),
        &bind,
    )?;
    Some((bytes, chal, nvars0, per0))
}

/// VERIFY a bound merged step. Every structural input is PUBLIC — the inner shape, the two binds and the
/// challenge fold — so the ties and the circuit are rebuilt from the statement, never from the prover's
/// object. Fail-closed.
#[must_use]
pub fn verify_bound_merged_fixed_step_bytes(
    bytes: &[u8],
    nvars0: usize,
    per0: usize,
    width: usize,
    carrier_bind: &[Fa4],
    out_bind: &[Fa4],
    extra: &[Ea4],
    chal_fold: Fa4,
    // ⛔ DB-213b — the table shapes this proof's STATEMENT fixes. No production path calls this entry; a
    // caller that ever does must derive them from its statement, never read them off the carrier.
    expected_constraint: &[(usize, usize)],
    expected_bus: &[(usize, usize)],
) -> bool {
    let Some(ties) = bound_step_ties(nvars0, per0, width, out_bind.len(), carrier_bind.len()) else {
        return false;
    };
    let bind = bound_step_bind(out_bind, carrier_bind, chal_fold);
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
        bytes,
        make_bound_step_constraint(nvars0, per0, extra.to_vec(), chal_fold),
        ties,
        Vec::new(),
        &bind,
        expected_constraint, expected_bus,
    )
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE IVC STEP — the bound recursion step PLUS the accumulator/work recurrence, welded so the
// `acc_in` a step claims to have inherited is the `acc_out` its inner proof actually committed to.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

use crate::acc_step_air as accs;

/// Domain separator for an IVC step's inner statement, so a certificate about the chain can never be
/// replayed as a proof about anything else.
pub const IVC_INNER_DOMAIN: u64 = 0x4956_435f_494e_4e; // "IVC_INN"
/// Domain separator for an IVC step's outer statement.
pub const IVC_OUTER_DOMAIN: u64 = 0x4956_435f_4f55_54; // "IVC_OUT"

/// The INNER statement of an IVC step: which protocol, the accumulator reached, and the work it cost.
/// Laid out in one place so the prover's absorbed bytes and the verifier's tie offsets cannot drift.
/// Index 0 is the domain, `1 ..= D` the accumulator, the rest the work limbs.
#[must_use]
pub fn ivc_inner_bind(acc: [u64; accs::D], work: u128) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(IVC_INNER_DOMAIN)];
    b.extend(acc.iter().map(|&v| Fa4::from_u64(crate::nullifier_insert_air::kred(v))));
    b.extend(accs::work_limbs(work).iter().map(|&v| Fa4::from_u64(v)));
    b
}
/// Offsets inside [`ivc_inner_bind`].
pub const INNER_ACC_OFF: usize = 1;
pub const INNER_WORK_OFF: usize = INNER_ACC_OFF + accs::D;
/// Length of an inner statement: domain + accumulator + work.
pub const INNER_BIND_LEN: usize = INNER_WORK_OFF + accs::WORK_LIMBS;

/// The OUTER statement: the step's own domain, the accumulator and work it REACHES, the summary it
/// applied and that block's work, and the transcript fold of the inner proof it verified. Everything an
/// adopter needs and nothing more.
#[must_use]
pub fn ivc_outer_bind(
    acc_out: [u64; accs::D],
    work_out: u128,
    summary: [u64; accs::D],
    block_work: u128,
    chal_fold: Fa4,
) -> Vec<Fa4> {
    let k = |v: u64| Fa4::from_u64(crate::nullifier_insert_air::kred(v));
    let mut b = vec![Fa4::from_u64(IVC_OUTER_DOMAIN)];
    b.extend(acc_out.iter().map(|&v| k(v)));
    b.extend(accs::work_limbs(work_out).iter().map(|&v| Fa4::from_u64(v)));
    b.extend(summary.iter().map(|&v| k(v)));
    b.extend(accs::work_limbs(block_work).iter().map(|&v| Fa4::from_u64(v)));
    b.push(chal_fold);
    // The INNER domain tag, carried publicly so the weld below can force the absorbed statement to be an
    // IVC statement and not some other protocol's bytes that happen to hash conveniently.
    b.push(Fa4::from_u64(IVC_INNER_DOMAIN));
    b
}
/// Offsets inside [`ivc_outer_bind`].
pub const OUTER_ACC_OFF: usize = 1;
pub const OUTER_WORK_OFF: usize = OUTER_ACC_OFF + accs::D;
pub const OUTER_SUMMARY_OFF: usize = OUTER_WORK_OFF + accs::WORK_LIMBS;
pub const OUTER_BLOCKWORK_OFF: usize = OUTER_SUMMARY_OFF + accs::D;
/// The inner domain tag sits after the challenge fold.
pub const OUTER_INNER_DOM_OFF: usize = OUTER_BLOCKWORK_OFF + accs::WORK_LIMBS + 1;
pub const OUTER_BIND_LEN: usize = OUTER_INNER_DOM_OFF + 1;

/// The three tables of an IVC step: the merged-fixed carrier, the transcript sponge, and the
/// accumulator step.
pub const T_MERGED: usize = 0;
pub const T_SPONGE: usize = 1;
pub const T_ACC: usize = 2;

/// The cross-ties of one IVC step, derived from PUBLIC shape alone so a remote verifier rebuilds them
/// byte-identically. Three groups, and the middle one is the whole point of the module:
///   * the transcript weld ([`bound_step_ties`]'s round-eval and challenge groups) — the inner proof's
///     challenges are Poseidon-derived from its own statement;
///   * ⭐ THE IVC LINK: the sponge cells that ABSORBED the inner statement's accumulator and work are
///     welded to the accumulator table's `acc_in` / `work_in`. `inner.acc_out == outer.acc_in`, in
///     circuit, with the inner values never becoming public;
///   * the outer statement: what this step REACHES (`acc_out`, `work_out`), what it APPLIED (`summary`,
///     the block's work) and the inner domain tag are welded to the verifier's own public IO.
#[must_use]
pub fn ivc_step_ties(nvars: usize, per: usize, width: usize) -> Option<Vec<CrossTieSpec>> {
    let (lens, samples) = schedule_lens(nvars, per, width, INNER_BIND_LEN);
    let (absorbed, squeezed, _steps) = plan(&lens, &samples)?;
    if absorbed.len() != lens.iter().sum::<usize>() || squeezed.len() != samples.iter().sum::<usize>() {
        return None; // fail-closed: the plan did not account for every element
    }
    let pubs = crate::whir_rec_block::PUBLIC_BIND_TABLE;
    let mut ties: Vec<CrossTieSpec> = Vec::new();

    // The inner DOMAIN tag is public — a step must have verified an IVC statement, not something else.
    let (row0, col0) = absorbed[0];
    ties.push(((T_SPONGE, vec![col0], row0), (pubs, vec![OUTER_INNER_DOM_OFF], 0usize)));

    // ⭐ THE IVC LINK. The inner statement's accumulator and work never become public; they are welded
    // from the cells that absorbed them straight into the recurrence that consumes them.
    absorbed.iter().skip(INNER_ACC_OFF).take(accs::D).enumerate().for_each(|(c, &(row, col))| {
        ties.push(((T_SPONGE, vec![col], row), (T_ACC, vec![accs::ACC_IN + c], 0usize)));
    });
    absorbed
        .iter()
        .skip(INNER_WORK_OFF)
        .take(accs::WORK_LIMBS)
        .enumerate()
        .for_each(|(k, &(row, col))| {
            ties.push(((T_SPONGE, vec![col], row), (T_ACC, vec![accs::WORK_IN + k], 0usize)));
        });

    // The transcript weld: round evals and challenges into the merged carrier's own committed columns.
    let evals_off = INNER_BIND_LEN + width * EXT_LIMBS;
    absorbed
        .iter()
        .skip(evals_off)
        .take(nvars * per * EXT_LIMBS)
        .enumerate()
        .for_each(|(i, &(row, col))| {
            ties.push(((T_SPONGE, vec![col], row), (T_MERGED, vec![i], 0usize)));
        });
    let tail = squeezed.len().checked_sub(EXT_LIMBS * nvars)?;
    let r_off = EXT_LIMBS * nvars * per;
    squeezed.iter().skip(tail).enumerate().for_each(|(i, &(row, col))| {
        ties.push(((T_SPONGE, vec![col], row), (T_MERGED, vec![r_off + i], 0usize)));
    });

    // The outer statement: what this step reached, and what it applied.
    let pub_cols = |off: usize, n: usize| -> Vec<usize> { (off..off + n).collect() };
    for (acc_col, pub_off, n) in [
        (accs::ACC_OUT, OUTER_ACC_OFF, accs::D),
        (accs::WORK_OUT, OUTER_WORK_OFF, accs::WORK_LIMBS),
        (accs::SUMMARY, OUTER_SUMMARY_OFF, accs::D),
        (accs::WORK_ADD, OUTER_BLOCKWORK_OFF, accs::WORK_LIMBS),
    ] {
        ties.push((
            (T_ACC, pub_cols(acc_col, n), 0usize),
            (pubs, pub_cols(pub_off, n), 0usize),
        ));
    }
    Some(ties)
}

/// The batch's constraint: merged-fixed step, transcript sponge, accumulator step.
pub enum IvcStepConstraint {
    Merged(crate::whir_rec_block::FixedDegreeMergedStepConstraint),
    Sponge(crate::sponge_chain_air::SpongeChainConstraint),
    Acc(accs::AccStepConstraint),
}

impl crate::air_zerocheck::AirConstraint for IvcStepConstraint {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            Self::Merged(c) => c.degree(nvars),
            Self::Sponge(c) => c.degree(nvars),
            Self::Acc(c) => c.degree(nvars),
        }
    }
    fn eval(
        &self,
        local: &crate::air_zerocheck::Row<'_>,
        at: &dyn Fn(usize, &[Ea4]) -> Ea4,
        x: &[Ea4],
    ) -> Ea4 {
        match self {
            Self::Merged(c) => c.eval(local, at, x),
            Self::Sponge(c) => c.eval(local, at, x),
            Self::Acc(c) => c.eval(local, at, x),
        }
    }
}

/// The factory both sides derive from PUBLIC parameters alone.
#[must_use]
pub fn make_ivc_constraint(
    nvars0: usize,
    per0: usize,
    chal_fold: Fa4,
) -> impl Fn(usize, Ea4) -> IvcStepConstraint + Clone {
    let (split, _w, _h) = crate::whir_rec_block::merged_fixed_shape(nvars0, per0, 1);
    let merged = crate::whir_rec_block::merged_fixed_step_make(nvars0, per0, split, Vec::new());
    let sponge = crate::sponge_chain_air::make_constraint(chal_fold);
    let acc = accs::make_acc_constraint();
    move |table: usize, gamma: Ea4| match table {
        T_MERGED => IvcStepConstraint::Merged(merged(gamma)),
        T_SPONGE => IvcStepConstraint::Sponge(sponge(gamma)),
        _ => IvcStepConstraint::Acc(acc(gamma)),
    }
}

/// Build the three tables of an IVC step. `sponge_acc` / `sponge_work` are what the SPONGE absorbs as the
/// inner statement; the public entry always passes the same values the accumulator table inherits, and
/// they are separate parameters ONLY so the refutation gate can build the one forgery that matters — an
/// accumulator table that inherits something the inner proof never committed to, with the public
/// transcript untouched so nothing but the weld can catch it. Module-private.
#[must_use]
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn ivc_step_tables(
    bundle_bytes: &[u8],
    sponge_acc: [u64; accs::D],
    sponge_work: u128,
    table_acc: [u64; accs::D],
    table_work: u128,
    summary: [u64; accs::D],
    block_work: u128,
    is_base: bool,
) -> Option<(Vec<Vec<Vec<Fa4>>>, Fa4, usize, usize, usize)> {
    let inner_bind = ivc_inner_bind(sponge_acc, sponge_work);
    let bundle: AirDirectBundle = postcard::from_bytes(bundle_bytes).ok()?;
    let (fv, ov, nvars0, per0) =
        crate::whir_rec_block::extract_fixed_degree_carrier_rows(bundle_bytes, &inner_bind)?;
    let (_nv, width) = *bundle.shapes.first()?;
    let (absorbs, samples) = transcript_schedule(&bundle, &inner_bind)?;
    let steps = replay(&absorbs, &samples);

    // The verifier derives the SAME cells from lengths alone; a disagreement would weld cells the prover
    // never filled, so it is CHECKED here rather than assumed.
    let (lens, samp2) = schedule_lens(nvars0, per0, width, INNER_BIND_LEN);
    let (_ac, _sc, planned) = plan(&lens, &samp2)?;
    let real_lens: Vec<usize> = absorbs.iter().map(Vec::len).collect();
    if planned != steps.len() || samp2 != samples || lens != real_lens {
        return None; // fail-closed: the public plan and the real walk must be the same walk
    }

    let (_split, _wm, height) = crate::whir_rec_block::merged_fixed_shape(nvars0, per0, 1);
    let row: Vec<Fa4> = fv
        .iter()
        .chain(ov.iter())
        .flat_map(|val| {
            <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(val)[..EXT_LIMBS].to_vec()
        })
        .collect();
    let merged: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; height]).collect();

    let sponge_rows = steps.len().next_power_of_two().max(1 << 5);
    let (sponge, chal) = build_trace(&steps, sponge_rows);
    let acc = accs::build_acc_trace(table_acc, summary, table_work, block_work, is_base, 1 << 5)?;
    Some((vec![merged, sponge, acc], chal, nvars0, per0, width))
}

/// PROVE one IVC step: recursively verify the inner proof with its challenges CONSTRAINED, and advance
/// the chain accumulator and the accumulated work in the same object. Returns the proof plus the PUBLIC
/// values a verifier needs. Fail-closed on any shape mismatch.
#[must_use]
pub fn prove_ivc_step_bytes(
    bundle_bytes: &[u8],
    inner_acc: [u64; accs::D],
    inner_work: u128,
    summary: [u64; accs::D],
    block_work: u128,
    is_base: bool,
) -> Option<(Vec<u8>, Fa4, usize, usize, usize)> {
    let (tables, chal, nvars0, per0, width) = ivc_step_tables(
        bundle_bytes,
        inner_acc,
        inner_work,
        inner_acc,
        inner_work,
        summary,
        block_work,
        is_base,
    )?;
    let acc_out = accs::acc_step_fold_native(accs::acc_effective(inner_acc, is_base), summary);
    let work_out = accs::work_effective(inner_work, is_base).checked_add(block_work)?;
    let ties = ivc_step_ties(nvars0, per0, width)?;
    let bind = ivc_outer_bind(acc_out, work_out, summary, block_work, chal);
    let bytes = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        tables,
        make_ivc_constraint(nvars0, per0, chal),
        Vec::new(),
        ties,
        Vec::new(),
        &bind,
    )?;
    Some((bytes, chal, nvars0, per0, width))
}

/// VERIFY one IVC step against the PUBLIC statement alone: the accumulator and work it claims to have
/// reached, the summary it applied, that block's work, the inner shape and the transcript fold. The
/// inherited accumulator and work are never named — they are the witness the weld pins. Fail-closed.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_ivc_step_bytes(
    bytes: &[u8],
    nvars0: usize,
    per0: usize,
    width: usize,
    acc_out: [u64; accs::D],
    work_out: u128,
    summary: [u64; accs::D],
    block_work: u128,
    chal_fold: Fa4,
    // ⛔ DB-213b — the table shapes this proof's STATEMENT fixes. No production path calls this entry; a
    // caller that ever does must derive them from its statement, never read them off the carrier.
    expected_constraint: &[(usize, usize)],
    expected_bus: &[(usize, usize)],
) -> bool {
    let Some(ties) = ivc_step_ties(nvars0, per0, width) else {
        return false;
    };
    let bind = ivc_outer_bind(acc_out, work_out, summary, block_work, chal_fold);
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
        bytes,
        make_ivc_constraint(nvars0, per0, chal_fold),
        ties,
        Vec::new(),
        &bind,
        expected_constraint, expected_bus,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::whir_rec_block::{
        prove_air_batch_light_decider_selfcontained_bytes_with_bus,
        prove_air_direct_light_decider_selfcontained_bytes, prove_spend_carrier_bytes,
        verify_air_batch_light_decider_selfcontained_bytes_with_bus, SpendRow, SPEND_CARRIER_DOMAIN,
    };

    /// The WHIR `nvars >= 5` floor this crate already pins the same way.
    const ROWS: usize = 32;

    /// A real carrier of the shape THIS WELD CONSUMES — the same gate, the same columns and the same
    /// public bind the production entry uses, proved on the DIRECT path.
    ///
    /// ⛔⛔⛔ AND THAT IS THE REMAINING WORK, STATED HERE RATHER THAN HIDDEN. Item 1 moved every
    /// value-carrying production carrier onto the BLINDED COMMITTED path, so
    /// `prove_spend_carrier_bytes` no longer returns an `AirDirectBundle`. The weld below still models
    /// the DIRECT verifier's transcript — `transcript_schedule` absorbs `bundle.openings[0]` before it
    /// can name γ, and a committed bundle has no `openings` vector at all: its pre-γ transcript is the
    /// COMMITMENT plus the OOD answers. That is a different schedule, not a different spelling, so the
    /// weld's migration is design work and is not done.
    ///
    /// ⭐ It is also the work §BP says is worth doing: the direct schedule absorbs 7,944 field elements
    /// before γ and the committed one absorbs 49, which is the 63x that decides whether a bound
    /// aggregate fits a 500 ms block. Building this fixture on the direct path keeps these gates
    /// testing the weld that EXISTS, and keeps the gap visible instead of turning it red and mute.
    fn real_carrier() -> (Vec<u8>, AirDirectBundle, Vec<Fa4>) {
        let bytes = direct_spend_carrier();
        let bundle: AirDirectBundle =
            postcard::from_bytes(&bytes).expect("the carrier decodes to its own bundle type");
        (bytes, bundle, vec![Fa4::from_u64(SPEND_CARRIER_DOMAIN)])
    }

    /// The direct-path twin of `prove_spend_carrier_bytes`, built from the same public pieces so the two
    /// cannot drift into different statements.
    pub(super) fn direct_spend_carrier() -> Vec<u8> {
        use crate::whir_rec_block::{
            spend_carrier_cols, spend_carrier_public_bind, SpendConservationGate,
        };
        let cols = spend_carrier_cols(&[SpendRow { in_value: 9, out_value: 5, fee: 4 }])
            .expect("the conservation carrier lays");
        let make = |gamma: Ea4| SpendConservationGate { gamma };
        prove_air_direct_light_decider_selfcontained_bytes(cols, make, &spend_carrier_public_bind())
            .expect("the direct carrier proves")
    }

    /// ⭐⭐⭐ GATE 1 — THE CONSTRAINED TRACE HOLDS A REAL PROOF'S CHALLENGES, AT NAMED CELLS.
    ///
    /// `poseidon2_air_parity` proved the clear-text replay reproduces `zc.r`. That is not yet enough to
    /// build on: the weld grabs CELLS of the committed trace, so what has to be true is that those cells
    /// hold those values. This reads the challenges back out of the trace columns a cross-tie would
    /// reference and demands they reassemble, in order, to the carrier's own `zc.r`.
    #[test]
    fn the_constrained_trace_holds_a_real_carriers_challenges_at_the_cells_a_weld_grabs() {
        let (bytes, bundle, pb) = real_carrier();
        let (absorbs, samples) =
            transcript_schedule(&bundle, &pb).expect("a real single-table carrier has a schedule");
        let steps = replay(&absorbs, &samples);
        let cells = squeezed_limb_cells(&steps);
        let (trace, _chal) = build_trace(&steps, steps.len().next_power_of_two().max(ROWS));
        let limbs: Vec<Fa4> = cells.iter().map(|&(r, c)| trace[c][r]).collect();
        let drawn = challenges_from_limbs(&limbs);

        // The walk draws the opening point, gamma and z before the round challenges; the LAST `nvars`
        // extension samples are the zerocheck challenges. Derived from the bundle, never a literal.
        let nvars = bundle.zc.r.len();
        assert!(drawn.len() > nvars, "the walk must draw more than the round challenges: {}", drawn.len());
        let tail = &drawn[drawn.len() - nvars..];
        assert_eq!(
            tail,
            bundle.zc.r.as_slice(),
            "⛔ the committed trace does NOT hold the challenges the REAL proof was built with. A weld \
             onto these cells would bind values the prover never saw — silent unsoundness."
        );
        eprintln!(
            "[transcript-bind] a real {} byte carrier's {nvars} zerocheck challenge(s) sit in the trace \
             at {} squeezed cell(s) across {} permutation row(s)",
            bytes.len(),
            cells.len(),
            steps.len()
        );
    }

    /// A short schedule with the same SHAPE as a real transcript (an `Ea4` draw off one duplexing), kept
    /// small so the two-table batch below proves in test time. The weld is what is under test here, not
    /// the transcript length.
    fn weld_schedule() -> (Vec<Vec<Fa4>>, Vec<usize>) {
        let g = |n: usize, s: u64| -> Vec<Fa4> {
            (0..n).map(|i| Fa4::from_u64(s + i as u64)).collect()
        };
        (vec![g(8, 11), g(3, 200), g(9, 400)], vec![0, EXT_LIMBS, EXT_LIMBS])
    }

    /// ⭐⭐⭐ GATE 2 — THE WELD HOLDS: a register that carries any OTHER challenge is REFUSED.
    ///
    /// This is the mechanism the join door needs. The sponge table proves the challenges were produced
    /// by a real sponge over the committed absorbs; the cross-tie proves the consumer used THOSE values
    /// and not values of its choosing. Both sides build their circuit and their tie list independently,
    /// exactly as a server and a remote adopter do.
    #[test]
    fn a_register_carrying_a_substituted_challenge_is_refused_by_the_weld() {
        let (absorbs, samples) = weld_schedule();
        let (tables, chal, cells, limbs) = tie_tables(&absorbs, &samples, ROWS);
        assert!(cells.len() >= 2 * EXT_LIMBS, "the schedule must squeeze several limbs: {}", cells.len());
        let bind = [Fa4::from_u64(0x5457_4c44)]; // "TWLD"
        let reg_w = limbs.len();

        let proof = prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables.clone(),
            make_tie_constraint(chal, reg_w),
            Vec::new(),
            weld(&cells),
            Vec::new(),
            &bind)
        .expect("an honest welded pair proves");
        assert!(
            verify_air_batch_light_decider_selfcontained_bytes_with_bus(
                &proof,
                make_tie_constraint(chal, reg_w), // INDEPENDENT: derived, not the prover's object
                weld(&cells),
                Vec::new(),
                &bind, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).1),
            "an independently-derived adopter must accept an honest weld"
        );
        eprintln!(
            "[transcript-bind] welded {} limb(s) across 2 tables; an independent adopter accepted {} \
             byte(s)",
            cells.len(),
            proof.len()
        );

        // THE FORGERY: the sponge is untouched and perfect; only the consumer's register is changed, to
        // a challenge the transcript never produced. This is precisely the freedom the native replay
        // leaves a prover, so it is the case that must fail.
        //
        // ⛔ THE WHOLE COLUMN MOVES, not one cell. Changing row 0 alone would break the register's OWN
        // constant-column gate, and the refusal would prove nothing about the weld — the detector under
        // test would never have been consulted. A forgery must be legal everywhere EXCEPT at the
        // mechanism being tested.
        let mut forged = tables.clone();
        for r in 0..ROWS {
            forged[1][0][r] += Fa4::ONE;
        }
        let accepted = match prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            forged.clone(),
            make_tie_constraint(chal, reg_w),
            Vec::new(),
            weld(&cells),
            Vec::new(),
            &bind) {
            None => false,
            Some(p) => verify_air_batch_light_decider_selfcontained_bytes_with_bus(
                &p,
                make_tie_constraint(chal, reg_w),
                weld(&cells),
                Vec::new(),
                &bind,
                &crate::whir_rec_block::declared_bus_shapes_for_tests(&p).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&p).1,
            ),
        };
        assert!(
            !accepted,
            "⛔ SUBSTITUTED CHALLENGE ACCEPTED: the weld does not bind the consumer to the sponge, so a \
             recursion built on it would still let a prover choose the inner challenges — the join door \
             unchanged."
        );

        // ⭐ THE ATTACK IS ARMED, AND THE WELD IS WHAT REFUSED IT. Run the SAME forged tables with NO
        // cross-ties: both gates still hold, and the forgery VERIFIES. Without this the refusal above
        // could have come from some other constraint and the weld could be doing nothing at all.
        let unwelded = prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            forged,
            make_tie_constraint(chal, reg_w),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &bind)
        .expect("the forged pair still satisfies both tables' own gates");
        assert!(
            verify_air_batch_light_decider_selfcontained_bytes_with_bus(
                &unwelded,
                make_tie_constraint(chal, reg_w),
                Vec::new(),
                Vec::new(),
                &bind, &crate::whir_rec_block::declared_bus_shapes_for_tests(&unwelded).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&unwelded).1),
            "⛔ CALIBRATION FAILED: the forged pair was refused even with NO cross-ties, so the case \
             above never exercised the weld. Fix the forgery, not the assertion."
        );
        eprintln!(
            "[transcript-bind] calibrated: the same substitution VERIFIES with no weld ({} byte(s)) and \
             is REFUSED with it",
            unwelded.len()
        );
    }

    /// ⭐⭐⭐ GATE 3 — THE RECURSION STEP ITSELF IS BOUND. A carrier whose committed challenges are not
    /// the ones its own transcript produces is REFUSED.
    ///
    /// This is the join door's hinge. `whole_chain_cert`'s STATUS section measures the hole exactly: the
    /// recursion replays Fiat-Shamir natively, so `r` is a prover-chosen witness and an n-step
    /// certificate over a real chain is the same object as a one-step certificate over a fabrication.
    /// Here the SAME merged-fixed step is proved with the sponge that derives `r` sitting beside it and
    /// welded to it. The honest step verifies for a party that rebuilds the ties from PUBLIC shape alone;
    /// a step whose committed `r` was moved is refused, and the calibration proves the weld is what
    /// refused it.
    #[test]
    fn a_recursion_step_whose_committed_challenge_is_not_its_transcripts_is_refused() {
        let (bytes, bundle, pb) = real_carrier();
        let (_nv, width) = bundle.shapes[0];
        let out = [Fa4::from_u64(0x424F_554E)]; // "BOUN" — this step's own statement
        let extra: [Ea4; 0] = [];

        let (proof, chal, nvars0, per0) =
            prove_bound_merged_fixed_step_bytes(&bytes, &pb, &out, &extra)
                .expect("an honest carrier proves a bound step");
        assert!(
            verify_bound_merged_fixed_step_bytes(
                &proof, nvars0, per0, width, &pb, &out, &extra, chal,
                &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).1,
            ),
            "a verifier rebuilding the ties from PUBLIC shape must accept an honest bound step"
        );
        eprintln!(
            "[transcript-bind] BOUND recursion step over a real {} byte carrier: nvars={nvars0} per={per0}, \
             {} tie(s), proof {} byte(s)",
            bytes.len(),
            bound_step_ties(nvars0, per0, width, out.len(), pb.len()).expect("ties").len(),
            proof.len()
        );

        // ⛔ HONEST READING OF THE TWO REFUSALS BELOW: both change the STATEMENT, which is observed at
        // the transcript start, so the challenger diverges and the proof would fail even with no weld at
        // all. They pin that the fold and the inner bind are part of the statement — real, but WEAK. The
        // gate that actually tests the weld is the next one, where the public transcript is identical.
        let wrong = chal + Fa4::ONE;
        assert!(
            !verify_bound_merged_fixed_step_bytes(
                &proof, nvars0, per0, width, &pb, &out, &extra, wrong,
                &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).1,
            ),
            "⛔ the bound step accepted a different challenge fold — the sponge is not binding the step"
        );

        // AND the inner STATEMENT: a verifier checking a different inner bind must refuse, because the
        // bind's limbs are welded to the sponge cells that absorbed them. This is the one that matters
        // for the join door: it is what stops a party with no chain naming an accumulator it invented.
        let other_pb = [Fa4::from_u64(0x5350_4e44_5f76_31 ^ 1)];
        assert_eq!(other_pb.len(), pb.len(), "the counterfactual bind must be the same SHAPE, or the \
             refusal could be a length check rather than the weld");
        assert!(
            !verify_bound_merged_fixed_step_bytes(
                &proof, nvars0, per0, width, &other_pb, &out, &extra, chal,
                &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).1,
            ),
            "⛔ the bound step accepted a DIFFERENT inner statement — the recursion still lets a prover \
             choose what it claims to have verified, and the join door is unchanged."
        );
        eprintln!(
            "[transcript-bind] the bound step refused a substituted challenge fold AND a substituted \
             inner statement (statement-level; the weld itself is pinned by the next gate)"
        );
    }

    /// ⭐⭐⭐ GATE 4 — THE REFUTATION GATE. A step whose SPONGE was raised over a different statement than
    /// the step declares, with the public transcript byte-identical, is refused ONLY by the weld.
    ///
    /// This is the one that cannot be passed by accident. The prover declares inner bind `pb` and builds
    /// the merged table from the real carrier for `pb` — both honest. Its sponge, however, absorbs `pb'`.
    /// Both tables still satisfy their own gates, the public bind is unchanged so every Fiat-Shamir
    /// challenge of the OUTER proof is unchanged, and nothing in the system notices — except the
    /// cross-ties, which demand the cells that absorbed the statement hold the statement the verifier
    /// knows. The calibration half proves exactly that: with the SAME tables and NO ties, the forgery
    /// VERIFIES. That is the attack this whole module exists to stop, armed and then refused.
    #[test]
    fn a_sponge_raised_over_a_different_statement_is_refused_by_the_weld_alone() {
        let (bytes, bundle, pb) = real_carrier();
        let (_nv, width) = bundle.shapes[0];
        let out = [Fa4::from_u64(0x424F_554E)];
        let extra: [Ea4; 0] = [];
        // A DIFFERENT inner statement of the SAME shape — so the schedule, the plan and the tie list are
        // all byte-identical and the refusal cannot come from a length or layout check.
        let other: Vec<Fa4> = pb.iter().map(|&v| v + Fa4::ONE).collect();
        assert_ne!(other, pb, "the counterfactual statement must differ");

        let (tables, chal, nvars0, per0, w2) = bound_step_tables(&bytes, &pb, &other)
            .expect("a sponge over another statement still builds two valid tables");
        assert_eq!(w2, width, "the inner shape is unchanged by the forgery");
        let ties = bound_step_ties(nvars0, per0, width, out.len(), pb.len()).expect("ties");
        // The proof DECLARES `pb` — the honest statement — while its sponge absorbed `other`.
        let bind = bound_step_bind(&out, &pb, chal);

        let welded = match crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables.clone(),
            make_bound_step_constraint(nvars0, per0, extra.to_vec(), chal),
            Vec::new(),
            ties.clone(),
            Vec::new(),
            &bind) {
            None => false,
            Some(p) => crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
                &p,
                make_bound_step_constraint(nvars0, per0, extra.to_vec(), chal),
                ties.clone(),
                Vec::new(),
                &bind,
                &crate::whir_rec_block::declared_bus_shapes_for_tests(&p).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&p).1,
            ),
        };
        assert!(
            !welded,
            "⛔ A SPONGE OVER A FOREIGN STATEMENT WAS ACCEPTED. The recursion still lets a prover claim \
             it verified something it did not, which is the join door exactly as measured."
        );

        // ⭐ THE ATTACK IS ARMED. Same tables, same statement, NO cross-ties: it VERIFIES. Without this
        // half the refusal above could have come from anywhere, and the weld could be doing nothing.
        let unwelded = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables,
            make_bound_step_constraint(nvars0, per0, extra.to_vec(), chal),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &bind)
        .expect("the forged pair satisfies both tables' own gates");
        assert!(
            crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
                &unwelded,
                make_bound_step_constraint(nvars0, per0, extra.to_vec(), chal),
                Vec::new(),
                Vec::new(),
                &bind, &crate::whir_rec_block::declared_bus_shapes_for_tests(&unwelded).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&unwelded).1),
            "⛔ CALIBRATION FAILED: the forgery was refused with NO ties, so the case above never \
             exercised the weld. Fix the forgery, not the assertion."
        );
        eprintln!(
            "[transcript-bind] ⭐ a sponge raised over a FOREIGN statement VERIFIES unwelded ({} byte(s)) \
             and is REFUSED by the {} cross-tie(s) — the native replay's freedom is gone",
            unwelded.len(),
            ties.len()
        );
    }

    /// ⛔⛔⛔ NOT A PREVIOUS STEP — A STAND-IN, AND THE DISTINCTION IS THE JOIN DOOR. This lays an
    /// accumulator trace for `(acc, work)` and proves it under the IVC inner statement. ANY party can
    /// do that for ANY accumulator and ANY work total; no chain is consulted and nothing below it is
    /// verified. Step i-1's real output is a THREE-TABLE batch carrying 241 cross-ties.
    ///
    /// ⭐ This doc previously read *"literally what step i-1 hands step i"*. It was false, and the
    /// falsehood is what let gates 5 and 6 read as an induction when they are only a weld MECHANISM —
    /// exactly the failure this tree pays most for (a header describing a property the code lacks).
    /// `an_ivc_chain_composes_step_on_step_so_only_a_base_step_can_begin` holds the real requirement.
    fn previous_step(acc: [u64; accs::D], work: u128) -> Vec<u8> {
        let summary = crate::poseidon2_compress::lanes_of(&[3u64, 1, 4, 1]);
        let trace = accs::build_acc_trace(acc, summary, work, 0, false, 1 << 5)
            .expect("the previous step lays out");
        prove_air_direct_light_decider_selfcontained_bytes(
            trace,
            accs::make_acc_constraint(),
            &ivc_inner_bind(acc, work),
        )
        .expect("the previous step proves")
    }

    /// ⭐⭐⭐ GATE 5 — ONE WHOLE IVC STEP. The inner proof is verified with its challenges CONSTRAINED,
    /// and the chain accumulator and accumulated work advance in the same object, against a statement
    /// that never names what the step inherited.
    #[test]
    fn an_ivc_step_verifies_and_advances_the_accumulator_and_the_work() {
        let inner_acc = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let inner_work = 1u128 << 70;
        let summary = crate::poseidon2_compress::lanes_of(&[101u64, 202, 303, 404]);
        let block_work = 1u128 << 30;
        let prev = previous_step(inner_acc, inner_work);

        let (proof, chal, nvars0, per0, width) =
            prove_ivc_step_bytes(&prev, inner_acc, inner_work, summary, block_work, false)
                .expect("an honest IVC step proves");
        let acc_out = accs::acc_step_fold_native(inner_acc, summary);
        let work_out = inner_work + block_work;
        assert!(
            verify_ivc_step_bytes(
                &proof, nvars0, per0, width, acc_out, work_out, summary, block_work, chal,
                &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).1,
            ),
            "a verifier holding only the PUBLIC statement must accept an honest IVC step"
        );
        eprintln!(
            "[ivc] one step over a real previous step: nvars={nvars0} per={per0}, {} tie(s), {} byte(s); \
             acc advanced and work {inner_work} -> {work_out}",
            ivc_step_ties(nvars0, per0, width).expect("ties").len(),
            proof.len()
        );
    }

    /// ⭐⭐⭐ GATE 6 — THE REFUTATION GATE FOR THE IVC LINK. A step whose accumulator table inherits
    /// something its INNER PROOF never committed to is refused, and only the weld can refuse it.
    ///
    /// The prover holds a real proof for `(acc, work)` and its sponge absorbs exactly that statement — so
    /// the transcript weld is satisfied and the recursion is honest. Its ACCUMULATOR TABLE, however,
    /// inherits an accumulator and a work total of its own choosing, and it publishes the outer statement
    /// those produce. Every table satisfies its own gates and the public bind is the prover's own, so
    /// nothing diverges — except the ties from the absorbed inner statement into the recurrence. The
    /// calibration half proves it: with the SAME tables and NO ties, the forgery VERIFIES.
    ///
    /// This is `pin_d2b`'s attacker in its final form — claiming to have inherited a chain it did not —
    /// and it is what `inner.acc_out == outer.acc_in` exists to stop.
    #[test]
    fn a_step_inheriting_what_its_inner_proof_never_committed_is_refused_by_the_weld_alone() {
        let inner_acc = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let inner_work = 1u128 << 40;
        let summary = crate::poseidon2_compress::lanes_of(&[101u64, 202, 303, 404]);
        let block_work = 1u128 << 30;
        let prev = previous_step(inner_acc, inner_work);

        // What the forger WISHES it had inherited: a different chain, with vastly more work.
        let wished_acc = crate::poseidon2_compress::lanes_of(&[77u64, 88, 99, 111]);
        let wished_work = 1u128 << 100;
        assert_ne!(wished_acc, inner_acc, "the counterfactual chain must differ");
        assert!(wished_work > inner_work, "the point of the forgery is MORE work than it holds");

        let (tables, chal, nvars0, per0, width) = ivc_step_tables(
            &prev, inner_acc, inner_work, wished_acc, wished_work, summary, block_work, false,
        )
        .expect("the forged trio still lays out");
        let acc_out = accs::acc_step_fold_native(wished_acc, summary);
        let work_out = wished_work + block_work;
        let bind = ivc_outer_bind(acc_out, work_out, summary, block_work, chal);
        let ties = ivc_step_ties(nvars0, per0, width).expect("ties");

        let welded = match crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables.clone(),
            make_ivc_constraint(nvars0, per0, chal),
            Vec::new(),
            ties.clone(),
            Vec::new(),
            &bind) {
            None => false,
            Some(p) => crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
                &p,
                make_ivc_constraint(nvars0, per0, chal),
                ties.clone(),
                Vec::new(),
                &bind,
                &crate::whir_rec_block::declared_bus_shapes_for_tests(&p).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&p).1,
            ),
        };
        assert!(
            !welded,
            "⛔ A STEP INHERITED A CHAIN ITS INNER PROOF NEVER COMMITTED TO. `inner.acc_out == \
             outer.acc_in` is not enforced, so a party can graft a real proof onto an invented history \
             and claim its work — the join door exactly as measured."
        );

        // ⭐ THE ATTACK IS ARMED. Same tables, same statement, NO cross-ties: it VERIFIES.
        let unwelded = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            tables,
            make_ivc_constraint(nvars0, per0, chal),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &bind)
        .expect("the forged trio satisfies every table's own gates");
        assert!(
            crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
                &unwelded,
                make_ivc_constraint(nvars0, per0, chal),
                Vec::new(),
                Vec::new(),
                &bind, &crate::whir_rec_block::declared_bus_shapes_for_tests(&unwelded).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&unwelded).1),
            "⛔ CALIBRATION FAILED: the forgery was refused with NO ties, so the case above never \
             exercised the weld. Fix the forgery, not the assertion."
        );
        eprintln!(
            "[ivc] ⭐ a step inheriting a chain its inner proof never committed to VERIFIES unwelded ({} \
             byte(s)) and is REFUSED by the {} cross-tie(s)",
            unwelded.len(),
            ties.len()
        );
    }

    /// ⛔⛔⛔ GATE 7 — THE THREE-TABLE STEP CANNOT COMPOSE, AND THAT IS WHY THE CERTIFICATE LIVES ELSEWHERE
    /// ([`crate::certificate_door`]; the one-table `ivc_one_table` that first answered this is deleted at
    /// source). This gate holds the STRUCTURAL FACT, so nobody rediscovers it by building on this step.
    ///
    /// Gates 5 and 6 prove the weld MECHANISM: a step's accumulator table inherits exactly what its
    /// inner proof committed to. They feed it [`previous_step`] — a SINGLE-TABLE accumulator proof
    /// **any party can mint for any accumulator and any work total**. Step i-1's real output is a
    /// THREE-TABLE batch carrying the 241 cross-ties that are what make it sound, and NO fold path recurses
    /// over a tied object at all (the bus-bundle fold extractor that refused them was deleted 2026-09-29 with
    /// its only caller; its reason stands — a tie is bound to the INNER commitment, which the outer circuit
    /// does not represent). So a step here may only inherit from an object with no chain behind it:
    /// there is no induction, and `is_base` is not the only way to begin.
    ///
    /// ⭐ The fix was never to relax the refusal — it was to stop needing it. The one-table step put the
    /// merged carrier, the sponge and the accumulator in ONE table and turned every cross-tie into a
    /// row-local residual at a PUBLIC row (`eq(row, x)`, the general case of the `is_first` these gates
    /// already use) — a constant 135,315 bytes, and no fixpoint (deleted at source). The certificate step that
    /// replaced it (`certificate_door`) runs the whole inner verifier as universal rows over a Spartan-committed
    /// witness with WHIR openings: 178,093 B per step, a proven fixpoint at T = 2^14 (2026-09-28).
    #[test]
    fn the_three_table_step_cannot_compose_which_is_why_the_one_table_step_exists() {
        let a0 = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let w0 = 1u128 << 70;
        let s1 = crate::poseidon2_compress::lanes_of(&[101u64, 202, 303, 404]);
        let bw = 1u128 << 30;

        // CALIBRATION — the hole is real HERE: a party holding NO chain mints the inner object itself
        // and the step stands. This is what an induction would make impossible.
        let wished = crate::poseidon2_compress::lanes_of(&[0xDEADu64, 0xBEEF, 0xFEED, 0xFACE]);
        let wished_work = 1u128 << 120;
        let fabricated = previous_step(wished, wished_work);
        let forged = prove_ivc_step_bytes(&fabricated, wished, wished_work, s1, bw, false);
        let forged_stands = forged.as_ref().is_some_and(|(p, chal, nv, pr, wd)| {
            verify_ivc_step_bytes(
                p,
                *nv,
                *pr,
                *wd,
                accs::acc_step_fold_native(wished, s1),
                wished_work + bw,
                s1,
                bw,
                *chal,
                &crate::whir_rec_block::declared_bus_shapes_for_tests(p).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(p).1,
            )
        });
        assert!(
            forged_stands,
            "CALIBRATION FAILED — if a chainless party can no longer mint a standing three-table step, \
             this gate has stopped describing the object it is about. Re-measure before editing it."
        );

        // THE STRUCTURAL FACT: step i+1 cannot consume step i's ACTUAL output.
        let prev = previous_step(a0, w0);
        let (step1, chal1, nv1, pr1, wd1) =
            prove_ivc_step_bytes(&prev, a0, w0, s1, bw, false).expect("step 1 proves");
        let acc1 = accs::acc_step_fold_native(a0, s1);
        let work1 = w0 + bw;
        assert!(
            verify_ivc_step_bytes(&step1, nv1, pr1, wd1, acc1, work1, s1, bw, chal1, &crate::whir_rec_block::declared_bus_shapes_for_tests(&step1).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&step1).1),
            "step 1 must verify before composition is even a question"
        );
        let s2 = crate::poseidon2_compress::lanes_of(&[5u64, 6, 7, 8]);
        assert!(
            prove_ivc_step_bytes(&step1, acc1, work1, s2, bw, false).is_none(),
            "⛔ THE THREE-TABLE STEP NOW COMPOSES. If that is deliberate, the cross-tie laundering \
             measured on the since-deleted bus-bundle fold extractor (a tie is bound to the INNER commitment) \
             says the composition is UNSOUND — a tie is checked by a reader of the step and by nothing \
             above it. Use the certificate step (`certificate_door`) instead, or prove that measurement no longer reproduces."
        );
        eprintln!(
            "[ivc-3table] chainless forgery STANDS here ({} byte(s)); step 2 over step 1's real output \
             is REFUSED — no induction. The composing chain lives in `certificate_door`.",
            step1.len()
        );
    }
}

/// ⭐ §BD COST PROBE — where the weld's time goes, on the PRODUCTION spend-validity carrier (depth 64).
/// Run: cargo test -p usdm-decider --release weld_cost_probe -- --ignored --nocapture
#[cfg(test)]
mod weld_cost_probe {
    use super::*;
    use crate::sponge_chain_air::{build_trace, make_constraint, replay};
    use crate::whir_rec_block::{
        prove_air_direct_light_decider_selfcontained_bytes, prove_spend_carrier_bytes,
        prove_spend_validity_carrier_with_commit_bytes, validity_public_bind_with_commit,
        verify_air_direct_light_decider_selfcontained_bytes, SpendRow, SpendValidityWitness,
        SPEND_CARRIER_DOMAIN,
    };
    use p3_koala_bear::KoalaBear;
    use std::time::Instant;

    fn production_validity_carrier() -> (Vec<u8>, AirDirectBundle, Vec<Fa4>) {
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
        let t = Instant::now();
        let (bytes, cms, nf, commit) =
            prove_spend_validity_carrier_with_commit_bytes(&w, crate::whir_rec_block::test_clue_digest(0)).expect("production validity carrier proves");
        eprintln!("[weld-probe] WALLET prove of the (pathless, constant-shape) validity carrier: {} ms, {} B", t.elapsed().as_millis(), bytes.len());
        let bundle: AirDirectBundle = postcard::from_bytes(&bytes).expect("decodes");
        let pb = validity_public_bind_with_commit(
            &[crate::whir_rec_block::to_f(&cms[0]), crate::whir_rec_block::to_f(&cms[1])],
            &crate::whir_rec_block::to_f(&nf),
            &crate::whir_rec_block::to_f(&commit),
            &crate::whir_rec_block::to_f(&crate::whir_rec_block::test_clue_digest(0)),
            &crate::whir_rec_block::to_f(&crate::whir_rec_block::spend_tag1(&w)),
        );
        (bytes, bundle, pb)
    }

    #[test]
    #[ignore] // measurement probe, not a gate
    fn weld_cost_probe() {
        // ── 1. The production carrier's shape and transcript ──────────────────────────────────────
        let (bytes, bundle, pb) = production_validity_carrier();
        let (nvars, width) = bundle.shapes[0];
        let opening_limbs = bundle.openings.iter().map(|v| v.len()).sum::<usize>() * 4;
        let (absorbs, samples) = transcript_schedule(&bundle, &pb).expect("schedule");
        let steps = replay(&absorbs, &samples);
        let absorbed: usize = absorbs.iter().map(|a| a.len()).sum();
        eprintln!(
            "[weld-probe] validity carrier: nvars={nvars} width={width} opening_limbs={opening_limbs} \
             absorbed_elems={absorbed} samples={} sponge_steps(permutations)={} pb_len={}",
            samples.iter().sum::<usize>(), steps.len(), pb.len()
        );
        // The small conservation carrier the existing weld tests use, for scale.
        let small = super::tests::direct_spend_carrier();
        let sb: AirDirectBundle = postcard::from_bytes(&small).expect("decodes");
        let spb = vec![Fa4::from_u64(SPEND_CARRIER_DOMAIN)];
        let (sa, ss) = transcript_schedule(&sb, &spb).expect("schedule");
        eprintln!("[weld-probe] small conservation carrier: width={} sponge_steps={}", sb.shapes[0].1, replay(&sa, &ss).len());

        // ── 2. The one-carrier weld (two tables + ties), production shape ─────────────────────────
        let out = [Fa4::from_u64(0x424F_554E)];
        let extra: [Ea4; 0] = [];
        let t = Instant::now();
        let welded = prove_bound_merged_fixed_step_bytes(&bytes, &pb, &out, &extra);
        let prove_ms = t.elapsed().as_millis();
        match welded {
            Some((proof, chal, nv0, p0)) => {
                let t = Instant::now();
                let ok = verify_bound_merged_fixed_step_bytes(&proof, nv0, p0, width, &pb, &out, &extra, chal, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).1);
                eprintln!(
                    "[weld-probe] ONE-CARRIER WELD (production validity carrier): prove {prove_ms} ms, verify {} ms, {} B, ok={ok}, ties={}",
                    t.elapsed().as_millis(), proof.len(),
                    bound_step_ties(nv0, p0, width, out.len(), pb.len()).map(|t| t.len()).unwrap_or(0)
                );
            }
            None => eprintln!("[weld-probe] ONE-CARRIER WELD: prover returned None after {prove_ms} ms"),
        }

        // ── 3. Sponge-only scaling: K concatenated walks of this carrier's transcript ─────────────
        for k in [1usize, 4, 16, 32] {
            let mut all_absorbs: Vec<Vec<KoalaBear>> = Vec::new();
            let mut all_samples: Vec<usize> = Vec::new();
            for _ in 0..k {
                all_absorbs.extend(absorbs.iter().cloned());
                all_samples.extend(samples.iter().cloned());
            }
            let ksteps = replay(&all_absorbs, &all_samples);
            let rows = ksteps.len().next_power_of_two().max(1 << 5);
            let (trace, chal) = build_trace(&ksteps, rows);
            let t = Instant::now();
            let proof = prove_air_direct_light_decider_selfcontained_bytes(trace, make_constraint(chal), &[chal]);
            let pm = t.elapsed().as_millis();
            let (ok, vm, sz) = match proof {
                Some(p) => {
                    let t = Instant::now();
                    let ok = verify_air_direct_light_decider_selfcontained_bytes(&p, make_constraint(chal), &[chal], crate::whir_rec_block::declared_direct_shape_for_tests(&p));
                    (ok, t.elapsed().as_millis(), p.len())
                }
                None => (false, 0, 0),
            };
            eprintln!(
                "[weld-probe] SPONGE-ONLY x{k}: {} permutation rows (padded {rows}) → prove {pm} ms, verify {vm} ms, {sz} B, ok={ok}",
                ksteps.len()
            );
        }
    }
}

/// ⛔⛔⛔ §BD-2 REFUTATION — CAN THE ONE-CARRIER WELD BE PASSED WITH NO INNER PROOF, IF THE SPONGE IS HONEST?
///
/// `bound_step_ties` welds the inner bind, the round evals and the challenges `r`. It leaves the absorbed
/// OPENINGS untied ("the standard Fiat-Shamir position") and the OPENING CHAIN (`γ_j`, masks, targets) is
/// not in the sponge's schedule at all. So: absorb the honest bind, ZERO openings and ZERO evals, let the
/// sponge derive `r` honestly, lay a merged row that holds those `r` with zero evals, zero claimed_final
/// and a zero opening half. Every tie holds by construction. If it verifies, the weld binds the
/// challenges to a statement but never binds a proof to the challenges.
#[cfg(test)]
mod one_carrier_weld_refutation {
    use super::*;
    use crate::sponge_chain_air::{build_trace, replay};
    use crate::whir_rec_block::{
        extract_fixed_degree_carrier_rows, merged_fixed_shape, prove_spend_carrier_bytes,
        prove_air_batch_light_decider_selfcontained_bytes_with_bus, SpendRow, SPEND_CARRIER_DOMAIN,
    };
    use p3_koala_bear::KoalaBear;

    #[test]
    fn a_bound_step_over_zero_evals_with_an_honestly_derived_r_is_measured() {
        // The honest carrier only lends its SHAPE (nvars, per, width, ov length) — nothing else of it is used.
        let bytes = super::tests::direct_spend_carrier();
        let bundle: AirDirectBundle = postcard::from_bytes(&bytes).expect("decodes");
        let pb = vec![Fa4::from_u64(SPEND_CARRIER_DOMAIN)];
        let (fv, ov, nvars0, per0) = extract_fixed_degree_carrier_rows(&bytes, &pb).expect("rows");
        let (_nv, width) = bundle.shapes[0];
        let (lens, samples) = schedule_lens(nvars0, per0, width, pb.len());
        let (_absorbed, squeezed, _steps) = plan(&lens, &samples).expect("plan");

        // THE FORGED WALK: honest bind, then zeros for every opening and every eval.
        let mut absorbs: Vec<Vec<KoalaBear>> = Vec::with_capacity(lens.len());
        absorbs.push(pb.clone());
        for &l in lens.iter().skip(1) {
            absorbs.push(vec![KoalaBear::default(); l]);
        }
        let steps = replay(&absorbs, &samples);
        let sponge_rows = steps.len().next_power_of_two().max(1 << 5);
        let (sponge, chal) = build_trace(&steps, sponge_rows);
        // The challenges the sponge actually squeezed — read from the very cells the ties will weld.
        let tail = squeezed.len() - EXT_LIMBS * nvars0;
        let limbs: Vec<Fa4> = squeezed[tail..].iter().map(|&(r, c)| sponge[c][r]).collect();
        let r: Vec<Ea4> = challenges_from_limbs(&limbs);
        assert_eq!(r.len(), nvars0);

        // THE FORGED MERGED ROW in the FIXED-DEGREE layout `[evals | r | claim | P | S | cf]`: zero evals,
        // the sponge's r, claim_k = 0 (the Lagrange fold of zeros), P/S computed HONESTLY from r (the
        // recurrences force them — a zeroed latch is a malformed row, not a forgery), cf = 0, and a zero
        // opening half.
        let (nv, per) = (nvars0, per0);
        assert_eq!(fv.len(), 3 * nv * per + 2 * nv + 1, "fixed-degree row layout");
        let mut forged_fv: Vec<Ea4> = vec![Ea4::ZERO; fv.len()];
        for k in 0..nv {
            forged_fv[nv * per + k] = r[k];
            // P_{k,0} = 1, P_{k,j+1} = P_{k,j}·(r_k − x_j)
            let mut pk = Ea4::ONE;
            for j in 0..per {
                forged_fv[nv * per + 2 * nv + k * per + j] = pk;
                pk *= r[k] - Ea4::from(Fa4::from_u64(j as u64));
            }
            // S_{k,per−1} = 1, S_{k,j} = S_{k,j+1}·(r_k − x_{j+1})
            let mut sk = Ea4::ONE;
            for j in (0..per).rev() {
                forged_fv[2 * nv * per + 2 * nv + k * per + j] = sk;
                if j > 0 {
                    sk *= r[k] - Ea4::from(Fa4::from_u64(j as u64));
                }
            }
        }
        let forged_ov: Vec<Ea4> = vec![Ea4::ZERO; ov.len()];
        let (_split, _wm, height) = merged_fixed_shape(nvars0, per0, 1);
        let row: Vec<Fa4> = forged_fv
            .iter()
            .chain(forged_ov.iter())
            .flat_map(|val| <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(val)[..EXT_LIMBS].to_vec())
            .collect();
        let merged: Vec<Vec<Fa4>> = row.iter().map(|&v| vec![v; height]).collect();

        let out = [Fa4::from_u64(0x424F_554E)];
        let extra: [Ea4; 0] = [];
        let ties = bound_step_ties(nvars0, per0, width, out.len(), pb.len()).expect("ties");
        // ⭐ CONTROL FIRST: the HONEST tables through the SAME prove/verify calls must verify, or a
        // refusal below is an artefact of this construction rather than the weld.
        {
            let (htables, hchal, _n, _p, _w) = bound_step_tables(&bytes, &pb, &pb).expect("honest tables");
            let hbind = bound_step_bind(&out, &pb, hchal);
            let hproof = prove_air_batch_light_decider_selfcontained_bytes_with_bus(
                htables,
                make_bound_step_constraint(nvars0, per0, extra.to_vec(), hchal),
                Vec::new(),
                ties.clone(),
                Vec::new(),
                &hbind)
            .expect("the honest step proves through the same path");
            assert!(
                verify_bound_merged_fixed_step_bytes(&hproof, nvars0, per0, width, &pb, &out, &extra, hchal, &crate::whir_rec_block::declared_bus_shapes_for_tests(&hproof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&hproof).1),
                "CONTROL FAILED: the honest step does not verify through this construction, so nothing \
                 below can be read"
            );
            eprintln!("[§BD-2] control: the honest carrier verifies through the identical construction");
        }
        let bind = bound_step_bind(&out, &pb, chal);
        let forged = prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            vec![merged, sponge],
            make_bound_step_constraint(nvars0, per0, extra.to_vec(), chal),
            Vec::new(),
            ties.clone(),
            Vec::new(),
            &bind);
        let Some(proof) = forged else {
            eprintln!("[§BD-2] the prover REFUSED the zero-eval forgery — the weld is not forgeable this way");
            return;
        };
        let verifies = verify_bound_merged_fixed_step_bytes(&proof, nvars0, per0, width, &pb, &out, &extra, chal, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).1);
        eprintln!(
            "[§BD-2] one-carrier weld over ZERO evals / ZERO openings / ZERO opening-chain, r honestly sponge-derived, {} ties: proves=true verifies={verifies} ({} B)",
            ties.len(), proof.len()
        );
        // ⛔⛔⛔ §BD-2 — OPEN, MEASURED 2026-09-14, RECORDED RATHER THAN ASSERTED AWAY.
        //
        //   control: honest carrier verifies through the identical construction
        //   ZERO evals / ZERO openings / ZERO opening chain, r honestly sponge-derived, 101 ties:
        //   proves=true verifies=true (31709 B)
        //
        // The weld binds the CHALLENGES to the STATEMENT (bind ↔ public IO, evals ↔ row, r ↔ row) and
        // that is all it binds. Nothing binds a PROOF to those challenges:
        //   (b) `claimed_final` is never evaluated against the opened trace values — the native verifier's
        //       `claim_last == eq(z,r)·C_γ(openings)` has no in-circuit counterpart, so cf is free;
        //   (c) the opening chain is unanchored at both ends (`target_0` from the openings' mu, the final
        //       target from `prover_rand`) and its `γ_j` are not in the sponge's schedule — `which_half_of_
        //       the_merged_row_refuses_a_tamper` shows the entire opening half zeroed still verifies.
        // With P/S latches computed honestly from the sponge's r, the zero row satisfies every residual.
        // The fix is the full native verifier in-circuit — see docs/FUNDS-LOSS-KILL-LIST.md §BD-2.
        assert!(
            verifies,
            "⭐ §BD-2 IS CLOSED — the bound step now refuses a zero-eval forgery with honestly derived r. \
             Flip this to `assert!(!verifies, …)` and close §BD-2 in the kill list."
        );
    }
}

/// §BD-2b — WHICH HALF OF THE MERGED ROW IS LOAD-BEARING? Honest sponge + honest sumcheck half, with the
/// opening half zeroed; then honest everything with a wrong claimed_final. Whatever refuses is what the
/// N-row aggregate must carry forward unchanged.
#[cfg(test)]
mod one_carrier_weld_anatomy {
    use super::*;
    use crate::whir_rec_block::{
        extract_fixed_degree_carrier_rows, merged_fixed_shape, prove_spend_carrier_bytes,
        prove_air_batch_light_decider_selfcontained_bytes_with_bus, SpendRow, SPEND_CARRIER_DOMAIN,
    };

    fn row_of(fv: &[Ea4], ov: &[Ea4], height: usize) -> Vec<Vec<Fa4>> {
        let row: Vec<Fa4> = fv
            .iter()
            .chain(ov.iter())
            .flat_map(|val| <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(val)[..EXT_LIMBS].to_vec())
            .collect();
        row.iter().map(|&v| vec![v; height]).collect()
    }

    #[test]
    fn which_half_of_the_merged_row_refuses_a_tamper() {
        let bytes = super::tests::direct_spend_carrier();
        let bundle: AirDirectBundle = postcard::from_bytes(&bytes).expect("decodes");
        let pb = vec![Fa4::from_u64(SPEND_CARRIER_DOMAIN)];
        let (fv, ov, nvars0, per0) = extract_fixed_degree_carrier_rows(&bytes, &pb).expect("rows");
        let (_nv, width) = bundle.shapes[0];
        let (tables, chal, _, _, _) = bound_step_tables(&bytes, &pb, &pb).expect("tables");
        let sponge = tables[1].clone();
        let (_s, _w, height) = merged_fixed_shape(nvars0, per0, 1);
        let out = [Fa4::from_u64(0x424F_554E)];
        let extra: [Ea4; 0] = [];
        let ties = bound_step_ties(nvars0, per0, width, out.len(), pb.len()).expect("ties");
        let bind = bound_step_bind(&out, &pb, chal);
        let run = |merged: Vec<Vec<Fa4>>| -> Option<bool> {
            let p = prove_air_batch_light_decider_selfcontained_bytes_with_bus(
                vec![merged, sponge.clone()],
                make_bound_step_constraint(nvars0, per0, extra.to_vec(), chal),
                Vec::new(),
                ties.clone(),
                Vec::new(),
                &bind)?;
            Some(verify_bound_merged_fixed_step_bytes(&p, nvars0, per0, width, &pb, &out, &extra, chal, &crate::whir_rec_block::declared_bus_shapes_for_tests(&p).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&p).1))
        };
        let honest = run(row_of(&fv, &ov, height));
        let ov_zero = run(row_of(&fv, &vec![Ea4::ZERO; ov.len()], height));
        let mut fv_cf = fv.clone();
        let cf = nvars0 * per0 + nvars0;
        fv_cf[cf] = fv_cf[cf] + Ea4::ONE;
        let wrong_final = run(row_of(&fv_cf, &ov, height));
        let mut ov_one = ov.clone();
        ov_one[0] = ov_one[0] + Ea4::ONE;
        let one_mask = run(row_of(&fv, &ov_one, height));
        eprintln!(
            "[§BD-2b] honest={honest:?} · opening_half_zeroed={ov_zero:?} · claimed_final+1={wrong_final:?} · one_mask_coeff+1={one_mask:?}  (None = prover refused, Some(v) = verifier verdict)"
        );
        assert_eq!(honest, Some(true), "control");
    }
}

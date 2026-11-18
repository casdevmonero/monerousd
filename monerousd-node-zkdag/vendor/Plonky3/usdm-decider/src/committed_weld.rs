// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.


//! ⭐⭐⭐ THE WELD, ON THE COMMITTED CARRIER — §BD-2's close, assembled.
//!
//! ⛔⛔⛔ WHAT IS UNSOUND WITHOUT IT. §BD-2/§BD-3 measured a recursion step with NO inner proof
//! verifying: the existing constraints enforce the inner sumcheck's ROUND CHAIN and then anchor the end
//! at a committed cell tied to nothing, so a row of zeros satisfies every identity. §BH closed half of
//! that by bringing `claim_last == eq(z,r)·C_γ(opened)` into the circuit — but left the challenges
//! themselves as free cells, and a prover that picks its own γ picks the batching scalar that
//! Schwartz-Zippel assumes it cannot.
//!
//! ## The three things welded here, in ONE proof
//! 1. **The BOUND step** (`recursion_bound::BoundStepConstraint`) over a row laid by
//!    `bound_step_row_committed` — the inner AIR evaluated in circuit on the opened row.
//! 2. **The TRANSCRIPT** — a constrained sponge (`sponge_chain_air`) replaying the committed verifier's
//!    walk, whose schedule comes from `committed_air::committed_schedule_lens`.
//! 3. **The CROSS-TIES** — the sponge's own absorbed and squeezed CELLS equated to the step's public
//!    bind, its round evals and its challenges. §AJ is why these are ties inside one proof rather than
//!    public inputs between two: a tie that lives between proofs is a tie the recursion drops.
//!
//! ⭐ WHY THE SCHEDULE IS TRUSTWORTHY. §BS measured a hand-written mirror of the committed transcript
//! reproducing **0 of 6** of a real carrier's challenges — the PCS touches the challenger in ways
//! reading its verifier does not reveal. So the schedule is not transcribed: `committed_schedule_lens`
//! is read off a RECORDING of the real challenger and checked against it on every run
//! (`bt_the_full_recorded_walk_lands_on_the_carriers_own_challenges`). A formula is needed because the
//! OUTER verifier does not hold the inner carrier and cannot record anything.
//!
//! ⭐ AND WHY IT IS AFFORDABLE. §BP: the direct verifier absorbs the whole opening — 7,944 field
//! elements — before it can name γ; the committed one absorbs a COMMITMENT. Measured end to end, a
//! carrier's whole transcript is **25 duplexings** here against **117** on the direct path.

use crate::air_zerocheck::{AirConstraint, Row};
use crate::committed_air::{committed_schedule_lens, committed_schedule_params, EXT_LIMBS};
use crate::hiding_decider::{Ea4, Fa4};
use crate::recursion_bound::{constant_inner, BoundLayout, BoundStepConstraint};
use crate::sponge_chain_air::SpongeChainConstraint;
use crate::transcript_bind_air::{plan, CrossTieSpec};

/// The sponge table's height — the WHIR `nvars >= 5` floor this crate pins everywhere.
const SPONGE_MIN_ROWS: usize = 32;
/// The step table's height. The bound step is ROW-LOCAL, so one logical row replicated is the whole
/// trace; the height only has to clear the same floor.
const STEP_ROWS: usize = 32;

/// The weld's two tables under one constraint type, because the batch prover takes one.
pub enum CommittedWeldAir<C: AirConstraint + Clone + Sync> {
    /// Table 0 — the bound recursion step over the committed carrier.
    Step { gamma: Ea4, layout: BoundLayout, inner: C },
    /// Table 1 — the sponge that DERIVES that step's challenges.
    Sponge(SpongeChainConstraint),
}

impl<C: AirConstraint + Clone + Sync> AirConstraint for CommittedWeldAir<C> {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            Self::Step { gamma, layout, inner } => BoundStepConstraint {
                gamma: *gamma,
                layout: *layout,
                inner: constant_inner(inner.clone()),
            }
            .degree(nvars),
            Self::Sponge(c) => c.degree(nvars),
        }
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        match self {
            Self::Step { gamma, layout, inner } => BoundStepConstraint {
                gamma: *gamma,
                layout: *layout,
                inner: constant_inner(inner.clone()),
            }
            .eval(local, at, x),
            Self::Sponge(c) => c.eval(local, at, x),
        }
    }
}

/// The factory BOTH sides derive from public parameters alone — the prover cannot hand the verifier a
/// circuit, so the circuit is a function of the statement.
#[must_use]
pub fn make_committed_weld_constraint<C: AirConstraint + Clone + Sync>(
    layout: BoundLayout,
    inner: C,
    chal_fold: Fa4,
) -> impl Fn(usize, Ea4) -> CommittedWeldAir<C> + Clone {
    // ⛔ THE COMMITTED SEED. A committed carrier's challenger is built from `COMMITTED_AIR_SEED`, so the
    // sponge that replays its walk must use that permutation — under the direct one it reproduces the
    // schedule perfectly and lands on challenges the proof never saw (measured, see `replay_with_seed`).
    let sponge = crate::sponge_chain_air::make_constraint_with_seed(
        crate::committed_air::COMMITTED_AIR_SEED,
        chal_fold,
    );
    move |table: usize, gamma: Ea4| match table {
        0 => CommittedWeldAir::Step { gamma, layout, inner: inner.clone() },
        _ => CommittedWeldAir::Sponge(sponge(gamma)),
    }
}

/// The outer statement: the caller's own bind, the INNER bind the recursion verified, and the challenge
/// fold the inner transcript produced.
#[must_use]
pub fn committed_weld_bind(
    out_bind: &[Fa4],
    carrier_bind: &[Fa4],
    chal_fold: Fa4,
    inner_gamma: Ea4,
) -> Vec<Fa4> {
    let mut b = out_bind.to_vec();
    b.extend_from_slice(carrier_bind);
    b.push(chal_fold);
    // ⛔⛔⛔ γ IS PART OF THE STATEMENT, NOT A PARAMETER THE CALLER SUPPLIES. The outer verifier does not
    // hold the carrier, so it cannot recompute γ; if γ arrived as a bare argument a prover could hand a
    // γ chosen to make a forged opened row satisfy the inner AIR. It goes in the bind and is TIED to the
    // sponge cell that produced it, so "the γ you were given" and "the γ this transcript squeezed" are
    // one cell.
    b.extend_from_slice(&<Ea4 as p3_field::BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&inner_gamma)[..EXT_LIMBS]);
    b
}

/// Where γ's four limbs sit in [`committed_weld_bind`]'s output.
#[must_use]
pub fn committed_weld_gamma_off(out_len: usize, carrier_bind_len: usize) -> usize {
    out_len + carrier_bind_len + 1
}

/// The CROSS-TIES — the whole point of the weld.
///
/// Every one equates a CELL of the sponge table with a CELL of the step table (or of the public bind),
/// so the step's challenges are not values it declared but values the constrained sponge produced.
///
/// ⛔ DERIVED FROM PUBLIC NUMBERS ONLY. The outer verifier does not hold the inner carrier, so it cannot
/// record the walk; it rebuilds these cells from the shape through
/// `committed_air::committed_schedule_lens`, whose agreement with a real recording is gated every run.
#[must_use]
pub fn committed_weld_ties(
    nvars: usize,
    per: usize,
    width: usize,
    bind_off: usize,
    pb_len: usize,
) -> Option<Vec<CrossTieSpec>> {
    let (ood, cap_elems) = committed_schedule_params(nvars, width)?;
    let (lens, samples) = committed_schedule_lens(nvars, per, pb_len, ood, cap_elems)?;
    let (absorbed, squeezed, _steps) = plan(&lens, &samples)?;
    if absorbed.len() != lens.iter().sum::<usize>() || squeezed.len() != samples.iter().sum::<usize>() {
        return None; // fail-closed: the plan did not account for every element
    }
    let mut ties: Vec<CrossTieSpec> = Vec::new();
    // 1) THE INNER STATEMENT. The first `pb_len` elements the sponge absorbs are the carrier's own public
    //    bind, and they must BE the bind the outer statement declares — otherwise the step is welded to
    //    a transcript raised over someone else's statement.
    absorbed.iter().take(pb_len).enumerate().for_each(|(i, &(row, col))| {
        ties.push((
            (1usize, vec![col], row),
            (crate::whir_rec_block::PUBLIC_BIND_TABLE, vec![bind_off + i], 0usize),
        ));
    });
    // 2) THE ROUND EVALS. In the committed walk they begin after the public bind, the commitment and the
    //    OOD answers — `width` does not appear, which is exactly why this path is affordable (§BP).
    let evals_off = pb_len + cap_elems + ood * EXT_LIMBS;
    absorbed
        .iter()
        .skip(evals_off)
        .take(nvars * per * EXT_LIMBS)
        .enumerate()
        .for_each(|(i, &(row, col))| {
            ties.push(((1usize, vec![col], row), (0usize, vec![i], 0usize)));
        });
    // 3) THE CHALLENGES — the residual §BD-2 needed. The LAST `nvars` extension samples of the walk are
    //    the round challenges, and `BoundLayout::r_at(k)` is where the step holds `r_k`. Without this the
    //    step's `r` is a free cell and a prover chooses the batching scalar Schwartz-Zippel assumes it
    //    cannot.
    let tail = squeezed.len().checked_sub(EXT_LIMBS * nvars)?;
    let r_off = EXT_LIMBS * nvars * per;
    squeezed.iter().skip(tail).enumerate().for_each(|(i, &(row, col))| {
        ties.push(((1usize, vec![col], row), (0usize, vec![r_off + i], 0usize)));
    });
    // 4) ⛔⛔⛔ THE OOD POINT `z` — THE HOLE THIS WELD SHIPPED WITH FOR ONE AFTERNOON.
    //    `BoundStepConstraint` closes with `cf == eq(z,r) · C_γ(opened)` and reads `z` from a committed
    //    cell. `cf` is forced by the tied evals and `r` by the tied squeezes — but with `z` free the
    //    equation is SOLVABLE: pick any `opened`, then set
    //      z_0 = (cf / (C(opened) · Π_{k>0} eq_k) − (1−r_0)) / (2·r_0 − 1).
    //    One division. MEASURED `proves=true verifies=true` by
    //    `a_step_that_solves_for_z_to_excuse_a_foreign_opened_row_is_refused` before this group existed.
    //    ⭐ THE LESSON: a residual that READS a cell proves nothing about that cell. Every input to the
    //    closing equation must be tied, and "it was right in the honest trace" is not a constraint.
    //
    //    `committed_schedule_lens` puts γ then every z_k in the samples after the LAST OOD answer, so
    //    γ occupies `[EXT_LIMBS·ood, EXT_LIMBS·(ood+1))` and z the `EXT_LIMBS·nvars` after it.
    let z_sq = EXT_LIMBS * (ood + 1);
    let z_off = EXT_LIMBS * (nvars * per + nvars);
    squeezed
        .iter()
        .skip(z_sq)
        .take(EXT_LIMBS * nvars)
        .enumerate()
        .for_each(|(i, &(row, col))| {
            ties.push(((1usize, vec![col], row), (0usize, vec![z_off + i], 0usize)));
        });
    // 5) γ — the batching scalar the inner AIR is evaluated at. Tied to the PUBLIC bind so the verifier's
    //    γ is the sponge's γ, not a number the prover chose to suit a forged row.
    let g_bind = committed_weld_gamma_off(bind_off, pb_len);
    squeezed
        .iter()
        .skip(EXT_LIMBS * ood)
        .take(EXT_LIMBS)
        .enumerate()
        .for_each(|(i, &(row, col))| {
            ties.push((
                (1usize, vec![col], row),
                (crate::whir_rec_block::PUBLIC_BIND_TABLE, vec![g_bind + i], 0usize),
            ));
        });
    Some(ties)
}

/// Build both tables of a committed weld from a REAL carrier.
///
/// `sponge_bind` is the statement the SPONGE absorbs. The public entry always passes the real
/// `carrier_bind`; it is a separate parameter ONLY so a refutation gate can build the one forgery that
/// matters — a sponge raised over a DIFFERENT statement than the step declares, with the public
/// transcript left untouched so nothing but the weld can catch it.
#[allow(clippy::type_complexity)]
fn committed_weld_tables<C, Mk>(
    carrier_bytes: &[u8],
    carrier_bind: &[Fa4],
    sponge_bind: &[Fa4],
    make_inner: Mk,
) -> Option<(Vec<Vec<Vec<Fa4>>>, Fa4, BoundLayout)>
where
    C: AirConstraint + Clone + Sync,
    Mk: Fn(Ea4) -> C,
{
    if sponge_bind.len() != carrier_bind.len() {
        return None; // fail-closed: the schedule SHAPE is public, so the two must agree on length
    }
    let (limbs, layout, _gamma) =
        crate::recursion_bound::bound_step_row_committed(carrier_bytes, carrier_bind, 0, 0)?;
    let inner_gamma = crate::committed_air::transcript_of_committed_carrier(carrier_bytes, carrier_bind)?.0;
    let _ = make_inner(inner_gamma); // the caller's factory must accept the carrier's own γ

    // The sponge's own walk, over the statement it is TOLD to absorb.
    let (ood, cap_elems) = committed_schedule_params(layout.nvars, layout.width)?;
    let (lens, samples) = committed_schedule_lens(layout.nvars, layout.per, sponge_bind.len(), ood, cap_elems)?;
    let (_a, _s, planned) = plan(&lens, &samples)?;

    // The real absorbed elements, in the walk's order: the statement, the commitment, the OOD answers,
    // then each round's evals. Taken from the carrier so the sponge replays what the verifier replayed.
    let absorbs = crate::committed_air::committed_absorb_bursts(carrier_bytes, sponge_bind)?;
    if absorbs.iter().map(Vec::len).collect::<Vec<_>>() != lens {
        return None; // fail-closed: the public plan and the real walk must be the same walk
    }
    let steps = crate::sponge_chain_air::replay_with_seed(
        crate::committed_air::COMMITTED_AIR_SEED,
        &absorbs,
        &samples,
    );
    if steps.len() != planned {
        return None;
    }
    let sponge_rows = steps.len().next_power_of_two().max(SPONGE_MIN_ROWS);
    let (sponge, chal) = crate::sponge_chain_air::build_trace_with_seed(
        crate::committed_air::COMMITTED_AIR_SEED,
        &steps,
        sponge_rows,
    );

    // The step is ROW-LOCAL, so one logical row replicated is the whole trace.
    let step: Vec<Vec<Fa4>> = limbs.iter().map(|&v| vec![v; STEP_ROWS]).collect();
    Some((vec![step, sponge], chal, layout))
}

/// PROVE a committed weld: one proof whose step's challenges ARE its constrained sponge's output.
///
/// Returns the bytes plus the PUBLIC values a verifier needs — the challenge fold and the inner shape.
/// Fail-closed on any shape mismatch.
#[must_use]
pub fn prove_committed_weld_bytes<C, Mk>(
    carrier_bytes: &[u8],
    carrier_bind: &[Fa4],
    out_bind: &[Fa4],
    make_inner: Mk,
) -> Option<(Vec<u8>, Fa4, BoundLayout)>
where
    C: AirConstraint + Clone + Sync,
    Mk: Fn(Ea4) -> C,
{
    prove_committed_weld_with_sponge_bind(carrier_bytes, carrier_bind, carrier_bind, out_bind, make_inner)
}

/// The prover with the sponge's statement separated — module-private knob, see
/// [`committed_weld_tables`]. A caller outside this file cannot raise a sponge over a foreign statement.
#[allow(clippy::type_complexity)]
fn prove_committed_weld_with_sponge_bind<C, Mk>(
    carrier_bytes: &[u8],
    carrier_bind: &[Fa4],
    sponge_bind: &[Fa4],
    out_bind: &[Fa4],
    make_inner: Mk,
) -> Option<(Vec<u8>, Fa4, BoundLayout)>
where
    C: AirConstraint + Clone + Sync,
    Mk: Fn(Ea4) -> C,
{
    let (tables, chal, layout) =
        committed_weld_tables(carrier_bytes, carrier_bind, sponge_bind, &make_inner)?;
    let inner_gamma =
        crate::committed_air::transcript_of_committed_carrier(carrier_bytes, carrier_bind)?.0;
    let ties =
        committed_weld_ties(layout.nvars, layout.per, layout.width, out_bind.len(), carrier_bind.len())?;
    let bind = committed_weld_bind(out_bind, carrier_bind, chal, inner_gamma);
    let bytes = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
        tables,
        make_committed_weld_constraint(layout, make_inner(inner_gamma), chal),
        Vec::new(),
        ties,
        Vec::new(),
        &bind,
    )?;
    Some((bytes, chal, layout))
}

/// VERIFY a committed weld. Every structural input is PUBLIC — the inner shape, both binds, the
/// challenge fold and the inner γ — so the ties and the circuit are rebuilt from the statement, never
/// from the prover's object. Fail-closed.
#[must_use]
pub fn verify_committed_weld_bytes<C, Mk>(
    bytes: &[u8],
    layout: BoundLayout,
    carrier_bind: &[Fa4],
    out_bind: &[Fa4],
    inner_gamma: Ea4,
    chal_fold: Fa4,
    make_inner: Mk,
    // ⛔ DB-213b — the table shapes this proof's STATEMENT fixes. No production path calls this entry; a
    // caller that ever does must derive them from its statement, never read them off the carrier.
    expected_constraint: &[(usize, usize)],
    expected_bus: &[(usize, usize)],
) -> bool
where
    C: AirConstraint + Clone + Sync,
    Mk: Fn(Ea4) -> C,
{
    let Some(ties) =
        committed_weld_ties(layout.nvars, layout.per, layout.width, out_bind.len(), carrier_bind.len())
    else {
        return false;
    };
    let bind = committed_weld_bind(out_bind, carrier_bind, chal_fold, inner_gamma);
    crate::whir_rec_block::verify_air_batch_light_decider_selfcontained_bytes_with_bus(
        bytes,
        make_committed_weld_constraint(layout, make_inner(inner_gamma), chal_fold),
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
        spend_carrier_cols, spend_carrier_public_bind, SpendConservationGate, SpendRow,
    };
    use p3_field::{Field, PrimeCharacteristicRing}; // the tests' field arithmetic; the lib itself never needed it

    const OUT: [Fa4; 1] = [Fa4::new(0x5745_4c44)]; // "WELD"

    /// A REAL production carrier — the blinded committed one every value carrier now ships as.
    fn carrier() -> (Vec<u8>, Vec<Fa4>) {
        let cols = spend_carrier_cols(&[SpendRow { in_value: 9, out_value: 5, fee: 4 }])
            .expect("the conservation carrier lays");
        let pb = spend_carrier_public_bind().to_vec();
        let mk = |g: Ea4| SpendConservationGate { gamma: g };
        let bytes = crate::committed_air::prove_air_blinded_bytes(cols, mk, &pb)
            .expect("the production carrier proves");
        assert!(
            crate::committed_air::verify_air_blinded_bytes(&bytes, mk, &pb, crate::committed_air::declared_blinded_laid_shape_for_tests(&bytes)),
            "CONTROL: the inner carrier must verify before anything is welded to it"
        );
        (bytes, pb)
    }

    /// The inner γ a carrier's own transcript names — what a verifier recomputes, never what a prover says.
    fn gamma_of(bytes: &[u8], pb: &[Fa4]) -> Ea4 {
        crate::recursion_bound::bound_step_row_committed(bytes, pb, 0, 0).expect("the row lays").2
    }

    /// The inner AIR the weld evaluates — the SAME wrapped constraint the shipped carrier was proved
    /// against. A second, equivalent wrapper would be two spellings of one circuit (§AO).
    fn inner() -> impl Fn(Ea4) -> crate::committed_air::Blinded<SpendConservationGate> + Clone {
        |g: Ea4| crate::committed_air::Blinded { inner: SpendConservationGate { gamma: g } }
    }

    /// ⭐⭐ THE BOUND STEP CLOSES AT `r` — and the refutation that proves the point is load-bearing.
    ///
    /// §BH part (b) puts `cf == eq(z,r) · C_γ(opened)` in-circuit. `C_γ` is evaluated by the native
    /// verifier at `proof.r`. A first cut of `BoundStepConstraint` passed the OUTER zerocheck's `x`
    /// instead — which asserts a DIFFERENT EQUATION. Every row-local gate ignores the point, so the
    /// mistake was invisible on ten gates out of ten; `Blinded` reads `x[0]`, and the weld failed with
    /// nothing saying why. So this gate checks both arms: at `r` the equation holds, and at any other
    /// point it MUST NOT — a green arm alone would pass just as happily on a constraint that never
    /// looked at the point at all.
    #[test]
    fn the_bound_steps_equation_holds_at_r_and_nowhere_else() {
        use crate::air_zerocheck::{OobLatch, Row};
        let (bytes, pb) = carrier();
        let (limbs, layout, gamma) =
            crate::recursion_bound::bound_step_row_committed(&bytes, &pb, 0, 0).expect("the row lays");
        let (_g2, z) = crate::committed_air::transcript_of_committed_carrier(&bytes, &pb).expect("γ,z");
        let b: crate::committed_air::CommittedAirBundle =
            postcard::from_bytes(&bytes).expect("decodes");
        // Rebuild the Ea4 values from the limbs the row carries.
        let basis: [Ea4; 4] = core::array::from_fn(|i| {
            <Ea4 as p3_field::BasedVectorSpace<Fa4>>::ith_basis_element(i).expect("4 basis elements")
        });
        let get = |i: usize| -> Ea4 {
            let o = i * 4;
            basis[0] * limbs[o] + basis[1] * limbs[o + 1] + basis[2] * limbs[o + 2] + basis[3] * limbs[o + 3]
        };
        let mut eq = Ea4::ONE;
        for k in 0..layout.nvars {
            let (zk, rk) = (get(layout.z_at(k)), get(layout.r_at(k)));
            eq *= zk * rk + (Ea4::ONE - zk) * (Ea4::ONE - rk);
        }
        let opened: Vec<Ea4> = (0..layout.width).map(|c| get(layout.opened_at(c))).collect();
        let oob = OobLatch::new();
        let row = Row::new(&opened, &oob);
        let at = |c: usize, _p: &[Ea4]| -> Ea4 {
            b.zc.shifted_opened.get(c).copied().unwrap_or(Ea4::ZERO)
        };
        let r_pt: Vec<Ea4> = (0..layout.nvars).map(|k| get(layout.r_at(k))).collect();
        let c_at_r = inner()(gamma).eval(&row, &at, &r_pt);
        let cf = get(layout.cf());
        assert_eq!(
            z.len(),
            layout.nvars,
            "⛔ the row's z is not the transcript's z — the step is bound to the wrong challenge"
        );
        assert_eq!(
            cf,
            eq * c_at_r,
            "⛔ THE BOUND STEP'S OWN EQUATION DOES NOT HOLD on a real committed carrier's row — the \
             fault is the STEP, not the sponge or the ties."
        );

        // ⛔ REFUTATION. Close the same row at `z` instead of `r`. A constraint that ignores the point
        // would sail through both arms; this one must not, or the `r` arm above proves nothing.
        let z_pt: Vec<Ea4> = (0..layout.nvars).map(|k| get(layout.z_at(k))).collect();
        let c_at_z = inner()(gamma).eval(&row, &at, &z_pt);
        assert_ne!(
            c_at_r, c_at_z,
            "⛔ THE CLOSING EQUATION DOES NOT DEPEND ON THE POINT IT IS CLOSED AT, so the arm above is \
             vacuous: `C_γ` evaluated at `r` and at `z` returned the same value. A bound step whose \
             inner AIR is evaluated at the OUTER point would verify here. Either the gate lost its \
             `Blinded` wrapper or `BoundStepConstraint` stopped forwarding the point."
        );
        eprintln!(
            "[weld] the bound step closes at r ({} vars); closing it at z instead does NOT hold",
            layout.nvars
        );
    }

    /// ⛔⛔⛔ IS `z` A FREE CELL? The forgery that asks whether the weld's closing equation can be solved.
    ///
    /// `BoundStepConstraint` closes with `cf == eq(z,r) · C_γ(opened)`, reading `z` from `z_at(k)`.
    /// `cf` is FORCED — the claim chain derives it from the round evals, and those are tied to the
    /// sponge. `r` is tied to the sponge's squeezes. But `z` is read from a committed cell, and if
    /// nothing pins that cell a prover may choose ANY `opened` and then solve for `z_0`:
    ///
    /// ```text
    ///   eq(z,r) = product over k of [ z_k*r_k + (1-z_k)(1-r_k) ]   — affine in each z_k
    ///   want eq(z,r) = cf / C(opened')   =>   z_0 = (t - (1-r_0)) / (2*r_0 - 1)
    /// ```
    ///
    /// One division. If that forgery stands, the weld proves nothing about the opened row at all.
    #[test]
    fn a_step_that_solves_for_z_to_excuse_a_foreign_opened_row_is_refused() {
        let (bytes, pb) = carrier();
        let (tb, chal, layout) = committed_weld_tables(&bytes, &pb, &pb, inner()).expect("tables");
        let gamma = gamma_of(&bytes, &pb);
        let basis: [Ea4; 4] = core::array::from_fn(|i| {
            <Ea4 as p3_field::BasedVectorSpace<Fa4>>::ith_basis_element(i).expect("4 basis elements")
        });
        let val = |t: &Vec<Vec<Fa4>>, i: usize| -> Ea4 {
            let o = i * EXT_LIMBS;
            basis[0] * t[o][0] + basis[1] * t[o + 1][0] + basis[2] * t[o + 2][0] + basis[3] * t[o + 3][0]
        };
        // The step table is ONE logical row replicated to the fixed height `STEP_ROWS` — a named
        // constant, not a height that grows with anything.
        let put = |t: &mut Vec<Vec<Fa4>>, i: usize, v: Ea4| {
            let o = i * EXT_LIMBS;
            let c = <Ea4 as p3_field::BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&v);
            (0..EXT_LIMBS).for_each(|j| t[o + j] = vec![c[j]; STEP_ROWS]);
        };

        let mut step = tb[0].clone();
        let r: Vec<Ea4> = (0..layout.nvars).map(|k| val(&step, layout.r_at(k))).collect();
        let cf = val(&step, layout.cf());

        // THE FOREIGN OPENED ROW. One cell moved is enough — if the weld says nothing about `opened`,
        // it says nothing about the spend the carrier claims to have proved.
        let c0 = val(&step, layout.opened_at(0));
        put(&mut step, layout.opened_at(0), c0 + Ea4::ONE);

        // SOLVE FOR z_0. Evaluate the inner AIR on the forged opened row, at `r`, exactly as the circuit
        // will, then make `eq(z,r)` the ratio the closing equation needs.
        let opened: Vec<Ea4> = (0..layout.width).map(|c| val(&step, layout.opened_at(c))).collect();
        let b2: crate::committed_air::CommittedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
        let oob = crate::air_zerocheck::OobLatch::new();
        let row = crate::air_zerocheck::Row::new(&opened, &oob);
        let at = |c: usize, _p: &[Ea4]| -> Ea4 { b2.zc.shifted_opened.get(c).copied().unwrap_or(Ea4::ZERO) };
        let c_forged = inner()(gamma).eval(&row, &at, &r);
        let Some(inv) = c_forged.try_inverse() else {
            eprintln!("[weld] the forged opened row zeroed the inner AIR — no ratio to hit; not armed");
            return;
        };
        let mut tail = Ea4::ONE;
        for k in 1..layout.nvars {
            let zk = val(&step, layout.z_at(k));
            tail *= zk * r[k] + (Ea4::ONE - zk) * (Ea4::ONE - r[k]);
        }
        let Some(tail_inv) = tail.try_inverse() else {
            eprintln!("[weld] the honest eq tail is zero — forgery not armed on this carrier");
            return;
        };
        let t = cf * inv * tail_inv;
        let denom = r[0] + r[0] - Ea4::ONE;
        let Some(dinv) = denom.try_inverse() else {
            eprintln!("[weld] r_0 == 1/2 — the solve degenerates; forgery not armed on this carrier");
            return;
        };
        let z0 = (t - (Ea4::ONE - r[0])) * dinv;
        put(&mut step, layout.z_at(0), z0);

        // CALIBRATION — the solve must actually satisfy the closing equation, or the assert below is
        // asserting that a BROKEN forgery fails, which proves nothing.
        let mut eq = Ea4::ONE;
        for k in 0..layout.nvars {
            let zk = val(&step, layout.z_at(k));
            eq *= zk * r[k] + (Ea4::ONE - zk) * (Ea4::ONE - r[k]);
        }
        assert_eq!(
            cf,
            eq * c_forged,
            "CALIBRATION: the solve for z_0 must close the equation on the FORGED opened row, or this \
             test is not the attack it claims to be"
        );

        // THE ATTACK, through the real door.
        let ties = committed_weld_ties(layout.nvars, layout.per, layout.width, OUT.len(), pb.len())
            .expect("ties");
        let bind = committed_weld_bind(&OUT, &pb, chal, gamma);
        let forged = crate::whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus(
            vec![step, tb[1].clone()],
            make_committed_weld_constraint(layout, inner()(gamma), chal),
            Vec::new(),
            ties,
            Vec::new(),
            &bind,
        );
        let verifies = forged
            .as_ref()
            .is_some_and(|b| verify_committed_weld_bytes(b, layout, &pb, &OUT, gamma, chal, inner(), &crate::whir_rec_block::declared_bus_shapes_for_tests(b).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(b).1));
        eprintln!("[weld] z-solve forgery: proves={} verifies={verifies}", forged.is_some());
        assert!(
            !verifies,
            "⛔⛔⛔ THE WELD IS FORGEABLE ON A FREE `z`: a step carrying a FOREIGN opened row verified \
             because `z` is a committed cell tied to nothing, so `eq(z,r)` can be solved to excuse any \
             `C(opened)`. `z` is squeezed by the very sponge this weld already constrains — tie it."
        );
    }

    /// ⛔⛔⛔ THE WELD IS NOT YET A FIXPOINT — MEASURED, so nobody routes it into an IVC and finds out.
    ///
    /// `BoundLayout::values()` is `nvars·per + 3·nvars + 1 + width`: the step row carries the inner
    /// proof's ENTIRE opened row inline. Each value is 4 limbs, so one level's COLUMN count is about
    /// four times the inner's. `whole_chain_cert` iterates its step — level N's proof is level N+1's
    /// inner — so a non-fixpoint width does not cost more, it diverges.
    ///
    /// ⭐ THE TENSION, NAMED. Today's IVC step IS a fixpoint (135,315 B at any height) precisely
    /// BECAUSE its merged row `[evals | r | claim | P | S | cf]` carries no opening — which is why
    /// §BD-2 measured that it binds challenges to a statement and nothing to a proof. The weld binds
    /// to the proof by carrying the opening, and loses the fixpoint. **Soundness and fixpoint are in
    /// tension, and the resolution is not a tweak to either one**: the opened row has to move behind a
    /// commitment and be opened in-circuit as ROWS of a narrow table (§BK `opening_auth_air`, whose
    /// column count is fixed at 208 and whose HEIGHT carries the openings), with the inner AIR
    /// evaluated by accumulation across those rows. That is §BK (c3)/(c4), and it is still open.
    #[test]
    fn the_welds_width_grows_with_its_inners_so_it_cannot_yet_be_iterated() {
        let (bytes, pb) = carrier();
        let (_limbs, layout, _g) =
            crate::recursion_bound::bound_step_row_committed(&bytes, &pb, 0, 0).expect("the row lays");
        let (tb, _c, _l) = committed_weld_tables(&bytes, &pb, &pb, inner()).expect("tables");
        let step_cols = tb[0].len();

        // The step table's columns are the inner row's values in limbs — measured, not assumed.
        assert_eq!(
            step_cols,
            EXT_LIMBS * layout.values(),
            "the step table is one limb-column per value of `BoundLayout::values()`"
        );

        // ⛔ THE DIVERGENCE. Feed this level's own column count back in as the next level's inner width.
        let next = EXT_LIMBS * (layout.nvars * layout.per + 3 * layout.nvars + 1 + step_cols);
        assert!(
            next > step_cols,
            "CONTROL: if this ever fails the layout changed and the finding below is stale"
        );
        let factor = next as f64 / step_cols as f64;
        eprintln!(
            "[weld] ⛔ NOT A FIXPOINT: inner width {} cols -> step table {} cols -> next level {} cols \
             (x{factor:.2} per level). Routing this into `whole_chain_cert`'s iterated step diverges; \
             §BK (c3)/(c4) — the opening behind a commitment, opened as ROWS — is what makes it close.",
            layout.width, step_cols, next
        );
        assert!(
            factor > 2.0,
            "⭐ THE WELD MAY HAVE BECOME A FIXPOINT — growth per level fell to x{factor:.2}. If the \
             opening moved behind a commitment, delete this gate, route the certificate step through \
             the weld, and flip §BD-3's refutation to `assert!(!verifies, …)`."
        );
    }

    /// ⛔⛔⛔ §BD-3 THROUGH THE WELDED DOOR — the forgery that mints a chain from nothing, retried.
    ///
    /// The one-table IVC step's refutation (`ivc_one_table`, deleted at source 2026-09-28 — the whole-chain
    /// certificate is a chain of `certificate_door` steps now) measured, live, that a one-table step over NO
    /// inner proof claiming 2^100 of work PROVED and VERIFIED through the DIRECT door (9.9 s, 135,315 B,
    /// `verifies=true`) while `whole_chain_cert::verify_whole_chain_cert` called exactly that function — so the
    /// join door adopted a fork-choice weight no chain ever paid for. This asks the same question of the weld.
    ///
    /// Arm 1 — NO INNER PROOF. The forger's whole trick is that no proof exists below them. The weld's
    /// prover parses carrier BYTES; there are none to pass.
    ///
    /// Arm 2 — A MINTED INNER PROOF. So the forger mints the cheapest carrier they can and claims it
    /// stands for the chain that never existed: a real, honestly-proved committed carrier, welded to an
    /// outer statement that inherits 2^100 of work. This is the arm that matters, because it is the one
    /// a forger can actually reach.
    #[test]
    fn bd3_a_step_claiming_a_chain_that_never_existed_cannot_be_welded() {
        // ── ARM 1. No inner proof exists. The weld cannot be stated, let alone proved.
        for nothing in [&[][..], &[0u8; 64][..], &[0xFFu8; 512][..]] {
            assert!(
                prove_committed_weld_bytes(nothing, &OUT, &OUT, inner()).is_none(),
                "⛔ §BD-3 THROUGH THE WELD: the weld's prover accepted {} byte(s) that are not a carrier. \
                 The direct door's forgery needs no inner proof at all; the weld must not offer it a way in.",
                nothing.len()
            );
        }

        // ── ARM 2. A real carrier, minted by the forger, welded to a statement it never stood for.
        let (bytes, pb) = carrier();
        let honest = prove_committed_weld_bytes(&bytes, &pb, &OUT, inner());
        let Some((wb, cf, layout)) = honest else { panic!("CONTROL: the honest weld must prove") };
        assert!(
            verify_committed_weld_bytes(&wb, layout, &pb, &OUT, gamma_of(&bytes, &pb), cf, inner(), &crate::whir_rec_block::declared_bus_shapes_for_tests(&wb).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&wb).1),
            "CONTROL: the honest weld must verify before a forgery of it means anything"
        );

        // THE CHAIN THAT NEVER EXISTED, in the outer statement's place. The forger holds a genuine proof
        // of a genuine statement (`pb`) and re-points its weld at an outer IO inheriting 2^100 of work.
        let forged_out: Vec<Fa4> = vec![
            Fa4::from_u64(0xDEAD_BEEF),
            Fa4::from_u64(0xCAFE_F00D),
            Fa4::from_u64(1u64 << 40),
        ];
        assert_ne!(forged_out.as_slice(), &OUT[..], "the forged statement must differ from the honest one");

        // The forger re-proves with the outer IO they want. The weld binds the outer IO into the
        // statement, so this is the strongest form of the attack: a fresh, internally consistent proof.
        let minted = prove_committed_weld_bytes(&bytes, &pb, &forged_out, inner());
        let Some((mb, mcf, mlayout)) = minted else {
            eprintln!("[§BD-3/weld] the weld's PROVER refused the re-pointed statement outright");
            return;
        };
        // It is a valid proof OF THE FORGED STATEMENT. That is expected and is not the attack: the
        // attack succeeds only if a verifier demanding the HONEST statement accepts it.
        assert!(
            verify_committed_weld_bytes(&mb, mlayout, &pb, &forged_out, gamma_of(&bytes, &pb), mcf, inner(), &crate::whir_rec_block::declared_bus_shapes_for_tests(&mb).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&mb).1),
            "the forger's own proof of their own statement should stand — the weld is not asked to lie"
        );
        assert!(
            !verify_committed_weld_bytes(&mb, mlayout, &pb, &OUT, gamma_of(&bytes, &pb), mcf, inner(), &crate::whir_rec_block::declared_bus_shapes_for_tests(&mb).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&mb).1),
            "⛔⛔⛔ §BD-3 LIVES THROUGH THE WELD: a proof raised over a chain that never existed was \
             accepted by a verifier demanding the REAL statement. The outer IO is not bound into the \
             weld's transcript, so re-pointing the statement costs nothing."
        );
        eprintln!(
            "[§BD-3/weld] ⭐ no inner proof ⇒ the weld cannot be stated (3 shapes refused); a minted \
             carrier re-pointed at a chain that never existed is REFUSED by a verifier demanding the \
             real statement ({} B)",
            mb.len()
        );
    }

    /// ⭐⭐ THE PARTS ARE WIRED TO THE RIGHT CELLS — the bisect that found the seed bug, kept as a gate.
    ///
    /// The weld's ties name CELLS. This reads them back: the sponge cells the challenge tie points at
    /// must hold the step's own `r` limbs, and the step's `r` must be the carrier's own `zc.r`. When
    /// those disagreed, the whole weld failed with nothing saying why — the parts verified separately
    /// and only the composition broke. That is what a wiring gate is for.
    #[test]
    fn the_welds_ties_point_at_cells_that_hold_the_carriers_own_challenges() {
        let (bytes, pb) = carrier();
        let (_limbs, layout, _g) =
            crate::recursion_bound::bound_step_row_committed(&bytes, &pb, 0, 0).expect("the row lays");
        let (ood, cap_elems) =
            crate::committed_air::committed_schedule_params(layout.nvars, layout.width).expect("params");
        let (lens, samples) = crate::committed_air::committed_schedule_lens(
            layout.nvars, layout.per, pb.len(), ood, cap_elems,
        )
        .expect("schedule");
        let (_absorbed, squeezed, _st) = plan(&lens, &samples).expect("plan");
        let (tb, _c, _l) = committed_weld_tables(&bytes, &pb, &pb, inner()).expect("tables");
        let (step, sponge) = (&tb[0], &tb[1]);

        let tail = squeezed.len() - EXT_LIMBS * layout.nvars;
        let r_off = EXT_LIMBS * layout.nvars * layout.per;
        let got: Vec<Fa4> = squeezed.iter().skip(tail).map(|&(row, col)| sponge[col][row]).collect();
        let want: Vec<Fa4> = (0..EXT_LIMBS * layout.nvars).map(|i| step[r_off + i][0]).collect();
        assert_eq!(
            got, want,
            "⛔ THE CHALLENGE TIE POINTS AT THE WRONG CELLS: the sponge cells it names do not hold the \
             step's `r`. MEASURED CAUSE the first time this fired — the sponge was replaying a committed \
             carrier's walk under the DIRECT permutation, reproducing the schedule element for element \
             and landing on challenges that proof never saw."
        );

        // And the step's `r` must be the carrier's own — a tie to a self-consistent wrong value is worse
        // than no tie, because it reads as bound.
        let basis: [Ea4; 4] = core::array::from_fn(|i| {
            <Ea4 as p3_field::BasedVectorSpace<Fa4>>::ith_basis_element(i).expect("4 basis elements")
        });
        let b2: crate::committed_air::CommittedAirBundle =
            postcard::from_bytes(&bytes).expect("decodes");
        for k in 0..layout.nvars {
            let o = r_off + EXT_LIMBS * k;
            let rk = basis[0] * step[o][0]
                + basis[1] * step[o + 1][0]
                + basis[2] * step[o + 2][0]
                + basis[3] * step[o + 3][0];
            assert_eq!(rk, b2.zc.r[k], "⛔ the step's r_{k} is not the carrier's own");
        }
        eprintln!(
            "[weld] every challenge tie names a sponge cell holding the carrier's own r ({} of them)",
            layout.nvars
        );
    }

    /// CONTROL. An honest weld proves, and a verifier that shares NO object with the prover — it rebuilt
    /// the ties and the circuit from the public statement alone — accepts.
    #[test]
    fn an_honest_committed_weld_proves_and_an_independent_verifier_accepts() {
        let (bytes, pb) = carrier();
        let (proof, chal, layout) =
            prove_committed_weld_bytes(&bytes, &pb, &OUT, inner()).expect("an honest weld proves");
        let g = crate::committed_air::transcript_of_committed_carrier(&bytes, &pb).expect("γ").0;
        assert!(
            verify_committed_weld_bytes(&proof, layout, &pb, &OUT, g, chal, inner(), &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).1),
            "an independently-derived verifier must accept an honest committed weld"
        );
        eprintln!(
            "[weld] nvars={} per={} width={} — proved and verified, {} byte(s)",
            layout.nvars,
            layout.per,
            layout.width,
            proof.len()
        );
    }

    /// ⭐⭐⭐ THE RESIDUAL §BD-2 NEEDED. A step whose committed challenge fold is not its transcript's
    /// must be refused — that is the difference between challenges a prover DECLARED and challenges a
    /// constrained sponge PRODUCED.
    #[test]
    fn a_weld_whose_challenge_fold_is_not_its_transcripts_is_refused() {
        let (bytes, pb) = carrier();
        let (proof, chal, layout) = prove_committed_weld_bytes(&bytes, &pb, &OUT, inner()).expect("proves");
        let g = crate::committed_air::transcript_of_committed_carrier(&bytes, &pb).expect("γ").0;
        let wrong = chal + Fa4::ONE;
        assert_ne!(wrong, chal, "the counterfactual fold must differ, or this pin proves nothing");
        assert!(
            !verify_committed_weld_bytes(&proof, layout, &pb, &OUT, g, wrong, inner(), &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).1),
            "⛔ THE CHALLENGE FOLD IS NOT BOUND: a verifier checking a different fold accepted this weld, \\
             so the step's challenges are values it declared rather than values the sponge produced."
        );
        eprintln!("[weld] a verifier expecting a different challenge fold refused");
    }

    /// ⭐⭐⭐ THE FORGERY THE WELD EXISTS FOR — a sponge raised over a DIFFERENT statement.
    ///
    /// The forger is HONEST everywhere the public transcript can see: a real carrier, a real step, a
    /// real sponge whose every permutation is correct. The one thing it changes is the STATEMENT the
    /// sponge absorbed. Nothing but tie (1) — the inner bind welded to the outer public IO — can catch
    /// it, which is why that tie exists.
    #[test]
    fn a_sponge_raised_over_a_different_statement_is_refused_by_the_weld_alone() {
        let (bytes, pb) = carrier();
        let other: Vec<Fa4> = pb.iter().map(|&f| f + Fa4::ONE).collect();
        assert_ne!(other, pb, "the counterfactual statement must differ");
        let forged =
            prove_committed_weld_with_sponge_bind(&bytes, &pb, &other, &OUT, inner());
        let g = crate::committed_air::transcript_of_committed_carrier(&bytes, &pb).expect("γ").0;
        match forged {
            // The builder may refuse outright — the walk over a foreign statement need not even plan.
            None => eprintln!("[weld] a foreign-statement sponge was refused at BUILD"),
            Some((proof, chal, layout)) => {
                assert!(
                    !verify_committed_weld_bytes(&proof, layout, &pb, &OUT, g, chal, inner(), &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).0, &crate::whir_rec_block::declared_bus_shapes_for_tests(&proof).1),
                    "⛔ THE WELD IS DECORATIVE: a sponge raised over a DIFFERENT statement verified \\
                     against the step's declared bind. The transcript proves nothing about which \\
                     statement the inner proof was checked over."
                );
                eprintln!("[weld] a foreign-statement sponge was refused at VERIFY");
            }
        }
    }
}

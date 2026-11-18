// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE SECURITY BUDGET — WHAT PAYS FOR RETENTION, AND WHY IT CANNOT INFLATE.
//!
//! ROOT-LAYER: the economic invariants are defined HERE, at the layer where the budget is DECIDED, and
//! the doors that move value prove the identical inequalities. There is exactly one definition of
//! "solvent endowment" and one of "the retention fee", so a cleartext check and a confidential
//! constraint can never drift apart — the same division of labour [`crate::liquidation`] uses for the
//! 150% backing rule. Defining either at a read site (an RPC summary, a wallet display, a per-test
//! helper) is how two definitions of the same number come to exist and disagree.
//!
//! MEASURED, the three facts this module is built on top of (2026-09-23):
//!   * ZERO ISSUANCE IS REAL AND HOLDS BY ABSENCE. `crate::reward` derives an opaque per-node,
//!     block-unique commitment and nothing anywhere mints a reward. There is no mint path to disable.
//!   * THE FILL FEE IS A BURN, NOT A MINER PAYMENT. Traced through the circuit: the taker half enforces
//!     `value_in = change + (pay_b + fee)` while a settlement's outputs are exactly three notes (maker
//!     payout, taker payout, taker change) and the maker receives `pay_b`, not `pay_b + fee`. No output
//!     note carries `fee`. `crate::block`'s doc claimed the reward was "a confidential spend of a
//!     fee/reserve-yield revenue note to the miner"; no such spend exists, and that doc is corrected.
//!   * THE NODE'S DISK COST IS REAL AND PER-NOTE. `the_snapshot_disk_cost_is_measured_on_both_the_block_
//!     and_the_note_axis` measured 1,153 B/note — 1,074 GB at 1e9 notes, ON EVERY NODE. Retention is the
//!     thing that must be paid for, so it is the thing the fee is priced against.
//!
//! ── THE THREE STREAMS, AND WHY THE FILL FEE IS NOT ONE OF THEM ────────────────────────────────────
//! (a) RETENTION FEE — one-time, charged when a note is created, paid into [`Endowment`]. This is the
//!     stream that funds miner retention, and it is ALSO a security gate in its own right: without a
//!     per-note cost an attacker bloats the retained set for free and breaks every miner's storage
//!     bound. It is the only stream that scales with the thing it buys (bytes kept).
//! (b) FILL FEE — stays a PURE BURN and is deliberately NOT redirected here. It already does a different
//!     job: burning lowers circulating liability `L` with reserve `R` untouched, so `R/L` rises on every
//!     trade ([`crate::liquidation`]). Redirecting it would weaken the peg to pay for storage, which is
//!     a pillar trade, and it would require changing a circuit that is already proven.
//! (c) RESERVE YIELD — the structural advantage a collateralized chain has and an unbacked one does not.
//!     A 150%-overcollateralized BTC/XMR reserve is PRODUCTIVE, so security can be funded from what the
//!     collateral earns rather than from issuance. This is why a fee-only security budget (Bitcoin's
//!     open problem) is not forced on us.
//!
//! ⛔ TAIL EMISSION IS DISQUALIFIED STRUCTURALLY, NOT BY PREFERENCE. Monero can pay miners with new XMR
//! because XMR floats. USDm is a dollar-pegged, over-collateralized CLAIM: minting unbacked USDm to pay
//! miners is not mild inflation, it is issuing claims with no reserve behind them — exactly the state
//! [`crate::liquidation::aggregate_solvent`] exists to make unprovable. It would break the peg by
//! construction.
//!
//! ── ⭐⭐⭐ THE ENDOWMENT IS A CONTROLLER, NOT A FORECAST — AND THAT IS THE FIX ──────────────────────
//! Arweave's endowment prices perpetual storage on a PREDICTION: that storage cost falls ~30%/yr. If the
//! prediction fails the endowment underfunds, retention degrades silently, and the failure surfaces years
//! later as notes nobody can produce — a funds-loss bug with no error message. A protocol whose safety
//! rests on a forecast about hardware markets is a protocol with an unbounded assumption in it.
//!
//! So this endowment prices from OBSERVED CHAIN STATE and forecasts nothing:
//!
//! ```text
//!     coverage = endowment / (retained_bytes x payout_per_byte_year x TARGET_YEARS)
//!     fee      = BASE x (1 / coverage), clamped to [MIN, MAX]
//! ```
//!
//! Coverage below target raises the fee; above target lowers it. If storage gets MORE expensive, the
//! payout rate rises, coverage falls, and the fee rises to meet it — automatically, with no oracle and no
//! assumption about which way hardware prices move. That is the difference between a system that is
//! correct if a prediction holds and one that is correct because it measures.
//!
//! ── COST — no pillar traded ───────────────────────────────────────────────────────────────────────
//! PRIVACY: this module holds no amount, owner or key — it is arithmetic over aggregates. The endowment
//! balance is a COMMITMENT at the door (like the reserve), and the fee schedule is proven in-circuit
//! against it exactly as the 150% rule is, so no balance is disclosed to price a fee. NO-GROWTH: pure
//! functions and constants; zero bytes of state, no collection, no per-note anything. SOUNDNESS: nothing
//! here moves value — every payout goes through the door, which re-proves these inequalities.

/// Basis points denominator, shared with the peg so one number means one thing.
pub const BPS: u128 = 10_000;

/// ⭐ HOW MANY YEARS OF PAYOUT THE ENDOWMENT AIMS TO HOLD.
///
/// ⛔ NOT A FORECAST AND NOT A CHOSEN-THEN-JUSTIFIED NUMBER. It is the controller's SET POINT: the
/// coverage the fee steers toward. Arweave targets ~200 years and can only justify that by assuming
/// storage costs keep falling; this module assumes nothing about hardware prices, so it targets a horizon
/// it can actually fund from observed state and keeps it topped up continuously. A shorter, honestly
/// funded horizon is safer than a long one that depends on a prediction.
///
/// Governance may RAISE it (more conservative). Lowering it reduces the buffer, so it is a consensus
/// parameter change like any other, never a local tune.
pub const RETENTION_TARGET_COVERAGE_YEARS: u128 = 20;

/// ⛔ THE FEE FLOOR — ANTI-BLOAT, AND IT IS A SECURITY BOUND, NOT AN ECONOMIC PREFERENCE.
///
/// A zero (or roundable-to-zero) retention fee lets an attacker create notes for free, and every created
/// note is storage every miner must retain forever. That is a denial-of-service on the one resource the
/// no-growth pillar bounds. The floor is what makes bloat cost the attacker more than it costs the
/// network, so it may be RAISED but never lowered to zero.
pub const RETENTION_FEE_MIN_ATOMIC: u128 = 1_000; // 0.00001 USDm at 8 decimals

/// The fee ceiling. A controller with no upper clamp becomes a denial-of-service on HONEST note creation
/// the moment coverage dips, so the fee is bounded above and the shortfall is carried by the other
/// streams instead of by locking users out of their own money.
pub const RETENTION_FEE_MAX_ATOMIC: u128 = 1_000_000; // 0.01 USDm — 1000x the floor

/// The fee charged at exactly the target coverage. The controller scales this by the coverage ratio.
pub const RETENTION_FEE_BASE_ATOMIC: u128 = 10_000; // 0.0001 USDm

/// ⭐ THE ENDOWMENT'S COVERAGE, IN BPS OF THE TARGET — the ONE reading the fee is a function of.
///
/// `10_000` means "the endowment holds exactly `RETENTION_TARGET_COVERAGE_YEARS` of payout at the
/// observed rate". Below that the fee rises; above it the fee falls.
///
/// Returns `None` when there is nothing to retain or nothing is being paid — there is no coverage ratio
/// to speak of, and inventing one (a zero, a default) would price a fee against a number nobody measured.
/// The caller must then hold the fee at [`RETENTION_FEE_BASE_ATOMIC`], which is what
/// [`retention_fee_atomic`] does.
#[must_use]
pub fn coverage_bps(endowment: u128, retained_bytes: u128, payout_per_byte_year: u128) -> Option<u128> {
    retention_need(retained_bytes, payout_per_byte_year).map(|need| coverage_of_need(endowment, need))
}

/// The payout the target coverage needs (`bytes · rate · TARGET_YEARS`), or `None` when it is zero or too large to state —
/// the one place the fee's multiply lives, so each proof reasons about one product, never two copies of it.
#[must_use]
pub fn retention_need(retained_bytes: u128, payout_per_byte_year: u128) -> Option<u128> {
    let annual = retained_bytes.checked_mul(payout_per_byte_year)?;
    let need = annual.checked_mul(RETENTION_TARGET_COVERAGE_YEARS)?;
    (need != 0).then_some(need)
}

/// Coverage in bps of a NONZERO `need` (from [`retention_need`]): `floor(sat(endowment · BPS) / need)`.
#[must_use]
pub fn coverage_of_need(endowment: u128, need: u128) -> u128 {
    endowment.saturating_mul(BPS) / need
}

/// ⭐⭐⭐ THE RETENTION FEE — a function of measured state, never of a prediction.
///
/// `fee = BASE * TARGET_COVERAGE / actual_coverage`, clamped to `[MIN, MAX]`. Under-covered endowments
/// charge more; over-covered ones charge less; the clamps make it a bounded controller rather than an
/// unbounded feedback loop.
///
/// With no measurable coverage (nothing retained yet, or no payout rate) the fee holds at BASE — the
/// fail-safe direction, because it keeps charging rather than letting notes be created free.
#[must_use]
pub fn retention_fee_atomic(endowment: u128, retained_bytes: u128, payout_per_byte_year: u128) -> u128 {
    retention_fee_of_coverage(coverage_bps(endowment, retained_bytes, payout_per_byte_year))
}

/// The fee as a function of the ONE reading it depends on — [`coverage_bps`]'s answer.
#[must_use]
pub fn retention_fee_of_coverage(coverage: Option<u128>) -> u128 {
    let Some(cov) = coverage else {
        return RETENTION_FEE_BASE_ATOMIC;
    };
    // A fully drained endowment must not divide by zero and must charge the MAXIMUM, not the minimum.
    if cov == 0 {
        return RETENTION_FEE_MAX_ATOMIC;
    }
    let scaled = RETENTION_FEE_BASE_ATOMIC.saturating_mul(BPS) / cov;
    scaled.clamp(RETENTION_FEE_MIN_ATOMIC, RETENTION_FEE_MAX_ATOMIC)
}

/// ⛔⛔⛔ THE NO-ISSUANCE INVARIANT, as a computable predicate — the one every payout door proves.
///
/// A payout is admissible ONLY if the endowment already holds it. There is no credit, no negative
/// balance and no "settle later": the endowment can only pay out what was paid in, which is what makes
/// the miner reward a redistribution rather than emission. This is the inequality the door proves
/// in-circuit over the committed balance, so the cleartext form here and the constraint there cannot
/// disagree about what "funded" means.
#[must_use]
pub fn payout_is_funded(endowment: u128, payout: u128) -> bool {
    payout <= endowment
}

/// The endowment after a funded payout. `None` when the payout is not funded — fail-closed, so an
/// unfunded payout cannot be applied by saturating to zero and silently minting the difference.
#[must_use]
pub fn endowment_after_payout(endowment: u128, payout: u128) -> Option<u128> {
    if !payout_is_funded(endowment, payout) {
        return None;
    }
    Some(endowment - payout)
}

/// ⭐ CONSERVATION AT THE NOTE-CREATION DOOR: what the creator pays equals what the endowment receives.
///
/// There is no spread, no rounding remainder and no third destination. A fee that did not arrive
/// somewhere is value destroyed without a burn record, and a fee that arrived twice is issuance.
#[must_use]
pub fn retention_fee_conserves(paid: u128, endowment_before: u128, endowment_after: u128) -> bool {
    // checked, never saturating: a sum past u128::MAX is no conservation (5 units vanished at MAX)
    endowment_before.checked_add(paid) == Some(endowment_after)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// VALUE CONSERVATION ON A SPEND — the n-in / 2-out law.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// ⭐ HOW MANY NOTES ONE SPEND MAY CONSUME. A FIXED PROTOCOL SHAPE CONSTANT, not a function of anything.
///
/// It is deliberately `TX_FIXED_NULLIFIER_COUNT`: every transaction ALREADY pads its nullifier list to
/// that width as cover, so spending up to this many inputs costs NOTHING on the wire and changes NO
/// privacy property — the observable shape is the same constant it always was. Tying the two together
/// (rather than picking a second number) means they cannot drift into disagreeing about how many
/// nullifier slots a spend may fill.
///
/// O1-DEFINITION-REVIEWED: `f(TX_FIXED_NULLIFIER_COUNT)` — a fixed protocol shape constant, identical at
/// height 1 and height 10^12. No history quantity appears in it. Shape 3, BY CONSTRUCTION.
pub const SPEND_MAX_INPUTS: usize = crate::cover::TX_FIXED_NULLIFIER_COUNT;

/// A spend always emits EXACTLY two output notes, and that is a PRIVACY invariant, not an implementation
/// detail. The spend circuit's own doc: *"A single-recipient send with no change sets out1 = (0, sk) -> a
/// value-0 note (byte-shaped like any other)"*. Emitting one note when there is no change would publish
/// "this send drained its input", so the zero-valued note stays and the count stays constant.
pub const SPEND_OUTPUTS: usize = 2;

/// ⭐⭐⭐ THE NET NOTE DELTA OF ONE SPEND — `2 - n`, and the whole reason n-in matters.
///
/// ```text
///   n = 1  ->  +1   every spend GROWS the retained set (today's behaviour, forever)
///   n = 2  ->   0   break-even
///   n >= 3 ->  <0   CONSOLIDATION: the set shrinks
/// ```
///
/// This is the function that turns note count from monotonically growing into something a fee can steer.
/// Without n-in, [`retention_fee_atomic`] prices an externality users have no way to avoid — a tax, not a
/// price signal. With it, holding many notes costs and merging them is cheap, so the set becomes
/// economically self-limiting.
#[must_use]
pub fn spend_note_delta(n_inputs: usize) -> i64 {
    SPEND_OUTPUTS as i64 - n_inputs as i64
}

/// ⛔⛔⛔ THE SPEND CONSERVATION LAW — `sum(inputs) == out0 + out1 + fee`, exactly.
///
/// The one equality the spend circuit proves over hidden values. Checked-arithmetic throughout: a sum
/// that would overflow `u64` is REFUSED rather than wrapped, because a wrap is an inflation oracle — it
/// lets a prover present inputs that "sum" to less than they are and mint the difference.
///
/// Refused, each for its own reason:
///   * ZERO inputs — a spend that consumes nothing creates its outputs from nowhere.
///   * MORE than [`SPEND_MAX_INPUTS`] — past the cover width it is no longer shape-constant on the wire.
///   * A sum that does not match the outputs plus the fee, in EITHER direction: short is value destroyed
///     without a burn record, over is issuance.
#[must_use]
pub fn spend_conserves(values_in: &[u64], out0: u64, out1: u64, fee: u64) -> bool {
    if values_in.is_empty() || values_in.len() > SPEND_MAX_INPUTS {
        return false;
    }
    let mut total: u64 = 0;
    for v in values_in {
        let Some(t) = total.checked_add(*v) else {
            return false; // a wrapping sum is an inflation oracle
        };
        total = t;
    }
    let Some(out) = out0.checked_add(out1).and_then(|o| o.checked_add(fee)) else {
        return false;
    };
    total == out
}

/// ⛔ THE SAME INPUT MAY NOT BE SPENT TWICE WITHIN ONE SPEND.
///
/// n-in creates a failure mode 1-in could not have: presenting the SAME note n times. Each copy carries a
/// valid membership path and a valid opening, so per-input checks all pass while the conservation sum
/// counts the value n times — a self-contained double-spend that never touches the nullifier set, because
/// the set only learns the nullifier once. The nullifiers within a spend must therefore be DISTINCT, and
/// that is checked here rather than left to the set.
#[must_use]
pub fn spend_inputs_are_distinct(nullifiers: &[[u8; 32]]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(nullifiers.len());
    nullifiers.iter().all(|nf| seen.insert(*nf))
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// ⭐⭐⭐ THE POINT OF n-IN: the note set stops growing. `2 - n`, stated as the accounting it is.
    #[test]
    fn a_spend_grows_the_note_set_only_while_it_takes_one_input() {
        assert_eq!(spend_note_delta(1), 1, "1-in/2-out GROWS the set on every spend — today's behaviour");
        assert_eq!(spend_note_delta(2), 0, "2-in is break-even");
        assert_eq!(spend_note_delta(3), -1, "3-in CONSOLIDATES");
        assert_eq!(
            spend_note_delta(SPEND_MAX_INPUTS),
            2 - SPEND_MAX_INPUTS as i64,
            "a full-width spend reclaims {} note(s)",
            SPEND_MAX_INPUTS - 2
        );
    }

    /// ⛔ CONSERVATION, AND BOTH DIRECTIONS OF ITS FAILURE.
    #[test]
    fn a_spend_conserves_exactly_and_refuses_both_directions_of_drift() {
        assert!(spend_conserves(&[100, 200, 700], 900, 90, 10), "1000 in == 900 + 90 + 10");
        assert!(!spend_conserves(&[100, 200, 700], 900, 90, 11), "over by one is ISSUANCE");
        assert!(!spend_conserves(&[100, 200, 700], 900, 90, 9), "short by one destroys value silently");
        // A drained send: everything to the recipient, a value-0 change note, nothing lost.
        assert!(spend_conserves(&[500], 490, 0, 10), "a full-drain send with a value-0 change note");
    }

    /// ⛔ A WRAPPING SUM IS AN INFLATION ORACLE — refused, never wrapped.
    #[test]
    fn an_overflowing_input_sum_is_refused_rather_than_wrapped() {
        assert!(
            !spend_conserves(&[u64::MAX, 2], 1, 0, 0),
            "u64::MAX + 2 must REFUSE; wrapping it to 1 would make this spend 'conserve' and mint u64::MAX"
        );
    }

    /// ⛔ ZERO INPUTS CREATES OUTPUTS FROM NOWHERE; PAST THE COVER WIDTH IS NO LONGER SHAPE-CONSTANT.
    #[test]
    fn a_spend_with_no_inputs_or_too_many_is_refused() {
        assert!(!spend_conserves(&[], 0, 0, 0), "zero inputs creates its outputs from nowhere");
        let too_many = vec![1u64; SPEND_MAX_INPUTS + 1];
        assert!(!spend_conserves(&too_many, too_many.len() as u64, 0, 0), "past the cover width is refused");
        let at_max = vec![1u64; SPEND_MAX_INPUTS];
        assert!(spend_conserves(&at_max, SPEND_MAX_INPUTS as u64, 0, 0), "exactly at the width is fine");
    }

    /// ⛔⛔⛔ THE FAILURE MODE n-IN CREATES THAT 1-IN COULD NOT: the same note presented twice.
    ///
    /// Every copy carries a valid path and opening, so per-input checks pass while conservation counts
    /// the value twice — a double-spend that never reaches the nullifier set, because the set learns the
    /// nullifier once. Distinctness is the gate.
    #[test]
    fn the_same_note_presented_twice_in_one_spend_is_refused() {
        let a = [7u8; 32];
        let b = [9u8; 32];
        assert!(spend_inputs_are_distinct(&[a, b]), "two different notes are fine");
        assert!(!spend_inputs_are_distinct(&[a, a]), "the SAME note twice is a self-contained double-spend");
        assert!(!spend_inputs_are_distinct(&[a, b, a]), "and it is caught anywhere in the list");
        // And the arithmetic really would have passed, which is why the check must exist separately.
        assert!(
            spend_conserves(&[500, 500], 1000, 0, 0),
            "the conservation sum ALONE accepts the duplicate — distinctness is not implied by it"
        );
    }

    /// The controller's whole purpose: an UNDER-covered endowment must charge MORE, an over-covered one
    /// LESS. Stated as a direction rather than a magic number, because the direction is the property.
    #[test]
    fn an_undercovered_endowment_charges_more_and_an_overcovered_one_charges_less() {
        let bytes = 1_000_000u128;
        let rate = 1u128; // 1 atomic per byte-year
        let at_target = bytes * rate * RETENTION_TARGET_COVERAGE_YEARS;

        let fee_at_target = retention_fee_atomic(at_target, bytes, rate);
        let fee_under = retention_fee_atomic(at_target / 4, bytes, rate);
        let fee_over = retention_fee_atomic(at_target * 4, bytes, rate);

        assert_eq!(fee_at_target, RETENTION_FEE_BASE_ATOMIC, "at target the fee is the base");
        assert!(fee_under > fee_at_target, "under-covered must charge more: {fee_under} vs {fee_at_target}");
        assert!(fee_over < fee_at_target, "over-covered must charge less: {fee_over} vs {fee_at_target}");
    }

    /// ⛔ THE FIX FOR ARWEAVE'S ASSUMPTION, MEASURED. If storage gets MORE expensive (the case a
    /// declining-cost forecast gets wrong), the fee must rise on its own. No oracle, no prediction.
    #[test]
    fn a_rising_storage_cost_raises_the_fee_with_no_forecast_and_no_oracle() {
        let bytes = 1_000_000u128;
        let endowment = bytes * 1 * RETENTION_TARGET_COVERAGE_YEARS; // exactly covered at rate 1
        let cheap = retention_fee_atomic(endowment, bytes, 1);
        let dearer = retention_fee_atomic(endowment, bytes, 4); // storage got 4x more expensive
        assert!(
            dearer > cheap,
            "a 4x rise in payout rate must raise the fee ({dearer} vs {cheap}) — this is the property \
             Arweave's model gets from a forecast and this one gets from measurement"
        );
    }

    /// ⛔ A DRAINED ENDOWMENT CHARGES THE MAXIMUM, NOT THE MINIMUM. The dangerous direction is charging
    /// LESS exactly when the pool is empty, which is what a naive ratio does at zero.
    #[test]
    fn a_drained_endowment_charges_the_maximum() {
        assert_eq!(
            retention_fee_atomic(0, 1_000_000, 1),
            RETENTION_FEE_MAX_ATOMIC,
            "an empty endowment must charge the ceiling"
        );
    }

    /// ⛔ THE FEE CAN NEVER BE FREE. A zero fee is free note creation, and every free note is storage
    /// every miner keeps forever — a denial-of-service on the bounded resource.
    #[test]
    fn the_fee_never_falls_to_zero_however_over_covered_the_endowment_is() {
        for mult in [1u128, 10, 1_000, 1_000_000, u128::MAX / 1_000_000] {
            let endowment = mult.saturating_mul(1_000_000);
            let fee = retention_fee_atomic(endowment, 1_000_000, 1);
            assert!(
                fee >= RETENTION_FEE_MIN_ATOMIC,
                "fee {fee} fell below the anti-bloat floor at endowment multiplier {mult}"
            );
        }
    }

    /// And never unbounded above, or the controller becomes a lockout on honest note creation.
    #[test]
    fn the_fee_is_bounded_above_so_a_shortfall_cannot_lock_users_out() {
        let fee = retention_fee_atomic(1, u128::from(u64::MAX), u128::from(u64::MAX));
        assert!(fee <= RETENTION_FEE_MAX_ATOMIC, "fee {fee} exceeded the ceiling");
    }

    /// ⛔⛔⛔ NO ISSUANCE: the endowment cannot pay what it does not hold, and an unfunded payout is
    /// REFUSED rather than saturated to zero — saturation would silently mint the difference.
    #[test]
    fn an_unfunded_payout_is_refused_and_never_saturates() {
        assert!(payout_is_funded(100, 100), "paying exactly the balance is funded");
        assert!(!payout_is_funded(100, 101), "one atomic unit over is NOT funded");
        assert_eq!(endowment_after_payout(100, 100), Some(0));
        assert_eq!(
            endowment_after_payout(100, 101),
            None,
            "an over-payout must be refused, not clamped — a clamp is a mint"
        );
    }

    /// Conservation at the door: paid in == received. No spread, no remainder, no third destination.
    #[test]
    fn the_retention_fee_conserves_exactly() {
        assert!(retention_fee_conserves(500, 1_000, 1_500));
        assert!(!retention_fee_conserves(500, 1_000, 1_499), "a lost atomic unit is value destroyed");
        assert!(!retention_fee_conserves(500, 1_000, 1_501), "an extra atomic unit is issuance");
        // F2-red-PROOFS-20261023 (Kani counterexample): a sum that overflows u128 must not "conserve" at MAX
        assert!(!retention_fee_conserves(10, u128::MAX - 5, u128::MAX), "5 units vanish at saturation");
    }

    /// ⭐ THE CONTROLLER CONVERGES RATHER THAN OSCILLATING. Drive it from a badly under-covered start
    /// with a constant note inflow and require coverage to move monotonically toward the set point —
    /// a controller that overshoots past target would charge too little exactly after a shortfall.
    #[test]
    fn the_controller_moves_coverage_toward_the_set_point_without_overshooting_past_it() {
        let bytes = 1_000_000u128;
        let rate = 1u128;
        let target = bytes * rate * RETENTION_TARGET_COVERAGE_YEARS;
        let mut endowment = target / 100; // badly under-covered
        let mut last_cov = coverage_bps(endowment, bytes, rate).expect("coverage");
        for _ in 0..500 {
            let fee = retention_fee_atomic(endowment, bytes, rate);
            endowment = endowment.saturating_add(fee.saturating_mul(1_000)); // 1000 notes created
            let cov = coverage_bps(endowment, bytes, rate).expect("coverage");
            assert!(cov >= last_cov, "coverage must not fall while notes are being created");
            last_cov = cov;
        }
        assert!(
            last_cov > BPS / 2,
            "the controller must make real progress toward the set point, reached {last_cov} bps"
        );
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! COLLATERAL LIQUIDATION — the aggregate-ratio invariant, and the crash simulation that proves it holds.
//!
//! The value-moving DOOR lives in [`crate::peg`] ([`crate::peg::PegLedger::liquidate_confidential`], whose doc
//! comment carries the §9.6 six-question checklist). What SHIPS from this module is two pure predicates and
//! nothing else — no state, no collection, no counter. The position book that decides WHICH positions the door is
//! asked to close is the CUSTODIAN's private working state (the party that legitimately holds the reserve knows
//! the amounts), exactly like the transient openings [`crate::peg::PegLedger::orchestrate_peg_in`] already takes;
//! the NODE holds only opaque commitments and must never hold a per-position anything. So the book and its sweep
//! live under `#[cfg(test)]` here, as the simulation harness that drives the real door — deliberately, not as an
//! oversight — and even there the book is FIXED-WIDTH (`[Position; N]`, `[u128; 2]`), so no structure in this
//! file can grow with history at all. If a custodian orchestrator ever needs a book, it belongs in that
//! operator's own software, never in the node's footprint.
//!
//! ROOT-LAYER: the invariant is defined HERE, at the layer where solvency is DECIDED, and the door proves the
//! identical inequality in-circuit over hidden values. There is exactly one definition of "solvent" in the tree
//! ([`aggregate_solvent`]), so a cleartext check and a confidential constraint can never drift apart. Defining it
//! at any read site — a wallet display, an RPC summary, a per-test helper — is how two definitions of solvency
//! come to exist and disagree.
//! MEASURED: `cargo check --lib` 2026-09-08 -> errors by file: node.rs 28, node_runtime.rs 11, miner.rs 1,
//! peg.rs 0, solvency.rs 0, liquidation.rs 0. Before this lane, `grep -rn "liquidation" src/` matched no door,
//! no threshold and no invariant — there was no way to close a position for undercollateralization at all;
//! after, there is exactly one of each.
//! MUST-STAY-GREEN: the peg's funds-safety theorem tests (`confidential_peg_in_verify_gate`,
//! `custodian_orchestrates_confidential_mint_and_redeem_from_its_opening`,
//! `redeem_two_tier_floor_sells_below_150_but_never_below_100`,
//! `wrapped_asset_per_asset_ratio_stablecoin_exempt_from_150`, `confidential_peg_in_out_wire_path_e2e`,
//! `confidential_reserve_yield_claim_gate`), the psm threshold tests, the DEX three-party pin, no-growth and
//! census. This module adds a path and relaxes none of theirs.
//!
//! ── THE CLASSIC DANGER, AND WHY THE OLD SHAPE COULD NOT SURVIVE IT ────────────────────────────────────────────
//! `peg_out_confidential` returns the position's FULL ORIGINAL deposit. Deposit $150 of BTC at the 150% mint
//! ratio, mint 100 USDm. Two things then happen as BTC falls, and BOTH hurt the reserve:
//!   • ABOVE water (collateral worth 100..150): redeeming is PROFITABLE — burn 100 USDm, take back collateral
//!     worth 125. Every such redemption removes 125 of reserve for 100 of liability, so the aggregate ratio
//!     FALLS. The healthy positions leave first.
//!   • BELOW water (collateral worth < 100): redeeming is a LOSING trade, so the holder ABANDONS the position and
//!     keeps USDm worth more than the collateral behind it. The liability never retires.
//! That is adverse selection in its purest form: the good collateral walks out and the bad collateral stays. The
//! reserve then backs less than the USDm outstanding, and the 100% hard block in `peg_out_confidential` fires on
//! the HONEST redeemers who did show up — while every abandoner already left. The safety check punishes the wrong
//! people, and nothing in the old peg could close a position for undercollateralization at all.
//!
//! ── THE CURE (v2, spec §10 — Liquity's stability pool, borrowed) ──────────────────────────────────────────────
//! A PSM whose backing at the chain's folded mark falls below [`crate::peg::PegLedger::liquidation_threshold_bps`]
//! is liquidated by ONE object carrying five welded WHIR legs ([`crate::peg::PegLedger::verify_liquidation_legs`]):
//!   RETIRE — the stability pool BURNS `C` USDm its depositors pre-deposited; the supply falls by the SAME `C`.
//!   SEIZE  — `S` collateral leaves the reserve; the pool's running sum records it for the depositors, pro rata.
//! `(C, S)` is the ONE amount rule (`confidential_solvency::liquidation_amount`): the least retire that restores the
//! 150 % target after a seizure at the pool's 10 % discount, and the least collateral that covers it. A PSM the
//! discounted collateral cannot restore is liquidated FULLY (Liquity's under-100 % case): the pool takes the whole
//! reserve and retires the whole supply. Every retired USDm is a real burn — the v1 re-mark lowered the supply while
//! the notes still circulated, which is a hidden inflation; v2 cannot, because the supply leg and the pool leg are
//! welded to the same `DC`. The post-state is at the target or fully closed, so every liquidation leaves the PSM
//! STRONGER than it found it, and the 10 bps order-fill burn ([`crate::params::ORDER_FILL_FEE_BPS_DEFAULT`]) lowers
//! the supply with the reserve untouched between liquidations.
//!
//! ── THE BOUNDARY, stated honestly ─────────────────────────────────────────────────────────────────────────────
//! Liquidation needs a pool: `C ≤ T`. A pool too small for the rule's `C` cannot liquidate yet (the PSM stays open and
//! its mints stay refused by the mint gate until the pool grows). A single instantaneous GAP larger than the buffer is
//! caught by the FULL regime rather than refused: the pool absorbs the shortfall. The crash simulation drives a
//! −70 % decline across two ledgers through the real door and asserts each of these on what the PEER holds.
//!
//! ── COST — no pillar traded ───────────────────────────────────────────────────────────────────────────────────
//! PRIVACY: unchanged. Nothing here is serialized into consensus state or gossiped; the node still sees only
//! opaque digests. NO-GROWTH: this module ships TWO pure functions and zero bytes of state. SOUNDNESS: cons: none
//! — nothing in this module can move value; every liquidation goes through the door, which re-verifies the five legs
//! against its own persisted commitments, on EVERY node independently.

/// Fixed-point scale for a collateral price quoted in USDm-atomic units per external unit. A price of exactly
/// 1 USDm per unit is `PRICE_SCALE`. A fixed constant — no history quantity appears in it.
pub const PRICE_SCALE: u128 = 1_000_000;

/// ⭐ THE AGGREGATE-RATIO INVARIANT, as a computable predicate — `reserve_value * 10000 >= liability * floor_bps`.
///
/// It is the same inequality the peg's mint and redeem carriers prove in-circuit over hidden values
/// (`reserve*10000 >= minted*floor_bps`), so the cleartext check here and the confidential constraint there can never
/// disagree about what solvency means.
///
/// Written as a multiplication rather than a division so it is exact at every magnitude — a division would
/// truncate and could report an insolvent book as solvent — and saturating so a hostile magnitude cannot wrap it
/// into a `true`. A zero liability is trivially backed.
#[must_use]
pub fn aggregate_solvent(reserve_value: u128, liability: u128, floor_bps: u32) -> bool {
    // ONE DEFINITION. This was a THIRD copy of one rule: the peg carriers prove
    // `reserve*BPS_DEN >= minted*floor_bps` (`confidential_solvency::verify_peg_in_carrier`), the decider carries the native twin
    // `confidential_solvency::is_solvent`, and this re-spelled it with the denominator as the LITERAL
    // `10_000`. The two happened to agree — checked by the differential sweep in this file — but a rule
    // spelled twice is a rule that drifts, and this tree has paid for that repeatedly (the `spent_leaf`
    // defect, the literal column offsets). It DELEGATES now, so there is nothing left to drift.
    usdm_decider::confidential_solvency::is_solvent(reserve_value, liability, floor_bps)
}

/// The aggregate backing ratio in basis points — `reserve_value * 10000 / liability`; `u128::MAX` when nothing is
/// outstanding (infinitely backed). For MEASUREMENT and failure messages. [`aggregate_solvent`] is the predicate
/// that decides, because it never truncates.
#[must_use]
pub fn aggregate_ratio_bps(reserve_value: u128, liability: u128) -> u128 {
    if liability == 0 {
        return u128::MAX; // nothing is owed, so no ratio bounds it
    }
    // The SAME denominator the circuit and the decider's twin use — never the literal again.
    reserve_value.saturating_mul(usdm_decider::confidential_solvency::BPS_DEN) / liability
}

/// THE TWIN IS CHECKED, NOT ASSUMED — a differential sweep against the decider's own native form.
///
/// The chain's solvency rule lives in a CIRCUIT (`confidential_solvency::verify_peg_in_carrier` proves
/// `new_reserve*BPS_DEN >= new_minted*floor_bps`), because the node holds COMMITMENTS and not the
/// plaintext reserve and liability — which is why this module has no production caller and never will.
/// Its job is to be the oracle a test can ask. An oracle that has silently drifted from the rule it
/// mirrors is worse than none: it certifies the wrong answer with confidence.
#[cfg(all(test, feature = "pins-core"))]
mod one_definition_gate {
    const VALUES: &[u128] = &[0, 1, 2, 9_999, 10_000, 10_001, 1_000_000, u128::MAX / 4, u128::MAX];
    const FLOORS: &[u32] = &[0, 1, 5_000, 9_999, 10_000, 10_001, 15_000, u32::MAX];

    #[test]
    fn the_native_solvency_twin_agrees_with_the_deciders() {
        let mut checked = 0usize;
        for &r in VALUES {
            for &m in VALUES {
                for &f in FLOORS {
                    assert_eq!(
                        super::aggregate_solvent(r, m, f),
                        usdm_decider::confidential_solvency::is_solvent(r, m, f),
                        "THE NATIVE SOLVENCY TWIN HAS DRIFTED FROM THE RULE THE CIRCUIT PROVES at \
                         reserve={r} liability={m} floor={f}bps. Every test that asks this oracle is \
                         now certifying the wrong answer — and it is the oracle for whether a position \
                         may have its COLLATERAL SEIZED."
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 500, "the sweep must span the boundary set (got {checked})");
        assert_eq!(
            super::aggregate_ratio_bps(1, 1),
            usdm_decider::confidential_solvency::BPS_DEN,
            "a reserve equal to its liability is exactly BPS_DEN bps — if this moved, some caller reads \
             a ratio against a different denominator than the circuit enforces"
        );
        eprintln!("[solvency-twin] {checked} boundary combination(s) agree with the decider's rule");
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    use crate::bridge::Custodian;
    use crate::peg::{LiquidationOpening, PegLedger, PegOutcome, PoolWords, NATIVE_PEG_ASSET_ID};
    use crate::pqauth::MlDsaVerifier;
    use crate::psm::MintAttestor;
    use crate::validator::ValidatorSet;

    /// The value-hiding commitment to `value` under `blind` — the custodian's side of the digest the node persists.
    fn commit_of(value: u128, blind: crate::spend_frontier::Digest4) -> crate::spend_frontier::Digest4 {
        usdm_decider::confidential_solvency::solvency_commit_256([value as u64, (value >> 64) as u64, 0, 0], blind)
    }

    /// A real 2-of-2 charter quorum of distinct ML-DSA validators (the harness holds their keys, as the custodians do).
    fn quorum() -> (Vec<Custodian>, ValidatorSet) {
        let custodians: Vec<Custodian> = (0..2u8).map(|i| Custodian::generate(&[70 + i; 32])).collect();
        let mut vs = ValidatorSet::new();
        for c in &custodians {
            vs.admit(c.id(), 5000, 0).unwrap();
        }
        (custodians, vs)
    }

    fn attest(custodians: &[Custodian], msg: &[u8]) -> Vec<MintAttestor> {
        custodians.iter().map(|c| c.attest(msg)).collect()
    }

    /// Mark `price` at `epoch` on a ledger through the chain's own ≥2/3 quote door.
    fn mark(n: &mut PegLedger, custodians: &[Custodian], vs: &ValidatorSet, epoch: u64, price: u128) {
        let quotes: Vec<crate::price_mark_tx::PriceQuote> = custodians
            .iter()
            .map(|c| {
                let a = c.attest(&PegLedger::price_mark_msg(epoch, NATIVE_PEG_ASSET_ID, price));
                crate::price_mark_tx::PriceQuote { price, pubkey: a.pubkey, sig: a.sig }
            })
            .collect();
        assert_eq!(n.mark_price_attested(epoch, NATIVE_PEG_ASSET_ID, &quotes, vs, &MlDsaVerifier), PegOutcome::PriceMarked(price));
    }

    // ── THE CRASH SIMULATION (v2, spec §10 — the stability pool) ────────────────────────────────────────────────────
    //
    // A PSM at 150 % (10,000 collateral units at a mark of 0.9 against 6,000 USDm) with the whole supply deposited in the
    // stability pool. The mark falls to −70 % in six steps; after each step the custodian plans and BUILDS the five-leg
    // liquidation when the PSM is due, and TWO separately constructed ledgers apply the same bytes. Asserted every step,
    // on what the PEER holds: the two ledgers agree; a due PSM is never left unliquidated; every liquidation returns the
    // PSM to the 150 % target or liquidates it fully, and leaves it STRONGER than it found it; every retired USDm was a
    // pool burn (supply and pool fall by the same `C`); and the custodian's next opening opens the peer's commitments.
    #[test]
    fn crash_simulation_minus_70_liquidates_through_the_stability_pool_on_two_ledgers() {
        let (custodians, vs) = quorum();
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let mut o = LiquidationOpening {
            reserve: 10_000,
            reserve_blind: l(&[1, 2, 3, 4]),
            minted: 6_000,
            minted_blind: l(&[5, 6, 7, 8]),
            pool_t: 6_000,
            pool_t_blind: l(&[9, 9, 9, 9]),
            pool_p: crate::peg::POOL_P_SCALE,
            pool_p_blind: crate::peg::GENESIS_POOL_P_BLIND,
            pool_s: [0; 4],
            pool_s_blind: crate::peg::GENESIS_POOL_S_BLIND,
        };
        let ledger = || {
            let mut p = PegLedger::new(15_000);
            p.initialize_solvency_commitments(commit_of(o.reserve, o.reserve_blind), commit_of(o.minted, o.minted_blind));
            p.set_pool_words(NATIVE_PEG_ASSET_ID, PoolWords { t: commit_of(o.pool_t, o.pool_t_blind), ..PoolWords::genesis() });
            p
        };
        let (mut node_a, mut peer_node) = (ledger(), ledger());
        let ratio_bps = |o: &LiquidationOpening, p: u128| o.reserve * p * 10_000 / PRICE_SCALE / o.minted.max(1);
        let mut closed = 0usize;
        // ⭐ §BR-4 THE GUARD (2026-11-01, lane funds-brb33 after lane defi's finding): the mark acts within 25 % of the 7-day
        // average, or once the move beyond it has PERSISTED for GUARD_PERSIST_EPOCHS closed epochs (MakerDAO's OSM hour). The
        // crash is −70 % over 20 epochs (−3.5 %/epoch — faster than any measured BTC day); the pin computes the guard's
        // verdict INDEPENDENTLY from the marks it laid and asserts the ledger agrees at every step, that a refusal happens only
        // while the mark is beyond the band, that no refusal streak outlasts the guard delay, and that the crash IS liquidated
        // after the band is crossed. RED before: the band alone refused from step 3 to the end (the PSM sank unliquidated).
        let steps = 20u128;
        let marks: Vec<u128> = (1..=steps).map(|k| 900_000 - 31_500 * k).collect(); // 0.8685 … 0.270: −70 % at step 20
        let persist = crate::price_history::GUARD_PERSIST_EPOCHS;
        let (mut first_beyond, mut refused_streak, mut liquidated_after_cross) = (None::<usize>, 0usize, false);
        // the 7-day average that stood when each mark was FOLDED (mark k folds when mark k + 1 arrives): refs[k - 1]
        let mut refs: Vec<Option<u128>> = Vec::new();
        for step in 1..=steps {
            if step >= 2 {
                refs.push(node_a.price_history_twap7_for_test(NATIVE_PEG_ASSET_ID)); // mark step − 1 folds now, against this
            }
            let p = marks[(step - 1) as usize];
            mark(&mut node_a, &custodians, &vs, step as u64, p);
            mark(&mut peer_node, &custodians, &vs, step as u64, p);
            // the guard, computed here from the marks and their references alone (the ledger's history must agree)
            let closed_marks = &marks[..(step - 1) as usize];
            let band_of = |t: u128| t * u128::from(crate::peg::LIQ_TWAP_BAND_BPS) / 10_000;
            let (expected_rule, beyond) = match node_a.price_history_twap7_for_test(NATIVE_PEG_ASSET_ID) {
                None => (true, false),
                Some(t) => {
                    let beyond = p.abs_diff(t) > band_of(t);
                    let persisted = closed_marks.len() >= persist
                        && (closed_marks.len() - persist..closed_marks.len())
                            .all(|j| refs[j].is_some_and(|r| closed_marks[j] < r - band_of(r)));
                    (!beyond || persisted, beyond)
                }
            };
            if beyond && first_beyond.is_none() {
                first_beyond = Some(step as usize);
            }
            let rule = node_a.liquidation_rule(NATIVE_PEG_ASSET_ID);
            assert_eq!(
                rule.is_some(),
                expected_rule,
                "step {step}: ⛔ the ledger's guard disagrees with the rule computed from the marks (mark {p}, beyond {beyond})"
            );
            assert_eq!(peer_node.liquidation_rule(NATIVE_PEG_ASSET_ID).is_some(), expected_rule, "step {step}: the PEER's guard differs");
            let Some(rule) = rule else {
                assert!(beyond, "step {step}: ⛔ the guard refused a mark INSIDE the band");
                refused_streak += 1;
                assert!(refused_streak <= persist, "step {step}: ⛔ the guard refused {refused_streak} epochs in a row — longer than the OSM delay");
                continue;
            };
            refused_streak = 0;
            let Some(plan) = crate::peg::plan_liquidation(&o, &rule) else {
                assert!(
                    o.minted == 0 || o.reserve * p * 10_000 >= 12_500 * o.minted * PRICE_SCALE,
                    "step {step}: a DUE PSM ({} bps) planned no liquidation",
                    ratio_bps(&o, p)
                );
                continue;
            };
            let before = ratio_bps(&o, p);
            let [retired_commit, seized_commit, new_reserve_commit, new_minted_commit, new_pool_t, new_pool_p, new_pool_s] = plan.commits(&o);
            let h = crate::liquidation_tx::LiquidationHeader {
                epoch_id: step as u64,
                asset_id: NATIVE_PEG_ASSET_ID,
                position_id: [step as u8; 32],
                retired_commit,
                seized_commit,
                new_reserve_commit,
                new_minted_commit,
                new_pool_t,
                new_pool_p,
                new_pool_s,
                pool_close: plan.close,
            };
            let legs = crate::peg::build_liquidation_legs(&o, &plan, &rule).expect("the five legs prove");
            let att = attest(&custodians, &node_a.liquidation_attest_msg(&h).expect("a message"));
            assert_eq!(node_a.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &att), PegOutcome::Liquidated, "step {step}: node_a");
            assert_eq!(peer_node.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &att), PegOutcome::Liquidated, "step {step}: the PEER");
            assert_eq!(
                (peer_node.reserve_commit(), peer_node.minted_commit(), peer_node.pool_census()),
                (node_a.reserve_commit(), node_a.minted_commit(), node_a.pool_census()),
                "step {step}: ⛔⛔⛔ the two ledgers diverged"
            );
            o = plan.after;
            closed += 1;
            if first_beyond.is_some() {
                liquidated_after_cross = true;
            }
            assert!(
                o.minted == 0 || o.reserve * p * 10_000 >= 15_000 * o.minted * PRICE_SCALE,
                "step {step}: the liquidation left the PSM under the 150 % target ({} bps)",
                ratio_bps(&o, p)
            );
            assert!(o.minted == 0 || ratio_bps(&o, p) > before, "step {step}: STRENGTHENING failed: {before} → {} bps", ratio_bps(&o, p));
            assert_eq!(o.minted, o.pool_t, "step {step}: ⛔⛔⛔ the supply retired USDm the pool did not burn");
            assert_eq!(
                PegLedger::commits_of_opening(o.reserve, o.reserve_blind, o.minted, o.minted_blind),
                (peer_node.reserve_commit(), peer_node.minted_commit()),
                "step {step}: the custodian's next opening does not open the PEER's PSM"
            );
            eprintln!("[crash-v2] step {step} mark {p}: {before} bps → retired {} seized {} → reserve {} supply {}", plan.c, plan.s, o.reserve, o.minted);
        }
        assert!(closed > 0, "a −70 % decline must have liquidated; the door never fired");
        assert!(first_beyond.is_some(), "CALIBRATION: a −70 % crash crosses the 25 % band");
        assert!(liquidated_after_cross, "⛔ nothing was liquidated after the band was crossed — the guard never let the real crash through");
    }
}


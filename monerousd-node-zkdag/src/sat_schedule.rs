// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! SATOSHI (SAT) — the issuance schedule and the public custody pendulum, as PURE arithmetic with no dependency, so the
//! value laws are model-checked on this exact source (`kani-proofs`, path-included: the cap, the halving, the pendulum's
//! bounds). [`crate::satoshi`] re-exports every item; read them there.

/// 1 SAT = 10^8 base units.
pub const BASE_UNITS_PER_SAT: u64 = 100_000_000;
/// The hard SUPPLY cap: 21,000,000 SAT = the reward schedule ([`SAT_REWARD_CAP`]) + the developer set-aside's bound
/// ([`SAT_SET_ASIDE_MAX`]). SAT has exactly three doors (spec §11.4): the block reward (capped at the fold by
/// [`crate::peg::PegLedger::credit_sat_reward`] against [`SAT_REWARD_CAP`]), the genesis set-aside (a constant note set whose
/// committed sum is proven ≤ [`SAT_SET_ASIDE_MAX`]), and a spend that conserves SAT.
pub const SATOSHI_CAP: u64 = 21_000_000 * BASE_UNITS_PER_SAT;
/// ⭐ §BR-13 (user 2026-10-25, docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §11): block rewards sum to 19,000,000 SAT.
pub const SAT_REWARD_CAP: u64 = 19_000_000 * BASE_UNITS_PER_SAT;
/// ⭐ §BR-13: the developer set-aside at genesis is AT MOST 2,000,000 SAT (9.5 %); the exact amount is private forever
/// (anywhere in [0, 2M]); the unused part is never created. `SAT_REWARD_CAP + SAT_SET_ASIDE_MAX == SATOSHI_CAP` is asserted
/// at compile time below.
pub const SAT_SET_ASIDE_MAX: u64 = 2_000_000 * BASE_UNITS_PER_SAT;
const _: () = assert!(SAT_REWARD_CAP + SAT_SET_ASIDE_MAX == SATOSHI_CAP);
/// The mesh's block-rate target this schedule is laid on, in ms: `dag::MESH_TARGET_SPACING_MS` (finding A-F60: the target is
/// derived from a block's bytes and Tor's lane rate; 3,221 ms on 2026-11-16), READ from the one dependency-free
/// source `chain_timing.rs`, which `kani-proofs` path-includes beside this file, so the schedule follows the chain's timing by
/// construction. MEASURED why it is no longer a literal (2026-11-16): c183575b moved the derived target 5,322 → 3,221 ms and the
/// hand-copied literal here stayed 5,322, so blocks came 1.65× faster than the schedule was laid for and SAT would have issued
/// 1.65× faster per year than §BR-13 approved; the one pin that compared them was red and no landing gate ran it.
pub const SCHEDULE_TARGET_SPACING_MS: u64 = crate::chain_timing::MESH_TARGET_SPACING_MS;
/// Blocks per halving era: four (Julian) years at the mesh's block-rate TARGET, 4 × 365.25 × 86,400,000 ms ÷ the target.
/// Derived, not tuned. A-F60 moved the target from 500 ms (to 5,322, then 3,221, now 1,953 ms: chain_timing::MESH_TARGET_SPACING_MS, so 64,634,101 blocks); the era stays FOUR YEARS and the reward per block
/// grows by the same factor, so SAT issued per year is what §BR-13 approved, to the base unit's rounding.
pub const HALVING_INTERVAL: u64 = 4 * 36_525 * 864_000 / SCHEDULE_TARGET_SPACING_MS;
/// The first era's reward per block, in base units: half the REWARD cap spread over the first era (a geometric series of
/// halvings sums to the reward cap). §BR-13: 3,762,960 base units ≈ 0.0376 SAT (was 4,159,090 ≈ 0.0416 against the 21M
/// supply cap before the set-aside was disclosed).
pub const INITIAL_REWARD: u64 = SAT_REWARD_CAP / (2 * HALVING_INTERVAL);

/// The reward a block whose parent key is `key` may mint. Zero after 63 halvings (the shift would empty it anyway).
#[must_use]
pub fn reward_at(key: u64) -> u64 {
    let era = key / HALVING_INTERVAL;
    if era >= 63 {
        0
    } else {
        INITIAL_REWARD >> era
    }
}

/// ⭐⭐⭐ SATOSHI §10.5–§10.8 — THE PUBLIC INCENTIVE PENDULUM (user ruling 2026-10-05: "Public pendulum").
///
/// thornode's `getPoolShare` (gitlab.com/thorchain/thornode, develop, x/thorchain/manager_network_current.go), with MonerousD's
/// PUBLIC inputs only — never the confidential reserve (a reward that is a function of it discloses it to the payee), never a
/// price (every bonder gains from a low one):
/// - `securing` = TOTAL SAT custody weight (a WEIGHTED takeover must outbid it; splitting a bond into dust seats cannot move it);
/// - `secured`  = issued SAT / 3, so the 50/50 point sits at two thirds of issued SAT bonded.
/// `securing ≤ secured ⇒ 10,000 bps` (thornode: "no payments to liquidity providers when more liquidity than security" — every
/// unit of income to bonders); otherwise the bonders' share is `secured / securing`.
#[must_use]
pub fn bonder_share_bps(custody_total: u128, sat_issued: u128) -> u32 {
    let secured = sat_issued / 3;
    if custody_total <= secured {
        return 10_000;
    }
    // secured < custody_total ⇒ the quotient is < 10,000; computed in u128, so no product overflows for any u64 supply
    u32::try_from(secured.saturating_mul(10_000) / custody_total).unwrap_or(10_000)
}

/// The custody bonders' rate for an epoch whose share is `share_bps`: `base` at the 50/50 point, up to 2× while bond is thin,
/// falling as bond grows (§10.8). `base` is the governance `custody_yield_base` (USDm base units per SAT base unit per epoch,
/// scaled by `CUSTODY_YIELD_SCALE`); no price and no reserve term.
#[must_use]
pub fn custody_rate(base: u64, share_bps: u32) -> u64 {
    let share = u128::from(share_bps.min(10_000));
    u64::try_from(u128::from(base) * share / 5_000).unwrap_or(u64::MAX)
}

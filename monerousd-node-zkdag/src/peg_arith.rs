// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Pure arithmetic for the bidirectional peg — extracted so Kani can path-include this file with
//! zero crate dependencies. The shipping `peg.rs` re-exports everything here.

/// `num * 10_000 / den` without u128 overflow. When `num * 10_000` fits, exact; when it
/// overflows (both operands > ~3.4e34), the result is within ±1 bps of the true value.
fn bps_of_ratio(num: u128, den: u128) -> u128 {
    match num.checked_mul(10_000) {
        Some(product) => product / den,
        None => {
            let nk = num / 10_000;
            let dk = den / 10_000;
            if dk == 0 { 9_999 } else { nk * 10_000 / dk }
        }
    }
}

/// 0.25 % — a small redemption from a healthy, over-collateralised reserve.
pub const WITHDRAW_FEE_MIN_BPS: u32 = 25;
/// 90 % — a near-total drain (the reserve keeps >= the rest).
pub const WITHDRAW_FEE_MAX_BPS: u32 = 9_000;

/// The dynamic withdrawal fee (basis points) for drawing `draw_units` out of a reserve currently holding
/// `reserve_units`, as a CONVEX function of utilization `u = draw/reserve`: `fee = min + (max−min)·u²`. Convex in
/// `u` so ordinary small redemptions are near-free while a whale trying to drain the reserve pays an escalating,
/// self-defeating fee (the fee is retained → re-collateralises the reserve). Pure + total (div-safe): an empty
/// reserve returns `max_bps`; `u` is clamped to ≤1 so the fee is bounded by `max_bps`. The `[min_bps, max_bps]`
/// band is the LIVE governance-tunable withdraw-fee band (defaults 25 .. 9000), threaded here so a governance
/// retune of redemption cost takes effect at once — never a hardcoded fee.
pub fn withdrawal_fee_bps(
    reserve_units: u128,
    draw_units: u128,
    min_bps: u32,
    max_bps: u32,
) -> u32 {
    let max_bps = max_bps.min(10_000);
    let min_bps = min_bps.min(max_bps);
    if reserve_units == 0 || draw_units >= reserve_units {
        return max_bps;
    }
    let u_bps = bps_of_ratio(draw_units, reserve_units);
    let u_sq_bps = u_bps * u_bps / 10_000;
    let span = (max_bps - min_bps) as u128;
    (min_bps as u128 + span * u_sq_bps / 10_000) as u32
}

/// ⭐ §BR-14 / spec §1 item 6 — split a protocol fee into (stakers 40 %, SAT bonders 25 %, surplus buffer 25 %, miner pool
/// 10 %), each rounded down, the rounding remainder to the surplus buffer, so the four parts sum to `fee` EXACTLY and none
/// overflows (Kani: `fee_split_conserves_and_keeps_its_shares`, refuted on a planted mutant). Zero-dep, path-included.
#[must_use]
pub fn fee_split(fee: u64) -> (u64, u64, u64, u64) {
    fee_split_at(fee, 0)
}

/// ⭐ §BR-3 17.1 / spec §1 item 6 — the split at halving `era`: the miner pool's share steps up as the block reward halves
/// (10 % in eras 0–1, 15 % in era 2, 20 % from era 3), taken from the stakers' share (40 % → 35 % → 30 %); bonders 25 % and
/// the surplus buffer 25 % throughout. Each share rounded down, the remainder to the surplus buffer, so the four parts sum to
/// `fee` exactly for every (fee, era) (Kani: `fee_split_at_conserves_at_every_era`). A function of the public era only.
#[must_use]
pub fn fee_split_at(fee: u64, era: u64) -> (u64, u64, u64, u64) {
    let (st_pct, mi_pct) = match era {
        0 | 1 => (40u64, 10u64),
        2 => (35, 15),
        _ => (30, 20),
    };
    let pct = |p: u64| fee / 100 * p + (fee % 100) * p / 100;
    let stakers = pct(st_pct);
    let bonders = fee / 4;
    let miner = pct(mi_pct);
    let surplus = fee - stakers - bonders - miner;
    (stakers, bonders, surplus, miner)
}

/// ⭐ §BR-11 — the miner pool's per-block payout for a quarter: the closed quarter's accrual divided by the number of blocks
/// it folded (at least one), rounded down, so `rate × blocks ≤ accrual` — the payouts can never overdraw what the quarter
/// credited (Kani: `miner_rate_never_overdraws`). Zero-dep, path-included.
#[must_use]
pub fn miner_rate(accrual: u64, blocks: u64) -> u64 {
    accrual / blocks.max(1)
}

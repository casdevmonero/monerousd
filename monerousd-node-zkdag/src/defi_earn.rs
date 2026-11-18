// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ EARN — THE PROVIDERS' ARITHMETIC: what a SAT deposit mints and what a withdrawal pays, every term a public rational
//! times the claimant's own amount (the claim relation's shape: one product, one truncation), every rounding toward the pool.
//!
//! A unit of pair `i` stands for `c/√p` SAT and `c·√p` coin of a pool at price `p = Y/X` (coin per SAT), `c` the pair's
//! constant (1: the launch's own units are `S_0 = √(X_0·Y_0)`, public because the launch position is a public donation).
//! `c_pool = √(X·Y)/S` never falls below `c`: a trade keeps `X·Y` (the clearing's invariant, finding A-F46's fix); a deposit
//! mints `u ≤ √(x_b·q)/c` for what it adds, and `√((X+x_b)(Y+q)) ≥ √(X·Y) + √(x_b·q)` (the geometric mean is superadditive);
//! a withdrawal of an EARN batch takes at most each side's pro-rata share (its tick brackets the pool's own ratio). So the
//! public formula never pays more than the pool holds for the units it pays — solvent by construction, at any pool ratio.
//!
//! The square roots are taken on the TICK GRID itself, never as an irrational: `√p_t` is bounded below by tick
//! `⌊t/2⌋ − 1` and above by tick `⌈t/2⌉ + 1` (`1.001^(t/2 ∓ 1)` against `1.001^(t/2)`, a margin of about one tick, far
//! past the grid's ppm rounding), each checked EXACTLY by the pins below over the whole tick range.
//! cons: the one-tick margin on each root costs a withdrawal about 0.1 % on each side and a deposit about 0.1 % of its
//! units, both kept by the pool (its `c_pool` rises, owned by no unit); a SAT deposit pays the trade fee on the half it sells.
//! SAFE AT SCALE: per claim, a constant number of 128-bit operations; nothing grows with providers, pairs or height.
//! AI RESISTANT: (a) — every payout below is what the claim relation pins over public rationals the leaf names; this file is
//! the native mirror the wallet quotes from and the pins measure.

use crate::defi_clear::{tick_mantissa, tick_ratio};

/// ⭐ An EARN batch: every `EARN_EVERY`-th batch of a pair (by its public number) clears no trade; its one tick is found over
/// the pool alone, so it brackets the pool's own ratio, and withdrawals are paid there.
pub const EARN_EVERY: u64 = 8;

/// Whether batch `batch` of a pair is an Earn batch.
#[must_use]
pub fn is_earn_batch(batch: u64) -> bool {
    batch % EARN_EVERY == EARN_EVERY - 1
}

/// ⭐ EARN STEP 3 — THE INCOME WINDOW on the chain clock (docs/COIN-POOL-DEPOSITS-SPEC-20261111.md, "Step 3 REFUTED … the
/// replacement"): one hour, the custody epoch's (`epoch_deal_tx::EPOCH_MS`). Each pair closes its window at the first batch
/// that opens past the boundary; one EarnEpoch raises every pair's index at the window's one protocol-wide rate; each pair's
/// next batch opening after the raise is its DEPOSIT batch. Cons: a deposit joins at most one window (plus the raise's
/// latency) after it is asked for. SAFE AT SCALE: one EarnEpoch per window whatever the users; AI RESISTANT: (a).
pub const EARN_WINDOW_MS: u64 = crate::epoch_deal_tx::EPOCH_MS;

/// A rational at or BELOW `√p_t`: tick `⌊t/2⌋ − 1`'s price.
#[must_use]
pub fn sqrt_down(t: i64) -> (u128, u128) {
    tick_ratio(t.div_euclid(2) - 1)
}

/// A rational at or ABOVE `√p_t`: tick `⌈t/2⌉ + 1`'s price.
#[must_use]
pub fn sqrt_up(t: i64) -> (u128, u128) {
    tick_ratio(-(-t).div_euclid(2) + 1)
}

/// `⌊a·num/den⌋` for an amount `a` and a tick rational (`None` past 2^64): the claim relation's own product.
#[must_use]
pub fn times(a: u64, (num, den): (u128, u128)) -> Option<u64> {
    usdm_decider::br15_audit::claim_out(a, num, den)
}

/// What a SAT deposit of `x` does at its batch's tick `t` (a TRADING batch): `x_s = ⌊x/2⌋` is SOLD through the batch (it
/// is a sell: it enters `ΔX`, pays the fee, moves the price like any sell) and its coin `q` stays in the pool; `x_b =
/// ⌈q·d_t/n_t⌉` SAT of the other half joins `q` at the tick; the rest comes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositTerms {
    pub sold: u64,
    pub coin: u64,
    pub joined: u64,
    pub refund: u64,
    pub units: u64,
}

/// The deposit's terms (`None` past 2^64 or for a deposit too small to sell a unit).
#[must_use]
pub fn deposit_terms(x: u64, t: i64) -> Option<DepositTerms> {
    let sold = x / 2;
    let (n, d) = tick_ratio(t);
    let coin = usdm_decider::br15_audit::sell_paid(sold, n, d)?;
    // ⌈q·d/n⌉: the SAT that matches the coin at the tick, rounded toward the pool
    let joined = {
        let fl = times(coin, (d, n))?;
        if u128::from(fl) * n == u128::from(coin) * d { fl } else { fl.checked_add(1)? }
    };
    let refund = (x - sold).checked_sub(joined)?;
    // u = ⌊q / (c·r')⌋, r' ≥ √p_t: then u·c ≤ q/√p_t ≤ √(x_b·q) because x_b ≥ q/p_t
    let (rn, rd) = sqrt_up(t);
    let units = times(coin, (rd, rn))?;
    Some(DepositTerms { sold, coin, joined, refund, units })
}

/// What a withdrawal of `u` units pays at an EARN batch whose tick `a` brackets the pool's ratio (`p_a ≤ Y/X < p_{a+1}`):
/// `⌊u·c/r'⌋` SAT with `r' ≥ √p_{a+1}` and `⌊u·c·r⌋` coin with `r ≤ √p_a` — each at most the unit's pro-rata share.
#[must_use]
pub fn withdraw_terms(u: u64, a: i64) -> Option<(u64, u64)> {
    let (un, ud) = sqrt_up(a + 1);
    let sat = times(u, (ud, un))?;
    let coin = times(u, sqrt_down(a))?;
    Some((sat, coin))
}

/// The same withdrawal paid wholly in SAT (the Earn batch's coin-floor bit is set): its coin side converted at `p_{a+1}`,
/// toward the pool.
#[must_use]
pub fn withdraw_all_sat(u: u64, a: i64) -> Option<u64> {
    let (sat, coin) = withdraw_terms(u, a)?;
    let (n1, d1) = tick_ratio(a + 1);
    sat.checked_add(times(coin, (d1, n1))?)
}

/// `r² ≤ p_t` exactly, on the grid's own mantissas (`1.001^k = m·2^(e−23)`): `m_r²·2^(2e_r) ≤ m_p·2^(e_p+23)`.
#[must_use]
pub fn squared_at_most(k: i64, t: i64) -> bool {
    let (mr, er) = tick_mantissa(k);
    let (mp, ep) = tick_mantissa(t);
    let (lhs, rhs) = (mr * mr, mp);
    let shift = 2 * er - ep - 23;
    // compare lhs·2^shift with rhs (both below 2^48; shift is small but signed)
    if shift >= 0 { (lhs << shift.min(80)) <= rhs } else { lhs <= (rhs << (-shift).min(80)) }
}

/// `r² ≥ p_t` exactly, the same comparison the other way.
#[must_use]
pub fn squared_at_least(k: i64, t: i64) -> bool {
    let (mr, er) = tick_mantissa(k);
    let (mp, ep) = tick_mantissa(t);
    let (lhs, rhs) = (mr * mr, mp);
    let shift = 2 * er - ep - 23;
    if shift >= 0 { (lhs << shift.min(80)) >= rhs } else { lhs >= (rhs << (-shift).min(80)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ THE ROOTS ARE BOUNDS, EXACTLY: over the whole tick range, `sqrt_down(t)² ≤ p_t ≤ sqrt_up(t)²` on the grid's own
    /// mantissas. CALIBRATION: the tick `⌊t/2⌋ + 1` (no margin the other way) is above `√p_t` for some `t`, so the margin is
    /// what makes the bound hold, not luck.
    #[test]
    fn earn_the_square_roots_bound_every_tick_from_below_and_above() {
        let mut above = false;
        for t in (-crate::defi_clear::TICK_RANGE + 4..crate::defi_clear::TICK_RANGE - 4).step_by(37) {
            assert!(squared_at_most(t.div_euclid(2) - 1, t), "⛔ sqrt_down({t})² exceeds p_t");
            assert!(squared_at_least(-(-t).div_euclid(2) + 1, t), "⛔ sqrt_up({t})² is below p_t");
            above |= !squared_at_most(t.div_euclid(2) + 1, t);
        }
        assert!(above, "CALIBRATION: one tick past the half is above the root somewhere");
    }

    /// ⭐ A WITHDRAWAL NEVER TAKES MORE THAN ITS SHARE: for pools at any ratio inside an Earn batch's bracket and any
    /// `c_pool ≥ 1`, each side paid is at most `u·X/S` and `u·Y/S`. TAMPER: paying the SAT side at `√p_a` (the bracket's
    /// low end) over-pays on some pool.
    #[test]
    fn earn_a_withdrawal_takes_at_most_its_share_on_each_side() {
        let mut seed = 0xEA21_u64;
        let mut r = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut tamper_overpaid = false;
        for _ in 0..400 {
            let a = (r() % 4_000) as i64 - 2_000;
            let (n0, d0) = tick_ratio(a);
            let (n1, d1) = tick_ratio(a + 1);
            let x = 1_000_000 + u128::from(r() % 1_000_000_000);
            // Y inside [p_a·X, p_{a+1}·X)
            let lo = x * n0 / d0 + 1;
            let hi = (x * n1 / d1).max(lo + 1);
            let y = lo + u128::from(r()) % (hi - lo);
            // S with c_pool = √(XY)/S ≥ 1: S ≤ √(XY)
            let s = ((x * y) as f64).sqrt() as u128 * (1_000 - u128::from(r() % 50)) / 1_000;
            let u = 1 + u128::from(r()) % s;
            let (sat, coin) = withdraw_terms(u as u64, a).expect("fits");
            assert!(u128::from(sat) * s <= u * x, "⛔ a withdrawal took more SAT than its share (a={a})");
            assert!(u128::from(coin) * s <= u * y, "⛔ a withdrawal took more coin than its share (a={a})");
            let (dn, dd) = sqrt_down(a);
            if u128::from(times(u as u64, (dd, dn)).expect("fits")) * s > u * x {
                tamper_overpaid = true;
            }
        }
        assert!(tamper_overpaid, "TAMPER: the SAT side paid at the bracket's low root over-pays on some pool");
    }

    /// ⭐ A DEPOSIT NEVER DILUTES: its units are at most `√(joined·coin)` (so `c_pool` cannot fall), it never refunds more
    /// than it brought, and the coin its sold half got is the sellers' own price less the fee.
    #[test]
    fn earn_a_deposit_mints_at_most_what_it_adds() {
        for (x, t) in [(10_000u64, 0i64), (1_000_000, 693), (123_456_789, -1_400), (5_000_000_000, 2_400), (7, 0)] {
            let Some(d) = deposit_terms(x, t) else { continue };
            assert!(d.sold + d.joined + d.refund == x, "the deposit's SAT is all accounted for");
            let u = u128::from(d.units);
            assert!(u * u <= u128::from(d.joined) * u128::from(d.coin), "⛔ a deposit minted more units than √(x_b·q)");
        }
    }
}

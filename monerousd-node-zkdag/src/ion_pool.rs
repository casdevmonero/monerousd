// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ IONSWAP POOLS — THE ARITHMETIC (docs/IONSWAP-POOLS-SPEC-20261110.md §2, §3, §6; lane goods, 2026-11-10).
//!
//! What a pool does to numbers, and nothing else: no object, no door, no proof, no state of any node. This is the part
//! of the spec that can be measured before a line of chain plumbing exists, so it is written and pinned first. The
//! objects that will call it are refuted on the bus before they are written (§9.3).
//!
//! THE RULES, each borrowed and cited:
//!
//! * **The curve** is the constant product `x · y` (Uniswap v2).
//! * **One price for a block** (Penumbra's batch, CoW's uniform clearing): all the trades of a block for one pool
//!   clear at `p = (Y + ΔY) / (X + ΔX)`, the chain's own clearing rule ([`crate::defi_clear::clear`]: "everyone
//!   deposits, then withdraws at the new ratio"). No order in a block is priced after another, so none can be
//!   sandwiched. An order whose floor the block's price does not meet is returned WHOLE; dropping it changes the
//!   price, so the rule is applied again until every order left clears at the price it sees.
//! * **Removals first, additions last.** A provider leaving is paid at the balances the block started with; a
//!   provider entering joins at the balances it ends with. Neither is priced by the block's own trades.
//! * **Shares** (Uniswap v2): the first provider gets `⌊√(x·y)⌋`, of which [`MINIMUM_SHARES`] are locked for ever
//!   (the first-depositor inflation attack and its fix); later providers get `⌊S · min(x/X, y/Y)⌋` and are handed back
//!   what does not fit the ratio.
//! * **The launch curve** (pump.fun's shape): the whole supply against a base amount `V` that does not exist,
//!   `x · (real + V) = X₀ · V`. A sell can only return tokens the curve sold, so `real` never goes below zero. When
//!   `real` reaches [`GRADUATION_BASE`] the curve becomes the pool at the same price, the tokens the pool does not need
//!   are burned, and every share of that opening liquidity is locked.
//! * **The fee** is taken from an order's INPUT and split four ways ([`FeeSplit`]). The pool's part stays in the pool.
//!
//! ROUNDING: every division rounds against the person the order belongs to and for the pool. The pins hold that the
//! product of the balances never falls across a batch with no removal, that a share never loses value, and that every
//! unit is accounted for (what came in equals what the pool gained plus what was paid out plus the three fee parts).
//!
//! cons: none of its own; this module moves nothing. The design's cons are the spec's §8.

use crate::defi_clear::clear;

/// The fee of one trade, in hundredths of a percent of its input, and where each part goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeSplit {
    /// Stays in the pool (its providers and its locked liquidity) or in the launch curve.
    pub pool_bps: u128,
    /// The token's creator.
    pub creator_bps: u128,
    /// The protocol's fee split (stakers, SAT bonders, buffer, miners).
    pub protocol_bps: u128,
    /// The publisher of the pool program (the chain-enforced contract publisher fee).
    pub publisher_bps: u128,
}

impl FeeSplit {
    pub const fn total_bps(&self) -> u128 {
        self.pool_bps + self.creator_bps + self.protocol_bps + self.publisher_bps
    }
}

/// A pool trade: 0.30 % in all (Uniswap v2's figure): 0.20 pool, 0.05 creator, 0.03 protocol, 0.02 publisher.
// PRODUCTION-SCALE-REVIEWED: fee rates in basis points, not sizes or counts of anything.
pub const POOL_FEE: FeeSplit = FeeSplit { pool_bps: 20, creator_bps: 5, protocol_bps: 3, publisher_bps: 2 };
/// A launch-curve trade: 0.80 % in all: 0.50 stays in the curve (and becomes locked pool liquidity), 0.15 creator,
/// 0.10 protocol, 0.05 publisher.
// PRODUCTION-SCALE-REVIEWED: fee rates in basis points, not sizes or counts of anything.
pub const CURVE_FEE: FeeSplit = FeeSplit { pool_bps: 50, creator_bps: 15, protocol_bps: 10, publisher_bps: 5 };
const BPS: u128 = 10_000;

/// Shares locked for ever when a pool gets its first liquidity (Uniswap v2's `MINIMUM_LIQUIDITY`): with them a share
/// can never be made worth so much that the next provider's deposit rounds to zero shares.
// PRODUCTION-SCALE-REVIEWED: Uniswap v2's own constant, in share units (a dust amount), not a bound on any set.
pub const MINIMUM_SHARES: u128 = 1_000;
/// The base amount a launch curve starts against (it does not exist; it only sets the starting price): 5,000 USDm.
pub const LAUNCH_VIRTUAL_BASE: u128 = 5_000 * 100_000_000;
/// The real base at which a launch curve becomes the pool: 50,000 USDm.
pub const GRADUATION_BASE: u128 = 50_000 * 100_000_000;

/// A pool: the token balance, the base balance, the shares outstanding, and how many of them nobody can ever remove.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Pool {
    pub x: u128,
    pub y: u128,
    pub shares: u128,
    pub locked: u128,
}

/// A launch curve: tokens left, the real base in it, the base that does not exist, and the supply it started with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Curve {
    pub x: u128,
    pub real: u128,
    pub v: u128,
    pub x0: u128,
}

/// One order of a block's batch. Amounts are atomic units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    /// Give `amount` of the token, take base; refuse less than `min_out`.
    Sell { amount: u128, min_out: u128 },
    /// Give `amount` of base, take the token; refuse less than `min_out`.
    Buy { amount: u128, min_out: u128 },
    /// Bring both assets for shares.
    Add { x: u128, y: u128 },
    /// Hand shares back for both assets.
    Remove { shares: u128 },
}

/// What an order's owner is paid. It states BOTH assets and the shares, so a caller cannot forget a refund.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Paid {
    pub x: u128,
    pub y: u128,
    pub shares: u128,
    /// The order was returned whole (its floor was not met, or it could not be applied): the amounts above are its input.
    pub returned: bool,
}

/// The three fee parts that leave the pool, per asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FeesOut {
    pub creator_x: u128,
    pub creator_y: u128,
    pub protocol_x: u128,
    pub protocol_y: u128,
    pub publisher_x: u128,
    pub publisher_y: u128,
}

/// A trade's input after the whole fee, and the three parts of the fee that leave the pool. The pool's own part is
/// `amount − net − creator − protocol − publisher` and stays. The whole fee is rounded UP (against the trader); the
/// three parts that leave are rounded down (for the pool).
fn fee_of(amount: u128, f: &FeeSplit) -> Option<(u128, u128, u128, u128)> {
    let total = amount.checked_mul(f.total_bps())?.div_ceil(BPS);
    let part = |bps: u128| amount.checked_mul(bps).map(|v| v / BPS);
    Some((amount.checked_sub(total)?, part(f.creator_bps)?, part(f.protocol_bps)?, part(f.publisher_bps)?))
}

/// The floor of a square root, exact for every `u128` (Newton's step from above).
fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut r = 1u128 << (128 - n.leading_zeros()).div_ceil(2);
    loop {
        let next = (r + n / r) / 2;
        if next >= r {
            return r;
        }
        r = next;
    }
}

/// The trades of one batch against balances `(x, y)`: who clears, what each is paid, and the balances after. Orders
/// that are not trades are left alone. An order is returned whole when its floor is not met at the price of the orders
/// that DO clear; the rule is applied until no further order drops (each pass drops at least one, so it ends).
fn trades(x: u128, y: u128, orders: &[Order], fee: &FeeSplit, paid: &mut [Paid], out: &mut FeesOut) -> Option<(u128, u128)> {
    // an order of nothing is nothing: it stays returned, never laid as a zero that moves a price by rounding
    let mut live: Vec<usize> = (0..orders.len())
        .filter(|&i| matches!(orders[i], Order::Sell { amount, .. } | Order::Buy { amount, .. } if amount > 0))
        .collect();
    loop {
        if live.is_empty() {
            return Some((x, y));
        }
        let (mut sells, mut buys, mut who_s, mut who_b) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for &i in &live {
            match orders[i] {
                Order::Sell { amount, .. } => {
                    sells.push(fee_of(amount, fee)?.0);
                    who_s.push(i);
                }
                Order::Buy { amount, .. } => {
                    buys.push(fee_of(amount, fee)?.0);
                    who_b.push(i);
                }
                _ => {}
            }
        }
        let c = clear(x, y, &sells, &buys)?;
        let mut dropped = Vec::new();
        for (k, &i) in who_s.iter().enumerate() {
            if matches!(orders[i], Order::Sell { min_out, .. } if c.seller_out[k] < min_out) {
                dropped.push(i);
            }
        }
        for (k, &i) in who_b.iter().enumerate() {
            if matches!(orders[i], Order::Buy { min_out, .. } if c.buyer_out[k] < min_out) {
                dropped.push(i);
            }
        }
        if !dropped.is_empty() {
            live.retain(|i| !dropped.contains(i));
            continue;
        }
        // every order left clears at this price: pay it, and keep the pool's part of each fee in the pool
        let (mut px, mut py) = (c.pool_x, c.pool_y);
        for (k, &i) in who_s.iter().enumerate() {
            if let Order::Sell { amount, .. } = orders[i] {
                let (net, cr, pr, pb) = fee_of(amount, fee)?;
                paid[i] = Paid { y: c.seller_out[k], ..Paid::default() };
                out.creator_x += cr;
                out.protocol_x += pr;
                out.publisher_x += pb;
                px = px.checked_add(amount - net - cr - pr - pb)?;
            }
        }
        for (k, &i) in who_b.iter().enumerate() {
            if let Order::Buy { amount, .. } = orders[i] {
                let (net, cr, pr, pb) = fee_of(amount, fee)?;
                paid[i] = Paid { x: c.buyer_out[k], ..Paid::default() };
                out.creator_y += cr;
                out.protocol_y += pr;
                out.publisher_y += pb;
                py = py.checked_add(amount - net - cr - pr - pb)?;
            }
        }
        return Some((px, py));
    }
}

/// An order handed back whole.
fn returned(o: &Order) -> Paid {
    match *o {
        Order::Sell { amount, .. } => Paid { x: amount, returned: true, ..Paid::default() },
        Order::Buy { amount, .. } => Paid { y: amount, returned: true, ..Paid::default() },
        Order::Add { x, y } => Paid { x, y, returned: true, ..Paid::default() },
        Order::Remove { shares } => Paid { shares, returned: true, ..Paid::default() },
    }
}

/// ⭐ ONE BLOCK'S BATCH AGAINST A POOL. Returns the pool after, what each order's owner is paid (same order as
/// `orders`), and the fee parts that leave. `None` only for an arithmetic overflow, which refuses the whole batch.
#[must_use]
pub fn step(pool: &Pool, orders: &[Order]) -> Option<(Pool, Vec<Paid>, FeesOut)> {
    let mut p = *pool;
    let mut paid: Vec<Paid> = orders.iter().map(returned).collect();
    let mut fees = FeesOut::default();
    // 1. removals, at the balances the block started with
    for (i, o) in orders.iter().enumerate() {
        if let Order::Remove { shares } = *o {
            // a locked share belongs to nobody, so nobody can hand one back; the check keeps the invariant if a caller errs
            if shares == 0 || shares > p.shares.saturating_sub(p.locked) {
                continue;
            }
            let (ox, oy) = (p.x.checked_mul(shares)? / p.shares, p.y.checked_mul(shares)? / p.shares);
            p = Pool { x: p.x - ox, y: p.y - oy, shares: p.shares - shares, locked: p.locked };
            paid[i] = Paid { x: ox, y: oy, ..Paid::default() };
        }
    }
    // 2. trades, at one price (a pool with an empty side prices nothing: its trades stay returned)
    if p.x > 0 && p.y > 0 {
        let (nx, ny) = trades(p.x, p.y, orders, &POOL_FEE, &mut paid, &mut fees)?;
        p.x = nx;
        p.y = ny;
    }
    // 3. additions, at the balances the block ends with
    for (i, o) in orders.iter().enumerate() {
        if let Order::Add { x, y } = *o {
            if p.shares == 0 {
                let s = isqrt(x.checked_mul(y)?);
                if s <= MINIMUM_SHARES {
                    continue; // too little to open a pool: returned whole
                }
                p = Pool { x, y, shares: s, locked: MINIMUM_SHARES };
                paid[i] = Paid { shares: s - MINIMUM_SHARES, ..Paid::default() };
                continue;
            }
            if p.x == 0 || p.y == 0 {
                continue;
            }
            let s = (x.checked_mul(p.shares)? / p.x).min(y.checked_mul(p.shares)? / p.y);
            if s == 0 {
                continue;
            }
            // what those shares are worth, rounded UP: a provider never gets a share for less than its part of the pool
            let (ux, uy) = (s.checked_mul(p.x)?.div_ceil(p.shares), s.checked_mul(p.y)?.div_ceil(p.shares));
            p = Pool { x: p.x.checked_add(ux)?, y: p.y.checked_add(uy)?, shares: p.shares.checked_add(s)?, locked: p.locked };
            paid[i] = Paid { x: x - ux, y: y - uy, shares: s, returned: false };
        }
    }
    Some((p, paid, fees))
}

impl Curve {
    /// A launch curve holding a token's whole supply.
    pub fn open(supply: u128) -> Curve {
        Curve { x: supply, real: 0, v: LAUNCH_VIRTUAL_BASE, x0: supply }
    }
}

/// What a batch did to a launch curve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CurveStep {
    /// Still a curve.
    Curve(Curve),
    /// The curve reached [`GRADUATION_BASE`]: it is now this pool (every share locked), and `burned` tokens are gone.
    Graduated { pool: Pool, burned: u128 },
}

/// ⭐ ONE BLOCK'S BATCH AGAINST A LAUNCH CURVE. Only trades happen on a curve; an addition or a removal is returned
/// whole (nobody provides to a curve, and nobody holds shares in one).
#[must_use]
pub fn curve_step(c: &Curve, orders: &[Order]) -> Option<(CurveStep, Vec<Paid>, FeesOut)> {
    let mut paid: Vec<Paid> = orders.iter().map(returned).collect();
    let mut fees = FeesOut::default();
    let (nx, ny) = trades(c.x, c.real.checked_add(c.v)?, orders, &CURVE_FEE, &mut paid, &mut fees)?;
    // ⛔ THE BASE THAT DOES NOT EXIST IS NEVER PAID. With the whole supply started on the curve this cannot happen (a
    // sell returns only what the curve sold); if it would, every order of the batch is returned and the curve stands.
    if ny < c.v {
        return Some((CurveStep::Curve(*c), orders.iter().map(returned).collect(), FeesOut::default()));
    }
    let after = Curve { x: nx, real: ny - c.v, v: c.v, x0: c.x0 };
    if after.real < GRADUATION_BASE {
        return Some((CurveStep::Curve(after), paid, fees));
    }
    // graduation: the pool opens with all the real base and the tokens that keep the price where it is
    let keep = after.x.checked_mul(after.real)? / after.v.checked_add(after.real)?;
    let shares = isqrt(keep.checked_mul(after.real)?);
    let pool = Pool { x: keep, y: after.real, shares, locked: shares };
    Some((CurveStep::Graduated { pool, burned: after.x - keep }, paid, fees))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ARITHMETIC ONLY: these pins hold the numbers of a batch. Whether two nodes agree on a pool is decided by the
    // objects that will call this module, which do not exist yet, and then on real nodes (spec §10).
    const U: u128 = 100_000_000;

    /// A walk of pseudo-random numbers for the batches below (the same walk every run, so a failure can be replayed).
    struct Walk(u64);
    impl Walk {
        fn next(&mut self, below: u128) -> u128 {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            u128::from(self.0 >> 11) % below.max(1)
        }
    }

    /// A 256-bit product as `(high, low)`, so two products of large numbers compare exactly.
    fn wide(a: u128, b: u128) -> (u128, u128) {
        const M: u128 = (1 << 64) - 1;
        let (a1, a0, b1, b0) = (a >> 64, a & M, b >> 64, b & M);
        let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
        let mid = (p00 >> 64) + (p01 & M) + (p10 & M);
        (p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64), (p00 & M) | ((mid & M) << 64))
    }

    fn total_in(orders: &[Order]) -> (u128, u128, u128) {
        orders.iter().fold((0, 0, 0), |(x, y, s), o| match *o {
            Order::Sell { amount, .. } => (x + amount, y, s),
            Order::Buy { amount, .. } => (x, y + amount, s),
            Order::Add { x: ax, y: ay } => (x + ax, y + ay, s),
            Order::Remove { shares } => (x, y, s + shares),
        })
    }

    #[test]
    fn every_unit_is_accounted_for_and_a_share_never_loses_value_over_random_batches() {
        let mut w = Walk(0x10f5);
        let (first, opened, _) = step(&Pool::default(), &[Order::Add { x: 1_000_000 * U, y: 50_000 * U }]).unwrap();
        let mut pool = first;
        let mut held = opened[0].shares; // the shares people hold
        let (mut cleared, mut handed_back) = (0u32, 0u32);
        for round in 0..400 {
            let n = 1 + w.next(6) as usize;
            let mut orders = Vec::new();
            let mut asked = 0u128;
            for _ in 0..n {
                orders.push(match w.next(5) {
                    0 | 1 => Order::Sell { amount: w.next(20_000 * U), min_out: if w.next(4) == 0 { w.next(2_000 * U) } else { 0 } },
                    2 | 3 => Order::Buy { amount: w.next(1_000 * U), min_out: if w.next(4) == 0 { w.next(40_000 * U) } else { 0 } },
                    _ if w.next(2) == 0 => Order::Add { x: w.next(50_000 * U), y: w.next(2_500 * U) },
                    _ => {
                        let s = w.next((held - asked) / 3 + 1);
                        asked += s;
                        Order::Remove { shares: s }
                    }
                });
            }
            let (after, paid, fees) = step(&pool, &orders).expect("no overflow at these sizes");
            let (in_x, in_y, in_s) = total_in(&orders);
            let (out_x, out_y, out_s) = paid.iter().fold((0, 0, 0), |(x, y, s), p| (x + p.x, y + p.y, s + p.shares));
            // every unit: what came in = what the pool gained + what was paid out + the fee parts that leave
            assert_eq!(pool.x + in_x, after.x + out_x + fees.creator_x + fees.protocol_x + fees.publisher_x, "token units, round {round}");
            assert_eq!(pool.y + in_y, after.y + out_y + fees.creator_y + fees.protocol_y + fees.publisher_y, "base units, round {round}");
            // shares: handed in by removers, handed out to adders, the rest is the pool's count
            let minted: u128 = paid.iter().zip(&orders).filter(|(p, o)| matches!(o, Order::Add { .. }) && !p.returned).map(|(p, _)| p.shares).sum();
            let kept: u128 = paid.iter().zip(&orders).filter(|(p, o)| matches!(o, Order::Remove { .. }) && p.returned).map(|(p, _)| p.shares).sum();
            assert_eq!(out_s, minted + kept, "no share is paid to an order that is neither an addition nor a returned removal");
            let burned = in_s - kept;
            assert_eq!(after.shares, pool.shares + minted - burned, "shares, round {round}");
            assert_eq!(after.locked, MINIMUM_SHARES, "locked shares never move");
            held = held + minted - burned;
            // one share's value never falls: (x·y)/S² after >= before, compared exactly
            assert!(
                wide(after.x * after.y, pool.shares * pool.shares) >= wide(pool.x * pool.y, after.shares * after.shares),
                "a share lost value in round {round}"
            );
            if !orders.iter().any(|o| matches!(o, Order::Remove { .. })) {
                assert!(after.x * after.y >= pool.x * pool.y, "the product fell with no removal, round {round}");
            }
            cleared += paid.iter().filter(|p| !p.returned).count() as u32;
            handed_back += paid.iter().filter(|p| p.returned).count() as u32;
            pool = after;
        }
        // the walk exercised both outcomes, or the assertions above measured nothing
        assert!(cleared > 500 && handed_back > 50, "cleared {cleared}, returned {handed_back}");
    }

    #[test]
    fn everyone_in_a_block_gets_one_price_so_a_place_inside_it_buys_nothing() {
        let pool = Pool { x: 1_000_000 * U, y: 50_000 * U, shares: 1, locked: 0 };
        let big = Order::Buy { amount: 5_000 * U, min_out: 0 };
        let small = Order::Buy { amount: 50 * U, min_out: 0 };
        let (_, a, _) = step(&pool, &[big, small]).unwrap();
        let (_, b, _) = step(&pool, &[small, big]).unwrap();
        assert_eq!((a[0].x, a[1].x), (b[1].x, b[0].x), "what an order is paid does not depend on where it sits in the block");
        // one price: tokens per base unit agree to the rounding of one unit (cross-multiplied)
        let diff = (a[0].x * 50 * U).abs_diff(a[1].x * 5_000 * U);
        assert!(diff <= 5_000 * U, "the two buyers paid different prices: {diff}");
        // the calibration: a venue that prices one after another does punish the buyer behind the big one
        let (after_big, _, _) = step(&pool, &[big]).unwrap();
        let (_, late, _) = step(&after_big, &[small]).unwrap();
        assert!(late[0].x < a[1].x);
    }

    #[test]
    fn an_order_whose_floor_is_not_met_is_returned_whole_and_the_rest_still_clear() {
        let pool = Pool { x: 1_000_000 * U, y: 50_000 * U, shares: 1, locked: 0 };
        let greedy = Order::Buy { amount: 100 * U, min_out: 1_000_000 * U };
        let plain = Order::Buy { amount: 100 * U, min_out: 0 };
        let (after, paid, _) = step(&pool, &[greedy, plain]).unwrap();
        assert_eq!(paid[0], Paid { y: 100 * U, returned: true, ..Paid::default() });
        assert!(!paid[1].returned && paid[1].x > 0);
        // and the plain order was priced as if the returned one had never been in the block
        let (alone, solo, _) = step(&pool, &[plain]).unwrap();
        assert_eq!((after, paid[1]), (alone, solo[0]));
    }

    #[test]
    fn a_trade_never_beats_the_curve_and_its_fee_reaches_the_four_places() {
        let pool = Pool { x: 1_000_000 * U, y: 50_000 * U, shares: 1, locked: 0 };
        let amount = 1_000 * U;
        let (after, paid, fees) = step(&pool, &[Order::Buy { amount, min_out: 0 }]).unwrap();
        // the fee-less constant-product answer for the whole input is more than anyone is paid
        let ceiling = pool.x - (pool.x * pool.y).div_ceil(pool.y + amount);
        assert!(paid[0].x < ceiling, "paid {} of a fee-less {}", paid[0].x, ceiling);
        assert_eq!(fees.creator_y, amount * 5 / 10_000);
        assert_eq!(fees.protocol_y, amount * 3 / 10_000);
        assert_eq!(fees.publisher_y, amount * 2 / 10_000);
        assert_eq!((fees.creator_x, fees.protocol_x, fees.publisher_x), (0, 0, 0), "a fee is taken in the asset that came in");
        // the pool kept its own part: everything that came in and did not go to the three others
        assert_eq!(after.y, pool.y + amount - fees.creator_y - fees.protocol_y - fees.publisher_y);
        assert!(after.x * after.y > pool.x * pool.y);
    }

    #[test]
    fn the_first_depositor_cannot_make_a_share_too_dear_for_the_next_one() {
        // the attack (Uniswap v2 before its fix): open with dust, then swell the balances so the victim's shares round to zero
        let (dust, paid, _) = step(&Pool::default(), &[Order::Add { x: 1, y: 1 }]).unwrap();
        assert!(paid[0].returned, "a pool cannot be opened with dust");
        assert_eq!(dust, Pool::default());
        // the smallest pool that opens leaves the attacker one share, and the locked shares take the swelling
        let (pool, paid, _) = step(&Pool::default(), &[Order::Add { x: 1_001, y: 1_001 }]).unwrap();
        assert_eq!((pool.shares, pool.locked, paid[0].shares), (1_001, MINIMUM_SHARES, 1));
        // the attacker swells both balances by 1,000,000 units of each asset; the victim then adds 1,000 of each
        let swollen = Pool { x: pool.x + 1_000_000 * U, y: pool.y + 1_000_000 * U, ..pool };
        let (after, got, _) = step(&swollen, &[Order::Add { x: 1_000 * U, y: 1_000 * U }]).unwrap();
        assert!(got[0].shares > 0, "the victim still gets shares");
        // what the victim's shares are worth is what it put in, to within one unit
        let put_x = 1_000 * U - got[0].x;
        let worth_x = after.x * got[0].shares / after.shares;
        assert!(put_x - worth_x <= 1, "the victim lost {} to rounding", put_x - worth_x);
        // and the attacker's one share holds a thousandth of what it gave: the locked shares hold the rest for ever
        assert!(after.x / after.shares < 1_000_000 * U / 500);
    }

    #[test]
    fn a_removal_is_paid_at_the_blocks_opening_balances_whatever_trades_beside_it() {
        let (pool, paid, _) = step(&Pool::default(), &[Order::Add { x: 1_000_000 * U, y: 50_000 * U }]).unwrap();
        let mine = paid[0].shares / 4;
        let (_, alone, _) = step(&pool, &[Order::Remove { shares: mine }]).unwrap();
        let (_, beside, _) = step(&pool, &[Order::Buy { amount: 20_000 * U, min_out: 0 }, Order::Remove { shares: mine }]).unwrap();
        assert_eq!(alone[0], beside[1], "a provider's exit is not priced by the block's own trades");
        assert!(alone[0].x > 0 && alone[0].y > 0 && !alone[0].returned);
        // nobody can hand back a locked share
        let (same, none, _) = step(&pool, &[Order::Remove { shares: pool.shares }]).unwrap();
        assert!(none[0].returned);
        assert_eq!(same, pool);
    }

    #[test]
    fn the_launch_curve_cannot_be_drained_and_graduates_at_the_same_price() {
        let supply = 1_000_000_000 * U;
        let c = Curve::open(supply);
        // buy, then sell every token bought: the seller gets back less than it paid, and the curve never holds more than the supply
        let (s1, paid, fees) = curve_step(&c, &[Order::Buy { amount: 10_000 * U, min_out: 0 }]).unwrap();
        let CurveStep::Curve(c1) = s1 else { panic!("no graduation at 10,000") };
        let bought = paid[0].x;
        assert!(bought > 0 && fees.creator_y > 0 && fees.protocol_y > 0 && fees.publisher_y > 0);
        let (s2, back, _) = curve_step(&c1, &[Order::Sell { amount: bought, min_out: 0 }]).unwrap();
        let CurveStep::Curve(c2) = s2 else { panic!("a sell does not graduate a curve") };
        assert!(back[0].y < 10_000 * U, "a round trip is never free");
        assert!(c2.x <= supply, "a sell returns only what the curve sold");
        // a hostile state that claims tokens nobody was sold cannot take the base that does not exist
        let (h, paid, _) = curve_step(&c, &[Order::Sell { amount: 1_000_000 * U, min_out: 0 }]).unwrap();
        assert_eq!(h, CurveStep::Curve(c), "the curve stands");
        assert!(paid[0].returned, "and the sell is returned whole");
        // nobody provides to a curve
        let (_, paid, _) = curve_step(&c, &[Order::Add { x: 5, y: 5 }, Order::Remove { shares: 5 }]).unwrap();
        assert!(paid[0].returned && paid[1].returned);
        // graduation: buy until the real base passes the mark
        let (mut cur, mut steps) = (c1, 0);
        let (pool, burned, before) = loop {
            let before = cur;
            let (s, _, _) = curve_step(&cur, &[Order::Buy { amount: 9_000 * U, min_out: 0 }]).unwrap();
            steps += 1;
            assert!(steps < 100, "the curve never graduated");
            match s {
                CurveStep::Curve(next) => cur = next,
                CurveStep::Graduated { pool, burned } => break (pool, burned, before),
            }
        };
        assert!(pool.y >= GRADUATION_BASE);
        assert_eq!(pool.locked, pool.shares, "every share of the launch liquidity is locked");
        assert!(burned > 0 && pool.x + burned <= before.x);
        // the pool opens at the curve's last price: y/x (pool) against (real + v)/x (the curve after the batch)
        let (lhs, rhs) = (pool.y * (pool.x + burned), (pool.y + before.v) * pool.x);
        assert!(lhs.abs_diff(rhs) <= pool.y + before.v, "the price moved at graduation");
        assert!(pool.y * supply > before.v * pool.x, "and it is above the starting price");
        // from here it is an ordinary pool: a provider adds its own and the launch liquidity stays locked
        let (after, paid, _) = step(&pool, &[Order::Add { x: pool.x / 10, y: pool.y / 10 }]).unwrap();
        assert!(paid[0].shares > 0 && after.locked == pool.locked);
        let (_, out, _) = step(&after, &[Order::Remove { shares: paid[0].shares }]).unwrap();
        assert!(!out[0].returned && out[0].x > 0 && out[0].y > 0, "and takes it out again");
    }

    #[test]
    fn the_square_root_is_the_floor_for_every_size() {
        for n in [0u128, 1, 2, 3, 4, 15, 16, 17, 1 << 64, (1 << 64) + 1, u128::MAX] {
            let r = isqrt(n);
            assert!(r.checked_mul(r).is_some_and(|sq| sq <= n), "isqrt({n}) = {r} is too large");
            assert!((r + 1).checked_mul(r + 1).is_none_or(|sq| sq > n), "isqrt({n}) = {r} is too small");
        }
    }
}

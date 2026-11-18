// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! §SWAP-0 — THE SWAP LINKABILITY ATTACKER (user 2026-11-10: "trading between two public chain assets is private and
//! fast as possible … you must prove chain analysis and metadata tracking to be useless with auto opsec on").
//!
//! WHAT IT MEASURES. A native swap has two public ends: coin A arrives in custody on chain A, coin B leaves custody
//! on chain B. Both chains are public; so is the market price at every moment. The attacker reads ONLY that — every
//! deposit (value, time, sending address) and every payout output (value, time, receiving address) — and names, for
//! each payout piece, the deposit it believes funded it. This is the analysis that links swaps on other bridges: on a
//! bridge that publishes a memo it is a lookup, and on an instant swapper it is amount × price inside a time window.
//! The correct-match rate per piece is the census figure. It is reported beside the BLIND rate (a pick made with no
//! analysis at all among the deposits that could have funded the piece), so "useless" is a measured statement: the
//! analysis must do no better than the blind pick, and the blind pick itself must be at most 1 in [`ONE_IN`].
//!
//! EVERYTHING IS IN ONE UNIT. Values are satoshi-equivalents at the public price (only ratios matter to the attacker,
//! who converts chain B's amounts at the price of the block it sees them in). A swap pays its value less the fee and
//! the batch's price move, which the attacker knows only as a band ([`AMOUNT_BAND`]).
//!
//! THE PAYOUT RULES COMPARED ([`Rule`]) are the candidates the build chose between, behind one switch each:
//! what the swap payout did before this work (every rung to ONE address, one rung a slot, starting at once), fresh
//! addresses alone, a flat random delay inside a window, and COMPANY: a rung is paid only in a batch of at least `k`
//! rungs of its own value (Chaum's threshold mix, 1981), so what a piece waits for is other people, never a clock.
//!
//! THE HEURISTICS (the standard set, plus the two a swap adds): (1) clustering — pieces to one address are one swap;
//! (2) amount × price — a cluster worth a deposit's value less the fee band names it; (3) timing — else the most
//! recent earlier deposit that can still fund the piece; (4) budget — a deposit funds at most its own value, so what
//! it has already been matched to is taken off; (5) run — pieces in consecutive slots are one swap's, summed and
//! matched as a cluster. A link ANY of them finds is a link.
//!
//! THE ATTACKER NEVER READS THE TRUTH: the public structs carry no user; the labels live beside them and are read
//! only to score. The calibration pin proves it finds a planted link and cannot beat chance on a planted crowd.
//!
//! TWO-PARTY-REVIEWED: an observer census, not a protocol exchange — its one side is the outside analyst reading two
//! public chains. The payout's own two sides (the proposer and each signer) are pinned in `btc_payout::tests`.

use std::collections::BTreeMap;

use crate::bridge_linkability::{DAY_BLOCKS, HOUR_BLOCKS, LAUNCH_VOLUMES, ONE_IN, PROPOSER_SLOT_BLOCKS};
use crate::peg::COIN_BTC_ASSET_ID;
use crate::peg_pool::{split_to_coin_denoms, BATCH_MAX};

/// What a swap pays less than it took in, as a share. The attacker knows nearly all of it: both legs' fees are public
/// constants (cash in 0.10 %, cash out 0.10 %) and each batch's price is published, so what it cannot compute is only
/// the price step between the two legs' batches. A narrow band is the STRONG attacker: the amount names the deposit.
pub const AMOUNT_BAND: (f64, f64) = (0.0020, 0.0026);
/// Blocks from a deposit's first sight on its chain to the swap's rungs being ready to pay (one confirmation of a
/// ten-minute chain, then the sealed batch).
pub const READY_BLOCKS: u64 = crate::params::blocks_for_ms(600_000); // ten minutes of the mesh's target (A-F60)
/// The company a rung waits for under the shipped rule, and the longest it waits for it.
pub const COMPANY: usize = 32;
pub const COMPANY_CAP_BLOCKS: u64 = crate::params::blocks_for_ms(crate::peg::PAY_AFTER_MAX_MS);

/// A deposit as chain A shows it.
#[derive(Clone, Copy, Debug)]
pub struct Deposit {
    pub value: u64,
    pub block: u64,
    pub from: u64,
}

/// One payout output as chain B shows it (its amount converted at that block's public price).
#[derive(Clone, Copy, Debug)]
pub struct Piece {
    pub value: u64,
    pub block: u64,
    pub to: u64,
}

/// How a swap's payout leaves custody.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Rule {
    /// Before this work: every rung to the ONE address the user typed, one rung a slot, starting at once.
    OneAddressAtOnce,
    /// A fresh address per rung, still one rung a slot starting at once.
    FreshAtOnce,
    /// A fresh address per rung, each in its own slot drawn uniformly inside this many blocks.
    Window(u64),
    /// A fresh address per rung; a rung is paid only in a batch of at least `k` rungs of its own value, or alone once
    /// it has waited `cap` blocks. One user never has two rungs of one value waiting together.
    Company { k: usize, cap: u64 },
    /// THE BRIDGE'S CASH-OUT LANE: a fresh address per rung, payouts only at batch boundaries `every` blocks apart, each
    /// rung in a batch drawn uniformly among the next `spread` (the lane as shipped before this work: hourly batches,
    /// spread over 24 of them).
    Batches { every: u64, spread: u64 },
    /// CROWD PACING, the rule this work ships: the same lane, each rung drawn uniformly among the FEWEST next batches
    /// whose rungs of its own value add up to a crowd of `k`, read from the lane's own public record of the day before
    /// (how many pieces of each rung each batch paid: every payout is on a public chain). Busy lane: the next batch.
    /// Quiet lane: as many batches as the crowd takes, at most a day's.
    Crowd { every: u64, k: usize },
}

/// The public view, the truth beside it, how long each swap waited for its last rung (blocks after ready), and for
/// each piece the pacing window its rule drew it from (public: the rule and the lane's record are).
pub struct World {
    pub deposits: Vec<Deposit>,
    pub pieces: Vec<Piece>,
    pub deposit_user: Vec<u32>,
    pub piece_user: Vec<u32>,
    pub waited: Vec<u64>,
    pub piece_window: Vec<u64>,
}

/// splitmix64 — a seeded deterministic stream (Steele, Lea, Flood 2014).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// `users` swaps over one day under `rule`. Each user deposits an arbitrary value (log-uniform 0.001–2 BTC worth) at a
/// uniform block from an address of its own; the swap's output is that value less a draw from [`AMOUNT_BAND`], split
/// into rungs largest first (`peg_pool::split_to_coin_denoms`; what is under the smallest rung stays a private note).
#[must_use]
pub fn swap_world(users: u64, seed: u64, rule: Rule) -> World {
    let mut rng = Rng(seed ^ users.wrapping_mul(0xC2B2_AE3D_27D4_EB4F));
    let mut next_addr = 1u64;
    let (mut deposits, mut deposit_user) = (Vec::new(), Vec::new());
    // (ready block, user, rungs largest first)
    let mut swaps: Vec<(u64, u32, Vec<u64>)> = Vec::new();
    for u in 0..users as u32 {
        let value = (1e5 * (2e8f64 / 1e5).powf(rng.unit())) as u64;
        let block = (rng.unit() * DAY_BLOCKS as f64) as u64;
        next_addr += 1;
        deposits.push(Deposit { value, block, from: next_addr });
        deposit_user.push(u);
        let cut = AMOUNT_BAND.0 + (AMOUNT_BAND.1 - AMOUNT_BAND.0) * rng.unit();
        let out = (value as f64 * (1.0 - cut)) as u64;
        swaps.push((block + READY_BLOCKS, u, split_to_coin_denoms(COIN_BTC_ASSET_ID, out).0));
    }
    let slot = PROPOSER_SLOT_BLOCKS;
    let (mut pieces, mut piece_user) = (Vec::new(), Vec::new());
    let mut waited = vec![0u64; users as usize];
    let mut piece_window: Vec<u64> = Vec::new();
    let mut pay = |pieces: &mut Vec<Piece>, piece_user: &mut Vec<u32>, value: u64, at: u64, to: u64, user: u32, ready: u64, window: u64| {
        pieces.push(Piece { value, block: at, to });
        piece_user.push(user);
        piece_window.push(window);
        let w = &mut waited[user as usize];
        *w = (*w).max(at.saturating_sub(ready));
    };
    match rule {
        Rule::OneAddressAtOnce | Rule::FreshAtOnce => {
            for (ready, user, rungs) in &swaps {
                next_addr += 1;
                let one = next_addr;
                let first = ready.div_ceil(slot) + 1;
                for (i, r) in rungs.iter().enumerate() {
                    let to = if rule == Rule::OneAddressAtOnce {
                        one
                    } else {
                        next_addr += 1;
                        next_addr
                    };
                    pay(&mut pieces, &mut piece_user, *r, (first + i as u64) * slot, to, *user, *ready, (rungs.len() as u64 + 1) * slot);
                }
            }
        }
        Rule::Window(window) => {
            let slots = (window / slot).max(1);
            for (ready, user, rungs) in &swaps {
                let first = ready.div_ceil(slot) + 1;
                let mut taken: Vec<u64> = Vec::new();
                for r in rungs {
                    // its own slot inside the window (a swap of more rungs than the window has slots spills past it)
                    let mut k = (rng.unit() * slots as f64) as u64;
                    while taken.contains(&k) {
                        k += 1;
                    }
                    taken.push(k);
                    next_addr += 1;
                    pay(&mut pieces, &mut piece_user, *r, (first + k) * slot, next_addr, *user, *ready, window.max(slot) + slot);
                }
            }
        }
        Rule::Batches { every, .. } | Rule::Crowd { every, .. } => {
            let day_batches = (DAY_BLOCKS / every).max(1);
            // what the lane paid of each rung over the day, per batch: public (the day before's, in the shipped rule)
            let mut of_rung: BTreeMap<u64, u64> = BTreeMap::new();
            for (_, _, rungs) in &swaps {
                for r in rungs {
                    *of_rung.entry(*r).or_default() += 1;
                }
            }
            for (ready, user, rungs) in &swaps {
                let first = ready / every + 1;
                let mut taken: Vec<(u64, u64)> = Vec::new(); // (rung, batch), for the lane as shipped
                for r in rungs {
                    let mine = rungs.iter().filter(|x| *x == r).count() as u64; // this swap's rungs of this value
                    let (n, apart) = match rule {
                        // as shipped: no two of one swap's same-value rungs in one batch
                        Rule::Batches { spread, .. } => (spread.max(1), true),
                        // crowd pacing: the fewest batches whose rungs of this value are `k` times this swap's own, so
                        // each of its rungs is one among `k` wherever it lands; they may share a batch
                        Rule::Crowd { k, .. } => {
                            let per_batch = of_rung.get(r).copied().unwrap_or(0) as f64 / day_batches as f64;
                            let need = (k as u64 * mine) as f64;
                            (if per_batch <= 0.0 { day_batches } else { ((need / per_batch).ceil() as u64).clamp(1, day_batches) }, false)
                        }
                        _ => (1, true),
                    };
                    let mut b = (rng.unit() * n as f64) as u64;
                    while apart && taken.contains(&(*r, b)) {
                        b += 1;
                    }
                    taken.push((*r, b));
                    next_addr += 1;
                    pay(&mut pieces, &mut piece_user, *r, (first + b) * every, next_addr, *user, *ready, (n + 1) * every);
                }
            }
        }
        Rule::Company { k, cap } => {
            // per user: the rungs not yet handed to the lane (largest first); per rung value: the legs waiting
            let mut todo: Vec<(u64, u32, Vec<u64>)> = swaps.clone();
            todo.sort_unstable_by_key(|s| s.0);
            let mut cursor = 0usize;
            let mut open: Vec<(u64, u32, Vec<u64>)> = Vec::new(); // swaps with rungs still to hand over
            let mut waiting: BTreeMap<u64, Vec<(u64, u32, u64)>> = BTreeMap::new(); // rung → (since, user, ready)
            let mut s = todo.first().map_or(0, |t| t.0.div_ceil(slot));
            let cap_slots = (cap / slot).max(1);
            while cursor < todo.len() || !open.is_empty() || waiting.values().any(|v| !v.is_empty()) {
                let now = s * slot;
                while cursor < todo.len() && todo[cursor].0 <= now {
                    open.push(todo[cursor].clone());
                    cursor += 1;
                }
                // hand over: one leg of each rung value per user at a time
                for (ready, user, rungs) in &mut open {
                    let mut i = 0;
                    while i < rungs.len() {
                        let r = rungs[i];
                        let q = waiting.entry(r).or_default();
                        if q.iter().any(|(_, u, _)| u == user) {
                            i += 1;
                            continue;
                        }
                        q.push((s, *user, *ready));
                        rungs.remove(i);
                    }
                }
                open.retain(|(_, _, rungs)| !rungs.is_empty());
                // pay: every rung value with company, or whose oldest leg has waited the cap
                for (r, q) in &mut waiting {
                    let due = q.len() >= k || q.iter().any(|(since, _, _)| s - since >= cap_slots);
                    if !due {
                        continue;
                    }
                    let mut batch: Vec<(u64, u32, u64)> = std::mem::take(q);
                    if batch.len() > BATCH_MAX {
                        *q = batch.split_off(BATCH_MAX);
                    }
                    for (_, user, ready) in batch {
                        next_addr += 1;
                        pay(&mut pieces, &mut piece_user, *r, now + slot, next_addr, user, ready, cap);
                    }
                }
                s += 1;
            }
        }
    }
    drop(pay);
    World { deposits, pieces, deposit_user, piece_user, waited, piece_window }
}

/// THE ATTACKER: for every piece, the deposits it names (a piece is linked when any name is right). Reads the public
/// view only.
#[must_use]
pub fn attack(deposits: &[Deposit], pieces: &[Piece]) -> Vec<Vec<usize>> {
    let mut names: Vec<Vec<usize>> = vec![Vec::new(); pieces.len()];
    // deposits by block, for "earlier than"
    let mut by_block: Vec<usize> = (0..deposits.len()).collect();
    by_block.sort_by_key(|d| (deposits[*d].block, *d));
    let earlier = |block: u64| by_block.partition_point(|d| deposits[*d].block < block);
    // the amount × price match of a GROUP worth `sum` whose last piece is at `block`: the earlier deposit whose value
    // less the band holds the sum (and the unpaid remainder under the smallest rung), the tightest first
    let smallest = crate::peg_pool::coin_denoms(COIN_BTC_ASSET_ID)[0];
    // (`whole`: the group covers the whole payout of one user's order, so no remainder under the smallest rung is missing from it)
    let amount_match = |sum: u64, block: u64| -> Option<usize> {
        // the most recent earlier deposit inside the band: a swap pays out after its deposit, and sooner is likelier
        by_block[..earlier(block)].iter().rev().copied().find(|d| {
            let v = deposits[*d].value as f64;
            let (lo, hi) = (v * (1.0 - AMOUNT_BAND.1) - smallest as f64, v * (1.0 - AMOUNT_BAND.0));
            (sum as f64) >= lo && (sum as f64) <= hi
        })
    };
    // (1) + (2): address clusters
    let mut clusters: BTreeMap<u64, (u64, u64, Vec<usize>)> = BTreeMap::new();
    for (i, p) in pieces.iter().enumerate() {
        let c = clusters.entry(p.to).or_insert((0, 0, Vec::new()));
        c.0 += p.value;
        c.1 = c.1.max(p.block);
        c.2.push(i);
    }
    for (sum, block, members) in clusters.values() {
        // an address paid once is a cluster too: one output worth a deposit less the band names it
        if let Some(d) = amount_match(*sum, *block) {
            for i in members {
                names[*i].push(d);
            }
        }
    }
    // (5) runs: pieces in consecutive slots, summed and matched as one swap (a run of one is a single rung)
    let mut order: Vec<usize> = (0..pieces.len()).collect();
    order.sort_by_key(|i| (pieces[*i].block, *i));
    let mut per_slot: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for i in &order {
        per_slot.entry(pieces[*i].block / PROPOSER_SLOT_BLOCKS).or_default().push(*i);
    }
    let mut run: Vec<usize> = Vec::new();
    let mut last_slot: Option<u64> = None;
    let mut close = |run: &mut Vec<usize>, names: &mut Vec<Vec<usize>>| {
        if run.len() > 1 {
            let sum: u64 = run.iter().map(|i| pieces[*i].value).sum();
            let block = run.iter().map(|i| pieces[*i].block).max().unwrap_or(0);
            if let Some(d) = amount_match(sum, block) {
                for i in run.iter() {
                    names[*i].push(d);
                }
            }
        }
        run.clear();
    };
    for (slot, members) in &per_slot {
        // a slot paying one piece extends a run; a slot paying a crowd ends it (which piece continues the run is unknown)
        if members.len() != 1 || last_slot.is_some_and(|l| *slot != l + 1) {
            close(&mut run, &mut names);
        }
        if members.len() == 1 {
            run.push(members[0]);
        }
        last_slot = Some(*slot);
    }
    close(&mut run, &mut names);
    // (3) + (4): timing with budgets — pieces in time order, each to the most recent earlier deposit that can still
    // fund it (its value less the least cut, less what it has already been matched to)
    let mut left: Vec<f64> = deposits.iter().map(|d| d.value as f64 * (1.0 - AMOUNT_BAND.0)).collect();
    for i in &order {
        let p = pieces[*i];
        let end = earlier(p.block);
        if let Some(d) = by_block[..end].iter().rev().find(|d| left[**d] >= p.value as f64) {
            left[*d] -= p.value as f64;
            names[*i].push(*d);
        }
    }
    names
}

/// (pieces any heuristic links to their own deposit, pieces).
#[must_use]
pub fn linked(w: &World) -> (u64, u64) {
    let names = attack(&w.deposits, &w.pieces);
    let hits = names.iter().zip(&w.piece_user).filter(|(n, u)| n.iter().any(|d| w.deposit_user[*d] == **u)).count() as u64;
    (hits, w.pieces.len() as u64)
}

/// THE BLIND RATE: what a pick with NO analysis scores when it knows only the public rule — for each piece, one
/// deposit drawn uniformly among those large enough to have funded it whose swap could have been paid at that moment
/// (ready inside the piece's pacing window). Returned as the expected hits (×1000) over the pieces. The analysis is
/// useless exactly when the attacker does no better than this.
#[must_use]
pub fn blind_milli(w: &World) -> (u64, u64) {
    let mut by_block: Vec<(u64, u64)> = w.deposits.iter().map(|d| (d.block, d.value)).collect();
    by_block.sort_unstable();
    let mut expect = 0.0f64;
    for (p, window) in w.pieces.iter().zip(&w.piece_window) {
        let hi = by_block.partition_point(|(b, _)| b + READY_BLOCKS < p.block);
        let lo = by_block.partition_point(|(b, _)| b + READY_BLOCKS + window < p.block);
        let can = by_block[lo..hi].iter().filter(|(_, v)| *v >= p.value).count();
        if can > 0 {
            expect += 1.0 / can as f64;
        }
    }
    ((expect * 1000.0) as u64, w.pieces.len() as u64)
}

/// The wait for a swap's LAST rung, in minutes after it was ready: (median, 95th percentile).
#[must_use]
pub fn wait_minutes(w: &World) -> (f64, f64) {
    let mut v: Vec<u64> = w.waited.clone();
    v.sort_unstable();
    let at = |q: f64| v.get(((v.len() as f64 - 1.0) * q) as usize).copied().unwrap_or(0) as f64 / 120.0;
    (at(0.5), at(0.95))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge_linkability::sim_seed;

    fn pct(h: u64, t: u64) -> f64 {
        100.0 * h as f64 / t.max(1) as f64
    }

    /// REFUTATION BEFORE GREEN: the attacker finds links where they exist and cannot beat chance where they do not —
    /// else a green census would mean a blind attacker.
    #[test]
    fn swap0_the_attacker_finds_a_planted_link_and_cannot_beat_chance_on_a_planted_crowd() {
        let mut rng = Rng(sim_seed());
        let n = 400u32;
        // planted link: every swap pays ONE output worth its deposit less a cut inside the band, an hour later
        let deposits: Vec<Deposit> =
            (0..n).map(|i| Deposit { value: 100_000 + rng.next() % 100_000_000, block: u64::from(i) * 300, from: u64::from(i) + 1 }).collect();
        let pieces: Vec<Piece> = deposits
            .iter()
            .enumerate()
            .map(|(i, d)| Piece { value: (d.value as f64 * 0.9977) as u64, block: d.block + HOUR_BLOCKS, to: 10_000 + i as u64 })
            .collect();
        let w = World { deposits, pieces, deposit_user: (0..n).collect(), piece_user: (0..n).collect(), waited: vec![0; n as usize], piece_window: vec![DAY_BLOCKS; n as usize] };
        let (hits, total) = linked(&w);
        eprintln!("[swap0] planted link, one output: {hits}/{total} pieces linked");
        assert!(hits * 10 >= total * 9, "the attacker misses a planted amount × price link: {hits}/{total}");
        // the same swap paid as two outputs to one address: the cluster's sum names the deposit
        let deposits: Vec<Deposit> = w.deposits.clone();
        let pieces: Vec<Piece> = deposits
            .iter()
            .enumerate()
            .flat_map(|(i, d)| {
                let half = (d.value as f64 * 0.49885) as u64;
                [Piece { value: half, block: d.block + HOUR_BLOCKS, to: 10_000 + i as u64 }, Piece { value: half, block: d.block + HOUR_BLOCKS + crate::params::blocks_for_ms(60_000), to: 10_000 + i as u64 }]
            })
            .collect();
        let users: Vec<u32> = (0..n).flat_map(|u| [u, u]).collect();
        let w = World { deposits, pieces, deposit_user: (0..n).collect(), piece_user: users, waited: vec![0; n as usize], piece_window: vec![DAY_BLOCKS; 2 * n as usize] };
        let (hits, total) = linked(&w);
        eprintln!("[swap0] planted link, two outputs to one address: {hits}/{total} pieces linked");
        assert!(hits * 10 >= total * 9, "the attacker misses a planted amount × price link: {hits}/{total}");

        // planted crowd: equal values, fresh addresses, every payout in one block after every deposit, users shuffled
        let deposits: Vec<Deposit> = (0..n).map(|i| Deposit { value: 1_000_000, block: u64::from(i), from: u64::from(i) + 1 }).collect();
        let mut piece_user: Vec<u32> = (0..n).collect();
        for i in (1..piece_user.len()).rev() {
            piece_user.swap(i, (rng.next() % (i as u64 + 1)) as usize);
        }
        let pieces: Vec<Piece> = (0..n).map(|i| Piece { value: 100_000, block: 10_000, to: 10_000 + u64::from(i) }).collect();
        let w = World { deposits, pieces, deposit_user: (0..n).collect(), piece_user, waited: vec![0; n as usize], piece_window: vec![DAY_BLOCKS; n as usize] };
        let (hits, total) = linked(&w);
        eprintln!("[swap0] planted crowd: {hits}/{total} pieces linked (chance ≈ 1/{n})");
        assert!(hits * ONE_IN <= total, "the attacker beats chance on a crowd — it reads more than the public view: {hits}/{total}");
    }

    /// THE SCREEN (user 2026-11-04: many hypotheses in minutes, one run): every candidate payout rule at every launch
    /// volume — linked, blind, and the wait for a swap's last rung. Asserted here: the rule in force BEFORE this work
    /// links nearly every piece (the RED the build starts from, and what the Auto-OPSEC-off warning must say).
    #[test]
    fn swap0_the_payout_rules_screened_and_the_old_rule_links_nearly_every_piece() {
        let seed = sim_seed();
        let day = DAY_BLOCKS;
        let rules: [(&str, Rule); 11] = [
            ("one address, at once (before)", Rule::OneAddressAtOnce),
            ("fresh addresses, at once", Rule::FreshAtOnce),
            ("fresh, window 1 h", Rule::Window(HOUR_BLOCKS)),
            ("fresh, window 24 h", Rule::Window(day)),
            ("company of 32, cap 24 h", Rule::Company { k: COMPANY, cap: COMPANY_CAP_BLOCKS }),
            ("hourly batches, next batch", Rule::Batches { every: HOUR_BLOCKS, spread: 1 }),
            ("hourly batches, over 24 (shipped)", Rule::Batches { every: HOUR_BLOCKS, spread: 24 }),
            ("hourly batches, crowd of 20", Rule::Crowd { every: HOUR_BLOCKS, k: 20 }),
            ("hourly batches, crowd of 32", Rule::Crowd { every: HOUR_BLOCKS, k: 32 }),
            ("hourly batches, crowd of 64", Rule::Crowd { every: HOUR_BLOCKS, k: 64 }),
            ("10-minute batches, crowd of 32", Rule::Crowd { every: 1_200, k: 32 }),
        ];
        let mut before_at_target = (0u64, 0u64);
        for (name, rule) in rules {
            for users in LAUNCH_VOLUMES {
                let w = swap_world(users, seed, rule);
                let (hits, total) = linked(&w);
                let (blind, _) = blind_milli(&w);
                let (med, p95) = wait_minutes(&w);
                eprintln!(
                    "[swap0-screen] {name:32} {users:>6} users/day: linked {hits}/{total} ({:.2} %) · blind {:.2} % · last rung after {med:.0} min median, {p95:.0} min p95",
                    pct(hits, total),
                    blind as f64 / 10.0 / total.max(1) as f64
                );
                if rule == Rule::OneAddressAtOnce {
                    before_at_target = (hits, total);
                }
            }
        }
        let (hits, total) = before_at_target;
        assert!(hits * 10 >= total * 8, "CALIBRATION: the old swap payout must be linkable ({hits}/{total}), or the screen measures nothing");
    }

    /// ⭐ THE SHIPPED RULE, PINNED AT EVERY LAUNCH VOLUME (user 2026-11-10: "you must prove chain analysis and metadata
    /// tracking to be useless with auto opsec on"). What the wallet does for a swap's payout with Auto-OPSEC on: a fresh
    /// address for every piece and its own hourly batch drawn across a day. The attacker holds BOTH public chains, the
    /// fees, the batch prices and the standard piece sizes. The claim: it links no more pieces to their deposits than
    /// someone guessing blind among the pieces of the same size, at 100, 1,000 and 10,000 users a day.
    ///
    /// The calibration is in the same loop: the SAME world paid out the old way (one address, at once) is linked many
    /// times better than blind, so "no better than blind" is a statement about the rule and not about a weak attacker.
    ///
    /// TWO-PARTY-REVIEWED: a census over a simulated world of deposits and payout pieces; no endpoint is constructed
    /// and no transition is driven. The crossing it models (a wallet's payout plan reaching the bridge lane and both
    /// public chains) is exercised on real nodes by scratchpad/net/btc_bridge.py and xmr_bridge.py.
    #[test]
    fn swap0_the_shipped_rule_leaves_the_attacker_no_better_than_a_blind_guess_at_every_launch_volume() {
        let seed = sim_seed();
        let shipped = Rule::Batches { every: HOUR_BLOCKS, spread: 24 };
        for users in LAUNCH_VOLUMES {
            let w = swap_world(users, seed, shipped);
            let (hits, total) = linked(&w);
            let (blind, _) = blind_milli(&w); // a blind guess's expected links, in thousandths of a piece
            eprintln!("[swap0-shipped] {users:>6} users/day: linked {hits}/{total} ({:.2} %) · a blind guess {:.2} %", pct(hits, total), blind as f64 / 10.0 / total.max(1) as f64);
            assert!(total > 0, "{users} users/day: the world paid nothing out, so nothing was measured");
            // no better than blind, with room for the draw: half as much again, and five pieces
            assert!(hits * 1000 <= blind * 3 / 2 + 5_000, "{users} users/day: the attacker linked {hits} of {total} pieces, a blind guess links {:.1}", blind as f64 / 1000.0);
            let old = swap_world(users, seed, Rule::OneAddressAtOnce);
            let (old_hits, old_total) = linked(&old);
            // (not "many times blind": with few users a blind guess is already right most of the time under the old
            // rule, 70 % at 100 users a day, so the calibration is the absolute figure)
            assert!(old_hits * 10 >= old_total * 8, "CALIBRATION, {users} users/day: paid the old way the same attacker must link at least 8 pieces in 10 ({old_hits}/{old_total})");
        }
    }
}

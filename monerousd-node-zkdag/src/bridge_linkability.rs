// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! §BR-0 — THE BRIDGE LINKABILITY ATTACKER (spec docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §5, R5 edge privacy).
//!
//! WHAT IT MEASURES. Bitcoin is public: every deposit into custody and every payout out of it is seen by anyone, with
//! its amount, its block and its address. The attacker reads ONLY that public view and the public rules (the fee band
//! of `peg::withdrawal_fee_bps`, the proposer slot of `btc_payout`) and names, for each payout piece, the deposit it
//! believes funded it. The correct-match rate per piece is the census figure: the spec bars it above 1 in 20 at the
//! target volume and reports it at each launch volume.
//!
//! THE EXIT IS THE SHIPPING ONE. A withdrawal's pieces are `btc_payout::payout_leg_outputs` of its release, paid at
//! the first proposer slot (`btc_payout::PROPOSER_SLOT_MS`) after its burn, at most `peg_pool::BATCH_MAX` legs a
//! slot; the release is the draw less `peg::withdrawal_fee_bps` over the reserve the simulation holds. When §BR-1
//! changes what a payout pays, this census measures the new shape with no edit here.
//!
//! THE HEURISTICS (the standard chain-analysis set: Meiklejohn et al. 2013 address clustering; Kappos et al. 2018
//! amount + timing matching of Zcash shielded-pool entries and exits): (1) address reuse — a payout to an address a
//! deposit came from is that deposit's; (2) clustering — payout pieces to one address are one withdrawal; (3) amount —
//! a withdrawal of a whole deposit less the band's floor fee names it; (4) timing — else the latest earlier deposit
//! that covers it; (5) intersection — a deposit already matched is not matched again (greedy, most confident first).
//!
//! THE ATTACKER NEVER READS THE TRUTH: `PublicDeposit` / `PublicPiece` carry no user; the truth labels live beside
//! them and are read only to score. The calibration pin proves it finds a planted link and cannot beat chance on a
//! planted crowd (refutation before green).
//!
//! TWO-PARTY-REVIEWED: an observer census, not a protocol exchange — its one side is the outside adversary reading
//! public Bitcoin. The payout's own two sides (the proposer and each signer) are pinned in `btc_payout::tests`; this
//! census reads the one output spelling both of them build from, `payout_leg_outputs`.

use std::collections::BTreeMap;

use crate::btc_payout::payout_leg_outputs;
use crate::peg::{withdrawal_fee_bps, WITHDRAW_FEE_MAX_BPS, WITHDRAW_FEE_MIN_BPS};
use crate::peg_pool::BATCH_MAX;

/// One simulated day, in chain ticks (A-F60: the chain's own day, `params::BLOCKS_PER_DAY`).
pub const DAY_BLOCKS: u64 = crate::params::BLOCKS_PER_DAY;
/// One simulated hour, in chain ticks (A-F60: it was the literal 7,200 — an hour only at 500 ms blocks).
pub const HOUR_BLOCKS: u64 = crate::params::blocks_for_ms(3_600_000);
/// The spec's bar: at most one correct match in this many pieces.
pub const ONE_IN: u64 = 20;
/// Launch-phase volumes the census reports (users per day); the last is the target it asserts.
pub const LAUNCH_VOLUMES: [u64; 3] = [100, 1_000, 10_000];
/// The seed when `SIM_SEED` is not set.
pub const DEFAULT_SEED: u64 = 0x5EED_B12D;

/// A deposit as Bitcoin shows it.
#[derive(Clone, Copy, Debug)]
pub struct PublicDeposit {
    pub sats: u64,
    pub block: u64,
    pub from: u64,
}

/// One payout output as Bitcoin shows it.
#[derive(Clone, Copy, Debug)]
pub struct PublicPiece {
    pub sats: u64,
    pub block: u64,
    pub to: u64,
}

/// The public view plus the truth labels the scorer (never the attacker) reads.
pub struct World {
    pub deposits: Vec<PublicDeposit>,
    pub pieces: Vec<PublicPiece>,
    pub deposit_user: Vec<u32>,
    pub piece_user: Vec<u32>,
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

/// `SIM_SEED` (decimal or `0x` hex), the farm's per-run seed — the same parse as `small_scope_model_tests::sim_seed`
/// and `harness::netsim`'s seed site; an unparsable value is refused, never read as the default.
#[must_use]
pub fn sim_seed() -> u64 {
    match std::env::var("SIM_SEED") {
        Err(_) => DEFAULT_SEED,
        Ok(s) => {
            let t = s.trim();
            let v = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(&h.replace('_', ""), 16).ok(),
                None => t.replace('_', "").parse().ok(),
            };
            v.unwrap_or_else(|| panic!("SIM_SEED={s:?} is not a decimal or 0x-hex u64"))
        }
    }
}

/// The model counts time in CHAIN TICKS (`dag::MESH_TARGET_SPACING_MS` each, `DAY_BLOCKS` a day); the chain counts it on its own clock (`Node::chain_time_ms`).
/// Each protocol interval below is the chain's, in ticks: a proposer slot (`btc_payout::PROPOSER_SLOT_MS`), an hour-epoch
/// (`epoch_deal_tx::EPOCH_MS`) and the epoch-anchor slot (`peg::EPOCH_ANCHOR_MS`).
pub const PROPOSER_SLOT_BLOCKS: u64 = crate::params::blocks_for_ms(crate::btc_payout::PROPOSER_SLOT_MS);
const MODEL_EPOCH_BLOCKS: u64 = crate::params::blocks_for_ms(crate::epoch_deal_tx::EPOCH_MS);
const MODEL_ANCHOR_BLOCKS: u64 = crate::params::blocks_for_ms(crate::peg::EPOCH_ANCHOR_MS);

/// §BR-1: the privacy delay's cap — a piece is paid in a batch the wallet drew at random inside [next batch, 24 h]
/// (`peg::PAY_AFTER_MAX_MS`, in ticks); the "fast, less private" switch draws the next batch.
pub const PRIVACY_DELAY_MAX_BLOCKS: u64 = crate::params::blocks_for_ms(crate::peg::PAY_AFTER_MAX_MS);

/// The share of users the mixed census models as having switched Auto-OPSEC OFF (the wallet's one privacy setting,
/// ON by default; off only through a warning that the transaction won't be private).
pub const AUTO_OPSEC_OFF_SHARE_MODELLED: f64 = 0.1;

/// Users over one day through the SHIPPING exit, every one on the wallet's default (Auto-OPSEC ON).
#[must_use]
pub fn shipping_world(users: u64, seed: u64) -> World {
    shipping_world_mixed(users, seed, 0.0).0
}

/// Users over one day through the SHIPPING exit. Each user deposits an arbitrary amount (log-uniform 0.001–2 BTC) at
/// a uniform block from a fresh address, holds an exponential time (mean 6 h), then withdraws all of it (70 %, the
/// "Cash out everything" path) or a uniform 20–100 % share.
///
/// ⭐ AUTO-OPSEC (user 2026-10-28): with the wallet's privacy setting ON — the default — a cash-out to the address the
/// deposit came from is REFUSED (`refuse_deposit_sender` in the wallet) and every piece waits for its own random batch
/// inside 24 h; there is no fast path. A user who switches it OFF (`off_share` of users, through the warning popup)
/// may cash out to the deposit's sender (20 % of them do, the reuse the old wallet only warned about) and is paid in
/// the next batch. Returns the world and, per user, whether that user had Auto-OPSEC off.
#[must_use]
pub fn shipping_world_mixed(users: u64, seed: u64, off_share: f64) -> (World, Vec<bool>) {
    let mut rng = Rng(seed ^ users.wrapping_mul(0xA24B_AED4_963E_E407));
    let mut off = Vec::new();
    let mut next_addr = 1u64;
    let mut deposits = Vec::new();
    let mut deposit_user = Vec::new();
    // (burn block, user, draw sats, reused destination or None = a fresh vault address per piece, next-batch payout)
    let mut burns: Vec<(u64, u32, u64, Option<u64>, bool)> = Vec::new();
    for u in 0..users as u32 {
        let sats = (1e5 * (2e8f64 / 1e5).powf(rng.unit())) as u64;
        let block = (rng.unit() * DAY_BLOCKS as f64) as u64;
        let from = next_addr;
        next_addr += 1;
        deposits.push(PublicDeposit { sats, block, from });
        deposit_user.push(u);
        let hold = (-(1.0 - rng.unit()).ln() * 43_200.0) as u64;
        let draw = if rng.unit() < 0.7 { sats } else { ((0.2 + 0.8 * rng.unit()) * sats as f64) as u64 };
        let wants_reuse = rng.unit() < 0.2;
        let opsec_off = rng.unit() < off_share;
        off.push(opsec_off);
        // Auto-OPSEC ON refuses the deposit's own sender as a cash-out address: the piece goes to a fresh vault address.
        let reuse = if wants_reuse && opsec_off { Some(from) } else { None };
        burns.push((block + hold + 1, u, draw, reuse, opsec_off));
    }
    let (pieces, piece_user) = pay_through_the_shipping_lane(&deposits, burns, &mut next_addr, &mut rng);
    (World { deposits, pieces, deposit_user, piece_user }, off)
}

/// The model's price: external atomic units per dollar (satoshis at $60,000 / BTC; the Monero path reads the same grid in
/// its own units). Only ratios matter to the attackers.
pub const MODEL_ATOMIC_PER_DOLLAR: u64 = 1_667;

/// The Bitcoin entry mix's round period in blocks (§BR-6: a round every ~150 s): every deposit of one round lands in ONE
/// co-signed transaction of standard outputs.
pub const MODEL_ENTRY_ROUND_BLOCKS: u64 = crate::params::blocks_for_ms(150_000); // a round every ~150 s

/// ⭐ §19.4 + §19.5 — THE CUSTODY VIEW of one day, on the SHIPPED shapes: what a custodian sees beyond the public chains.
/// DEPOSITS: on Bitcoin as ladder units through the §BR-6 entry round (standard outputs of every depositor of a round in one
/// transaction); on Monero WHOLE, one transfer at the moment the user acted (the multisig's shared view key shows it with its
/// amount and payment id). CASH-OUTS
/// as dollar rungs (`peg_pool::split_to_usd_denoms`), each released at its batch's price, each to a fresh address, each
/// arriving at custody as an anonymous CLAIM at its own drawn moment between the staged note's anchor and ten minutes
/// before its batch (`claim_relay_moment_ms`) — custody never sees the request time, only that arrival. The same users and
/// draws as [`shipping_world`]; the attackers are the same [`attack`] and [`exact_amount_attack`], fed custody's view.
#[must_use]
pub fn custody_world(users: u64, seed: u64, monero: bool) -> World {
    // what SHIPS: Bitcoin deposits through the entry round (Auto-OPSEC, §BR-6); a Monero deposit is one transfer from the
    // user's own Monero wallet (§19.5 item 3's split is measured unnecessary below and not built — it would ask the user to
    // send several transfers by hand)
    custody_world_deposits(users, seed, monero, !monero)
}

/// [`custody_world`] with the deposit side chosen: `split` = ladder units (the Bitcoin entry round; the Monero wallet's
/// split, §19.5 item 3), else each deposit WHOLE at the block the user acted (what custody saw before either).
#[must_use]
pub fn custody_world_deposits(users: u64, seed: u64, monero: bool, split: bool) -> World {
    let mut rng = Rng(seed ^ users.wrapping_mul(0xA24B_AED4_963E_E407) ^ u64::from(monero));
    let (mut deposits, mut deposit_user, mut pieces, mut piece_user) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut next_addr = 1u64;
    let epoch = MODEL_EPOCH_BLOCKS;
    for u in 0..users as u32 {
        let sats = (1e5 * (2e8f64 / 1e5).powf(rng.unit())) as u64;
        let block = (rng.unit() * DAY_BLOCKS as f64) as u64;
        let units = if split { crate::peg_pool::split_to_denoms(sats).0 } else { vec![sats] };
        for unit in &units {
            let at = match (split, monero) {
                (false, _) => block,
                (true, true) => block + (rng.unit() * HOUR_BLOCKS as f64) as u64,
                (true, false) => block - block % MODEL_ENTRY_ROUND_BLOCKS + MODEL_ENTRY_ROUND_BLOCKS,
            };
            next_addr += 1;
            deposits.push(PublicDeposit { sats: *unit, block: at, from: next_addr });
            deposit_user.push(u);
        }
        let minted: u64 = units.iter().sum();
        let hold = (-(1.0 - rng.unit()).ln() * 43_200.0) as u64;
        let draw = if rng.unit() < 0.7 { minted } else { ((0.2 + 0.8 * rng.unit()) * minted as f64) as u64 };
        let request = block + HOUR_BLOCKS + hold + 1;
        let release = draw - (u128::from(draw) * u128::from(WITHDRAW_FEE_MIN_BPS) / 10_000) as u64;
        let dollars = release / MODEL_ATOMIC_PER_DOLLAR;
        let (rungs, _stays_usdm) = crate::peg_pool::split_to_usd_denoms(dollars.saturating_mul(crate::peg_pool::USDM_ATOMIC_PER_DOLLAR));
        for rung in rungs {
            let paid = rung / crate::peg_pool::USDM_ATOMIC_PER_DOLLAR * MODEL_ATOMIC_PER_DOLLAR;
            let pay_after = request + PROPOSER_SLOT_BLOCKS + (rng.unit() * (PRIVACY_DELAY_MAX_BLOCKS - PROPOSER_SLOT_BLOCKS) as f64) as u64;
            let batch = (pay_after / epoch + 1) * epoch;
            let ready = request + MODEL_ANCHOR_BLOCKS;
            let last = batch.saturating_sub(1_200).max(ready);
            let arrival = ready + (rng.unit() * (last - ready) as f64) as u64;
            next_addr += 1;
            pieces.push(PublicPiece { sats: paid, block: arrival, to: next_addr });
            piece_user.push(u);
        }
    }
    World { deposits, pieces, deposit_user, piece_user }
}

/// ⭐ §19.5 — THE EXACT-AMOUNT ATTACKER custody can run. Custody knows when each piece was REQUESTED, so it groups the
/// pieces requested at one block (one cash-out's pieces, when the block holds one request) and sums them; a group whose sum
/// is to the satoshi an earlier deposit's whole release at the floor fee (the "Cash out everything" path) names that deposit
/// when exactly one deposit fits — every piece of the group then names it. Reads the same view as [`attack`].
#[must_use]
pub fn exact_amount_attack(deposits: &[PublicDeposit], pieces: &[PublicPiece]) -> Vec<Option<usize>> {
    let mut by_release: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (d, dep) in deposits.iter().enumerate() {
        let release = dep.sats - (u128::from(dep.sats) * u128::from(WITHDRAW_FEE_MIN_BPS) / 10_000) as u64;
        by_release.entry(release).or_default().push(d);
    }
    let mut group_sum: BTreeMap<u64, u64> = BTreeMap::new();
    for p in pieces {
        *group_sum.entry(p.block).or_default() += p.sats;
    }
    // a ladder cash-out's pieces sum to its release LESS the remainder below the smallest unit (it stays USDm), so custody
    // matches a release in [sum, sum + smallest unit); a whole-amount (Monero) cash-out matches at the sum exactly
    let unit = (crate::peg_pool::USD_DENOMS[0] / crate::peg_pool::USDM_ATOMIC_PER_DOLLAR * MODEL_ATOMIC_PER_DOLLAR)
        .max(crate::peg_pool::PAYOUT_DENOMS[0]);
    let named: BTreeMap<u64, usize> = group_sum
        .iter()
        .filter_map(|(block, sum)| {
            let fits: Vec<usize> = by_release
                .range(*sum..sum.saturating_add(unit))
                .flat_map(|(_, v)| v.iter().copied())
                .filter(|d| deposits[*d].block < *block)
                .collect();
            (fits.len() == 1).then(|| (*block, fits[0]))
        })
        .collect();
    pieces.iter().map(|p| named.get(&p.block).copied()).collect()
}

/// Burns become pieces the way the §BR-1 exit pays them (spec §13): the release is the draw less the band fee over the
/// reserve held at that moment; the wallet splits it into LADDER PIECES (`peg_pool::split_to_denoms`, largest first — the
/// remainder below the smallest unit stays USDm, a private balance), each piece its own burn to a FRESH vault address
/// (or, on reuse, the one address) with its own sealed `pay_after` drawn uniformly inside [next batch, 24 h]; the
/// proposer pays a piece in the first slot at or after its pay-after, up to `BATCH_MAX` legs a slot (a later slot pays
/// the rest). Before §BR-1 a burn was ONE output of the exact release at the slot after its burn — 9 of 10 pieces named
/// their deposit.
fn pay_through_the_shipping_lane(
    deposits: &[PublicDeposit],
    mut burns: Vec<(u64, u32, u64, Option<u64>, bool)>,
    next_addr: &mut u64,
    rng: &mut Rng,
) -> (Vec<PublicPiece>, Vec<u32>) {
    burns.sort_unstable();
    // (block, kind: 0 deposit / 1 burn, index) — a deposit in the same block as a burn counts first
    let mut events: Vec<(u64, u8, usize)> = deposits.iter().enumerate().map(|(i, d)| (d.block, 0, i)).collect();
    events.extend(burns.iter().enumerate().map(|(i, b)| (b.0, 1, i)));
    events.sort_unstable();
    let mut reserve: u128 = 0;
    // one owed PIECE: (pay-after block, user, piece sats, destination)
    let mut owed: Vec<(u64, u32, u64, u64)> = Vec::new();
    for (block, kind, i) in events {
        if kind == 0 {
            reserve += u128::from(deposits[i].sats);
            continue;
        }
        let (_, user, draw, reuse, fast) = burns[i];
        let fee_bps = withdrawal_fee_bps(reserve, u128::from(draw), WITHDRAW_FEE_MIN_BPS, WITHDRAW_FEE_MAX_BPS);
        let release = draw - (u128::from(draw) * u128::from(fee_bps) / 10_000) as u64;
        let (legs, _remainder_stays_usdm) = crate::peg_pool::split_to_denoms(release);
        for piece in legs {
            reserve = reserve.saturating_sub(u128::from(piece));
            let to = reuse.unwrap_or_else(|| {
                *next_addr += 1;
                *next_addr
            });
            let spread = rng.unit();
            let delay = if fast {
                PROPOSER_SLOT_BLOCKS
            } else {
                PROPOSER_SLOT_BLOCKS + (spread * (PRIVACY_DELAY_MAX_BLOCKS - PROPOSER_SLOT_BLOCKS) as f64) as u64
            };
            owed.push((block + delay, user, piece, to));
        }
    }
    owed.sort_unstable();
    let mut pieces = Vec::new();
    let mut piece_user = Vec::new();
    let mut slot_paid: BTreeMap<u64, usize> = BTreeMap::new();
    for (pay_after, user, piece, to) in owed {
        let mut slot = pay_after.div_ceil(PROPOSER_SLOT_BLOCKS);
        while *slot_paid.entry(slot).or_default() >= BATCH_MAX {
            slot += 1;
        }
        *slot_paid.entry(slot).or_default() += 1;
        // A-F21 / A-F35: what ships is the piece less its equal share of its batch's miner fee. That share is PUBLIC (the
        // batch's fee and its output count are on Bitcoin), so an observer adds it back: the attacker is handed the release
        // itself — the most any observer can recover — and gains nothing from one batch's share differing from another's.
        // CACHE-ONLY: a census model of what an observer of Bitcoin reads; it moves no state on any chain.
        for sats in payout_leg_outputs(piece) {
            pieces.push(PublicPiece { sats, block: slot * PROPOSER_SLOT_BLOCKS, to });
            piece_user.push(user);
        }
    }
    (pieces, piece_user)
}
/// The attacker: for every piece, the index of the deposit it names (or `None`). Reads the public view only.
#[must_use]
pub fn attack(deposits: &[PublicDeposit], pieces: &[PublicPiece]) -> Vec<Option<usize>> {
    // (2) clustering: pieces to one address are one withdrawal — (summed sats, last block)
    let mut clusters: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    for p in pieces {
        let c = clusters.entry(p.to).or_insert((0, 0));
        c.0 += p.sats;
        c.1 = c.1.max(p.block);
    }
    // (NEW) reconstruct the running reserve at every block from the PUBLIC Bitcoin view: cumulative
    // deposits minus cumulative payouts. This lets the attacker compute the exact expected fee for a
    // withdrawal at any block, using the same convex u² band the protocol publishes.
    let mut events: Vec<(u64, i128)> = Vec::new();
    for d in deposits {
        events.push((d.block, d.sats as i128));
    }
    for p in pieces {
        events.push((p.block, -(p.sats as i128)));
    }
    events.sort_unstable();
    let mut reserve_at: BTreeMap<u64, u128> = BTreeMap::new();
    let mut running: i128 = 0;
    for (b, delta) in &events {
        running += delta;
        reserve_at.insert(*b, running.max(0) as u128);
    }
    let by_from: BTreeMap<u64, usize> = deposits.iter().enumerate().map(|(i, d)| (d.from, i)).collect();
    // Every (score, cluster, deposit) a heuristic proposes, lower more confident, matched greedily most-confident-first with
    // each deposit and each cluster used once. The STRONG proposals (address reuse at −1, an amount match at r < 0.005) are
    // few and listed whole. The WEAK ones (timing only: score 1 + age in days, for EVERY earlier deposit large enough) are
    // C × D — 1.2e9 pairs at the 10,000-user target, a 5 GB vector (MEASURED: the family run killed at the 4 GB cap,
    // f254-B-small.log) — so they are generated LAZILY in the same global order: each cluster's next eligible deposit by
    // age sits in a min-heap keyed (score, cluster, deposit), exactly the sort's key, so the matching is unchanged.
    let mut strong: Vec<(f64, u64, usize)> = Vec::new();
    let mut weak_ok: Vec<(u64, u64, u64, bool)> = Vec::new(); // (cluster to, its sats, its block, reuse-matched)
    let strong_pair = |dep: &PublicDeposit, sats: u64, est_reserve: u128| -> Option<f64> {
        // (3) strongest amount heuristic: try BOTH the floor fee and the reserve-estimated fee,
        // take whichever gives the tighter match — this catches both healthy-reserve withdrawals
        // (floor fee) and early-day / stressed-reserve withdrawals (higher fee)
        let floor_release = dep.sats as f64 * (1.0 - f64::from(WITHDRAW_FEE_MIN_BPS) / 10_000.0);
        let est_fee = withdrawal_fee_bps(est_reserve, u128::from(dep.sats), WITHDRAW_FEE_MIN_BPS, WITHDRAW_FEE_MAX_BPS);
        let est_release = dep.sats as f64 * (1.0 - f64::from(est_fee) / 10_000.0);
        let r_floor = (sats as f64 - floor_release).abs() / dep.sats as f64;
        let r_est = (sats as f64 - est_release).abs() / dep.sats as f64;
        let r = r_floor.min(r_est);
        (r < 0.005).then_some(r)
    };
    let est_reserve_at = |block: u64| reserve_at.range(..=block).next_back().map_or(0u128, |(_, &r)| r);
    for (to, (sats, block)) in &clusters {
        // (1) address reuse
        if let Some(&d) = by_from.get(to) {
            if deposits[d].block < *block {
                strong.push((-1.0, *to, d));
                weak_ok.push((*to, *sats, *block, true));
                continue;
            }
        }
        let est = est_reserve_at(*block);
        for (d, dep) in deposits.iter().enumerate() {
            if dep.block >= *block || dep.sats < *sats {
                continue;
            }
            if let Some(r) = strong_pair(dep, *sats, est) {
                strong.push((r, *to, d));
            }
        }
        weak_ok.push((*to, *sats, *block, false));
    }
    // (5) intersection: most confident first, each deposit and each cluster matched once — the strong phase whole …
    strong.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    let mut cluster_of: BTreeMap<u64, usize> = BTreeMap::new();
    let mut used = vec![false; deposits.len()];
    for (_, to, d) in strong {
        if used[d] || cluster_of.contains_key(&to) {
            continue;
        }
        used[d] = true;
        cluster_of.insert(to, d);
    }
    // … then the weak phase, lazily: deposits by (block descending, index ascending) = ascending age, ties by index.
    let mut by_age: Vec<usize> = (0..deposits.len()).collect();
    by_age.sort_by(|a, b| deposits[*b].block.cmp(&deposits[*a].block).then(a.cmp(b)));
    // the first position in `by_age` whose deposit is strictly before `block`
    let first_before = |block: u64| by_age.partition_point(|&d| deposits[d].block >= block);
    // a pair that was strong stays strong (taken above, or dead because its deposit was used): skip it here
    let is_strong = |to: u64, sats: u64, block: u64, d: usize| -> bool {
        by_from.get(&to) == Some(&d) && deposits[d].block < block || strong_pair(&deposits[d], sats, est_reserve_at(block)).is_some()
    };
    #[derive(PartialEq)]
    struct Key(f64, u64, usize, usize); // (score, cluster, deposit, cursor)
    impl Eq for Key {}
    impl PartialOrd for Key {
        fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(o))
        }
    }
    impl Ord for Key {
        fn cmp(&self, o: &Self) -> std::cmp::Ordering {
            // reversed: BinaryHeap is a max-heap
            o.0.total_cmp(&self.0).then(o.1.cmp(&self.1)).then(o.2.cmp(&self.2))
        }
    }
    let info: BTreeMap<u64, (u64, u64)> = weak_ok.iter().map(|(to, s, b, _)| (*to, (*s, *b))).collect();
    // the next weak candidate of cluster `to` at or after cursor `k` (skipping too-small, strong and used deposits)
    let next = |to: u64, mut k: usize, used: &[bool]| -> Option<Key> {
        let (sats, block) = info[&to];
        while k < by_age.len() {
            let d = by_age[k];
            if deposits[d].sats >= sats && !used[d] && !is_strong(to, sats, block, d) {
                return Some(Key(1.0 + (block - deposits[d].block) as f64 / DAY_BLOCKS as f64, to, d, k));
            }
            k += 1;
        }
        None
    };
    let mut heap = std::collections::BinaryHeap::new();
    for (to, _sats, block, reused) in &weak_ok {
        if *reused || cluster_of.contains_key(to) {
            continue; // a reuse-matched cluster proposed only its reuse pair; a matched cluster is done
        }
        if let Some(k) = next(*to, first_before(*block), &used) {
            heap.push(k);
        }
    }
    while let Some(Key(_, to, d, k)) = heap.pop() {
        if cluster_of.contains_key(&to) {
            continue;
        }
        if used[d] {
            if let Some(n) = next(to, k + 1, &used) {
                heap.push(n);
            }
            continue;
        }
        used[d] = true;
        cluster_of.insert(to, d);
    }
    pieces.iter().map(|p| cluster_of.get(&p.to).copied()).collect()
}

/// (correct matches, pieces).
#[must_use]
pub fn correct_match(w: &World) -> (u64, u64) {
    correct_match_for(w, |_| true)
}

/// (pieces linked by EITHER attacker — the heuristic [`attack`] or the [`exact_amount_attack`] — and pieces): the census
/// figure for any observer, public or custody (§19.5). A link only one attacker finds is still a link.
#[must_use]
pub fn linked(w: &World) -> (u64, u64) {
    let heuristic = attack(&w.deposits, &w.pieces);
    let exact = exact_amount_attack(&w.deposits, &w.pieces);
    let hits = heuristic
        .iter()
        .zip(&exact)
        .zip(&w.piece_user)
        .filter(|((g, x), u)| [**g, **x].iter().flatten().any(|d| w.deposit_user[*d] == **u))
        .count() as u64;
    (hits, w.piece_user.len() as u64)
}

/// [`correct_match`] counted over the pieces of the users `keep` selects only (the attacker still sees every piece).
#[must_use]
pub fn correct_match_for(w: &World, keep: impl Fn(u32) -> bool) -> (u64, u64) {
    let guess = attack(&w.deposits, &w.pieces);
    let (mut hits, mut total) = (0u64, 0u64);
    for (g, u) in guess.iter().zip(&w.piece_user) {
        if !keep(*u) {
            continue;
        }
        total += 1;
        if let Some(d) = g {
            if w.deposit_user[*d] == *u {
                hits += 1;
            }
        }
    }
    (hits, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attacker as it was written before the lazy weak phase — every proposal materialized and sorted. Kept as the
    /// reference the production attacker is measured against (`the_lazy_attacker_matches_the_reference_exactly`).
    #[allow(clippy::all)]
    fn attack_reference(deposits: &[PublicDeposit], pieces: &[PublicPiece]) -> Vec<Option<usize>> {
    // (2) clustering: pieces to one address are one withdrawal — (summed sats, last block)
    let mut clusters: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    for p in pieces {
        let c = clusters.entry(p.to).or_insert((0, 0));
        c.0 += p.sats;
        c.1 = c.1.max(p.block);
    }
    // (NEW) reconstruct the running reserve at every block from the PUBLIC Bitcoin view: cumulative
    // deposits minus cumulative payouts. This lets the attacker compute the exact expected fee for a
    // withdrawal at any block, using the same convex u² band the protocol publishes.
    let mut events: Vec<(u64, i128)> = Vec::new();
    for d in deposits {
        events.push((d.block, d.sats as i128));
    }
    for p in pieces {
        events.push((p.block, -(p.sats as i128)));
    }
    events.sort_unstable();
    let mut reserve_at: BTreeMap<u64, u128> = BTreeMap::new();
    let mut running: i128 = 0;
    for (b, delta) in &events {
        running += delta;
        reserve_at.insert(*b, running.max(0) as u128);
    }
    let by_from: BTreeMap<u64, usize> = deposits.iter().enumerate().map(|(i, d)| (d.from, i)).collect();
    // every (score, cluster, deposit) a heuristic proposes; lower is more confident
    let mut proposals: Vec<(f64, u64, usize)> = Vec::new();
    for (to, (sats, block)) in &clusters {
        // (1) address reuse
        if let Some(&d) = by_from.get(to) {
            if deposits[d].block < *block {
                proposals.push((-1.0, *to, d));
                continue;
            }
        }
        // estimate the reserve at this payout block from the running public tally
        let est_reserve = reserve_at.range(..=*block).next_back().map_or(0u128, |(_, &r)| r);
        for (d, dep) in deposits.iter().enumerate() {
            if dep.block >= *block || dep.sats < *sats {
                continue;
            }
            // (3) strongest amount heuristic: try BOTH the floor fee and the reserve-estimated fee,
            // take whichever gives the tighter match — this catches both healthy-reserve withdrawals
            // (floor fee) and early-day / stressed-reserve withdrawals (higher fee)
            let floor_release = dep.sats as f64 * (1.0 - f64::from(WITHDRAW_FEE_MIN_BPS) / 10_000.0);
            let est_fee = withdrawal_fee_bps(est_reserve, u128::from(dep.sats), WITHDRAW_FEE_MIN_BPS, WITHDRAW_FEE_MAX_BPS);
            let est_release = dep.sats as f64 * (1.0 - f64::from(est_fee) / 10_000.0);
            let r_floor = (*sats as f64 - floor_release).abs() / dep.sats as f64;
            let r_est = (*sats as f64 - est_release).abs() / dep.sats as f64;
            let r = r_floor.min(r_est);
            let score = if r < 0.005 {
                r
            } else {
                1.0 + (*block - dep.block) as f64 / DAY_BLOCKS as f64
            };
            proposals.push((score, *to, d));
        }
    }
    // (5) intersection: most confident first, each deposit and each cluster matched once
    proposals.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    let mut cluster_of: BTreeMap<u64, usize> = BTreeMap::new();
    let mut used = vec![false; deposits.len()];
    for (_, to, d) in proposals {
        if used[d] || cluster_of.contains_key(&to) {
            continue;
        }
        used[d] = true;
        cluster_of.insert(to, d);
    }
    pieces.iter().map(|p| cluster_of.get(&p.to).copied()).collect()
}

    /// The lazy weak phase changes memory, never the verdict: on small worlds of both populations (Auto-OPSEC on, and 10 %
    /// off with reuse and next-batch payouts), across seeds, the production attacker names EXACTLY the deposits the
    /// materialize-and-sort reference names, piece for piece.
    #[test]
    fn the_lazy_attacker_matches_the_reference_exactly() {
        for seed in [1u64, 7, 0xB2, 0x5eed] {
            for users in [40u64, 150] {
                for off in [0.0, AUTO_OPSEC_OFF_SHARE_MODELLED] {
                    let (w, _) = shipping_world_mixed(users, seed, off);
                    assert_eq!(
                        attack(&w.deposits, &w.pieces),
                        attack_reference(&w.deposits, &w.pieces),
                        "⛔ the lazy attacker diverged from the reference (seed {seed}, {users} users, off share {off})"
                    );
                }
            }
        }
    }

    /// REFUTATION BEFORE GREEN: the attacker must find links where they exist and must not beat chance where they do
    /// not — else a green census would mean a blind attacker.
    #[test]
    fn br0_the_linkability_attacker_finds_a_planted_link_and_cannot_beat_chance_on_a_planted_crowd() {
        let seed = sim_seed();
        let mut rng = Rng(seed);
        let n = 500u32;
        // planted link: every user withdraws its whole deposit as one output, less the floor fee
        let deposits: Vec<PublicDeposit> = (0..n)
            .map(|i| PublicDeposit { sats: 100_000 + rng.next() % 100_000_000, block: u64::from(i) * 300, from: u64::from(i) + 1 })
            .collect();
        let pieces: Vec<PublicPiece> = deposits
            .iter()
            .enumerate()
            .map(|(i, d)| PublicPiece { sats: d.sats * 9_975 / 10_000, block: d.block + HOUR_BLOCKS, to: 10_000 + i as u64 })
            .collect();
        let linked = World { deposits, pieces, deposit_user: (0..n).collect(), piece_user: (0..n).collect() };
        let (hits, total) = correct_match(&linked);
        eprintln!("[br0] planted link: {hits}/{total} pieces matched (seed {seed})");
        assert!(hits * 10 >= total * 9, "the attacker misses a planted amount link: {hits}/{total}");

        // planted crowd: equal amounts, fresh addresses, every exit in one block after every entry, users shuffled
        let deposits: Vec<PublicDeposit> =
            (0..n).map(|i| PublicDeposit { sats: 1_000_000, block: u64::from(i), from: u64::from(i) + 1 }).collect();
        let mut piece_user: Vec<u32> = (0..n).collect();
        for i in (1..piece_user.len()).rev() {
            piece_user.swap(i, (rng.next() % (i as u64 + 1)) as usize);
        }
        let pieces: Vec<PublicPiece> =
            (0..n).map(|i| PublicPiece { sats: 1_000_000, block: 10_000, to: 10_000 + u64::from(i) }).collect();
        let crowd = World { deposits, pieces, deposit_user: (0..n).collect(), piece_user };
        let (hits, total) = correct_match(&crowd);
        eprintln!("[br0] planted crowd: {hits}/{total} pieces matched (chance ≈ 1/{n})");
        assert!(hits * ONE_IN <= total, "the attacker beats chance on a crowd — it reads more than the public view: {hits}/{total}");
    }

    /// THE CENSUS (R5, spec §5): at the target volume a payout piece names its deposit at most 1 in 20. RED on the
    /// source of 2026-10-25: a payout is ONE output of the exact release, a burn's slot follows its burn, so amount
    /// and timing name the depositor. GREEN with §BR-1 (2026-10-28, spec §13): ladder pieces, a fresh vault address
    /// per piece, a sealed pay-after drawn inside 24 h — the shipping lane above models exactly what the node enforces
    /// (`is_denom` at the executor and every attestor; the pay-after gate at propose and sign). RED again on the run of
    /// 2026-10-28 (23.9 % / 20.9 %): the model let 20 % of users cash out to their deposit's own sender, which clusters
    /// every piece onto the deposit. GREEN with Auto-OPSEC (§BR-2 landing): the shipped wallet's default REFUSES that
    /// address (`refuse_deposit_sender`), so the default population is the census's subject; the off population is
    /// measured beside it by `br0_auto_opsec_users_keep_one_in_twenty_beside_users_who_switched_it_off`.
    #[test]
    fn br0_a_withdrawal_piece_names_its_deposit_at_most_one_in_twenty() {
        let seed = sim_seed();
        let mut at_target = (0u64, 0u64);
        for users in LAUNCH_VOLUMES {
            // §19.5: the public observer runs BOTH attackers too (the heuristic set and the exact-amount sum)
            at_target = linked(&shipping_world(users, seed));
            let (hits, total) = at_target;
            eprintln!(
                "[br0] {users} users/day: {hits}/{total} pieces matched ({:.1} %, bar {:.1} %, seed {seed})",
                100.0 * hits as f64 / total.max(1) as f64,
                100.0 / ONE_IN as f64
            );
        }
        let (hits, total) = at_target;
        assert!(total > 0, "the census measured no payout piece");
        assert!(
            hits * ONE_IN <= total,
            "at the target volume ({} users/day) {hits} of {total} payout pieces name their deposit — over 1 in {ONE_IN}",
            LAUNCH_VOLUMES[LAUNCH_VOLUMES.len() - 1]
        );
    }

    /// ⭐ §19.5 — CUSTODY, the adversary that sees both ends of the MONERO path, names a cash-out's deposit at most 1 in 20 at
    /// the target volume. RED on today's shapes (exact XMR releases, the request block custody can date): it turns green only
    /// when §19.4 (the anonymous claim custody cannot date) and §19.5 (XMR ladder pieces, deposits through entry rounds)
    /// change what [`custody_world`] models. The rate at every launch volume is printed.
    #[test]
    fn br0_custody_viewing_the_monero_path_names_a_deposit_at_most_one_in_twenty() {
        custody_bar(true);
    }

    /// ⭐ §19.5 — the same bar for custody on the BITCOIN path (ladder pieces already, but the request block custody can
    /// date). RED on today's shapes; §19.4 is what turns it green.
    #[test]
    fn br0_custody_viewing_the_bitcoin_path_names_a_deposit_at_most_one_in_twenty() {
        custody_bar(false);
    }

    fn custody_bar(monero: bool) {
        let seed = sim_seed();
        let chain = if monero { "monero" } else { "bitcoin" };
        let mut at_target = (0u64, 0u64);
        for users in LAUNCH_VOLUMES {
            let w = custody_world(users, seed, monero);
            let (h1, _) = correct_match(&w);
            let (hits, total) = linked(&w);
            at_target = (hits, total);
            eprintln!(
                "[br0-custody] {chain} path, {users} users/day: {hits}/{total} pieces linked by custody (heuristic alone {h1}) ({:.1} %, bar {:.1} %, seed {seed})",
                100.0 * hits as f64 / total.max(1) as f64,
                100.0 / ONE_IN as f64
            );
        }
        // what a deposit-side split would buy: the same day with the OTHER deposit shape (printed, not asserted) — measured
        // 2026-11-01: Bitcoin whole 2/114,054, Monero split 5/115,398: the anonymous claim, not the split, defeats custody
        let w = custody_world_deposits(LAUNCH_VOLUMES[LAUNCH_VOLUMES.len() - 1], seed, monero, monero);
        let (other, of) = linked(&w);
        let shape = if monero { "split into ladder transfers" } else { "whole" };
        eprintln!("[br0-custody] {chain} path, deposits {shape}: {other}/{of} pieces linked ({:.1} %)", 100.0 * other as f64 / of.max(1) as f64);
        let (hits, total) = at_target;
        assert!(total > 0, "the census measured no payout piece");
        assert!(
            hits * ONE_IN <= total,
            "⛔ CUSTODY LINKS THE {chain} PATH: at {} users/day it names the deposit of {hits} of {total} pieces — over 1 in {ONE_IN}",
            LAUNCH_VOLUMES[LAUNCH_VOLUMES.len() - 1]
        );
    }

    /// AUTO-OPSEC (user 2026-10-28): users who switch privacy OFF must not cost the default users theirs. At the target
    /// volume with [`AUTO_OPSEC_OFF_SHARE_MODELLED`] of users off (reusing the deposit's sender, paid next batch), the
    /// pieces of the users who kept Auto-OPSEC ON still name their deposit at most 1 in 20; the off users' rate is
    /// printed (it is the cost the warning popup names). Calibration: the off users ARE more linkable than the on users,
    /// else the model did not switch anything off.
    #[test]
    fn br0_auto_opsec_users_keep_one_in_twenty_beside_users_who_switched_it_off() {
        let seed = sim_seed();
        let users = LAUNCH_VOLUMES[LAUNCH_VOLUMES.len() - 1];
        let (w, off) = shipping_world_mixed(users, seed, AUTO_OPSEC_OFF_SHARE_MODELLED);
        let (on_hits, on_total) = correct_match_for(&w, |u| !off[u as usize]);
        let (off_hits, off_total) = correct_match_for(&w, |u| off[u as usize]);
        let pct = |h: u64, t: u64| 100.0 * h as f64 / t.max(1) as f64;
        eprintln!(
            "[br0] {users} users/day, {:.0} % Auto-OPSEC off: on {on_hits}/{on_total} ({:.1} %) · off {off_hits}/{off_total} ({:.1} %) (seed {seed})",
            AUTO_OPSEC_OFF_SHARE_MODELLED * 100.0,
            pct(on_hits, on_total),
            pct(off_hits, off_total)
        );
        assert!(on_total > 0 && off_total > 0, "the mixed census measured both groups");
        assert!(
            on_hits * ONE_IN <= on_total,
            "users who kept Auto-OPSEC on lose their 1-in-{ONE_IN} bar beside users who switched it off: {on_hits}/{on_total}"
        );
        assert!(
            pct(off_hits, off_total) > pct(on_hits, on_total),
            "CALIBRATION: switching Auto-OPSEC off made no one more linkable — the model switched nothing off"
        );
    }
}

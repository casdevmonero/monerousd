// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ §BR-15 (spec §18.3) — THE KEYLESS LAUNCH POSITION: the SAT/USDm pool the private DeFi layer opens with, born at
//! genesis on every node, held by nobody.
//!
//! **Where its SAT comes from.** The developer set-aside (§11, `sat_set_aside`) spends a public 2M-SAT input into the
//! set-aside note (recorded) and an output that is never recorded. The launch position SPLITS that unrecorded output — an
//! asset spend carrier over its public commitment — into the POSITION note (never recorded: no key can ever spend it) and a
//! rest (never recorded: never created). So the set-aside, the position and the unused part come out of ONE 2M bound: the
//! 21M cap and SAT's three doors are unchanged, miners keep the 19M, and the position's size is as private as the set-aside.
//!
//! **What the custody set holds (spec §18.13).** Degree-t Shamir shares of the pool's four lines: X = the position's own SAT
//! P, Y = `⌊P · price⌋` (virtual USDm at the launch price [`LAUNCH_PRICE`] — a full-range constant-product curve from the
//! launch price up, Uniswap v2's), and two FLOORS the audited clearing never sells past: `F_X = 0` (only real SAT ever
//! leaves) and `F_Y = Y` (the virtual USDm is never paid). Each custodian's share is sealed to its ML-KEM-768 custody key, and
//! ONE proof (`br15_audit::pool_open_circuit`) shows the shares open the position note's value — the PUBLIC
//! [`DefiLaunch::position`] — at that price.
//!
//! **The public donation (user 2026-11-02: "lets let the first sat pool be a public donation").** The position is
//! [`LAUNCH_DONATION_SAT`], published in the launch bytes and checked by every node at boot (a launch of any other amount
//! opens no book). On a full-range curve `X · Y` stays `X₀ · Y₀`, so the price `Y / X = X₀Y₀ / X²` grows without bound as the
//! pool's SAT runs out (after $1M of buys $29.64 per SAT, after $10M ≈ $2,000): the pool is NEVER bought out — the
//! private-depth range of §18.10 sold out at $9 after $675k. The set-aside's REST stays private: the donation is only a lower
//! bound on it. Cons, quantified: the launch pool's depth is public (a $10,000 probe read the private depth to ≈ 1 % anyway),
//! so each batch's net SAT flow against the pool follows from consecutive prices — net flow only, never an order, a fill or a
//! position; the proof's public input grows by four limbs (16 B).
//!
//! **Two pools (§18.14, user 2026-11-04):** the donation splits evenly into SAT/BTC and SAT/XMR, each one-sided at the launch price in its own coin; where this note says "the position" or "USDm" of the single pool that came first, read each pool and its coin.
//!
//! **Why no chain object.** The launch is a genesis FACT — canonical bytes compiled into every node (`defi_launch.bin`,
//! identical in every build of a network), verified at boot against the canonical set-aside; the book every node starts from
//! is a function of the network, as `PegLedger::genesis`'s own blinds are. Bytes that do not verify open no book (fail
//! closed: the DeFi layer stays shut, the chain runs). An empty file: no launch position.
//!
//! **The launch price** ([`LAUNCH_PRICE`]) is the donor's choice (user 2026-11-02: "if we set the price to 1 dollar they have
//! to pay 1 dollar per sat and it'll go up from there" — the numbers to choose by are spec §18.10's table). It may never be
//! below [`MINING_COST_FLOOR`] — the pool must not sell SAT for less than mining it costs.
//!
//! **The mining-cost floor** ([`MINING_COST_FLOOR`]) is the measured cost to mine one SAT on the reference node at launch, New Liberty
//! Standard's 2009 method (electricity per coin): the reference machine's whole wall power while it mines (the adapter's own
//! telemetry, `SystemPowerIn`), × the block interval at the launch target (500 ms), × the blocks per SAT at the launch reward
//! (`10^8 / INITIAL_REWARD` = 26.575), at the U.S. average residential price (EIA 2024: 16.48 ¢/kWh). MEASURED 2026-11-02 on
//! the reference node (Apple M1 Pro, 10 cores): 47.967 W → 637.4 J → $0.0000292 per SAT = 292 USDm-atomic per 10^7
//! SAT-atomic (both assets carry 8 decimals). `br15_the_launch_floor_is_the_measured_cost_to_mine_one_sat` re-reads it.
//!
//! **The donation** (user 2026-11-02): 225,000 SAT of the set-aside go into the position, publicly; the rest of the set-aside
//! stays the developer's set-aside note, its amount private (a note commitment under the 2M bound).
//!
//! §9.6 (the genesis book is the door the pool enters by): (1) PoW — none: a genesis fact compiled into every node, as the
//! set-aside's bytes are; (2) its proofs — the split carrier over the set-aside's unrecorded output and the position proof
//! against the circuit this node FORMS from (n, t, floor, SAT tag), at every boot; (3) value — the pool's SAT is the
//! position note's, inside the set-aside's 2M bound; nothing is recorded, so nothing is spendable but by the audited
//! clearing; (4) replay — once: the book is opened at genesis only, never by a later object; (5) bounded work — two
//! verifications, a roster of at most `MAX_ROSTER`; (6) parity with the set-aside door: canonical bytes, a carrier over a
//! public input, verified before anything applies.
//!
//! **The founding seats (user 2026-11-04: "the launch contains the first bond … so users can trade instantly at launch").**
//! Custody, the price mark, the reserve addresses and the sealed batch all need a SAT-bonded set, and SAT otherwise enters only by mining, so a launch whose
//! first custodians must first mine and bond opens no bridge and no book for as long as that takes. The launch therefore carries one [`FoundingSeat`] per
//! custodian of the book's roster: the rest of the position's split is spent, seat by seat, by the SAME welded carrier a `Class::SatBond` carries, locking
//! exactly [`founding_seat_weight`] SAT under the operator's own key, so a seat is a real bond with a real locked note (returned by `Class::Unbond`, burned by
//! a slash), out of the one 2M bound, and every node starts from the same set, active at once. Cons, quantified: [`FOUNDING_BOND_TOTAL_SAT`] of the
//! set-aside is locked until its operators unbond, and with the donation it raises the public lower bound on the set-aside to 325,000 SAT (the amount stays
//! private); about 60 KB per seat in the launch bytes, and one carrier verification per seat at boot. Taking 2/3 of custody from 100,000 SAT bonded needs 200,000
//! SAT, which on the launch curve costs about $1.8M or a month of mining at the target rate, and the theft ladder still slashes that bond.
//! §9.6 (the founding seats are a door into the validator set): (1) PoW — none: a genesis fact compiled into every node; (2) its proofs — the welded carrier per
//! seat, each over the previous rest, and the operator's ML-DSA signature over [`founding_seat_statement`], at every boot; (3) value — conservation by the
//! carriers, chained from the position's split, so the seats cannot exceed the 2M input; the locked note is never recorded until an unbond returns it;
//! (4) replay — a genesis fact, applied once when the node's state is first made; each id seats once ([`founding_seats_verdict`] refuses a repeat); (5) bounded work
//! — one seat per roster key, at most `MAX_ROSTER`; (6) parity with `Class::SatBond`: its weld and its signature are here; its membership leg and spent-set
//! check have no subject (the input is the launch's own unrecorded rest, named by the previous carrier, never a recorded note).
//!
//! BORROWED: genesis validators of Cosmos and Ethereum's beacon chain (the first set is a fact of the genesis state); Uniswap v2's full-range constant-product position (the price unbounded as the reserve empties), the locked
//! launch liquidity of a fair launch (published, withdrawable by no key), New Liberty Standard's 2009 cost-of-
//! production price, the GJKR/Pedersen dealing to per-member encryption keys (the epoch deal's sealing shape).

use crate::defi_batch::{self as db, DefiBook, Word};
use crate::defi_custody::{self as dcu, CustodianState};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use usdm_decider::br15_audit as ba;
use usdm_decider::hiding_decider::Fa4;

/// The canonical launch bytes for this build's network (empty: no launch position).
pub const CANONICAL: &[u8] = include_bytes!("defi_launch.bin");

/// The measured cost to mine one SAT, USDm-atomic per SAT-atomic as `(num, den)`: $0.0000292 per SAT (module note: the
/// measurement). The launch price may never be below it.
pub const MINING_COST_FLOOR: (u64, u64) = (292, 10_000_000);

/// ⭐ THE LAUNCH PRICE, USDm-atomic per SAT-atomic as `(num, den)`: $1.00 per SAT (both assets carry 8 decimals) — the donor's
/// working number (user 2026-11-02), chosen by the spec §18.10 table; the pool's first tick and the start of its curve.
pub const LAUNCH_PRICE: (u64, u64) = (1, 1);

/// ⭐ THE PUBLIC DONATION, in SAT (user 2026-11-02: 225,000 SAT of the set-aside, "a public donation"): the launch position's
/// size, published in the launch bytes and refused at boot if they state any other.
pub const LAUNCH_DONATION_SAT: u64 = 225_000;

/// ⭐ §18.14 (user 2026-11-04: "split 225k between btc and xmr pools"): each pool's public position, half the donation.
pub const LAUNCH_POOL_SAT: u64 = LAUNCH_DONATION_SAT / db::PAIRS as u64;

/// ⭐ THE FOUNDING BOND, in SAT, across all the founding seats: public, and checked at boot. Module note: why this size.
pub const FOUNDING_BOND_TOTAL_SAT: u64 = 100_000;

/// One founding seat's custody weight, SAT base units: the founding bond in equal parts over a roster of `n`.
#[must_use]
pub fn founding_seat_weight(n: usize) -> Option<u64> {
    let total = FOUNDING_BOND_TOTAL_SAT.checked_mul(crate::satoshi::BASE_UNITS_PER_SAT)?;
    total.checked_div(u64::try_from(n).ok()?)
}

/// An ML-KEM-768 encapsulation key's width (a custody key the roster publishes).
pub const EK_BYTES: usize = 1_184;

/// ⭐ ONE FOUNDING SEAT: a custodian of the book's roster, bonded by the launch. Its custody KEM key is the roster's key at the same index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundingSeat {
    /// O1-FOOTPRINT-REVIEWED: one ML-DSA-65 key, bounded by `asset_tx::ASSET_MINT_AUTH_BYTES_MAX` in `decode`.
    pub pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: one compressed secp256k1 point (the bridge endpoint's custody point), 33 B, checked in `decode`.
    pub secp33: Vec<u8>,
    pub ed32: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: one whole note (`cover::PQ_NOTE_BYTES`), checked in `decode`; sealed to the operator, returned at unbond.
    pub locked_note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: one welded asset bond carrier, bounded by `asset_tx::ASSET_SPEND_CARRIER_BYTES_MAX` in `decode`.
    pub carrier: Vec<u8>,
    pub nullifier: [u8; 32],
    pub lc_blind: [u8; 32],
    /// what is left after this seat (never recorded); the next seat's input
    pub rest_cm: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: one ML-DSA-65 signature, bounded by `asset_tx::ASSET_MINT_AUTH_BYTES_MAX` in `decode`.
    pub sig: Vec<u8>,
}

/// The statement a founding operator signs: the bond statement a `Class::SatBond` signs, plus the custody keys a membership seat's signed header names.
#[must_use]
pub fn founding_seat_statement(vid: &[u8; 32], weight: u64, locked_cm: &[u8; 32], nullifier: &[u8; 32], secp33: &[u8], ed32: &[u8; 32], kem_ek: &[u8]) -> Vec<u8> {
    let mut m = crate::sat_bond_tx::sat_bond_msg(vid, weight, locked_cm, nullifier);
    m.extend_from_slice(b"|MONEROUSD-FOUNDING-SEAT-v1");
    m.extend_from_slice(secp33);
    m.extend_from_slice(ed32);
    m.extend_from_slice(kem_ek);
    m
}

/// ⭐ ONE POOL'S LAUNCH POSITION (§18.14): a one-sided SAT position at the launch price, stated in the pair's coin, like a Uniswap v3 position above its lower bound: buyers' coin fills its other side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchPool {
    /// O1-FOOTPRINT-REVIEWED: one pool commitment per custodian (roster order), bounded with `eks`.
    pub share_commits: Vec<[u64; 4]>,
    /// O1-FOOTPRINT-REVIEWED: one sealed pool state (its four line shares and salt) per custodian, exactly `SEALED_BYTES` each.
    pub sealed: Vec<Vec<u8>>,
    /// the position proof (`pool_open_circuit`)
    pub open_proof: Vec<u8>,
    /// the split: an asset spend carrier over what the last split left, its nullifier and published blind
    pub split: Vec<u8>,
    pub split_nf: [u8; 32],
    pub split_lc_blind: [u8; 32],
    /// the position note's commitment and the rest's (neither ever recorded)
    pub position_cm: [u8; 32],
    /// ⭐ the position, PUBLIC (SAT-atomic): the proof's public input, so the pool holds exactly what this states
    pub position: u64,
    pub rest_cm: [u8; 32],
    /// ⭐ the launch price in this pair's coin: coin atoms per SAT atom as `(num, den)`, $1 per SAT at the marks the launch command read; from then on the pool's ratio is the price
    pub price: (u64, u64),
}

/// ⭐ THE LAUNCH, as the canonical bytes hold it: the custody set, its two pools and the founding seats.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiLaunch {
    /// O1-FOOTPRINT-REVIEWED: the founding custody set's ML-KEM-768 keys, at most `MAX_ROSTER`, checked in `decode`.
    pub eks: Vec<Vec<u8>>,
    pub t: u32,
    /// O1-FOOTPRINT-REVIEWED: exactly [`db::PAIRS`], checked in `decode`.
    pub pools: Vec<LaunchPool>,
    /// O1-FOOTPRINT-REVIEWED: one founding seat per roster key, at most `MAX_ROSTER`, checked in `decode`.
    pub founding: Vec<FoundingSeat>,
}

/// A custody id: the blake3 of its ML-KEM key (the book's roster names keys, never people).
#[must_use]
pub fn custody_id(ek: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key("USDMD-BR15-CUSTODY-ID-v1").update(ek).finalize().as_bytes()
}

impl DefiLaunch {
    /// The canonical encoding; `None` only if serialization itself fails.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    /// One canonical, bounded encoding: a roster of 1..=MAX_ROSTER keys at the honest-majority threshold `⌊(n − 1)/3⌋`, one
    /// commitment and one constant-width sealed share per key.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = crate::chain_object::decode_exact(bytes)?;
        let n = t.eks.len();
        if n == 0 || n > db::MAX_ROSTER || t.t as usize != (n - 1) / 3 {
            return None;
        }
        if t.eks.iter().any(|k| k.len() != EK_BYTES) || t.pools.len() != db::PAIRS as usize {
            return None;
        }
        let pool_ok = |p: &LaunchPool| {
            p.share_commits.len() == n
                && p.sealed.len() == n
                && p.sealed.iter().all(|s| s.len() == db::SEALED_BYTES)
                && p.open_proof.len() <= db::MAX_PROOF_BYTES
                && p.split.len() <= db::MAX_PROOF_BYTES
                && p.price.0 > 0
                && p.price.1 > 0
        };
        if !t.pools.iter().all(pool_ok) {
            return None;
        }
        let auth = crate::asset_tx::ASSET_MINT_AUTH_BYTES_MAX;
        let wide = t.founding.iter().any(|s| {
            s.pubkey.is_empty()
                || s.pubkey.len() > auth
                || s.sig.is_empty()
                || s.sig.len() > auth
                || s.secp33.len() != 33
                || s.locked_note.len() != crate::cover::PQ_NOTE_BYTES
                || s.carrier.is_empty()
                || s.carrier.len() > crate::asset_tx::ASSET_SPEND_CARRIER_BYTES_MAX
        });
        if wide {
            return None;
        }
        Some(t)
    }

    /// ⭐ THE FOUNDING SEATS' VERDICT: one seat per roster key, each a distinct id, each spending what the last one left (the first, the position
    /// split's rest) into a locked note of exactly the seat weight in SAT by the bond carrier, each signed by its own key over the statement naming the
    /// roster's custody key at its index. Bytes that fail open no book and seat nobody.
    pub fn founding_seats_verdict(&self) -> Result<(), &'static str> {
        use crate::spend_frontier::cm_bytes_to_root as r;
        if self.founding.len() != self.eks.len() {
            return Err("the launch does not seat its whole roster");
        }
        let Some(weight) = founding_seat_weight(self.eks.len()) else {
            return Err("the founding bond does not divide over this roster");
        };
        let Some(mut input) = self.pools.last().map(|p| p.rest_cm) else {
            return Err("the launch names no pool");
        };
        let mut seen = std::collections::HashSet::new();
        for (s, ek) in self.founding.iter().zip(&self.eks) {
            let vid = crate::pqauth::pubkey_id(&s.pubkey);
            if !seen.insert(vid) {
                return Err("one key holds two founding seats");
            }
            let (Some(locked), Some(rest), Some(nf), Some(blind), Some(leaf)) = (
                crate::spend_frontier::note_cm_of(&s.locked_note),
                r(&s.rest_cm),
                r(&s.nullifier),
                r(&s.lc_blind),
                r(&input),
            ) else {
                return Err("a founding seat's digest is not canonical");
            };
            let lc = usdm_decider::note_membership_air::note_leaf_commitment(leaf, nf, blind);
            let tag = crate::satoshi::asset_tag();
            if !usdm_decider::whir_rec_block::verify_asset_bond_validity_carrier_bytes(&s.carrier, locked, rest, nf, lc, weight, tag) {
                return Err("a founding seat's carrier does not lock exactly its weight in SAT out of what the last one left");
            }
            let locked_cm = crate::spend_frontier::leaf_to_cm_bytes(locked);
            let m = founding_seat_statement(&vid, weight, &locked_cm, &s.nullifier, &s.secp33, &s.ed32, ek);
            if !crate::pqauth::ml_dsa_verify(&m, &s.pubkey, &s.sig) {
                return Err("a founding seat is not signed by the key it seats");
            }
            input = s.rest_cm;
        }
        Ok(())
    }

    /// ⭐ THE VERDICT against the canonical set-aside: each split spends what the last one left (the first, the set-aside's unrecorded output) into its pool's position and a rest, and each
    /// position proof opens its pool's shares to its position note's value — the public position — at that pool's launch price.
    pub fn verdict(&self, set_aside: &crate::sat_set_aside::SatSetAsideTx) -> Result<(), &'static str> {
        use crate::spend_frontier::cm_bytes_to_root as r;
        let mut input = set_aside.out1_cm;
        let n = self.eks.len();
        for p in &self.pools {
            let (Some(leaf), Some(nf), Some(blind), Some(pos), Some(rest)) = (r(&input), r(&p.split_nf), r(&p.split_lc_blind), r(&p.position_cm), r(&p.rest_cm)) else {
                return Err("a launch digest is not canonical");
            };
            let lc = usdm_decider::note_membership_air::note_leaf_commitment(leaf, nf, blind);
            if !usdm_decider::whir_rec_block::verify_asset_spend_validity_carrier_bytes(&p.split, pos, rest, nf, lc) {
                return Err("a split does not spend what the last one left into its pool's position");
            }
            let Some(shape) = ba::pool_open_r1cs(n, self.t as usize, p.price, crate::satoshi::asset_tag()) else {
                return Err("the position circuit cannot form for this roster");
            };
            let commits: Vec<[Fa4; 4]> = p.share_commits.iter().map(|c| core::array::from_fn(|k| Fa4::from_u64(c[k]))).collect();
            let io = ba::pool_open_io(&pos, p.position, &commits);
            if !usdm_decider::spartan_ccs::verify_committed(&shape, &io, &p.open_proof) {
                return Err("a pool's shares do not open its stated position at its launch price");
            }
            input = p.rest_cm;
        }
        Ok(())
    }

    /// ⭐ Whether each pool states exactly its half of the public donation.
    #[must_use]
    pub fn is_the_public_donation(&self) -> bool {
        let want = LAUNCH_POOL_SAT.checked_mul(crate::satoshi::BASE_UNITS_PER_SAT);
        self.pools.len() == db::PAIRS as usize && self.pools.iter().all(|p| Some(p.position) == want)
    }

    /// The book a pool opens: the roster (ids of its keys), the keys, the pool commitments, batch 0 open from the first fold step, its launch price's tick as the search's first window.
    #[must_use]
    pub fn book(&self, pair: u8) -> DefiBook {
        let Some(p) = self.pools.get(pair as usize) else {
            return DefiBook { pair, ..DefiBook::default() };
        };
        DefiBook {
            pair,
            roster: self.eks.iter().map(|k| custody_id(k)).collect(),
            eks: self.eks.clone(),
            t: self.t,
            pool_commits: p.share_commits.clone(),
            fee_commits: db::launch_fee_commits(pair, self.eks.len()),
            batch: 0,
            opened_at: 0,
            opened_ms: 0,
            orders: Vec::new(),
            last_tick: crate::defi_clear::rule_tick(u128::from(p.price.1), u128::from(p.price.0)),
            last_expired: false,
            last_sells: false,
            prices: Default::default(),
            income_index: 0,
            pending: Vec::new(),
            slotted: false,
            slot_parts: 0,
            handover: None,
            // ⭐ Earn step 3 — the closed window's lines at public zeros, and the launch units present (sampled) from the start;
            // every other window field starts at its default (no window closed, raised or deposited yet)
            close_commits: db::launch_close_commits(pair, self.eks.len()),
            sampling: true,
            ..DefiBook::default()
        }
    }

    /// ⭐ Custodian `i`'s pool state from the launch: its sealed share opened with its decapsulation key and checked against
    /// its commitment. `None` — not this custodian's.
    #[must_use]
    pub fn capture(&self, dk: &[u8], pair: u8, i: usize) -> Option<CustodianState> {
        let p = self.pools.get(pair as usize)?;
        let (lines, salt) = dcu::open_pool_share(dk, p.sealed.get(i)?)?;
        let st = CustodianState::at_launch(lines, salt, pair, i);
        (st.commit() == *p.share_commits.get(i)?).then_some(st)
    }
}

#[cfg(test)]
thread_local! {
    /// Test seam: THIS thread's stand-in launch bytes (a concurrent test's genesis never sees them).
    static CANONICAL_FOR_TEST: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// Test builds only: stand in other canonical launch bytes on this thread (the pins build them from a test set-aside).
#[cfg(test)]
pub fn set_canonical_for_test(bytes: Option<Vec<u8>>) {
    CANONICAL_FOR_TEST.with(|c| *c.borrow_mut() = bytes);
}

/// The canonical launch bytes this node holds (`None`: no launch position).
#[must_use]
pub fn canonical_bytes() -> Option<Vec<u8>> {
    #[cfg(test)]
    if let Some(b) = CANONICAL_FOR_TEST.with(|c| c.borrow().clone()) {
        return Some(b);
    }
    (!CANONICAL.is_empty()).then(|| CANONICAL.to_vec())
}

fn verified_launch() -> Option<DefiLaunch> {
    let l = canonical_bytes().and_then(|b| DefiLaunch::decode(&b))?;
    let Some(sa) = crate::sat_set_aside::canonical_bytes().and_then(|b| crate::sat_set_aside::SatSetAsideTx::decode(&b)) else {
        eprintln!("[defi-launch] ⛔ launch bytes without a canonical set-aside: the DeFi layer stays shut");
        return None;
    };
    if !l.is_the_public_donation() {
        eprintln!("[defi-launch] ⛔ the launch's pools do not state the public donation of {LAUNCH_DONATION_SAT} SAT, split evenly: the DeFi layer stays shut");
        return None;
    }
    match (sa.proves_the_bound(), l.verdict(&sa).and_then(|()| l.founding_seats_verdict())) {
        (true, Ok(())) => Some(l),
        (false, _) => {
            eprintln!("[defi-launch] ⛔ the set-aside does not prove its bound: the DeFi layer stays shut");
            None
        }
        (true, Err(why)) => {
            eprintln!("[defi-launch] ⛔ the launch does not verify ({why}): the DeFi layer stays shut");
            None
        }
    }
}

fn the_launch() -> Option<DefiLaunch> {
    #[cfg(test)]
    if CANONICAL_FOR_TEST.with(|c| c.borrow().is_some()) {
        return verified_launch();
    }
    static LAUNCH: std::sync::OnceLock<Option<DefiLaunch>> = std::sync::OnceLock::new();
    LAUNCH.get_or_init(verified_launch).clone()
}

/// ⭐ THE FOUNDING SEATS every node starts from: `(vid, weight, seat)`, empty when the launch does not verify (no book, no seats), in roster order with the
/// roster's custody key.
#[must_use]
pub fn genesis_seats() -> Vec<([u8; 32], u64, FoundingSeat, Vec<u8>)> {
    let Some(l) = the_launch() else {
        return Vec::new();
    };
    let Some(weight) = founding_seat_weight(l.eks.len()) else {
        return Vec::new();
    };
    l.founding.into_iter().zip(l.eks).map(|(s, ek)| (crate::pqauth::pubkey_id(&s.pubkey), weight, s, ek)).collect()
}

/// ⭐ THE GENESIS BOOK: the verified launch position's, or a shut book. Verified once per process (two proofs); a test that
/// stands in bytes verifies them on every call.
#[must_use]
pub fn genesis_book() -> DefiBook {
    genesis_books().swap_remove(0)
}

/// ⭐ §18.14 — every pool's genesis book, in pair order: shut and empty on a chain with no launch.
#[must_use]
pub fn genesis_books() -> Vec<DefiBook> {
    let l = the_launch();
    (0..db::PAIRS).map(|pair| l.as_ref().map_or_else(|| DefiBook { pair, ..DefiBook::default() }, |l| l.book(pair))).collect()
}

/// Test builds: the launch splitting a test set-aside's unrecorded output (`out1_value` SAT, owned by `out1_owner`) into a public position of `position` SAT in each pool, at the launch price,
/// dealt among custodians with keys `eks`. The dealing returned is the first pool's.
#[cfg(test)]
pub fn build_for_test(
    out1_value: u64,
    out1_owner: usdm_decider::whir_rec_block::NoteOwner,
    position: u64,
    eks: &[Vec<u8>],
    key: &[u8; 32],
) -> Option<(DefiLaunch, ba::PoolDealing)> {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block as wr;
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let n = eks.len();
    let t = (n - 1) / 3;
    let mut draw = blake3::Hasher::new_keyed(key).update(b"launch-test").finalize_xof();
    let mut word = || -> Word {
        let mut b = [0u8; 32];
        draw.fill(&mut b);
        let l: Word = core::array::from_fn(|k| u64::from_le_bytes(b[8 * k..8 * k + 8].try_into().unwrap_or([0; 8])));
        ba::fadd(&[l[0], l[1], l[2], l[3] >> 2], &[0; 4])
    };
    let (mut value, mut owner) = (out1_value, out1_owner);
    let mut pools = Vec::new();
    let mut first = None;
    for pair in 0..u64::from(db::PAIRS) {
        let pos_owner = wr::NoteOwner::from_test_key(lanes_of(&[0xD1A, key[0].into(), 1, pair]));
        let lc_blind = lanes_of(&[0xD1A, key[0].into(), 2, pair]);
        // the last split's rest is the founding chain's first input
        let next = if pair + 1 == u64::from(db::PAIRS) { founding_rest_owner_for_test(key, 0) } else { wr::NoteOwner::from_test_key(lanes_of(&[0xD1A, key[0].into(), 3, pair])) };
        let w = wr::AssetSpendValidityWitness {
            value_in: value,
            owner,
            value_out: value,
            fee: 0,
            lc_blind,
            out0_value: position,
            out0_opening: pos_owner.opening(),
            out1_value: value.checked_sub(position)?,
            out1_opening: next.opening(),
            asset: crate::satoshi::asset_tag(),
        };
        let (split, cms, nf, _lc) = wr::prove_asset_spend_validity_carrier_bytes(&w)?;
        let d = ba::PoolDealing {
            position,
            sk: pos_owner.opening(),
            tag: crate::satoshi::asset_tag(),
            price: LAUNCH_PRICE,
            coeffs: (0..ba::POOL_LINES).map(|_| (0..t).map(|_| word()).collect()).collect(),
            salts: (0..n).map(|i| [Fa4::from_u64(i as u64 + 11), Fa4::from_u64(key[1].into()), Fa4::from_u64(7 + pair), Fa4::from_u64(9)]).collect(),
        };
        if d.position_cm() != cms[0] {
            return None;
        }
        let (r1cs, io, wit) = ba::pool_open_circuit(&d)?;
        let open_proof = usdm_decider::spartan_ccs::prove_committed(&r1cs, &io, &wit)?;
        let sealed = (0..n).map(|i| dcu::seal_pool_share(&eks[i], &d.shares(i), &d.salts[i])).collect::<Option<Vec<_>>>()?;
        pools.push(LaunchPool {
            share_commits: d.share_commits().iter().map(|c| core::array::from_fn(|k| p3_field::PrimeField64::as_canonical_u64(&c[k]))).collect(),
            sealed,
            open_proof,
            split,
            split_nf: b32(nf),
            split_lc_blind: b32(lc_blind),
            position_cm: b32(cms[0]),
            position,
            rest_cm: b32(cms[1]),
            price: LAUNCH_PRICE,
        });
        first.get_or_insert(d);
        value -= position;
        owner = next;
    }
    let founding = founding_seats_for_test(value, eks, key);
    Some((DefiLaunch { eks: eks.to_vec(), t: t as u32, pools, founding }, first?))
}

/// Test builds: the founding seats over the position split's rest of `rest_value`, with fresh operator keys; empty when the rest cannot cover them
/// (a launch whose [`DefiLaunch::founding_seats_verdict`] then refuses).
#[cfg(test)]
fn founding_seats_for_test(rest_value: u64, eks: &[Vec<u8>], key: &[u8; 32]) -> Vec<FoundingSeat> {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block as wr;
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let Some(weight) = founding_seat_weight(eks.len()) else {
        return Vec::new();
    };
    if rest_value < weight * eks.len() as u64 {
        return Vec::new();
    }
    let tag = crate::satoshi::asset_tag();
    let (mut value, mut owner) = (rest_value, founding_rest_owner_for_test(key, 0));
    let mut out = Vec::with_capacity(eks.len());
    for (i, ek) in eks.iter().enumerate() {
        let next = founding_rest_owner_for_test(key, i as u64 + 1);
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let vid = crate::pqauth::pubkey_id(&pk);
        let (dk_ek, _) = crate::pqkem::keypair();
        let spk = lanes_of(&[0xD1B, key[0].into(), i as u64]);
        let Some((note, opening)) = crate::faucet::seal_asset_note(&dk_ek, &spk, weight, tag, None) else {
            return Vec::new();
        };
        let lc_blind = lanes_of(&[0xD1C, key[0].into(), i as u64]);
        let w = wr::AssetSpendValidityWitness {
            value_in: value,
            owner: owner.clone(),
            value_out: value,
            fee: 0,
            lc_blind,
            out0_value: weight,
            out0_opening: opening,
            out1_value: value - weight,
            out1_opening: next.opening(),
            asset: tag,
        };
        let Some((carrier, cms, nf, _)) = wr::prove_asset_bond_validity_carrier_bytes(&w, weight) else {
            return Vec::new();
        };
        let (secp33, ed32) = (vec![2u8; 33], [7u8; 32]);
        let m = founding_seat_statement(&vid, weight, &b32(cms[0]), &b32(nf), &secp33, &ed32, ek);
        let Some(sig) = crate::pqauth::ml_dsa_sign(&m, &sk) else {
            return Vec::new();
        };
        out.push(FoundingSeat { pubkey: pk, secp33, ed32, locked_note: note.to_vec(), carrier, nullifier: b32(nf), lc_blind: b32(lc_blind), rest_cm: b32(cms[1]), sig });
        value -= weight;
        owner = next;
    }
    out
}

/// Test builds: the rest's owner at step `i` of the founding chain (step 0 is the position split's rest).
#[cfg(test)]
fn founding_rest_owner_for_test(key: &[u8; 32], i: u64) -> usdm_decider::whir_rec_block::NoteOwner {
    usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[0xD1D, key[0].into(), i]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐⭐ THE LAUNCH POSITION OPENS THE GENESIS BOOK FROM THE SET-ASIDE'S REMAINDER: a test set-aside of 1.2M SAT to the
    /// developer leaves 0.8M unrecorded; the launch splits the PUBLIC donation of 225,000 SAT of it into the position, a
    /// full-range curve at $1/SAT, dealt among 4 custodians. The genesis book is open, each custodian captures its share from
    /// the sealed bytes, the shares open (P, Y, 0, Y), and the custody runtime settles the first batch from them: a $100 buy
    /// gets just under 100 SAT at the rule's tick over the public P — and a $10,000,000 buy, forty times the pool's opening
    /// value, also settles and still leaves SAT in the pool (the price unbounded, never bought out).
    /// TAMPER: a position larger than the remainder cannot be split; a launch whose split names another set-aside, whose
    /// position proof is swapped, whose shares are re-committed, whose public position is misstated, or which states any
    /// amount but the public donation, opens NO book (the DeFi layer stays shut, fail closed).
    /// TWO-PARTY-REVIEWED: the parties are the dealer that seals (`build_for_test`) and four custodians that each open ONLY
    /// with their own decapsulation key (`capture`, and a custodian opening another's share is refused); every node forms
    /// the same genesis book from the same bytes, and the two-node chain agreement on the DeFi objects is pinned in
    /// `defi_batch::pins` (one node produces, the second ingests, both hold the same book).
    #[test]
    fn br15_the_launch_position_opens_the_genesis_book_from_the_set_aside_remainder() {
        use usdm_decider::poseidon2_compress::lanes_of;
        use usdm_decider::whir_rec_block as wr;
        let unit = crate::satoshi::BASE_UNITS_PER_SAT;
        let out1_owner = wr::NoteOwner::from_test_key(lanes_of(&[0x5e7a, 7, 7, 7]));
        let max = crate::satoshi::SAT_SET_ASIDE_MAX;
        let sa = crate::sat_set_aside::build_for_test_with_out1(1_200_000 * unit, lanes_of(&[0x5e7a, 1, 1, 1]), max, out1_owner.opening())
            .expect("the test set-aside builds");
        assert!(sa.proves_the_bound(), "PRECONDITION: the set-aside proves its bound");
        let kems: Vec<(Vec<u8>, Vec<u8>)> = (0..4).map(|_| crate::pqkem::keypair()).collect();
        let eks: Vec<Vec<u8>> = kems.iter().map(|k| k.0.clone()).collect();
        let position = LAUNCH_POOL_SAT * unit;
        assert!(build_for_test(800_000 * unit, out1_owner.clone(), 800_000 * unit + 1, &eks, &[1; 32]).is_none(), "⛔ a position above the remainder split");
        let (launch, d) = build_for_test(800_000 * unit, out1_owner.clone(), position, &eks, &[1; 32]).expect("the launch builds");
        assert!(launch.is_the_public_donation(), "the launch states the public donation");
        assert_eq!(d.lines(), [position, position, 0, position], "(P, Y, 0, Y): the full-range curve on the position's own SAT");
        let bytes = launch.encode().expect("encodes");
        assert_eq!(DefiLaunch::decode(&bytes), Some(launch.clone()), "one canonical encoding");
        assert_eq!(launch.verdict(&sa), Ok(()), "⛔ the honest launch does not verify");

        crate::sat_set_aside::set_canonical_for_test(Some(sa.encode()));
        set_canonical_for_test(Some(bytes));
        let book = genesis_books().swap_remove(0);
        assert!(book.is_open(), "⛔ the genesis book is not open");
        assert_eq!(book.roster, eks.iter().map(|k| custody_id(k)).collect::<Vec<_>>(), "the roster names the custody keys");
        let states: Vec<CustodianState> = (0..4).map(|i| launch.capture(&kems[i].1, 0, i).expect("custodian i captures its pool share")).collect();
        assert!(launch.capture(&kems[0].1, 0, 1).is_none(), "⛔ a custodian opened another's pool share");
        for (i, st) in states.iter().enumerate() {
            assert_eq!(st.lines, d.shares(i), "custodian {i} holds the dealt shares");
        }
        // the first batch settles from the launch's shares: one buy at the launch price, no maximum
        let first_batch = |usdm: u64, seed: u8| {
            let mut book1 = book.clone();
            let buy = dcu::deal_order(usdm, 3, [0x0D, 1, 2, 3, 4, 5, 6, 7], 4, 1, &[seed; 32]);
            book1.orders.push(db::BookOrder {
                amount_commit: buy.amount_commit(),
                limit_commit: buy.limit_commit(),
                share_commits: buy.share_commits().iter().map(|c| core::array::from_fn(|k| p3_field::PrimeField64::as_canonical_u64(&c[k]))).collect(),
            });
            let shares = vec![(0..4).map(|i| Some((dcu::dealing_lines(&buy, i), buy.salts[i]))).collect::<Vec<_>>()];
            let run = dcu::run_batch(&book1, &states, &shares, &[seed + 1; 32]).expect("the batch settles");
            assert_eq!(run.settle.verdict(&book1), Ok(run.settle.leaves.clone()), "⛔ a node refuses the settlement");
            run
        };
        let run = first_batch(100 * unit, 3);
        let want = crate::defi_clear::rule_tick(u128::from(position), u128::from(d.y0()) + u128::from(100 * unit));
        assert_eq!(run.settle.tick, want, "the first tick is the rule's over the public position");
        let sat = crate::defi_clear::buyer_claim(u128::from(100 * unit), want).expect("fits");
        assert!(sat < 100 * u128::from(unit) && sat > 99 * u128::from(unit), "a $100 buy at $1/SAT gets just under 100 SAT");
        // NEVER BOUGHT OUT: $10M — forty times the pool's opening value — settles, and the pool keeps SAT
        let whale = 10_000_000 * unit;
        let big = first_batch(whale, 5);
        let left = big.next.iter().map(|c| c.lines[0]).collect::<Vec<_>>();
        let left = ba::fsub(&ba::fmul(&ba::fsmall(2), &left[0]), &left[1]); // t = 1: Lagrange at 0 over x = 1, 2
        let bought = crate::defi_clear::buyer_claim(u128::from(whale), big.settle.tick).expect("fits");
        assert!(bought < u128::from(position), "⛔ a $10M buy took the whole public pool");
        assert_ne!(left, ba::fsmall(0), "⛔ the pool's SAT ran out");
        let px = |t: i64| 1.001f64.powi(i32::try_from(t).unwrap_or(i32::MAX));
        eprintln!(
            "[br15-launch] public donation {} SAT on a full-range curve at $1/SAT: $100 buys {:.4} SAT at tick {want}; $10M buys {:.0} SAT at ≈ ${:.0} per SAT (tick {}), {:.0} SAT stay in the pool",
            position / unit,
            sat as f64 / unit as f64,
            bought as f64 / unit as f64,
            px(big.settle.tick),
            big.settle.tick,
            (u128::from(position) - bought) as f64 / unit as f64
        );

        // TAMPER: another set-aside (its remainder is not the one split), a swapped proof, re-committed shares — no book
        let other = crate::sat_set_aside::build_for_test_with_out1(1_100_000 * unit, lanes_of(&[0x5e7a, 1, 1, 1]), max, out1_owner.opening()).expect("builds");
        assert!(launch.verdict(&other).is_err(), "⛔ the launch verified against another set-aside's remainder");
        let mut swapped = launch.clone();
        swapped.pools[0].open_proof = build_for_test(800_000 * unit, out1_owner.clone(), position - 1, &eks, &[2; 32]).expect("builds").0.pools[0].open_proof.clone();
        assert!(swapped.verdict(&sa).is_err(), "⛔ a position proof of another pool verified");
        let mut misstated = launch.clone();
        misstated.pools[0].position -= 1;
        assert!(misstated.verdict(&sa).is_err(), "⛔ a misstated public donation verified");
        let (other_amount, _) = build_for_test(800_000 * unit, out1_owner.clone(), position + unit, &eks, &[6; 32]).expect("builds");
        assert_eq!(other_amount.verdict(&sa), Ok(()), "PRECONDITION: a launch of 225,001 SAT proves");
        set_canonical_for_test(Some(other_amount.encode().expect("encodes")));
        assert!(!genesis_books().swap_remove(0).is_open(), "⛔ a launch of another amount than the public donation opened the book");
        let mut recommitted = launch.clone();
        recommitted.pools[0].share_commits[0][0] ^= 1;
        assert!(recommitted.verdict(&sa).is_err(), "⛔ re-committed pool shares verified");
        set_canonical_for_test(Some(recommitted.encode().expect("encodes")));
        assert!(!genesis_books().swap_remove(0).is_open(), "⛔ an unverified launch opened the book");
        set_canonical_for_test(None);
        crate::sat_set_aside::set_canonical_for_test(None);
    }

    /// ⭐ THE FLOOR IS THE MEASURED COST TO MINE ONE SAT (New Liberty Standard's method): the reference machine's wall power
    /// (its adapter's telemetry, read now) × the launch block interval × the blocks per SAT at the launch reward, at the EIA
    /// average price — recomputed and compared with [`MINING_COST_FLOOR`] within the measurement's spread (×2 either way: the
    /// same machine reads 25–95 W across idle and full load); and the launch price is at or above it (the pool never sells SAT
    /// for less than mining it costs).
    /// CALIBRATION: the arithmetic over the recorded 47.967 W gives the recorded floor's 292 per 10^7 (within 1 %).
    /// ⭐ THE FOUNDING SEATS: an honest launch seats its whole roster on a fresh node, active at once with their custody keys and locked notes; every
    /// tampered launch seats nobody and opens no book. CALIBRATION: the honest bytes pass the same verdict first.
    #[test]
    fn a_launch_seats_its_roster_at_genesis_and_a_tampered_seat_seats_nobody() {
        let unit = crate::satoshi::BASE_UNITS_PER_SAT;
        let max = crate::satoshi::SAT_SET_ASIDE_MAX;
        let out1_owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[0x5e7a, 9, 9, 9]));
        let sa = crate::sat_set_aside::build_for_test_with_out1(1_200_000 * unit, usdm_decider::poseidon2_compress::lanes_of(&[0x5e7a, 1, 1, 1]), max, out1_owner.opening()).expect("builds");
        let eks: Vec<Vec<u8>> = (0..4).map(|_| crate::pqkem::keypair().0).collect();
        let position = LAUNCH_POOL_SAT * unit;
        let (launch, _) = build_for_test(800_000 * unit, out1_owner.clone(), position, &eks, &[3; 32]).expect("the launch builds");
        assert_eq!(launch.founding_seats_verdict(), Ok(()), "⛔ the honest founding seats do not verify");
        crate::sat_set_aside::set_canonical_for_test(Some(sa.encode()));
        set_canonical_for_test(Some(launch.encode().expect("encodes")));
        let seats = genesis_seats();
        assert_eq!(seats.len(), 4, "the whole roster seats");
        let w = founding_seat_weight(4).expect("divides");
        assert_eq!(w, 25_000 * unit, "the founding bond in equal parts");
        let mut vs = crate::validator::ValidatorSet::new();
        crate::validator::seat_founders(&mut vs, &seats);
        for (vid, weight, _, _) in &seats {
            assert_eq!(vs.bond_of(vid), u128::from(*weight), "a founder holds its weight");
            assert_eq!(vs.finality_weight_of_at(vid, 0), u128::from(*weight), "a founder votes from the first block");
        }
        assert_eq!(vs.bonded_custody().len(), 4, "the reserve is the founders' from the first block");
        assert_eq!(vs.bonded_custodian_eks().len(), 4, "the sealed lanes reach every founder");

        // TAMPER: each is refused by the same verdict, and a bytes-level swap seats nobody and opens no book
        let refused = |l: &DefiLaunch, what: &str| assert!(l.founding_seats_verdict().is_err(), "⛔ {what} verified");
        let mut t = launch.clone();
        t.founding.pop();
        refused(&t, "a launch seating part of its roster");
        let mut t = launch.clone();
        t.founding[1] = t.founding[0].clone();
        refused(&t, "one key in two seats");
        let mut t = launch.clone();
        t.founding[2].rest_cm = t.founding[3].rest_cm;
        refused(&t, "a seat chained to another's rest (value taken twice)");
        let mut t = launch.clone();
        t.founding[0].ed32[0] ^= 1;
        refused(&t, "a custody point the operator did not sign");
        let mut t = launch.clone();
        t.eks.swap(0, 1);
        refused(&t, "a roster key the operator did not sign");
        let mut t = launch.clone();
        t.founding[0].carrier[100] ^= 1;
        refused(&t, "a tampered carrier");
        let (other, _) = build_for_test(800_000 * unit, out1_owner.clone(), position, &eks, &[4; 32]).expect("builds");
        let mut t = launch.clone();
        t.founding[3] = other.founding[3].clone();
        refused(&t, "a seat from another launch");
        // every pair's pool takes its own position from the split chain (`build_for_test` splits once per pair), so the rest
        // that cannot cover the founding bond is every position plus one unit — `position + unit` (written when the launch had
        // one pool) could not even build a second pool, and this refusal never ran
        let (short, _) = build_for_test(u64::from(db::PAIRS) * position + unit, out1_owner, position, &eks, &[5; 32]).expect("builds");
        refused(&short, "a launch whose rest cannot cover the founding bond");
        set_canonical_for_test(Some(t.encode().expect("encodes")));
        assert!(genesis_seats().is_empty(), "⛔ tampered bytes seated someone");
        assert!(!genesis_books().swap_remove(0).is_open(), "⛔ tampered bytes opened the book");
        set_canonical_for_test(None);
        crate::sat_set_aside::set_canonical_for_test(None);
    }

    #[test]
    fn br15_the_launch_floor_is_the_measured_cost_to_mine_one_sat() {
        let blocks_per_sat = crate::satoshi::BASE_UNITS_PER_SAT as f64 / crate::sat_schedule::INITIAL_REWARD as f64;
        let floor_of = |watts: f64| watts * 0.5 * blocks_per_sat / 3.6e6 * 0.1648;
        let recorded = MINING_COST_FLOOR.0 as f64 / MINING_COST_FLOOR.1 as f64;
        assert!(
            u128::from(LAUNCH_PRICE.0) * u128::from(MINING_COST_FLOOR.1) >= u128::from(MINING_COST_FLOOR.0) * u128::from(LAUNCH_PRICE.1),
            "⛔ the launch price is below the measured cost to mine a SAT"
        );
        assert!((floor_of(47.967) - recorded).abs() / recorded < 0.01, "CALIBRATION: the recorded watts give the recorded floor ({} vs {recorded})", floor_of(47.967));
        let out = std::process::Command::new("ioreg").args(["-rn", "AppleSmartBattery"]).output();
        let watts = out.ok().and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            let at = s.find("\"SystemPowerIn\"=")? + "\"SystemPowerIn\"=".len();
            s[at..].split(|c: char| !c.is_ascii_digit()).next()?.parse::<f64>().ok().map(|mw| mw / 1000.0)
        });
        match watts {
            Some(w) if w > 0.0 => {
                let f = floor_of(w);
                eprintln!("[br15-floor] the reference machine reads {w:.3} W now → ${f:.8} per SAT (recorded ${recorded:.8})");
                assert!(f / recorded < 2.0 && recorded / f < 2.0, "⛔ the floor is off the machine's measured cost by more than ×2: re-measure and record it");
            }
            _ => eprintln!("[br15-floor] this machine has no adapter telemetry: the recorded measurement stands (the calibration above holds)"),
        }
    }
}

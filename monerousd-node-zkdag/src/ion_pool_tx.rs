// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ IONSWAP POOLS — THE OBJECTS (docs/IONSWAP-POOLS-SPEC-20261110.md §13; lane goods, 2026-11-11).
//!
//! User 2026-11-11: "ionswap pools are different from the launch pools and are withdrawable. having users add liquidity
//! thats not withdrawable is funds loss." · "Are we utilizing our dsol layer enough on ionswap?"
//!
//! WHAT A POOL IS ON THE CHAIN. One pool per token against USDm. Its whole state (balances, shares, what the creator is
//! owed, a short ring of past prices) is ONE row, and the chain keeps only a commitment to it: the row is the STORAGE of
//! a leaf of the DSOL contract-state root (`contract_state`, `PegLedger::contract_state_root`), at the contract id
//! [`ion_pool_cid`], under a native program id no deployed code can have ([`ion_pool_code_id`]). So a node holds 32 bytes
//! for every contract and every pool together, the root is journaled, rewound, checkpointed and carried to a joiner with
//! every other ledger word, and nothing here adds a field a rewind could forget (finding A-F31's class).
//!
//! TWO OBJECTS.
//! * [`IonOrderTx`] (`Class::IonOrder`): buy, sell, add liquidity, REMOVE liquidity, or launch a curve. It burns its
//!   input notes by the chain's existing public-amount spend (the asset creation's fee burn for USDm, the SAT bond's
//!   welded asset spend for a token or a share note), bound to this order's own words, and says where its payout goes
//!   (a one-time owner opening, the sealed part of its payout notes, and its owner's own locators). At its fold it
//!   joins the ledger's short list of pending orders. It never
//!   touches the pool's leaf, so any number of orders for one pool ride one block and none races another.
//! * [`IonSettleTx`] (`Class::IonSettle`): the batch. It carries the pool's row before, the row's path in the root, and
//!   the payout notes. ANY node forms it (a producer does, for every pool with pending orders); no committee, no key.
//!   The fold takes EVERY pending order of the pool folded at or before the stated step, recomputes the batch
//!   ([`settle`], the arithmetic of `ion_pool`) and accepts the settlement only if its notes are exactly the ones the
//!   recomputation yields; then it moves the leaf. A settlement cannot leave an order out, pay an order another amount,
//!   or pick which orders of a step clear together.
//!
//! WITHDRAWABLE, BY CONSTRUCTION. A share is an ordinary private note of the pool's own share asset ([`share_tag`]),
//! minted to the provider by the batch that took its deposit. Handing shares back is an order like any other: it needs
//! no one's consent, it is settled by whoever produces the next block, removals leave FIRST in their batch at the
//! balances the batch started with, and the only shares nobody can hand back are the 1,000 units locked at a pool's
//! first deposit (`ion_pool::MINIMUM_SHARES`, Uniswap v2's inflation fix: dust) and a graduated launch curve's (nobody
//! deposited those: they are the token's own supply and its buyers' purchase money).
//!
//! §9.6, THE ORDER DOOR. (1) PoW: the carrying block's and the tx stamp. (2) Proof: one welded public-amount spend per
//! leg (`verify_bond_validity_carrier_with_commit_bytes` / `verify_asset_bond_validity_carrier_bytes`), `out0` bound to
//! THIS order ([`ion_burn_cm`]), and each spent note's membership at the Fold door (`Node::fee_note_membership_refusal`).
//! (3) Value: an order only destroys (its `out0`s) and returns change; it creates nothing. (4) Replay: its legs'
//! nullifiers, refused by the spent set. (5) Bounded: at most two legs; at most [`ION_STEP_ORDERS_MAX`] orders a pool a
//! fold step and [`ION_PENDING_MAX`] pending in all (a refused order burns nothing and is sent again). (6) Parity with
//! the creation's fee burn: every check it runs, per leg. (7) Scale: constant in the bonded set and in height; pending
//! is bounded by the orders in flight. (8) AI resistance: (a) a proof for every unit that enters; a lying prover gains
//! nothing (a leg that proves another amount or another order's burn does not verify), a persuasive message has nothing
//! to ask for.
//! §9.6, THE SETTLEMENT DOOR. (1) PoW: the carrying block's. (2) Proof: none of its own and none needed: every word it
//! carries is recomputed by every node from the ledger's pending orders and the row the path proves; the row is proven
//! against the root (`contract_state::update_root` / `insert_root`). (3) Value: what it pays is `ion_pool::step` of
//! what the orders burned; [`settle`] checks, unit for unit, that what entered equals what the pool kept plus what was
//! paid plus the fee parts, and the ledger's layer word (`PegLedger::ion_usdm_held`) refuses a settlement that would
//! pay out more USDm than the pool layer ever took in (the turnstile: a fault in this arithmetic is bounded by what
//! the layer holds and never reaches a cash note). (4) Replay: the row it carries must BE the pool's leaf under the root,
//! and a row never repeats (its batch number only rises), so a settlement applies at most once; its own bytes' one-time
//! id ([`IonSettleTx::own_nullifiers`]) refuses the same object carried again through the spent set.
//! (5) Bounded: at most `ION_STEP_ORDERS_MAX` orders a step, three notes an order. (6) Parity with the DeFi batch's
//! settlement: the batch is fixed by the fold before it is settled, the settlement is checked whole; the custody
//! quorum is dropped because nothing here is secret. (7) Scale: constant in the bonded set and height. (8) AI
//! resistance: (b) ordinary code every node runs, behind the layer's conservation word; no person, key or machine.
//!
//! WHAT THE CHAIN SHOWS (stated, spec §4 and §8): a pool's two balances, its share count and its price, once a batch,
//! and each order's size. Never who traded, who provides, or what any one person holds: inputs are private notes, a
//! payout goes to a one-time key, shares are private notes. The user asked for pools ranked by liquidity, which is the
//! balances; an order's size being public is this lane's cost until the sealed lane (spec §10 step 6).
//!
//! cons, quantified: an order is about 0.2 MB of carriers (one or two welded spends and their member legs), as a
//! creation's fee burn is; a settlement is about 1.2 KB a payout note plus the row (about 0.8 KB) and its path; a
//! trade completes in the block after the one that carried it (two blocks), not one; a pending order is about 1.4 KB in
//! the ledger until its batch (its sealed shell is 1.1 KB of that), so the pending list is at most about 350 KB; a pool's
//! row must be known to
//! whoever settles it, so a node keeps a CACHE row per pool (about 0.8 KB each, not chain state, refilled from peers
//! and checked against the root).
//!
//! BORROWED: Uniswap v2 (the pool, shares, removal as the provider's own act); Penumbra's swap and its batch (orders
//! of a block clear together at one price; a swap's size is public, its owner is not); Cardano's batchers and CoW's
//! solvers (anyone forms the batch, the chain checks it whole); Ethereum's account trie leaf `H(code, storage)` and
//! its native programs (a contract whose code is the runtime's own); Zcash's turnstile (a layer never pays out more
//! than it took in).
//! DIGITAL-CASH-PRIVACY-REVIEWED: see WHAT THE CHAIN SHOWS; no owner, note or wallet is named by either object.

use crate::asset_tx::CreationFee as BurnLeg;
use crate::contract_state::{contract_leaf, empty_leaf, insert_root, update_root, verify_path, PathWire};
use crate::ion_pool::{curve_step, step, Curve, CurveStep, Order, Pool};
use crate::spend_frontier::{cm_bytes_to_leaf, cm_bytes_to_root, leaf_to_cm_bytes, note_cm_of, Digest4};
use serde::{Deserialize, Serialize};
use usdm_decider::whir_rec_block::{asset_note_cm, wrapped_asset_tag, PROTOCOL_FEE_ATOMIC, USDM_ASSET_TAG};

/// A note's layout, the one every wallet scans (`cm ‖ ct ‖ enc ‖ vt`): the ML-KEM-768 ciphertext's width, and where the
/// 32-byte covered field (the amount, then the asset tag) and the view tag sit.
pub const ION_SHELL_CT_BYTES: usize = 1088;
// PRODUCTION-SCALE-REVIEWED: a byte offset inside one note's fixed layout (its 32-byte commitment comes first): the
// production layout itself, not a count of blocks, notes or covers.
const NOTE_CT_OFF: usize = 32;
const NOTE_CT_END: usize = NOTE_CT_OFF + ION_SHELL_CT_BYTES;
const NOTE_ENC_END: usize = NOTE_CT_END + 32;


/// Give USDm, take the token.
pub const ION_BUY: u8 = 0;
/// Give the token, take USDm.
pub const ION_SELL: u8 = 1;
/// Bring both for shares.
pub const ION_ADD: u8 = 2;
/// Hand shares back for both.
pub const ION_REMOVE: u8 = 3;
/// Put a token's supply on a launch curve (only where no pool exists yet).
pub const ION_LAUNCH: u8 = 4;
/// The token's CREATOR takes the fee parts the pool holds for it (`IonRow::owed_creator_x`, `owed_creator_y`). The order
/// burns a little USDm of its own (any amount above zero; a wallet sends one atomic unit), which gives it a nullifier,
/// the flat network fee and a place in the pending list like every other order, and gets that amount back with what it
/// is owed. It carries [`IonCreatorAuth`]: the key the token's id binds signed THIS order (so its payout notes).
pub const ION_CLAIM: u8 = 5;
/// ⭐ LOCK (spec §14, user 2026-11-12: "the optional ability to lock their liquidity … with the ability to select the
/// amount of time/unlock date"). Hands back `shares` of this pool's PLAIN shares (`lock_from == 0`) or of its shares
/// locked until week `lock_from` (an EXTENSION: `lock_until > lock_from`, so a lock is never shortened), and is paid the
/// same number of shares LOCKED until week `lock_until` ([`locked_share_tag`]). Settled beside the batch: it trades
/// nothing and prices nothing, and a locked share earns and is worth what a plain share is.
pub const ION_LOCK: u8 = 6;
/// UNLOCK: from week `lock_from` on, hands back shares locked until it and is paid plain shares (a provider who stays).
pub const ION_UNLOCK: u8 = 7;
/// The furthest unlock date a lock may name, in weeks from the settling block's week: four years.
pub const ION_LOCK_WEEKS_MAX: u32 = 208;
/// The most unlock dates one pool's row may list at once (78 years of weekly entries; spec §14.2): a lock that would pass
/// it is handed back.
// PRODUCTION-SCALE-REVIEWED: a bound on one row's table, production's own figure; no test runs at a reduced value of it.
pub const ION_LOCK_ENTRIES_MAX: usize = 4_096;
/// A lock week is seven days, and week 0 begins on Monday 5 January 1970, 00:00 UTC (the epoch was a Thursday).
const LOCK_WEEK_SECS: u64 = 604_800;
const LOCK_WEEK_ZERO_SECS: u64 = 345_600;

/// The lock week a chain clock (seconds) stands in: every unlock date is the Monday 00:00 UTC that week `w` begins on.
#[must_use]
pub fn lock_week_of(secs: u64) -> u32 {
    u32::try_from(secs.saturating_sub(LOCK_WEEK_ZERO_SECS) / LOCK_WEEK_SECS).unwrap_or(u32::MAX)
}

/// The chain clock (seconds) week `w` begins at: from this instant on, shares locked until `w` may leave the pool.
#[must_use]
pub fn lock_week_start_secs(week: u32) -> u64 {
    LOCK_WEEK_ZERO_SECS + u64::from(week) * LOCK_WEEK_SECS
}

/// The asset id of a pool's shares locked until week `week` (never a created asset's id, nor a pool's plain shares').
/// A PLAIN HASH of the pool and the week, on purpose (spec §14.2): a tag a node could invert by trying weeks would let a
/// grinder of asset ids aim at pools × weeks² targets instead of one.
#[must_use]
pub fn locked_share_asset_id(cid: &[u8; 32], week: u32) -> [u8; 32] {
    let mut pre = [0u8; 36];
    pre[..32].copy_from_slice(cid);
    pre[32..].copy_from_slice(&week.to_le_bytes());
    blake3::derive_key("MonerousD ionswap pool locked share v1", &pre)
}

/// The note tag of a pool's shares locked until week `week`.
#[must_use]
pub fn locked_share_tag(cid: &[u8; 32], week: u32) -> [u64; 3] {
    wrapped_asset_tag(&locked_share_asset_id(cid, week))
}

/// ⛔ EVERY ORDER PAYS THE FLAT NETWORK FEE (found reading the real-node check against this file, before any of it ran).
/// A USDm leg's carrier welds the fee (`PROTOCOL_FEE_ATOMIC`); a token or share leg welds none. A sale, a removal and a
/// launch brought no USDm, so they paid nothing: anyone holding one unit of a token could fill a pool's
/// [`ION_STEP_ORDERS_MAX`] orders in every step, and the ledger's [`ION_PENDING_MAX`], for free, with orders whose
/// floor is never met and which hand the unit back to be used again. So an order that brings no USDm for the pool
/// brings this one atomic unit of it, through a USDm leg that pays the network fee like every other spend. The unit
/// goes to the token creator's fee part (`IonRow::owed_creator_y`): it touches neither the pool's balances nor whether
/// the pool was ever opened (a unit left in an unopened pool's balance would have blocked a later launch).
/// cons: a sale, a removal and a launch cost the network fee and one atomic unit (0.00000001 USDm), and carry one more
/// spend (their wallet proves a second leg; the person needs that much USDm to sell or to leave a pool).
pub const ION_FEE_UNIT: u64 = 1;

/// The most orders one pool takes in one fold step: with three notes an order at most, a step's batch fits the notes a
/// block carries. An order past it is refused at its fold with nothing burned, and its wallet sends it again.
pub const ION_STEP_ORDERS_MAX: usize = 32;
/// The most orders pending in the ledger at once, over every pool (orders in flight; a settlement removes them).
pub const ION_PENDING_MAX: usize = 256;
/// The most pools' settlements ONE fold step writes (`IonSettleTx::brought_forward`): the first as carried and the rest
/// with their paths brought forward over the ones before them. A bound on a step's WORK (under 126,480 hashes), not on
/// what a pool may settle: a settlement past it is refused on the item and formed again next step, and at one a step
/// (what stood before 2026-11-11) a pool among a thousand busy ones waited a thousand steps.
pub const ION_STEP_SETTLES_MAX: usize = 32;
/// One pool's leaf as a fold step wrote it: `(the pool's contract id, the new leaf, the path it was written through)`.
/// O1-FOOTPRINT-REVIEWED: 256 digests a write, at most `ION_STEP_SETTLES_MAX` of them, for the length of one fold step.
pub type IonStepWrite = ([u8; 32], Digest4, Vec<Digest4>);
/// How many past prices a row carries (one a batch that traded).
pub const ION_PRICE_RING: usize = 32;
/// A price is base atoms for one token atom, times this.
pub const ION_PRICE_SCALE: u128 = 1_000_000_000_000;
/// The one-time id kind of a settlement on the nullifier lane (`peg::one_time_id_nf`).
pub const ONE_TIME_ION_SETTLE: u8 = 11;

/// The native program id every pool's leaf names. No deployed contract can have it: a deploy's code id is the hash of
/// its code, and a pool's contract id ([`ion_pool_cid`]) is not one a deploy can be given (`dsol_deploy_tx::dsol_cid`
/// derives a deploy's from its fee note), so the call door, which verifies a proof against code hashing to the leaf's
/// code id, can never move a pool's leaf. Only the settlement door does.
#[must_use]
pub fn ion_pool_code_id() -> [u8; 32] {
    blake3::derive_key("MonerousD native program v1", b"ionswap pool")
}

/// The contract id of a token's pool: where its leaf sits in the contract-state root.
#[must_use]
pub fn ion_pool_cid(token: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(33);
    pre.extend_from_slice(token);
    pre.push(0); // the base asset: USDm
    blake3::derive_key("MonerousD ionswap pool cid v1", &pre)
}

/// The asset id of a pool's shares (never a created asset's id: a created id is `derived_id` of a descriptor).
#[must_use]
pub fn share_asset_id(cid: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("MonerousD ionswap pool share v1", cid)
}

/// The note tag of a pool's shares.
#[must_use]
pub fn share_tag(cid: &[u8; 32]) -> [u64; 3] {
    wrapped_asset_tag(&share_asset_id(cid))
}

/// The manifest digest inside every pool's leaf: no publisher fee, no publisher, no deployer (nothing can update it).
#[must_use]
pub fn ion_manifest_digest() -> Digest4 {
    crate::dsol_deploy_tx::ContractManifest {
        code_id: ion_pool_code_id(),
        publisher_fee_le: [0u8; 8],
        publisher_spk: [0u8; 32],
        deployer_id: [0u8; 32],
        kc_commit: [0u8; 32],
        height_class: 0,
    }
    .digest()
}

/// What a pool is: a launch curve, or a pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IonState {
    Curve(Curve),
    Pool(Pool),
}

/// ⭐ A POOL'S ROW: the storage of its leaf. Everything a batch reads and writes, and nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IonRow {
    pub token: [u8; 32],
    pub state: IonState,
    /// Every order of this pool folded at or before this fold step is settled.
    pub settled_through: u64,
    /// How many batches have settled (the next settlement's number).
    pub batch: u64,
    /// The creator's part of the fees, not yet claimed, in the token and in USDm.
    pub owed_creator_x: u128,
    pub owed_creator_y: u128,
    /// `(chain clock, seconds; price × ION_PRICE_SCALE)`, oldest first, at most [`ION_PRICE_RING`].
    /// O1-FOOTPRINT-REVIEWED: bounded by [`ION_PRICE_RING`]; [`IonRow::well_formed`] refuses a longer ring.
    pub prices: Vec<(u64, u64)>,
    /// ⭐ THE LIQUIDITY LOCKS (spec §14): `(unlock week, shares locked until it)`, ascending, every count above zero, the
    /// sum never above the shares a provider can hold (`shares − locked`). Exact: a LOCK adds, a removal or an unlock of
    /// locked shares subtracts, an entry at zero is deleted. An entry stays past its week while its shares are
    /// outstanding, so every node can name a locked share for as long as it exists ([`locked_share_tag`] is a plain hash).
    /// O1-FOOTPRINT-REVIEWED: at most [`ION_LOCK_ENTRIES_MAX`] (`well_formed`); at most [`ION_LOCK_WEEKS_MAX`] future
    /// entries, and one new entry a pool a week, each opened by an order that paid the network fee (spec §14.2).
    pub locks: Vec<(u32, u128)>,
    /// The token's units a launch curve BURNED when it became this pool (`ion_pool::CurveStep::Graduated`): destroyed, so
    /// no wallet holds them. What a pool's tokenomics subtract from the supply (spec §14.3); 0 for a pool no curve made.
    pub burned_x: u128,
}

impl IonRow {
    /// The row a pool has before anything happened to it.
    #[must_use]
    pub fn new(token: [u8; 32]) -> IonRow {
        IonRow { token, state: IonState::Pool(Pool::default()), settled_through: 0, batch: 0, owed_creator_x: 0, owed_creator_y: 0, prices: Vec::new(), locks: Vec::new(), burned_x: 0 }
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    #[must_use]
    pub fn well_formed(&self) -> bool {
        self.prices.len() <= ION_PRICE_RING && self.token != [0u8; 32] && self.locks_well_formed()
    }

    /// The lock table's own rule: bounded, ascending, no empty entry, no week 0 (`lock_from == 0` means plain shares), and
    /// never more shares locked than a provider can hold (a curve holds none).
    fn locks_well_formed(&self) -> bool {
        if self.locks.len() > ION_LOCK_ENTRIES_MAX || self.locks.iter().any(|(w, s)| *w == 0 || *s == 0) || self.locks.windows(2).any(|p| p[0].0 >= p[1].0) {
            return false;
        }
        let Some(total) = self.locks.iter().try_fold(0u128, |a, (_, s)| a.checked_add(*s)) else {
            return false;
        };
        match self.state {
            IonState::Pool(p) => p.shares.checked_sub(p.locked).is_some_and(|holdable| total <= holdable),
            IonState::Curve(_) => total == 0,
        }
    }

    /// Shares locked until week `week` (0 when none are).
    #[must_use]
    pub fn locked_until(&self, week: u32) -> u128 {
        self.locks.iter().find(|(w, _)| *w == week).map_or(0, |(_, s)| *s)
    }

    /// Add `shares` locked until `week` (`None`: an overflow, or a new entry past [`ION_LOCK_ENTRIES_MAX`]).
    fn lock_add(&mut self, week: u32, shares: u128) -> Option<()> {
        match self.locks.binary_search_by_key(&week, |(w, _)| *w) {
            Ok(i) => self.locks[i].1 = self.locks[i].1.checked_add(shares)?,
            Err(i) => {
                if self.locks.len() >= ION_LOCK_ENTRIES_MAX {
                    return None;
                }
                self.locks.insert(i, (week, shares));
            }
        }
        Some(())
    }

    /// Take `shares` locked until `week` off the table, deleting an entry that reaches zero (`None`: fewer are locked there).
    fn lock_sub(&mut self, week: u32, shares: u128) -> Option<()> {
        let i = self.locks.binary_search_by_key(&week, |(w, _)| *w).ok()?;
        let left = self.locks[i].1.checked_sub(shares)?;
        if left == 0 {
            self.locks.remove(i);
        } else {
            self.locks[i].1 = left;
        }
        Some(())
    }

    /// ⭐ WHAT CANNOT LEAVE THE POOL AT WEEK `now` (what the green or orange lock on a page reads, spec §14.3):
    /// `(shares nobody can take out now, all shares)`. Nobody can take out the shares locked until a later week, nor the
    /// shares no provider holds (the first deposit's minimum, a graduated curve's whole liquidity). A launch curve has
    /// no shares at all and nobody can take its liquidity out: it reads `(1, 1)`.
    #[must_use]
    pub fn unremovable_now(&self, now: u32) -> (u128, u128) {
        match self.state {
            IonState::Curve(_) => (1, 1),
            IonState::Pool(p) => {
                let future: u128 = self.locks.iter().filter(|(w, _)| *w > now).map(|(_, s)| *s).sum();
                (p.locked.saturating_add(future).min(p.shares), p.shares)
            }
        }
    }

    /// The leaf this row occupies: `contract_leaf(native program, manifest, H(row))`.
    #[must_use]
    pub fn leaf(&self) -> Digest4 {
        contract_leaf(&ion_pool_code_id(), ion_manifest_digest(), cm_bytes_to_leaf(blake3::hash(&self.encode()).as_bytes()))
    }

    /// `(token balance, USDm really in it)`.
    #[must_use]
    pub fn balances(&self) -> (u128, u128) {
        match self.state {
            IonState::Curve(c) => (c.x, c.real),
            IonState::Pool(p) => (p.x, p.y),
        }
    }

    /// The price now, × [`ION_PRICE_SCALE`] (a curve prices against its virtual base too); `None` with an empty side.
    #[must_use]
    pub fn price(&self) -> Option<u64> {
        let (x, y) = match self.state {
            IonState::Curve(c) => (c.x, c.real.checked_add(c.v)?),
            IonState::Pool(p) => (p.x, p.y),
        };
        if x == 0 || y == 0 {
            return None;
        }
        Some(u64::try_from(y.checked_mul(ION_PRICE_SCALE)? / x).unwrap_or(u64::MAX))
    }

    /// What a pools list ranks by: the USDm side, twice (both sides are worth the same at the pool's own price); a
    /// curve's real USDm.
    #[must_use]
    pub fn liquidity_usdm(&self) -> u128 {
        match self.state {
            IonState::Curve(c) => c.real,
            IonState::Pool(p) => p.y.saturating_mul(2),
        }
    }
}

/// An order's words: everything but its spends. What the ledger keeps while the order is pending.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IonOrderCore {
    pub kind: u8,
    /// Token atoms the order brings (sell, add, launch).
    pub x: u64,
    /// USDm atoms the order brings (buy, add).
    pub y: u64,
    /// Share units the order hands back (remove).
    pub shares: u64,
    /// The least a buy or a sell accepts; below it the order is returned whole.
    pub min_out: u64,
    /// The opening `P(spk, seed)` every payout note of this order is owned by (a canonical digest). Fresh for every order:
    /// the seed is the shell's own shared secret's, so two orders of one wallet share nothing an observer can see.
    pub owner_opening: [u8; 32],
    /// ⭐ THE PAYOUT NOTES' SEALED PART, made by the owner's wallet before the amounts exist: the ML-KEM-768 ciphertext to
    /// the owner's own scan key (its shared secret gives the notes' seed), the 32-byte keystream that covers a note's
    /// amount and asset tag, and the view tag. The batch completes each payout note from these and the amount it pays
    /// ([`ion_payout_note`]), so a payout is byte for byte a note the owner's ordinary scan finds and opens, with no rule
    /// of its own in any wallet, and a restore from the wallet's seed opens it like any note. The keystream is public
    /// here because what it covers (an amount, a tag) is public in this lane.
    /// WHY IT RIDES THE ORDER AND STAYS IN THE PENDING ENTRY (about 1.1 KB of it): a payout must be formable by any node
    /// from the ledger alone. Kept in a cache instead, a network that restarted between an order's fold and its batch
    /// would hold a burned input and no way to seal its payout.
    /// O1-FOOTPRINT-REVIEWED: exactly [`ION_SHELL_CT_BYTES`]; `decode` refuses any other width.
    pub shell_ct: Vec<u8>,
    pub shell_pad: [u8; 32],
    pub shell_vt: u8,
    /// The owner's own locators its payout notes are filed at, one for each asset a payout can be in (the token, USDm,
    /// the pool's shares, in that order), each as the 32 bytes a locator clue is made of (`locator ‖ salt ‖ hint`,
    /// 16 + 8 + 8). One note a locator, as every self-note of a wallet has, so a payout is found where a change note is.
    pub locators: [[u8; 32]; 3],
    /// ⭐ A SWAP OF ONE TOKEN FOR ANOTHER, IN ONE ORDER (a sale only; all zero on every other order): the token to BUY
    /// with this sale's USDm proceeds. The sale settles in its own pool like any sale; instead of a USDm payout note,
    /// its proceeds become a pending BUY in `hop`'s pool, paid by that pool's next batch to this order's own payout
    /// notes ([`IonSettled::forwards`]). Each leg has its own floor: `min_out` is the least USDm the sale accepts (below
    /// it the tokens come back whole and nothing else happens) and `hop_min_out` the least of the second token the buy
    /// accepts (below it the USDm comes back as a note: the person then holds USDm, never less than the first floor).
    /// BORROWED: a routed swap through a common pair (Uniswap's router: token → base → token); here the two hops are
    /// two batches, each at its pool's one price for the step, so neither can be sandwiched.
    pub hop: [u8; 32],
    /// The least of `hop`'s token the swap accepts (0 with no hop).
    pub hop_min_out: u64,
    /// ⭐ LOCKS (spec §14; zero on every order but a REMOVE, a LOCK and an UNLOCK: one order, one encoding). The unlock
    /// week of the shares this order hands back (0: plain shares). A REMOVE of locked shares is handed back whole until
    /// the settling block's week reaches it.
    pub lock_from: u32,
    /// A LOCK's new unlock week (0 on every other order).
    pub lock_until: u32,
}

/// The clue a note at `locator` is filed under: a locator clue, the same bytes the owner's wallet derives for itself
/// (`oli::tag_clue_bytes_v2` of the locator, its salt and its hint).
#[must_use]
pub fn ion_locator_clue(locator: &[u8; 32]) -> Vec<u8> {
    let (loc, rest) = locator.split_at(crate::oli::LOC_BYTES);
    let loc: [u8; crate::oli::LOC_BYTES] = loc.try_into().unwrap_or([0u8; crate::oli::LOC_BYTES]);
    let salt: [u8; 8] = rest[..8].try_into().unwrap_or([0u8; 8]);
    let hint: [u8; 8] = rest[8..].try_into().unwrap_or([0u8; 8]);
    crate::oli::tag_clue_bytes_v2(&loc, &salt, &hint)
}

impl IonOrderCore {
    /// The locator a payout in `asset` is filed at.
    #[must_use]
    pub fn locator_of(&self, asset: IonAsset) -> [u8; 32] {
        self.locators[match asset {
            IonAsset::Token => 0,
            IonAsset::Usdm => 1,
            // an order pays at most one share note, plain or locked: they share the third locator
            IonAsset::Share | IonAsset::Locked(_) => 2,
        }]
    }

    /// The share asset this order hands back: plain shares, or shares locked until `lock_from`.
    #[must_use]
    pub fn shares_in(&self) -> IonAsset {
        if self.lock_from == 0 {
            IonAsset::Share
        } else {
            IonAsset::Locked(self.lock_from)
        }
    }
}

/// What a leg burns, or a payout pays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IonAsset {
    Token,
    Usdm,
    Share,
    /// The pool's shares locked until this week ([`locked_share_tag`]).
    Locked(u32),
}

impl IonOrderCore {
    /// The legs this kind of order must carry, in order: what each burns and how much. `None` for a kind that does not
    /// exist or words that are not this kind's (one order, one encoding).
    #[must_use]
    pub fn legs(&self) -> Option<Vec<(IonAsset, u64)>> {
        let none = |a: u64, b: u64| a == 0 && b == 0;
        // only a sale may name a second pool, and a floor for it only with one (one order, one encoding)
        let hops = self.hop != [0u8; 32];
        if (hops && self.kind != ION_SELL) || (!hops && self.hop_min_out != 0) {
            return None;
        }
        // only a removal, a lock and an unlock name a lock week (one order, one encoding)
        if (self.lock_from != 0 || self.lock_until != 0) && !matches!(self.kind, ION_REMOVE | ION_LOCK | ION_UNLOCK) {
            return None;
        }
        // a share order: shares, nothing else, no floor; the network fee through one USDm unit
        let share_order = self.shares > 0 && none(self.x, self.y) && self.min_out == 0;
        let shares = (self.shares_in(), self.shares);
        match self.kind {
            ION_BUY if self.y > 0 && none(self.x, self.shares) => Some(vec![(IonAsset::Usdm, self.y)]),
            ION_SELL if self.x > 0 && none(self.y, self.shares) => Some(vec![(IonAsset::Token, self.x), (IonAsset::Usdm, ION_FEE_UNIT)]),
            ION_ADD if self.x > 0 && self.y > 0 && none(self.shares, self.min_out) => Some(vec![(IonAsset::Token, self.x), (IonAsset::Usdm, self.y)]),
            ION_REMOVE if share_order && self.lock_until == 0 => Some(vec![shares, (IonAsset::Usdm, ION_FEE_UNIT)]),
            ION_LAUNCH if self.x > 0 && none(self.y, self.shares) && self.min_out == 0 => Some(vec![(IonAsset::Token, self.x), (IonAsset::Usdm, ION_FEE_UNIT)]),
            ION_CLAIM if self.y > 0 && none(self.x, self.shares) && self.min_out == 0 => Some(vec![(IonAsset::Usdm, self.y)]),
            // a lock only lengthens: a new week past the one the shares stand at (past plain shares' 0)
            ION_LOCK if share_order && self.lock_until > self.lock_from => Some(vec![shares, (IonAsset::Usdm, ION_FEE_UNIT)]),
            ION_UNLOCK if share_order && self.lock_from > 0 && self.lock_until == 0 => Some(vec![shares, (IonAsset::Usdm, ION_FEE_UNIT)]),
            _ => None,
        }
    }

    /// The USDm unit this order brings ONLY to pay the network fee ([`ION_FEE_UNIT`]): a sale, a removal, a launch, a
    /// lock and an unlock.
    #[must_use]
    pub fn fee_unit(&self) -> u64 {
        match self.kind {
            ION_SELL | ION_REMOVE | ION_LAUNCH | ION_LOCK | ION_UNLOCK => ION_FEE_UNIT,
            _ => 0,
        }
    }

    /// The batch order this is (a launch is not one: [`settle`] decides it before the batch runs).
    fn as_order(&self) -> Order {
        match self.kind {
            ION_BUY => Order::Buy { amount: u128::from(self.y), min_out: u128::from(self.min_out) },
            ION_SELL => Order::Sell { amount: u128::from(self.x), min_out: u128::from(self.min_out) },
            ION_ADD => Order::Add { x: u128::from(self.x), y: u128::from(self.y) },
            ION_REMOVE => Order::Remove { shares: u128::from(self.shares) },
            _ => Order::Add { x: 0, y: 0 }, // a launch: nothing to the batch (an addition of nothing is returned as nothing)
        }
    }
}

/// The note tag of an asset in a token's pool.
#[must_use]
pub fn ion_tag(token: &[u8; 32], asset: IonAsset) -> [u64; 3] {
    match asset {
        IonAsset::Token => wrapped_asset_tag(token),
        IonAsset::Usdm => USDM_ASSET_TAG,
        IonAsset::Share => share_tag(&ion_pool_cid(token)),
        IonAsset::Locked(week) => locked_share_tag(&ion_pool_cid(token), week),
    }
}

/// What an order's burns are bound to: the pool and every word of the order.
#[must_use]
pub fn ion_order_bind(token: &[u8; 32], core: &IonOrderCore) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + 1_400);
    pre.extend_from_slice(token);
    pre.extend_from_slice(&postcard::to_allocvec(core).unwrap_or_default());
    blake3::derive_key("MonerousD ionswap order v1", &pre)
}

/// The commitment leg `k` of an order MUST destroy: `amount` of the leg's asset, to an opening that is a public
/// function of the order, so every node recomputes it, no other order can use the burn, and nobody can spend it.
#[must_use]
pub fn ion_burn_cm(bind: &[u8; 32], k: usize, amount: u64, tag: [u64; 3]) -> Digest4 {
    asset_note_cm(amount, tag, ion_burn_opening(bind, k))
}

/// The opening of leg `k`'s destroyed output: a public function of the order (what the spender's proof names as `out0`'s
/// opening). No key opens it: it is a hash, not `P(spk, seed)` of any key pair anyone holds.
#[must_use]
pub fn ion_burn_opening(bind: &[u8; 32], k: usize) -> Digest4 {
    let mut pre = [0u8; 33];
    pre[..32].copy_from_slice(bind);
    pre[32] = k as u8;
    cm_bytes_to_leaf(&blake3::derive_key("MonerousD ionswap order burn v1", &pre))
}

/// The largest creator key or signature a claim carries (ML-DSA-65: a 1,952-byte key, a 3,309-byte signature).
// PRODUCTION-SCALE-REVIEWED: a BYTE bound on one key or one signature field of one order (4,096 bytes, production's
// own figure), never a count of blocks, notes or cover slots; no test runs at a reduced value of it.
pub const ION_CREATOR_AUTH_BYTES_MAX: usize = 4096;

/// What a creator's signature covers: the claim's domain, the token and the order's own bind (its kind, amounts, payout
/// opening, sealed shell and locators), so a signature authorises exactly one order's payout and no other.
#[must_use]
pub fn ion_claim_msg(token: &[u8; 32], bind: &[u8; 32]) -> Vec<u8> {
    let mut m = b"MUSD/ion/creator-claim/v1".to_vec();
    m.extend_from_slice(token);
    m.extend_from_slice(bind);
    m
}

/// ⭐ "I CREATED THIS TOKEN, AND I PLACE THIS ORDER" (an [`ION_CLAIM`] order carries one, no other kind may).
/// The token's id binds its creator's key (`asset_tx::asset_id_of_creator`), so the descriptor words and the key
/// reproduce the id or they are not the creator's; the signature is over [`ion_claim_msg`] of the order's own bind.
/// Self-contained: every node answers from these bytes, no registry is read (the mint's `creator_authorised` shape).
/// AI RESISTANT: (a) a check every node makes (a hash equality and an ML-DSA-65 signature); a lying sender needs a key
/// it does not hold.
/// DIGITAL-CASH-PRIVACY-REVIEWED: a token's creator key and descriptor are already public on its creation; the claim
/// says its creator collected, and the amounts are the pool's own public fee parts (the DeFi layer's stated cost).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IonCreatorAuth {
    pub kind: crate::asset_tx::AssetKind,
    pub symbol: String,
    pub name: String,
    pub logo: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: at most [`ION_CREATOR_AUTH_BYTES_MAX`] (`IonOrderTx::decode`); released with the transaction.
    pub pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: at most [`ION_CREATOR_AUTH_BYTES_MAX`] (`IonOrderTx::decode`); released with the transaction.
    pub sig: Vec<u8>,
}

impl IonCreatorAuth {
    /// Is the key the creator of `token`, and did it sign the order `bind` names?
    #[must_use]
    pub fn authorises(&self, token: &[u8; 32], bind: &[u8; 32], v: &dyn crate::pqauth::PqVerifier) -> bool {
        crate::asset_tx::asset_id_of_creator(self.kind, &self.symbol, &self.name, self.logo, &self.pubkey) == *token
            && v.verify(&self.pubkey, &ion_claim_msg(token, bind), &self.sig)
    }
}

/// ⭐ AN ORDER (`Class::IonOrder`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IonOrderTx {
    pub token: [u8; 32],
    pub core: IonOrderCore,
    /// One public-amount spend per asset the order brings (the asset creation's fee-burn shape).
    /// O1-FOOTPRINT-REVIEWED: at most two (`decode` refuses another count); released with the transaction.
    pub legs: Vec<BurnLeg>,
    /// The creator's word, on an [`ION_CLAIM`] order and on no other.
    pub creator: Option<IonCreatorAuth>,
}

impl IonOrderTx {
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::IonOrder, &self.encode())
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Refuses rather than guesses: the words are one kind's, the legs are that kind's count, and every digest came
    /// from a prover.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<IonOrderTx> {
        let t: IonOrderTx = crate::chain_object::decode_exact(bytes)?;
        if t.token == [0u8; 32] {
            return None;
        }
        cm_bytes_to_root(&t.core.owner_opening)?; // an opening that is no canonical digest came from no wallet
        // three payouts of one order never share a locator (one note a locator)
        let l = &t.core.locators;
        if l[0] == l[1] || l[0] == l[2] || l[1] == l[2] {
            return None;
        }
        if t.core.shell_ct.len() != ION_SHELL_CT_BYTES || t.core.legs()?.len() != t.legs.len() {
            return None;
        }
        if t.core.hop == t.token {
            return None; // a swap's second pool is another pool
        }
        // a claim carries its creator's word and no other order does (one order, one encoding)
        if (t.core.kind == ION_CLAIM) != t.creator.is_some() {
            return None;
        }
        if let Some(c) = &t.creator {
            let fits = |b: &Vec<u8>| !b.is_empty() && b.len() <= ION_CREATOR_AUTH_BYTES_MAX;
            if c.symbol.trim().is_empty() || c.symbol.len() > 32 || c.name.len() > 128 || !fits(&c.pubkey) || !fits(&c.sig) {
                return None;
            }
        }
        for f in &t.legs {
            if f.carrier.is_empty() || f.membership_carrier.is_empty() || f.membership_tip.is_empty() {
                return None;
            }
            if f.change_clue.is_empty() || f.change_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
                return None;
            }
            if f.change_note.len() != crate::cover::PQ_NOTE_BYTES && f.change_note.len() != 64 {
                return None;
            }
            note_cm_of(&f.change_note)?;
            cm_bytes_to_root(&f.nullifier)?;
            cm_bytes_to_root(&f.leaf_commit)?;
        }
        if t.legs.len() == 2 && t.legs[0].nullifier == t.legs[1].nullifier {
            return None; // one note cannot pay both sides
        }
        Some(t)
    }

    /// The order's id: its first leg's nullifier (unique on the chain: the spent set refuses a second use).
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        self.legs.first().map_or([0u8; 32], |f| f.nullifier)
    }

    /// Does every leg prove: one note of the leg's asset is spent, `out0` destroys exactly the order's stated amount
    /// into THIS order's burn commitment, and `out1` is the change (a USDm leg pays the flat network fee on top)?
    #[must_use]
    pub fn legs_verify(&self) -> bool {
        let Some(want) = self.core.legs() else {
            return false;
        };
        if want.len() != self.legs.len() {
            return false;
        }
        let bind = ion_order_bind(&self.token, &self.core);
        want.iter().zip(&self.legs).enumerate().all(|(k, ((asset, amount), f))| {
            let (Some(nf), Some(lc), Some(change)) = (cm_bytes_to_root(&f.nullifier), cm_bytes_to_root(&f.leaf_commit), note_cm_of(&f.change_note)) else {
                return false;
            };
            let tag = ion_tag(&self.token, *asset);
            let out0 = ion_burn_cm(&bind, k, *amount, tag);
            match asset {
                IonAsset::Usdm => usdm_decider::verify_bond_validity_carrier_with_commit_bytes(&f.carrier, out0, change, nf, *amount, lc, PROTOCOL_FEE_ATOMIC),
                _ => usdm_decider::whir_rec_block::verify_asset_bond_validity_carrier_bytes(&f.carrier, out0, change, nf, lc, *amount, tag),
            }
        })
    }

    /// A CLAIM is its token's creator's: the key the token's id binds signed this order. Every other kind carries no
    /// such word and needs none (`true`). Judged from the object's own bytes, at the gossip door and again at the fold.
    #[must_use]
    pub fn creator_verifies(&self, v: &dyn crate::pqauth::PqVerifier) -> bool {
        match (&self.creator, self.core.kind == ION_CLAIM) {
            (Some(c), true) => c.authorises(&self.token, &ion_order_bind(&self.token, &self.core), v),
            (None, false) => true,
            _ => false,
        }
    }

    /// The object's own lane tags: its legs' nullifiers.
    #[must_use]
    pub fn own_nullifiers(&self) -> Vec<[u8; 32]> {
        self.legs.iter().map(|f| f.nullifier).collect()
    }

    /// How much USDm the order burns into the pool layer (the layer word's credit when the order applies).
    #[must_use]
    pub fn usdm_in(&self) -> u64 {
        match self.core.kind {
            ION_BUY | ION_ADD | ION_CLAIM => self.core.y,
            _ => self.core.fee_unit(),
        }
    }

    /// Whether the order pays the flat network fee (a USDm leg's carrier welds it).
    #[must_use]
    pub fn pays_network_fee(&self) -> bool {
        self.usdm_in() > 0
    }
}

/// An order the fold applied, waiting for its batch (ledger state; a settlement removes it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IonPending {
    pub token: [u8; 32],
    /// The fold step the order applied at.
    pub step: u64,
    /// The order's id ([`IonOrderTx::id`]): what its payout notes' seeds derive from.
    pub id: [u8; 32],
    pub core: IonOrderCore,
}

/// One payout note of a settled order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IonPayout {
    /// Which pending order (its index in the batch) it pays.
    pub order: usize,
    pub asset: IonAsset,
    pub amount: u64,
    /// The note's commitment: `asset_note_cm(amount, the asset's tag, the order's owner opening)`.
    pub cm: Digest4,
}

/// ⭐ A PAYOUT NOTE'S BYTES, completed from its order's sealed shell: `cm ‖ ct ‖ enc ‖ vt`, with `enc` the shell's
/// keystream over the amount (8 little-endian bytes) and the asset tag (three little-endian limbs). This is the one
/// note layout (`faucet::seal_note_with_opening`, the wallet's `note_from_encaps`): a wallet's scan decapsulates `ct`,
/// reads the amount and the tag back through the same keystream, and recomputes `cm` under its own key.
#[must_use]
pub fn ion_payout_note(core: &IonOrderCore, p: &IonPayout, tag: [u64; 3]) -> Vec<u8> {
    let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    n[..NOTE_CT_OFF].copy_from_slice(&leaf_to_cm_bytes(p.cm));
    if core.shell_ct.len() == ION_SHELL_CT_BYTES {
        n[NOTE_CT_OFF..NOTE_CT_END].copy_from_slice(&core.shell_ct);
    }
    let mut enc = core.shell_pad;
    for (i, b) in p.amount.to_le_bytes().iter().enumerate() {
        enc[i] ^= *b;
    }
    for (i, limb) in tag.iter().enumerate() {
        for (j, b) in limb.to_le_bytes().iter().enumerate() {
            enc[8 + i * 8 + j] ^= *b;
        }
    }
    n[NOTE_CT_END..NOTE_ENC_END].copy_from_slice(&enc);
    n[NOTE_ENC_END] = core.shell_vt;
    n
}

/// What a batch did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IonSettled {
    pub row: IonRow,
    /// The payout notes, in the batch's order, each order's token note first, then its USDm note, then its shares.
    pub payouts: Vec<IonPayout>,
    /// The USDm the payouts carry out of the pool layer.
    pub usdm_paid: u64,
    /// The USDm part of the fees that is the protocol's (and, until a pool program has a publisher, the publisher's):
    /// credited to the chain's fee pools, and so also out of the pool layer.
    pub usdm_fees: u64,
    /// ⭐ THE SECOND LEGS OF THIS BATCH'S SWAPS ([`IonOrderCore::hop`]): for every sale that named a second pool and
    /// was filled, a pending BUY in that pool of exactly the USDm the sale earned, with the sale's own payout words.
    /// The USDm never leaves the pool layer (it is not in `usdm_paid`); the ledger appends these to its pending orders
    /// when the settlement applies (`PegLedger::ion_apply_settlement` sets each one's step).
    /// O1-FOOTPRINT-REVIEWED: at most one a settled order of a step ([`ION_STEP_ORDERS_MAX`]); each takes the pending
    /// slot its own sale just left.
    pub forwards: Vec<IonPending>,
    /// ⛔ DOES THE TREE HOLD THIS POOL'S ROW AFTER THE BATCH? `true` for every pool that had a row, and for a batch that
    /// OPENED one (a first deposit that minted shares, or a launch that opened a curve). `false` when the pool had no
    /// row and the batch opened nothing: every order was handed back whole and NOTHING is written to the tree.
    ///
    /// WHY (found reading this file against NO GROWTH, 2026-11-11, before anything ran): the first shape wrote a row
    /// for every settled pool. A buy into a 32-byte id that names no pool was handed back, and left an empty row every
    /// node keeps for good: about a thousand rows, a megabyte on every node and every phone, for each dollar of network
    /// fees. Now a row exists only where a pool was opened, and opening takes notes of the token itself, which exist
    /// only for an asset whose creation was paid for: at most ONE row an asset, each bought at the asset's creation price.
    pub opened: bool,
    /// The batch's arithmetic did not compute and every order was handed back whole ([`settle`]'s fallback). The fold
    /// says so in its log; nothing else reads it.
    pub handed_back: bool,
}

/// ⭐ ONE BATCH OF A POOL: the row after, and every payout. `orders` are the pool's pending orders the settlement
/// covers, in the ledger's order; `pre` is the row the path proved (`None`: the pool has no leaf yet); `secs` is the
/// chain clock of the settling block, in seconds. `None` refuses the whole batch: an overflow, a row or an order that
/// is not this pool's, or a conservation check that does not hold.
///
/// ⛔ A STEP IS ALWAYS SETTLED: when the batch's own arithmetic does not compute (an overflow, a conservation check
/// that does not hold), every order of the step is handed back whole ([`hand_back`]). Only a settlement that is WRONG
/// (no orders, an order of another pool or a later step, a row that is not this pool's or is already past the cutoff)
/// is refused.
/// SAFE-FALLBACK: without it, a step whose batch did not compute could never be settled by anyone: a settlement
/// settles the pool's EARLIEST pending step, so that step's orders, their burned inputs with them, and every later
/// order of the pool would wait for ever on one arithmetic corner. The fallback pays out exactly what each order
/// burned, to the order's own notes, and never touches the pool's balances, so it cannot be used to take anything:
/// the worst a person who finds such a corner can do is void one step's batch of one pool, at a network fee a step.
/// No such input is known (the pins hold the arithmetic); this is what happens if one exists.
#[must_use]
pub fn settle(token: &[u8; 32], pre: Option<&IonRow>, orders: &[IonPending], cutoff: u64, secs: u64) -> Option<IonSettled> {
    if orders.is_empty() || orders.iter().any(|o| o.token != *token || o.step > cutoff) {
        return None;
    }
    if pre.is_some_and(|r| r.token != *token || !r.well_formed() || cutoff <= r.settled_through) {
        return None;
    }
    settle_batch(token, pre, orders, cutoff, secs).or_else(|| hand_back(token, pre, orders, cutoff))
}

/// Every order of the step back to its owner, whole: the token, the USDm and the shares it burned, each to the order's
/// own note of that asset. The pool's balances and price are untouched; a pool that has a row moves its batch counter
/// and its cutoff (so the row never repeats and an older settlement is refused), and keeps the fee units for its
/// creator; with no row, nothing is written and the units are the fee pools' ([`IonSettled::opened`]).
fn hand_back(token: &[u8; 32], pre: Option<&IonRow>, orders: &[IonPending], cutoff: u64) -> Option<IonSettled> {
    let opened = pre.is_some();
    let mut row = pre.cloned().unwrap_or_else(|| IonRow::new(*token));
    let units: u128 = orders.iter().map(|o| u128::from(o.core.fee_unit())).sum();
    let mut payouts = Vec::new();
    let mut paid_y = 0u128;
    for (i, o) in orders.iter().enumerate() {
        let opening = cm_bytes_to_root(&o.core.owner_opening)?;
        // the shares go back as the shares they were: plain, or locked until the same week
        for (asset, amount) in [(IonAsset::Token, o.core.x), (IonAsset::Usdm, o.core.y), (o.core.shares_in(), o.core.shares)] {
            if amount != 0 {
                payouts.push(IonPayout { order: i, asset, amount, cm: asset_note_cm(amount, ion_tag(token, asset), opening) });
            }
        }
        paid_y = paid_y.checked_add(u128::from(o.core.y))?;
    }
    let mut usdm_fees = 0u64;
    if opened {
        row.owed_creator_y = row.owed_creator_y.saturating_add(units);
        row.settled_through = cutoff;
        row.batch = row.batch.checked_add(1)?;
    } else {
        usdm_fees = u64::try_from(units).ok()?;
    }
    Some(IonSettled { row, payouts, usdm_paid: u64::try_from(paid_y).ok()?, usdm_fees, forwards: Vec::new(), opened, handed_back: true })
}

/// The batch itself ([`settle`] checked that the settlement is this pool's). `None`: the arithmetic did not compute.
fn settle_batch(token: &[u8; 32], pre: Option<&IonRow>, orders: &[IonPending], cutoff: u64, secs: u64) -> Option<IonSettled> {
    let mut row = match pre {
        Some(r) if r.token == *token && r.well_formed() && cutoff > r.settled_through => r.clone(),
        Some(_) => return None,
        None => IonRow::new(*token),
    };
    let (x_before, y_before) = row.balances();
    // A LAUNCH is decided before the batch: on a pool nothing has ever entered, the first order that is a launch or an
    // addition decides what the pool is. A launch that does not open the curve is handed back whole.
    let untouched = matches!(row.state, IonState::Pool(p) if p == Pool::default());
    let opener = orders.iter().position(|o| o.core.kind == ION_LAUNCH || o.core.kind == ION_ADD);
    let launched: Option<usize> = match opener {
        Some(i) if untouched && orders[i].core.kind == ION_LAUNCH => Some(i),
        _ => None,
    };
    if let Some(i) = launched {
        row.state = IonState::Curve(Curve::open(u128::from(orders[i].core.x)));
    }
    // A CLAIM, a LOCK and an UNLOCK are no part of the batch: they trade nothing and price nothing. Nor is a REMOVAL of
    // shares locked until a week the settling block has not reached (spec §14): it is handed back whole, as the same
    // locked shares. The batch is every other order; a step with none of those leaves the pool's balances as they were.
    let week = lock_week_of(secs);
    let early = |o: &IonPending| o.core.kind == ION_REMOVE && o.core.lock_from != 0 && week < o.core.lock_from;
    let traded: Vec<usize> = (0..orders.len())
        .filter(|i| !matches!(orders[*i].core.kind, ION_CLAIM | ION_LOCK | ION_UNLOCK) && !early(&orders[*i]))
        .collect();
    let batch: Vec<Order> = traded.iter().map(|i| orders[*i].core.as_order()).collect();
    let (mut state, batch_paid, fees, burned) = if batch.is_empty() {
        (row.state.clone(), Vec::new(), crate::ion_pool::FeesOut::default(), 0u128)
    } else {
        match row.state {
            IonState::Curve(c) => {
                let (after, paid, fees) = curve_step(&c, &batch)?;
                match after {
                    CurveStep::Curve(c2) => (IonState::Curve(c2), paid, fees, 0u128),
                    CurveStep::Graduated { pool, burned } => (IonState::Pool(pool), paid, fees, burned),
                }
            }
            IonState::Pool(p) => {
                let (after, paid, fees) = step(&p, &batch)?;
                (IonState::Pool(after), paid, fees, 0u128)
            }
        }
    };
    if batch_paid.len() != traded.len() {
        return None;
    }
    // what each order is paid, in the pending list's own order (a claim's line is filled in below)
    let mut paid = vec![crate::ion_pool::Paid::default(); orders.len()];
    for (slot, p) in traded.iter().zip(&batch_paid) {
        paid[*slot] = *p;
    }
    // the token part of the protocol's and the publisher's fee stays with the pool (no fee pool holds a token)
    let stay_x = fees.protocol_x.checked_add(fees.publisher_x)?;
    match &mut state {
        IonState::Curve(c) => c.x = c.x.checked_add(stay_x)?,
        IonState::Pool(p) => p.x = p.x.checked_add(stay_x)?,
    }
    row.state = state;
    // ⭐ THE LOCKS (spec §14), decided after the trade, in the pending list's own order, every node the same. What each
    // order's shares are paid in: by default the shares it handed back (a deposit's new shares are plain).
    let mut share_out: Vec<IonAsset> = orders.iter().map(|o| o.core.shares_in()).collect();
    for (i, o) in orders.iter().enumerate() {
        let s = u128::from(o.core.shares);
        match o.core.kind {
            // an early removal of locked shares: the same locked shares back, nothing else
            ION_REMOVE if early(o) => paid[i] = crate::ion_pool::Paid { shares: s, returned: true, ..Default::default() },
            // a removal of locked shares from their week on, filled: those shares leave the table with the pool
            ION_REMOVE if o.core.lock_from != 0 && !paid[i].returned => row.lock_sub(o.core.lock_from, s)?,
            ION_LOCK => {
                // a date on the grid: after the settling block's week and at most four years on; a pool that has shares
                // a provider can hold; and the shares handed back are on the table (plain: what no lock holds yet)
                let date_ok = o.core.lock_until > week && o.core.lock_until <= week.saturating_add(ION_LOCK_WEEKS_MAX);
                let held = match row.state {
                    IonState::Pool(p) if o.core.lock_from == 0 => {
                        let locked: u128 = row.locks.iter().map(|(_, n)| *n).sum();
                        p.shares.saturating_sub(p.locked).saturating_sub(locked) >= s
                    }
                    IonState::Pool(_) => row.locked_until(o.core.lock_from) >= s,
                    IonState::Curve(_) => false,
                };
                let mut after = row.clone();
                let moved = date_ok
                    && held
                    && (o.core.lock_from == 0 || after.lock_sub(o.core.lock_from, s).is_some())
                    && after.lock_add(o.core.lock_until, s).is_some();
                if moved {
                    row = after;
                    share_out[i] = IonAsset::Locked(o.core.lock_until);
                }
                paid[i] = crate::ion_pool::Paid { shares: s, returned: !moved, ..Default::default() };
            }
            ION_UNLOCK => {
                let moved = week >= o.core.lock_from && row.locked_until(o.core.lock_from) >= s && row.lock_sub(o.core.lock_from, s).is_some();
                if moved {
                    share_out[i] = IonAsset::Share;
                }
                paid[i] = crate::ion_pool::Paid { shares: s, returned: !moved, ..Default::default() };
            }
            _ => {}
        }
    }
    // DID THIS BATCH LEAVE A POOL? Every pool that had a row has one after; a pool with none has one only if this
    // batch opened it ([`IonSettled::opened`]). With no pool, nothing traded and every order goes back whole.
    let opened = pre.is_some() || !matches!(row.state, IonState::Pool(p) if p == Pool::default());
    // the USDm units the orders that bring no USDm paid their network fee through ([`ION_FEE_UNIT`]): the creator's,
    // held in the pool's row; where no row is left to hold them, the protocol's (the chain's fee pools)
    let units: u128 = orders.iter().map(|o| u128::from(o.core.fee_unit())).sum();
    let (units_to_creator, units_to_fees) = if opened { (units, 0) } else { (0, units) };
    row.owed_creator_x = row.owed_creator_x.checked_add(fees.creator_x)?;
    row.owed_creator_y = row.owed_creator_y.checked_add(fees.creator_y)?.checked_add(units_to_creator)?;
    let usdm_fees = u64::try_from(fees.protocol_y.checked_add(fees.publisher_y)?.checked_add(units_to_fees)?).ok()?;
    // the payouts
    let mut payouts = Vec::new();
    let mut forwards = Vec::new();
    let mut forwarded = 0u128; // USDm that left this pool for a swap's second pool, and so stayed in the pool layer
    let (mut paid_x, mut paid_y) = (0u128, 0u128);
    // what claims took out of the creator's parts (this batch's own fee parts included: they were added above)
    let (mut claimed_x, mut claimed_y) = (0u128, 0u128);
    for (i, (o, p)) in orders.iter().zip(&paid).enumerate() {
        // a launch that did not open the curve goes back whole; one that did is the curve itself
        let mut x_out = if o.core.kind == ION_LAUNCH && launched != Some(i) { u128::from(o.core.x) } else { p.x };
        let mut y_out = p.y;
        if o.core.kind == ION_CLAIM {
            // THE CREATOR'S CLAIM (its door proved the key): everything the pool holds for the creator, and the USDm
            // the claim itself burned. A second claim of the same step finds nothing owed and gets its own USDm back.
            x_out = row.owed_creator_x;
            y_out = row.owed_creator_y.checked_add(u128::from(o.core.y))?;
            claimed_x = claimed_x.checked_add(row.owed_creator_x)?;
            claimed_y = claimed_y.checked_add(row.owed_creator_y)?;
            row.owed_creator_x = 0;
            row.owed_creator_y = 0;
        }
        paid_x = paid_x.checked_add(x_out)?;
        paid_y = paid_y.checked_add(y_out)?;
        // A SWAP'S FIRST LEG, FILLED: its USDm is not paid as a note; it becomes the second pool's pending buy, with
        // this order's own payout words and the second floor. (A sale handed back whole, or one that earned nothing,
        // forwards nothing.)
        if o.core.kind == ION_SELL && o.core.hop != [0u8; 32] && !p.returned && y_out > 0 {
            forwarded = forwarded.checked_add(y_out)?;
            forwards.push(IonPending {
                token: o.core.hop,
                step: 0, // set by the ledger when the settlement applies
                id: blake3::derive_key("MonerousD ionswap swap second leg v1", &o.id),
                core: IonOrderCore { kind: ION_BUY, x: 0, y: u64::try_from(y_out).ok()?, shares: 0, min_out: o.core.hop_min_out, hop: [0u8; 32], hop_min_out: 0, ..o.core.clone() },
            });
            y_out = 0;
        }
        for (asset, amount) in [(IonAsset::Token, x_out), (IonAsset::Usdm, y_out), (share_out[i], p.shares)] {
            if amount == 0 {
                continue;
            }
            // One note an asset an order (an order's notes share its opening and differ by tag). A note holds 64 bits,
            // and no payout can pass that: an asset has ONE mint of at most 64 bits, USDm's whole supply is 64 bits, and a
            // pool's shares never exceed the larger of its balances. Were it ever to, the batch is refused whole.
            let amount = u64::try_from(amount).ok()?;
            let opening = cm_bytes_to_root(&o.core.owner_opening)?;
            payouts.push(IonPayout { order: i, asset, amount, cm: asset_note_cm(amount, ion_tag(token, asset), opening) });
        }
    }
    // ⛔ CONSERVATION, unit for unit, checked on every batch: what entered equals what the pool kept, plus what was
    // paid, plus the fee parts that left, plus (at a graduation) the tokens burned.
    let (mut in_x, mut in_y) = (0u128, 0u128);
    for o in orders {
        match o.core.kind {
            ION_BUY | ION_CLAIM => in_y += u128::from(o.core.y),
            ION_SELL | ION_LAUNCH => in_x += u128::from(o.core.x),
            ION_ADD => {
                in_x += u128::from(o.core.x);
                in_y += u128::from(o.core.y);
            }
            _ => {}
        }
    }
    // (the creator's parts are held beside the pool's balances: a batch moves its fee parts into them, a claim pays
    // out of them, so what a claim took stands on the side of what entered)
    in_y = in_y.checked_add(units)?; // the fee units entered, and went to the creator's part
    let (x_after, y_after) = row.balances();
    row.burned_x = row.burned_x.checked_add(burned)?;
    if x_before.checked_add(in_x)?.checked_add(claimed_x)? != x_after.checked_add(paid_x)?.checked_add(fees.creator_x)?.checked_add(burned)? {
        return None;
    }
    // (the fee units stand once on the right: with the creator's part, or inside `usdm_fees` where no pool was left)
    if y_before.checked_add(in_y)?.checked_add(claimed_y)? != y_after.checked_add(paid_y)?.checked_add(fees.creator_y)?.checked_add(units_to_creator)?.checked_add(u128::from(usdm_fees))? {
        return None;
    }
    // ⛔ a batch that leaves no pool moved nothing but those units: no fee, no creator's part, no forward, and every
    // asset an order brought is in its own payout. Checked, so that "nothing is written" can never hide a balance.
    if !opened && (row.balances() != (0, 0) || row.owed_creator_x != 0 || row.owed_creator_y != 0 || !forwards.is_empty() || in_x != paid_x || in_y != paid_y.checked_add(units)?) {
        return None;
    }
    row.settled_through = cutoff;
    row.batch = row.batch.checked_add(1)?;
    // one price a batch that TRADED (the ring's own rule): a step of claims, locks and unlocks does not move the chart
    if !batch.is_empty() {
        if let Some(p) = row.price() {
            if row.prices.len() >= ION_PRICE_RING {
                row.prices.remove(0);
            }
            row.prices.push((secs, p));
        }
    }
    // ⛔ the row it leaves is one the chain can hold: a lock table that is bounded, ordered, and never locks more shares
    // than providers can hold (were it not, the batch is refused and every order handed back)
    if !row.well_formed() {
        return None;
    }
    Some(IonSettled { row, payouts, usdm_paid: u64::try_from(paid_y.checked_sub(forwarded)?).ok()?, usdm_fees, forwards, opened, handed_back: false })
}

/// ⭐ A SETTLEMENT (`Class::IonSettle`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IonSettleTx {
    pub token: [u8; 32],
    /// It settles EVERY pending order of this pool folded at or before this fold step.
    pub cutoff: u64,
    /// The pool's row before (`None`: the pool has no leaf yet).
    pub pre: Option<IonRow>,
    /// The leaf's place in the contract-state root: of `pre`'s leaf, or of the empty leaf.
    pub path: PathWire,
    /// `(note, locator)`: the payout notes, in the fold's own order, each with the locator its order named for that asset
    /// (the clue it is filed under is [`ion_locator_clue`] of it).
    /// O1-FOOTPRINT-REVIEWED: at most three notes an order of a step (`decode` refuses more than a pool's pending
    /// orders could yield); released with the block.
    pub notes: Vec<(Vec<u8>, [u8; 32])>,
}

impl IonSettleTx {
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::IonSettle, &self.encode())
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<IonSettleTx> {
        let t: IonSettleTx = crate::chain_object::decode_exact(bytes)?;
        // a batch is one step's orders of one pool (`verdict`): at most three notes an order
        if t.token == [0u8; 32] || t.notes.len() > 3 * ION_STEP_ORDERS_MAX {
            return None;
        }
        if t.pre.as_ref().is_some_and(|r| !r.well_formed() || r.token != t.token) {
            return None;
        }
        t.path.expand()?;
        for (note, _) in &t.notes {
            if note.len() != crate::cover::PQ_NOTE_BYTES && note.len() != 64 {
                return None;
            }
            note_cm_of(note)?;
        }
        Some(t)
    }

    /// The batch this settles: the pool's next.
    #[must_use]
    pub fn batch(&self) -> u64 {
        self.pre.as_ref().map_or(0, |r| r.batch)
    }

    /// The object's own lane tag: a one-time id of THESE EXACT BYTES, so the same settlement carried twice is refused by
    /// the spent set like any re-carried object.
    /// ⛔ WHY NOT AN ID OF (pool, batch): the fold's contest over a tag is decided before any class door runs. Were the id
    /// the batch's, a worthless settlement (well formed, false, so refused at its door) placed ahead of the true one in a
    /// block would take the batch's tag, be refused, and leave the true one a contest loser: whoever could order a block
    /// could hold a pool's pending orders unpaid for as long as it kept doing so. With an id of the bytes, two different
    /// settlements of one batch contest nothing: the first valid one moves the pool's leaf, and every other is refused at
    /// its own door because the row it carries is no longer the pool's (a row never repeats: its batch number only rises).
    ///
    /// ⛔ THE BYTES ARE THE CARRIED FORM'S (found 2026-11-11 by this module's own two-node pins the first time they ran,
    /// RED on all three). A block carries an object in its carriage form (`chain_object::carriage_of`: every payout
    /// note as its 64-byte reference, `cm ‖ hash of the note`), and the publisher lays the tag on the block's lane from
    /// the WHOLE object. The id was the hash of whichever bytes it was asked of, so a peer, which only ever holds the
    /// carried form, derived another tag, found it on no lane, and its note door refused the object: the settlement
    /// applied at that peer's fold and its PAYOUT NOTES were never recorded there ("B does not hold the buyer's
    /// returned USDm"). The id is now of the carried form whichever form it is asked of (`note_ref` returns a
    /// reference unchanged); a reference binds the whole note, so the id still binds every byte.
    #[must_use]
    pub fn own_nullifiers(&self) -> Vec<[u8; 32]> {
        let mut carried = self.clone();
        for (note, _) in &mut carried.notes {
            if let Some(r) = crate::chain_object::note_ref(note) {
                *note = r;
            }
        }
        vec![crate::peg::one_time_id_nf(ONE_TIME_ION_SETTLE, blake3::hash(&carried.encode()).as_bytes())]
    }

    /// ⭐⭐ SEVERAL POOLS SETTLE IN ONE FOLD STEP (2026-11-11) — THIS SETTLEMENT WITH ITS PATH BROUGHT FORWARD over the
    /// leaves earlier settlements of the SAME step wrote. `None` when its path opens `root` as carried, or cannot be
    /// brought forward to it.
    ///
    /// WHAT WAS WRONG (found by `a_swap_sells_in_one_pool_and_is_paid_in_another_token_on_two_nodes` the first time it
    /// ran: two pools' settlements in one block, one pool opened): a settlement proves its pool's row by a path under the
    /// contract-state root as it stood when it was formed. The first settlement a step applies moves that root, so
    /// every other settlement of the step was refused ("the row the settlement carries is not the pool's row") and
    /// formed again a step later: ONE pool settled per fold step, chain-wide, however many pools had orders waiting.
    /// A thousand busy pools would each have settled once in a thousand steps.
    /// THE RULE: writing another pool's leaf changes exactly one sibling of this pool's path, the one where the two
    /// contract ids part, and that sibling is computed from the other settlement's own path and new leaf
    /// (`contract_state::rebase_path`). So the fold keeps, for the step it is folding, each settlement's contract id,
    /// new leaf and path as written, and a later settlement whose carried path no longer opens the root is brought
    /// forward over them in the block's own order; it is then judged by the unchanged verdict against the ledger's
    /// root. Nothing is believed: a path that does not open the root after that is refused exactly as before. Every node
    /// folds the same block's objects in the same order, so every node brings the same paths forward.
    /// BOUNDED WORK: at most [`ION_STEP_SETTLES_MAX`] settlements a step are brought forward; one costs at most 255
    /// hashes for each earlier one, so a step's whole cost is under 32 × 31 / 2 × 255 = 126,480 hashes. A settlement
    /// past the bound is refused on the item and formed again next step.
    /// SCALE: (a) nodes that bond: no term. (b) pools with orders in one step: up to the bound per step, where it was
    /// one. (c) height: no term. Not carried forward over a contract deploy or call of the same step (those writes
    /// are not kept here): a settlement behind one is refused on the item and formed again.
    /// AI RESISTANT: ordinary code proposing a path; the proof that decides is the same path check against the
    /// ledger's own root.
    #[must_use]
    pub fn brought_forward(&self, root: Digest4, earlier: &[IonStepWrite]) -> Option<IonSettleTx> {
        if earlier.is_empty() || earlier.len() >= ION_STEP_SETTLES_MAX {
            return None;
        }
        let cid = ion_pool_cid(&self.token);
        let mut sibs = self.path.expand()?;
        let old_leaf = self.pre.as_ref().map_or_else(empty_leaf, IonRow::leaf);
        if verify_path(root, &cid, old_leaf, &sibs) {
            return None;
        }
        for (other, leaf, path) in earlier {
            let _ = crate::contract_state::rebase_path(&cid, &mut sibs, other, *leaf, path);
        }
        if !verify_path(root, &cid, old_leaf, &sibs) {
            return None;
        }
        Some(IonSettleTx { path: PathWire::compact(&sibs)?, ..self.clone() })
    }

    /// ⭐ THE FOLD'S WHOLE VERDICT, a pure function of this object, the root the ledger holds, the ledger's pending
    /// orders and the fold step and clock it is judged at. `Ok((root after, what the batch did, how many pending
    /// orders it settles))`; the caller then checks the layer word and writes.
    pub fn verdict(&self, root: Digest4, pending: &[IonPending], fold_step: u64, secs: u64) -> Result<(Digest4, IonSettled), &'static str> {
        if self.cutoff >= fold_step {
            return Err("a settlement covers only steps that folded before its own");
        }
        let cid = ion_pool_cid(&self.token);
        let sibs = self.path.expand().ok_or("the settlement's path is malformed")?;
        let old_leaf = self.pre.as_ref().map_or_else(empty_leaf, IonRow::leaf);
        if !verify_path(root, &cid, old_leaf, &sibs) {
            return Err("the row the settlement carries is not the pool's row under this node's contract-state root");
        }
        // ⛔ A BATCH IS THE ORDERS OF ONE STEP, THE POOL'S EARLIEST PENDING ONE (corrected 2026-11-11, before anything
        // ran). The first rule settled EVERY pending order of the pool at once: a pool whose settlements lagged a few
        // steps would owe more payout notes than one block carries (256), no settlement of it could ever be included,
        // and its orders, their burned inputs with them, would wait for ever. One step's orders are at most
        // `ION_STEP_ORDERS_MAX` (three notes each: 96), so a batch always fits, a backlog drains a step a block, and
        // "one price for every order of a pool that lands in the same block" is exactly what a batch is.
        let earliest = pending.iter().filter(|o| o.token == self.token).map(|o| o.step).min().ok_or("the pool has no pending order")?;
        if self.cutoff != earliest {
            return Err("a settlement settles the pool's earliest pending step, and this one names another");
        }
        let orders: Vec<IonPending> = pending.iter().filter(|o| o.token == self.token && o.step == earliest).cloned().collect();
        if orders.len() > ION_STEP_ORDERS_MAX {
            return Err("the pool's pending step holds more orders than a step takes");
        }
        let done = settle(&self.token, self.pre.as_ref(), &orders, self.cutoff, secs).ok_or("the batch does not compute (a stale row, an overflow, or it does not conserve)")?;
        if done.payouts.len() != self.notes.len() {
            return Err("the settlement does not carry exactly the batch's payout notes");
        }
        for (p, (note, locator)) in done.payouts.iter().zip(&self.notes) {
            if note_cm_of(note) != Some(p.cm) || *locator != orders[p.order].core.locator_of(p.asset) {
                return Err("a payout note is not the one the batch pays, or is not at its order's locator");
            }
            // a whole note must also SAY what it holds, or its owner cannot open it
            if note.len() == crate::cover::PQ_NOTE_BYTES && *note != ion_payout_note(&orders[p.order].core, p, ion_tag(&self.token, p.asset)) {
                return Err("a payout note's bytes are not the batch's");
            }
        }
        // a batch that leaves no pool writes nothing: the root stands (the path above proved the pool has no leaf)
        if !done.opened {
            return Ok((root, done));
        }
        let new_leaf = done.row.leaf();
        let after = match &self.pre {
            Some(_) => update_root(root, &cid, old_leaf, new_leaf, &sibs),
            None => insert_root(root, &cid, new_leaf, &sibs),
        }
        .ok_or("the contract-state root does not move by this path")?;
        Ok((after, done))
    }
}

/// The most leaves one page of the pools-cache refill carries: 32 leaves, each with its compact path (about 0.4 KB for a
/// tree of a thousand contracts), and the rows of the pools among them (at most about 0.8 KB each) are about 40 KB, one
/// frame. A SIZE OF ONE MESSAGE, never a bound on what a node may hold or fetch: an asker pages until it holds the tree.
pub const ION_PAGE_ITEMS: usize = 32;

/// ⭐ ONE PAGE OF A HOLDER'S CONTRACT TREE (`WireMsg::IonResp`): its next leaves after the key the asker named, EACH WITH
/// ITS OWN PATH under the root the answerer stood on, and the rows of the pools among them. The asker keeps a leaf only
/// if that path opens ITS OWN ledger's contract-state root, and a row only if it is the storage of a leaf it holds
/// (`node::objects::ion_pool::IonCache::take_page`), so a page can add nothing the chain does not hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IonCachePage {
    /// The contract-state root the answerer stood on when it read the page.
    pub root: [u8; 32],
    /// The key the asker named: the page starts at the answerer's first leaf after it (the zero key: from the start).
    pub after: [u8; 32],
    /// `(contract id, leaf, the leaf's path under root)`, ids strictly rising.
    /// O1-FOOTPRINT-REVIEWED: at most [`ION_PAGE_ITEMS`]; [`IonCachePage::decode`] refuses more. Released with the message.
    pub items: Vec<([u8; 32], [u8; 32], PathWire)>,
    /// The rows of the pools among `items`.
    /// O1-FOOTPRINT-REVIEWED: at most one a leaf of the page; [`IonCachePage::decode`] refuses more.
    pub rows: Vec<IonRow>,
    /// The answerer holds no leaf after the last one here.
    pub done: bool,
}

impl IonCachePage {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// One encoding, inside the page's bounds: at most [`ION_PAGE_ITEMS`] leaves with rising ids, at most one row a
    /// leaf, and no path longer than the tree is deep.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<IonCachePage> {
        let p: IonCachePage = crate::chain_object::decode_exact(bytes)?;
        let rising = p.items.windows(2).all(|w| w[0].0 < w[1].0);
        let paths = p.items.iter().all(|(_, _, path)| path.sibs.len() <= crate::contract_state::DEPTH);
        (p.items.len() <= ION_PAGE_ITEMS && p.rows.len() <= p.items.len() && rising && paths).then_some(p)
    }
}

/// What the fold did with a blob offered to these classes.
#[derive(Debug, PartialEq, Eq)]
pub enum IonApply {
    NotIon,
    /// An order joined the pending list; a settlement moved its pool.
    Applied,
    /// Refused on the item only (the block stands); nothing was written and nothing is spent.
    Refused(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract_state::ContractStateTree;

    const U: u64 = 100_000_000;
    const TOKEN: [u8; 32] = [0x71; 32];

    fn opening(i: u8) -> [u8; 32] {
        leaf_to_cm_bytes(cm_bytes_to_leaf(&[i; 32]))
    }
    fn core(kind: u8, x: u64, y: u64, shares: u64, min_out: u64, who: u8) -> IonOrderCore {
        let l = |k: u8| [who.wrapping_mul(3).wrapping_add(k); 32];
        IonOrderCore { kind, x, y, shares, min_out, owner_opening: opening(who), shell_ct: vec![who; ION_SHELL_CT_BYTES], shell_pad: [who ^ 0x5A; 32], shell_vt: who, locators: [l(0), l(1), l(2)], hop: [0u8; 32], hop_min_out: 0, lock_from: 0, lock_until: 0 }
    }
    fn pend(step: u64, who: u8, c: IonOrderCore) -> IonPending {
        IonPending { token: TOKEN, step, id: [who; 32], core: c }
    }
    fn sum(s: &IonSettled, asset: IonAsset, order: usize) -> u64 {
        s.payouts.iter().filter(|p| p.asset == asset && p.order == order).map(|p| p.amount).sum()
    }

    /// A pool opened by a deposit, traded against, and LEFT: the provider's shares hand back both assets, more than it
    /// put in by the fees the trades left, and what nobody can remove is the 1,000 locked units alone.
    #[test]
    fn a_provider_removes_what_it_added_and_the_fees_it_earned() {
        let add = pend(5, 1, core(ION_ADD, 1_000 * U, 2_000 * U, 0, 0, 1));
        let s1 = settle(&TOKEN, None, &[add], 5, 100).expect("the first deposit opens the pool");
        let shares = sum(&s1, IonAsset::Share, 0);
        assert!(shares > 0 && sum(&s1, IonAsset::Token, 0) == 0 && sum(&s1, IonAsset::Usdm, 0) == 0, "the first provider gets shares and no change");
        let IonState::Pool(p1) = s1.row.state else { panic!("a pool") };
        assert_eq!(p1.locked, crate::ion_pool::MINIMUM_SHARES);
        assert_eq!(u128::from(shares) + p1.locked, p1.shares, "every share is the provider's or the locked minimum");
        // a buy and a sell in one batch clear at one price
        let buy = pend(7, 2, core(ION_BUY, 0, 100 * U, 0, 1, 2));
        let sell = pend(7, 3, core(ION_SELL, 40 * U, 0, 0, 1, 3));
        let s2 = settle(&TOKEN, Some(&s1.row), &[buy, sell], 7, 200).expect("the batch clears");
        assert!(sum(&s2, IonAsset::Token, 0) > 0 && sum(&s2, IonAsset::Usdm, 1) > 0, "each side is paid the other asset");
        assert!(s2.usdm_fees > 0 && s2.row.owed_creator_y > 0 && s2.row.owed_creator_x > 0, "the fee parts are accounted");
        assert_eq!(s2.row.prices.len(), 2, "one price a batch");
        // the provider leaves with everything but the locked dust
        let remove = pend(9, 1, core(ION_REMOVE, 0, 0, shares, 0, 1));
        let s3 = settle(&TOKEN, Some(&s2.row), &[remove], 9, 300).expect("a removal settles");
        let (out_x, out_y) = (sum(&s3, IonAsset::Token, 0), sum(&s3, IonAsset::Usdm, 0));
        let IonState::Pool(p2) = s2.row.state else { panic!("a pool") };
        let IonState::Pool(p3) = s3.row.state else { panic!("a pool") };
        assert_eq!(p3.shares, p3.locked, "⛔ a share that is not the locked minimum stayed behind");
        assert_eq!(u128::from(out_x) + p3.x, p2.x, "⛔ the removal did not hand back the pool's tokens");
        assert_eq!(u128::from(out_y) + p3.y, p2.y, "⛔ the removal did not hand back the pool's USDm");
        // what stays is the locked minimum's part: a millionth of a percent of this pool
        assert!(p3.x * 1_000_000 < p2.x && p3.y * 1_000_000 < p2.y, "⛔ more than dust is locked");
        // k grew by the pool's part of the fees: the provider is paid for providing
        assert!(u128::from(out_x) * u128::from(out_y) > u128::from(1_000 * U) * u128::from(2_000 * U) * 999 / 1_000, "the provider left with its deposit's worth");
    }

    /// A removal of shares the pool never issued, and a removal reaching into the locked minimum, pay nothing: the
    /// shares come back.
    #[test]
    fn a_removal_cannot_take_what_is_locked_or_what_does_not_exist() {
        let s1 = settle(&TOKEN, None, &[pend(1, 1, core(ION_ADD, 500 * U, 500 * U, 0, 0, 1))], 1, 1).expect("opens");
        let IonState::Pool(p1) = s1.row.state else { panic!("a pool") };
        let all = u64::try_from(p1.shares).expect("fits"); // more than anyone holds: the locked minimum is in it
        let s2 = settle(&TOKEN, Some(&s1.row), &[pend(2, 9, core(ION_REMOVE, 0, 0, all, 0, 9))], 2, 2).expect("settles");
        assert_eq!((sum(&s2, IonAsset::Token, 0), sum(&s2, IonAsset::Usdm, 0)), (0, 0), "⛔ a removal reached the locked shares");
        assert_eq!(sum(&s2, IonAsset::Share, 0), all, "the shares are handed back whole");
        assert_eq!(s2.row.balances(), s1.row.balances(), "the pool did not move");
    }

    /// ⛔ NO ROW WITHOUT A POOL (NO GROWTH). Orders into a token that has no pool are handed back whole and the batch
    /// says the tree is not to be written: a buy, a sale, a removal and a claim, alone and together. The fee units
    /// they brought go to the chain's fee pools (there is no row to hold a creator's part). The verdict keeps the root,
    /// so every node holds the same tree as before, whatever anyone paid in network fees. And the same step with one
    /// real deposit in it DOES open the pool: the rule turns on whether a pool exists after, nothing else.
    /// RED before the rule (2026-11-11): `settle` returned a row for every batch and the verdict inserted its leaf.
    /// TWO-PARTY-REVIEWED: a pure function of the ledger's words; its two-node pin is
    /// `a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes` (the unopened-pool arm).
    #[test]
    fn orders_into_no_pool_are_handed_back_and_nothing_is_written() {
        // CROSS-NODE-REVIEWED: a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes
        let orders = [
            pend(4, 1, core(ION_BUY, 0, 7 * U, 0, 1, 1)),
            pend(4, 2, core(ION_SELL, 3 * U, 0, 0, 1, 2)),
            pend(4, 3, core(ION_REMOVE, 0, 0, 5 * U, 0, 3)),
        ];
        for batch in [&orders[..1], &orders[1..2], &orders[2..], &orders[..]] {
            let s = settle(&TOKEN, None, batch, 4, 10).expect("a batch on no pool computes");
            assert!(!s.opened, "⛔ a batch that opened nothing says a pool exists: every node would keep a row for it");
            assert!(s.forwards.is_empty() && s.row.balances() == (0, 0) && s.row.owed_creator_y == 0 && s.row.owed_creator_x == 0, "nothing is held for a pool that does not exist");
            for (i, o) in batch.iter().enumerate() {
                assert_eq!((sum(&s, IonAsset::Token, i), sum(&s, IonAsset::Usdm, i), sum(&s, IonAsset::Share, i)), (o.core.x, o.core.y, o.core.shares), "⛔ order {i} did not come back whole");
            }
            let units: u64 = batch.iter().map(|o| o.core.fee_unit()).sum();
            assert_eq!(s.usdm_fees, units, "the fee units the orders brought are the fee pools'");
        }
        // the verdict: the root stands, with the non-membership path it was proved against
        let tree = ContractStateTree::new();
        let pending: Vec<IonPending> = orders.to_vec();
        let done = settle(&TOKEN, None, &pending, 4, 10).expect("computes");
        let notes = done.payouts.iter().map(|p| (ion_payout_note(&pending[p.order].core, p, ion_tag(&TOKEN, p.asset)), pending[p.order].core.locator_of(p.asset))).collect();
        let t = IonSettleTx { token: TOKEN, cutoff: 4, pre: None, path: tree.path(&ion_pool_cid(&TOKEN)), notes };
        let (root_after, d) = t.verdict(tree.root(), &pending, 5, 10).expect("the settlement of an unopened pool is accepted");
        assert!(!d.opened);
        assert_eq!(root_after, tree.root(), "⛔ a batch that opened nothing moved the contract-state root: a leaf was written for no pool");
        // CALIBRATION: one real deposit in the same step opens the pool, and then the row IS written
        let mut with_add = pending.clone();
        with_add.push(pend(4, 4, core(ION_ADD, 100 * U, 100 * U, 0, 0, 4)));
        let opened = settle(&TOKEN, None, &with_add, 4, 10).expect("computes");
        assert!(opened.opened && opened.row.balances().0 > 0, "a deposit opens the pool and its row is kept");
    }

    /// ⛔ A STEP IS ALWAYS SETTLED (SAFE-FALLBACK). A row whose creator part cannot take one more unit makes the
    /// batch's own arithmetic overflow; before the fallback `settle` answered `None`, no node could ever form a
    /// settlement of that step, and the step's orders and every later order of the pool waited for ever with their
    /// inputs burned. Now every order of the step comes back whole, the pool's balances stand, and the row moves on
    /// (its batch counter and cutoff), so the next step settles like any other.
    /// TWO-PARTY-REVIEWED: a pure function of the ledger's words; the fold that calls it is pinned on two nodes by
    /// `a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes`.
    #[test]
    fn a_batch_that_does_not_compute_hands_every_order_back_and_the_pool_goes_on() {
        // CROSS-NODE-REVIEWED: a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes
        let s1 = settle(&TOKEN, None, &[pend(1, 1, core(ION_ADD, 1_000 * U, 2_000 * U, 0, 0, 1))], 1, 1).expect("opens");
        let mut jammed = s1.row.clone();
        jammed.owed_creator_y = u128::MAX; // one more fee unit does not fit
        let orders = [
            pend(3, 2, core(ION_BUY, 0, 100 * U, 0, 1, 2)),
            pend(3, 3, core(ION_SELL, 40 * U, 0, 0, 1, 3)),
            pend(3, 4, core(ION_ADD, 10 * U, 20 * U, 0, 0, 4)),
        ];
        assert!(settle_batch(&TOKEN, Some(&jammed), &orders, 3, 30).is_none(), "CALIBRATION: this batch's own arithmetic does not compute");
        let s = settle(&TOKEN, Some(&jammed), &orders, 3, 30).expect("⛔ a step whose batch does not compute cannot be settled: its orders wait for ever");
        assert!(s.handed_back && s.opened && s.forwards.is_empty() && s.usdm_fees == 0);
        for (i, o) in orders.iter().enumerate() {
            assert_eq!((sum(&s, IonAsset::Token, i), sum(&s, IonAsset::Usdm, i), sum(&s, IonAsset::Share, i)), (o.core.x, o.core.y, o.core.shares), "⛔ order {i} did not come back whole");
        }
        assert_eq!(s.usdm_paid, 120 * U, "the layer pays back exactly the USDm the step's orders brought");
        assert_eq!(s.row.balances(), jammed.balances(), "⛔ a handed-back step moved the pool's balances");
        assert_eq!((s.row.batch, s.row.settled_through, s.row.prices.len()), (jammed.batch + 1, 3, jammed.prices.len()), "the row moves on and no price is stamped");
        // a settlement that is WRONG is still refused: another pool's order, a step past the cutoff, a cutoff the row passed
        assert!(settle(&TOKEN, Some(&jammed), &[IonPending { token: [9; 32], ..orders[0].clone() }], 3, 30).is_none(), "⛔ another pool's order was handed back from this one");
        assert!(settle(&TOKEN, Some(&jammed), &orders, 2, 30).is_none(), "⛔ a step past the cutoff was settled");
        assert!(settle(&TOKEN, Some(&s.row), &orders, 3, 30).is_none(), "⛔ a step the row already passed was settled again");
        // and the honest batch on the honest row is NOT handed back
        let honest = settle(&TOKEN, Some(&s1.row), &orders, 3, 30).expect("computes");
        assert!(!honest.handed_back && sum(&honest, IonAsset::Token, 0) > 0, "CALIBRATION: the same orders trade on a row that computes");
    }

    /// A launch opens a curve on an untouched pool; buyers buy along it; a second launch, and a launch onto a pool
    /// that exists, are handed back whole.
    #[test]
    fn a_launch_opens_a_curve_once_and_any_other_is_returned() {
        let supply = 1_000_000_000 * U;
        let orders = [pend(3, 1, core(ION_LAUNCH, supply, 0, 0, 0, 1)), pend(3, 2, core(ION_BUY, 0, 50 * U, 0, 1, 2)), pend(3, 4, core(ION_LAUNCH, 77, 0, 0, 0, 4))];
        let s = settle(&TOKEN, None, &orders, 3, 10).expect("the launch batch settles");
        let IonState::Curve(c) = s.row.state else { panic!("a curve") };
        assert_eq!(c.x0, u128::from(supply));
        assert!(c.real > 0 && sum(&s, IonAsset::Token, 1) > 0, "the buyer bought along the curve in the launch's own batch");
        assert_eq!(sum(&s, IonAsset::Token, 0), 0, "the launch is the curve: nothing comes back to it");
        assert_eq!(sum(&s, IonAsset::Token, 2), 77, "⛔ a second launch was not handed back whole");
        let again = settle(&TOKEN, Some(&s.row), &[pend(4, 5, core(ION_LAUNCH, 55, 0, 0, 0, 5))], 4, 11).expect("settles");
        assert_eq!(sum(&again, IonAsset::Token, 0), 55, "⛔ a launch onto an existing curve was not handed back whole");
        // nobody provides to a curve, and nobody holds shares in one
        let add = settle(&TOKEN, Some(&s.row), &[pend(4, 6, core(ION_ADD, 10 * U, 10 * U, 0, 0, 6))], 4, 11).expect("settles");
        assert_eq!((sum(&add, IonAsset::Token, 0), sum(&add, IonAsset::Usdm, 0), sum(&add, IonAsset::Share, 0)), (10 * U, 10 * U, 0), "an addition to a curve is returned whole");
    }

    /// The settlement's verdict against a real contract-state tree: the honest one moves the root to the new row's
    /// leaf; a forged payout, a missing order's note, a stale row, a foreign path, an order of a later step and a
    /// cutoff at the judging step are each refused. A pure function of bytes (no node): what two nodes hold after a
    /// settlement is the two-node pin's claim, named inside.
    #[test]
    fn a_settlement_is_checked_whole_against_the_root_and_the_pending_orders() {
        // CROSS-NODE-REVIEWED: a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes
        let cid = ion_pool_cid(&TOKEN);
        let mut tree = ContractStateTree::new();
        tree.insert([0x11; 32], cm_bytes_to_leaf(&[0x22; 32])); // some other contract
        let pending = vec![
            pend(5, 1, core(ION_ADD, 1_000 * U, 1_000 * U, 0, 0, 1)),
            pend(6, 2, core(ION_BUY, 0, 10 * U, 0, 1, 2)), // a later step: not in a settlement through step 5
            IonPending { token: [0x99; 32], step: 5, id: [7; 32], core: core(ION_BUY, 0, 5 * U, 0, 1, 7) }, // another pool's
        ];
        let done = settle(&TOKEN, None, &pending[..1], 5, 50).expect("settles");
        let notes: Vec<(Vec<u8>, [u8; 32])> =
            done.payouts.iter().map(|p| (ion_payout_note(&pending[p.order].core, p, ion_tag(&TOKEN, p.asset)), pending[p.order].core.locator_of(p.asset))).collect();
        let honest = IonSettleTx { token: TOKEN, cutoff: 5, pre: None, path: tree.path(&cid), notes: notes.clone() };
        assert_eq!(IonSettleTx::decode(&honest.encode()), Some(honest.clone()), "it round-trips");
        // THE TAG IS THE CARRIED FORM'S (found 2026-11-11, RED on the two-node pins): a block carries the settlement with
        // every payout note as its 64-byte reference, and a peer must derive the very tag the publisher laid on the lane
        // from the whole object, or its note door refuses the settlement and records no payout.
        let carried = crate::chain_object::carriage_of(&honest.wire()).expect("a settlement has a carriage form");
        let (_, carried_payload) = crate::chain_object::unframe(&carried).expect("the carriage is framed");
        let as_carried = IonSettleTx::decode(carried_payload).expect("the carried form decodes");
        assert!(
            !as_carried.notes.is_empty() && as_carried.notes.iter().all(|(n, _)| n.len() == crate::chain_object::NOTE_REF_BYTES),
            "CALIBRATION: the carried form holds references, not notes"
        );
        assert_ne!(as_carried.encode(), honest.encode(), "CALIBRATION: the two forms are different bytes");
        assert_eq!(as_carried.own_nullifiers(), honest.own_nullifiers(), "⛔ a peer derives another tag than the one the publisher laid on the lane");
        let mut other_note = honest.clone();
        other_note.notes[0].0[40] ^= 1;
        assert_ne!(other_note.own_nullifiers(), honest.own_nullifiers(), "the tag still binds every byte of a payout note");
        let (root1, d1) = honest.verdict(tree.root(), &pending, 7, 50).expect("the honest settlement is accepted");
        assert_eq!(d1, done);
        tree.insert(cid, done.row.leaf());
        assert_eq!(root1, tree.root(), "the root moved to the new row's leaf");
        // every payout note is the one layout (the order's ciphertext and view tag, its keystream over the amount and
        // the tag), and each is filed under a locator clue of the full clue width
        for (p, (note, locator)) in done.payouts.iter().zip(&notes) {
            let c = &pending[p.order].core;
            assert_eq!(&note[32..1120], &c.shell_ct[..], "the ciphertext is the order's");
            assert_eq!(note[1152], c.shell_vt, "the view tag is the order's");
            let plain: Vec<u8> = note[1120..1152].iter().zip(&c.shell_pad).map(|(a, b)| a ^ b).collect();
            assert_eq!(u64::from_le_bytes(plain[..8].try_into().expect("8")), p.amount, "the covered amount is what the batch paid");
            let tag: [u64; 3] = core::array::from_fn(|i| u64::from_le_bytes(plain[8 + 8 * i..16 + 8 * i].try_into().expect("8")));
            assert_eq!(tag, ion_tag(&TOKEN, p.asset), "the covered tag is the payout's asset");
            assert_eq!(ion_locator_clue(locator).len(), crate::peg_in_tx::OWNER_CLUE_MAX, "a payout's clue is a clue of the one width");
        }
        let old_root = { let mut t = ContractStateTree::new(); t.insert([0x11; 32], cm_bytes_to_leaf(&[0x22; 32])); t.root() };
        let refuse = |t: &IonSettleTx, root: Digest4, step: u64| t.verdict(root, &pending, step, 50).is_err();
        // FORGE: a payout of one more share unit
        let mut forged = honest.clone();
        let mut p = done.payouts[0].clone();
        p.amount += 1;
        p.cm = asset_note_cm(p.amount, ion_tag(&TOKEN, p.asset), cm_bytes_to_root(&pending[0].core.owner_opening).expect("canonical"));
        forged.notes[0].0 = ion_payout_note(&pending[0].core, &p, ion_tag(&TOKEN, p.asset));
        assert!(refuse(&forged, old_root, 7), "⛔ a settlement paying more than the batch computes was accepted");
        // SUBSTITUTE: the right commitment, bytes that say another amount
        let mut lying = honest.clone();
        lying.notes[0].0[1120] ^= 1;
        assert!(refuse(&lying, old_root, 7), "⛔ a payout note whose bytes lie about its amount was accepted");
        // STRIP: no notes
        let mut stripped = honest.clone();
        stripped.notes.clear();
        assert!(refuse(&stripped, old_root, 7), "⛔ a settlement that pays nobody was accepted");
        // another owner's locator
        let mut moved = honest.clone();
        moved.notes[0].1 = [0xEE; 32];
        assert!(refuse(&moved, old_root, 7), "⛔ a payout filed at another locator was accepted");
        // REPLAY against the moved root: the pool now has a leaf, so the empty-leaf path no longer verifies
        assert!(refuse(&honest, root1, 8), "⛔ the same settlement applied twice");
        // a row that is not the pool's
        let mut stale = honest.clone();
        stale.pre = Some(IonRow::new(TOKEN));
        assert!(refuse(&stale, old_root, 7), "⛔ a settlement carrying a row the root does not hold was accepted");
        // the cutoff must be a step that already folded
        assert!(refuse(&honest, old_root, 5), "⛔ a settlement covering its own fold step was accepted");
        // A BATCH IS THE POOL'S EARLIEST PENDING STEP: a settlement that names the later step while the earlier one waits
        // is refused (it would pay step 6 at a price step 5's orders never moved)
        let mut wide = honest.clone();
        wide.cutoff = 6;
        assert!(refuse(&wide, old_root, 7), "⛔ a settlement named a later step while an earlier one is pending");
        // once step 5 is settled, step 6 is the earliest and settles against the row step 5 left
        let rest = &pending[1..];
        let next = settle(&TOKEN, Some(&done.row), &rest[..1], 6, 51).expect("step 6 settles after step 5");
        let second = IonSettleTx {
            token: TOKEN,
            cutoff: 6,
            pre: Some(done.row.clone()),
            path: tree.path(&cid),
            notes: next.payouts.iter().map(|p| (ion_payout_note(&rest[0].core, p, ion_tag(&TOKEN, p.asset)), rest[0].core.locator_of(p.asset))).collect(),
        };
        assert!(second.verdict(root1, rest, 8, 51).is_ok(), "⛔ the next step's batch is refused after the first settled");
    }

    /// ⭐ A SWAP OF ONE TOKEN FOR ANOTHER, IN ONE ORDER. A sale names a second pool: when its batch fills it, its USDm
    /// is NOT paid as a note; it is forwarded as a pending BUY in the second pool with the sale's own payout words and
    /// the second floor, and the USDm stays in the pool layer (it is not in `usdm_paid`). The second pool's batch then
    /// pays the second token to the SAME opening at the token locator. A sale whose own floor is not met is handed
    /// back whole and forwards nothing; a second leg whose floor is not met hands the USDm back as a note. Only a sale
    /// may name a second pool, and never its own.
    #[test]
    fn a_swap_sells_in_one_pool_and_buys_in_the_next_with_a_floor_on_each_leg() {
        // CROSS-NODE-REVIEWED: a_swap_sells_in_one_pool_and_is_paid_in_another_token_on_two_nodes
        const OTHER: [u8; 32] = [0x72; 32];
        // two pools, each opened by a deposit
        let open = |token: [u8; 32]| settle(&token, None, &[IonPending { token, step: 1, id: [1; 32], core: core(ION_ADD, 1_000 * U, 1_000 * U, 0, 0, 1) }], 1, 1).expect("opens").row;
        let (row_a, row_b) = (open(TOKEN), open(OTHER));
        let swap = |min_usdm: u64, min_other: u64| IonOrderCore { hop: OTHER, hop_min_out: min_other, ..core(ION_SELL, 10 * U, 0, 0, min_usdm, 5) };
        assert_eq!(swap(1, 1).legs(), Some(vec![(IonAsset::Token, 10 * U), (IonAsset::Usdm, ION_FEE_UNIT)]), "a swap is a sale: the same legs");
        assert!(IonOrderCore { hop: OTHER, ..core(ION_BUY, 0, 5, 0, 1, 1) }.legs().is_none(), "⛔ an order that is no sale names a second pool");
        assert!(IonOrderCore { hop_min_out: 3, ..core(ION_SELL, 5, 0, 0, 1, 1) }.legs().is_none(), "⛔ a second floor with no second pool");
        // FILLED: the sale's USDm is forwarded, not paid
        let order = IonPending { token: TOKEN, step: 2, id: [5; 32], core: swap(1, 1) };
        let leg1 = settle(&TOKEN, Some(&row_a), &[order.clone()], 2, 2).expect("the sale settles");
        assert_eq!(leg1.forwards.len(), 1, "⛔ a filled swap forwarded nothing");
        let fwd = &leg1.forwards[0];
        assert!(fwd.token == OTHER && fwd.core.kind == ION_BUY && fwd.core.y > 9 * U && fwd.core.min_out == 1 && fwd.core.hop == [0u8; 32], "the second leg is a buy in the second pool of exactly the sale's USDm");
        assert_eq!((fwd.core.owner_opening, fwd.core.locators, &fwd.core.shell_ct), (order.core.owner_opening, order.core.locators, &order.core.shell_ct), "⛔ the second leg does not pay the swap's own payout notes");
        assert_eq!(sum(&leg1, IonAsset::Usdm, 0), 0, "⛔ the forwarded USDm was also paid as a note");
        assert_eq!(leg1.usdm_paid, 0, "⛔ forwarded USDm left the pool layer");
        let (IonState::Pool(a0), IonState::Pool(a1)) = (row_a.state.clone(), leg1.row.state.clone()) else { panic!("pools") };
        assert!(a0.y - a1.y >= u128::from(fwd.core.y), "the USDm left the first pool's own balance");
        // the second pool's batch pays the second token to the same opening
        let mut second = fwd.clone();
        second.step = 3;
        let leg2 = settle(&OTHER, Some(&row_b), &[second.clone()], 3, 3).expect("the buy settles");
        let got = sum(&leg2, IonAsset::Token, 0);
        assert!(got > 9 * U && leg2.forwards.is_empty(), "the swap is paid in the second token, and a second leg forwards nothing");
        assert_eq!(leg2.payouts[0].cm, asset_note_cm(got, ion_tag(&OTHER, IonAsset::Token), cm_bytes_to_root(&order.core.owner_opening).expect("canonical")), "⛔ the second token is not paid to the swap's own opening");
        // FIRST FLOOR NOT MET: the tokens come back whole, nothing is forwarded
        let high = IonPending { core: swap(1_000 * U, 1), ..order.clone() };
        let back = settle(&TOKEN, Some(&row_a), &[high], 2, 2).expect("settles");
        assert!(back.forwards.is_empty() && sum(&back, IonAsset::Token, 0) == 10 * U, "⛔ a sale below its floor forwarded or kept something");
        // SECOND FLOOR NOT MET: the USDm comes back as a note
        let mut picky = fwd.clone();
        picky.step = 3;
        picky.core.min_out = 1_000 * U;
        let refund = settle(&OTHER, Some(&row_b), &[picky.clone()], 3, 3).expect("settles");
        assert_eq!((sum(&refund, IonAsset::Token, 0), sum(&refund, IonAsset::Usdm, 0)), (0, picky.core.y), "⛔ a second leg below its floor did not hand the USDm back whole");
    }

    /// An order's words are one kind's, and the burn commitment is bound to every one of them.
    #[test]
    fn an_orders_words_are_one_kinds_and_its_burn_is_bound_to_all_of_them() {
        assert!(core(ION_BUY, 0, 5, 0, 1, 1).legs().is_some());
        assert!(core(ION_BUY, 1, 5, 0, 1, 1).legs().is_none(), "a buy that also brings tokens is no order");
        assert!(core(ION_REMOVE, 0, 0, 5, 1, 1).legs().is_none(), "a removal states no floor");
        assert!(core(9, 0, 5, 0, 0, 1).legs().is_none(), "an unknown kind is no order");
        assert_eq!(core(ION_ADD, 3, 4, 0, 0, 1).legs(), Some(vec![(IonAsset::Token, 3), (IonAsset::Usdm, 4)]));
        // every order carries a USDm leg, so every order pays the network fee: one that brings no USDm brings the unit
        assert_eq!(core(ION_SELL, 3, 0, 0, 1, 1).legs(), Some(vec![(IonAsset::Token, 3), (IonAsset::Usdm, ION_FEE_UNIT)]));
        assert_eq!(core(ION_REMOVE, 0, 0, 5, 0, 1).legs(), Some(vec![(IonAsset::Share, 5), (IonAsset::Usdm, ION_FEE_UNIT)]));
        assert_eq!(core(ION_LAUNCH, 9, 0, 0, 0, 1).legs(), Some(vec![(IonAsset::Token, 9), (IonAsset::Usdm, ION_FEE_UNIT)]));
        for kind in [ION_BUY, ION_SELL, ION_ADD, ION_REMOVE, ION_LAUNCH, ION_CLAIM] {
            let c = match kind {
                ION_BUY | ION_CLAIM => core(kind, 0, 5, 0, 0, 1),
                ION_ADD => core(kind, 3, 4, 0, 0, 1),
                ION_REMOVE => core(kind, 0, 0, 5, 0, 1),
                _ => core(kind, 3, 0, 0, 0, 1),
            };
            assert!(c.legs().expect("an order").iter().any(|(a, n)| *a == IonAsset::Usdm && *n > 0), "⛔ an order of kind {kind} brings no USDm leg and would pay no network fee");
        }
        let a = core(ION_BUY, 0, 5 * U, 0, 7, 1);
        let bind = ion_order_bind(&TOKEN, &a);
        let cm = ion_burn_cm(&bind, 0, a.y, USDM_ASSET_TAG);
        for other in [core(ION_BUY, 0, 5 * U, 0, 8, 1), core(ION_BUY, 0, 5 * U, 0, 7, 2), IonOrderCore { locators: [a.locators[1], a.locators[0], a.locators[2]], ..a.clone() }, IonOrderCore { shell_vt: 9, ..a.clone() }] {
            assert_ne!(ion_burn_cm(&ion_order_bind(&TOKEN, &other), 0, other.y, USDM_ASSET_TAG), cm, "⛔ two different orders share a burn");
        }
        assert_ne!(ion_burn_cm(&ion_order_bind(&[0x72; 32], &a), 0, a.y, USDM_ASSET_TAG), cm, "⛔ another pool's order shares the burn");
        assert_ne!(ion_burn_cm(&bind, 1, a.y, USDM_ASSET_TAG), cm, "⛔ two legs of one order share a burn");
        assert_ne!(share_tag(&ion_pool_cid(&TOKEN)), wrapped_asset_tag(&TOKEN), "a pool's shares are not its token");
        assert_ne!(share_tag(&ion_pool_cid(&TOKEN)), USDM_ASSET_TAG, "a pool's shares are not USDm");
    }

    /// ⭐⭐ LIQUIDITY LOCKS (spec §14; user 2026-11-12: "the optional ability to lock their liquidity on ionswap with the
    /// ability to select the amount of time/unlock date"). On one pool, at the settling block's own clock:
    /// - a LOCK of plain shares until a Monday two weeks on is paid the same number of LOCKED shares, and the row lists
    ///   them by date; the pool's balances do not move and the lock makes the pool read locked;
    /// - a lock dated this week, and one dated more than four years on, are handed back as the plain shares they were;
    /// - a REMOVAL of the locked shares before their Monday is handed back whole, as the same locked shares, and moves
    ///   nothing; from that Monday on it pays both assets and the date leaves the table;
    /// - an EXTENSION moves shares to a later date and never to an earlier one; an UNLOCK before the date is handed back,
    ///   from it pays plain shares;
    /// - the shapes no wallet may send decode as no order (a lock that does not lengthen, a lock week on a buy, an
    ///   unlock of plain shares);
    /// - a LYING SETTLER that pays the early removal (its notes computed at a later clock) is refused by the verdict,
    ///   which recomputes the batch at the settling block's own clock.
    /// TWO-PARTY-REVIEWED: a pure function of the ledger's words; the fold that calls it is pinned on two nodes by
    /// `a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes`, and the real-node check `pool` drives it.
    #[test]
    fn a_lock_holds_shares_until_its_monday_and_every_early_door_hands_them_back() {
        let at = |week: u32, day: u64| lock_week_start_secs(week) + day * 86_400 + 3_600; // a moment inside `week`
        let w0 = lock_week_of(1_794_787_200); // the week of Monday 16 November 2026
        assert_eq!(lock_week_start_secs(w0), 1_794_787_200, "CALIBRATION: a week begins on its Monday 00:00 UTC");
        assert_eq!((lock_week_of(at(w0, 6)), lock_week_of(lock_week_start_secs(w0 + 1))), (w0, w0 + 1), "CALIBRATION: the week turns at Monday 00:00");
        let s1 = settle(&TOKEN, None, &[pend(1, 1, core(ION_ADD, 1_000 * U, 2_000 * U, 0, 0, 1))], 1, at(w0, 0)).expect("opens");
        let shares = sum(&s1, IonAsset::Share, 0);
        let half = shares / 2;
        let lock = |from: u32, until: u32, n: u64, who: u8| IonOrderCore { lock_from: from, lock_until: until, ..core(ION_LOCK, 0, 0, n, 0, who) };
        // ── a lock until w0+2, and two that are refused on their dates
        let early_date = lock(0, w0, 10, 2);
        let far_date = lock(0, w0 + ION_LOCK_WEEKS_MAX + 1, 10, 3);
        assert!(lock(0, w0 + 2, half, 1).legs().is_some() && early_date.legs().is_some() && far_date.legs().is_some(), "CALIBRATION: all three are well-formed orders (their dates are judged at the settlement)");
        let s2 = settle(&TOKEN, Some(&s1.row), &[pend(2, 1, lock(0, w0 + 2, half, 1)), pend(2, 2, early_date), pend(2, 3, far_date)], 2, at(w0, 1)).expect("settles");
        assert_eq!(sum(&s2, IonAsset::Locked(w0 + 2), 0), half, "⛔ the lock was not paid in shares locked until its Monday");
        assert_eq!((sum(&s2, IonAsset::Share, 0), sum(&s2, IonAsset::Token, 0), sum(&s2, IonAsset::Usdm, 0)), (0, 0, 0), "⛔ a lock paid something else");
        assert_eq!(s2.row.locks, vec![(w0 + 2, u128::from(half))], "⛔ the row does not list the lock by its date");
        assert_eq!(s2.row.balances(), s1.row.balances(), "⛔ a lock moved the pool's balances");
        assert_eq!(s2.row.prices, s1.row.prices, "⛔ a step of locks moved the price chart");
        for (i, n) in [(1usize, 10u64), (2, 10)] {
            assert_eq!(sum(&s2, IonAsset::Share, i), n, "⛔ the lock dated off the grid (order {i}) was not handed back as the plain shares it was");
        }
        let (fixed, of) = s2.row.unremovable_now(w0);
        assert!(fixed * 2 > of, "⛔ a pool with half its shares locked plus its minimum does not read locked ({fixed} of {of})");
        assert!(s1.row.unremovable_now(w0).0 * 2 < s1.row.unremovable_now(w0).1, "CALIBRATION: the same pool read unlocked before the lock");
        assert_eq!(s2.row.unremovable_now(w0 + 2).0, s1.row.unremovable_now(w0).0, "from its Monday on, a lock no longer holds the pool");
        // ── a removal of the locked shares, the week before their date: handed back whole, as the same locked shares
        let remove_locked = IonOrderCore { lock_from: w0 + 2, ..core(ION_REMOVE, 0, 0, half, 0, 1) };
        assert_eq!(remove_locked.legs().map(|l| l[0]), Some((IonAsset::Locked(w0 + 2), half)), "a removal of locked shares spends a locked share note");
        let pending_early = [pend(3, 1, remove_locked.clone())];
        let s3 = settle(&TOKEN, Some(&s2.row), &pending_early, 3, at(w0 + 1, 6)).expect("settles");
        assert_eq!(sum(&s3, IonAsset::Locked(w0 + 2), 0), half, "⛔ an early removal of locked shares did not hand them back locked");
        assert_eq!((sum(&s3, IonAsset::Token, 0), sum(&s3, IonAsset::Usdm, 0)), (0, 0), "⛔⛔ LOCKED LIQUIDITY LEFT THE POOL BEFORE ITS DATE");
        assert_eq!((s3.row.balances(), &s3.row.locks), (s2.row.balances(), &s2.row.locks), "⛔ an early removal moved the pool or its lock table");
        // ── the LYING SETTLER: the same removal's notes as a later clock would pay them, offered at the early clock
        let cid = ion_pool_cid(&TOKEN);
        let mut tree = ContractStateTree::new();
        tree.insert(cid, s2.row.leaf());
        let notes_of = |d: &IonSettled| -> Vec<(Vec<u8>, [u8; 32])> { d.payouts.iter().map(|p| (ion_payout_note(&pending_early[p.order].core, p, ion_tag(&TOKEN, p.asset)), pending_early[p.order].core.locator_of(p.asset))).collect() };
        let late = settle(&TOKEN, Some(&s2.row), &pending_early, 3, at(w0 + 2, 0)).expect("computes at the later clock");
        let liar = IonSettleTx { token: TOKEN, cutoff: 3, pre: Some(s2.row.clone()), path: tree.path(&cid), notes: notes_of(&late) };
        assert!(liar.verdict(tree.root(), &pending_early, 4, at(w0 + 1, 6)).is_err(), "⛔⛔ a settlement paying locked liquidity out before its date was accepted");
        let honest = IonSettleTx { notes: notes_of(&s3), ..liar.clone() };
        assert!(honest.verdict(tree.root(), &pending_early, 4, at(w0 + 1, 6)).is_ok(), "CALIBRATION: the honest settlement at the same clock is accepted");
        // ── from its Monday on, the removal pays both assets and the date leaves the table
        let s4 = settle(&TOKEN, Some(&s3.row), &[pend(4, 1, remove_locked)], 4, at(w0 + 2, 0)).expect("settles");
        assert!(sum(&s4, IonAsset::Token, 0) > 0 && sum(&s4, IonAsset::Usdm, 0) > 0, "⛔ the locked shares could not be taken out on their date");
        assert!(s4.row.locks.is_empty(), "⛔ a removed lock stayed on the table");
        // ── EXTENSION and UNLOCK, on the other half
        let s5 = settle(&TOKEN, Some(&s4.row), &[pend(5, 1, lock(0, w0 + 3, half, 1))], 5, at(w0 + 2, 1)).expect("settles");
        assert_eq!(s5.row.locks, vec![(w0 + 3, u128::from(half))]);
        assert!(lock(w0 + 3, w0 + 3, half, 1).legs().is_none() && lock(w0 + 3, w0 + 2, half, 1).legs().is_none(), "⛔ a lock that does not lengthen decodes as an order");
        let s6 = settle(&TOKEN, Some(&s5.row), &[pend(6, 1, lock(w0 + 3, w0 + 9, half, 1))], 6, at(w0 + 2, 2)).expect("settles");
        assert_eq!((sum(&s6, IonAsset::Locked(w0 + 9), 0), &s6.row.locks), (half, &vec![(w0 + 9, u128::from(half))]), "⛔ an extension did not move the shares to the later date");
        let unlock = IonOrderCore { lock_from: w0 + 9, ..core(ION_UNLOCK, 0, 0, half, 0, 1) };
        let s7 = settle(&TOKEN, Some(&s6.row), &[pend(7, 1, unlock.clone())], 7, at(w0 + 8, 6)).expect("settles");
        assert_eq!((sum(&s7, IonAsset::Locked(w0 + 9), 0), sum(&s7, IonAsset::Share, 0), &s7.row.locks), (half, 0, &s6.row.locks), "⛔ an unlock before its date was taken");
        let s8 = settle(&TOKEN, Some(&s7.row), &[pend(8, 1, unlock)], 8, at(w0 + 9, 0)).expect("settles");
        assert_eq!((sum(&s8, IonAsset::Share, 0), s8.row.locks.is_empty()), (half, true), "⛔ an unlock on its date did not pay plain shares");
        // ── shapes no wallet may send
        assert!(IonOrderCore { lock_from: w0, ..core(ION_BUY, 0, 5, 0, 1, 1) }.legs().is_none(), "⛔ a buy names a lock week");
        assert!(IonOrderCore { lock_until: w0 + 2, ..core(ION_REMOVE, 0, 0, 5, 0, 1) }.legs().is_none(), "⛔ a removal names a new lock date");
        assert!(core(ION_UNLOCK, 0, 0, 5, 0, 1).legs().is_none(), "⛔ an unlock of plain shares decodes");
        // the locked shares' tag is the pool's and the week's, and no other's
        assert_ne!(ion_tag(&TOKEN, IonAsset::Locked(w0 + 2)), ion_tag(&TOKEN, IonAsset::Locked(w0 + 3)));
        assert_ne!(ion_tag(&TOKEN, IonAsset::Locked(w0 + 2)), ion_tag(&TOKEN, IonAsset::Share));
        assert_ne!(ion_tag(&TOKEN, IonAsset::Locked(w0 + 2)), ion_tag(&[0x72; 32], IonAsset::Locked(w0 + 2)));
    }

    /// ⛔ A LOCK TABLE THE CHAIN CANNOT HOLD IS NO ROW: out of order, an empty entry, week 0, more shares locked than
    /// providers hold, or a lock on a curve. A settlement whose row carries one is refused at `settle`'s first check.
    #[test]
    fn a_lock_table_out_of_its_rule_is_refused() {
        let s1 = settle(&TOKEN, None, &[pend(1, 1, core(ION_ADD, 1_000 * U, 2_000 * U, 0, 0, 1))], 1, 10).expect("opens");
        let IonState::Pool(p) = s1.row.state else { panic!("a pool") };
        let holdable = p.shares - p.locked;
        assert!(s1.row.well_formed(), "CALIBRATION: an empty table is well formed");
        for (what, locks) in [
            ("out of order", vec![(9u32, 1u128), (8, 1)]),
            ("a repeated date", vec![(8, 1), (8, 1)]),
            ("an empty entry", vec![(8, 0)]),
            ("week 0", vec![(0, 1)]),
            ("more locked than providers hold", vec![(8, holdable + 1)]),
        ] {
            let bad = IonRow { locks, ..s1.row.clone() };
            assert!(!bad.well_formed(), "⛔ a lock table with {what} reads well formed");
            assert!(settle(&TOKEN, Some(&bad), &[pend(2, 2, core(ION_BUY, 0, U, 0, 1, 2))], 2, 20).is_none(), "⛔ a row with {what} was settled");
        }
        let at_most = IonRow { locks: vec![(8, holdable)], ..s1.row.clone() };
        assert!(at_most.well_formed(), "CALIBRATION: every holdable share locked is well formed");
    }
}

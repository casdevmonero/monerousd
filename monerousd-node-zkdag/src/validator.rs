// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! PoS bonded-validator overlay (brick 8): the finality gadget + bond admission.
//!
//! Validators post a confidential bond; a block becomes FINALIZED once validators holding ≥2/3 of
//! the total bonded weight vote for it. Finality is an OVERLAY — it advances `finalized_height` as
//! an afterthought and NEVER gates block production or acceptance (the GHOSTDAG runs at the ONE
//! correct width — 32 by default, `ChainParams::default().dag_width == ghostdag_k == 32` — so up to
//! 32 honest concurrent producers merge as blue, giving unconditional liveness: with every node a
//! producer, the chain cannot halt even if the whole validator quorum is offline).
//!
//! Bond admission uses a THORChain-style anti-drain floor: the required bond is `2× the bridge TVL`
//! — ZERO at zero reserve (the founding seats are free) — so buying a majority of the validator set
//! always costs more than the value it could steal from the bridge.
//!
//! [`FinalityTracker::record_verified_vote`] counts a vote whose PQ threshold signature the CALLER
//! (the node ingress) has ALREADY verified — same layer separation as block ingress (structural
//! verify at the edge, then act). The ML-DSA vote-signature verifier is wired at that ingress in the
//! following brick; this module is the (real) bonded-weight threshold accounting it feeds.

use std::collections::{HashMap, HashSet};

use crate::block::BlockId;

// The finality threshold (2/3 of the bonded weight) is `crate::quorum_math::two_thirds_met`, shared by every tally.
/// Bond floor must be at least this multiple of the bridge TVL (THORChain anti-drain).
pub const BOND_TVL_MULTIPLE: u128 = 2;

// ⛔ DB-345 (history, the pause DELETED 2026-10-02) — A USDm VALIDATOR BOND WAS PAUSED at every door. MEASURED 2026-09-28
// (slot B19, two real `usdmd-node` processes): a wallet's 3 USDm bond was LAID and the producer admitted its weight, while
// its peer — which had not yet fetched the bond's input record — refused it at graft (the one-step membership re-verify
// read the local DA store, and graft applied once): node0 weight 0, node1 300,000,000 after 421.8 s. Honest nodes held
// DIFFERENT validator sets, and this weight drives finality and the bond-weighted custody tally.
//
// What closed B19's class (DB-274), each part pinned RED-first:
// - the bond set applies only at the canonical FOLD (P2), and a shell whose header commits a bond or credit set WAITS
//   there for its body (P5: `db274_p5_a_shell_whose_header_commits_a_bond_set_waits_for_its_body_then_seats_like_the_producer`);
// - the fold re-verifies the input's membership at the `MemberDoor::Fold` door: the named record must be folded BEFORE the
//   bond's block — the canonical order's verdict, never "does this node hold it" — with no per-node ordinal lane
//   (`a_fold_door_membership_verdict_is_the_same_on_a_node_holding_an_unfolded_record_and_one_without_it`);
// - ⛔ SINCE 2026-10-07 VALIDATOR BONDS ARE SAT-ONLY (`Node::USDM_BOND_RETIRED`): a USDm bond seats nothing on any node,
//   even laid with its proven statement by a rogue producer
//   (`a_usdm_bond_a_rogue_producer_lays_with_its_proven_statement_seats_nothing_on_the_peer`); SAT bonds are `Class::SatBond`.
// ⛔⛔⛔ THERE IS NO BASE FLOOR. `BASE_BOND_FLOOR = 2000` stood here until 2026-09-17, and it is the reason
// the FIRST free seat never landed: the real-node seat journey logged `membership seat PUBLISHED` on both
// processes, the block carried the seat (bond_set 5,421 bytes), and `admit` refused it on the publisher's
// OWN node — `BondBelowFloor { bond: 1, floor: 2000 }`, silently. The required bond is ADAPTIVE and only
// adaptive (owner: "the bond price is supposed to be adaptive like thorchain and based on the reserve … so
// the founding quorum should be free since no funds are deposited yet"; "membership bonding should be free
// whenever the required bond equals zero, i.e. reserve is zero"). A constant that keeps the floor above zero
// at zero reserve is the rule's negation, not a safety margin — with `bridge_tvl()` confidential (=0) it
// made the floor 2000 FOREVER, for every seat, whatever the reserve held.

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidatorError {
    #[error("bond {bond} below the adaptive floor {floor}")]
    BondBelowFloor { bond: u128, floor: u128 },
    #[error("validator already bonded")]
    AlreadyBonded,
    #[error("validator permanently slashed for equivocation — cannot re-admit")]
    Slashed,
    /// SATOSHI §9: a re-bond names a validator with no live custody seat.
    #[error("validator holds no custody seat to re-bond")]
    NotBonded,
}

/// The required bond floor given the current bridge TVL: `2 × TVL`, and therefore ZERO at zero TVL — the
/// adaptive rule at its zero point, which is what makes the founding quorum free (`Class::MembershipBond`
/// admits at [`crate::params::MEMBERSHIP_BOND_WEIGHT`] exactly while `peg.reserve_is_zero()`).
pub fn required_bond_floor(bridge_tvl: u128) -> u128 {
    BOND_TVL_MULTIPLE.saturating_mul(bridge_tvl)
}

/// A bonded validator's EXTERNAL bridge-custody points — the compressed foreign-curve points (33-byte secp for
/// BTC, 32-byte Ed25519 for XMR) it contributes to the reserve key-aggregate. Bytes only (the foreign curves live
/// at `crate::bridge`, never here); each validator derives these from its OWN bridge seed. The reserve is the
/// key-AGGREGATE of the LIVE bonded set's points, so it starts as the founding validator (1-of-1, deposits work
/// day 1) and grows to t-of-n as more bond — decentralization by construction, never a solo key held off the set.
#[derive(Clone)]
pub struct BridgeCustody {
    pub secp33: Vec<u8>,
    pub ed32: [u8; 32],
}

/// ⭐ DB-274 P2 (§8.7) — ONE validator's entry in the set: its weight, custody point, custodian KEM key and whether
/// it is barred. The custody point keeps the exported shape `(secp33, ed32)` the snapshot already carries.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VidState {
    pub bond: Option<u128>,
    /// ⭐ SATOSHI — the FINALITY seat (USDm bond or free membership seat), journaled beside the custody seat. MEASURED
    /// 2026-10-05 (read, building the re-bond): the custody/finality split left this out, so a rewound fold step restored the
    /// custody weight and LEFT a finality seat it had admitted — voting weight no chain object grants.
    pub finality: Option<u128>,
    pub custody: Option<(Vec<u8>, [u8; 32])>,
    pub kem_ek: Option<Vec<u8>>,
    pub slashed: bool,
    /// ⭐ G2b (lane a 2026-10-22) — THE VIEW AT A HEIGHT travels with the seat through the fold journal: the height each
    /// seat kind ACTIVATES for finality (its canonical landing height plus `FINALITY_SEAT_ACTIVATION_DELAY`; `0` for a
    /// genesis / fixture seat) and the departed row an exit left (weight, active_from, active_until). A rewound fold step
    /// puts the view back with the seat, so no node holds a seat whose activation height another node's rewind forgot.
    pub bond_active_from: Option<u64>,
    pub finality_active_from: Option<u64>,
    pub departed_bond: Option<DepartedSeat>,
    pub departed_finality: Option<DepartedSeat>,
    /// ⭐ SAFE AT SCALE — the custody seat this id holds (`ValidatorSet::custody_seat`), journaled with the seat so a
    /// rewound fold step puts a custodian back on the seat — and so in the vault — it held.
    pub custody_seat: Option<u64>,
    /// ⭐ §BR-3 17.3 — the SAT delegated to this seat (counted inside `bond`), journaled with it so a rewound fold step puts
    /// the delegated part back with the weight.
    pub delegated: Option<u128>,
    /// ⭐ §BR-3 17.6 — the seat's own-weight yield words `(index last settled at — None once unseated, accrued)`.
    pub own_yield: Option<(Option<u128>, u64)>,
}

/// ⭐ G2b (lane a 2026-10-22) — A SEAT THAT LEFT THE SET, kept for the heights it still weighs on. Ethereum's
/// `exit_epoch`: a validator is active for epoch `e` iff `activation_epoch <= e < exit_epoch`, and an attestation is
/// judged against the set active at ITS epoch, never against the set at the moment the node happens to process it.
/// `active_until` = the exit's canonical landing height plus `FINALITY_SEAT_ACTIVATION_DELAY`. Bounded: pruned once a
/// vote at any height it weighs on is below the tally's retention (`ValidatorSet::prune_departed_below`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DepartedSeat {
    pub weight: u128,
    pub active_from: u64,
    pub active_until: u64,
}

/// ⭐ §BR-3 17.3/17.6 — one id's seat words as the snapshot and the sync bundle carry them: `(id, delegated, own-yield last
/// index, own-yield accrued)`.
pub type SeatWords = ([u8; 32], u128, Option<u128>, u64);

/// The bonded validator set. `id` is a validator's PQ public-key hash.
#[derive(Clone)]
pub struct ValidatorSet {
    /// ⭐ SATOSHI (docs/SATOSHI-NATIVE-TOKEN.md §6) — CUSTODY weight: SAT bonded through `Class::SatBond`. This is what
    /// `bond_of` / `total_bond` answer, so every ≥ 2/3 gate that guards the reserve (the custody tally, credits, price
    /// marks, liquidation signatures, the theft slash) is SAT-weighted. A USDm bond or a free membership seat weighs
    /// NOTHING here — DB-391: a bond denominated in the reserve's own liability is refunded by the theft it should deter.
    bonds: HashMap<[u8; 32], u128>,
    /// FINALITY weight: the free membership seats and USDm bonds (USDm keeps its bond utility, user 9/28) — read by the
    /// finality voters and the anchor classification, never by a reserve gate.
    finality_bonds: HashMap<[u8; 32], u128>,
    total_finality: u128,
    /// ⭐⭐⭐ G2b (lane a 2026-10-22) — FINALITY IS JUDGED AGAINST THE SET ACTIVE AT THE VOTED HEIGHT, one function of the
    /// chain. MEASURED (node::pins::two_nodes_holding_the_same_blocks_read_the_same_finality_whichever_of_them_folded_a_seat_first,
    /// scratchpad/night/g2b-denominator-node-2-20261022.log:1638): two nodes holding the SAME blocks read (1, Some) and
    /// (0, None), because `record_verified_vote` read `finality_weight_of` / `total_finality_weight` — the set THIS node's
    /// fold had applied at the carrier's graft, and the fold cursor is per-node. Borrowed shape (Ethereum
    /// `get_active_validator_indices(state, epoch)`: `activation_epoch <= epoch < exit_epoch`; Tendermint: the validator
    /// set AT height h): every seat kind keeps the height it ACTIVATES (its canonical landing height, the fold's chain-block
    /// blue score, plus `params::FINALITY_SEAT_ACTIVATION_DELAY`; `0` = seated at genesis / by a fixture), every exit
    /// leaves a departed row active until its own landing plus the delay, and the tally asks `finality_weight_of_at` /
    /// `total_finality_weight_at` for the voted height. Missing entry = active from 0 (a set imported from a pre-G2b
    /// carrier). Bounded by the live seats (+ the departed rows within retention).
    bond_active_from: HashMap<[u8; 32], u64>,
    /// ⭐ SAFE AT SCALE — each bonded custodian's CUSTODY SEAT (`custody_vaults`): drawn when its bond was admitted
    /// (`custody_vaults::draw_seat`), kept until it leaves or a split of its vault moves it. Vault `k` is seats
    /// `16k … 16k + 15`, so a bond changes ONE vault (two on a split) and a leave one, whatever the bonded set. A word of chain state like the activation height beside it: assigned at the fold of the bond's own
    /// chain object, journaled with the seat (`VidState`), carried by the snapshot and certified in the bundle
    /// (`custody_seats`). Bounded by the bonded custodians.
    custody_seat: HashMap<[u8; 32], u64>,
    finality_active_from: HashMap<[u8; 32], u64>,
    departed_bond: HashMap<[u8; 32], DepartedSeat>,
    departed_finality: HashMap<[u8; 32], DepartedSeat>,
    /// Per-bonded-validator bridge-custody points (the reserve is their live key-aggregate). A validator without
    /// registered custody is in the finality/mint quorum but not the reserve aggregate (fail-closed, never faked).
    custody: HashMap<[u8; 32], BridgeCustody>,
    /// Per-bonded-custodian ML-KEM-768 encapsulation key — where a peg-in executor seals the custodian-only
    /// transition delta (`crate::peg_attest`). Registered from the member's SIGNED seat header, removed with
    /// the seat. Kept beside `custody` rather than inside `BridgeCustody` so the certified custody tuple the
    /// DSYNC bundle and the snapshot already carry keeps its shape.
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX (one entry per bonded custodian, dropped on remove)
    kem_eks: HashMap<[u8; 32], Vec<u8>>,
    total_bond: u128,
    /// Validators SLASHED for equivocation (double-signing finality votes). Their bond is FORFEITED
    /// (burned — never returned) and they can NEVER re-admit: a permanent, protocol-enforced penalty
    /// so a stake-based finality attack LOSES money, not merely fails. This is the economic teeth.
    slashed: HashSet<[u8; 32]>,
    /// Total bond burned by slashing (these units leave the bonded weight forever; observability).
    slashed_bond_burned: u128,
    /// ⭐ §BR-3 17.3 — SAT DELEGATED to each validator id (asset-tag conversion, `sat_delegation_tx`): exactly the sum of the
    /// outstanding delegated notes of tag `delegated_tag(id)` (a Delegate adds, an Undelegate subtracts — conservation by
    /// construction). While the id is seated the word is counted INSIDE its `bonds` weight (every tally, total and export
    /// carries it) and the seat's OWN locked weight stays `bonds − delegated` (the re-bond rule). An unbond takes the weight out
    /// of the tally but KEEPS the word (the notes still exist; a re-seat counts them again and an Undelegate still subtracts
    /// them); a slash burns it (the id is barred and its Undelegates refused). Bounded by the ids holding outstanding
    /// delegations, each of which once held a floor-bonded seat.
    delegated: HashMap<[u8; 32], u128>,
    /// ⭐ §BR-3 17.6 — each id's OWN-weight bonders' yield: `(the index it last settled at — None once unseated, the yield
    /// accrued and not yet claimed)`. Settled at every own-weight change (seat, re-bond, unbond), burned by a slash, paid by
    /// a `BondYieldClaim`. Bounded by ids that once held a floor-bonded seat with unclaimed yield.
    own_yield: HashMap<[u8; 32], (Option<u128>, u64)>,
    /// #75 brick 4 — the CONFIDENTIAL bonded-stake accumulator. The total bonded weight lives here ONLY as a
    /// value-hiding Poseidon commitment (opaque 4-limb digest): a re-executing node can NEITHER read nor sum the
    /// DAG's total stake, closing the plaintext stake leak. Each admit/unbond/slash advances it via a WHIR-bound
    /// `verify_bond_transition_carrier` conservation proof (no backing — a bond IS the deposit) and the node ONLY
    /// swaps the digest. A fresh set starts at the ZERO digest; `initialize_bond_commitment` seeds the genuine
    /// empty-set commitment on cutover (the set is rebuilt from its bond notes on load, so this is runtime state,
    /// not a serialized field). O(1) state.
    bond_commit: crate::spend_frontier::Digest4,
}

impl ValidatorSet {
    pub fn new() -> Self {
        ValidatorSet {
            bonds: HashMap::new(),
            finality_bonds: HashMap::new(),
            total_finality: 0,
            bond_active_from: HashMap::new(),
            custody_seat: HashMap::new(),
            finality_active_from: HashMap::new(),
            departed_bond: HashMap::new(),
            departed_finality: HashMap::new(),
            custody: HashMap::new(),
            kem_eks: HashMap::new(),
            total_bond: 0,
            slashed: HashSet::new(),
            slashed_bond_burned: 0,
            delegated: HashMap::new(),
            own_yield: HashMap::new(),
            bond_commit: usdm_decider::poseidon2_compress::zero_digest(),
        }
    }

    /// Register a bonded validator's bridge-custody points (its share of the reserve key-aggregate). Kept only for a
    /// CURRENTLY-bonded id (a non-bonded id contributes nothing to the reserve — fail-closed). Idempotent per id.
    pub fn register_custody(&mut self, id: [u8; 32], secp33: Vec<u8>, ed32: [u8; 32]) {
        // SATOSHI: registered for ANY seated id (its signed seat header names these keys); the reserve GROUP below is drawn
        // from CUSTODY-weighted (SAT-bonded) members only, so a finality-only seat holds its keys but custodies nothing.
        if self.is_seated(&id) {
            self.custody.insert(id, BridgeCustody { secp33, ed32 });
        }
    }

    /// Register a bonded custodian's ML-KEM encapsulation key (from its signed seat header). Kept only for a
    /// CURRENTLY-bonded id; refused past `PEG_ATTEST_SEALED_MAX` custodians (a proposal seals to at most that
    /// many, so an ek nobody could ever be sealed to is not stored). Idempotent per id.
    pub fn register_custody_kem(&mut self, id: [u8; 32], kem_ek: Vec<u8>) {
        if self.is_seated(&id)
            && (self.kem_eks.contains_key(&id)
                || self.kem_eks.len() < crate::peg_attest::PEG_ATTEST_SEALED_MAX)
        {
            self.kem_eks.insert(id, kem_ek);
        }
    }

    /// Whether `id` holds ANY seat (custody SAT, or finality USDm / membership).
    pub fn is_seated(&self, id: &[u8; 32]) -> bool {
        self.bonds.get(id).is_some_and(|b| *b > 0) || self.finality_bonds.get(id).is_some_and(|b| *b > 0)
    }
    /// The encapsulation key registered for `id`'s seat (the one its signed seat header named), whether or not `id` is a
    /// CUSTODIAN (`bonded_custodian_eks` — SAT-weighted members only).
    pub fn registered_kem_ek(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.kem_eks.get(id).cloned()
    }
    /// ⭐ T3 / T2 (2026-11-03) — EVERY registered seat key, sorted by id: what the chain registered from each seat's signed
    /// header, membership seats included. The checkpoint and the DSYNC bundle carry THIS (both restore it through
    /// [`Self::import_kem_eks`], which clears first), so a restarted or jumped node holds the table every replaying node
    /// holds. MEASURED why (certify-cb7fdf7c6d0b-20261103-001910.log T3): both carried `bonded_custodian_eks` — SAT seats
    /// only — so node 0, restarted in T1.7 while node 1 held only its membership seat, kept no key for node 1; once node 1
    /// bonded SAT custody, the stake's reward leg was sealed to nobody that could open it ("this custodian holds no sealed
    /// reward leg"), and the unstake was refused "this custodian's stakers' pool opening is stale". Sealing still reads
    /// [`Self::bonded_custodian_eks`] (SAT seats only): carrying a membership key seals nothing to it.
    /// BORROWED: Ethereum's state transition function — a restarted or snap-synced node holds the state every replaying
    /// node holds, never a filtered subset of it. O1-FOOTPRINT-REVIEWED: the same table, bounded by PEG_ATTEST_SEALED_MAX.
    pub fn seated_kem_eks(&self) -> Vec<([u8; 32], Vec<u8>)> {
        let mut out: Vec<([u8; 32], Vec<u8>)> =
            self.kem_eks.iter().filter(|(id, _)| self.is_seated(id)).map(|(id, ek)| (*id, ek.clone())).collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Every bonded custodian with a registered encapsulation key, sorted by id — the executor seals a
    /// peg-in delta to each of these.
    pub fn bonded_custodian_eks(&self) -> Vec<([u8; 32], Vec<u8>)> {
        let mut out: Vec<([u8; 32], Vec<u8>)> = self
            .kem_eks
            .iter()
            .filter(|(id, _)| self.is_bonded_custodian(id))
            .map(|(id, ek)| (*id, ek.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// The LIVE bonded set's bridge-custody points (sorted by id, so every node computes the SAME reserve address),
    /// for validators that are BOTH bonded AND have registered custody. The reserve is their key-aggregate: it
    /// starts at the founding validator (1-of-1) and grows to t-of-n as more bond — never a solo key off the set.
    pub fn bonded_custody(&self) -> Vec<BridgeCustody> {
        let mut ids: Vec<&[u8; 32]> = self
            .custody
            .keys()
            .filter(|id| self.bonds.contains_key(*id))
            .collect();
        ids.sort();
        ids.into_iter().map(|id| self.custody[id].clone()).collect()
    }

    /// DB-121 (2026-09-20): the bonded custodians WITH their bond weight, sorted by id — what the reserve
    /// custody leaf is built from (`crate::btc_tx::custody_leaf`): a member's slots in the k-of-n script are
    /// proportional to its bond, so the on-chain quorum is the same ≥2/3-of-weight rule `bond_of` drives in
    /// the post-quantum tally. Sorted so every node derives byte-identical script and address from one set.
    pub fn bonded_custody_weighted(&self) -> Vec<(BridgeCustody, u128)> {
        let mut ids: Vec<&[u8; 32]> = self
            .custody
            .keys()
            .filter(|id| self.bonds.contains_key(*id))
            .collect();
        ids.sort();
        ids.into_iter()
            .map(|id| (self.custody[id].clone(), self.bonds[id]))
            .collect()
    }

    /// ⭐ SAFE AT SCALE — [`Self::bonded_custody_weighted`] for the given custodians only (one custody vault's members):
    /// the same rows in the same id order, so on a one-vault chain it IS that list.
    pub fn custody_weighted_of(&self, members: &[[u8; 32]]) -> Vec<(BridgeCustody, u128)> {
        let mut ids: Vec<&[u8; 32]> = members.iter().filter(|id| self.custody.contains_key(*id) && self.bonds.contains_key(*id)).collect();
        ids.sort();
        ids.dedup();
        ids.into_iter().map(|id| (self.custody[id].clone(), self.bonds[id])).collect()
    }

    /// ⭐ SAFE AT SCALE — [`Self::bonded_custodian_eks`] for the given custodians only (one custody vault's members), sorted
    /// by id: who a vault's sealed legs go to.
    pub fn custodian_eks_of(&self, members: &[[u8; 32]]) -> Vec<([u8; 32], Vec<u8>)> {
        self.bonded_custodian_eks().into_iter().filter(|(id, _)| members.contains(id)).collect()
    }

    pub fn total_bond(&self) -> u128 {
        self.total_bond
    }

    /// §BR-8 B8-a — the decoy candidates: every bonded custodian with a registered custody point, as `(id, weight, x-only
    /// point)`, sorted by id — the decoy rule draws from it and pays the point's BIP-86 output.
    #[must_use]
    pub fn decoy_candidates(&self) -> Vec<([u8; 32], u128, [u8; 32])> {
        let mut ids: Vec<&[u8; 32]> = self.custody.keys().filter(|id| self.bonds.get(*id).is_some_and(|b| *b > 0)).collect();
        ids.sort();
        ids.into_iter()
            .filter_map(|id| {
                let p = &self.custody[id].secp33;
                let x: [u8; 32] = p.get(1..33)?.try_into().ok()?;
                Some((*id, self.bonds[id], x))
            })
            .collect()
    }

    /// The validator SET's size: every id seated with either weight (custody SAT, or finality USDm / membership). The
    /// custody-only count is `custody_threshold`'s `n`; a reader that wants "how many validators" wants this one.
    /// MEASURED 2026-10-04: counting the custody map alone read a membership-seated validator set as 0 on every node.
    pub fn len(&self) -> usize {
        self.seated_ids().len()
    }
    /// Every seated id (either weight > 0), the one definition `len` and `bonded_ids` share.
    fn seated_ids(&self) -> std::collections::HashSet<[u8; 32]> {
        self.bonds
            .iter()
            .chain(self.finality_bonds.iter())
            .filter(|(_, &b)| b > 0)
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.bonds.is_empty() && self.finality_bonds.is_empty()
    }

    pub fn bond_of(&self, id: &[u8; 32]) -> u128 {
        self.bonds.get(id).copied().unwrap_or(0)
    }

    /// ⭐ THE ONE custody-seat predicate (class 4, 2026-11-02): `id` holds a LIVE custody (SAT) seat on this chain — a
    /// released, slashed or exited seat (`remove_exiting_at`) is gone. Every "does this node act as a custodian" question
    /// (`Node::bonded_custodian_identity`) and every "seal to the custodians" list (`bonded_custodian_eks`) reads this.
    pub fn is_bonded_custodian(&self, id: &[u8; 32]) -> bool {
        self.bonds.get(id).is_some_and(|b| *b > 0)
    }

    /// Whether `id` holds a FINALITY (membership / USDm) seat of its own — never its custody (SAT) seat, which votes finality
    /// too: the membership door asks this so a SAT seat folded first leaves the identity's own seat (and point) still open.
    pub fn holds_finality_seat(&self, id: &[u8; 32]) -> bool {
        self.finality_bonds.get(id).is_some_and(|b| *b > 0)
    }

    /// FINALITY weight of `id`: its custody (SAT) seat plus its finality (USDm / membership) seat.
    pub fn finality_weight_of(&self, id: &[u8; 32]) -> u128 {
        self.bond_of(id).saturating_add(self.finality_bonds.get(id).copied().unwrap_or(0))
    }

    /// The finality denominator: every seat of every kind — the CURRENT set (the display, the anchor classification, the
    /// seat instance digest). ⛔ The quorum is judged with [`Self::total_finality_weight_at`] (G2b).
    pub fn total_finality_weight(&self) -> u128 {
        self.total_bond.saturating_add(self.total_finality)
    }

    /// ⭐ G2b — `id`'s weight toward a vote at height `h`: each seat kind from its activation height, each departed row
    /// over `[active_from, active_until)`. A SLASHED id weighs NOTHING in the numerator at any height (Ethereum counts only
    /// unslashed attesting balance); its departed row still stands in the denominator until its exit matures.
    pub fn finality_weight_of_at(&self, id: &[u8; 32], h: u64) -> u128 {
        if self.slashed.contains(id) {
            return 0;
        }
        self.weight_of_at_including_slashed(id, h)
    }

    fn weight_of_at_including_slashed(&self, id: &[u8; 32], h: u64) -> u128 {
        let mut w: u128 = 0;
        if let Some(b) = self.bonds.get(id) {
            if self.bond_active_from.get(id).copied().unwrap_or(0) <= h {
                w = w.saturating_add(*b);
            }
        }
        if let Some(f) = self.finality_bonds.get(id) {
            if self.finality_active_from.get(id).copied().unwrap_or(0) <= h {
                w = w.saturating_add(*f);
            }
        }
        for d in [self.departed_bond.get(id), self.departed_finality.get(id)].into_iter().flatten() {
            if d.active_from <= h && h < d.active_until {
                w = w.saturating_add(d.weight);
            }
        }
        w
    }

    /// ⭐ G2b — the finality denominator for a vote at height `h`: every seat and departed row active at `h`, slashed
    /// included. O(seats + departed rows) per vote — bounded by the set, never by history.
    pub fn total_finality_weight_at(&self, h: u64) -> u128 {
        self.every_vid().iter().fold(0u128, |a, id| a.saturating_add(self.weight_of_at_including_slashed(id, h)))
    }

    /// ⭐ G2b — the activation heights and departed rows, deterministically sorted, for the snapshot and the DSYNC bundle
    /// (`(custody_active_from, finality_active_from, departed_custody, departed_finality)`; a departed row is
    /// `(id, weight, active_from, active_until)`).
    #[allow(clippy::type_complexity)]
    pub fn seat_activations(
        &self,
    ) -> (Vec<([u8; 32], u64)>, Vec<([u8; 32], u64)>, Vec<([u8; 32], u128, u64, u64)>, Vec<([u8; 32], u128, u64, u64)>) {
        // active from 0 is the default a missing row means (a genesis / fixture seat, a pre-G2b carrier): not exported,
        // so the carried bytes and the chain-replay comparison read ONE canonical form for one view.
        let mut cf: Vec<([u8; 32], u64)> =
            self.bond_active_from.iter().filter(|(_, v)| **v != 0).map(|(k, v)| (*k, *v)).collect();
        cf.sort();
        let mut ff: Vec<([u8; 32], u64)> =
            self.finality_active_from.iter().filter(|(_, v)| **v != 0).map(|(k, v)| (*k, *v)).collect();
        ff.sort();
        let rows = |m: &HashMap<[u8; 32], DepartedSeat>| {
            let mut v: Vec<([u8; 32], u128, u64, u64)> =
                m.iter().map(|(k, d)| (*k, d.weight, d.active_from, d.active_until)).collect();
            v.sort();
            v
        };
        (cf, ff, rows(&self.departed_bond), rows(&self.departed_finality))
    }

    /// ⭐ G2b — the inverse of [`Self::seat_activations`], run AFTER the seats themselves were imported: an activation
    /// height is kept only for an id that holds that seat kind (a stale row never outlives its seat); a carrier without
    /// these rows (pre-G2b) leaves every seat active from 0, as it was judged before.
    pub fn import_seat_activations(
        &mut self,
        custody_from: Vec<([u8; 32], u64)>,
        finality_from: Vec<([u8; 32], u64)>,
        departed_custody: Vec<([u8; 32], u128, u64, u64)>,
        departed_finality: Vec<([u8; 32], u128, u64, u64)>,
    ) {
        self.bond_active_from = custody_from.into_iter().filter(|(id, _)| self.bonds.contains_key(id)).collect();
        self.finality_active_from =
            finality_from.into_iter().filter(|(id, _)| self.finality_bonds.contains_key(id)).collect();
        let rows = |v: Vec<([u8; 32], u128, u64, u64)>| -> HashMap<[u8; 32], DepartedSeat> {
            v.into_iter()
                .map(|(id, weight, active_from, active_until)| (id, DepartedSeat { weight, active_from, active_until }))
                .collect()
        };
        self.departed_bond = rows(departed_custody);
        self.departed_finality = rows(departed_finality);
    }

    /// ⭐ G2b — drop the departed rows no vote the tally still accepts can weigh on: a vote is refused below
    /// `finalized − FINALITY_VOTE_RETENTION`, so a row whose `active_until` is below that bound is never read again.
    /// O(rows dropped); keeps the departed maps bounded by the exits within retention.
    pub fn prune_departed_below(&mut self, finalized_height: u64) {
        let cutoff = finalized_height.saturating_sub(FINALITY_VOTE_RETENTION);
        if cutoff == 0 {
            return;
        }
        self.departed_bond.retain(|_, d| d.active_until >= cutoff);
        self.departed_finality.retain(|_, d| d.active_until >= cutoff);
    }

    /// ⭐ SATOSHI — seat FINALITY weight only (a USDm bond or a free membership seat): no reserve gate counts it.
    /// Active from height 0 — a GENESIS / FIXTURE seat (Ethereum's genesis validators activate at `GENESIS_EPOCH`). The
    /// chain's doors seat with [`Self::admit_finality_active_from`] at the fold's landing height plus the delay (G2b).
    pub fn admit_finality(&mut self, id: [u8; 32], weight: u128) -> Result<(), ValidatorError> {
        self.admit_finality_active_from(id, weight, 0)
    }

    /// ⭐ G2b — seat finality weight that counts toward votes at heights `>= active_from`.
    pub fn admit_finality_active_from(&mut self, id: [u8; 32], weight: u128, active_from: u64) -> Result<(), ValidatorError> {
        if self.slashed.contains(&id) {
            return Err(ValidatorError::Slashed);
        }
        if self.finality_bonds.contains_key(&id) {
            return Err(ValidatorError::AlreadyBonded);
        }
        self.total_finality = self.total_finality.saturating_add(weight);
        self.finality_bonds.insert(id, weight);
        self.finality_active_from.insert(id, active_from);
        Ok(())
    }

    /// ⭐ SATOSHI §10 — THE PUBLIC TAKEOVER FIGURES, from custody weights (consensus state, already public; the reserve is
    /// never read). `(custody_total, effective_security, takeover_cost)`:
    /// - `effective_security`: the custody weight of the bottom ⌈2n/3⌉ custody seats BY COUNT — THORChain's
    ///   `effectiveSecurityBond`, a DISPLAYED statistic only: THORChain is one-node-one-vote, this tally is bond-WEIGHTED, so
    ///   the pendulum reads the TOTAL custody weight instead (§10.7 V1 — dust seats cannot move a total);
    /// - `takeover_cost`: the SAT weight a newcomer must bond to clear the custody tally (≥ 2/3, `two_thirds_met`) ALONE
    ///   against every seat that exists: [`crate::quorum_math::least_capturing_weight`], `2H` base units.
    #[must_use]
    pub fn takeover_figures(&self) -> (u128, u128, u128) {
        let mut w: Vec<u128> = self.bonds.values().copied().filter(|b| *b > 0).collect();
        w.sort_unstable();
        let n = w.len();
        let bottom = n - n / 3; // the bottom ⌈2n/3⌉ seats — the ones a 2/3 takeover must outweigh
        let effective: u128 = w.iter().take(bottom).fold(0u128, |a, b| a.saturating_add(*b));
        let total = self.total_bond;
        (total, effective, crate::quorum_math::least_capturing_weight(total))
    }
    /// ⭐ §BR-3 17.3 — the SAT delegated to `id` (inside [`Self::bond_of`] while `id` is seated).
    pub fn delegated_to(&self, id: &[u8; 32]) -> u128 {
        self.delegated.get(id).copied().unwrap_or(0)
    }
    /// Whether `id` holds a live custody seat.
    fn custody_seated(&self, id: &[u8; 32]) -> bool {
        self.bonds.get(id).is_some_and(|b| *b > 0)
    }
    /// The ONE delegation rule, read without moving anything: a live, unslashed custody seat and a non-zero amount.
    /// `None` = admissible.
    pub fn delegate_refusal(&self, id: &[u8; 32], amount: u128) -> Option<&'static str> {
        if self.slashed.contains(id) {
            return Some("the validator is slashed");
        }
        if amount == 0 {
            return Some("a delegation of nothing");
        }
        (!self.custody_seated(id)).then_some("the validator holds no custody seat")
    }
    /// Delegate `amount` to `id`: its delegated word, its seat's weight and the total rise by it.
    pub fn delegate(&mut self, id: [u8; 32], amount: u128) -> Result<(), &'static str> {
        if let Some(why) = self.delegate_refusal(&id, amount) {
            return Err(why);
        }
        *self.bonds.entry(id).or_insert(0) = self.bond_of(&id).saturating_add(amount);
        *self.delegated.entry(id).or_insert(0) = self.delegated_to(&id).saturating_add(amount);
        self.total_bond = self.total_bond.saturating_add(amount);
        Ok(())
    }
    /// The ONE undelegation rule, read without moving anything: an unslashed id whose delegated word covers `amount` (it
    /// always does for a real delegated note — the word is the sum of them). `None` = admissible.
    /// ⭐ §22 5 — a slashed id still holding its delegated word (an operator-first slash for misbehaviour that lost no one's
    /// money) is ADMITTED: each delegator takes its SAT back through the ordinary unbonding. A slash that burned the word
    /// (reserve theft) leaves nothing to undelegate.
    pub fn undelegate_refusal(&self, id: &[u8; 32], amount: u128) -> Option<&'static str> {
        if self.slashed.contains(id) && self.delegated_to(id) == 0 {
            return Some("the validator was slashed: its delegations were burned with it");
        }
        (amount > self.delegated_to(id)).then_some("an undelegation larger than this validator's delegated weight")
    }
    /// The yield-claim rule: a slashed validator's delegations earn nothing more (they secure nothing) — the delegator
    /// undelegates instead; otherwise the undelegation rule.
    pub fn claim_refusal(&self, id: &[u8; 32], amount: u128) -> Option<&'static str> {
        if self.slashed.contains(id) {
            return Some("the validator was slashed: its delegations earn nothing more — undelegate them");
        }
        self.undelegate_refusal(id, amount)
    }
    /// Undelegate `amount` from `id`: the word falls by it, and — while `id` is seated — so do its seat's weight and the
    /// total. `Ok(true)` when a seated weight moved, `Ok(false)` when the id is unseated (its weight already left the tally).
    pub fn undelegate(&mut self, id: [u8; 32], amount: u128) -> Result<bool, &'static str> {
        if let Some(why) = self.undelegate_refusal(&id, amount) {
            return Err(why);
        }
        let left = self.delegated_to(&id) - amount;
        if left == 0 {
            self.delegated.remove(&id);
        } else {
            self.delegated.insert(id, left);
        }
        if !self.custody_seated(&id) {
            return Ok(false);
        }
        *self.bonds.entry(id).or_insert(0) = self.bond_of(&id).saturating_sub(amount);
        self.total_bond = self.total_bond.saturating_sub(amount);
        Ok(true)
    }
    /// ⭐ §BR-3 17.3 — every id a delegation can name or still holds notes of: each live custody seat (`seated: true`) and each
    /// unseated id holding a delegated word, sorted, with no amount. A wallet picks a seat to delegate to from it and matches
    /// its own delegated notes' tags against it locally (a seed restore needs nothing else).
    pub fn delegation_targets(&self) -> Vec<([u8; 32], bool)> {
        let mut v: Vec<([u8; 32], bool)> = self.bonds.iter().filter(|(_, b)| **b > 0).map(|(k, _)| (*k, true)).collect();
        v.extend(self.delegated.keys().filter(|k| !self.custody_seated(k)).map(|k| (*k, false)));
        v.sort();
        v
    }
    /// The seat's OWN weight (its locked bond, without what is delegated to it); 0 when unseated.
    pub fn own_weight(&self, id: &[u8; 32]) -> u128 {
        self.bond_of(id).saturating_sub(self.delegated_to(id))
    }
    /// ⭐ §BR-3 17.6 — settle `id`'s own-weight yield up to index `y` (before any own-weight change): the accrual grows by
    /// `own · (y − last)`, and the seat now stands at `y`. An id with no entry yet only takes `y` as its baseline (a seat
    /// never earns for time before it was settled — the safe direction); an unseated id accrues nothing.
    pub fn settle_own_yield(&mut self, id: &[u8; 32], y: u128) {
        let own = self.own_weight(id);
        let seated = self.custody_seated(id);
        let e = self.own_yield.entry(*id).or_insert((None, 0));
        if let Some(last) = e.0 {
            e.1 = e.1.saturating_add(crate::peg::bond_yield_between(own, last, y));
        }
        e.0 = seated.then_some(y);
        if e.0.is_none() && e.1 == 0 {
            self.own_yield.remove(id);
        }
    }
    /// The own-weight yield `id` could claim at index `y` (settled, read without moving anything).
    pub fn own_yield_at(&self, id: &[u8; 32], y: u128) -> u64 {
        let (last, accrued) = self.own_yield.get(id).copied().unwrap_or((None, 0));
        accrued.saturating_add(last.map_or(0, |l| crate::peg::bond_yield_between(self.own_weight(id), l, y)))
    }
    /// ⭐ §22 3 — weigh `id`'s settled own-yield accrual by its uptime as the seat leaves (an unbond or a 7-day exit): it keeps
    /// `accrued × active / windows` (`validator_activity::uptime_split`); the rest was never owed and stays in the bonders' pool
    /// for the active seats. Returns the part not owed.
    pub fn scale_own_yield(&mut self, id: &[u8; 32], active: u64, windows: u64) -> u64 {
        let Some(e) = self.own_yield.get_mut(id) else { return 0 };
        let (kept, retained) = crate::validator_activity::uptime_split(e.1, active, windows);
        e.1 = kept;
        retained
    }
    /// ⭐⭐ R4b (spec §3f) — NOBODY IS HELD HOSTAGE BY THE RELEASE GATE. The gate (R4) makes a leaver wait on its old
    /// vault: two thirds of that vault must sweep the old key and retire it. So for every quarter that closes while a
    /// vault still holds a leaver whose window has passed, that vault's seated members' OWN-weight yield of the quarter
    /// — the index's rise from `y0` to `y1` — is theirs no longer: it is split equally among the leavers the vault
    /// holds (`to`), who claim it through the ordinary yield claim. The delay costs the vault what it earned and pays
    /// the ones who wait; nobody votes, claims or proposes it.
    /// Each member is settled to `y0` first (what it earned before this quarter stays its own) and then stands at `y1`
    /// having earned nothing in between; a seat with no entry yet only takes `y1` as its baseline. Delegated weight is
    /// untouched: a delegator's note carries its own index and cannot sweep a vault. Returns what the leavers were
    /// credited; the split's remainder (under one unit per leaver) and nothing else stays in the bonders' pool.
    /// Conservation: every unit credited to a leaver is a unit a member's own weight was entitled to at this index and
    /// now is not — the pool's entitlements never rise (pinned: the sum of every id's due before and after).
    /// AI RESISTANT: (b) code and economics over public words every node holds alike. A vault cannot dodge it by
    /// claiming early: the index only moves at the close, and the diversion runs with the close, before any object of
    /// that block. SAFE AT SCALE: sixteen members and the leavers one vault holds, per holding vault, per quarter.
    pub fn divert_own_yield(&mut self, from: &[[u8; 32]], to: &[[u8; 32]], y0: u128, y1: u128) -> u64 {
        if to.is_empty() || y1 <= y0 {
            return 0;
        }
        let mut forgone: u64 = 0;
        for m in from {
            if to.contains(m) || !self.custody_seated(m) {
                continue;
            }
            let own = self.own_weight(m);
            let e = self.own_yield.entry(*m).or_insert((None, 0));
            if let Some(last) = e.0 {
                e.1 = e.1.saturating_add(crate::peg::bond_yield_between(own, last, y0));
                forgone = forgone.saturating_add(crate::peg::bond_yield_between(own, last.max(y0), y1));
            }
            e.0 = Some(y1);
        }
        let share = forgone / to.len() as u64;
        if share == 0 {
            return 0;
        }
        for l in to {
            let e = self.own_yield.entry(*l).or_insert((None, 0));
            e.1 = e.1.saturating_add(share);
        }
        share.saturating_mul(to.len() as u64)
    }

    /// Pay out `id`'s own-weight yield at index `y`: settle, then zero the accrual; returns what was paid.
    pub fn take_own_yield(&mut self, id: &[u8; 32], y: u128) -> u64 {
        self.settle_own_yield(id, y);
        let Some(e) = self.own_yield.get_mut(id) else { return 0 };
        let paid = std::mem::take(&mut e.1);
        if e.0.is_none() {
            self.own_yield.remove(id);
        }
        paid
    }
    /// ⭐ §BR-3 17.3/17.6 — every id's seat words `(id, delegated, own-yield last index, own-yield accrued)`, sorted (the
    /// snapshot carries them beside the seats).
    pub fn seat_words(&self) -> Vec<SeatWords> {
        let mut ids: Vec<[u8; 32]> = self.delegated.keys().chain(self.own_yield.keys()).copied().collect();
        ids.sort_unstable();
        ids.dedup();
        ids.into_iter()
            .map(|k| {
                let (last, accrued) = self.own_yield.get(&k).copied().unwrap_or((None, 0));
                (k, self.delegated_to(&k), last, accrued)
            })
            .collect()
    }
    /// Restore the seat words a snapshot carried (a seated id's weight already holds its delegated word inside `bonds`, so a
    /// word larger than that weight is refused; a slashed id's words were burned).
    pub fn import_seat_words(&mut self, v: Vec<SeatWords>) {
        self.delegated.clear();
        self.own_yield.clear();
        for (k, d, last, accrued) in v {
            if self.slashed.contains(&k) {
                continue;
            }
            if d > 0 && (!self.custody_seated(&k) || self.bond_of(&k) >= d) {
                self.delegated.insert(k, d);
            }
            if last.is_some() || accrued > 0 {
                self.own_yield.insert(k, (last.filter(|_| self.custody_seated(&k)), accrued));
            }
        }
    }

    /// ⭐ SATOSHI §9 — RE-BOND: replace a SEATED validator's custody weight with `weight` (its locked note was consumed into a
    /// larger one). Refused unless the id holds a live custody seat and is not slashed; returns the weight it replaced.
    pub fn rebond_custody(&mut self, id: [u8; 32], weight: u128) -> Result<u128, ValidatorError> {
        if let Some(e) = self.rebond_refusal(&id, weight) {
            return Err(e);
        }
        // §BR-3 17.3: `weight` is the seat's OWN new locked weight; the delegated part rides on top of it unchanged
        let old = self.bond_of(&id);
        let new = weight.saturating_add(self.delegated_to(&id));
        self.bonds.insert(id, new);
        self.total_bond = self.total_bond.saturating_sub(old).saturating_add(new);
        Ok(old)
    }
    /// The ONE re-bond rule, read without moving anything ([`Self::rebond_custody`] applies it): `None` = admissible. The
    /// fold's objects step decides a SAT re-bond with this against the step's frozen pre-state, and the bond step seats it.
    pub fn rebond_refusal(&self, id: &[u8; 32], weight: u128) -> Option<ValidatorError> {
        if self.slashed.contains(id) {
            return Some(ValidatorError::Slashed);
        }
        let old = match self.bonds.get(id) {
            Some(b) if *b > 0 => b.saturating_sub(self.delegated_to(id)), // §BR-3 17.3: the seat's OWN locked weight
            _ => return Some(ValidatorError::NotBonded),
        };
        // ⛔ §9.3 R1 (lane-harness): a re-bond only RAISES the weight. A lower one would hand the locked value back as change
        // at once — an exit with no unbond, no window, nothing for a slash to burn.
        if weight <= old {
            return Some(ValidatorError::BondBelowFloor { bond: weight, floor: old.saturating_add(1) });
        }
        None
    }
    /// Every finality seat, for the snapshot.
    pub fn finality_seats(&self) -> Vec<([u8; 32], u128)> {
        let mut v: Vec<([u8; 32], u128)> = self.finality_bonds.iter().map(|(k, w)| (*k, *w)).collect();
        v.sort();
        v
    }

    pub fn import_finality_state(&mut self, seats: Vec<([u8; 32], u128)>) {
        self.finality_bonds = seats.into_iter().collect();
        self.total_finality = self.finality_bonds.values().fold(0u128, |a, b| a.saturating_add(*b));
    }

    /// The set of currently-bonded validator ids (bond > 0). Used by the peer directory's eclipse-resistance
    /// admission: a snapshot the caller can test against without holding a borrow on the whole set, so a peer's
    /// signer `H(pubkey)` can be checked for "is this a stake-backed anchor?".
    pub fn bonded_ids(&self) -> std::collections::HashSet<[u8; 32]> {
        self.seated_ids()
    }

    /// ⭐ THE CUSTODY SET — ids holding a SAT custody bond (`bonds` > 0), exactly the set [`Self::is_bonded_custodian`] admits.
    /// A free membership seat carries finality weight and NO custody weight (SATOSHI §6; custody is SAT-only, user 2026-10-07),
    /// so it is in `bonded_ids` (every seat) and never here. Every custody rotation and quorum reads this.
    pub fn custody_ids(&self) -> std::collections::HashSet<[u8; 32]> {
        self.bonds.iter().filter(|(_, &b)| b > 0).map(|(id, _)| *id).collect()
    }

    /// ⭐ SAFE AT SCALE — the bonded custodians in SENIORITY order: the height each custody bond became active
    /// (`bond_active_from`, carried by the snapshot and the certified bundle with the bond), then the id. The one
    /// order [`Self::custody_vaults`] cuts; the same custodians [`Self::custody_ids`] names.
    /// cons: one sort of the bonded custodians per call (n log n, n = the bonded set); nothing stored.
    pub fn custody_by_seniority(&self) -> Vec<[u8; 32]> {
        let mut v: Vec<(u64, [u8; 32])> =
            self.bonds.iter().filter(|(_, &b)| b > 0).map(|(id, _)| (self.bond_active_from.get(id).copied().unwrap_or(0), *id)).collect();
        v.sort_unstable();
        v.into_iter().map(|(_, id)| id).collect()
    }

    /// ⭐ SAFE AT SCALE — THE CUSTODY VAULTS of the bonded set, by SEAT (`custody_vaults::by_seats`): vault k is the
    /// custodians on seats 16k … 16k + 15, each list sorted by id, an empty vault keeping its index. A bond takes a
    /// seat by the draw and a leave frees one (`admit_active_from_drawn`, `remove_exiting_at`), so a bond changes one
    /// vault — two when a full vault must split — and a leave one, whatever the bonded set: a vault's ledgers, openings
    /// and foreign keys are never reshuffled by a stranger's bond. The seats travel with the set (snapshot, certified bundle, bond journal), so a node that holds
    /// the validator set holds the vaults. Up to 16 custodians bonded in order are one vault — the whole custody set,
    /// as it was. BORROWED: THORChain's Asgard vault membership (a node belongs to one vault until it churns out).
    /// ⭐ THE CUT IS LIVE (`custody_vaults::CUT_LIVE`, 2026-11-12): a changed vault's coins follow its members (the foreign
    /// wallets are re-keyed and swept) and a merged vault's coins follow its ledgers, so this answers the seated cut. The
    /// one-vault branch below stays for a chain that turns the switch off (`custody_vaults::cut_live`).
    pub fn custody_vaults(&self) -> Vec<Vec<[u8; 32]>> {
        if !crate::custody_vaults::cut_live() {
            let mut all: Vec<[u8; 32]> = self.bonds.iter().filter(|(_, &b)| b > 0).map(|(id, _)| *id).collect();
            if all.is_empty() {
                return Vec::new();
            }
            all.sort_unstable();
            return vec![all];
        }
        // the seated cut: vault k is the custodians on seats 16k … 16k + 15 (`custody_vaults::by_seats`)
        let seats: Vec<(u64, [u8; 32])> = self.bonds.iter().filter(|(_, &b)| b > 0).filter_map(|(id, _)| self.custody_seat.get(id).map(|s| (*s, *id))).collect();
        crate::custody_vaults::by_seats(&seats)
    }

    /// ⭐ R5 (spec §3f.2) — the occupied seats of vault `vault`, ascending: what a rotation's draw picks from
    /// (`custody_vaults::mix_seats`). Empty while the cut is not live (one vault: nothing to mix with).
    pub fn custody_seats_of_vault(&self, vault: u32) -> Vec<u64> {
        if !crate::custody_vaults::cut_live() {
            return Vec::new();
        }
        let mut seats: Vec<u64> = self
            .bonds
            .iter()
            .filter(|(_, &b)| b > 0)
            .filter_map(|(id, _)| self.custody_seat.get(id).copied())
            .filter(|s| crate::custody_vaults::vault_of_seat(*s) == vault as usize)
            .collect();
        seats.sort_unstable();
        seats
    }

    /// ⭐ R5 (spec §3f.2) — THE MIX: the bonded custodians on each pair of seats exchange seats. A pair either of whose
    /// seats no bonded custodian holds is left alone (the draw only names occupied seats; this keeps a stale pair from
    /// moving anyone). Sizes do not change: each vault gives and takes one custodian per pair. The seat is part of each
    /// custodian's `VidState`, so the bond step's journal — which diffs every custodian's state — rewinds a mix with the
    /// fold step that made it. Returns how many pairs swapped.
    /// CHAIN-OBJECT: no object names the seats — the pairs are the consequence, at one fold step, of chain state every
    /// node holds (`Node::vault_rotations_at_fold`), applied inside that step's bond journal.
    pub fn swap_custody_seats(&mut self, pairs: &[(u64, u64)]) -> usize {
        let mut done = 0usize;
        for (x, y) in pairs {
            let holder = |set: &Self, seat: u64| set.custody_seat.iter().find(|(id, s)| **s == seat && set.bonds.get(*id).is_some_and(|b| *b > 0)).map(|(id, _)| *id);
            let (Some(a), Some(b)) = (holder(self, *x), holder(self, *y)) else { continue };
            if a == b {
                continue;
            }
            self.custody_seat.insert(a, *y);
            self.custody_seat.insert(b, *x);
            done += 1;
        }
        done
    }

    /// The members of the vault `id` sits in, sorted by id — `None` when `id` holds no custody seat.
    pub fn custody_vault_of(&self, id: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
        if !self.is_bonded_custodian(id) {
            return None;
        }
        self.custody_vaults().into_iter().find(|v| v.binary_search(id).is_ok())
    }

    /// The index of the vault `id` sits in — `None` when `id` holds no custody seat.
    pub fn custody_vault_index_of(&self, id: &[u8; 32]) -> Option<u32> {
        if !self.is_bonded_custodian(id) {
            return None;
        }
        self.custody_vaults().iter().position(|v| v.binary_search(id).is_ok()).and_then(|i| u32::try_from(i).ok())
    }

    /// ⭐ SAFE AT SCALE — WHICH VAULT TAKES ON VAULT `from`'S LEDGERS WHEN IT MERGES (`Class::VaultMerge`): the other
    /// vault with the most members, the lowest index among equals — the vault best able to stand behind more — and
    /// ONLY WHEN IT OUTRANKS `from` (more members; or as many and a lower index). `None` when no other vault outranks
    /// it (nothing better to merge into: the ledgers stay where they are, and the chain behaves as it did before
    /// vaults). So ledgers move toward the strongest vault and stop there.
    /// FOUND 2026-11-11 by the lifecycle model (`models/custody-lifecycle`, its `any_other_vault_takes` calibration)
    /// before the merge lane was built: under "any other vault with a member", two thin vaults hand the same ledgers
    /// back and forth — A merges into B; B is then thin with moved ledgers and merges into A — a foreign sweep fee
    /// each time, for ever, and a custodian of the stronger of the two could never leave.
    /// One rule every custodian reads from its own chain's set, so both vaults' signers name the same pair. The ledger
    /// door does not enforce the choice (it demands both vaults' quorums, whichever pair signs): the rule is how honest
    /// custodians agree, never what makes a merge safe.
    pub fn custody_merge_target(&self, from: u32) -> Option<u32> {
        let vaults = self.custody_vaults();
        let from = usize::try_from(from).ok()?;
        let rank = |i: usize| (vaults.get(i).map_or(0, Vec::len), std::cmp::Reverse(i));
        let (best, _) = vaults.iter().enumerate().filter(|(i, v)| *i != from && !v.is_empty()).max_by_key(|(i, _)| rank(*i))?;
        if rank(best) <= rank(from) {
            return None;
        }
        u32::try_from(best).ok()
    }

    /// What the vault of `members` may hold (`custody_vaults::cover`): three quarters of its cheapest quorum's bond.
    pub fn custody_vault_cover(&self, members: &[[u8; 32]]) -> u128 {
        let bonds: Vec<u128> = members.iter().map(|m| self.bond_of(m)).collect();
        crate::custody_vaults::cover(&bonds)
    }

    /// The reserve CUSTODY GROUP commitment — the bond-weighted multisig tally's member set — a deterministic digest binding the EXACT bonded quorum (its
    /// sorted member ids + each bond + the total). A Buy-USDm atomic-swap deposit address is derived from this,
    /// so the reserve is controllable ONLY by that t-of-n threshold set — never a solo key (decentralization
    /// pillar). Empty set → `None` (no quorum): the caller MUST fail-closed and derive NO address, because a
    /// fabricated deposit address would lose the user's real funds.
    pub fn custody_group_commit(&self) -> Option<[u8; 32]> {
        if self.bonds.is_empty() {
            return None;
        }
        let mut members: Vec<(&[u8; 32], u128)> = self.bonds.iter().map(|(k, v)| (k, *v)).collect();
        members.sort_by(|a, b| a.0.cmp(b.0));
        let mut pre: Vec<u8> = Vec::with_capacity(32 + 16 + members.len() * 48);
        pre.extend_from_slice(b"USDMD-FROST-RESERVE-GROUP-v1");
        pre.extend_from_slice(&(members.len() as u64).to_le_bytes());
        pre.extend_from_slice(&self.total_bond.to_le_bytes());
        for (id, bond) in &members {
            pre.extend_from_slice(*id);
            pre.extend_from_slice(&bond.to_le_bytes());
        }
        Some(crate::hash::Hash32::hash(&pre).0)
    }

    /// The member-count threshold shown to users as "t-of-n" (⌊2n/3⌋+1). The ≥2/3-BY-BONDED-WEIGHT gate is the
    /// real authorization enforced in [`crate::psm::authorize_mint`]; this is the human-readable quorum size.
    pub fn custody_threshold(&self) -> usize {
        let n = self.bonds.len();
        if n == 0 {
            0
        } else {
            (n * 2) / 3 + 1
        }
    }

    /// ⭐ EXPORT the set's full value-bearing state for the node snapshot, DETERMINISTICALLY (sorted by
    /// id, so two saves of one state are byte-identical). The bonded set survives a restart the same way
    /// `bond_locked` always has — before this, EVERY restart emptied `validators`, the resumed node
    /// rejected all finality votes at `bond_of(voter)==0`, and finality died until a fresh bond landed
    /// (the doc note "rebuilt from its bond notes on load" described a rebuild that was never written;
    /// the snapshot IS that load path now). O(validators) — bounded by the CURRENT set, never by history.
    #[allow(clippy::type_complexity)]
    pub fn export_state(
        &self,
    ) -> (
        Vec<([u8; 32], u128)>,
        Vec<[u8; 32]>,
        u128,
        crate::spend_frontier::Digest4,
        Vec<([u8; 32], Vec<u8>, [u8; 32])>,
    ) {
        let mut bonds: Vec<([u8; 32], u128)> = self.bonds.iter().map(|(k, v)| (*k, *v)).collect();
        bonds.sort_by(|a, b| a.0.cmp(&b.0));
        let mut slashed: Vec<[u8; 32]> = self.slashed.iter().copied().collect();
        slashed.sort();
        let mut custody: Vec<([u8; 32], Vec<u8>, [u8; 32])> = self
            .custody
            .iter()
            .map(|(k, c)| (*k, c.secp33.clone(), c.ed32))
            .collect();
        custody.sort_by(|a, b| a.0.cmp(&b.0));
        (
            bonds,
            slashed,
            self.slashed_bond_burned,
            self.bond_commit,
            custody,
        )
    }

    /// Restore the custodian encapsulation keys a snapshot carried (beside `import_state`; only ids that are
    /// bonded after the import are kept, so a stale ek never outlives its seat).
    pub fn import_kem_eks(&mut self, eks: Vec<([u8; 32], Vec<u8>)>) {
        self.kem_eks.clear();
        for (id, ek) in eks {
            self.register_custody_kem(id, ek);
        }
    }

    /// IMPORT the exact state a snapshot carried (the inverse of [`Self::export_state`]) — a direct
    /// restore, never re-admission: the floor was enforced when each bond was ADMITTED, and re-judging an
    /// old bond against a newer floor on every reboot would silently evict live validators. Totals are
    /// recomputed from the restored bonds (one source of truth, nothing double-counted).
    pub fn import_state(
        &mut self,
        bonds: Vec<([u8; 32], u128)>,
        slashed: Vec<[u8; 32]>,
        slashed_bond_burned: u128,
        bond_commit: crate::spend_frontier::Digest4,
        custody: Vec<([u8; 32], Vec<u8>, [u8; 32])>,
    ) {
        self.bonds = bonds.into_iter().collect();
        self.total_bond = self.bonds.values().fold(0u128, |a, b| a.saturating_add(*b));
        // SAFE AT SCALE: a seat row never outlives its bond; `import_custody_seats` installs the carried seats next (a
        // carrier without them leaves every custodian seated in seniority order, the same on every node that reads it)
        let bonded = &self.bonds;
        self.custody_seat.retain(|id, _| bonded.contains_key(id));
        self.seat_the_unseated();
        self.slashed = slashed.into_iter().collect();
        self.slashed_bond_burned = slashed_bond_burned;
        self.bond_commit = bond_commit;
        self.custody = custody
            .into_iter()
            .map(|(id, secp33, ed32)| (id, BridgeCustody { secp33, ed32 }))
            .collect();
    }

    /// Admit a validator if its bond meets the current adaptive floor. Fail-closed. Active for finality from height 0 — a
    /// GENESIS / FIXTURE seat; the chain's SAT-bond door seats with [`Self::admit_active_from`] (G2b).
    pub fn admit(
        &mut self,
        id: [u8; 32],
        bond: u128,
        bridge_tvl: u128,
    ) -> Result<(), ValidatorError> {
        self.admit_active_from(id, bond, bridge_tvl, 0)
    }

    /// ⭐ G2b — admit custody weight that counts toward finality votes at heights `>= active_from`. A FIXTURE's or a
    /// rebuilt set's seat: the draw under zero randomness (the chain's bond step seats through
    /// [`Self::admit_active_from_drawn`], with the folded block's id).
    pub fn admit_active_from(
        &mut self,
        id: [u8; 32],
        bond: u128,
        bridge_tvl: u128,
        active_from: u64,
    ) -> Result<(), ValidatorError> {
        self.admit_active_from_drawn(id, bond, bridge_tvl, active_from, &[0u8; 32])
    }

    /// [`Self::admit_active_from`] with the chain randomness its custody seat is drawn under (`custody_vaults::draw_seat`).
    pub fn admit_active_from_drawn(
        &mut self,
        id: [u8; 32],
        bond: u128,
        bridge_tvl: u128,
        active_from: u64,
        entropy: &[u8; 32],
    ) -> Result<(), ValidatorError> {
        if let Some(e) = self.admit_refusal(&id, bond, bridge_tvl) {
            return Err(e);
        }
        // §BR-3 17.3: a re-seated id's outstanding delegations count again on top of its own bond
        let weight = bond.saturating_add(self.delegated_to(&id));
        self.total_bond = self.total_bond.saturating_add(weight);
        self.bonds.insert(id, weight);
        self.bond_active_from.insert(id, active_from);
        self.draw_custody_seat(id, entropy);
        Ok(())
    }

    /// ⭐ SAFE AT SCALE — SEAT A NEW CUSTODIAN BY THE DRAW (`custody_vaults::draw_seat`): a seat among the free seats of
    /// vaults that already hold eight members, drawn under `entropy` and the custodian's own id; when no such seat
    /// exists a full vault is split and the eight members the draw names move with it. The moved members' seats are
    /// part of their `VidState`, so the bond step's journal (which diffs every custodian's state) rewinds a split with
    /// the bond that caused it.
    fn draw_custody_seat(&mut self, id: [u8; 32], entropy: &[u8; 32]) {
        let taken: std::collections::BTreeSet<u64> = self.custody_seat.iter().filter(|(k, _)| **k != id && self.bonds.contains_key(*k)).map(|(_, s)| *s).collect();
        let mut h = blake3::Hasher::new_derive_key("MonerousD custody seat entropy v1");
        h.update(entropy);
        h.update(&id);
        let seating = crate::custody_vaults::draw_seat(&taken, h.finalize().as_bytes());
        for (old, new) in &seating.moved {
            if let Some(who) = self.custody_seat.iter().find(|(k, s)| **s == *old && self.bonds.contains_key(*k)).map(|(k, _)| *k) {
                self.custody_seat.insert(who, *new);
            }
        }
        self.custody_seat.insert(id, seating.seat);
    }

    /// The seat a custodian admitted now would take: the lowest number no bonded custodian holds.
    fn lowest_free_custody_seat(&self) -> u64 {
        let taken: std::collections::BTreeSet<u64> = self.custody_seat.iter().filter(|(id, _)| self.bonds.contains_key(*id)).map(|(_, s)| *s).collect();
        crate::custody_vaults::lowest_free_seat(&taken)
    }

    /// ⭐ SAFE AT SCALE — every bonded custodian's seat, sorted by id: what the snapshot carries and the bundle certifies
    /// beside the seats (as `seat_activations` carries their activation heights).
    pub fn custody_seats(&self) -> Vec<([u8; 32], u64)> {
        let mut v: Vec<([u8; 32], u64)> = self.custody_seat.iter().filter(|(id, _)| self.bonds.contains_key(*id)).map(|(id, s)| (*id, *s)).collect();
        v.sort_unstable();
        v
    }

    /// The inverse of [`Self::custody_seats`], run AFTER the seats themselves were imported: a row is kept only for a
    /// bonded id and only on a seat no earlier row took; a bonded custodian left without one — a carrier from before
    /// seats, a refused row — takes the lowest free seat in seniority order (activation height, then id), the same on
    /// every node that reads the same carrier.
    pub fn import_custody_seats(&mut self, rows: Vec<([u8; 32], u64)>) {
        self.custody_seat.clear();
        let mut taken: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for (id, seat) in rows {
            if self.bonds.contains_key(&id) && !self.custody_seat.contains_key(&id) && taken.insert(seat) {
                self.custody_seat.insert(id, seat);
            }
        }
        self.seat_the_unseated();
    }

    /// Give every bonded custodian that holds no seat the lowest free one, in seniority order.
    fn seat_the_unseated(&mut self) {
        let mut unseated: Vec<(u64, [u8; 32])> = self
            .bonds
            .keys()
            .filter(|id| !self.custody_seat.contains_key(*id))
            .map(|id| (self.bond_active_from.get(id).copied().unwrap_or(0), *id))
            .collect();
        unseated.sort_unstable();
        for (_, id) in unseated {
            let seat = self.lowest_free_custody_seat();
            self.custody_seat.insert(id, seat);
        }
    }

    /// The ONE admission rule, read without moving anything ([`Self::admit`] applies it): `None` = admissible.
    pub fn admit_refusal(&self, id: &[u8; 32], bond: u128, bridge_tvl: u128) -> Option<ValidatorError> {
        if self.slashed.contains(id) {
            // A slashed (equivocating) validator is barred forever — no re-admission with a fresh bond.
            return Some(ValidatorError::Slashed);
        }
        if self.bonds.contains_key(id) {
            return Some(ValidatorError::AlreadyBonded);
        }
        let floor = required_bond_floor(bridge_tvl);
        if bond < floor {
            return Some(ValidatorError::BondBelowFloor { bond, floor });
        }
        None
    }

    /// Remove a validator's bond from the set (unbond / withdraw), decrementing the total bonded weight. Returns
    /// the freed bond, or None if it wasn't bonded. Its finality/governance weight stops counting at ONCE, at every
    /// height — a FIXTURE exit; the chain's unbond door exits with [`Self::remove_exiting_at`] (G2b).
    pub fn remove(&mut self, id: &[u8; 32]) -> Option<u128> {
        self.remove_exiting_at(id, None)
    }

    /// ⭐ G2b — remove both seats; with `Some(active_until)` each seat leaves a departed row that still weighs on votes at
    /// heights below it (its activation height carried over), so two nodes whose folds stand on either side of the exit
    /// judge a vote at `h` against the same set. `None` = the seat vanishes at every height (a fixture's exit).
    pub fn remove_exiting_at(&mut self, id: &[u8; 32], active_until: Option<u64>) -> Option<u128> {
        // both seats leave together: a validator is one identity whichever asset it bonded
        let custody = self.bonds.remove(id);
        let finality = self.finality_bonds.remove(id);
        if custody.is_none() && finality.is_none() {
            return None;
        }
        self.custody.remove(id); // a departed/slashed validator leaves the reserve key-aggregate immediately
        // §BR-3 17.3: the delegated WORD stays (its notes still exist); the weight leaves the tally with `bonds` above
        self.kem_eks.remove(id); // …and is sealed to no more
        let custody_from = self.bond_active_from.remove(id).unwrap_or(0);
        self.custody_seat.remove(id); // SAFE AT SCALE: its custody seat is free for the next bond (its own vault alone changes)
        let finality_from = self.finality_active_from.remove(id).unwrap_or(0);
        let mut gone: u128 = 0;
        if let Some(b) = custody {
            self.total_bond = self.total_bond.saturating_sub(b);
            gone = gone.saturating_add(b);
            if let Some(until) = active_until {
                if custody_from < until {
                    self.departed_bond.insert(*id, DepartedSeat { weight: b, active_from: custody_from, active_until: until });
                }
            }
        }
        if let Some(f) = finality {
            self.total_finality = self.total_finality.saturating_sub(f);
            gone = gone.saturating_add(f);
            if let Some(until) = active_until {
                if finality_from < until {
                    self.departed_finality
                        .insert(*id, DepartedSeat { weight: f, active_from: finality_from, active_until: until });
                }
            }
        }
        Some(gone)
    }

    /// SLASH a validator for a PROVABLE protocol fault (equivocation — double-signing finality votes
    /// for two different blocks at the same height). Removes its bond from the set (its finality +
    /// governance weight stops counting immediately), FORFEITS that bond (burned — never returned to
    /// the validator), and records the id as permanently slashed so it can never re-admit. Returns the
    /// burned amount, or `None` if it wasn't bonded. This is what makes a stake-based finality attack
    /// cost money: a double-signer loses its stake, it doesn't just get ignored.
    pub fn slash(&mut self, id: &[u8; 32]) -> Option<u128> {
        self.slash_exiting_at(id, None)
    }

    /// ⭐ G2b — the slash at its canonical exit height: the weight leaves the numerator at every height at once (a slashed
    /// id weighs nothing, [`Self::finality_weight_of_at`]) and stays in the denominator until `active_until`, so a quorum
    /// judged by a node that has not folded the slash yet and one that has read the same ratio.
    pub fn slash_exiting_at(&mut self, id: &[u8; 32], active_until: Option<u64>) -> Option<u128> {
        let bond = self.remove_exiting_at(id, active_until)?;
        self.slashed.insert(*id);
        self.delegated.remove(id); // §BR-3 17.4: the delegations are burned with the seat
        self.own_yield.remove(id); // §BR-3 17.6: and its unclaimed own yield
        self.slashed_bond_burned = self.slashed_bond_burned.saturating_add(bond);
        Some(bond)
    }

    /// ⭐ §22 5 — OPERATOR-FIRST SLASH for misbehaviour that loses no one's money (equivocation, epoch-key fraud): the seat
    /// leaves exactly as [`Self::slash_exiting_at`] takes it out, the id is barred forever, and only the OPERATOR's own weight
    /// is burned — the delegated word stays, so every delegator undelegates through the ordinary unbonding
    /// ([`Self::undelegate_refusal`]). The split is `validator_activity::slash_split` (Kani-proven to conserve). Returns the
    /// own weight burned.
    pub fn slash_operator_first_exiting_at(&mut self, id: &[u8; 32], active_until: Option<u64>) -> Option<u128> {
        let delegated = self.delegated_to(id);
        let gone = self.remove_exiting_at(id, active_until)?;
        let s = crate::validator_activity::slash_split(
            gone.saturating_sub(delegated),
            delegated.min(gone),
            crate::validator_activity::SlashCause::NoLoss,
        );
        self.slashed.insert(*id);
        self.own_yield.remove(id); // §BR-3 17.6: its unclaimed own yield goes with the operator
        self.slashed_bond_burned = self.slashed_bond_burned.saturating_add(s.own_burned);
        Some(s.own_burned)
    }

    /// ⭐ §22 5 — the operator-first slash of a validator already UNBONDING (its weight `amount` left the set at the unbond,
    /// delegated part included): barred forever, its own part burned, the delegated word kept. Returns the own part.
    pub fn mark_slashed_operator_first(&mut self, id: [u8; 32], amount: u128) -> u128 {
        let own = amount.saturating_sub(self.delegated_to(&id));
        self.slashed.insert(id);
        self.own_yield.remove(&id);
        self.slashed_bond_burned = self.slashed_bond_burned.saturating_add(own);
        own
    }

    /// ⭐ DB-274 P2 (§8.7) — slash a validator whose weight ALREADY left the set (it is unbonding): the id is barred
    /// forever and `amount` (its weight at the unbond) counts as burned. The unbonding collateral itself is dropped by
    /// the caller, so it never returns.
    pub fn mark_slashed(&mut self, id: [u8; 32], amount: u128) {
        self.slashed.insert(id);
        self.delegated.remove(&id); // §BR-3 17.4: the delegations are burned with the seat
        self.own_yield.remove(&id); // §BR-3 17.6: and its unclaimed own yield
        self.slashed_bond_burned = self.slashed_bond_burned.saturating_add(amount);
    }

    /// ⭐ DB-274 P2 (§8.7) — everything this set holds for ONE validator, the unit a fold step's journal restores.
    pub fn vid_state(&self, id: &[u8; 32]) -> VidState {
        VidState {
            bond: self.bonds.get(id).copied(),
            finality: self.finality_bonds.get(id).copied(),
            custody: self.custody.get(id).map(|c| (c.secp33.clone(), c.ed32)),
            kem_ek: self.kem_eks.get(id).cloned(),
            slashed: self.slashed.contains(id),
            bond_active_from: self.bond_active_from.get(id).copied(),
            finality_active_from: self.finality_active_from.get(id).copied(),
            departed_bond: self.departed_bond.get(id).copied(),
            departed_finality: self.departed_finality.get(id).copied(),
            custody_seat: self.custody_seat.get(id).copied(),
            delegated: self.delegated.get(id).copied(),
            own_yield: self.own_yield.get(id).copied(),
        }
    }

    /// ⭐ DB-274 P2 (§8.7) — put ONE validator back exactly as [`Self::vid_state`] read it; `total_bond` follows.
    pub fn set_vid_state(&mut self, id: [u8; 32], s: VidState) {
        if let Some(old) = self.bonds.remove(&id) {
            self.total_bond = self.total_bond.saturating_sub(old);
        }
        if let Some(b) = s.bond {
            self.bonds.insert(id, b);
            self.total_bond = self.total_bond.saturating_add(b);
        }
        if let Some(old) = self.finality_bonds.remove(&id) {
            self.total_finality = self.total_finality.saturating_sub(old);
        }
        if let Some(f) = s.finality {
            self.finality_bonds.insert(id, f);
            self.total_finality = self.total_finality.saturating_add(f);
        }
        match s.custody {
            Some((secp33, ed32)) => {
                self.custody.insert(id, BridgeCustody { secp33, ed32 });
            }
            None => {
                self.custody.remove(&id);
            }
        }
        match s.kem_ek {
            Some(ek) => {
                self.kem_eks.insert(id, ek);
            }
            None => {
                self.kem_eks.remove(&id);
            }
        }
        if s.slashed {
            self.slashed.insert(id);
        } else {
            self.slashed.remove(&id);
        }
        // G2b: the view at a height follows the seat
        for (map, v) in [(&mut self.bond_active_from, s.bond_active_from), (&mut self.finality_active_from, s.finality_active_from)] {
            match v {
                Some(h) => {
                    map.insert(id, h);
                }
                None => {
                    map.remove(&id);
                }
            }
        }
        for (map, v) in [(&mut self.departed_bond, s.departed_bond), (&mut self.departed_finality, s.departed_finality)] {
            match v {
                Some(d) => {
                    map.insert(id, d);
                }
                None => {
                    map.remove(&id);
                }
            }
        }
        // SAFE AT SCALE: the custody seat comes back with the seat it numbers. A custody weight restored with no seat (a
        // journal row from before seats) takes the lowest free one, as an admission does.
        match s.custody_seat {
            Some(n) if self.bonds.contains_key(&id) => {
                self.custody_seat.insert(id, n);
            }
            _ => {
                self.custody_seat.remove(&id);
                if self.bonds.contains_key(&id) {
                    let n = self.lowest_free_custody_seat();
                    self.custody_seat.insert(id, n);
                }
            }
        }
        // §BR-3 17.3: the delegated part comes back with the seat
        match s.delegated {
            Some(d) => {
                self.delegated.insert(id, d);
            }
            None => {
                self.delegated.remove(&id);
            }
        }
        match s.own_yield {
            Some(w) => {
                self.own_yield.insert(id, w);
            }
            None => {
                self.own_yield.remove(&id);
            }
        }
    }

    /// ⭐ DB-274 P2 (§8.7) — the set-level scalars a fold step can move: the burned total and the confidential
    /// bonded-stake commitment.
    pub fn scalars(&self) -> (u128, crate::spend_frontier::Digest4) {
        (self.slashed_bond_burned, self.bond_commit)
    }

    /// ⭐ DB-274 P2 (§8.7) — restore what [`Self::scalars`] read.
    pub fn set_scalars(&mut self, burned: u128, commit: crate::spend_frontier::Digest4) {
        self.slashed_bond_burned = burned;
        self.bond_commit = commit;
    }

    /// Every validator id this set holds anything for (bonded, custody, KEM key or slashed), sorted.
    pub fn every_vid(&self) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = self
            .bonds
            .keys()
            .chain(self.finality_bonds.keys())
            .chain(self.custody.keys())
            .chain(self.kem_eks.keys())
            .chain(self.slashed.iter())
            .chain(self.departed_bond.keys()) // G2b: a departed row is part of the view a fold step can move
            .chain(self.departed_finality.keys())
            .copied()
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Whether `id` has been permanently slashed for equivocation.
    pub fn is_slashed(&self, id: &[u8; 32]) -> bool {
        self.slashed.contains(id)
    }

    /// Total bond burned via slashing (left the bonded weight forever).
    pub fn slashed_bond_burned(&self) -> u128 {
        self.slashed_bond_burned
    }

    /// The set's persisted CONFIDENTIAL bonded-stake commitment — the value-hiding Poseidon digest of the total
    /// bonded weight. An opaque 4-limb digest; a re-executing node reads NO stake total from it.
    pub fn bond_commit(&self) -> crate::spend_frontier::Digest4 {
        self.bond_commit
    }

    /// Seed the confidential bonded-stake commitment at cutover: the value-hiding digest of the genuine current
    /// total bonded weight. A generic node receives this opaque digest, never the total.
    pub fn initialize_bond_commitment(&mut self, bond_commit: crate::spend_frontier::Digest4) {
        self.bond_commit = bond_commit;
    }

    /// #75 brick 4 — VERIFY a confidential bond ADMIT: the custodian/validator's WHIR-bound
    /// [`usdm_decider::confidential_solvency::verify_bond_transition_carrier`] proof that
    /// `open(current_bond_commit) + bond == open(new_bond_commit)` (conservation over the HIDDEN stake totals),
    /// against the set's OWN persisted commitment. The node never learns a stake total. On admit the SMALLER
    /// total is the current one (`a`), the LARGER is the new one (`s`).
    /// ⛔ DELTA-BOUND (free-witness census, 2026-09-29): the carrier states `[current, delta, new]` and the delta is
    /// the commitment of the bond itself. The earlier verifier bound only `(current, new)`, so ANY delta satisfied it
    /// — the conservation named no bond at all.
    #[must_use]
    pub fn verify_bond_admit(
        &self,
        carrier_bytes: &[u8],
        delta_commit: crate::spend_frontier::Digest4,
        new_bond_commit: crate::spend_frontier::Digest4,
    ) -> bool {
        usdm_decider::confidential_solvency::verify_transition_carrier(
            carrier_bytes,
            &[self.bond_commit, delta_commit, new_bond_commit],
            usdm_decider::confidential_solvency::TransitionDomain::Bond,
        )
    }

    /// #75 brick 4 — VERIFY a confidential bond REDUCE (unbond / slash): the proof that
    /// `open(new_bond_commit) + bond == open(current_bond_commit)` — the reduction read as a conservation where
    /// the SMALLER total is the new one (`a`) and the LARGER is the current one (`s`). Fail-closed like admit.
    #[must_use]
    pub fn verify_bond_reduce(
        &self,
        carrier_bytes: &[u8],
        delta_commit: crate::spend_frontier::Digest4,
        new_bond_commit: crate::spend_frontier::Digest4,
    ) -> bool {
        usdm_decider::confidential_solvency::verify_transition_carrier(
            carrier_bytes,
            &[new_bond_commit, delta_commit, self.bond_commit],
            usdm_decider::confidential_solvency::TransitionDomain::Bond,
        )
    }

    /// ⛔ SELF-PROOF ONLY — a bonded WEIGHT the membership does not account for.
    ///
    /// `total_bond` is the DENOMINATOR of every ≥2/3 gate in this tree: finality
    /// ([`FinalityTracker::record_verified_vote`]) and the peg's mint/redeem authorisation both ask
    /// `weight * 3 >= 2 * total_bond`. Every public door keeps it in step with `bonds`
    /// (admit/remove/import all recompute or adjust it together), so the ONLY way to build the state
    /// where the membership agrees and the denominator does not is to write it — and that state must
    /// be constructible, or the comparison over `total_bond` in
    /// `harness::fuzz::authority_book` would be a claim nobody has made go red. A node holding a
    /// SMALLER total finalises on less than two-thirds of the real bonded weight; a node holding a
    /// larger one refuses a quorum the mesh accepted.
    ///
    /// Nothing but that refutation lane may call it, and the name says so at the call site.
    #[cfg(test)]
    pub fn force_total_bond_for_selfproof(&mut self, total: u128) {
        self.total_bond = total;
    }

    /// The finality twin of [`Self::force_total_bond_for_selfproof`] (SATOSHI §6): moves ONLY the finality denominator's
    /// seat part, so `harness::fuzz::authority_book` can prove its `total_finality` comparison fires. Refutation lane only.
    #[cfg(test)]
    pub fn force_total_finality_for_selfproof(&mut self, total: u128) {
        self.total_finality = total;
    }

    /// Advance the persisted bonded-stake commitment to the proof's NEW digest. MUST be called ONLY after
    /// [`Self::verify_bond_admit`] / [`Self::verify_bond_reduce`] accepts — the node swaps the opaque digest and
    /// learns no stake. The confidential analogue of `total_bond += bond` / `total_bond -= bond`.
    pub fn apply_bond_transition(&mut self, new_bond_commit: crate::spend_frontier::Digest4) {
        self.bond_commit = new_bond_commit;
    }
}

impl Default for ValidatorSet {
    fn default() -> Self {
        Self::new()
    }
}

/// ⭐ Seat the launch's founding custodians in a new set: bonded, active from the first block, their signed custody keys registered. A genesis fact on every node
/// (`defi_launch::genesis_seats`, verified at boot). `false` only if the set refuses a seat, which its rule cannot on an empty set of distinct ids.
pub fn seat_founders(set: &mut ValidatorSet, seats: &[([u8; 32], u64, crate::defi_launch::FoundingSeat, Vec<u8>)]) -> bool {
    let mut all = true;
    for (vid, weight, seat, ek) in seats {
        if set.admit_active_from(*vid, u128::from(*weight), 0, 0).is_err() {
            all = false;
            continue;
        }
        set.register_custody(*vid, seat.secp33.clone(), seat.ed32);
        set.register_custody_kem(*vid, ek.clone());
    }
    all
}

/// The result of recording a PQ-verified finality vote.
#[derive(Debug, PartialEq, Eq)]
pub enum VoteRecord {
    /// This vote pushed the block to finality (≥2/3 bonded weight).
    Finalized,
    /// Counted toward the block's tally, but the block is not final yet.
    Counted,
    /// EQUIVOCATION: this voter ALREADY signed a DIFFERENT block at the SAME height — a provable
    /// double-sign fault. The vote is NOT counted, and the caller MUST slash the voter (`first_block`
    /// is the earlier block it voted, evidence of the conflict).
    Equivocation { first_block: BlockId },
    /// The voter carries no bonded weight (unbonded or already slashed) — vote ignored.
    NoWeight,
    /// ⭐ G2b — NOT JUDGED YET: this node's fold cursor stands below `height − FINALITY_SEAT_ACTIVATION_DELAY`, so a seat
    /// or exit that counts at this height may not have been applied here. The node keeps the verified vote
    /// (`Node::deferred_votes`) and judges it once its fold reaches that height — never against a set it cannot yet know.
    Deferred,
}

/// Votes for heights more than this far below the finalized height are neither counted nor kept:
/// the tally's footprint is `FINALITY_VOTE_RETENTION × validators` rows, never the chain's history.
pub const FINALITY_VOTE_RETENTION: u64 = 4096;

/// `MONEROUSD_FINALITY_TRACE=1` prints every finality vote cast and received (a diagnosis lane the
/// real-node harness turns on; off by default — a vote a second per validator would be console noise).
pub fn finality_trace_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("MONEROUSD_FINALITY_TRACE").map(|v| v == "1").unwrap_or(false))
}

/// Accumulates bonded-weight votes per block and advances the finalized height on ≥2/3. Enforces
/// ONE vote per (validator, height): a second, conflicting vote is caught as equivocation → slash.
pub struct FinalityTracker {
    finalized_height: u64,
    /// ⭐ THE FINALIZED BLOCK ITSELF — the identity `finalized_height` alone could never carry.
    ///
    /// A height is a NUMBER; fork choice needs a BLOCK. "Do not select a tip that abandons finalized
    /// history" is a question about ancestry, and ancestry is answered against an id, never against a
    /// counter — two competing branches both have a block at height H. Recorded in lockstep with
    /// `finalized_height` (same monotonic guard, same assignment), so the pair can never disagree
    /// about which block the quorum actually committed.
    ///
    /// `None` until the bonded quorum first crosses ≥2/3. Every consumer MUST treat `None`, and an id
    /// this node does not hold, as "no bound" — see [`crate::dag::Dag::set_finality_floor`].
    finalized_block: Option<BlockId>,
    voters: HashMap<BlockId, HashSet<[u8; 32]>>,
    /// The single block each validator committed to at each height. A later, DIFFERENT block at the
    /// same height is equivocation. `(voter, height) -> the block it first voted`.
    /// Keyed HEIGHT-FIRST (2026-09-18) so a level's votes and the retention cut are range operations.
    ///
    /// ⭐ G1 (lane b 2026-10-24) — THE TALLY HOLDS THE OPEN HEIGHTS ONLY (above `finalized_height`); a finalization moves the
    /// rows at or below it to [`Self::settled`]. Ethereum's fork-choice store prunes its votes below the finalized checkpoint
    /// the same way (proto-array `maybe_prune`): a settled height can never be finalized again, so its rows decide nothing.
    voted_at: std::collections::BTreeMap<(u64, [u8; 32]), BlockId>,
    /// ⭐ G1 (lane b 2026-10-24) — THE SLASHER MEMORY: `(height, voter) -> block` at SETTLED heights, down to the retention
    /// depth, read only to catch a second, conflicting vote as equivocation EVIDENCE (Lighthouse's slasher DB beside its
    /// fork-choice store). The evidence is a chain object verified from its own two certificates
    /// (`equivocation_tx::proves_equivocation`), so which node remembers the first vote decides only which node AUTHORS it,
    /// never whether a slash applies. Local by design: a node holds the votes it folded, and a restart re-folds only its
    /// window — MEASURED (joiner-restart-f1.log): 689 → 45 rows here across a restart while the open tally held 5 → 5, and
    /// three live peers of one chain already held 1014 / 1008 / 689. cons: none — the same rows the one map held, split.
    settled: std::collections::BTreeMap<(u64, [u8; 32]), BlockId>,
    /// ⭐ DB-472 (lane stable 2026-10-30) — THE CERTIFICATE BEHIND EACH OPEN ROW, kept so a fold rewind can hand a vote it
    /// judged back to the deferred queue ([`Self::reopen_above`]). A carried vote is judged against the set active at its
    /// height, which this node knows only once its fold cursor stands at `height − FINALITY_SEAT_ACTIVATION_DELAY`; the
    /// cursor can DROP (a fold root drop), and a row judged above the cursor it stands on now is a verdict this node could not
    /// reach from where it is. MEASURED (stable/c8.log, five replayers at one quiet point, cursor 46 everywhere): the vote
    /// (111, 3d1c77) TALLIED on the three nodes whose cursor had touched 47 before dropping to 46, DEFERRED on the two that
    /// had not — `finality` DIFFERS across honest nodes on one chain. Pruned with the open rows (at or below the finalized
    /// height nothing re-opens). O1-FOOTPRINT-REVIEWED: one certificate per open row — bounded by the open tally itself.
    open_certs: std::collections::BTreeMap<(u64, [u8; 32]), VoteCert>,
}

impl FinalityTracker {
    /// ⛔ SELF-PROOF ONLY — a finality height the chain has not reached.
    ///
    /// Builds the violating state for the finality half of `I-CP`, so that comparison is proven able
    /// to go red rather than assumed. A party ahead here treats as IRREVERSIBLE what the mesh may
    /// still reorg — a payment declared final that can still be undone. Nothing but the refutation
    /// lane may call it.
    #[cfg(test)]
    pub fn force_finalized_height_for_selfproof(&mut self, h: u64) {
        self.finalized_height = h;
    }

    pub fn new() -> Self {
        FinalityTracker {
            finalized_height: 0,
            finalized_block: None,
            voters: HashMap::new(),
            voted_at: std::collections::BTreeMap::new(),
            settled: std::collections::BTreeMap::new(),
            open_certs: std::collections::BTreeMap::new(),
        }
    }

    pub fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// The block the bonded quorum finalized at [`Self::finalized_height`], or `None` before the first
    /// ≥2/3 crossing. This is what fork choice binds to — never the bare height.
    pub fn finalized_block(&self) -> Option<BlockId> {
        self.finalized_block
    }

    /// ⭐ G1 (lane a 2026-10-22) — RE-INSTALL THE FINALIZED CHECKPOINT A RESTART RESTORED. The pair is one function of the
    /// carried votes (G2) and is persisted beside the fold it was derived from (`persist::FoldRecord::finalized` —
    /// Ethereum's `finalized_checkpoint` in the fork-choice store; Tendermint's last commit height): a node whose
    /// finalizing carrier has folded below its window cannot re-derive it from the bodies it still holds, and finality is
    /// MONOTONE — a payment final before a restart is final after it. Monotone here too: installs only ABOVE the current
    /// height (the restored window's re-tally may already stand higher) and prunes the tally rows below retention exactly
    /// as a live finalization does. The caller binds the pair to the chain first (`Node::install_persisted_finality`).
    /// `true` iff installed.
    pub fn install_finalized_checkpoint(&mut self, height: u64, block: BlockId) -> bool {
        if height == 0 || height <= self.finalized_height {
            return false;
        }
        self.finalized_height = height;
        self.finalized_block = Some(block);
        self.prune_below_retention();
        true
    }

    /// Record a vote whose PQ threshold signature the caller has ALREADY verified. Returns a
    /// [`VoteRecord`]: `Finalized` if this vote pushed the block to ≥2/3 bonded weight, `Counted` if
    /// tallied but not yet final, `Equivocation` if this voter already committed a DIFFERENT block at
    /// the SAME height (the caller MUST slash), or `NoWeight` if the voter is unbonded/slashed.
    /// Advancing `finalized_height` is monotonic — it never regresses. A re-vote for the SAME block is
    /// idempotent.
    pub fn record_verified_vote(
        &mut self,
        set: &ValidatorSet,
        block: BlockId,
        block_height: u64,
        voter: [u8; 32],
    ) -> VoteRecord {
        self.record_verified_vote_on_chain(set, block, block_height, voter, true)
    }

    /// ⭐⭐ A-F86 (lane af58, 2026-11-16) — FINALITY ONLY EVER EXTENDS ITS OWN CHAIN. [`Self::record_verified_vote`] with the
    /// caller's verdict `extends_final`: whether `block`'s SELECTED CHAIN passes through this tracker's finalized block
    /// (`Dag::selected_chain_through`). A quorum for a block that does not extend it is COUNTED (the votes are real and
    /// the slasher memory keeps them) but never finalizes: the finalized blocks form one selected chain, the chain the fork
    /// choice floors on (`Dag::finality_admits`) and the fold roots on (`Dag::fold_root_by_finality`).
    /// BORROWED: GRANDPA and Casper FFG — a finalized block is an ancestor of every later finalized block; a vote for a
    /// block is a vote for its chain.
    /// MEASURED why (lane af58 rig, main e62feae1, double-spend round 3): node 1's tally finalized height 117 as 31442b75,
    /// then height 118 as d94af5e1, whose selected parent is the sibling 08d68e0d (31442b75 is not even in its past); the
    /// head flipped back, and node 0, which had folded 31442b75 under its final root, could never re-fold
    /// (`[fold-order] ordinal 117 would append at leaf 30976`), split its spine and stopped folding for ~25 minutes.
    /// AI RESISTANT: (a) for the votes (each an ML-DSA signature the door verified) and (b) for the rule — a quorum that
    /// does not extend the final block moves nothing, so a lying voter set gains a counted row and no finality.
    /// SCALE: one selected-chain walk of the levels between the final block and the voted one per finalizing vote;
    /// constant in height and in the bonded set.
    pub fn record_verified_vote_on_chain(
        &mut self,
        set: &ValidatorSet,
        block: BlockId,
        block_height: u64,
        voter: [u8; 32],
        extends_final: bool,
    ) -> VoteRecord {
        // A validator with no seat (never seated, or already slashed) has no weight.
        // ⛔⛔⛔ DB-437 — THE TALLY COUNTS FINALITY WEIGHT, THE WEIGHT THE DOORS ADMIT. SATOSHI §6 split the set: a free
        // membership seat is FINALITY membership (`finality_bonds`), custody weight is SAT only (`bond_of`). Both node doors
        // (`Node::submit_finality_vote`, `ingest_finality_vote_gossip`) admit on `finality_weight_of`, but this tracker still
        // read `bond_of` here, in the tally sum, in the 2/3 denominator and in the follow weight — so a seat-only voter passed
        // the door and was dropped as `NoWeight`, and a mesh of membership seats could never finalize.
        // ROOT-LAYER: this is where a vote's weight is produced for the quorum; the doors already read the §6 weight.
        // MEASURED: `db437_a_seated_mesh_holds_every_seat_and_every_node_finalizes` before — seats [3, 3, 3], 204 votes cast,
        //   204 `NotBonded`, finalized [0, 0, 0] at tips [128, 128, 128] (night/link44-db437-trace.log).
        // MUST-STAY-GREEN: the validator finality pins (`finality_needs_two_thirds_bonded_weight`, the equivocation and
        //   retention pins), satoshi_pins (a SAT seat votes finality too), db370.
        // cons: none — a SAT seat's finality weight is its bond plus 0, so a SAT-only set tallies exactly as before.
        // ⭐ G2b (lane a 2026-10-22): THE WEIGHT AND THE DENOMINATOR ARE THE SET ACTIVE AT THE VOTED HEIGHT
        // (`finality_weight_of_at` / `total_finality_weight_at`), never the set this node's fold has applied so far —
        // MEASURED: two nodes holding the same blocks read (1, Some) vs (0, None) when a seat folded between their grafts
        // of one carried vote (g2b-denominator-node-2-20261022.log:1638). The caller defers a vote its fold cannot judge yet.
        if set.finality_weight_of_at(&voter, block_height) == 0 {
            return VoteRecord::NoWeight;
        }
        // EQUIVOCATION GATE: a validator may commit AT MOST ONE block per height. A second, DIFFERENT
        // block at the same height is a provable double-sign fault → do NOT count it; signal the caller
        // to slash. A repeat vote for the same block falls through (idempotent).
        // RETENTION (2026-09-18): a vote for a height more than `FINALITY_VOTE_RETENTION` below the
        // finalized height is neither counted nor re-flooded — nothing it could finalize is still open,
        // and the tally maps are bounded by the retention depth (before this they grew with history: one row per
        // (validator, height) ever voted).
        if block_height.saturating_add(FINALITY_VOTE_RETENTION) < self.finalized_height {
            return VoteRecord::NoWeight;
        }
        // ⛔ A-F106 (lane speed5, 2026-11-19) — THE OPEN TALLY IS BOUNDED BY THE VOTES' OWN FRONTIER, NOT ONLY BY FINALITY. The
        // rule above prunes against `finalized_height`, so on a chain whose finality does not move (the overlay absent, A-F100,
        // or stalled) the open tally grew by every vote of every height for ever (NO GROWTH). MEASURED (replica census, a
        // fixture that never finalizes): (242, 122) open rows and voters at height ~240 and climbing. The frontier is the highest
        // height any held vote names (the last key of `voted_at`); a vote more than RETENTION under it cannot finalize anything
        // the chain still has open (finality only extends its own chain, A-F86), so it is not tallied, and the rows under the
        // floor leave. Finality is an overlay: nothing on the cash path reads this tally.
        // SCALE: the open tally holds at most RETENTION heights × the voters, whatever finality does.
        // cons: a vote that arrives more than RETENTION (4,096) heights late is not tallied — it could finalize nothing open.
        let frontier = self.voted_at.keys().next_back().map_or(0, |(h, _)| *h).max(block_height);
        let floor = frontier.saturating_sub(FINALITY_VOTE_RETENTION);
        if block_height < floor {
            return VoteRecord::NoWeight;
        }
        if self.voted_at.keys().next().is_some_and(|(h, _)| *h < floor) {
            let open = self.voted_at.split_off(&(floor, [0u8; 32]));
            // a block has ONE height, so every row naming a block under the floor is under the floor too: its voters go with it
            for (_, gone) in std::mem::replace(&mut self.voted_at, open) {
                self.voters.remove(&gone);
            }
            self.open_certs = self.open_certs.split_off(&(floor, [0u8; 32]));
        }
        // G1: a SETTLED height finalizes nothing — the vote is judged against the slasher memory only, never tallied
        if block_height <= self.finalized_height {
            return match self.settled.get(&(block_height, voter)) {
                Some(prev) if *prev != block => VoteRecord::Equivocation { first_block: *prev },
                Some(_) => VoteRecord::Counted,
                None => {
                    self.settled.insert((block_height, voter), block);
                    VoteRecord::Counted
                }
            };
        }
        match self.voted_at.get(&(block_height, voter)) {
            Some(prev) if *prev != block => return VoteRecord::Equivocation { first_block: *prev },
            Some(_) => {} // same block — idempotent re-vote
            None => {
                self.voted_at.insert((block_height, voter), block);
            }
        }

        let voters = self.voters.entry(block).or_default();
        voters.insert(voter);
        let weight: u128 = voters.iter().fold(0u128, |a, v| a.saturating_add(set.finality_weight_of_at(v, block_height)));

        // weight / total >= 2/3  ⟺  weight * 3 >= 2 * total — over EVERY seat active at this height (DB-437, SATOSHI §6, G2b)
        let total = set.total_finality_weight_at(block_height);
        let quorum = crate::quorum_math::two_thirds_met(weight, total);
        if quorum && !extends_final && block_height > self.finalized_height {
            // DIGITAL-CASH-PRIVACY-REVIEWED: two public heights and a public block-id prefix; never a key or amount.
            eprintln!(
                "[finality] ⛔ A-F86: a quorum at height {block_height} for {} does not extend the finalized block at {} — counted, \
                 never finalized (finality only extends its own chain)",
                &block.to_hex()[..8],
                self.finalized_height
            );
        }
        let finalized = quorum && extends_final;
        if finalized && block_height > self.finalized_height {
            // ONE assignment for the pair: the height and the block that EARNED it move together, so no
            // consumer can ever read a height belonging to one branch beside an id belonging to another.
            self.finalized_height = block_height;
            self.finalized_block = Some(block);
            self.prune_below_retention();
        }
        if finalized {
            VoteRecord::Finalized
        } else {
            VoteRecord::Counted
        }
    }

    /// Move the tally rows at or below the finalized height to the slasher memory (G1: the tally holds open heights
    /// only) and drop the memory below the retention depth — O(rows moved), amortised O(1) per vote.
    fn prune_below_retention(&mut self) {
        let open = self.voted_at.split_off(&(self.finalized_height.saturating_add(1), [0u8; 32]));
        let settled = std::mem::replace(&mut self.voted_at, open);
        for (key, block) in settled {
            self.voters.remove(&block);
            self.settled.entry(key).or_insert(block);
        }
        let cutoff = self.finalized_height.saturating_sub(FINALITY_VOTE_RETENTION);
        if cutoff > 0 {
            self.settled = self.settled.split_off(&(cutoff, [0u8; 32]));
        }
        self.open_certs = self.open_certs.split_off(&(self.finalized_height.saturating_add(1), [0u8; 32]));
    }

    /// DB-472: keep `cert` beside its open row (a vote this tracker just counted at a height above the finalized one), so a
    /// later fold rewind can re-open it. A certificate whose row is not open — a settled height, an equivocation, a vote
    /// with no weight — is not kept.
    pub fn keep_open_cert(&mut self, cert: VoteCert, voter: [u8; 32]) {
        let key = (cert.height, voter);
        if self.voted_at.get(&key) == Some(&cert.block) {
            self.open_certs.insert(key, cert);
        }
    }

    /// DB-472: RE-OPEN every open row above `bound` — the height this node can no longer judge after its fold cursor dropped
    /// — whose certificate it kept: the row leaves the tally (and its voter leaves the block's voter set) and its certificate
    /// is returned for the deferred queue, judged again by the same rule once the cursor reaches it. A row with no kept
    /// certificate stays (nothing here could re-judge it). Finalization is never undone: only heights above the finalized
    /// one are open.
    pub fn reopen_above(&mut self, bound: u64) -> Vec<([u8; 32], VoteCert)> {
        let from = bound.max(self.finalized_height).saturating_add(1);
        let keys: Vec<(u64, [u8; 32])> =
            self.open_certs.range((from, [0u8; 32])..).map(|(k, _)| *k).collect();
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(cert) = self.open_certs.remove(&key) else { continue };
            if let Some(block) = self.voted_at.remove(&key) {
                if let Some(vs) = self.voters.get_mut(&block) {
                    vs.remove(&key.1);
                    if vs.is_empty() {
                        self.voters.remove(&block);
                    }
                }
            }
            out.push((key.1, cert));
        }
        out
    }

    /// The bonded weight already counted for `block` — what a validator that has not voted at that
    /// level yet may FOLLOW (the symmetric target, [`crate::node::Node::finality_vote_targets`]).
    pub fn vote_weight_of(&self, set: &ValidatorSet, block: &BlockId, height: u64) -> u128 {
        self.voters
            .get(block)
            .map(|vs| vs.iter().fold(0u128, |a, v| a.saturating_add(set.finality_weight_of_at(v, height)))) // DB-437 + G2b
            .unwrap_or(0)
    }

    /// ⭐ A-F86 — `voter`'s open votes (heights above the finalized one), highest first. Bounded by the open rows.
    pub fn open_votes_of(&self, voter: &[u8; 32]) -> Vec<(u64, BlockId)> {
        let mut v: Vec<(u64, BlockId)> = self.voted_at.iter().filter(|((_, k), _)| k == voter).map(|((h, _), b)| (*h, *b)).collect();
        v.sort_by(|a, b| b.0.cmp(&a.0));
        v
    }

    /// ⭐ A-F86 — whether `block` can no longer reach a 2/3 quorum at `height`: more than a third of the weight active there
    /// has already voted for OTHER blocks (one vote per key per height, so those keys cannot add to it without an
    /// equivocation the slasher burns). A voter whose own vote is dead may vote off its chain: no quorum can contain it.
    pub fn vote_is_dead(&self, set: &ValidatorSet, height: u64, block: &BlockId) -> bool {
        let against: u128 = self
            .voted_at
            .range((height, [0u8; 32])..=(height, [0xffu8; 32]))
            .filter(|(_, b)| *b != block)
            .fold(0u128, |a, ((h, v), _)| a.saturating_add(set.finality_weight_of_at(v, *h)));
        let total = set.total_finality_weight_at(height);
        total > 0 && against.saturating_mul(3) > total
    }

    /// Rows held by the two tally maps (the footprint pin reads it).
    pub fn tally_rows(&self) -> (usize, usize) {
        (self.voted_at.len(), self.voters.len())
    }

    /// The open tally's rows `(height, voter, block)` — a census diagnostic (two nodes whose tally differs name the vote).
    #[cfg(test)]
    pub fn open_keys_for_test(&self) -> Vec<(u64, [u8; 32], BlockId)> {
        self.voted_at.iter().map(|((h, v), b)| (*h, *v, *b)).collect()
    }

    /// Rows held by the slasher memory (settled heights, G1) — local evidence, never the tally.
    pub fn settled_rows(&self) -> usize {
        self.settled.len()
    }

    /// The block `voter` committed at `height` in this tally, if any — the receipt doors' equivocation and duplicate
    /// check against the CARRIED votes (G2: the tally is fed only at the fold, so a heard vote is judged against it, never
    /// written into it).
    pub fn voted_block_at(&self, height: u64, voter: &[u8; 32]) -> Option<BlockId> {
        self.voted_at.get(&(height, *voter)).or_else(|| self.settled.get(&(height, *voter))).copied()
    }
}

impl Default for FinalityTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// A validator's finality vote, authenticated by a PQ signature over the vote message. The node
/// ingress verifies `sig` (ML-DSA, via [`crate::pqauth`]) before counting; the voter id is
/// `H(pubkey)`. `pubkey`/`sig` are opaque PQ-sized bytes so the base layer stays post-quantum.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VoteCert {
    pub pubkey: Vec<u8>,
    pub block: BlockId,
    pub height: u64,
    pub sig: Vec<u8>,
}

impl VoteCert {
    /// Postcard-encode for a [`crate::protocol::WireMsg::Vote`] payload — a finality vote gossips across
    /// the bonded set bidirectionally so every validator independently tallies the ≥2/3 quorum.
    pub fn to_wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Decode a received vote payload; a corrupt/truncated frame is `None` (fail-closed).
    pub fn from_wire(bytes: &[u8]) -> Option<VoteCert> {
        crate::chain_object::decode_exact(bytes)
    }
}

/// The outcome of submitting a finality vote at the node ingress.
#[derive(Debug, PartialEq, Eq)]
pub enum FinalityVoteOutcome {
    /// The vote pushed the block to finality (≥2/3 bonded weight).
    Finalized,
    /// G2 (2026-10-22): the vote verified, binds to this node's DAG and is POOLED as a `Class::FinalityVote` object; it is
    /// COUNTED when a block carries it and this node folds that block (`finality_vote_tx::apply_chain_finality_vote`). A
    /// receipt door never tallies, so this is the honest answer for every admitted vote; `Finalized` is the fold door's.
    Counted,
    /// The PQ signature did not authenticate the vote — rejected fail-closed.
    Unauthenticated,
    /// The voter is not a bonded validator, so it carries no weight.
    NotBonded,
    /// ⛔ DB-266 — EQUIVOCATION detected: the voter double-signed (a different block at the same height). The vote
    /// was not counted and the conflicting cert is QUEUED as evidence (`Node::take_pending_equivocations`). Nothing is
    /// slashed here: the slash lands on every node when a block carries the published evidence.
    Equivocation,
    /// G2: the vote verified and binds, but this node's pool refused the framed object (its stamp could not be ground, or
    /// the pool is at its weight cap) — nothing tallied, nothing gossiped; the voter re-votes on its next stride.
    NotPooled,
}

/// ⭐ DB-272 / DB-341 — THE NODE'S OWN VOTE KEY, ONE DEFINITION for the daemon, the onion serve (finality voter, bridge
/// signer, announce), the in-process node, the bridge's custody derivation and the loopback RPC (`/sign_bond`, own unbond):
/// `persist::state_dir()/validator-<persist::serving_port()>.key` = `(pk_len_le ‖ pk ‖ sk)`, drawn fresh-random on first use and
/// stable across restarts. The binary signs finality votes and its seat with it. The RPC signs this node's own UNBOND
/// with it, because the weight a wallet bonds sits under THIS identity (`/validator_id`), never under the wallet's key.
pub fn node_vote_key_path() -> std::path::PathBuf {
    let dir = crate::node_files::state_dir();
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("validator-{}.key", crate::node_files::serving_port()))
}

/// Load this node's vote keypair from [`node_vote_key_path`], or draw and persist a fresh one on first use.
/// The file goes through the custody keystore (sealed at rest only if the operator opted in).
/// ⛔ LIVENESS FIRST (user 2026-09-28): a key file that EXISTS but will not open (sealed, and the passphrase is missing
/// or wrong) never stops the node and is never replaced. The node runs with its VALIDATOR ROLE OFF: this process holds
/// an in-memory identity that is never written and never bonded ([`vote_key_locked`] makes `/validator_id`,
/// `/sign_bond` and the node's own unbond refuse), so no value is ever bound to a key that dies at restart. The
/// custody point and KEM come from the same sealed files, so a locked node requests no seat either.
/// O1-INFINITY-REVIEWED: this reads the node's OWN identity key, one file of fixed size (4 + ML-DSA pk + sk ≈ 5.9 KB,
/// + 98 B when sealed). It is not chain state and authorizes nothing about the chain; the file existed and was read
/// here before, and only its at-rest form changes.
pub fn load_or_create_node_vote_key() -> (Vec<u8>, Vec<u8>) {
    let path = node_vote_key_path();
    // O1-INFINITY-REVIEWED: the node's own identity key, one fixed-size file, read here as before.
    match crate::keystore::read_key_file(&path) {
        Ok(bytes) => {
            if let Some((pk, sk, _provisioned)) = parse_vote_key_file(&bytes) {
                return (pk, sk);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return locked_role_off_identity(&e),
    }
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let mut out = Vec::with_capacity(4 + pk.len() + sk.len());
    out.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    out.extend_from_slice(&pk);
    out.extend_from_slice(&sk);
    if let Err(e) = crate::keystore::write_key_file(&path, &out) {
        eprintln!("[validator] ⛔ could not persist this node's new validator key: {e}");
    }
    (pk, sk)
}

/// ⭐⭐⭐ A BONDED IDENTITY IS DERIVED FROM THE OPERATOR'S SEED, AND IT IS AUTOMATIC (user 2026-09-28: "our validating
/// nodes that are bonded should simply work after bonding not require any extra setup or passwords").
///
/// The borrowed shape is Ethereum's: validator keys are DERIVED from the mnemonic (EIP-2333/2334), so a lost machine or
/// file is re-provisioned from the seed and every bond on the identity survives. The wallet holds the seed and derives
/// the identity (`pq::derive_validator_identity`); its bond flow hands THIS node only the DERIVED keys over loopback
/// (`/provision_validator`), and the node restarts itself onto them. No password, no manual step, and the seed never
/// reaches the node.
///
/// A key file the node drew for itself (a node that never bonded) carries no trailer. A provisioned one ends with
/// [`PROVISIONED_TRAILER`], and `/sign_bond` signs only for a provisioned identity: a bond can never sit on a key the
/// operator could not re-derive.
pub const PROVISIONED_TRAILER: &[u8] = b"MUSD/validator/provisioned-from-seed/v1";

/// Parse a vote key file: `(pk_len u32 LE ‖ pk ‖ sk [‖ PROVISIONED_TRAILER])` → `(pk, sk, provisioned)`.
#[must_use]
pub fn parse_vote_key_file(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>, bool)> {
    let (body, provisioned) = match bytes.strip_suffix(PROVISIONED_TRAILER) {
        Some(b) => (b, true),
        None => (bytes, false),
    };
    let pk_len = u32::from_le_bytes(body.get(..4)?.try_into().ok()?) as usize;
    let pk = body.get(4..4 + pk_len)?.to_vec();
    let sk = body.get(4 + pk_len..)?.to_vec();
    (!pk.is_empty() && !sk.is_empty()).then_some((pk, sk, provisioned))
}

/// The key files a provision replaced while this process still runs the identity it booted with: one entry per node the
/// process hosts (a daemon: at most one). ⛔ DB-406: KEYED BY THE KEY FILE, never one process-wide bit — the journey
/// simulator hosts several nodes in one process, and a bit set by node 0's provision read as "restart" for every node.
/// O1-FOOTPRINT-REVIEWED: bounded by the nodes one process hosts (a daemon 1, the simulator ≤ its node count).
static IDENTITY_RESTART: std::sync::Mutex<Vec<std::path::PathBuf>> = std::sync::Mutex::new(Vec::new());

/// Was this node's identity provisioned from an operator's seed (not self-drawn)? Read from the key file itself, the one
/// source of the identity. ⛔ DB-406: this was a process-wide bit the LAST key load set, so in a process hosting several
/// nodes it named whichever node loaded last — never the file `/sign_bond` signs with.
/// O1-INFINITY-REVIEWED: one fixed-size identity file (≈ 6 KB), read once per bond signature.
#[must_use]
pub fn vote_identity_provisioned() -> bool {
    crate::keystore::read_key_file(&node_vote_key_path())
        .ok()
        .and_then(|b| parse_vote_key_file(&b))
        .is_some_and(|(_, _, provisioned)| provisioned)
}

/// Has a provision installed a new identity this process is not running yet? The daemon's shutdown watcher treats it
/// exactly as a shutdown request (snapshot, then a clean exit), and the supervisor (launchd KeepAlive, the wallet's
/// watchdog) restarts the node onto the new identity. The journey simulator's step loop is that supervisor for its nodes.
#[must_use]
pub fn identity_restart_requested() -> bool {
    let pending = IDENTITY_RESTART.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    !pending.is_empty() && pending.contains(&node_vote_key_path())
}

/// The process that saw [`identity_restart_requested`] is gone: a new one boots from the files and runs the installed
/// identity. A daemon never calls this (its exit drops the static); the journey simulator, whose "processes" share one
/// test process, calls it at each simulated node's boot.
pub fn forget_identity_restart() {
    let path = node_vote_key_path();
    IDENTITY_RESTART.lock().unwrap_or_else(std::sync::PoisonError::into_inner).retain(|p| *p != path);
}

/// The custody ML-KEM-768 keypair a provisioned validator derives from its vote key: FIPS 203 `KeyGen_internal(d, z)`
/// with `d`, `z` domain-separated blake3 derivations of the vote secret. Deterministic, so a node re-provisioned from
/// the seed recovers the SAME custody key and every peg delta sealed to it stays openable.
#[must_use]
pub fn custody_kem_from_vote_sk(vote_sk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use fips203::traits::{KeyGen as _, SerDes as _};
    let (d, z) = custody_kem_seeds(vote_sk);
    let (ek, dk) = fips203::ml_kem_768::KG::keygen_from_seed(d, z);
    (ek.into_bytes().to_vec(), dk.into_bytes().to_vec())
}

/// The KEM seeds `(d, z)`: blake3's KEY-DERIVATION mode under two distinct context labels over the vote secret. One
/// secret feeding two schemes is safe only through a domain-separated KDF, never by reusing the raw bytes as the other
/// scheme's seed (the cross-scheme key-reuse shape); `custody_kem_seeds_are_domain_separated_from_the_vote_key` pins it.
fn custody_kem_seeds(vote_sk: &[u8]) -> ([u8; 32], [u8; 32]) {
    (
        blake3::derive_key("MUSD/validator/custody-kem/d/v1", vote_sk),
        blake3::derive_key("MUSD/validator/custody-kem/z/v1", vote_sk),
    )
}

/// What a provision did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provision {
    /// The derived identity is installed; the node restarts onto it.
    Installed,
    /// The node already runs this exact provisioned identity; nothing changed.
    AlreadyThisIdentity,
}

/// ⭐ Install a seed-derived validator identity handed in by the operator's wallet (the DERIVED keys, never the seed).
///
/// §9.6 (a door that admits outside bytes into the node's identity):
/// 1. PoW: none applies (a local identity, not a chain object); loopback-only like every route beside it.
/// 2. Proof: both keypairs must prove themselves here: the vote key signs a probe its own pk verifies, and the KEM ek
///    encapsulates to a secret its dk recovers. A mismatched or malformed pair is refused before anything is written.
/// 3. Conservation: no value moves; what this refuses is STRANDING value. An identity that holds weight (a bond, a
///    slash, or a bond pending in this pool) is never replaced (`holds_weight`).
/// 4. Replay: installing the identity already running is a no-op (`AlreadyThisIdentity`).
/// 5. Bounded work: one sign/verify, one encaps/decaps, two fixed-size file writes.
/// 6. Parity with the self-draw path (`load_or_create_node_vote_key`): the same one path formula, the same keystore
///    writer (so an opted-in seal applies and a locked key is refused, never overwritten), the same file format.
/// O1-INFINITY-REVIEWED: reads and writes only the node's own two fixed-size identity files (vote key, custody KEM);
/// never chain state, never per block.
pub fn provision_identity(
    vote_pk: &[u8],
    vote_sk: &[u8],
    holds_weight: impl Fn(&[u8; 32]) -> bool,
) -> Result<Provision, &'static str> {
    if vote_key_locked() {
        return Err("VALIDATOR_IDENTITY_LOCKED");
    }
    let path = node_vote_key_path();
    let installed = provision_identity_at(&path, vote_pk, vote_sk, holds_weight)?;
    if installed == Provision::Installed {
        let mut pending = IDENTITY_RESTART.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !pending.contains(&path) {
            pending.push(path);
        }
        eprintln!("[validator] a seed-derived validator identity was provisioned; the node restarts onto it");
    }
    Ok(installed)
}

/// [`provision_identity`] at an explicit vote key path (its custody KEM sits beside it as `.kem`). The one body both
/// the route and the pins run.
/// O1-INFINITY-REVIEWED: reads and writes only the node's own two fixed-size identity files; never chain state.
pub fn provision_identity_at(
    path: &std::path::Path,
    vote_pk: &[u8],
    vote_sk: &[u8],
    holds_weight: impl Fn(&[u8; 32]) -> bool,
) -> Result<Provision, &'static str> {
    let probe = b"MUSD/validator/provision-probe/v1";
    let sig = crate::pqauth::ml_dsa_sign(probe, vote_sk).ok_or("PROVISION_VOTE_KEY_MALFORMED")?;
    if !crate::pqauth::ml_dsa_verify(probe, vote_pk, &sig) {
        return Err("PROVISION_VOTE_KEYPAIR_MISMATCH");
    }
    // The custody KEM is DERIVED here from the vote key, never handed in: no decapsulation key crosses the wire, and
    // it is recoverable from the seed through the vote key (as the bridge's secp/XMR custody points already are).
    let (kem_ek, kem_dk) = custody_kem_from_vote_sk(vote_sk);
    let (ss, ct) = crate::pqkem::encapsulate(&kem_ek).ok_or("PROVISION_KEM_KEY_MALFORMED")?;
    if crate::pqkem::decapsulate(&ct, &kem_dk).as_deref() != Some(ss.as_slice()) {
        return Err("PROVISION_KEM_KEYPAIR_MISMATCH");
    }
    let (kem_ek, kem_dk) = (kem_ek.as_slice(), kem_dk.as_slice());
    // O1-INFINITY-REVIEWED: the node's own fixed-size identity file at the one path the caller names.
    let mut replaced: Option<Vec<u8>> = None;
    match crate::keystore::read_key_file(path) {
        Ok(bytes) => {
            if let Some((pk, _sk, provisioned)) = parse_vote_key_file(&bytes) {
                if provisioned && pk == vote_pk {
                    return Ok(Provision::AlreadyThisIdentity);
                }
                if holds_weight(&crate::pqauth::pubkey_id(&pk)) {
                    return Err("VALIDATOR_IDENTITY_HOLDS_WEIGHT");
                }
                if pk != vote_pk {
                    replaced = Some(bytes.clone());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) if crate::keystore::is_locked(&e) => return Err("VALIDATOR_IDENTITY_LOCKED"),
        Err(_) => return Err("VALIDATOR_KEY_UNREADABLE"),
    }
    // The KEM first, so the vote key never names a custody key that is not on disk.
    let mut kem = Vec::with_capacity(4 + kem_ek.len() + kem_dk.len());
    kem.extend_from_slice(&(kem_ek.len() as u32).to_le_bytes());
    kem.extend_from_slice(kem_ek);
    kem.extend_from_slice(kem_dk);
    crate::keystore::write_key_file(&path.with_extension("kem"), &kem).map_err(|_| "PROVISION_KEM_WRITE_FAILED")?;
    let mut vote = Vec::with_capacity(4 + vote_pk.len() + vote_sk.len() + PROVISIONED_TRAILER.len());
    vote.extend_from_slice(&(vote_pk.len() as u32).to_le_bytes());
    vote.extend_from_slice(vote_pk);
    vote.extend_from_slice(vote_sk);
    vote.extend_from_slice(PROVISIONED_TRAILER);
    // ⭐ A-F81 (lane af58, 2026-11-16): the identity being replaced is kept beside the new one as `<vote key>.retiring`, so the
    // node can RETIRE the seat it held under it (`NodeRuntime::retire_previous_identity`). It holds no weight past a free
    // membership seat (refused above otherwise), and a free seat has no lock anchor, so its unbond releases at once
    // (`Node::bond_matured_at`, DB-258c). Before, the first seat stayed: a node seated twice and every validator count read
    // two seats for each provisioned node (MEASURED churn-dead 13:28, main 1cc75401: [6, 6, 6] seats for 3 nodes).
    // Written BEFORE the new key, so a failure between the two leaves the old identity in place, never a lost key.
    if let Some(old) = replaced {
        crate::keystore::write_key_file(&path.with_extension("retiring"), &old).map_err(|_| "PROVISION_RETIRING_WRITE_FAILED")?;
    }
    crate::keystore::write_key_file(path, &vote).map_err(|_| "PROVISION_VOTE_WRITE_FAILED")?;
    Ok(Provision::Installed)
}

/// ⭐ A-F81 — the identity a provisioning replaced, while its seat may still stand: `(pk, sk)` read from
/// `<vote key>.retiring` (written by [`provision_identity_at`]), or `None`. O1-INFINITY-REVIEWED: one fixed-size file.
#[must_use]
pub fn retiring_identity() -> Option<(Vec<u8>, Vec<u8>)> {
    let bytes = crate::keystore::read_key_file(&node_vote_key_path().with_extension("retiring")).ok()?;
    parse_vote_key_file(&bytes).map(|(pk, sk, _)| (pk, sk))
}

/// ⭐ A-F81 — the retiring identity's seat is gone from the chain: its key file is removed (nothing is left to sign for).
pub fn clear_retiring_identity() {
    let _ = std::fs::remove_file(node_vote_key_path().with_extension("retiring"));
}

static VOTE_KEY_LOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Is this node's validator identity LOCKED (its sealed key would not open this run)? While it is, every route that
/// binds value to the identity refuses (`/validator_id`, `/sign_bond`, the node's own unbond), and the node runs as a
/// plain node. Unlocking needs only the operator's passphrase back, or re-provisioning the identity from the seed.
#[must_use]
pub fn vote_key_locked() -> bool {
    VOTE_KEY_LOCKED.load(std::sync::atomic::Ordering::Relaxed)
}

/// The identity a node runs with while its real key is locked: drawn once per process, held in RAM, NEVER written
/// (the locked file stays exactly as it is) and never bonded (see [`vote_key_locked`]). Its finality votes carry no
/// weight, because no bond names it.
fn locked_role_off_identity(e: &std::io::Error) -> (Vec<u8>, Vec<u8>) {
    static IN_MEMORY: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    VOTE_KEY_LOCKED.store(true, std::sync::atomic::Ordering::Relaxed);
    IN_MEMORY
        .get_or_init(|| {
            eprintln!(
                "[validator] ⛔ this node's validator key is LOCKED ({e}). The node RUNS with its validator role OFF: \
                 the key file is left untouched, and nothing is bonded, seated or unbonded until the keystore \
                 passphrase is restored or the identity is re-provisioned from the operator's seed."
            );
            crate::pqauth::ml_dsa_keypair()
        })
        .clone()
}

#[cfg(all(test, feature = "pins-core"))]
mod provision_tests {
    use super::*;

    /// ⭐⭐⭐ THE AUTOMATIC VALIDATOR'S DOOR (user 2026-09-28): a seed-derived identity installs with no setup, proves
    /// itself, derives its custody KEM on the node, is idempotent, and NEVER replaces an identity that holds weight.
    /// TWO-PARTY-REVIEWED: the wallet (which derives and hands in the keypair) and the node (which proves and installs
    /// it) are the two parties; the wallet side is pinned in `pq::tests` against these same node functions.
    #[test]
    fn a_provisioned_identity_installs_proves_itself_and_never_replaces_one_holding_weight() {
        // The keystore's writer creates the parent directory; the name is unique per test process.
        let path = std::env::temp_dir().join(format!("musd-provision-{}", std::process::id())).join("validator-1.key");
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let (other_pk, other_sk) = crate::pqauth::ml_dsa_keypair();
        // A mismatched pair is refused before anything is written.
        assert_eq!(
            provision_identity_at(&path, &pk, &other_sk, |_| false),
            Err("PROVISION_VOTE_KEYPAIR_MISMATCH"),
            "⛔ a vote key that does not sign for its own pk must never install"
        );
        assert!(!path.exists(), "nothing is written for a refused pair");
        // A fresh node installs it, with the custody KEM derived from the vote key beside it.
        assert_eq!(provision_identity_at(&path, &pk, &sk, |_| false), Ok(Provision::Installed));
        let bytes = crate::keystore::read_key_file(&path).expect("the vote key is on disk");
        let (got_pk, got_sk, provisioned) = parse_vote_key_file(&bytes).expect("it parses");
        assert_eq!((got_pk.as_slice(), got_sk.as_slice(), provisioned), (pk.as_slice(), sk.as_slice(), true));
        let kem = crate::keystore::read_key_file(&path.with_extension("kem")).expect("the custody KEM is on disk");
        let (ek, dk) = custody_kem_from_vote_sk(&sk);
        assert_eq!(kem, [&(ek.len() as u32).to_le_bytes()[..], &ek, &dk].concat(), "the KEM is the one derived from sk");
        let (ss, ct) = crate::pqkem::encapsulate(&ek).expect("the derived ek encapsulates");
        assert_eq!(crate::pqkem::decapsulate(&ct, &dk), Some(ss), "the derived custody KEM opens its own deltas");
        assert_eq!(custody_kem_from_vote_sk(&sk), (ek, dk), "the custody KEM derivation is deterministic");
        // Idempotent.
        assert_eq!(provision_identity_at(&path, &pk, &sk, |_| false), Ok(Provision::AlreadyThisIdentity));
        // ⛔ An identity that holds weight is NEVER replaced: its bonds would be stranded.
        assert_eq!(
            provision_identity_at(&path, &other_pk, &other_sk, |_| true),
            Err("VALIDATOR_IDENTITY_HOLDS_WEIGHT"),
            "⛔⛔ a provision replaced an identity that holds weight"
        );
        let still = parse_vote_key_file(&crate::keystore::read_key_file(&path).expect("read")).expect("parse");
        assert_eq!(still.0, pk, "the weighted identity is untouched");
        // A weightless identity (a node that never bonded) is replaced.
        assert_eq!(provision_identity_at(&path, &other_pk, &other_sk, |_| false), Ok(Provision::Installed));
    }

    /// The custody KEM's seeds are domain-separated derivations, never the vote key's own bytes reused, and never
    /// equal to each other (lane-recursion's DB-360 §6 note: one secret, two schemes, only through a labelled KDF).
    /// TWO-PARTY-REVIEWED: a derivation on one node's own secret; no boundary is crossed.
    #[test]
    fn custody_kem_seeds_are_domain_separated_from_the_vote_key() {
        let (_pk, sk) = crate::pqauth::ml_dsa_keypair();
        let (d, z) = custody_kem_seeds(&sk);
        assert_ne!(d, z, "the two KEM seeds must differ");
        for seed in [d, z] {
            assert!(!sk.windows(32).any(|w| w == seed), "⛔ a KEM seed must never be a window of the vote key bytes");
        }
        let (_pk2, sk2) = crate::pqauth::ml_dsa_keypair();
        assert_ne!(custody_kem_seeds(&sk2), (d, z), "another vote key derives another custody KEM");
    }

    /// A self-drawn key file (no trailer) reads as NOT provisioned, so `/sign_bond` never signs a bond onto it; a
    /// trailer alone is not a key.
    /// TWO-PARTY-REVIEWED: a parse of one node's own file; no boundary is crossed.
    #[test]
    fn a_self_drawn_key_is_not_provisioned_and_the_trailer_is_not_key_material() {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let plain = [&(pk.len() as u32).to_le_bytes()[..], &pk, &sk].concat();
        assert_eq!(parse_vote_key_file(&plain), Some((pk.clone(), sk.clone(), false)));
        let marked = [&plain[..], PROVISIONED_TRAILER].concat();
        assert_eq!(parse_vote_key_file(&marked), Some((pk, sk, true)), "the trailer is stripped, never read as sk");
        assert_eq!(parse_vote_key_file(PROVISIONED_TRAILER), None, "a trailer alone is not a key");
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn vid(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    /// ⭐ SAFE AT SCALE — A CUSTODIAN'S SEAT IS CHAIN STATE THAT TRAVELS WITH IT. Two sets: A follows the bond events; B is
    /// handed A's exported state (the snapshot's and the bundle's rows). Twenty custodians bond in order, each seated by
    /// the draw: the seventeenth splits the one full vault, so two vaults of at least eight hold all twenty on distinct
    /// seats. A custodian leaves — only its own vault changes; a new one bonds — it joins a vault that already holds
    /// eight, and the other vault does not change. B, importing A's rows, holds the same seats and so the same vaults —
    /// where a set rebuilt from the bonds alone (no seat rows) would seat them by another rule. A rewound
    /// step (`set_vid_state`) puts a custodian back on the seat it held. A relay's forged row (a seat already taken) is
    /// refused and the custodian is seated by rule.
    #[test]
    fn safe_at_scale_a_custody_seat_is_kept_until_its_holder_leaves_and_travels_with_the_set() {
        crate::custody_vaults::TEST_CUT_LIVE.with(|c| c.set(true));
        let mut a = ValidatorSet::new();
        for i in 1u8..=20 {
            a.admit_active_from(vid(i), 100, 0, u64::from(i)).expect("admits");
        }
        let seats: std::collections::BTreeSet<u64> = a.custody_seats().iter().map(|(_, s)| *s).collect();
        assert_eq!(seats.len(), 20, "twenty custodians hold twenty distinct seats");
        let v = a.custody_vaults();
        assert_eq!((v.len(), v.iter().map(Vec::len).sum::<usize>()), (2, 20), "the seventeenth bond split the one full vault: two vaults hold all twenty");
        assert!(v.iter().all(|x| x.len() >= crate::custody_vaults::VAULT_MIN), "each half kept eight older members: {:?}", v.iter().map(Vec::len).collect::<Vec<_>>());
        let leaver_state = a.vid_state(&vid(5));
        let left = crate::custody_vaults::vault_of_seat(leaver_state.custody_seat.expect("a bonded custodian holds a seat"));
        a.remove(&vid(5)).expect("leaves");
        let after_leave = a.custody_vaults();
        assert_eq!(after_leave[1 - left], v[1 - left], "⛔ a leave changed a vault it was not in");
        assert_eq!(after_leave[left].len(), v[left].len() - 1);
        a.admit_active_from(vid(99), 100, 0, 500).expect("the newcomer admits");
        let after_bond = a.custody_vaults();
        let joined = crate::custody_vaults::vault_of_seat(a.vid_state(&vid(99)).custody_seat.expect("seated"));
        assert_eq!(after_bond[1 - joined], after_leave[1 - joined], "⛔ a bond changed a vault it did not join");
        assert!(after_leave[joined].len() >= crate::custody_vaults::VAULT_MIN, "⛔ the newcomer joined a vault of fewer than eight while a vault of eight had room");
        assert_eq!(a.custody_seats().iter().map(|(_, s)| *s).collect::<std::collections::BTreeSet<u64>>().len(), 20, "no two custodians share a seat");

        // party B: handed A's state as a carrier hands it
        let (bonds, slashed, burned, commit, custody) = a.export_state();
        let (cf, ff, dc, df) = a.seat_activations();
        let mut b = ValidatorSet::new();
        b.import_state(bonds.clone(), slashed.clone(), burned, commit, custody.clone());
        b.import_seat_activations(cf.clone(), ff.clone(), dc.clone(), df.clone());
        let without_rows = b.custody_vaults();
        assert_ne!(without_rows, a.custody_vaults(), "CALIBRATION: a set rebuilt from the bonds alone seats the newcomer by seniority — another vault than the chain's");
        b.import_custody_seats(a.custody_seats());
        assert_eq!(b.custody_seats(), a.custody_seats(), "the peer holds every custodian on the chain's seat");
        assert_eq!(b.custody_vaults(), a.custody_vaults(), "…and so cuts the chain's vaults");

        // a rewound step puts a custodian back on its seat
        b.remove(&vid(99));
        let was = leaver_state.custody_seat;
        b.set_vid_state(vid(5), leaver_state);
        assert_eq!(b.vid_state(&vid(5)).custody_seat, was, "the rewound custodian is back on its seat");

        // a forged row naming a seat already taken is refused; that custodian is seated by rule, on a free seat
        let mut forged = a.custody_seats();
        let dup = forged[0].1;
        forged[3].1 = dup;
        let mut c = ValidatorSet::new();
        c.import_state(bonds, slashed, burned, commit, custody);
        c.import_seat_activations(cf, ff, dc, df);
        c.import_custody_seats(forged.clone());
        let seats: Vec<u64> = c.custody_seats().iter().map(|(_, s)| *s).collect();
        let mut distinct = seats.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), seats.len(), "⛔ two custodians hold one seat after a forged row");
        assert_eq!(c.custody_seats().iter().find(|(id, _)| *id == forged[0].0).map(|(_, s)| *s), Some(dup), "the first claimant keeps the seat");
    }

    /// ⭐ SAFE AT SCALE — LEDGERS MOVE TOWARD THE STRONGEST VAULT AND STOP THERE (`custody_merge_target`). Two parties
    /// hold the same seats (B from A's carried rows). A vault's merge target is the fullest other vault, the lowest
    /// index among equals, and only when that vault OUTRANKS it. CALIBRATION, the case the lifecycle model found: of
    /// two thin vaults (six and five members) the weaker names the stronger and the stronger names NOBODY — under "any
    /// other vault with a member" each named the other, and their ledgers would be handed back and forth for ever.
    /// Equal vaults: the lower index keeps the ledgers. And every party names the same pair.
    #[test]
    fn safe_at_scale_a_vaults_ledgers_merge_only_into_a_vault_that_outranks_it_on_every_party() {
        crate::custody_vaults::TEST_CUT_LIVE.with(|c| c.set(true));
        // custodian i on seat i: vault 0 is seats 0–15, vault 1 seats 16–31, vault 2 seats 32–47
        let seated = |on: &[u64]| -> (ValidatorSet, ValidatorSet) {
            let mut a = ValidatorSet::new();
            for (i, _) in on.iter().enumerate() {
                a.admit_active_from(vid(i as u8 + 1), 100, 0, i as u64 + 1).expect("admits");
            }
            a.import_custody_seats(on.iter().enumerate().map(|(i, s)| (vid(i as u8 + 1), *s)).collect());
            let (bonds, slashed, burned, commit, custody) = a.export_state();
            let mut b = ValidatorSet::new();
            b.import_state(bonds, slashed, burned, commit, custody);
            b.import_custody_seats(a.custody_seats());
            (a, b)
        };
        let seats = |sizes: &[usize]| -> Vec<u64> { sizes.iter().enumerate().flat_map(|(v, n)| (0..*n as u64).map(move |j| v as u64 * 16 + j)).collect() };
        let targets = |sizes: &[usize]| -> Vec<Option<u32>> {
            let (a, b) = seated(&seats(sizes));
            assert_eq!(a.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), sizes, "the fixture's vaults");
            let of = |s: &ValidatorSet| (0..sizes.len() as u32).map(|v| s.custody_merge_target(v)).collect::<Vec<_>>();
            assert_eq!(of(&a), of(&b), "⛔ two parties holding the same seats name different merge targets");
            of(&b)
        };
        // a full vault and a thin one: the thin one names the full one; the full one names nobody
        assert_eq!(targets(&[16, 8]), vec![None, Some(0)]);
        // THE MODEL'S CASE — two thin vaults: only the weaker has a target
        assert_eq!(targets(&[6, 5]), vec![None, Some(0)], "⛔ the stronger of two thin vaults named the weaker: their ledgers would go back and forth");
        assert_eq!(targets(&[5, 6]), vec![Some(1), None]);
        // equals: the lower index keeps the ledgers, the higher one names it
        assert_eq!(targets(&[6, 6]), vec![None, Some(0)]);
        // three vaults: each names the strongest that outranks it; the strongest names nobody
        assert_eq!(targets(&[8, 16, 16]), vec![Some(1), None, Some(1)]);
        assert_eq!(targets(&[3, 2, 3]), vec![None, Some(0), Some(0)]);
        // one vault: nothing to merge into
        assert_eq!(targets(&[7]), vec![None]);
    }

    // #75 brick 4: the confidential bonded-stake accumulator gate — the set VERIFIES a WHIR-bound conservation
    // proof over HIDDEN stake totals (never summing stake), against its OWN persisted bond commitment. An admit
    // advances the digest; a reduce (unbond/slash) is the same proof read backwards; a tampered claimed total
    // REJECTS. This is the confidential replacement for the plaintext `total_bond` accumulator.
    #[test]
    fn confidential_bond_accumulator_gate() {
        use usdm_decider::confidential_solvency as cs;
        let (old_blind, new_blind) = (usdm_decider::poseidon2_compress::lanes_of(&[2, 4, 6, 8]), usdm_decider::poseidon2_compress::lanes_of(&[1, 3, 5, 7]));
        // the set's persisted state: 5000 bonded, held as an opaque digest.
        let mut set = ValidatorSet::new();
        set.initialize_bond_commitment(cs::solvency_commit_256(
            cs::u256_from_u64(5_000),
            old_blind,
        ));
        // a validator admits a 3000 bond: 5000 + 3000 = 8000, proven over hidden totals, the delta BOUND.
        let delta_blind = usdm_decider::poseidon2_compress::lanes_of(&[9, 11, 13, 15]);
        let (bytes, [ac, dc, sc]) = cs::prove_transition_carrier(
            cs::u256_from_u64(5_000),
            cs::u256_from_u64(3_000),
            &[old_blind, delta_blind, new_blind],
            cs::TransitionDomain::Bond,
        )
        .expect("bond admit proves");
        assert_eq!(
            ac,
            set.bond_commit(),
            "the proof's current-total commit matches the set's persisted state"
        );
        assert!(
            set.verify_bond_admit(&bytes, dc, sc),
            "set VERIFIES the confidential bond admit against its persisted commitment"
        );
        // a tampered claimed new total REJECTS.
        let mut wrong = sc;
        wrong[0] ^= 1;
        assert!(
            !set.verify_bond_admit(&bytes, dc, wrong),
            "a tampered claimed new bonded-total commitment REJECTS"
        );
        // ⛔ a tampered DELTA rejects: the conservation names THIS bond, not any amount (the old verifier accepted it).
        let mut other_delta = dc;
        other_delta[0] ^= 1;
        assert!(
            !set.verify_bond_admit(&bytes, other_delta, sc),
            "⛔ a carrier verified against ANOTHER bond's delta commitment — the conservation names no bond"
        );
        // apply advances the digest (confidential total_bond += bond).
        set.apply_bond_transition(sc);
        assert_eq!(set.bond_commit(), sc, "persisted bond commitment advanced");
        // a REDUCE (unbond/slash the 3000 back out): 5000 + 3000 = 8000 read backwards, so the set verifies the
        // return to the 5000 digest as `open(5000) + 3000 == open(8000)`.
        assert!(
            set.verify_bond_reduce(&bytes, dc, ac),
            "set VERIFIES the confidential bond reduce back to the prior total"
        );
    }

    #[test]
    fn bond_floor_adapts_to_bridge_tvl() {
        // ⭐ ZERO reserve -> ZERO floor: the founding seats are free (owner's rule, 2026-09-17). A base
        // constant here refused the first free seat on the publisher's own node — measured.
        assert_eq!(required_bond_floor(0), 0);
        // small TVL -> 2x TVL, no base underneath it.
        assert_eq!(required_bond_floor(100), 200);
        // large TVL -> 2x TVL (anti-drain: bonding majority costs > drainable value).
        assert_eq!(required_bond_floor(5000), 10_000);
    }

    /// ⭐ T3 / T2 (2026-11-03) — THE CARRIED KEY TABLE IS THE WHOLE TABLE: a membership seat's key, carried through the list a
    /// checkpoint and a bundle carry (`seated_kem_eks`) and restored by `import_kem_eks`, survives — so once that seat bonds
    /// SAT custody, the restored node seals to it exactly as a replaying node does. TAMPER: the SAT-only list
    /// (`bonded_custodian_eks`, what both carried before) loses it, and the restored node would seal to nobody.
    #[test]
    fn a_membership_seats_key_survives_the_carried_table_and_is_sealed_to_once_it_bonds_custody() {
        let (m, c) = (vid(7), vid(8));
        let mut live = ValidatorSet::new();
        live.admit_finality_active_from(m, crate::params::MEMBERSHIP_BOND_WEIGHT, 0).expect("a membership seat");
        live.admit(c, 3_000_000, 0).expect("a custody seat");
        live.register_custody_kem(m, vec![0xAA; 32]);
        live.register_custody_kem(c, vec![0xBB; 32]);
        let restore = |carried: Vec<([u8; 32], Vec<u8>)>| {
            let mut r = ValidatorSet::new();
            r.admit_finality_active_from(m, crate::params::MEMBERSHIP_BOND_WEIGHT, 0).expect("the same membership seat");
            r.admit(c, 3_000_000, 0).expect("the same custody seat");
            r.import_kem_eks(carried);
            r
        };
        let mut restored = restore(live.seated_kem_eks());
        assert_eq!(restored.registered_kem_ek(&m), live.registered_kem_ek(&m), "⛔ the membership seat's key did not survive the carried table");
        assert_eq!(restored.seated_kem_eks(), live.seated_kem_eks(), "⛔ the restored table is not the live table");
        // the membership seat bonds SAT custody on both: both seal to it
        live.admit(m, u128::from(crate::sat_schedule::INITIAL_REWARD), 0).expect("the membership seat bonds custody");
        restored.admit(m, u128::from(crate::sat_schedule::INITIAL_REWARD), 0).expect("the membership seat bonds custody on the restored node");
        assert_eq!(restored.bonded_custodian_eks(), live.bonded_custodian_eks(), "⛔ the restored node seals to another set");
        assert!(restored.bonded_custodian_eks().iter().any(|(id, _)| *id == m), "⛔ the restored node seals nothing to the new custodian");
        // TAMPER: the SAT-only list as the carried table loses the membership key
        let lossy = restore(ValidatorSet::bonded_custodian_eks(&{
            let mut before = ValidatorSet::new();
            before.admit_finality_active_from(m, crate::params::MEMBERSHIP_BOND_WEIGHT, 0).unwrap();
            before.admit(c, 3_000_000, 0).unwrap();
            before.register_custody_kem(m, vec![0xAA; 32]);
            before.register_custody_kem(c, vec![0xBB; 32]);
            before
        }));
        assert_eq!(lossy.registered_kem_ek(&m), None, "calibration: the SAT-only carried list drops the membership seat's key");
    }

    /// The seat the genesis quorum is made of: weight [`crate::params::MEMBERSHIP_BOND_WEIGHT`] at zero
    /// reserve must ADMIT. This is the unit-level twin of the real-node seat journey's first arm.
    #[test]
    fn a_free_membership_seat_admits_at_zero_reserve() {
        let mut set = ValidatorSet::new();
        set.admit(vid(1), crate::params::MEMBERSHIP_BOND_WEIGHT, 0)
            .expect("a free seat at zero reserve is admitted");
        assert_eq!(set.total_bond(), crate::params::MEMBERSHIP_BOND_WEIGHT);
    }

    /// SATOSHI §10 — the public takeover figures: three seats 10/20/30 → total 60; effective security = the bottom two seats
    /// (⌈2·3/3⌉ = 2) = 30; takeover = 2·60 = 120, the least weight that clears the custody tally (≥ 2/3) alone: 120 of 180
    /// is exactly 2/3, 119 of 179 is short. No seats → all zero except the 1 base unit that opens an empty set.
    #[test]
    fn the_takeover_figures_are_the_bottom_two_thirds_and_the_custody_tallys_own_threshold() {
        let mut v = ValidatorSet::new();
        assert_eq!(v.takeover_figures(), (0, 0, 1), "an empty custody set");
        assert!(crate::quorum_math::two_thirds_met(1, 1) && !crate::quorum_math::two_thirds_met(0, 0));
        for (i, w) in [10u128, 20, 30].iter().enumerate() {
            v.admit([i as u8 + 1; 32], *w, 0).expect("a custody seat admits at zero TVL");
        }
        let (total, effective, cost) = v.takeover_figures();
        assert_eq!((total, effective, cost), (60, 30, 120));
        assert!(crate::quorum_math::two_thirds_met(cost, cost + total), "the cost clears the custody tally alone");
        assert!(!crate::quorum_math::two_thirds_met(cost - 1, cost - 1 + total), "one base unit less does not");
    }
    #[test]
    fn admit_enforces_adaptive_floor() {
        let mut set = ValidatorSet::new();
        let tvl = 5000; // floor = 10_000
        assert!(matches!(
            set.admit(vid(1), 9_999, tvl).unwrap_err(),
            ValidatorError::BondBelowFloor { .. }
        ));
        set.admit(vid(1), 10_000, tvl).unwrap();
        assert_eq!(set.total_bond(), 10_000);
        assert_eq!(
            set.admit(vid(1), 10_000, tvl).unwrap_err(),
            ValidatorError::AlreadyBonded
        );
    }

    /// ⛔ DB-472 (lane stable 2026-10-30) — AN OPEN ROW RE-OPENS ABOVE THE BOUND, A FINALIZED HEIGHT NEVER DOES. A vote counted
    /// at an open height keeps its certificate; `reopen_above` takes it back out of the tally (its weight leaves the block)
    /// and hands the certificate back, and counting the same certificate again lands the tracker exactly where it stood.
    /// TWO-PARTY-REVIEWED: two independent trackers — one that never re-opened, one that re-opened and re-judged — compared.
    #[test]
    fn db472_an_open_row_reopens_above_the_bound_and_a_finalized_height_never_does() {
        let mut set = ValidatorSet::new();
        for i in 1..=3u8 {
            set.admit(vid(i), 2000, 0).unwrap();
        }
        let cert = |b: BlockId, h: u64| VoteCert { pubkey: vec![1], block: b, height: h, sig: vec![2] };
        let (fin_b, open_b) = (crate::hash::Hash32::hash(b"db472-final"), crate::hash::Hash32::hash(b"db472-open"));
        let mut live = FinalityTracker::new();
        let mut moved = FinalityTracker::new();
        for t in [&mut live, &mut moved] {
            for v in [1u8, 2] {
                assert!(matches!(t.record_verified_vote(&set, fin_b, 10, vid(v)), VoteRecord::Counted | VoteRecord::Finalized));
                t.keep_open_cert(cert(fin_b, 10), vid(v));
            }
            assert_eq!(t.record_verified_vote(&set, open_b, 20, vid(1)), VoteRecord::Counted);
            t.keep_open_cert(cert(open_b, 20), vid(1));
        }
        assert_eq!(live.finalized_height(), 10, "CALIBRATION: height 10 finalized on two of three");
        assert!(moved.reopen_above(30).is_empty(), "nothing above the bound re-opens");
        let back = moved.reopen_above(15);
        assert_eq!(back.len(), 1, "⛔ the open row above the bound must re-open: {back:?}");
        assert_eq!((back[0].0, back[0].1.height), (vid(1), 20));
        assert_eq!(moved.tally_rows(), (0, 0), "⛔ the re-opened row left the tally and its voter left the block");
        assert_eq!(moved.finalized_height(), 10, "⛔ a finalized height is never undone");
        assert!(moved.reopen_above(0).is_empty(), "⛔ a finalized height never re-opens");
        assert_eq!(moved.record_verified_vote(&set, open_b, 20, vid(1)), VoteRecord::Counted);
        assert_eq!(
            (moved.tally_rows(), moved.vote_weight_of(&set, &open_b, 20)),
            (live.tally_rows(), live.vote_weight_of(&set, &open_b, 20)),
            "⛔ re-judging the re-opened certificate lands where the tracker that never re-opened stands"
        );
    }

    /// ⭐ A-F86 — a quorum for a block that does not extend the finalized one is counted and never finalizes, and a vote
    /// becomes DEAD (free to be left by its voter) only once more than a third of the weight voted otherwise at its height.
    /// MEASURED on real nodes before the rule: height 117 final as one sibling, height 118 final on the other's chain.
    #[test]
    fn af86_finality_only_extends_its_own_chain_and_a_vote_dies_only_past_a_third_against() {
        let mut set = ValidatorSet::new();
        for i in 1..=3u8 {
            set.admit(vid(i), 2000, 0).unwrap();
        }
        let mut fin = FinalityTracker::new();
        let a = crate::hash::Hash32::hash(b"af86-a-117");
        let off = crate::hash::Hash32::hash(b"af86-sibling-chain-118");
        let on = crate::hash::Hash32::hash(b"af86-a-chain-119");
        fin.record_verified_vote_on_chain(&set, a, 117, vid(1), true);
        assert_eq!(fin.record_verified_vote_on_chain(&set, a, 117, vid(2), true), VoteRecord::Finalized);
        assert_eq!((fin.finalized_height(), fin.finalized_block()), (117, Some(a)));
        // a full quorum on a block off the final block's chain: counted, never finalized
        for v in 1..=3u8 {
            assert_eq!(fin.record_verified_vote_on_chain(&set, off, 118, vid(v), false), VoteRecord::Counted);
        }
        assert_eq!((fin.finalized_height(), fin.finalized_block()), (117, Some(a)), "a quorum off the final chain moved finality");
        // the chain goes on: a quorum that extends it finalizes as before
        fin.record_verified_vote_on_chain(&set, on, 119, vid(1), true);
        assert_eq!(fin.record_verified_vote_on_chain(&set, on, 119, vid(2), true), VoteRecord::Finalized);
        assert_eq!((fin.finalized_height(), fin.finalized_block()), (119, Some(on)));
        // a vote dies only once MORE than a third of the weight voted otherwise at its height
        let (x, y, z) = (crate::hash::Hash32::hash(b"af86-x"), crate::hash::Hash32::hash(b"af86-y"), crate::hash::Hash32::hash(b"af86-z"));
        fin.record_verified_vote_on_chain(&set, x, 121, vid(1), true);
        fin.record_verified_vote_on_chain(&set, y, 121, vid(2), true);
        assert!(!fin.vote_is_dead(&set, 121, &x), "one third against still leaves x a quorum (vid 1 + vid 3)");
        fin.record_verified_vote_on_chain(&set, z, 121, vid(3), true);
        assert!(fin.vote_is_dead(&set, 121, &x), "two thirds voted otherwise: x can never reach a quorum");
        assert_eq!(fin.open_votes_of(&vid(1)).first(), Some(&(121, x)));
    }

    #[test]
    fn finality_needs_two_thirds_bonded_weight() {
        let mut set = ValidatorSet::new();
        // three equal validators, low TVL so the floor is the base.
        for i in 1..=3u8 {
            set.admit(vid(i), 2000, 0).unwrap();
        }
        assert_eq!(set.total_bond(), 6000);

        let mut fin = FinalityTracker::new();
        let block = crate::hash::Hash32::hash(b"a-finalized-block");

        // one vote = 1/3 -> counted, not finalized.
        assert_eq!(
            fin.record_verified_vote(&set, block, 42, vid(1)),
            VoteRecord::Counted
        );
        assert_eq!(fin.finalized_height(), 0);
        // a non-bonded voter contributes nothing.
        assert_eq!(
            fin.record_verified_vote(&set, block, 42, vid(9)),
            VoteRecord::NoWeight
        );
        assert_eq!(fin.finalized_height(), 0);
        // second distinct vote = 2/3 -> finalized, height advances.
        assert_eq!(
            fin.record_verified_vote(&set, block, 42, vid(2)),
            VoteRecord::Finalized
        );
        assert_eq!(fin.finalized_height(), 42);
        // finalized height is monotonic (an older block cannot regress it).
        let older = crate::hash::Hash32::hash(b"older-block");
        fin.record_verified_vote(&set, older, 10, vid(1));
        fin.record_verified_vote(&set, older, 10, vid(2));
        assert_eq!(fin.finalized_height(), 42);
    }

    /// ⭐ O(1) FOOTPRINT (2026-09-18): the tally maps grew with history — one row per (validator, height)
    /// forever. They are bounded by the retention depth now, and a vote below it is refused as NoWeight
    /// (not counted, not re-flooded) instead of re-growing the map.
    #[test]
    fn finality_tally_is_bounded_by_the_retention_depth() {
        let mut set = ValidatorSet::new();
        for i in 1..=3u8 {
            set.admit(vid(i), 2000, 0).unwrap();
        }
        let mut fin = FinalityTracker::new();
        let n = FINALITY_VOTE_RETENTION * 3;
        for h in 1..=n {
            let block = crate::hash::Hash32::hash(&h.to_le_bytes());
            fin.record_verified_vote(&set, block, h, vid(1));
            fin.record_verified_vote(&set, block, h, vid(2));
        }
        assert_eq!(fin.finalized_height(), n);
        // CACHE-ONLY: the slasher memory is local evidence derived from the carried votes this node folded; a slash applies
        // only from the carried `Class::Equivocation` object (`equivocation_tx::apply_chain_equivocation`)
        let (open, blocks) = fin.tally_rows();
        let rows = open + fin.settled_rows();
        assert!(rows <= (FINALITY_VOTE_RETENTION as usize + 1) * 2, "voted_at + settled rows {rows} grew with history");
        assert!(blocks <= FINALITY_VOTE_RETENTION as usize + 1, "voters rows {blocks} grew with history");
        let stale = crate::hash::Hash32::hash(b"stale");
        assert_eq!(fin.record_verified_vote(&set, stale, 1, vid(3)), VoteRecord::NoWeight);
        assert_eq!((fin.tally_rows(), fin.settled_rows()), ((open, blocks), rows - open), "a stale vote must not re-grow the tally");
    }

    /// ⛔ A-F106 (lane speed5, 2026-11-19): the open tally is bounded while finality does NOT move. One of three equal seats
    /// votes every height for three retention depths, so no height ever reaches 2/3 and `finalized_height` stays 0 — the case
    /// a chain whose overlay is absent or stalled lives in. RED on the rule that pruned only against `finalized_height`
    /// (the tally grew by one row a height: 3 × RETENTION rows); bounded by RETENTION + 1 on the vote frontier's floor.
    #[test]
    fn af106_the_open_tally_is_bounded_while_finality_does_not_move() {
        let mut set = ValidatorSet::new();
        for i in 1..=3u8 {
            set.admit(vid(i), 2000, 0).unwrap();
        }
        let mut fin = FinalityTracker::new();
        let n = FINALITY_VOTE_RETENTION * 3;
        for h in 1..=n {
            let block = crate::hash::Hash32::hash(&h.to_le_bytes());
            assert_ne!(fin.record_verified_vote(&set, block, h, vid(1)), VoteRecord::Finalized, "CALIBRATION: one of three seats never finalizes");
        }
        assert_eq!(fin.finalized_height(), 0, "CALIBRATION: finality never moved");
        let (open, blocks) = fin.tally_rows();
        assert!(open <= FINALITY_VOTE_RETENTION as usize + 1, "⛔ A-F106: the open tally holds {open} rows after {n} heights with no finality");
        assert!(blocks <= FINALITY_VOTE_RETENTION as usize + 1, "⛔ A-F106: the voters map holds {blocks} blocks after {n} heights");
        // a vote far under the frontier is not tallied and re-grows nothing; one at the frontier still counts
        let stale = crate::hash::Hash32::hash(b"af106-stale");
        assert_eq!(fin.record_verified_vote(&set, stale, 1, vid(2)), VoteRecord::NoWeight);
        assert_eq!(fin.tally_rows(), (open, blocks), "a stale vote must not re-grow the tally");
        let fresh = crate::hash::Hash32::hash(&n.to_le_bytes());
        assert_eq!(fin.record_verified_vote(&set, fresh, n, vid(2)), VoteRecord::Counted, "a vote at the frontier is still tallied");
    }

    // ADVERSARIAL: a validator that DOUBLE-SIGNS (two different blocks at the same height) is detected
    // as equivocation and SLASHED — bond forfeited, weight gone, barred forever. Honest voters untouched.
    #[test]
    fn equivocation_is_slashed_and_barred_forever() {
        let mut set = ValidatorSet::new();
        for i in 1..=3u8 {
            set.admit(vid(i), 2000, 0).unwrap();
        }
        assert_eq!(set.total_bond(), 6000);

        let mut fin = FinalityTracker::new();
        let block_a = crate::hash::Hash32::hash(b"block-A@height-7");
        let block_b = crate::hash::Hash32::hash(b"block-B@height-7"); // CONFLICTING, SAME height

        // honest first vote; re-voting the SAME block is idempotent (NOT equivocation).
        assert_eq!(
            fin.record_verified_vote(&set, block_a, 7, vid(1)),
            VoteRecord::Counted
        );
        assert_eq!(
            fin.record_verified_vote(&set, block_a, 7, vid(1)),
            VoteRecord::Counted
        );
        // a DIFFERENT block at the SAME height by the same voter = EQUIVOCATION (evidence = block_a).
        assert_eq!(
            fin.record_verified_vote(&set, block_b, 7, vid(1)),
            VoteRecord::Equivocation {
                first_block: block_a
            }
        );

        // SLASH: bond burned, removed, zero weight.
        let burned = set.slash(&vid(1)).expect("equivocator was bonded");
        assert_eq!(burned, 2000);
        assert_eq!(set.slashed_bond_burned(), 2000);
        assert_eq!(set.bond_of(&vid(1)), 0, "slashed validator has zero weight");
        assert_eq!(
            set.total_bond(),
            4000,
            "slashed bond left the bonded weight forever"
        );
        assert!(set.is_slashed(&vid(1)));

        // BARRED FOREVER: cannot re-admit even with a fresh sufficient bond.
        assert_eq!(set.admit(vid(1), 2000, 0), Err(ValidatorError::Slashed));

        // Honest validators are untouched: vid(2)+vid(3) still finalize over the remaining 4000 weight.
        assert_eq!(set.bond_of(&vid(2)), 2000);
        let mut fin2 = FinalityTracker::new();
        let good = crate::hash::Hash32::hash(b"good-block");
        assert_eq!(
            fin2.record_verified_vote(&set, good, 9, vid(2)),
            VoteRecord::Counted
        );
        assert_eq!(
            fin2.record_verified_vote(&set, good, 9, vid(3)),
            VoteRecord::Finalized
        );
        assert_eq!(fin2.finalized_height(), 9);
    }
}

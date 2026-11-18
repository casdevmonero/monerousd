// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! DB-121x — THE MONERO PAYOUT LANE: how a burn of USDm becomes XMR at the redeemer's address, signed by the bonded
//! custodians' own wallets and observed confirmed by each of them (EXTERNAL-CHAIN code, the Monero twin of
//! `btc_payout`).
//!
//! THE SHAPE. Monero's k-of-n multisig signs in SEQUENCE: one wallet builds the transaction (`transfer`, never
//! relayed), each further signer adds its signature from its own wallet (`sign_multisig`), and whoever holds k
//! signatures relays it (`submit_multisig`). Before any of that the wallets must have exchanged their view of the
//! reserve's outputs (`export_multisig_info` → `import_multisig_info`). This lane automates all of it over the
//! mesh — nothing is done by hand — with the bond-weighted tally's rules from the Bitcoin lane kept intact:
//!   • an obligation exists only because a block carried the burn (`Class::PegOut`) and this custodian opened its
//!     sealed leg; the destination never rides the mesh (DB-110);
//!   • F1: a burn is paid only from a finalized block; F4: one signature per burn per custodian; F5: the release is
//!     recorded when THIS node's own wallet sees the payout confirmed (Monero's 10-block lock), never on a
//!     signature count; F7: a signer refuses a fee above `FEE_CEIL_MULTIPLE` × its own daemon's estimate;
//!   • the proposer rotates by finalized chain time (`btc_payout::PROPOSER_SLOT_MS`) so no one node's silence holds
//!     a payout; the signing order is the sorted member list rotated to the proposer, so k signers never fork the
//!     set in two directions;
//!   • every signer checks, on ITS OWN wallet (`describe_transfer`), that the set pays exactly what ITS OWN book
//!     owes — the addresses and amounts — and nothing else.
//! No caps, no throttles, no pause: a burn is paid as soon as it is finalized and the wallets agree. One Monero
//! transaction pays at most `XMR_LEGS_MAX` burns (Monero's own output limit); every further burn STAYS OWED in the
//! book and the next payout pays it — nothing is ever dropped. The book is this custodian's own file beside its
//! validator key; every collection in it is a function of the burns the chain still says are owed (removed when
//! settled or no longer pending) and of the member count — never history.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::node::Node;
use crate::protocol::WireMsg;
use crate::xmr_custody::{set_id, threshold, CustodyLane};
use crate::xmr_rpc::{DaemonRpc, WalletRpc};

/// The lane's poll — the Bitcoin lane's own cadence.
/// PAST-CHATS-CHECKED: `btc_payout::PAYOUT_POLL_MS`.
pub const XMR_PAYOUT_POLL_MS: u64 = crate::btc_payout::PAYOUT_POLL_MS;
/// How many burns ONE Monero transaction pays: Monero allows 16 outputs per transaction and one is the change.
/// Burns beyond it stay owed and ride the next transaction — a transaction size, never a limit on what is paid.
/// PAST-CHATS-CHECKED: Monero protocol constant (BULLETPROOF_MAX_OUTPUTS = 16), minus the change output.
pub const XMR_LEGS_MAX: usize = 15;
/// A signer refuses a fee above this many times its own daemon's per-byte estimate over the set's byte length —
/// the Bitcoin lane's own ceiling. The multisig set is longer than the transaction it carries, so the bound is
/// generous for the default priority and still refuses Monero's higher priority multipliers.
/// PAST-CHATS-CHECKED: `btc_payout::FEE_CEIL_MULTIPLE`.
pub const XMR_FEE_CEIL_MULTIPLE: u64 = crate::btc_payout::FEE_CEIL_MULTIPLE;

/// One burn's Monero obligation, as THIS custodian opened it from the block that carried the burn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmrObligation {
    pub release_atomic: u64,
    pub redeem_to: String,
    pub burn_height: u64,
    /// §BR-1: the sealed pay-after, chain-time ms (see `btc_payout::Obligation::pay_after`).
    #[serde(default)]
    pub pay_after: u64,
}

/// The custodian's Monero book: the burns it owes and the one payout it signed for each (F4). Both maps hold one
/// row per burn the chain still says is owed and shed it at settlement.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XmrBook {
    pub obligations: BTreeMap<[u8; 32], XmrObligation>,
    pub locks: BTreeMap<[u8; 32], [u8; 32]>,
}

/// A custodian's exported multisig state for the set, signed with its chain identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncMsg {
    pub set_id: [u8; 32],
    pub from: [u8; 32],
    pub info: String,
    pub signer_pk: Vec<u8>,
    pub sig: Vec<u8>,
}

/// A payout in progress: the burns it pays (nullifiers only, at most `XMR_LEGS_MAX`), the multisig set as signed so
/// far, the signers in order (the proposer first, at most the member count), the tx hashes once complete, and
/// whether it was relayed. Signed by the LAST signer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutMsg {
    pub set_id: [u8; 32],
    pub legs: Vec<[u8; 32]>,
    pub txset: String,
    pub signers: Vec<[u8; 32]>,
    pub txids: Vec<String>,
    pub submitted: bool,
    /// A custodian's notice that ITS OWN wallet saw this payout confirmed — the resolution a node without a
    /// wallet sheds its relay memory on (a custodian settles only on its own observation, F5, never on this).
    pub settled: bool,
    pub signer_pk: Vec<u8>,
    pub sig: Vec<u8>,
}

impl PayoutMsg {
    /// One payout's identity across its signing rounds: the set, the proposer and the burns it pays.
    pub fn id(&self) -> [u8; 32] {
        let mut pre = Vec::with_capacity(64 + 32 * self.legs.len());
        pre.extend_from_slice(b"USDMD-XMR-PAYOUT-ID-v1");
        pre.extend_from_slice(&self.set_id);
        if let Some(p) = self.signers.first() {
            pre.extend_from_slice(p);
        }
        for l in &self.legs {
            pre.extend_from_slice(l);
        }
        *blake3::hash(&pre).as_bytes()
    }

    fn statement(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(128 + 32 * (self.legs.len() + self.signers.len()));
        m.extend_from_slice(b"USDMD-XMR-PAYOUT-v1");
        m.extend_from_slice(&self.set_id);
        m.extend_from_slice(&(self.legs.len() as u32).to_le_bytes());
        for l in &self.legs {
            m.extend_from_slice(l);
        }
        m.extend_from_slice(blake3::hash(self.txset.as_bytes()).as_bytes());
        m.extend_from_slice(&(self.signers.len() as u32).to_le_bytes());
        for s in &self.signers {
            m.extend_from_slice(s);
        }
        for t in &self.txids {
            m.extend_from_slice(t.as_bytes());
        }
        m.push(self.submitted as u8);
        m.push(self.settled as u8);
        m
    }
}

fn sync_statement(set_id: &[u8; 32], info: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(48 + 32);
    m.extend_from_slice(b"USDMD-XMR-SYNC-v1");
    m.extend_from_slice(set_id);
    m.extend_from_slice(blake3::hash(info.as_bytes()).as_bytes());
    m
}

fn signed_by_member(node: &Node, from: &[u8; 32], pk: &[u8], sig: &[u8], statement: &[u8]) -> bool {
    crate::pqauth::pubkey_id(pk) == *from
        && node.custodian_ids_sorted().contains(from)
        && crate::pqauth::ml_dsa_verify(statement, pk, sig)
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn h32(display: &[u8; 32]) -> String {
    crate::btc_tx::hex(&display[..8])
}

struct Slot {
    msg: PayoutMsg,
    /// when this node first held the round (unix ms): an own proposal still short of its signatures after
    /// [`XMR_PROPOSAL_REBUILD_POLLS`] polls is rebuilt
    born_ms: u64,
}

/// Polls an own proposal may wait short of its signatures before the proposer drops it and builds a fresh one. Monero's
/// multisig refuses a transaction set made with state the other members have since moved past ("This signature was made
/// with stale data: export fresh multisig data"); the members re-share their state every poll, so a rebuilt set signs.
/// One refused set used to strand the payout for good (MEASURED 2026-11-08, real nodes: one proposal, one stale-data
/// refusal, no Monero ever paid). F4 still holds: the other member signs at most one set per leg (its lock).
const XMR_PROPOSAL_REBUILD_POLLS: u64 = 12;

/// The lane: the book, the payouts in flight (one slot per payout, shed at settlement), what this node last
/// imported from each member (one digest per member), and the poll clock.
pub struct XmrPayoutLane {
    book: XmrBook,
    book_path: PathBuf,
    slots: BTreeMap<[u8; 32], Slot>,
    imported: BTreeMap<[u8; 32], [u8; 32]>,
    last_poll_ms: u64,
    /// this wallet's last exported multisig state and the (balance, unlocked) it was exported at: re-shared as is every
    /// poll, exported afresh only when the wallet's outputs moved (see `tick`)
    exported: Option<(String, (u64, u64))>,
    /// spec §3g.1: the rebalance parts (by leg id) this custodian's own wallet showed arrived for its vault at its last
    /// poll (`check_rebalance_arrival`). PROCESS-LOCAL by design: re-read every poll. At most one (the carve door).
    rebalance_seen: BTreeSet<[u8; 32]>,
    /// spec §3g.1: the rebalance moves this custodian's own wallet received, by transaction: `(fee, the receiving set)`.
    /// A Monero payout's fee comes out of what it pays, so the part arrives less the fee and the receiving vault's ledger
    /// (which the take moves by the whole part) owes that fee to `Class::ReserveCost` — judged from these records and this
    /// wallet (`judge_rebalance_cost`), each written only while the slot that names the payment id stood on the chain.
    /// Kept in this lane's own file: a fee that left custody must reach the ledger whatever restarts in between (A-F21).
    /// O1-INFINITY-REVIEWED: an entry leaves once the chain books it; at most `crate::btc_payout::COSTS_PENDING_MAX`.
    rebalance_costs: BTreeMap<String, (u64, [u8; 32])>,
    rebalance_costs_path: PathBuf,
}

fn rebalance_costs_path() -> PathBuf {
    crate::persist::state_dir().join(format!("xmr-rebalance-{}.bin", crate::persist::serving_port()))
}

/// The tag that tells a Monero rebalance move's cost evidence from a sweep's and a Bitcoin move's.
const XMR_REBALANCE_EVIDENCE_TAG: &[u8; 4] = b"XMRB";

/// The evidence a Monero rebalance move's cost signature carries: the receiving set, the move's transaction and its fee.
/// What makes it true is in each judge's own record and wallet (`XmrPayoutLane::judge_rebalance_cost`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmrRebalanceCost {
    pub set_id: [u8; 32],
    pub txid: String,
    pub fee: u64,
}

impl XmrRebalanceCost {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = XMR_REBALANCE_EVIDENCE_TAG.to_vec();
        out.extend_from_slice(&postcard::to_allocvec(self).unwrap_or_default());
        out
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let e: Self = crate::chain_object::decode_exact(bytes.strip_prefix(XMR_REBALANCE_EVIDENCE_TAG)?)?;
        (e.txid.len() == 64 && e.fee > 0).then_some(e)
    }
}

fn book_path() -> PathBuf {
    // DB-341: a per-node file lives in the node's state directory under the port this process SERVES — an isolated
    // node (MONEROUSD_STATE_DIR) never reads or writes the operator's live book.
    crate::persist::state_dir().join(format!("xmr-book-{}.bin", crate::persist::serving_port()))
}

impl XmrPayoutLane {
    pub fn new() -> Self {
        let book_path = book_path();
        // Through the custody keystore: sealed at rest under the operator passphrase when one is configured.
        // O1-INFINITY-REVIEWED: this custodian's own book, one file whose size is set by the obligations still open
        // (settled ones leave it); the read existed before and only the at-rest form changes.
        let book = match crate::keystore::read_key_file(&book_path) {
            Ok(bytes) => match crate::chain_object::decode_exact::<XmrBook>(&bytes) {
                Some(b) => b,
                None => {
                    eprintln!("[xmr-payout] ⛔ the Monero book on disk does not decode — starting from an empty book; obligations re-appear as this node re-applies its blocks");
                    XmrBook::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => XmrBook::default(),
            Err(e) => {
                eprintln!("[xmr-payout] ⛔ the Monero book on disk does not open ({e}) — starting from an empty book; obligations re-appear as this node re-applies its blocks");
                XmrBook::default()
            }
        };
        // spec §3g.1: this lane's own record of the rebalance moves it received (a separate file: the book's encoding is unchanged)
        let rebalance_costs_path = rebalance_costs_path();
        let rebalance_costs = crate::keystore::read_key_file(&rebalance_costs_path).ok().and_then(|b| crate::chain_object::decode_exact(&b)).unwrap_or_default();
        XmrPayoutLane {
            book,
            book_path,
            slots: BTreeMap::new(),
            imported: BTreeMap::new(),
            last_poll_ms: 0,
            exported: None,
            rebalance_seen: BTreeSet::new(),
            rebalance_costs,
            rebalance_costs_path,
        }
    }

    fn save_rebalance_costs(&self) {
        match postcard::to_allocvec(&self.rebalance_costs) {
            Ok(bytes) => {
                if let Err(e) = crate::keystore::write_key_file(&self.rebalance_costs_path, &bytes) {
                    eprintln!("[xmr-payout] ⛔ the rebalance cost record was not written: {e}");
                }
            }
            Err(e) => eprintln!("[xmr-payout] ⛔ the rebalance cost record did not encode: {e}"),
        }
    }

    /// ⭐ spec §3g.1 — THE ONE LEG ID OF A REBALANCE'S MONERO MOVE out of vault `from`: derived from the slot's own coin seed,
    /// so a payout round names the part it moves (it is no burn), and this custodian's lock under it records that it signed
    /// one (`rebalance_signed`).
    #[must_use]
    pub fn rebalance_leg_id(node: &Node, from: u32) -> Option<[u8; 32]> {
        let seed = node.rebalance_coin_seed(from, "XMR")?;
        let mut h = blake3::Hasher::new_derive_key("musdm.xmr.rebalance-leg.v1");
        h.update(&seed);
        Some(*h.finalize().as_bytes())
    }

    /// The payment id vault `from`'s part is sent under, and the integrated address of key `key`'s wallet it goes to —
    /// both derived by both vaults from the chain alone.
    fn rebalance_dest(node: &Node, from: u32, key: &crate::peg::VaultKeyRow) -> Option<([u8; 8], String)> {
        let seed = node.rebalance_coin_seed(from, "XMR")?;
        let mut pid = [0u8; 8];
        pid.copy_from_slice(&seed[..8]);
        let (_, main) = Node::vault_key_monero(key)?;
        Some((pid, crate::bridge::xmr_integrated_address(main, &pid)?))
    }

    /// The part's piconero: the reserve of the part this custodian holds of vault `from`'s Monero bridge leg.
    fn rebalance_atomic(node: &Node, from: u32) -> Option<u64> {
        let p = node.rebalance_part_held(from, crate::peg::XMR_PEG_ASSET_ID)?;
        u64::try_from(p.0).ok().filter(|v| *v > 0)
    }

    /// Has THIS custodian's own lane signed a Monero move of vault `from`'s part? (A custodian signs a part's move or its
    /// cancel, never both.)
    #[must_use]
    pub fn rebalance_signed(&self, node: &Node, from: u32) -> bool {
        Self::rebalance_leg_id(node, from).is_some_and(|id| self.book.locks.contains_key(&id))
    }

    /// Did THIS custodian's own wallet show vault `from`'s part arrive (`check_rebalance_arrival`, read each poll)?
    #[must_use]
    pub fn rebalance_arrived(&self, node: &Node, from: u32) -> bool {
        Self::rebalance_leg_id(node, from).is_some_and(|id| self.rebalance_seen.contains(&id))
    }

    /// The poll's look for a part FOR this custodian's vault on its own wallet: an incoming transfer under the slot's
    /// payment id, past Monero's lock, whose amount and public fee add to exactly the part (a Monero payout's fee comes
    /// out of what it pays). Found: the part arrived, and the transfer's fee is recorded for the cost lane.
    /// CACHE-ONLY: this custodian's own view of Monero; it decides only what THIS custodian signs.
    fn check_rebalance_arrival(&mut self, node: &Node, rpc: &WalletRpc, sid: &[u8; 32]) {
        self.rebalance_seen.clear();
        let here = node.vault_here();
        let incoming: Vec<u32> = node.peg().vault_parts_all().filter(|(_, p)| p.into == here && p.legs.iter().any(|l| l.asset == crate::peg::XMR_PEG_ASSET_ID)).map(|(f, _)| f).collect();
        if incoming.is_empty() {
            return;
        }
        let Ok(transfers) = rpc.incoming() else { return };
        for from in incoming {
            let (Some(key), Some(want), Some(id)) = (node.rebalance_consented_key(from), Self::rebalance_atomic(node, from), Self::rebalance_leg_id(node, from)) else { continue };
            let Some((pid, _)) = Self::rebalance_dest(node, from, &key) else { continue };
            let pid_hex = crate::btc_tx::hex(&pid);
            for t in transfers.iter().filter(|t| t.payment_id == pid_hex) {
                let Ok(Some((amount, fee, confs, _))) = rpc.transfer_fee(&t.txid) else { continue };
                if confs >= crate::xmr_watch::XMR_SPEND_LOCK_BLOCKS && fee > 0 && amount.checked_add(fee) == Some(want) {
                    self.rebalance_seen.insert(id);
                    if !self.rebalance_costs.contains_key(&t.txid) && self.rebalance_costs.len() < crate::btc_payout::COSTS_PENDING_MAX {
                        self.rebalance_costs.insert(t.txid.clone(), (fee, *sid));
                        self.save_rebalance_costs();
                        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line and a public Monero fee — custody's own move between vaults.
                        eprintln!("[xmr-payout] a rebalance's part arrived in this vault's wallet (less its {fee} piconero fee, owed to the ledger)");
                    }
                }
            }
        }
    }

    /// The rebalance moves this custodian's own wallet received whose fee the chain has not booked, as cost evidence.
    #[must_use]
    pub fn rebalance_cost_evidence(&self) -> Vec<Vec<u8>> {
        self.rebalance_costs.iter().map(|(txid, (fee, sid))| XmrRebalanceCost { set_id: *sid, txid: txid.clone(), fee: *fee }.encode()).collect()
    }

    /// The fees of rebalance moves this custodian's wallet received and the chain has not booked yet, dropping the ones it
    /// has: counted back into the Monero solvency reading, as a sweep's are.
    pub fn rebalance_fees_in_flight(&mut self, node: &Node) -> u64 {
        let ledger = node.ledger_here(crate::peg::XMR_PEG_ASSET_ID);
        let before = self.rebalance_costs.len();
        self.rebalance_costs.retain(|txid, _| crate::btc_tx::unhex(txid).and_then(|b| <[u8; 32]>::try_from(b).ok()).is_some_and(|t| !node.reserve_cost_booked(ledger, &t)));
        if self.rebalance_costs.len() != before {
            self.save_rebalance_costs();
        }
        self.rebalance_costs.values().fold(0u64, |a, (fee, _)| a.saturating_add(*fee))
    }

    /// ⭐⭐ JUDGE A MONERO REBALANCE MOVE'S FEE (A-F21: the ledger follows every coin) from THIS node's own record and wallet —
    /// `(ledger asset, fee, transaction)` when, here and now: the set the evidence names is this custodian's own vault's
    /// current set; its own record holds that transaction at that fee (written only while the slot naming the payment id
    /// stood on its chain); and its own wallet shows that transaction arriving, at that public fee, past Monero's lock.
    /// AI RESISTANT: (b) bounded by the receiving vault's quorum and the cost door's own bound: a false cost needs two thirds
    /// of the vault to have recorded a transfer that never came at the slot's payment id.
    #[must_use]
    pub fn judge_rebalance_cost(&self, evidence: &[u8], node: &Node, rpc: &WalletRpc) -> Option<(u32, u64, [u8; 32])> {
        let e = XmrRebalanceCost::decode(evidence)?;
        node.custodian_id()?;
        if e.set_id != set_id(&node.custody_set_here()) || self.rebalance_costs.get(&e.txid) != Some(&(e.fee, e.set_id)) {
            return None;
        }
        let (_, fee, confs, _) = rpc.transfer_fee(&e.txid).ok().flatten()?;
        let id: [u8; 32] = crate::btc_tx::unhex(&e.txid)?.try_into().ok()?;
        (fee == e.fee && confs >= crate::xmr_watch::XMR_SPEND_LOCK_BLOCKS).then_some((crate::peg::XMR_PEG_ASSET_ID, e.fee, id))
    }

    /// ⭐⭐ spec §3g.1 — A REBALANCE'S MONERO MOVE: one round whose one leg is this vault's part (`rebalance_leg_id`). A custodian
    /// signs it only when, on ITS OWN chain, record and wallet: its own vault has a part at rest with a Monero leg; two thirds
    /// of the receiving vault consented to a key the chain records as that vault's CURRENT key (`Node::rebalance_send_key`);
    /// and the set pays exactly one recipient — that key's wallet at the slot's payment id — the part less at most the fee it
    /// carries, the fee inside F7. The common round checks (set, signers, the last signer's signature, F4's lock) are the
    /// cash-out's own.
    /// §9.6 and the pillar answers: as `btc_payout::PayoutLane::verify_rebalance_move` (the same rule on Monero).
    fn verify_rebalance(&self, m: &PayoutMsg, node: &Node, rpc: &WalletRpc) -> Option<Vec<(String, u64)>> {
        let from = node.vault_here();
        let (Some(key), Some(part)) = (node.rebalance_send_key(from), Self::rebalance_atomic(node, from)) else {
            eprintln!("[xmr-payout] not signing the rebalance move: no consent of the receiving vault to its current key, or no opening of the part here");
            return None;
        };
        let (_, dest) = Self::rebalance_dest(node, from, &key)?;
        if let Some(locked) = self.book.locks.get(&m.legs[0]) {
            if *locked != m.id() {
                eprintln!("[xmr-payout] ⛔ not signing: this custodian already signed another move of this part (F4)");
                return None;
            }
        }
        let (recipients, fee) = match rpc.describe_multisig(&m.txset) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[xmr-payout] not signing: this node's wallet could not read the proposed set: {e}");
                return None;
            }
        };
        let ok = recipients.len() == 1 && recipients[0].address == dest && u128::from(recipients[0].amount) + u128::from(fee) == u128::from(part);
        if !ok {
            eprintln!("[xmr-payout] ⛔ not signing: the set does not pay exactly the part, less its fee, to the key the receiving vault consented to");
            return None;
        }
        if !Self::fee_ok(fee, &m.txset) {
            return None;
        }
        Some(vec![(dest, part)])
    }

    pub fn book(&self) -> &XmrBook {
        &self.book
    }

    /// How many payouts this node is tracking (the status door and the journeys read it).
    pub fn proposals_in_flight(&self) -> usize {
        self.slots.len()
    }

    /// Through the custody keystore (atomic: a temp name renamed into place; sealed when a passphrase is configured).
    fn save(&self) {
        match postcard::to_allocvec(&self.book) {
            Ok(bytes) => {
                if let Err(e) = crate::keystore::write_key_file(&self.book_path, &bytes) {
                    eprintln!("[xmr-payout] ⛔ the Monero book was not written: {e}");
                }
            }
            Err(e) => eprintln!("[xmr-payout] ⛔ the Monero book did not encode: {e}"),
        }
    }

    /// OWED, the hand-over — the burns a payout round names (empty for bytes that are not one round): what the runtime
    /// checks this custodian's legs against before the round is judged.
    #[must_use]
    pub fn legs_named(bytes: &[u8]) -> Vec<[u8; 32]> {
        crate::chain_object::decode_exact::<PayoutMsg>(bytes).map(|m| m.legs).unwrap_or_default()
    }

    /// OWED, the hand-over — does this lane's book hold the obligation of the cash-out that burned `nf`?
    #[must_use]
    pub fn holds_leg(&self, nf: &[u8; 32]) -> bool {
        self.book.obligations.contains_key(nf)
    }

    /// A burn this custodian opened owes Monero. CHAIN-OBJECT: `Class::PegOut` — the runtime hands this over from
    /// the block's own event, and only while the chain still says the release is pending.
    pub fn book_obligation(&mut self, node: &Node, nf: [u8; 32], release_atomic: u64, redeem_to: String, burn_height: u64, pay_after: u64) {
        if release_atomic == 0 || !node.peg().release_pending(&nf) {
            return;
        }
        self.book.obligations.entry(nf).or_insert(XmrObligation { release_atomic, redeem_to, burn_height, pay_after });
        self.save();
        // DB-375: the burn's nullifier is NOT logged (beside the amount it links a USDm spend to an external payout).
        eprintln!("[xmr-payout] obligation booked ({} atomic, height {})", release_atomic, burn_height);
    }

    fn sign(signer: Option<(&[u8], &[u8])>, statement: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let (pk, sk) = signer?;
        let sig = crate::pqauth::ml_dsa_sign(statement, sk)?;
        Some((pk.to_vec(), sig))
    }

    fn am_proposer(node: &Node) -> bool {
        let Some(me) = node.custodian_id() else { return false };
        // SAFE AT SCALE: the rotation is over THIS custodian's vault (the whole bonded set on a one-vault chain)
        let ids = node.custody_set_here();
        if ids.is_empty() {
            return false;
        }
        let slot = (node.payout_final_time_ms() / crate::btc_payout::PROPOSER_SLOT_MS) as usize % ids.len();
        ids[slot] == me
    }

    /// The member who signs next: the sorted members rotated to start at the proposer, the first not yet signed.
    fn next_signer(members: &[[u8; 32]], signers: &[[u8; 32]]) -> Option<[u8; 32]> {
        let proposer = signers.first()?;
        let start = members.iter().position(|m| m == proposer)?;
        (0..members.len())
            .map(|i| members[(start + i) % members.len()])
            .find(|m| !signers.contains(m))
    }

    /// F7 for Monero: the fee a set carries against this node's own daemon estimate over the set's byte length.
    pub(crate) fn fee_ok(fee: u64, txset: &str) -> bool {
        let Some(daemon) = DaemonRpc::from_env() else {
            eprintln!("[xmr-payout] not signing: this node has no Monero daemon (MONEROUSD_XMR_DAEMON_URL) to judge the proposal's fee against");
            return false;
        };
        let Ok(per_byte) = daemon.fee_per_byte() else {
            eprintln!("[xmr-payout] not signing: this node's Monero daemon gave no fee estimate");
            return false;
        };
        let set_bytes = (txset.len() / 2) as u64;
        let ceiling = per_byte.saturating_mul(set_bytes).saturating_mul(XMR_FEE_CEIL_MULTIPLE);
        if fee == 0 || fee > ceiling {
            eprintln!("[xmr-payout] ⛔ not signing: the fee {fee} is outside (0, {XMR_FEE_CEIL_MULTIPLE}× this node's own estimate over the set's length] (F7)");
            return false;
        }
        true
    }

    /// The burns this node pays in the NEXT transaction: owed, finalized, on this node's Monero network, not in
    /// flight — the first `XMR_LEGS_MAX` by nullifier; every other payable burn stays in the book and the next
    /// transaction pays it.
    fn payable_legs(&self, node: &Node) -> Vec<([u8; 32], XmrObligation)> {
        let finalized = node.payout_final_height(); // SPEED L7 + FINALITY OVERLAY (2026-11-17): vote-final OR 64 levels deep (Node::payout_final_height)
        let net = crate::bridge::xmr_net_byte();
        let in_flight: BTreeSet<[u8; 32]> = self.slots.values().flat_map(|s| s.msg.legs.iter().copied()).collect();
        self.book
            .obligations
            .iter()
            .filter(|(nf, ob)| {
                !in_flight.contains(*nf)
                    && node.peg().release_pending(nf)
                    && ob.burn_height <= finalized
                    && crate::bridge::xmr_address_net(&ob.redeem_to) == Some(net)
            })
            .map(|(nf, ob)| (*nf, ob.clone()))
            .take(XMR_LEGS_MAX)
            .collect()
    }

    /// Verify a payout message against THIS node's book, wallet and chain; the recipients it must pay.
    fn verify(&self, m: &PayoutMsg, node: &Node, rpc: &WalletRpc, members: &[[u8; 32]], sid: &[u8; 32]) -> Option<Vec<(String, u64)>> {
        if m.set_id != *sid || m.legs.is_empty() || m.legs.len() > XMR_LEGS_MAX || m.signers.is_empty() {
            return None;
        }
        // R7, coins first: while this vault's merge is due its Monero is leaving for the receiving vault's key (the
        // sweep lane empties this wallet) — no cash-out is signed from coins that are leaving; the receiving vault's
        // custodians pay it once the ledgers have followed. The Bitcoin lane holds the same rule.
        // CACHE-ONLY: read from the chain-derived set and ledgers; it decides only what THIS custodian signs.
        if node.own_vault_coins_leaving() {
            eprintln!("[xmr-payout] not signing: this vault's merge is due — its Monero moves to the receiving vault before any cash-out is paid from it");
            return None;
        }
        let last = m.signers.last()?;
        if !signed_by_member(node, last, &m.signer_pk, &m.sig, &m.statement()) {
            return None;
        }
        let mut seen = BTreeSet::new();
        for s in &m.signers {
            if !members.contains(s) || !seen.insert(*s) {
                return None;
            }
        }
        // spec §3g.1: a round whose one leg is this vault's part at rest is the REBALANCE MOVE, judged by its own rule
        if m.legs.len() == 1 && Self::rebalance_leg_id(node, node.vault_here()) == Some(m.legs[0]) {
            return self.verify_rebalance(m, node, rpc);
        }
        let finalized = node.payout_final_height(); // SPEED L7 + FINALITY OVERLAY (2026-11-17): vote-final OR 64 levels deep (Node::payout_final_height)
        let mut want: Vec<(String, u64)> = Vec::with_capacity(m.legs.len());
        for (i, nf) in m.legs.iter().enumerate() {
            if m.legs[..i].contains(nf) || !node.peg().release_pending(nf) {
                eprintln!("[xmr-payout] not signing: a leg is not an owed burn on this node's chain");
                return None;
            }
            let Some(ob) = self.book.obligations.get(nf) else {
                eprintln!("[xmr-payout] not signing: this custodian holds no sealed leg for a proposed burn");
                return None;
            };
            if ob.burn_height > finalized {
                eprintln!("[xmr-payout] not signing yet: the burn's block is not finalized on this node (F1)");
                return None;
            }
            if ob.pay_after > node.payout_final_time_ms() {
                eprintln!("[xmr-payout] not signing yet: the piece's sealed pay-after is past the finalized chain clock (§BR-1)");
                return None;
            }
            if let Some(locked) = self.book.locks.get(nf) {
                if *locked != m.id() {
                    eprintln!("[xmr-payout] ⛔ not signing: this custodian already signed another payout for a leg (F4)");
                    return None;
                }
            }
            want.push((ob.redeem_to.clone(), ob.release_atomic));
        }
        let (recipients, fee) = match rpc.describe_multisig(&m.txset) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[xmr-payout] not signing: this node's wallet could not read the proposed set: {e}");
                return None;
            }
        };
        let mut got: Vec<(String, u64)> = recipients.into_iter().map(|r| (r.address, r.amount)).collect();
        got.sort();
        let mut want_sorted = want.clone();
        want_sorted.sort();
        // ⛔ every leg is paid to its own address, less at most its share of the fee, and the fee comes WHOLLY out of the legs
        // (`subtract_fee_from_outputs`): the reserve falls by exactly what the book owes — never by the fee on top, which
        // would leave the custody wallet below Monero's committed reserve after every payout
        let owed: u128 = want_sorted.iter().map(|(_, v)| u128::from(*v)).sum();
        let paid: u128 = got.iter().map(|(_, v)| u128::from(*v)).sum();
        let legs_ok = got.len() == want_sorted.len()
            && got.iter().zip(&want_sorted).all(|((ga, gv), (wa, wv))| ga == wa && gv <= wv && wv - gv <= fee);
        if !legs_ok || paid + u128::from(fee) != owed {
            eprintln!("[xmr-payout] ⛔ not signing: the set does not pay exactly the legs this custodian's own book owes, less the fee it carries");
            return None;
        }
        if !Self::fee_ok(fee, &m.txset) {
            return None;
        }
        Some(want)
    }

    fn broadcast(&self, m: &PayoutMsg) -> Option<WireMsg> {
        postcard::to_allocvec(m).ok().map(WireMsg::XmrPayoutRound)
    }

    /// Settle payouts this node's own wallet sees confirmed (F5); drop obligations the chain no longer owes.
    /// Returns this custodian's settled notices, one per payout it just settled, for the nodes that relay.
    /// CACHE-ONLY: what this marks (`settle_reserve_release_observed`) mirrors a payout THIS node's own wallet
    /// watched confirm on the foreign chain; the burn it releases was applied from `Class::PegOut` long before.
    fn settle(&mut self, node: &mut Node, rpc: &WalletRpc, signer: Option<(&[u8], &[u8])>) -> Vec<WireMsg> {
        let mut notices = Vec::new();
        let ids: Vec<[u8; 32]> = self.slots.keys().copied().collect();
        for id in ids {
            let Some(slot) = self.slots.get(&id) else { continue };
            if !slot.msg.submitted || slot.msg.txids.is_empty() {
                continue;
            }
            let mut confirmed = true;
            for txid in &slot.msg.txids {
                match rpc.tx_confirmations(txid) {
                    Ok(Some(c)) if c >= crate::xmr_watch::XMR_SPEND_LOCK_BLOCKS => {}
                    Ok(_) => confirmed = false,
                    Err(e) => {
                        eprintln!("[xmr-payout] this node's wallet did not answer for payout {txid}: {e}");
                        confirmed = false;
                    }
                }
            }
            if !confirmed {
                continue;
            }
            let legs = slot.msg.legs.clone();
            let txids = slot.msg.txids.clone();
            let mut notice = slot.msg.clone();
            // spec §3g.1: a rebalance move names its part, not a burn — nothing to release, and its lock stays (the cancel
            // rule reads it) until the part's slot closes
            // (read from this lane's own book: a leg that is no obligation it holds and no burn the chain owes)
            let rebalance = legs.len() == 1 && !self.book.obligations.contains_key(&legs[0]) && !node.peg().release_pending(&legs[0]);
            for nf in legs.iter().filter(|_| !rebalance) {
                // CACHE-ONLY: the release recorded here mirrors a payout THIS node's own wallet watched confirm;
                // the burn was applied from `Class::PegOut` long before.
                let outcome = node.settle_reserve_release_observed(nf);
                // DB-375: no nullifier beside the payout txids (that pair IS the USDm↔XMR link).
                eprintln!("[xmr-payout] ⭐ SETTLED — payout {:?} confirmed ({outcome:?})", txids);
                self.book.obligations.remove(nf);
                self.book.locks.remove(nf);
            }
            self.slots.remove(&id);
            self.save();
            notice.settled = true;
            if let Some((pk, sig)) = Self::sign(signer, &notice.statement()) {
                notice.signer_pk = pk;
                notice.sig = sig;
                if let Some(w) = self.broadcast(&notice) {
                    notices.push(w);
                }
            }
        }
        // DB-125 (measured 2026-09-21, run 3): a burn a reorg or a jump takes off this node's selected chain for a
        // while is NOT "no longer owed" — it returns with its block, and the sealed leg it was booked with is the
        // only copy this custodian holds (the destination is blinded on the chain, DB-110). Pruning it on that
        // transient left the redeemer unpaid for good ("holds no sealed leg"). Only a release the chain state
        // shows SETTLED (burned, no longer pending — replayed from this node's own settlement) sheds it.
        let settled: Vec<[u8; 32]> = self
            .book
            .obligations
            .keys()
            .filter(|nf| node.peg().is_burned(nf) && !node.peg().release_pending(nf))
            .copied()
            .collect();
        if !settled.is_empty() {
            for nf in settled {
                self.book.obligations.remove(&nf);
                self.book.locks.remove(&nf);
            }
            self.save();
        }
        notices
    }

    /// The poll: settle what confirmed, share this wallet's state, propose when it is this node's turn, re-send
    /// what is in flight.
    pub fn tick(&mut self, node: &mut Node, custody: &CustodyLane, signer: Option<(&[u8], &[u8])>, now_ms: u64) -> Vec<WireMsg> {
        let mut out = Vec::new();
        if now_ms.saturating_sub(self.last_poll_ms) < XMR_PAYOUT_POLL_MS {
            return out;
        }
        self.last_poll_ms = now_ms;
        let Some(rpc) = custody.rpc() else { return out };
        let Some((sid, _address)) = custody.ready_address() else { return out };
        // SAFE AT SCALE: the payout set is THIS custodian's vault (the whole bonded set on a one-vault chain)
        let members = node.custody_set_here();
        if set_id(&members) != sid {
            return out;
        }
        let Some(me) = node.custodian_id() else { return out };
        // CACHE-ONLY: settlement mirrors what THIS node's own wallet saw confirm (F5); the burns were applied
        // from `Class::PegOut`, and the notices it returns only let wallet-less nodes shed relay memory.
        out.extend(self.settle(node, rpc, signer));
        // spec §3g.1: a part for this vault arriving in its own wallet; and the lock of a part whose slot closed leaves (one at
        // most per part, never a growing set — a cash-out's lock stays while its burn is owed).
        // CACHE-ONLY: this custodian's own view of its wallet and its own signing record; the ledgers move only by the
        // `Class::VaultRebalance` and `Class::ReserveCost` objects blocks carry.
        self.check_rebalance_arrival(node, rpc, &sid);
        let here = node.vault_here();
        let part_id = Self::rebalance_leg_id(node, here);
        let before = self.book.locks.len();
        let owed = &self.book.obligations;
        self.book.locks.retain(|nf, _| owed.contains_key(nf) || node.peg().release_pending(nf) || Some(*nf) == part_id);
        if self.book.locks.len() != before {
            self.save();
        }
        let part_due = part_id.is_some_and(|id| !self.book.locks.contains_key(&id)) && Self::rebalance_atomic(node, here).is_some() && node.rebalance_send_key(here).is_some();
        // ⛔ every member shares its multisig state each poll, owed a payout or not: the proposer cannot build (and no member can
        // sign) without every member's state, so one custodian that holds no obligation here held every payout back
        // (MEASURED 2026-11-08, real nodes: node 1 "still needs the other members' multisig state" 45 polls running, node 0
        // silent — it had booked no obligation, and the poll returned before its export).
        let idle = self.book.obligations.is_empty() && self.slots.is_empty() && !part_due;
        if let Err(e) = rpc.refresh() {
            eprintln!("[xmr-payout] this node's wallet did not refresh: {e}");
        }
        // share this wallet's view of the reserve's outputs with the other members. Monero draws fresh signing nonces at every
        // export, and a transaction set built on an earlier export no longer signs ("This signature was made with stale data:
        // export fresh multisig data"), so the state is exported once and re-shared as is, and exported afresh only when this
        // wallet's outputs moved (its balance or unlocked balance changed: a deposit arrived or matured, a payout spent).
        // Exporting on every poll made almost every proposal stale before its signer reached it (MEASURED 2026-11-08, real
        // nodes: 9 of 9 signatures refused as stale data; the one run that paid had signed inside one poll).
        let state = rpc.balance().ok().map(|(b, u, _)| (b, u));
        let fresh = match (&self.exported, state) {
            (Some((info, at)), Some(now)) if *at == now => Some(Ok(info.clone())),
            (Some((info, _)), None) => Some(Ok(info.clone())),
            _ => None,
        };
        let exported = fresh.unwrap_or_else(|| {
            let r = rpc.export_multisig_info();
            if let (Ok(info), Some(now)) = (&r, state) {
                self.exported = Some((info.clone(), now));
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line to this node's own log, once per change of this custody wallet's
                // outputs; no amount, address, key or member identity.
                eprintln!("[xmr-payout] exported this wallet's multisig state afresh (its outputs moved); it is shared every poll");
            }
            r
        });
        match exported {
            Ok(info) => {
                if let Some((pk, sig)) = Self::sign(signer, &sync_statement(&sid, &info)) {
                    let msg = SyncMsg { set_id: sid, from: me, info, signer_pk: pk, sig };
                    if let Ok(bytes) = postcard::to_allocvec(&msg) {
                        out.push(WireMsg::XmrPayoutSync(bytes));
                    }
                }
            }
            Err(e) => eprintln!("[xmr-payout] this node's wallet exported no multisig state: {e}"),
        }
        // an own proposal that never gathered its signatures was built on state another member has moved past: drop it
        // and release its legs, so this turn builds a fresh one from the state every member just re-shared
        let k = threshold(members.len()) as usize;
        let stale: Vec<[u8; 32]> = self
            .slots
            .iter()
            .filter(|(_, s)| {
                !s.msg.submitted
                    && s.msg.signers.len() < k
                    && s.msg.signers.first() == Some(&me)
                    && now_ms.saturating_sub(s.born_ms) >= XMR_PROPOSAL_REBUILD_POLLS * XMR_PAYOUT_POLL_MS
            })
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(slot) = self.slots.remove(&id) {
                for nf in &slot.msg.legs {
                    if self.book.locks.get(nf) == Some(&id) {
                        self.book.locks.remove(nf);
                    }
                }
                self.save();
                eprintln!("[xmr-payout] an own proposal waited {XMR_PROPOSAL_REBUILD_POLLS} polls short of its signatures — rebuilding it from the members' fresh state");
            }
        }
        if idle {
            return out;
        }
        // re-send what is in flight so a member that missed a round hears the latest state
        for slot in self.slots.values() {
            if let Some(w) = self.broadcast(&slot.msg) {
                out.push(w);
            }
        }
        if !Self::am_proposer(node) {
            return out;
        }
        // R7, coins first: a vault whose merge is due proposes no cash-out from a wallet the sweep lane is emptying
        if node.own_vault_coins_leaving() {
            return out;
        }
        // spec §3g.1: this vault's part, once the receiving vault consented to its current key — one round, before cash-outs
        let in_flight = part_id.is_some_and(|id| self.slots.values().any(|s| s.msg.legs.first() == Some(&id)));
        if part_due && !in_flight {
            if let (Some(id), Some(key), Some(part)) = (part_id, node.rebalance_send_key(here), Self::rebalance_atomic(node, here)) {
                if let Some((_, dest)) = Self::rebalance_dest(node, here, &key) {
                    out.extend(self.propose_round(node, rpc, &members, sid, me, signer, now_ms, vec![id], vec![(dest, part)], "the rebalance's Monero move"));
                    return out;
                }
            }
        }
        let legs = self.payable_legs(node);
        if legs.is_empty() {
            return out;
        }
        let dests: Vec<(String, u64)> = legs.iter().map(|(_, ob)| (ob.redeem_to.clone(), ob.release_atomic)).collect();
        let leg_ids: Vec<[u8; 32]> = legs.iter().map(|(nf, _)| *nf).collect();
        out.extend(self.propose_round(node, rpc, &members, sid, me, signer, now_ms, leg_ids, dests, "a Monero payout"));
        out
    }

    /// Build, sign, lock and offer ONE payout round paying `dests` for `leg_ids` — the cash-out's batch, or a rebalance's
    /// move (spec §3g.1). The founding custodian alone holds a plain wallet (Monero's multisig needs two members): it builds
    /// and relays the payment itself and the same observation rule settles it.
    #[allow(clippy::too_many_arguments)]
    fn propose_round(
        &mut self,
        _node: &Node,
        rpc: &WalletRpc,
        members: &[[u8; 32]],
        sid: [u8; 32],
        me: [u8; 32],
        signer: Option<(&[u8], &[u8])>,
        now_ms: u64,
        leg_ids: Vec<[u8; 32]>,
        dests: Vec<(String, u64)>,
        what: &str,
    ) -> Vec<WireMsg> {
        let mut out = Vec::new();
        match rpc.balance() {
            Ok((_bal, _unlocked, import_needed)) if import_needed => {
                eprintln!("[xmr-payout] not proposing yet: this wallet still needs the other members' multisig state");
                return out;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("[xmr-payout] not proposing: this node's wallet did not answer: {e}");
                return out;
            }
        }
        let legs_atomic: u64 = dests.iter().map(|d| d.1).sum();
        if members.len() == 1 {
            let txid = match rpc.transfer_relay(&dests) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[xmr-payout] not paying: this node's wallet could not build {what}: {e}");
                    return out;
                }
            };
            let mut msg = PayoutMsg {
                set_id: sid,
                legs: leg_ids,
                txset: String::new(),
                signers: vec![me],
                txids: vec![txid],
                submitted: true,
                settled: false,
                signer_pk: Vec::new(),
                sig: Vec::new(),
            };
            if let Some((pk, sig)) = Self::sign(signer, &msg.statement()) {
                msg.signer_pk = pk;
                msg.sig = sig;
            }
            let id = msg.id();
            for nf in &msg.legs {
                self.book.locks.insert(*nf, id);
            }
            self.save();
            eprintln!("[xmr-payout] ⭐ PAYOUT BROADCAST {:?} ({what}: {} legs, {legs_atomic} atomic, one custodian)", msg.txids, msg.legs.len());
            self.slots.insert(id, Slot { msg, born_ms: now_ms });
            return out;
        }
        let txset = match rpc.transfer_multisig(&dests) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[xmr-payout] not proposing: this node's wallet could not build {what}: {e}");
                return out;
            }
        };
        let mut msg = PayoutMsg {
            set_id: sid,
            legs: leg_ids,
            txset,
            signers: vec![me],
            txids: Vec::new(),
            submitted: false,
            settled: false,
            signer_pk: Vec::new(),
            sig: Vec::new(),
        };
        let Some((pk, sig)) = Self::sign(signer, &msg.statement()) else { return out };
        msg.signer_pk = pk;
        msg.sig = sig;
        let id = msg.id();
        for nf in &msg.legs {
            self.book.locks.insert(*nf, id);
        }
        self.save();
        eprintln!("[xmr-payout] PROPOSING {what}: {} legs, {legs_atomic} atomic", msg.legs.len());
        if let Some(w) = self.broadcast(&msg) {
            out.push(w);
        }
        self.slots.insert(id, Slot { msg, born_ms: now_ms });
        out
    }

    /// A member's exported multisig state arrived; import it into this node's wallet when it is new.
    pub fn on_sync(&mut self, bytes: &[u8], node: &Node, custody: &CustodyLane) -> bool {
        let Some(m) = crate::chain_object::decode_exact::<SyncMsg>(bytes) else { return false };
        if m.info.is_empty() || !signed_by_member(node, &m.from, &m.signer_pk, &m.sig, &sync_statement(&m.set_id, &m.info)) {
            return false;
        }
        // SAFE AT SCALE: a member speaks for ITS OWN vault's wallet (the whole bonded set's on a one-vault chain); every
        // node relays each distinct state once, and only a custodian of THAT vault imports it into its wallet
        let Some(members) = node.custody_vault_of(&m.from) else { return false };
        if m.set_id != set_id(&members) {
            return false;
        }
        let digest = *blake3::hash(m.info.as_bytes()).as_bytes();
        let heard = self.imported.get(&m.from).is_some_and(|d| *d == digest);
        let mine = node.custodian_id().is_some_and(|me| me == m.from);
        if heard || mine {
            return false; // heard already, or this node's own state back through the relay
        }
        // each distinct state is relayed once by every node (one digest per member, overwritten by the next);
        // a custodian imports it into its own wallet first, and a refused import is heard again on the re-send
        self.imported.insert(m.from, digest);
        let in_my_vault = node.custodian_id().is_some_and(|me| members.contains(&me));
        if let Some(rpc) = custody.rpc().filter(|_| in_my_vault) {
            match rpc.import_multisig_info(&[m.info.clone()]) {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a count of outputs this node's own wallet completed, once per distinct member state.
                Ok(n) => eprintln!("[xmr-payout] imported a member's multisig state: {n} output(s) completed"),
                Err(e) => {
                    eprintln!("[xmr-payout] this node's wallet refused a member's multisig state: {e}");
                    self.imported.remove(&m.from);
                }
            }
        }
        true
    }

    /// A payout round arrived. Judge it on this node's own book and wallet; sign when it is this node's turn;
    /// relay it when it is new. Returns (fresh, messages to send).
    pub fn on_payout(&mut self, bytes: &[u8], node: &mut Node, custody: &CustodyLane, signer: Option<(&[u8], &[u8])>) -> (bool, Vec<WireMsg>) {
        let mut out = Vec::new();
        let Some(m) = crate::chain_object::decode_exact::<PayoutMsg>(bytes) else { return (false, out) };
        // SAFE AT SCALE: this custodian judges and signs the rounds of ITS OWN vault (the whole bonded set on a one-vault
        // chain). A round signed by a custodian of another vault is that vault's business: this node relays it exactly as
        // a node without a wallet does, so every vault's rounds cross the mesh whoever carries them.
        let members = node.custody_set_here();
        let sid = set_id(&members);
        let id = m.id();
        let other_vault = node.custody_vault_of(&crate::pqauth::pubkey_id(&m.signer_pk)).is_some_and(|v| v != members);
        // a node without a custody wallet cannot judge the set: it relays each well-signed round once (a round
        // with more signatures, or the broadcast, is a new round of the same payout) and holds one slot per
        // payout in flight — shed the moment a custodian's settled notice resolves it (relayed once itself)
        let Some(rpc) = custody.rpc().filter(|_| !other_vault) else {
            let from = crate::pqauth::pubkey_id(&m.signer_pk);
            if !signed_by_member(node, &from, &m.signer_pk, &m.sig, &m.statement()) {
                return (false, out);
            }
            if m.settled {
                let resolved = self.slots.remove(&id).is_some();
                return (resolved, out);
            }
            if m.signers.last() != Some(&from) {
                return (false, out);
            }
            let newer = match self.slots.get(&id) {
                Some(s) => (m.signers.len(), m.submitted) > (s.msg.signers.len(), s.msg.submitted),
                None => true,
            };
            if newer {
                self.slots.insert(id, Slot { msg: m, born_ms: unix_now_ms() });
            }
            return (newer, out);
        };
        if m.settled {
            return (false, out); // a custodian settles on its own wallet's observation only (F5)
        }
        let Some(_want) = self.verify(&m, node, rpc, &members, &sid) else { return (false, out) };
        let newer = match self.slots.get(&id) {
            Some(s) => (m.signers.len(), m.submitted) > (s.msg.signers.len(), s.msg.submitted),
            None => true,
        };
        if !newer {
            return (false, out);
        }
        for nf in &m.legs {
            self.book.locks.insert(*nf, id);
        }
        self.save();
        let me = node.custodian_id();
        let k = threshold(members.len()) as usize;
        let mut msg = m.clone();
        if !msg.submitted && msg.signers.len() < k {
            if let (Some(me), Some(next)) = (me, Self::next_signer(&members, &msg.signers)) {
                if next == me {
                    match rpc.sign_multisig(&msg.txset) {
                        Ok((set, hashes)) => {
                            msg.txset = set;
                            msg.signers.push(me);
                            msg.txids = hashes;
                            eprintln!("[xmr-payout] SIGNED payout {}… ({} of {} signatures)", h32(&id), msg.signers.len(), k);
                            if msg.signers.len() >= k {
                                match rpc.submit_multisig(&msg.txset) {
                                    Ok(hashes) => {
                                        msg.txids = hashes;
                                        msg.submitted = true;
                                        eprintln!("[xmr-payout] ⭐ PAYOUT BROADCAST {:?} ({} legs)", msg.txids, msg.legs.len());
                                    }
                                    Err(e) => eprintln!("[xmr-payout] the signed payout did not relay from this node: {e} — the set is complete and will be offered again"),
                                }
                            }
                            if let Some((pk, sig)) = Self::sign(signer, &msg.statement()) {
                                msg.signer_pk = pk;
                                msg.sig = sig;
                            }
                            if let Some(w) = self.broadcast(&msg) {
                                out.push(w);
                            }
                        }
                        Err(e) => {
                            // no signature exists: release the legs this round locked, so the proposer's rebuilt set can be
                            // signed (F4 locks a leg to the one set this node SIGNED; it signed none)
                            eprintln!("[xmr-payout] this node's wallet did not sign the payout: {e}");
                            for nf in &m.legs {
                                if self.book.locks.get(nf) == Some(&id) {
                                    self.book.locks.remove(nf);
                                }
                            }
                            self.save();
                            return (false, out);
                        }
                    }
                }
            }
        }
        self.slots.insert(id, Slot { msg, born_ms: unix_now_ms() });
        (true, out)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn the_signing_order_is_the_members_rotated_to_the_proposer() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let members = [a, b, c];
        assert_eq!(XmrPayoutLane::next_signer(&members, &[b]), Some(c));
        assert_eq!(XmrPayoutLane::next_signer(&members, &[b, c]), Some(a));
        assert_eq!(XmrPayoutLane::next_signer(&members, &[c]), Some(a));
        assert_eq!(XmrPayoutLane::next_signer(&members, &[a, b, c]), None);
        assert_eq!(XmrPayoutLane::next_signer(&members, &[]), None);
    }

    #[test]
    fn a_payout_message_round_trips_and_its_id_is_stable_across_signing_rounds() {
        let mut m = PayoutMsg {
            set_id: [7u8; 32],
            legs: vec![[1u8; 32], [2u8; 32]],
            txset: "abcd".into(),
            signers: vec![[9u8; 32]],
            txids: vec![],
            submitted: false,
            settled: false,
            signer_pk: vec![1, 2, 3],
            sig: vec![4, 5, 6],
        };
        let id0 = m.id();
        let bytes = postcard::to_allocvec(&m).expect("encodes");
        let back: PayoutMsg = postcard::from_bytes(&bytes).expect("decodes");
        assert_eq!(back, m);
        m.signers.push([8u8; 32]);
        m.txset = "abcdef".into();
        m.submitted = true;
        assert_eq!(m.id(), id0, "another signature does not make it another payout");
        let mut other = m.clone();
        other.legs.push([3u8; 32]);
        assert_ne!(other.id(), id0);
    }
}

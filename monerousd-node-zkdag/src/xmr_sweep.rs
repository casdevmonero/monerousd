// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ SAFE AT SCALE, stage three (spec §3f R3; finding A-F20) — THE MONERO SWEEP: a replaced custody key stops holding
//! Monero. (EXTERNAL-CHAIN code, the Monero twin of `btc_payout`'s consolidation.)
//!
//! FOUND (A-F20, read from `xmr_custody`): Monero custody is one multisig wallet per member set. When a vault's
//! members change, the lane forms a NEW wallet for the new set and nothing ever moved the old wallet's coins — the
//! old set went on holding them (a custodian that left still co-held reserve coins after its bond was released, and
//! the new set could not pay a cash-out from them).
//!
//! AND FOUND 2026-11-11 reading `xmr_watch`: the deposit watcher reads only the wallet the wallet-rpc has OPEN. A
//! deposit paid to a key the chain had just replaced — a valid deposit address inside its window (spec §3f R2) —
//! arrived in that key's wallet, was never read, and was never minted. So this lane's visit to a wallet the lanes do
//! not keep open also READS it (`xmr_watch::sweep_now`, which writes only the open wallet's own addresses).
//!
//! THE RULE. The chain records each vault's keys (`PegLedger::vault_keys`): the member set and the Monero main
//! address of its wallet. Every alive key that names this node, records an address, and whose wallet is not the one
//! the custody lanes keep open is VISITED (every poll while something is in flight, once a minute otherwise): its
//! deposits are read. For a REPLACED key the old set's members also sweep whatever the old wallet can spend to the
//! vault's CURRENT key's recorded address — at once, and again whenever more matures there (Monero's fee is small and
//! flat: there is no low-fee wait, and a late deposit inside the window is simply swept after it is minted):
//!   • each member's own wallet-rpc opens the old set's wallet for one VISIT a poll, and reopens the current set's
//!     wallet before the visit ends — the custody and payout lanes never see another wallet open;
//!   • the members share the old wallet's multisig state (`SweepMsg::Sync`), one builds the sweep (`transfer`, the
//!     fee taken from the amount — the wallet falls by exactly what it held), each next signer reads the set on ITS
//!     OWN wallet (`describe_transfer`) and signs only if it pays ONE recipient, the address ITS OWN chain records
//!     for the vault's current key, at a fee inside F7; whoever completes the quorum relays it;
//!   • a member whose own old wallet shows the sweep confirmed says so (`SweepMsg::Done`: the transaction and its
//!     fee). Two thirds of the old set saying so is what lets a custodian that never held the old wallet book the
//!     fee: it also reads the transaction arriving in the CURRENT wallet, on its own wallet-rpc, at that fee
//!     (`judge_cost`), and signs the `Class::ReserveCost` header its own opening derives (`Node::own_reserve_cost_sig`).
//! A key holder the chain no longer seats takes part in exactly this and nothing else, as on Bitcoin.
//!
//! §9.6 (a custody proposal lane, the sweep's rounds): (1) no PoW — not a chain object; nothing here moves chain
//! state; (2) every message is signed by a member of the old set THE RECEIVER'S OWN CHAIN records, and every signer
//! reads the set on its own wallet; (3) value — none leaves custody but the miner fee: the one recipient is derived
//! from the chain's record, never read from a message, and the fee is bounded by F7 on each signer's own daemon;
//! (4) a replayed round spends outputs that are gone — Monero refuses it; (5) work — one visit a poll, one round in
//! flight per old set, messages bounded at their decode; (6) parity with `xmr_payout::verify`: the same wallet
//! reading and the same fee ceiling, and where a payout's recipients are its burns' sealed destinations this one's is
//! the chain's; (7) SCALE — one old set's members (sixteen at most), a visit a poll, nothing per bonded node;
//! (8) AI RESISTANT — (b) code and economics bounded by the old key's own quorum: a lying proposer can move coins
//! only to the vault's own current address, and a persuasive message gains nothing — no address, amount or fee is
//! taken from the wire.
//! cons: two wallet opens a poll per member while a sweep is in flight, and a minute apart while a key that names it
//! is alive with nothing in flight; a late deposit to a replaced key costs one more sweep fee; Monero's ten-block
//! lock stands between a sweep and its booking.
//!
//! BORROWED: THORChain — an Asgard vault's funds migrate to the new vault at churn, signed by the retiring vault's
//! own members; this tree's `xmr_payout` (the sequential k-of-n signing order, the F7 fee ceiling, the wallet's own
//! reading of a set before any signature).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::node::Node;
use crate::peg::VaultKeyRow;
use crate::protocol::WireMsg;
use crate::xmr_custody::{set_id, threshold, wallet_name};
use crate::xmr_rpc::WalletRpc;

/// The lane's poll — the custody lanes' own cadence.
pub const XMR_SWEEP_POLL_MS: u64 = crate::btc_payout::PAYOUT_POLL_MS;
/// How often a wallet with nothing in flight is visited: a Monero deposit takes ten blocks (about twenty minutes) to
/// mature, so reading an old key's wallet once a minute loses nothing and spares the wallet-rpc two opens a poll.
pub const XMR_SWEEP_IDLE_MS: u64 = 60_000;
/// Confirmations after which this lane calls a sweep settled: Monero's own spend lock.
pub const XMR_SWEEP_CONFIRMATIONS: u64 = 10;
/// A round that gathered no further signature in this many polls was built on multisig state a member has moved
/// past: it is dropped and the next proposer builds a fresh one (`xmr_payout`'s own rule).
pub const XMR_SWEEP_REBUILD_POLLS: u64 = 12;
/// The widest text one message carries (a multisig state or a transaction set, hex): a sweep of a wallet's every
/// output is the largest set a custody wallet builds.
pub const XMR_SWEEP_TEXT_MAX: usize = 1 << 20;
/// The relay-once ring's bound.
const RELAY_RING_MAX: usize = 256;

/// One message of the sweep lane (`WireMsg::XmrSweep`), each signed by a member of the old set it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SweepMsg {
    /// A member's exported multisig state of the old set's wallet.
    Sync { set_id: [u8; 32], from: [u8; 32], info: String, signer_pk: Vec<u8>, sig: Vec<u8> },
    /// The sweep in progress: the set as signed so far, the signers in order (the proposer first), the transaction
    /// hashes once the quorum is complete, whether it was relayed. Signed by the LAST signer.
    Round { set_id: [u8; 32], txset: String, signers: Vec<[u8; 32]>, txids: Vec<String>, submitted: bool, signer_pk: Vec<u8>, sig: Vec<u8> },
    /// A member's statement that ITS OWN wallet of the old set shows the sweep `txid` confirmed, at fee `fee`.
    Done { set_id: [u8; 32], txid: String, fee: u64, from: [u8; 32], signer_pk: Vec<u8>, sig: Vec<u8> },
}

impl SweepMsg {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Bounded decode: strict full consumption, every text inside `XMR_SWEEP_TEXT_MAX`, at most sixteen signers and
    /// four hashes, the ML-DSA ceilings.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let m: Self = crate::chain_object::decode_exact(bytes)?;
        let keys_ok = |pk: &[u8], sig: &[u8]| !pk.is_empty() && !sig.is_empty() && pk.len() <= crate::peg_attest::PEG_ATTEST_PUBKEY_MAX && sig.len() <= crate::peg_attest::PEG_ATTEST_SIG_MAX;
        let ok = match &m {
            SweepMsg::Sync { info, signer_pk, sig, .. } => !info.is_empty() && info.len() <= XMR_SWEEP_TEXT_MAX && keys_ok(signer_pk, sig),
            SweepMsg::Round { txset, signers, txids, signer_pk, sig, .. } => {
                txset.len() <= XMR_SWEEP_TEXT_MAX
                    && !signers.is_empty()
                    && signers.len() <= crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS
                    && txids.len() <= 4
                    && txids.iter().all(|t| t.len() == 64)
                    && keys_ok(signer_pk, sig)
            }
            SweepMsg::Done { txid, fee, signer_pk, sig, .. } => txid.len() == 64 && *fee > 0 && keys_ok(signer_pk, sig),
        };
        ok.then_some(m)
    }

    fn set(&self) -> [u8; 32] {
        match self {
            SweepMsg::Sync { set_id, .. } | SweepMsg::Round { set_id, .. } | SweepMsg::Done { set_id, .. } => *set_id,
        }
    }

    /// What the message's signer signed: a domain-separated digest of everything but the signature.
    fn statement(&self) -> Vec<u8> {
        let mut h = blake3::Hasher::new_derive_key("USDMD-XMR-SWEEP-v1");
        match self {
            SweepMsg::Sync { set_id, from, info, .. } => {
                h.update(b"sync");
                h.update(set_id);
                h.update(from);
                h.update(info.as_bytes());
            }
            SweepMsg::Round { set_id, txset, signers, txids, submitted, .. } => {
                h.update(b"round");
                h.update(set_id);
                h.update(&(txset.len() as u64).to_le_bytes());
                h.update(txset.as_bytes());
                h.update(&(signers.len() as u64).to_le_bytes());
                for s in signers {
                    h.update(s);
                }
                h.update(&(txids.len() as u64).to_le_bytes());
                for t in txids {
                    h.update(t.as_bytes());
                }
                h.update(&[u8::from(*submitted)]);
            }
            SweepMsg::Done { set_id, txid, fee, from, .. } => {
                h.update(b"done");
                h.update(set_id);
                h.update(txid.as_bytes());
                h.update(&fee.to_le_bytes());
                h.update(from);
            }
        }
        h.finalize().as_bytes().to_vec()
    }

    /// Is the message signed by the member it says signed it (the named sender, or a round's last signer)? That
    /// member's id when it is.
    fn signed_by(&self) -> Option<[u8; 32]> {
        let (from, pk, sig) = match self {
            SweepMsg::Sync { from, signer_pk, sig, .. } | SweepMsg::Done { from, signer_pk, sig, .. } => (*from, signer_pk, sig),
            SweepMsg::Round { signers, signer_pk, sig, .. } => (*signers.last()?, signer_pk, sig),
        };
        (crate::pqauth::pubkey_id(pk) == from && crate::pqauth::ml_dsa_verify(&self.statement(), pk, sig)).then_some(from)
    }

    /// Sign the message as `signer` (its `(public key, secret key)`), filling the two signature fields.
    pub(crate) fn sign(mut self, signer: Option<(&[u8], &[u8])>) -> Option<Self> {
        let (pk, sk) = signer?;
        let made = crate::pqauth::ml_dsa_sign(&self.statement(), sk)?;
        match &mut self {
            SweepMsg::Sync { signer_pk, sig, .. } | SweepMsg::Round { signer_pk, sig, .. } | SweepMsg::Done { signer_pk, sig, .. } => {
                *signer_pk = pk.to_vec();
                *sig = made;
            }
        }
        Some(self)
    }
}

/// The evidence a Monero sweep's cost signature carries (`ReserveCostSig::evidence`): the old set, the sweep's
/// transaction and its fee. Small on purpose — what makes it true is in each judge's own lane (the old set's own
/// statements) and its own wallet (`SweepLane::judge_cost`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmrCostEvidence {
    pub set_id: [u8; 32],
    pub txid: String,
    pub fee: u64,
}

/// The tag that tells a Monero sweep's evidence from a Bitcoin consolidation's.
const XMR_EVIDENCE_TAG: &[u8; 4] = b"XMRS";

impl XmrCostEvidence {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = XMR_EVIDENCE_TAG.to_vec();
        out.extend_from_slice(&postcard::to_allocvec(self).unwrap_or_default());
        out
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let e: Self = crate::chain_object::decode_exact(bytes.strip_prefix(XMR_EVIDENCE_TAG)?)?;
        (e.txid.len() == 64 && e.fee > 0).then_some(e)
    }
}

/// A Monero transaction hash (64 hex characters) as the 32 bytes a `ReserveCostHeader` names.
fn txid_bytes(txid: &str) -> Option<[u8; 32]> {
    crate::btc_tx::unhex(txid.trim())?.try_into().ok()
}

/// The sweep in flight for one old set, as this node last saw it.
#[derive(Clone, Debug)]
struct Round {
    txset: String,
    signers: Vec<[u8; 32]>,
    txids: Vec<String>,
    submitted: bool,
    signer_pk: Vec<u8>,
    sig: Vec<u8>,
    /// when this node first held the round at this many signatures (the rebuild clock)
    seen_ms: u64,
    /// the fee THIS node's own wallet read off the set (a member that built or signed it); `None` otherwise
    fee: Option<u64>,
}

impl Round {
    fn msg(&self, sid: &[u8; 32]) -> SweepMsg {
        SweepMsg::Round { set_id: *sid, txset: self.txset.clone(), signers: self.signers.clone(), txids: self.txids.clone(), submitted: self.submitted, signer_pk: self.signer_pk.clone(), sig: self.sig.clone() }
    }
}

/// The lane: per old set, the members' shared multisig states, the round in flight and the members' settled
/// statements. PROCESS-LOCAL by design: every piece is re-sent by its author every poll until the chain retires the
/// key, and the old wallet itself is the state that matters.
/// O1-INFINITY-REVIEWED: keyed by the alive replaced keys that record a Monero address (at most
/// `VAULT_KEYS_ALIVE_MAX − 1` per vault) × their members (sixteen at most); every map is pruned to the sets the
/// chain still records, every poll.
pub struct SweepLane {
    last_poll_ms: u64,
    infos: BTreeMap<[u8; 32], BTreeMap<[u8; 32], String>>,
    imported: BTreeMap<([u8; 32], [u8; 32]), [u8; 32]>,
    rounds: BTreeMap<[u8; 32], Round>,
    done: BTreeMap<([u8; 32], String, u64), BTreeSet<[u8; 32]>>,
    /// the sweeps THIS node's own old wallet showed confirmed: `(transaction, fee)` per old set, re-stated every visit
    settled: BTreeMap<[u8; 32], Vec<(String, u64)>>,
    /// the old wallets this machine does not hold (an open created a fresh file): never visited again
    absent: BTreeSet<[u8; 32]>,
    /// when each key's wallet is visited next: every poll while something is in flight, once a minute otherwise
    next_visit_ms: BTreeMap<[u8; 32], u64>,
    relayed: VecDeque<[u8; 32]>,
}

impl Default for SweepLane {
    fn default() -> Self {
        Self::new()
    }
}

/// A key whose Monero wallet is being EMPTIED, by its member set `sid`, as this node's chain holds it — with its vault:
///   • an alive REPLACED key that records a Monero address (R3: its coins go to its vault's current key);
///   • the CURRENT key of a vault whose merge this chain says is due (`Node::vault_merge_due`; R7, R8: coins first —
///     they move to the RECEIVING vault's current key before the ledgers do, and that vault signs its acceptance only
///     when its own wallet shows them).
/// Every check of "is this a member of a set being swept" reads this, never a message.
fn old_set<'a>(node: &'a Node, sid: &[u8; 32]) -> Option<(u32, &'a VaultKeyRow)> {
    let retiring = node.vault_merge_due().map(|(from, _)| from);
    node.peg()
        .vault_keys_all()
        .find(|(v, k)| !k.xmr_address.is_empty() && set_id(&k.members) == *sid && (k.replaced_tick.is_some() || retiring == Some(*v)))
}

/// ⭐ WHERE THE MONERO OF KEY `row` OF VAULT `vault` GOES (spec §3f R3, R7): a replaced key pays its own vault's
/// current key — also while that vault's merge is due (two hops for a retiring vault's replaced keys, so every
/// custodian of the vault judges each fee from a wallet it holds); the CURRENT key of a vault whose merge is due pays
/// the receiving vault's current key. `None`: nothing to move (a current key with no merge due, a target with no
/// recorded address, or the key's own address).
/// CACHE-ONLY: read from the chain's key record, seats and ledgers; it decides only what THIS custodian signs.
fn sweep_target(node: &Node, vault: u32, row: &VaultKeyRow) -> Option<String> {
    let to = match (row.replaced_tick, node.vault_merge_due()) {
        (Some(_), _) => vault,
        (None, Some((from, into))) if from == vault => into,
        _ => return None,
    };
    target_address(node, to).filter(|t| t.as_bytes() != row.xmr_address.as_slice())
}

/// The Monero main address the chain records for vault `vault`'s CURRENT key — where a sweep pays. `None` when the
/// vault has no current key or it records no Monero address.
fn target_address(node: &Node, vault: u32) -> Option<String> {
    let k = node.peg().vault_key_current(vault)?;
    std::str::from_utf8(&k.xmr_address).ok().filter(|a| !a.is_empty()).map(str::to_string)
}

impl SweepLane {
    #[must_use]
    pub fn new() -> Self {
        SweepLane {
            last_poll_ms: 0,
            infos: BTreeMap::new(),
            imported: BTreeMap::new(),
            rounds: BTreeMap::new(),
            done: BTreeMap::new(),
            settled: BTreeMap::new(),
            absent: BTreeSet::new(),
            next_visit_ms: BTreeMap::new(),
            relayed: VecDeque::new(),
        }
    }

    /// Is the lane's next poll due at `now_ms`? Asked by the runtime before it reaches for a wallet-rpc; a `true`
    /// starts the next period whether or not a visit follows (a node with no wallet is asked once a period, not once
    /// a loop).
    pub fn poll_due(&mut self, now_ms: u64) -> bool {
        if now_ms.saturating_sub(self.last_poll_ms) < XMR_SWEEP_POLL_MS {
            return false;
        }
        self.last_poll_ms = now_ms;
        true
    }

    /// Drop everything about a set the chain no longer records as a replaced key with a Monero address.
    fn prune(&mut self, node: &Node) {
        let alive = |sid: &[u8; 32]| old_set(node, sid).is_some();
        self.infos.retain(|sid, _| alive(sid));
        self.imported.retain(|(sid, _), _| alive(sid));
        self.rounds.retain(|sid, _| alive(sid));
        self.done.retain(|(sid, _, _), _| alive(sid));
        self.settled.retain(|sid, _| alive(sid));
        // the two maps below also hold a CURRENT key the lanes have moved on from: kept while any alive key has that set
        let recorded = |sid: &[u8; 32]| node.peg().vault_keys_all().any(|(_, k)| set_id(&k.members) == *sid);
        self.absent.retain(|sid| recorded(sid));
        self.next_visit_ms.retain(|sid, _| recorded(sid));
    }

    /// Has this node's own old wallet shown every transaction of `r` confirmed?
    fn is_settled(&self, sid: &[u8; 32], r: &Round) -> bool {
        !r.txids.is_empty() && self.settled.get(sid).is_some_and(|s| r.txids.iter().all(|t| s.iter().any(|(x, _)| x == t)))
    }

    /// ⭐ A MESSAGE OF THE SWEEP LANE ARRIVED. Verified against THIS node's chain: the set it names is an alive
    /// replaced key with a Monero address, and its signer is a member of that key (a custodian that left signs with
    /// the same identity key it bonded with, so a member the chain no longer seats is still a member of its old
    /// key). `true` when it is new — relay it once.
    pub fn on_msg(&mut self, bytes: &[u8], node: &Node, now_ms: u64) -> bool {
        let Some(m) = SweepMsg::decode(bytes) else { return false };
        let sid = m.set();
        let Some((_, row)) = old_set(node, &sid) else { return false };
        let Some(from) = m.signed_by() else { return false };
        if row.members.binary_search(&from).is_err() {
            return false;
        }
        let h = *blake3::hash(bytes).as_bytes();
        if self.relayed.contains(&h) {
            return false;
        }
        self.relayed.push_back(h);
        while self.relayed.len() > RELAY_RING_MAX {
            self.relayed.pop_front();
        }
        match m {
            SweepMsg::Sync { from, info, .. } => {
                self.infos.entry(sid).or_default().insert(from, info);
            }
            SweepMsg::Round { txset, signers, txids, submitted, signer_pk, sig, .. } => {
                let mut seen = BTreeSet::new();
                if signers.iter().any(|s| row.members.binary_search(s).is_err() || !seen.insert(*s)) {
                    return false;
                }
                // kept when it is further along than the round held, or the round held is one this node's own wallet
                // already saw confirmed (a later sweep of the same wallet: coins that arrived after the first)
                let newer = match self.rounds.get(&sid) {
                    Some(r) => (signers.len(), submitted) > (r.signers.len(), r.submitted) || (self.is_settled(&sid, r) && r.txids != txids),
                    None => true,
                };
                if newer {
                    self.rounds.insert(sid, Round { txset, signers, txids, submitted, signer_pk, sig, seen_ms: now_ms, fee: None });
                }
            }
            SweepMsg::Done { txid, fee, from, .. } => {
                self.done.entry((sid, txid, fee)).or_default().insert(from);
            }
        }
        true
    }

    /// The member who signs a round next: the old set's members rotated to start at the proposer, the first that has
    /// not signed (`xmr_payout`'s own order, so k signers never fork the set in two directions).
    fn next_signer(members: &[[u8; 32]], signers: &[[u8; 32]]) -> Option<[u8; 32]> {
        let start = members.iter().position(|m| Some(m) == signers.first())?;
        (0..members.len()).map(|i| members[(start + i) % members.len()]).find(|m| !signers.contains(m))
    }

    /// ⭐ THE LANE'S POLL for this node (its own identity, seated or not): for the OLDEST replaced key that names it,
    /// records a Monero address and is due, one visit to that set's wallet — then the current set's wallet
    /// (`current_wallet`) is open again. Returns the messages to gossip. Called once a period (`poll_due`).
    /// CACHE-ONLY: a custodian's own wallet work on a foreign chain; nothing here decides chain state.
    pub fn tick(&mut self, node: &Node, rpc: &WalletRpc, password: &str, current_wallet: Option<&str>, signer: Option<(&[u8], &[u8])>, now_ms: u64) -> Vec<WireMsg> {
        let mut out = Vec::new();
        self.prune(node);
        let Some((pk, _)) = signer else { return out };
        let me = crate::pqauth::pubkey_id(pk);
        // every alive key that names this node and records an address, with the address its coins go to
        // (`sweep_target`): a replaced key; a current key the live seats have already moved on from (its wallet still
        // takes deposits until the new key is recorded — it is read, never swept); and the wallet the lanes keep OPEN
        // only when a due merge empties it (R7: coins first)
        let mut rows: Vec<(VaultKeyRow, Option<String>)> = node
            .peg()
            .vault_keys_all()
            .filter(|(_, k)| !k.xmr_address.is_empty() && k.members.binary_search(&me).is_ok() && !self.absent.contains(&set_id(&k.members)))
            .map(|(v, k)| (k.clone(), sweep_target(node, v, k)))
            .filter(|(k, target)| current_wallet != Some(wallet_name(&set_id(&k.members)).as_str()) || (k.replaced_tick.is_none() && target.is_some()))
            .collect();
        rows.sort_by_key(|(k, _)| k.since_tick);
        // one wallet a poll: the oldest whose next visit has come (a wallet with nothing in flight is read once a
        // minute — a Monero deposit takes longer than that to mature — and every poll while a sweep is in flight)
        let Some((row, target)) = rows.into_iter().find(|(k, _)| self.next_visit_ms.get(&set_id(&k.members)).is_none_or(|t| now_ms >= *t)) else { return out };
        let sid = set_id(&row.members);
        let busy = self.visit(node, rpc, password, &row, &sid, target.as_deref(), me, signer, now_ms, &mut out);
        self.next_visit_ms.insert(sid, now_ms.saturating_add(if busy { XMR_SWEEP_POLL_MS } else { XMR_SWEEP_IDLE_MS }));
        // the custody and payout lanes find the wallet they left: the current set's, open
        match current_wallet {
            Some(name) => {
                if let Err(e) = rpc.open_or_create(name, password) {
                    eprintln!("[xmr-sweep] ⛔ the current set's wallet did not reopen after the visit: {e}");
                }
            }
            None => {
                let _ = rpc.close();
            }
        }
        out
    }

    /// One visit to the wallet of a key the lanes do not keep open: read the deposits paid to its addresses (the
    /// watcher's own sweep, on this wallet), and — for a REPLACED key with somewhere to go (`target`) — share and
    /// take in the members' multisig state, settle a relayed sweep, sign a round whose turn is this node's, or on
    /// this node's proposer turn build the sweep. `true` while something is in flight (visit again next poll).
    #[allow(clippy::too_many_arguments)]
    fn visit(&mut self, node: &Node, rpc: &WalletRpc, password: &str, row: &VaultKeyRow, sid: &[u8; 32], target: Option<&str>, me: [u8; 32], signer: Option<(&[u8], &[u8])>, now_ms: u64, out: &mut Vec<WireMsg>) -> bool {
        match rpc.open_or_create(&wallet_name(sid), password) {
            Ok(false) => {}
            Ok(true) => {
                // this machine never held that set's wallet: nothing to read or sweep from here
                eprintln!("[xmr-sweep] ⛔ this machine holds no wallet for a custody key that names this custodian — it takes no part in reading or sweeping it");
                self.absent.insert(*sid);
                return false;
            }
            Err(e) => {
                eprintln!("[xmr-sweep] the key's wallet did not open: {e}");
                return false;
            }
        }
        let n = row.members.len();
        let multisig = n > 1;
        if multisig && !matches!(rpc.is_multisig(), Ok((true, true, _, _))) {
            return false; // the set never finished its exchange on this wallet: it holds nothing
        }
        if let Err(e) = rpc.refresh() {
            eprintln!("[xmr-sweep] the key's wallet did not refresh: {e}");
        }
        // R2: a deposit paid to this key's address is read from THIS wallet — the one place it can be seen
        // CACHE-ONLY: this custodian's own reading of its own wallet; a mint is decided by the object a block carries.
        if let Err(e) = crate::xmr_watch::sweep_now(rpc) {
            eprintln!("[xmr-sweep] the key's wallet did not answer the deposit read: {e}");
        }
        let Some(target) = target else { return false }; // not replaced, or nowhere to go yet: read, never swept
        let Ok((balance, unlocked, import_needed)) = rpc.balance() else { return false };
        let mut push = |m: SweepMsg| out.push(WireMsg::XmrSweep(m.encode()));
        // every sweep this node's own old wallet has shown confirmed is stated again, so a custodian that missed the
        // statement can still judge the fee
        for (txid, fee) in self.settled.get(sid).cloned().unwrap_or_default() {
            if let Some(m) = (SweepMsg::Done { set_id: *sid, txid, fee, from: me, signer_pk: Vec::new(), sig: Vec::new() }).sign(signer) {
                push(m);
            }
        }
        if multisig {
            // share this wallet's view of the old set's outputs, and take in the others'
            if let Ok(info) = rpc.export_multisig_info() {
                if let Some(m) = (SweepMsg::Sync { set_id: *sid, from: me, info, signer_pk: Vec::new(), sig: Vec::new() }).sign(signer) {
                    push(m);
                }
            }
            let fresh: Vec<([u8; 32], String)> = self
                .infos
                .get(sid)
                .into_iter()
                .flatten()
                .filter(|(from, info)| **from != me && self.imported.get(&(*sid, **from)) != Some(blake3::hash(info.as_bytes()).as_bytes()))
                .map(|(from, info)| (*from, info.clone()))
                .collect();
            for (from, info) in fresh {
                if rpc.import_multisig_info(&[info.clone()]).is_ok() {
                    self.imported.insert((*sid, from), *blake3::hash(info.as_bytes()).as_bytes());
                }
            }
        }
        let k = if multisig { threshold(n) as usize } else { 1 };
        // a round that stopped gathering signatures was built on state a member moved past: the next proposer rebuilds
        if self.rounds.get(sid).is_some_and(|r| !r.submitted && now_ms.saturating_sub(r.seen_ms) >= XMR_SWEEP_REBUILD_POLLS * XMR_SWEEP_POLL_MS) {
            self.rounds.remove(sid);
        }
        if let Some(mut r) = self.rounds.get(sid).cloned() {
            if r.submitted && !self.is_settled(sid, &r) {
                // settle on THIS wallet's own observation, then say so (the statement a non-member's cost judgement reads)
                let confirmed = !r.txids.is_empty() && r.txids.iter().all(|t| matches!(rpc.tx_confirmations(t), Ok(Some(c)) if c >= XMR_SWEEP_CONFIRMATIONS));
                if !confirmed {
                    push(r.msg(sid)); // re-offer the relayed round so a member that missed it settles too
                    return true;
                }
                let fee = r.fee.or_else(|| rpc.describe_multisig(&r.txset).ok().map(|(_, f)| f)).or_else(|| rpc.transfer_fee(&r.txids[0]).ok().flatten().map(|t| t.1));
                let Some(fee) = fee.filter(|f| *f > 0) else { return true };
                self.settled.entry(*sid).or_default().push((r.txids[0].clone(), fee));
                self.done.entry((*sid, r.txids[0].clone(), fee)).or_default().insert(me);
                if let Some(m) = (SweepMsg::Done { set_id: *sid, txid: r.txids[0].clone(), fee, from: me, signer_pk: Vec::new(), sig: Vec::new() }).sign(signer) {
                    push(m);
                }
                // DIGITAL-CASH-PRIVACY-REVIEWED: custody's own sweep between its own wallets, public on Monero; no user's value.
                eprintln!("[xmr-sweep] ⭐ SETTLED — this node's own old wallet shows the sweep {} confirmed", r.txids[0]);
            } else if !r.submitted {
                if r.signers.len() < k && Self::next_signer(&row.members, &r.signers) == Some(me) {
                    // THIS NODE'S TURN: read the set on its own wallet — one recipient, the chain's address, a fee inside F7
                    let read = rpc.describe_multisig(&r.txset);
                    let ok = match &read {
                        Ok((recipients, fee)) => recipients.len() == 1 && recipients[0].address == target && recipients[0].amount > 0 && crate::xmr_payout::XmrPayoutLane::fee_ok(*fee, &r.txset),
                        Err(_) => false,
                    };
                    if !ok {
                        eprintln!("[xmr-sweep] ⛔ not signing: the set does not pay exactly the address this node's chain records for the vault's current key, at a fee inside the ceiling");
                        self.rounds.remove(sid);
                        return true;
                    }
                    match rpc.sign_multisig(&r.txset) {
                        Ok((set, hashes)) => {
                            r.txset = set;
                            r.signers.push(me);
                            r.txids = hashes;
                            r.fee = read.ok().map(|(_, f)| f);
                            if r.signers.len() >= k {
                                match rpc.submit_multisig(&r.txset) {
                                    Ok(hashes) => {
                                        r.txids = hashes;
                                        r.submitted = true;
                                        // DIGITAL-CASH-PRIVACY-REVIEWED: custody's own sweep between its own wallets — a tx hash public on Monero; no user's value.
                                        eprintln!("[xmr-sweep] ⭐ SWEEP BROADCAST {:?} — a replaced key's Monero moves to the vault's current key", r.txids);
                                    }
                                    Err(e) => eprintln!("[xmr-sweep] the signed sweep did not relay from this node: {e} — the set is complete and is offered again"),
                                }
                            }
                            r.seen_ms = now_ms;
                            if let Some(SweepMsg::Round { signer_pk, sig, .. }) = r.msg(sid).sign(signer) {
                                (r.signer_pk, r.sig) = (signer_pk, sig);
                                push(r.msg(sid));
                                self.rounds.insert(*sid, r);
                            }
                        }
                        Err(e) => {
                            eprintln!("[xmr-sweep] this node's wallet did not sign the sweep: {e}");
                            self.rounds.remove(sid);
                        }
                    }
                } else {
                    push(r.msg(sid)); // not this node's turn: re-offer the round as its last signer signed it
                }
                return true;
            }
        }
        // no unsettled round: on this node's proposer turn, build the sweep of everything the old wallet can spend.
        // Coins that exist but are still locked (a deposit maturing) keep the visits coming every poll.
        // FINALITY OVERLAY (lane speed5, 2026-11-17, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md G5): the turn rotates on the overlay clock
        // the payouts read (`Node::payout_final_time_ms`: vote-final OR 64 levels deep), so a finality stall never freezes the turn on
        // a proposer that is down; F1 moved btc_payout/xmr_payout and left this one (census S-CUSTODY-CLOCK, scratchpad/secure.py).
        let turn = (node.payout_final_time_ms() / crate::btc_payout::PROPOSER_SLOT_MS) as usize % n;
        if row.members[turn] != me || unlocked == 0 || import_needed {
            return balance > 0;
        }
        let dest = [(target.to_string(), unlocked)];
        let mut r = Round { txset: String::new(), signers: vec![me], txids: Vec::new(), submitted: false, signer_pk: Vec::new(), sig: Vec::new(), seen_ms: now_ms, fee: None };
        if multisig {
            match rpc.transfer_multisig(&dest) {
                Ok(set) => {
                    r.fee = rpc.describe_multisig(&set).ok().map(|(_, f)| f);
                    // the builder is the set's first signer. Monero's `transfer` already carries the builder's
                    // signature (signing again is refused, and the built set stands); a wallet whose build is unsigned
                    // signs it here.
                    r.txset = match rpc.sign_multisig(&set) {
                        Ok((signed, _)) => signed,
                        Err(_) => set,
                    };
                }
                Err(e) => {
                    eprintln!("[xmr-sweep] not proposing: this node's wallet could not build the sweep: {e}");
                    return true;
                }
            }
        } else {
            // a one-custodian set is a plain wallet: it builds and relays the sweep itself
            match rpc.transfer_relay(&dest) {
                Ok(txid) => {
                    r.txids = vec![txid];
                    r.submitted = true;
                }
                Err(e) => {
                    eprintln!("[xmr-sweep] not sweeping: this node's wallet could not build the sweep: {e}");
                    return true;
                }
            }
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line — custody's own wallets; no amount, address or member identity.
        eprintln!("[xmr-sweep] PROPOSING the sweep of a replaced key's Monero to the vault's current key");
        if let Some(SweepMsg::Round { signer_pk, sig, .. }) = r.msg(sid).sign(signer) {
            (r.signer_pk, r.sig) = (signer_pk, sig);
            push(r.msg(sid));
            self.rounds.insert(*sid, r);
        }
        true
    }

    /// The sweeps two thirds of their old set have called settled, as cost evidence — for this node's cost lane to
    /// judge (`judge_cost`) and sign.
    #[must_use]
    pub fn cost_evidence(&self, node: &Node) -> Vec<Vec<u8>> {
        self.done
            .iter()
            .filter(|((sid, _, _), who)| old_set(node, sid).is_some_and(|(_, k)| who.len() >= threshold(k.members.len()).max(1) as usize))
            .map(|((sid, txid, fee), _)| XmrCostEvidence { set_id: *sid, txid: txid.clone(), fee: *fee }.encode())
            .collect()
    }

    /// ⭐⭐ JUDGE A MONERO SWEEP'S FEE (finding A-F21: the ledger follows every coin), from THIS node's own chain, its
    /// own lane and its own wallet — `(ledger asset, fee, transaction)` when, here and now:
    ///   • the set the evidence names is an alive replaced key of THIS custodian's own vault on its own chain;
    ///   • two thirds of that key's members have each said, under their own identity keys, that their own old wallet
    ///     shows this transaction confirmed at this fee (gathered by this node's lane, never carried in the evidence);
    ///   • this node's own wallet — the CURRENT set's, which every custodian of the vault holds — shows that
    ///     transaction arriving at the wallet's main address at that fee, past Monero's lock.
    /// A custodian that never held the old wallet judges exactly what one that swept it judges. A deposit (it pays
    /// an integrated address, and no old set calls it a sweep) and a stranger's payment derive nothing.
    /// AI RESISTANT: (b) bounded by the old key's own quorum — a false cost needs two thirds of the old set to sign
    /// a false statement AND a real transaction at that fee into the vault's own wallet; the door then bounds what
    /// one cost may book (`PegLedger::check_reserve_cost`).
    #[must_use]
    pub fn judge_cost(&self, evidence: &[u8], node: &Node, rpc: &WalletRpc) -> Option<(u32, u64, [u8; 32])> {
        let e = XmrCostEvidence::decode(evidence)?;
        node.custodian_id()?;
        let (vault, row) = old_set(node, &e.set_id)?;
        if vault != node.vault_here() {
            return None;
        }
        let said = self.done.get(&(e.set_id, e.txid.clone(), e.fee))?;
        if said.iter().filter(|id| row.members.binary_search(id).is_ok()).count() < threshold(row.members.len()).max(1) as usize {
            return None;
        }
        let id = txid_bytes(&e.txid)?;
        let seen = if row.replaced_tick.is_some() {
            // a replaced key's sweep ARRIVES in the wallet every custodian of the vault holds: its main address
            let (_, fee, confirmations, to_main) = rpc.transfer_fee(&e.txid).ok().flatten()?;
            to_main && fee == e.fee && confirmations >= XMR_SWEEP_CONFIRMATIONS
        } else {
            // a due merge's sweep LEAVES that wallet (the current key's, for the receiving vault's): judged as a
            // transaction this custodian's own wallet SENT, at that fee, past Monero's lock — never as an arrival in
            // a wallet of another vault, which it does not hold
            let (fee, confirmations) = rpc.sent_fee(&e.txid).ok().flatten()?;
            fee == e.fee && confirmations >= XMR_SWEEP_CONFIRMATIONS
        };
        seen.then_some((crate::peg::XMR_PEG_ASSET_ID, e.fee, id))
    }

    /// The fees of sweeps this node's own wallet judges true and that the chain has not booked: counted back into
    /// the Monero solvency reading, so a fee on its way to the ledger never holds the vault's deposits.
    #[must_use]
    pub fn fees_in_flight(&self, node: &Node, rpc: &WalletRpc) -> u64 {
        let ledger = node.ledger_here(crate::peg::XMR_PEG_ASSET_ID);
        self.cost_evidence(node)
            .iter()
            .filter_map(|e| self.judge_cost(e, node, rpc))
            .filter(|(_, _, txid)| !node.reserve_cost_booked(ledger, txid))
            .fold(0u64, |a, (_, fee, _)| a.saturating_add(fee))
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// The codec alone: each message has one encoding, a signature stands only over its own statement, and every
    /// out-of-bounds shape is refused at the decode (the lane itself is pinned on four custodians and a Monero chain
    /// in `node::vault_pins`).
    // TWO-PARTY-REVIEWED: a codec bound has one endpoint by nature; the second endpoint of this class — another
    // custodian's lane and wallet judging the bytes — is
    // `node::vault_pins::safe_at_scale_a_replaced_keys_monero_is_swept_to_the_vaults_current_key_and_a_newcomer_judges_the_fee_on_its_own_wallet`.
    #[test]
    fn a_sweep_message_has_one_encoding_its_signature_binds_its_own_statement_and_wide_shapes_are_refused() {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let me = crate::pqauth::pubkey_id(&pk);
        let key = Some((pk.as_slice(), sk.as_slice()));
        let blank = || (Vec::new(), Vec::new());
        let (p, s) = blank();
        let sync = SweepMsg::Sync { set_id: [1; 32], from: me, info: "state".into(), signer_pk: p, sig: s }.sign(key).expect("signs");
        let (p, s) = blank();
        let round = SweepMsg::Round { set_id: [1; 32], txset: "aa".into(), signers: vec![me], txids: vec!["ab".repeat(32)], submitted: true, signer_pk: p, sig: s }.sign(key).expect("signs");
        let (p, s) = blank();
        let done = SweepMsg::Done { set_id: [1; 32], txid: "ab".repeat(32), fee: 9, from: me, signer_pk: p, sig: s }.sign(key).expect("signs");
        for m in [&sync, &round, &done] {
            assert_eq!(SweepMsg::decode(&m.encode()).as_ref(), Some(m), "one encoding");
            assert_eq!(m.signed_by(), Some(me), "the signer's own statement verifies");
            let mut tail = m.encode();
            tail.push(0);
            assert!(SweepMsg::decode(&tail).is_none(), "⛔ a trailing byte was read as a sweep message");
        }
        // a signature lifted onto another statement verifies under nothing
        let SweepMsg::Done { signer_pk, sig, .. } = done.clone() else { unreachable!() };
        let lifted = SweepMsg::Done { set_id: [1; 32], txid: "ab".repeat(32), fee: 10, from: me, signer_pk: signer_pk.clone(), sig: sig.clone() };
        assert_eq!(lifted.signed_by(), None, "⛔ a statement's signature was accepted over another fee");
        let other = SweepMsg::Done { set_id: [1; 32], txid: "ab".repeat(32), fee: 9, from: [7; 32], signer_pk, sig };
        assert_eq!(other.signed_by(), None, "⛔ a statement was accepted under a sender its key is not");
        // bounds
        let off = |m: SweepMsg| SweepMsg::decode(&m.encode()).is_none();
        let (p, s) = (vec![1u8; 4], vec![2u8; 4]);
        assert!(off(SweepMsg::Sync { set_id: [1; 32], from: me, info: String::new(), signer_pk: p.clone(), sig: s.clone() }), "⛔ an empty state decoded");
        assert!(off(SweepMsg::Sync { set_id: [1; 32], from: me, info: "x".repeat(XMR_SWEEP_TEXT_MAX + 1), signer_pk: p.clone(), sig: s.clone() }), "⛔ a state past the bound decoded");
        assert!(off(SweepMsg::Round { set_id: [1; 32], txset: "aa".into(), signers: Vec::new(), txids: Vec::new(), submitted: false, signer_pk: p.clone(), sig: s.clone() }), "⛔ a round nobody signed decoded");
        assert!(off(SweepMsg::Round { set_id: [1; 32], txset: "aa".into(), signers: vec![me; crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS + 1], txids: Vec::new(), submitted: false, signer_pk: p.clone(), sig: s.clone() }), "⛔ more signers than a vault holds decoded");
        assert!(off(SweepMsg::Round { set_id: [1; 32], txset: "aa".into(), signers: vec![me], txids: vec!["short".into()], submitted: true, signer_pk: p.clone(), sig: s.clone() }), "⛔ a malformed transaction hash decoded");
        assert!(off(SweepMsg::Done { set_id: [1; 32], txid: "ab".repeat(32), fee: 0, from: me, signer_pk: p.clone(), sig: s.clone() }), "⛔ a statement of no fee decoded");
        assert!(off(SweepMsg::Done { set_id: [1; 32], txid: "ab".repeat(32), fee: 9, from: me, signer_pk: p, sig: Vec::new() }), "⛔ an unsigned statement decoded");
        // the cost evidence: tagged, one encoding, never read as a Bitcoin consolidation's
        let e = XmrCostEvidence { set_id: [1; 32], txid: "ab".repeat(32), fee: 9 };
        assert_eq!(XmrCostEvidence::decode(&e.encode()), Some(e.clone()));
        assert!(crate::btc_payout::CostEvidence::decode(&e.encode()).is_none(), "⛔ a Monero sweep's evidence decoded as a Bitcoin consolidation's");
        assert!(XmrCostEvidence::decode(&e.encode()[4..]).is_none(), "⛔ untagged bytes decoded as a Monero sweep's evidence");
    }
}

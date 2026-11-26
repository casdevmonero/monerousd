// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ §BR-15 (spec §18.9) — THE CUSTODIAN'S DeFi LANE: how a custody node runs its half of every batch with the others over
//! the gossip mesh, end to end, with no coordinator.
//!
//! **What it holds** (`defi-custody-<port>.bin` beside the custody book, through the custody keystore — sealed at rest): its
//! own pool shares (from the genesis launch, then from each settlement the chain applied), the sealed share of each order of
//! the open batch AS THE BLOCK CARRIED IT (captured at the instant the order applied — AGENTS.md §6), and the state its own
//! run left it pending until the chain applies the settlement.
//!
//! **A batch, per custodian** (`tick`):
//! 1. the batch closes (the fold's blue score passes its window) → the HANDSHAKE: to every other custodian an ML-KEM
//!    encapsulation to its custody key (`DefiMpcMsg::Hello`). The pair key of custodians i, j is `H(ss_i→j, ss_j→i)`: only the
//!    holders of BOTH decapsulation keys can compute it (a KEM-based authenticated key exchange, KEMTLS's shape, borrowed) —
//!    a node gossiping in a custodian's name holds neither and its messages fail their tag. Every distinct handshake a peer is
//!    named in yields a CANDIDATE key; the key is fixed only by the peer's `Confirm` (a tag under it, which needs both secrets)
//!    — so a forger racing a custodian's handshake neither reads a message nor locks the real peer out.
//! 2. every order's share is opened with the custodian's own key and the order's epoch key (the epoch secret the payout lane
//!    released), and its engine (`defi_mpc_net::Party`) runs `defi_custody::run_party` on its own thread; each message the
//!    engine sends rides one `DefiMpcMsg::Data` to its recipient, encrypted and tagged under the pair key, numbered so a
//!    re-ordered or repeated gossip copy is placed or dropped exactly.
//! 3. the run ends → its part (`DefiMpcMsg::Part`, tagged per recipient) to every custodian; whoever holds all n parts
//!    publishes the settlement (every custodian builds the same bytes: one transaction id, the mempool keeps one).
//! 4. the chain applies the settlement → the pending state becomes the custodian's state (only if the chain's pool commitment
//!    for it is the run's).
//!
//! **A failed run moves no value**: a custodian offline past the batch's expiry (the engine waits until the lane drops the run), a
//! malformed order — the batch expires and every order refunds; the next batch runs fresh.
//!
//! §9.6 (the lane's ingress is a gossip message, not a chain object): (1) PoW — none: it moves nothing on its own; the
//! settlement it produces enters by the DefiSettle door; (2) authenticity — each Data and Part entry is tagged under the
//! pair key; a Hello is a public encapsulation; (3) value — none; the verdict decides; (4) replay — sequence numbers per
//! (batch, sender), a batch's run state cleared when the batch closes; (5) bounded — one run at a time, entries for the open
//! batch only, one Hello per peer; (6) parity with `EpochRelease` (the other custodian gossip): sealed per recipient.
//!
//! ROOT-LAYER: the custodian's own process is where its half of the batch is PRODUCED (it alone holds its shares and keys);
//! the chain decides the result at the DefiSettle door. A file that does not open reads as an empty custody file: the
//! custodian recaptures its launch shares and sits out any batch whose pool commitment its state does not open (refunds).
//! MEASURED: `br15_four_custodian_lanes_settle_a_batch_over_gossip_and_a_forger_is_ignored` (this file) — four lanes, each
//! its own engine thread, every message through `on_msg`; the settlement every lane builds passes the verdict.
//! MUST-STAY-GREEN: every `br15_*` pin of `defi_custody`, `defi_mpc_net` and `defi_acceptance_tests`.
//!
//! BORROWED: KEMTLS's KEM-only authentication; the custody lanes' gossip-and-tick shape (`btc_payout`); Tendermint's "every
//! honest node can publish the agreed result".
//! DIGITAL-CASH-PRIVACY-REVIEWED: on the wire only the batch number, sender index, sequence number and ciphertexts; no amount,
//! order, share or owner is readable by a relaying node.
//! TWO-PARTY-REVIEWED: the pin runs four custodian lanes, each with its own keys and its own engine thread, plus a forger.

use crate::defi_batch::{self as db, CustodianPart, DefiBook, DefiSettleTx, Word};
use crate::defi_clear::F255;
use usdm_decider::br15_audit as ba;
use usdm_decider::hiding_decider::Fa4;
use crate::defi_custody::{self as dcu, CustodianState, OrderShare};
use crate::defi_mpc_net::{Comm, Party};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver, Sender};

/// One slice of a custodian's engine's wait for a peer's message: it waits slice after slice until the message comes or the
/// lane drops the run (its batch settled or expired) — `LaneComm::recv`.
pub const PEER_WAIT_MS: u64 = 60_000;
/// How often a custodian re-sends its handshake while it waits for the others' (a peer that restarted, or missed it).
pub const HELLO_RESEND_MS: u64 = 5_000;
const TAG: usize = 16;
/// The candidate keys kept per peer (a forger's handshakes beyond this are dropped; the peer's own re-sent handshake is a
/// candidate already, so the real key survives any flood that arrives after it).
pub const MAX_CANDIDATES: usize = 8;
/// The longest a re-send waits after backing off (RFC 6298 §2.5: a maximum, if any, is at least 60 s). The batch's own expiry
/// still bounds the run.
pub const RTO_MAX_MS: u64 = 240_000;

/// ⭐ THE RE-SEND TIMER, BORROWED WHOLE FROM TCP (RFC 6298, Jacobson/Karels): the wait before a re-send is the measured
/// round trip plus four times its variation, never a fixed guess. MEASURED 2026-11-08 (real nodes, the DeFi rig): a round
/// trip through the shared cell queue took ~100 s (queue depth median 762 cells at 16 cells/s), while the fixed 5 s first
/// wait re-sent every engine message about four times before its first copy left this node; those copies were 47,271 of
/// the ~68,600 cells queued in the run, which is what made the queue that deep. Karn's rule: a re-sent message gives no
/// sample (its acknowledgement could answer either copy).
#[derive(Clone, Copy, Debug)]
struct Rto {
    srtt_ms: Option<u64>,
    rttvar_ms: u64,
    rto_ms: u64,
}

impl Rto {
    fn new() -> Self {
        Rto { srtt_ms: None, rttvar_ms: 0, rto_ms: HELLO_RESEND_MS }
    }
    /// One round-trip sample (RFC 6298 §2.2–2.3; G is the lane's tick, under the floor).
    fn sample(&mut self, r: u64) {
        match self.srtt_ms {
            None => {
                self.srtt_ms = Some(r);
                self.rttvar_ms = r / 2;
            }
            Some(srtt) => {
                self.rttvar_ms = (3 * self.rttvar_ms + srtt.abs_diff(r)) / 4;
                self.srtt_ms = Some((7 * srtt + r) / 8);
            }
        }
        self.collapse();
    }
    /// The timer from the estimate again (§5.7: after a backoff, a new acknowledgement recomputes it).
    fn collapse(&mut self) {
        if let Some(srtt) = self.srtt_ms {
            self.rto_ms = (srtt + 4 * self.rttvar_ms).clamp(HELLO_RESEND_MS, RTO_MAX_MS);
        }
    }
    /// A timeout: the wait doubles (§5.5).
    fn backoff(&mut self) {
        self.rto_ms = self.rto_ms.saturating_mul(2).min(RTO_MAX_MS);
    }
}

/// What a block taught this node about the DeFi batch (drained by the lane every tick).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefiEvent {
    /// an order applied to the open batch at `index`: its epoch, epoch ciphertext and every custodian's sealed share
    Order { batch: u64, index: u32, epoch: u64, epoch_ct: Vec<u8>, sealed: Vec<Vec<u8>> },
    /// the batch closed on the chain (settled or expired)
    Closed { batch: u64 },
    /// an old custodian's handover dealing applied (spec §18.11): every new custodian's sealed sub-share
    HandoverDeal { batch: u64, from: u32, sealed: Vec<Vec<u8>> },
}

/// What a slot in a custodian's intake can still become: carried in a batch's slots, or dropped — and which dead branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlotFate {
    Carried,
    /// its nullifier is already spent on this node's chain
    NullifierSpent,
    /// its member leg is refused at the fold door (its anchor left this node's ring and epoch anchors, or it speaks for another object)
    LegRefused,
    /// dead by a host that does not tell the two apart
    Dead,
}

/// The lane's view of its node (the node, or a test's stand-in): the book, the fold's blue score, the events, the door.
/// ⭐ A-F114 — what a cover's wrapper is proven over under the constant chain: the end of the record before a span of the
/// window, that span's first index, and its `SPAN` records' tags and leaves (`canon_chain::CanonRecent`), handed to the
/// slot builder's thread (it reads no node). A cover's leaf is an output of the span's first record.
#[derive(Clone, Debug)]
pub struct CanonCoverWindow {
    pub start_end: crate::spend_frontier::Digest4,
    pub start_index: u64,
    pub recs: Vec<(Vec<[u8; 32]>, Vec<crate::spend_frontier::Digest4>)>,
}

pub trait DefiHost {
    /// ⭐ A-F114 — under the constant chain, the window span a cover's wrapper is proven over (`None`: not enough records yet,
    /// or before the upgrade)
    fn canon_cover_window(&self) -> Option<CanonCoverWindow> {
        self.canon_cover_window_at(None)
    }
    /// ⭐ A-F114 — the window span that CLOSES a global span (aligned, `(index + 1) % SPAN == 0`) at chain end `end`, or the
    /// newest such span (`None`)
    fn canon_cover_window_at(&self, _end: Option<crate::spend_frontier::Digest4>) -> Option<CanonCoverWindow> {
        None
    }
    /// ⭐ A-F114 — the chain end of the wrapper a slot's holder relayed for nullifier `nf` (`None`: none held)
    fn slot_wrapper_end(&self, _nf: [u64; 8]) -> Option<crate::spend_frontier::Digest4> {
        None
    }
    /// ⭐ A-F114 — keep the wrappers the slot builder proved (its covers'), by nullifier, for the slots' publication
    fn hold_wrappers(&mut self, _ws: Vec<([u8; 32], Vec<u8>)>) {}
    fn book(&self) -> DefiBook;
    fn score(&self) -> u64;
    /// The chain clock at this node's tip (`Node::chain_time_ms`): what a batch's settlement window counts on.
    fn chain_ms(&self) -> u64;
    fn drain_defi_events(&mut self) -> Vec<DefiEvent>;
    /// the epoch key pair this custodian holds for `epoch` (released, not yet erased)
    fn epoch_keys(&self, epoch: u64) -> Option<(crate::epoch_key::EpochPublicKey, crate::epoch_key::EpochSecretKey)>;
    fn publish_settle(&mut self, t: &DefiSettleTx) -> bool;
    /// the bonded custody set's keys, in the canonical order a handover's new roster must name (spec §18.11)
    fn bonded_custody(&self) -> Vec<Vec<u8>>;
    fn publish_handover(&mut self, t: &crate::defi_handover::DefiHandoverTx) -> bool;
    /// ⭐ spec §18.12 — the slots this node's wallet handed it since the last tick (`(claim, bytes)`)
    fn drain_intake(&mut self) -> Vec<(bool, Vec<u8>)>;
    /// the epoch an order seals to now and its released public key (the one a buyer's wallet reads from `/defi_book`)
    fn seal_epoch(&self) -> Option<(u64, crate::epoch_key::EpochPublicKey)>;
    /// A-F26: the newest epoch anchor `(ordinal, root, frontier)`. `None` when no anchor has folded since start.
    fn epoch_anchor_info(&self) -> Option<(u64, crate::spend_frontier::Digest4, crate::spend_frontier::PoseidonSpendFrontier)>;
    /// `k` leaves this node holds, each with its gathered member book at the batch's epoch anchor (A-F26: every cover
    /// is proven at the same anchor as every real slot, so no partition by anchor tells them apart).
    fn cover_books(&self, k: usize, anchor_ordinal: u64, anchor_root: crate::spend_frontier::Digest4, anchor_frontier: &crate::spend_frontier::PoseidonSpendFrontier) -> Vec<([u8; 32], crate::member_witness::MemberWitnessBook)>;
    /// whether a slot's member leg holds HERE and its nullifier is unspent (a slot that would sink the batch's slots is left out)
    fn slot_live(&self, carrier: &[u8], tuple: &[u8], leaf_commit: [u64; 8], nf: [u64; 8]) -> bool;
    /// whether a slot can never be carried: its nullifier spent or its leg refused. A leg still pending here only waits, so it is never dropped for that (its holder asks again next batch).
    fn slot_dead(&self, carrier: &[u8], tuple: &[u8], leaf_commit: [u64; 8], nf: [u64; 8]) -> bool {
        !self.slot_live(carrier, tuple, leaf_commit, nf)
    }
    /// a slot's fate in this custodian's intake — the branch, so a drop names its cause; never the slot itself
    fn slot_fate(&self, carrier: &[u8], tuple: &[u8], leaf_commit: [u64; 8], nf: [u64; 8]) -> SlotFate {
        if self.slot_dead(carrier, tuple, leaf_commit, nf) {
            SlotFate::Dead
        } else {
            SlotFate::Carried
        }
    }
    fn publish_slots(&mut self, t: &db::DefiSlotsTx) -> bool;
    /// publish the expiry of a batch past its settlement window; `false` when it could not be pooled
    fn publish_expire(&mut self, _t: &db::DefiExpireTx) -> bool {
        false
    }
    /// ⭐ Earn step 3 — every pair's book (pair order), what an EarnEpoch spans; a host with one pool returns its one book
    fn books(&self) -> Vec<DefiBook> {
        vec![self.book()]
    }
    /// ⭐ Earn step 3 — publish an EarnEpoch chunk; `false` when it could not be pooled
    fn publish_epoch(&mut self, _t: &db::DefiEarnEpochTx) -> bool {
        false
    }
}

/// ⭐ The node as a lane host: its book and blue score, its fold's DeFi events, the payout lane's released epoch keys, the
/// DefiSettle door.
pub struct NodeHost<'a> {
    pub pair: u8,
    pub node: &'a mut crate::node::Node,
    pub payout: &'a crate::btc_payout::PayoutLane,
}

impl NodeHost<'_> {
    /// ⭐ A-F114 — is a slot's nullifier spent, as THIS node can say before carrying it? Under the network upgrade no node
    /// holds the spent set, so the custody intake reads the canonical chain's recent window (a spend inside it). A spend older
    /// than the window is refused at the fold by the slot's own wrapper, the authority as everywhere; this is a courtesy that
    /// keeps a dead slot out of the batch early. Before the upgrade it is the spent set, as it was.
    fn slot_spent(&self, nf: [u64; 8]) -> bool {
        let tag = crate::spend_frontier::leaf_to_cm_bytes(nf);
        if crate::params::canon_live() {
            self.node.canon_recent.holds(&tag)
        } else {
            self.node.is_nullifier_spent(&crate::hash::Hash32(tag))
        }
    }
}

impl DefiHost for NodeHost<'_> {
    fn chain_ms(&self) -> u64 {
        self.node.chain_time_ms()
    }
    fn book(&self) -> DefiBook {
        self.node.peg().defi_book_of(self.pair).cloned().unwrap_or_default()
    }
    fn score(&self) -> u64 {
        self.node.selected_tip_blue_score().unwrap_or(0)
    }
    fn drain_defi_events(&mut self) -> Vec<DefiEvent> {
        self.node.drain_defi_events(self.pair)
    }
    fn epoch_keys(&self, epoch: u64) -> Option<(crate::epoch_key::EpochPublicKey, crate::epoch_key::EpochSecretKey)> {
        self.payout.epoch_secret(epoch)
    }
    fn publish_settle(&mut self, t: &DefiSettleTx) -> bool {
        self.node.publish_defi_settle(t).is_ok()
    }
    fn bonded_custody(&self) -> Vec<Vec<u8>> {
        crate::defi_handover::canonical_roster(&self.node.validators().bonded_custodian_eks())
    }
    fn publish_handover(&mut self, t: &crate::defi_handover::DefiHandoverTx) -> bool {
        self.node.publish_defi_handover(t).is_ok()
    }
    fn drain_intake(&mut self) -> Vec<(bool, Vec<u8>)> {
        self.node.drain_defi_intake(self.pair)
    }
    fn seal_epoch(&self) -> Option<(u64, crate::epoch_key::EpochPublicKey)> {
        let ek = self.node.peg().epoch_keys();
        ek.release_epoch().and_then(|e| ek.release_key(e).map(|pk| (e, pk.clone())))
    }
    fn epoch_anchor_info(&self) -> Option<(u64, crate::spend_frontier::Digest4, crate::spend_frontier::PoseidonSpendFrontier)> {
        self.node.epoch_anchor_info().map(|(o, r, f)| (o, r, f.clone()))
    }
    fn cover_books(&self, k: usize, anchor_ordinal: u64, anchor_root: crate::spend_frontier::Digest4, anchor_frontier: &crate::spend_frontier::PoseidonSpendFrontier) -> Vec<([u8; 32], crate::member_witness::MemberWitnessBook)> {
        // A-F26: every cover is proven at the batch's epoch anchor, the same anchor every real slot names
        let mut held: Vec<[u8; 32]> = self.node.held_note_cms().into_iter().collect();
        held.sort_unstable();
        let mut start = [0u8; 8];
        if let Some(e) = dcu::custody_entropy() {
            start.copy_from_slice(&e[..8]);
        }
        let from = (u64::from_le_bytes(start) as usize) % held.len().max(1);
        let mut out = Vec::with_capacity(k);
        for cm in held.iter().cycle().skip(from).take(held.len().min(4 * k)) {
            if out.len() == k {
                break;
            }
            if let Ok(book) = self.node.member_book_for_note_at_epoch_anchor(cm, anchor_ordinal, anchor_root, anchor_frontier) {
                out.push((*cm, book));
            }
        }
        out
    }
    fn canon_cover_window_at(&self, end: Option<crate::spend_frontier::Digest4>) -> Option<CanonCoverWindow> {
        if !crate::canon_chain::canon_live() {
            return None;
        }
        let span = crate::canon_carrier_core::SPAN;
        let oldest = self.node.canon_recent.oldest()?;
        let all = self.node.canon_recent.range(oldest, crate::canon_chain::CANON_RECENT_RECORDS);
        // a record that closes a global span, with a whole span and its predecessor in the window: the named end, or the newest
        // its predecessor's end: the record before it in the window, or the chain's genesis value for the span at record 0
        // (FOUND by the real-order pin: a note funded in the chain's first span had no window record before it)
        let before = |first: usize| -> Option<crate::spend_frontier::Digest4> {
            if first > 0 {
                Some(all[first - 1].1)
            } else {
                (all[0].0 == 0).then(crate::canon_chain::genesis)
            }
        };
        let closes = |j: usize| (all[j].0 + 1) % span as u64 == 0 && j + 1 >= span && before(j + 1 - span).is_some();
        let j = (0..all.len()).rev().find(|&j| closes(j) && end.is_none_or(|e| all[j].1 == e))?;
        let first = j + 1 - span;
        Some(CanonCoverWindow {
            start_end: before(first)?,
            start_index: all[first].0,
            recs: all[first..=j].iter().map(|(_, _, t, l, _)| (t.as_ref().clone(), l.as_ref().clone())).collect(),
        })
    }
    fn slot_wrapper_end(&self, nf: [u64; 8]) -> Option<crate::spend_frontier::Digest4> {
        let k = crate::spend_frontier::leaf_to_cm_bytes(nf);
        let (_, held) = self.node.canon_held_wrappers.iter().find(|(x, _)| *x == k)?;
        let ws: Vec<crate::nf_sparse::CanonAbsence> = postcard::from_bytes(held).ok()?;
        ws.first().map(|w| w.end)
    }
    fn hold_wrappers(&mut self, ws: Vec<([u8; 32], Vec<u8>)>) {
        for (nf, w) in ws {
            self.node.canon_hold_wrappers(nf, w);
        }
    }
    fn slot_live(&self, carrier: &[u8], tuple: &[u8], leaf_commit: [u64; 8], nf: [u64; 8]) -> bool {
        // ⭐ A-F114: under the constant chain a slot's leg is its relayed wrapper, judged by the canonical door
        if crate::canon_chain::canon_live() {
            return carrier.is_empty()
                && tuple.is_empty()
                && self.node.canon_slot_state(&crate::spend_frontier::leaf_to_cm_bytes(nf), &leaf_commit) == crate::canon_chain::CanonSlot::Live;
        }
        !self.slot_spent(nf) && self.node.defi_member_leg(carrier, tuple, leaf_commit, nf)
    }
    fn slot_dead(&self, carrier: &[u8], tuple: &[u8], leaf_commit: [u64; 8], nf: [u64; 8]) -> bool {
        if crate::canon_chain::canon_live() {
            // a member leg under the constant chain is one encoding too many: it can never be carried
            return !carrier.is_empty()
                || !tuple.is_empty()
                || matches!(
                    self.node.canon_slot_state(&crate::spend_frontier::leaf_to_cm_bytes(nf), &leaf_commit),
                    crate::canon_chain::CanonSlot::Spent | crate::canon_chain::CanonSlot::Refused
                );
        }
        self.slot_spent(nf) || self.node.defi_member_leg_refused(carrier, tuple, leaf_commit, nf)
    }
    fn slot_fate(&self, carrier: &[u8], tuple: &[u8], leaf_commit: [u64; 8], nf: [u64; 8]) -> SlotFate {
        if crate::canon_chain::canon_live() {
            return match self.node.canon_slot_state(&crate::spend_frontier::leaf_to_cm_bytes(nf), &leaf_commit) {
                crate::canon_chain::CanonSlot::Spent => SlotFate::NullifierSpent,
                crate::canon_chain::CanonSlot::Refused => SlotFate::LegRefused,
                _ if !carrier.is_empty() || !tuple.is_empty() => SlotFate::LegRefused,
                _ => SlotFate::Carried,
            };
        }
        if self.node.is_nullifier_spent(&crate::hash::Hash32(crate::spend_frontier::leaf_to_cm_bytes(nf))) {
            SlotFate::NullifierSpent
        } else if self.node.defi_member_leg_refused(carrier, tuple, leaf_commit, nf) {
            SlotFate::LegRefused
        } else {
            SlotFate::Carried
        }
    }
    fn publish_slots(&mut self, t: &db::DefiSlotsTx) -> bool {
        self.node.publish_defi_slots(t).is_ok()
    }
    fn publish_expire(&mut self, t: &db::DefiExpireTx) -> bool {
        self.node.publish_defi_expire(t).is_ok()
    }
    fn books(&self) -> Vec<DefiBook> {
        (0..db::PAIRS).map(|p| self.node.peg().defi_book_of(p).cloned().unwrap_or_default()).collect()
    }
    fn publish_epoch(&mut self, t: &db::DefiEarnEpochTx) -> bool {
        self.node.publish_defi_earn_epoch(t).is_ok()
    }
}

/// The largest settlement chunk a custodian publishes: one transaction's weight less a margin for the wrapper.
pub const SETTLE_CHUNK_BYTES: usize = crate::params::MAX_TX_WEIGHT_BYTES as usize - 64 * 1024;

/// One lane message, as gossip carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefiMpcMsg {
    /// the sender's encapsulation to each other custodian (`(to, ML-KEM ciphertext)`)
    Hello { batch: u64, from: u32, cts: Vec<(u32, Vec<u8>)>, copy: u32 },
    /// key confirmation: a tag under the candidate pair key the sender derived for `(from, to)`
    Confirm { batch: u64, from: u32, to: u32, tag: [u8; TAG] },
    /// one engine message to `to`, under the pair key: `seq` numbers the sender's messages to `to` in this batch
    Data { batch: u64, from: u32, to: u32, seq: u64, body: Vec<u8>, copy: u32 },
    /// the sender's settlement part, tagged per recipient (`(to, tag)`) over its encoding
    Part { batch: u64, from: u32, part: Vec<u8>, tags: Vec<(u32, [u8; TAG])>, copy: u32 },
    /// ⭐ spec §18.12 — a buyer's order slot (`claim = false`) or claim slot, gossiped to the custody set for its batch's slots
    Submit { claim: bool, body: Vec<u8> },
    /// the receiver's cumulative acknowledgement: it has placed every `Data` from `to` to `from` below `next` (BORROWED: TCP's
    /// cumulative ACK). The sender re-sends what is not acknowledged, so one gossip copy lost on a dropped link never stalls
    /// the run (MEASURED 2026-11-08, real nodes: four batches in a row aborted on a 60 s receive while the two custodians'
    /// Tor links dropped and recovered, and every one refunded).
    /// Tagged under the pair key (`ack_tag`), as `Confirm` and `Part` are: a forged acknowledgement would stop a re-send.
    Ack { batch: u64, from: u32, to: u32, next: u64, tag: [u8; TAG], copy: u32 },
}
// `copy` (on every kind that is sent again): which re-send this is, outside every tag and body and read by nobody. Every relay
// drops a byte-identical message it has seen (`DefiLane::seen`), so without it a re-send would stop at the first relay that
// passed the lost copy; the receiver still places each message exactly once (by `seq`, by sender, by key).

impl DefiMpcMsg {
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    /// One canonical encoding, bounded: at most `MAX_ROSTER` entries per message, an engine message of at most 2^20 field
    /// elements, a part of at most two proofs' bound.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let m: Self = crate::chain_object::decode_exact(bytes)?;
        let ok = match &m {
            Self::Hello { cts, .. } => cts.len() <= db::MAX_ROSTER && cts.iter().all(|(_, c)| c.len() == crate::pqkem::ciphertext_len()),
            Self::Confirm { .. } => true,
            Self::Data { body, .. } => body.len() <= (32 << 20) + TAG,
            Self::Part { part, tags, .. } => part.len() <= 2 * db::MAX_PROOF_BYTES && tags.len() <= db::MAX_ROSTER,
            Self::Submit { body, .. } => body.len() <= 3 * db::MAX_PROOF_BYTES,
            Self::Ack { .. } => true,
        };
        ok.then_some(m)
    }
}

/// One filed order share: (the order's index in its batch's book, its epoch, the epoch key's ciphertext, this custodian's sealed share).
type FiledOrder = (u32, u64, Vec<u8>, Vec<u8>);

/// File `entry` in `list` once: an order already there (the same sealed bytes — a fold's replay of its slots) keeps one entry and
/// takes the index the chain named last (a re-fold may renumber a batch's slots). `true` when the list changed.
fn file_order(list: &mut Vec<FiledOrder>, entry: FiledOrder) -> bool {
    match list.iter_mut().find(|e| e.1 == entry.1 && e.2 == entry.2 && e.3 == entry.3) {
        Some(e) if e.0 == entry.0 => false,
        Some(e) => {
            e.0 = entry.0;
            true
        }
        None => {
            list.push(entry);
            true
        }
    }
}

/// What a custodian keeps across restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CustodyFile {
    /// its pool shares (`None` until it captured them from the launch)
    me: Option<CustodianState>,
    /// the open batch and the sealed share of each of its orders, as the blocks carried them (index, epoch, epoch ct, mine)
    batch: u64,
    orders: Vec<(u32, u64, Vec<u8>, Vec<u8>)>,
    /// the next batch's orders, placed while the open one clears (spec §18.11)
    #[serde(default)]
    queued: Vec<(u32, u64, Vec<u8>, Vec<u8>)>,
    /// the state its run for a batch left, pending the chain's settlement
    next: Option<(u64, CustodianState)>,
    /// ⭐ spec §18.11 — as a NEW custodian of an open handover: the sub-shares it captured (old custodian index, its state), and
    /// the pool state its acceptance commits to, pending the switch
    #[serde(default)]
    handover_subs: Vec<(u32, dcu::SubShare)>,
    #[serde(default)]
    handover_next: Option<CustodianState>,
}

/// A custodian's links for one run: the engine's sends leave through `out` (the lane encrypts and gossips them); each peer's
/// messages arrive, in order, on its own channel.
struct LaneComm {
    me: usize,
    n: usize,
    out: Sender<(usize, Vec<F255>)>,
    inbox: Vec<Receiver<Vec<F255>>>,
    self_tx: Sender<Vec<F255>>,
    /// raised when the lane drops the run (its batch moved on: settled or expired) — the only end of a wait
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Comm for LaneComm {
    fn me(&self) -> usize {
        self.me
    }
    fn n(&self) -> usize {
        self.n
    }
    fn send(&mut self, to: usize, msg: Vec<F255>) {
        // a closed channel means the lane dropped the run (its batch closed); the engine's next receive ends it
        if to == self.me {
            let _ = self.self_tx.send(msg);
        } else {
            let _ = self.out.send((to, msg));
        }
    }
    /// A run lives as long as its batch, never as long as one wait: a peer's link can be silent for minutes and recover
    /// (MEASURED 2026-11-08, real nodes: every batch aborted on a 60 s receive while the custodians' Tor links dropped and
    /// came back, and every one refunded). It waits in [`PEER_WAIT_MS`] slices until the message comes or the lane drops
    /// the run; the batch's own expiry is the bound, as before.
    fn recv(&mut self, from: usize) -> Option<Vec<F255>> {
        loop {
            match self.inbox[from].recv_timeout(std::time::Duration::from_millis(PEER_WAIT_MS)) {
                Ok(m) => return Some(m),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) if !self.stop.load(std::sync::atomic::Ordering::Relaxed) => {}
                Err(_) => return None,
            }
        }
    }
}

/// The handshake and the run of one batch.
struct Run {
    batch: u64,
    /// my encapsulation secrets to each peer and their ciphertexts (re-sent until every peer answered)
    ss_to: BTreeMap<u32, [u8; 32]>,
    cts: Vec<(u32, Vec<u8>)>,
    hello_sent_ms: u64,
    /// each peer's candidate pair keys (one per distinct handshake naming it, at most [`MAX_CANDIDATES`]) and whether this
    /// custodian sent its confirmation under each; the pair keys the peers CONFIRMED
    cand: BTreeMap<u32, Vec<([u8; 32], bool)>>,
    keys: BTreeMap<u32, [u8; 32]>,
    /// peers whose handshake arrived AGAIN after this custodian confirmed their key — `(an answer is due, when it last
    /// answered one)`: its
    /// confirmation is sent to them again (TCP's shape: a repeated SYN is answered with the SYN-ACK again), at most once per
    /// [`HELLO_RESEND_MS`] each. A peer still sending its handshake has not received this custodian's confirmation, and a
    /// custodian whose engine started sends no other handshake message, so a lost confirmation left the peer waiting for
    /// the batch's whole window (MEASURED 2026-11-09, real nodes: pair 0's batch 2 closed after 2,340 s with "1 engine
    /// message sent, 0 placed from peers" on one custodian while the other never started). Bounded by the roster.
    reconfirm: BTreeMap<u32, (bool, u64)>,
    /// the engine, once started: its outbox, each peer's inbox and expected sequence, the sequence of my sends, its result
    started: bool,
    out_rx: Option<Receiver<(usize, Vec<F255>)>>,
    in_tx: BTreeMap<u32, Sender<Vec<F255>>>,
    next_in: BTreeMap<u32, u64>,
    held_in: BTreeMap<(u32, u64), Vec<F255>>,
    seq_out: BTreeMap<u32, u64>,
    /// every `Data` sent and not yet acknowledged by its recipient (`(to, seq)`), re-sent every [`HELLO_RESEND_MS`]; this
    /// custodian's own part, re-sent on the same cadence until the run ends. Bounded by the engine's lock-step rounds: a
    /// round's messages are acknowledged before the peer's next round can need them.
    /// each with where its latest copy is ([`Sent`]) and whether it was re-sent since (Karn's rule)
    unacked: BTreeMap<(u32, u64), Sent>,
    my_part: Option<Sent>,
    /// the re-send timer: when it was started (`None` = not running) and its wait ([`Rto`], RFC 6298)
    timer_ms: Option<u64>,
    rto: Rto,
    /// the copy counter of this custodian's re-sends (see `DefiMpcMsg`'s `copy`)
    copies: u32,
    /// an engine message was placed since the last acknowledgement went out
    ack_due: bool,
    result: Option<std::thread::JoinHandle<Result<RunOut, &'static str>>>,
    /// the parts gathered (mine included) and the outcome every custodian agreed
    parts: BTreeMap<u32, CustodianPart>,
    /// `(tick, sells, j_min, complaint set, phase-1 digests)`
    agreed: Option<(i64, bool, u64, Vec<u32>, Vec<[u64; 4]>)>,
    /// ⭐ Earn step 3 — an EARNEPOCH run (`Some(raise)`; its run id is [`epoch_run_id`]) instead of a batch's: its parts and
    /// the `(rate, phase-1 digests)` every custodian agreed
    epoch: Option<u64>,
    eparts: BTreeMap<u32, db::EpochPart>,
    eagreed: Option<(u64, Vec<[u64; 4]>)>,
    published: bool,
    /// the settlement's non-closing chunks are out (spec §18.11); the closing one follows once the book holds them
    chunks_out: bool,
    /// the engine's stop: raised when this run is dropped (`Drop`), ending any wait it is in
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// when the engine started (unix ms, 0 = not yet) and how many engine messages from peers this run placed
    started_ms: u64,
    placed: u64,
    /// ⭐ THE RUN'S OWN TRAFFIC, for its closing line ([`Run::traffic`]) — one run names where its time went: engine messages
    /// first sent and sent again `(count, bytes)`, part copies, every other lane message (handshake, confirmation,
    /// acknowledgement), the summed wait of first copies in this node's own queue and of clean round trips `(ms, samples)`,
    /// and what this lane heard from the wire meanwhile `(new, new bytes, repeats)` — each new one relayed once.
    /// O1-FOOTPRINT-REVIEWED: fixed-width counters, one run at a time.
    sent_first: (u64, u64),
    sent_again: (u64, u64),
    part_sent: (u64, u64),
    sent_other: (u64, u64),
    queue_wait: (u64, u64),
    rtt: (u64, u64),
    heard: (u64, u64, u64),
}

/// What a run's engine returns: a batch's party result, or an EarnEpoch's.
enum RunOut {
    Batch(dcu::PartyOut),
    Epoch(dcu::EpochOut),
}

/// ⭐ Earn step 3 — the run id of the EarnEpoch completing raise `raise`: the top bit set, so it is never a batch number (each
/// run's handshake, pair keys and message nonces are keyed by its id).
#[must_use]
pub fn epoch_run_id(raise: u64) -> u64 {
    (1u64 << 63) | raise
}

pub use crate::defi_batch::epoch_due;

/// Where a sent copy is (RFC 6298 §5.1 times a segment from its TRANSMISSION): handed to the cell channel this tick, queued
/// there at a departure mark (`CellChannel::last_queued_mark`), or gone from this node — its last cell handed to the
/// transport — at a known time. A copy still in this node's own outbound queue has not been sent: it is never timed, and
/// never sent again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leave {
    Handed,
    At(i64),
    Left(u64),
}

/// One sent message awaiting its acknowledgement, or this custodian's part awaiting the run's end.
struct Sent {
    msg: DefiMpcMsg,
    /// when its latest copy was handed to the channel (unix ms)
    copy_ms: u64,
    /// re-sent since its first copy (Karn's rule: its acknowledgement gives no sample)
    resent: bool,
    leave: Leave,
}

impl Sent {
    fn new(msg: DefiMpcMsg, now_ms: u64) -> Self {
        Sent { msg, copy_ms: now_ms, resent: false, leave: Leave::Handed }
    }
    /// At the start of a pump (one per tick, so the runtime has handed back the mark of every copy the last pump sent):
    /// when the latest copy left this node, if it left just now (`departed`: the channel's departure count now).
    fn resolve(&mut self, departed: i64, now_ms: u64) -> Option<u64> {
        match self.leave {
            // SAFE-FALLBACK: a whole tick passed and no mark came back (a lane driven without a cell channel, as the
            // in-process pins drive it): it is timed from its hand-off, the timer this lane had before departure marks —
            // it re-sends, never withholds a re-send.
            Leave::Handed => self.leave = Leave::Left(self.copy_ms),
            Leave::At(mark) if departed >= mark => self.leave = Leave::Left(now_ms),
            _ => return None,
        }
        self.left_at()
    }
    /// When its latest copy left this node, if it has.
    fn left_at(&self) -> Option<u64> {
        match self.leave {
            Leave::Left(t) => Some(t),
            _ => None,
        }
    }
}

impl Run {
    /// DIGITAL-CASH-PRIVACY-REVIEWED: message counts, byte totals and waits fixed by the batch's constant slot shape and this
    /// node's own link, to this node's own log; no order, amount, owner, key or share.
    fn traffic(&self) -> String {
        let mb = |b: u64| b as f64 / 1e6;
        let mean = |(sum, n): (u64, u64)| if n == 0 { 0 } else { sum / n };
        format!(
            "engine messages sent {} ({:.2} MB), sent again {} ({:.2} MB); part copies {} ({:.2} MB); other lane messages {} ({:.2} MB); \
             mean wait in this node's own queue {} ms over {}; mean round trip {} ms over {}; heard {} new ({:.2} MB, each relayed once), {} repeats",
            self.sent_first.0,
            mb(self.sent_first.1),
            self.sent_again.0,
            mb(self.sent_again.1),
            self.part_sent.0,
            mb(self.part_sent.1),
            self.sent_other.0,
            mb(self.sent_other.1),
            mean(self.queue_wait),
            self.queue_wait.1,
            mean(self.rtt),
            self.rtt.1,
            self.heard.0,
            mb(self.heard.1),
            self.heard.2
        )
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

impl Drop for Run {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // a batch that closed on a run still going: how far it got, so a slow engine is told apart from a peer that never
        // answered. DIGITAL-CASH-PRIVACY-REVIEWED: the public batch number, a duration and message counts fixed by the
        // batch's constant slot shape, to this node's own log; no order, amount, owner or key.
        if self.started_ms > 0 && self.result.is_some() {
            eprintln!(
                "[defi-lane] batch {} closed with this custodian's run unfinished after {} s: {} engine message(s) sent, {} placed from peers, {} unacknowledged — {}",
                self.batch,
                unix_ms().saturating_sub(self.started_ms) / 1000,
                self.seq_out.values().sum::<u64>(),
                self.placed,
                self.unacked.len(),
                self.traffic()
            );
        }
    }
}

/// ⭐ THE CUSTODIAN'S LANE.
pub struct DefiLane {
    /// ⭐ §18.14 — the pair this lane runs
    pub pair: u8,
    /// ⭐ A-F114 — this member's cover share for a batch in proving (the batch, its job), and the last batch it delivered
    share_job: Option<(u64, std::sync::mpsc::Receiver<Option<CoverShare>>)>,
    share_sent: Option<u64>,
    /// ⭐ A-F114 — relays of the wrappers this lane proved (`postcard((legs, wrappers))`, the `WireMsg::CanonWrappers` body), for
    /// the runtime to send (`NodeRuntime`'s lane loop drains it)
    pub wrapper_relay: Vec<Vec<u8>>,
    path: Option<std::path::PathBuf>,
    file: CustodyFile,
    /// this custodian's custody KEM pair (the key the book's roster names) and its index there
    kem: Option<(Vec<u8>, Vec<u8>)>,
    me_index: Option<u32>,
    run: Option<Run>,
    /// messages that arrived before this custodian's own run of their batch began (bounded: one handshake per peer, and
    /// the engine messages a peer can send before its first answer)
    early_hello: BTreeMap<(u64, u32), Vec<u8>>,
    early: Vec<DefiMpcMsg>,
    /// the lane messages this node has relayed or sent itself (their hashes), so each is relayed once and its own is never
    /// relayed back; O1-FOOTPRINT-REVIEWED: cleared at [`SEEN_MAX`] (a re-relay of an old message is harmless: its addressee
    /// drops a repeated sequence number)
    seen: std::collections::HashSet<[u8; 32]>,
    /// the cell channel's departure count as of this tick (`CellChannel::departed_net`, set by the runtime before each tick)
    departed: i64,
    /// the batch at which this custodian last published a handover Open, Deal and Accept (each once per batch)
    handover_open_sent: Option<u64>,
    handover_deal_sent: Option<u64>,
    handover_accept_sent: Option<u64>,
    /// ⭐ spec §18.12 — the order and claim slots the custody set holds for the next batch's slots, oldest first.
    /// O1-FOOTPRINT-REVIEWED: at most `4 × SLOTS` each (an older one is dropped first); a placed or spent one leaves.
    pending_orders: Vec<db::DefiOrderTx>,
    pending_claims: Vec<db::DefiClaimTx>,
    /// the batch whose slots this custodian published
    slots_sent: Option<u64>,
    /// the batch whose slots are being built off the tick thread (covers' proofs and legs), and where they arrive
    slot_job: Option<(u64, std::sync::mpsc::Receiver<Option<(Vec<db::DefiSlotsTx>, Vec<([u8; 32], Vec<u8>)>)>>)>,
    /// the batch whose expiry this node last pooled, and the fold step it did so at
    expire_sent: Option<(u64, u64)>,
    /// ⭐ Earn step 3 — this custodian's shares of EVERY pair's closed window `(lines, salt)` (pair order), handed in by the
    /// runtime before each tick from each pair's lane ([`DefiLane::close_lines`]): what pair 0's lane runs an EarnEpoch over.
    /// CACHE-ONLY: a copy of this custodian's own files' state, refreshed every tick; the book's close commitments decide.
    epoch_lines: Vec<Option<([Word; ba::CLOSE_LINES], [Fa4; 4])>>,
}

/// ⭐ THE BATCH'S SLOTS from its real orders and claims (oldest first) and covers to exactly `SLOTS` each, every cover's leg
/// proven from one of `books` (gathered on the tick thread), in the custody's random order (a cover's position names nothing).
/// ⭐ A-F114 — ONE switch-form cover leg (the builder's covers and a committee member's share alike): the leaf an output of
/// the window span's first record (`i` picks which), the production carrier over the span, the wrapper for the cover's
/// own `(nf, lc = P(P(leaf, nf), blind))` (the claim and order proofs' own cross-bind spelling). Returns the leg the cover
/// proof takes (no member carrier, no tuple) and `(nf bytes, lc, held wrapper bytes)`.
fn canon_cover_leg(w: &CanonCoverWindow, i: usize, nf: [u64; 8], blind: [u64; 8]) -> Option<(dcu::CoverLeg, ([u8; 32], crate::spend_frontier::Digest4, Vec<u8>))> {
    let made = w.recs.first()?;
    let leaf = *made.1.get(i % made.1.len().max(1))?;
    let nf_b = crate::spend_frontier::leaf_to_cm_bytes(nf);
    let c = usdm_decider::poseidon2_compress::compress;
    let lc = c(&c(&leaf, &nf), &blind);
    let mut car = crate::canon_carrier_core::CanonCarrier::starting_at(crate::canon_chain::to_lanes(&w.start_end), w.start_index);
    car.pending = vec![(crate::canon_chain::tag_lanes(&nf_b), crate::canon_chain::to_lanes(&leaf))];
    for (k, (tags, leaves)) in w.recs.iter().enumerate() {
        let idx = w.start_index + k as u64;
        car.absorb(idx, &crate::canon_chain::record(tags, leaves, idx)).ok()?;
    }
    let (proof, end) = car.spend(0, crate::canon_chain::to_lanes(&nf), crate::canon_chain::to_lanes(&blind)).ok()?;
    let held = postcard::to_allocvec(&vec![crate::nf_sparse::CanonAbsence { proof, end: crate::canon_chain::of_lanes(&end) }]).ok()?;
    Some(((leaf, Vec::new(), Vec::new(), lc), (nf_b, lc, held)))
}

/// ⭐ A-F114 — A COMMITTEE MEMBER'S SHARE OF A BATCH'S COVERS (audit 23:30): `k` covers (claims first, then orders) proven to
/// the window span `w` under this member's own `key`, with their wrappers. Submitted to the batch's intake as ordinary slots
/// (a cover is told from a real slot by nothing), so the builder proves only what the shares leave.
pub(crate) fn build_cover_share(
    book: &DefiBook,
    epoch: u64,
    pk: &crate::epoch_key::EpochPublicKey,
    k: usize,
    key: &[u8; 32],
    w: &CanonCoverWindow,
) -> Option<(Vec<db::DefiClaimTx>, Vec<db::DefiOrderTx>, Vec<([u8; 32], crate::spend_frontier::Digest4, Vec<u8>)>)> {
    let next = std::cell::Cell::new(0usize);
    let out: std::cell::RefCell<Vec<([u8; 32], crate::spend_frontier::Digest4, Vec<u8>)>> = std::cell::RefCell::new(Vec::new());
    let leg_for = |nf: [u64; 8], blind: [u64; 8]| -> Option<dcu::CoverLeg> {
        let i = next.get();
        next.set(i + 1);
        let (leg, held) = canon_cover_leg(w, i, nf, blind)?;
        out.borrow_mut().push(held);
        Some(leg)
    };
    let (mut claims, mut orders) = (Vec::new(), Vec::new());
    for j in 0..k {
        let kk = *blake3::Hasher::new_keyed(key).update(b"share").update(&(j as u64).to_le_bytes()).finalize().as_bytes();
        if j < k.div_ceil(2) {
            claims.push(dcu::cover_claim(book.pair, &leg_for, &kk)?);
        } else {
            orders.push(dcu::cover_order(book, epoch, pk, &leg_for, &kk)?);
        }
    }
    Some((claims, orders, out.into_inner()))
}

type CoverShare = (Vec<db::DefiClaimTx>, Vec<db::DefiOrderTx>, Vec<([u8; 32], crate::spend_frontier::Digest4, Vec<u8>)>);

pub(crate) fn build_slots(
    book: &DefiBook,
    epoch: u64,
    pk: &crate::epoch_key::EpochPublicKey,
    mut orders: Vec<db::DefiOrderTx>,
    mut claims: Vec<db::DefiClaimTx>,
    books: &[([u8; 32], crate::member_witness::MemberWitnessBook)],
    key: &[u8; 32],
    canon: Option<&CanonCoverWindow>,
) -> Option<(Vec<db::DefiSlotsTx>, Vec<([u8; 32], Vec<u8>)>)> {
    let next = std::cell::Cell::new(0usize);
    let wrappers: std::cell::RefCell<Vec<([u8; 32], Vec<u8>)>> = std::cell::RefCell::new(Vec::new());
    let leg_for = |nf: [u64; 8], blind: [u64; 8]| -> Option<dcu::CoverLeg> {
        let i = next.get();
        next.set(i + 1);
        // ⭐ A-F114 — UNDER THE CONSTANT CHAIN A COVER'S LEG IS ITS OWN WRAPPER, never a member leg: its leaf an output of
        // the window span's first record, its one-note list followed over the span by the production carrier
        // (`canon_carrier_core::CanonCarrier`), the wrapper bound to the cover's own `(nf, lc)` with
        // `lc = P(P(leaf, nf), blind)` (the claim and order proofs' own cross-bind spelling). The wrapper is held under the
        // cover's nullifier for the slots' publication. A cover mints 0 by its own proof; a cover that cannot be proven
        // gives no batch (the batch waits).
        // (decided by the window the tick thread passed, never this thread's switch: a test turns the switch on per thread)
        if let Some(w) = canon {
            let (leg, (nf_b, _, held)) = canon_cover_leg(w, i, nf, blind)?;
            wrappers.borrow_mut().push((nf_b, held));
            return Some(leg);
        }
        let (cm, mb) = books.get(i % books.len().max(1))?;
        let (carrier, tuple) = mb.carrier_for(cm, nf, blind, &[0u8; 32], &[0u8; 32]).ok()?;
        let mut tb = Vec::with_capacity(crate::member_transition::MEMBER_TUPLE_BYTES);
        crate::member_transition::write_tuple(&tuple, &mut tb);
        Some((crate::spend_frontier::note_leaf_of(cm), carrier, tb, tuple.leaf_commit))
    };
    while orders.len() < db::SLOTS {
        let k = *blake3::Hasher::new_keyed(key).update(b"order").update(&(orders.len() as u64).to_le_bytes()).finalize().as_bytes();
        orders.push(dcu::cover_order(book, epoch, pk, &leg_for, &k)?);
    }
    while claims.len() < db::SLOTS {
        let k = *blake3::Hasher::new_keyed(key).update(b"claim").update(&(claims.len() as u64).to_le_bytes()).finalize().as_bytes();
        claims.push(dcu::cover_claim(book.pair, &leg_for, &k)?);
    }
    let mut perm = blake3::Hasher::new_keyed(key).update(b"perm").finalize_xof();
    let mut shuffle = |len: usize| -> Vec<usize> {
        let mut idx: Vec<usize> = (0..len).collect();
        for i in (1..len).rev() {
            let mut b = [0u8; 8];
            perm.fill(&mut b);
            idx.swap(i, (u64::from_le_bytes(b) % (i as u64 + 1)) as usize);
        }
        idx
    };
    let po = shuffle(orders.len());
    let pc = shuffle(claims.len());
    let parts = db::DefiSlotsTx::parts(book.pair, book.batch, po.into_iter().map(|i| orders[i].clone()).collect(), pc.into_iter().map(|i| claims[i].clone()).collect())?;
    Some((parts, wrappers.into_inner()))
}

/// How many fold steps past a batch's close every custodian (not only its publisher) publishes the slots.
pub const SLOTS_FALLBACK_STEPS: u64 = 6;
/// Fold steps before a node pools an unlanded expiry again.
pub const EXPIRE_RESEND_STEPS: u64 = 8;

/// The most wallet slots a node holds for its custody lane before refusing more (a few batches' worth).
pub const DEFI_INTAKE_MAX: usize = 4 * db::SLOTS;


/// The relayed-message memory's bound.
pub const SEEN_MAX: usize = 1 << 16;

fn pair_key(batch: u64, lo: u32, hi: u32, ss_lo_hi: &[u8; 32], ss_hi_lo: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/br15-lane/pair-key/v1");
    h.update(&batch.to_le_bytes()).update(&lo.to_le_bytes()).update(&hi.to_le_bytes()).update(ss_lo_hi).update(ss_hi_lo);
    *h.finalize().as_bytes()
}
fn nonce(batch: u64, from: u32, to: u32, seq: u64) -> Vec<u8> {
    [batch.to_le_bytes().as_slice(), &from.to_le_bytes(), &to.to_le_bytes(), &seq.to_le_bytes()].concat()
}
fn seal_body(k: &[u8; 32], nonce: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut ks = vec![0u8; plain.len()];
    blake3::Hasher::new_keyed(k).update(b"stream").update(nonce).finalize_xof().fill(&mut ks);
    let mut out: Vec<u8> = plain.iter().zip(&ks).map(|(a, b)| a ^ b).collect();
    let tag = blake3::Hasher::new_keyed(k).update(b"tag").update(nonce).update(&out).finalize();
    out.extend_from_slice(&tag.as_bytes()[..TAG]);
    out
}
fn open_body(k: &[u8; 32], nonce: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let (body, tag) = sealed.split_at(sealed.len().checked_sub(TAG)?);
    let want = blake3::Hasher::new_keyed(k).update(b"tag").update(nonce).update(body).finalize();
    if want.as_bytes()[..TAG] != *tag {
        return None;
    }
    let mut ks = vec![0u8; body.len()];
    blake3::Hasher::new_keyed(k).update(b"stream").update(nonce).finalize_xof().fill(&mut ks);
    Some(body.iter().zip(&ks).map(|(a, b)| a ^ b).collect())
}
fn words(v: &[F255]) -> Vec<u8> {
    v.iter().flat_map(|f| f.0.iter().flat_map(|w| w.to_le_bytes())).collect()
}
fn unwords(b: &[u8]) -> Option<Vec<F255>> {
    if b.len() % 32 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 32);
    for c in b.chunks_exact(32) {
        let mut w = [0u64; 4];
        for (k, x) in w.iter_mut().enumerate() {
            *x = u64::from_le_bytes(c[8 * k..8 * k + 8].try_into().ok()?);
        }
        out.push(F255(w));
    }
    Some(out)
}
fn confirm_tag(k: &[u8; 32], batch: u64, from: u32, to: u32) -> [u8; TAG] {
    let h = blake3::Hasher::new_keyed(k).update(b"confirm").update(&nonce(batch, from, to, 0)).finalize();
    core::array::from_fn(|i| h.as_bytes()[i])
}
fn ack_tag(k: &[u8; 32], batch: u64, from: u32, to: u32, next: u64) -> [u8; TAG] {
    let h = blake3::Hasher::new_keyed(k).update(b"ack").update(&nonce(batch, from, to, next)).finalize();
    core::array::from_fn(|i| h.as_bytes()[i])
}
fn part_tag(k: &[u8; 32], batch: u64, from: u32, part: &[u8]) -> [u8; TAG] {
    let h = blake3::Hasher::new_keyed(k).update(b"part").update(&batch.to_le_bytes()).update(&from.to_le_bytes()).update(part).finalize();
    core::array::from_fn(|i| h.as_bytes()[i])
}

impl DefiLane {
    /// The lane of a custody node whose custody KEM pair is `kem`, keeping its file at `path` (`None`: nothing persisted —
    /// a test's lane).
    #[must_use]
    pub fn new(path: Option<std::path::PathBuf>, kem: Option<(Vec<u8>, Vec<u8>)>) -> Self {
        let file = match path.as_ref().map(|p| crate::keystore::read_key_file(p)) {
            // ONE object, ONE encoding (chain_object::decode_exact): a file with a tolerated tail is not this file
            Some(Ok(b)) => match crate::chain_object::decode_exact::<CustodyFile>(&b) {
                Some(f) => f,
                None => {
                    eprintln!("[defi-lane] ⛔ the custodian's file does not decode exactly; it recaptures from the launch and sits out until its state is the chain's");
                    CustodyFile::default()
                }
            },
            _ => CustodyFile::default(),
        };
        DefiLane {
            pair: 0,
            path,
            file,
            kem,
            me_index: None,
            run: None,
            early_hello: BTreeMap::new(),
            early: Vec::new(),
            seen: std::collections::HashSet::new(),
            departed: 0,
            handover_open_sent: None,
            handover_deal_sent: None,
            handover_accept_sent: None,
            pending_orders: Vec::new(),
            pending_claims: Vec::new(),
            slots_sent: None,
            slot_job: None,
            share_job: None,
            share_sent: None,
            wrapper_relay: Vec::new(),
            expire_sent: None,
            epoch_lines: Vec::new(),
        }
    }
    /// ⭐ Earn step 3 — this custodian's shares of its pair's closed window and their salt (`None` until it holds state).
    #[must_use]
    pub fn close_lines(&self) -> Option<([Word; ba::CLOSE_LINES], [Fa4; 4])> {
        self.file.me.as_ref().map(|s| (s.close, s.close_salt))
    }
    /// ⭐ Earn step 3 — every pair's closed-window shares of this custodian (pair order), from each pair's lane: pair 0's lane
    /// runs the EarnEpoch over them. Set by the runtime before each tick.
    pub fn set_epoch_lines(&mut self, lines: Vec<Option<([Word; ba::CLOSE_LINES], [Fa4; 4])>>) {
        self.epoch_lines = lines;
    }
    /// The lane of THIS node (its custody KEM pair, its file beside the custody book).
    #[must_use]
    pub fn for_node(pair: u8) -> Self {
        let path = crate::persist::state_dir().join(format!("defi-custody-{}-{pair}.bin", crate::persist::serving_port()));
        let mut l = Self::new(Some(path), crate::bridge::node_own_custody_kem());
        l.pair = pair;
        l
    }
    /// ⭐ Earn step 3 — THIS node's EarnEpoch lane (index `PAIRS`): its custody KEM pair, no file (it holds no batch state;
    /// every input is pair lanes' closed-window shares, handed over each tick by [`DefiLane::set_epoch_lines`]).
    #[must_use]
    pub fn for_epoch() -> Self {
        let mut l = Self::new(None, crate::bridge::node_own_custody_kem());
        l.pair = db::PAIRS;
        l
    }
    /// Test builds: a lane holding `me` already (a launch's captured state).
    #[cfg(test)]
    pub(crate) fn with_state(kem: (Vec<u8>, Vec<u8>), me: CustodianState) -> Self {
        let mut l = Self::new(None, Some(kem));
        l.file.me = Some(me);
        l
    }
    fn save(&self) {
        let Some(p) = self.path.as_ref() else { return };
        match postcard::to_allocvec(&self.file) {
            Ok(bytes) => {
                if let Err(e) = crate::keystore::write_key_file(p, &bytes) {
                    eprintln!("[defi-lane] ⛔ the custodian's file did not persist: {e}");
                }
            }
            Err(e) => eprintln!("[defi-lane] ⛔ the custodian's file did not encode: {e}"),
        }
    }

    /// ⭐ THE HANDOVER ROLE (spec §18.11), every tick before the batch's: open a handover when the bonded custody set differs
    /// from the roster; as an old custodian, deal (once); as a new one, capture the sub-shares the dealings carried, accept
    /// once every old custodian has dealt, and adopt the new state when the chain switches.
    fn handover_tick<H: DefiHost>(&mut self, host: &mut H, book: &DefiBook) {
        let Some((ek, dk)) = self.kem.clone() else { return };
        let me_old = book.eks.iter().position(|k| *k == ek);
        // adopt: the chain switched to a roster holding this custodian's acceptance
        if let (Some(i), Some(next)) = (me_old, self.file.handover_next.as_ref()) {
            if book.handover.is_none() && next.is_the_books(book, i) {
                self.file.me = self.file.handover_next.take();
                self.file.handover_subs.clear();
                self.save();
            }
        }
        let Some(h) = book.handover.as_ref() else {
            let bonded = host.bonded_custody();
            if me_old.is_some() && book.is_open() && !bonded.is_empty() && bonded != book.eks && self.handover_open_sent != Some(book.batch) {
                let t = crate::defi_handover::DefiHandoverTx::Open { pair: book.pair, batch: book.batch, new_eks: bonded };
                if host.publish_handover(&t) {
                    self.handover_open_sent = Some(book.batch);
                }
            }
            return;
        };
        if !h.frozen {
            return;
        }
        // as an old custodian: deal once
        if let (Some(i), Some(me)) = (me_old, self.file.me.as_ref()) {
            if h.subs.get(i).is_some_and(Option::is_none) && self.handover_deal_sent != Some(book.batch) {
                let key = dcu::custody_entropy().unwrap_or([0; 32]);
                if let Some(t) = crate::defi_handover::deal(book, me, u32::try_from(i).unwrap_or(u32::MAX), &key) {
                    if host.publish_handover(&t) {
                        self.handover_deal_sent = Some(book.batch);
                    }
                }
            }
        }
        // as a new custodian: accept once every old custodian has dealt and every sub-share is captured
        let Some(j) = h.new_eks.iter().position(|k| *k == ek) else { return };
        let _ = &dk;
        if h.dealt() && h.accepts.get(j).is_some_and(Option::is_none) && self.handover_accept_sent != Some(book.batch) {
            let mut subs: Vec<dcu::SubShare> = Vec::with_capacity(book.roster.len());
            for i in 0..book.roster.len() {
                match self.file.handover_subs.iter().find(|(f, _)| *f as usize == i) {
                    Some((_, st)) => subs.push(st.clone()),
                    None => return,
                }
            }
            let key = dcu::custody_entropy().unwrap_or([0; 32]);
            if let Some((t, next)) = crate::defi_handover::accept(book, u32::try_from(j).unwrap_or(u32::MAX), &subs, &key) {
                if host.publish_handover(&t) {
                    self.handover_accept_sent = Some(book.batch);
                    self.file.handover_next = Some(next);
                    self.save();
                }
            }
        }
    }

    /// ⭐ ONE TICK: take the blocks' events, start or advance this batch's run, return the gossip to send.
    pub fn tick<H: DefiHost>(&mut self, host: &mut H, now_ms: u64) -> Vec<DefiMpcMsg> {
        // ⭐ Earn step 3 — the EarnEpoch lane (index `PAIRS`) runs only the window's raise
        if self.pair == db::PAIRS {
            return self.epoch_tick(host, now_ms);
        }
        let book = host.book();
        let events = host.drain_defi_events();
        self.handover_capture(&events, &book);
        self.handover_tick(host, &book);
        // ⭐ A BATCH NO SETTLEMENT REACHED NEVER HOLDS THE POOL. One stopped custody run left a pool on its batch for good: the expiry door existed and nothing ever published to it (MEASURED 2026-11-05 on real nodes: the Monero pool on batch 3 at fold step 889, its window closed at 247, while the Bitcoin pool reached batch 25). Every node publishes it once the window passes, and again if it did not land; the fold takes one and refuses the rest.
        if book.is_open() && book.batch_expired(host.score(), host.chain_ms()) {
            let score = host.score();
            let due = self.expire_sent.map_or(true, |(b, at)| b != book.batch || score >= at.saturating_add(EXPIRE_RESEND_STEPS));
            if due {
                let leaves = book.orders.iter().map(|o| db::refund_leaf(&o.amount_commit, &o.limit_commit)).collect();
                if host.publish_expire(&db::DefiExpireTx { pair: book.pair, batch: book.batch, leaves }) {
                    self.expire_sent = Some((book.batch, score));
                }
            }
        }
        // ⭐ §18.12: this node's wallet's slots go to every custodian (this one included)
        let mut gossip: Vec<DefiMpcMsg> = Vec::new();
        for (claim, body) in host.drain_intake() {
            let m = DefiMpcMsg::Submit { claim, body };
            self.take_submission(&m);
            gossip.push(m);
        }
        if book.frozen() {
            return gossip;
        }
        if let Some((parts, ws)) = self.slots_due(host, &book) {
            // A-F114: the covers' wrappers are held first, so the slots' publication finds every slot's (`publish_defi_slots`)
            host.hold_wrappers(ws);
            // every part, each its own transaction (spec §18.12); the batch is this custodian's once all of them pooled
            if parts.iter().fold(true, |ok, t| host.publish_slots(t) && ok) {
                self.slots_sent = Some(book.batch);
            }
        }
        let ek = self.kem.as_ref().map(|k| k.0.clone());
        self.me_index = ek.and_then(|ek| book.eks.iter().position(|k| *k == ek)).and_then(|i| u32::try_from(i).ok()).filter(|_| book.is_open());
        let Some(me) = self.me_index else {
            return gossip;
        };
        if crate::canon_chain::canon_live() {
            self.cover_share_tick(host, &book, me, &mut gossip);
        }
        self.absorb(events, &book, me);
        let mut out = gossip;
        let Some(state) = self.file.me.clone() else { return out };
        if !state.is_the_books(&book, me as usize) {
            // this custodian's shares are not the chain's (its pending state not yet applied, or lost): it sits out
            return out;
        }
        if self.run.as_ref().is_some_and(|r| r.batch != book.batch) {
            self.run = None;
        }
        // the run starts once the batch's slots have applied (spec §18.12: the slots ARE the batch's orders)
        if self.run.is_none() && book.slotted {
            self.begin(&book, me);
        }
        if !self.drive(host, &book, me, Some(state), now_ms, &mut out) {
            return out;
        }
        if let Some(t) = self.settlement(&book) {
            // ⭐ spec §18.11: a settlement past one transaction travels as chunks — every chunk but the last at once, the last
            // (the one that closes the batch and carries its leaves) once this node's book holds all the others
            let Some(mut chunks) = t.chunks(SETTLE_CHUNK_BYTES) else {
                eprintln!("[defi-lane] ⛔ batch {}: one custodian's part does not fit a transaction (the batch expires and refunds)", t.batch);
                return out;
            };
            let last = chunks.pop();
            let chunks_out = self.run.as_ref().is_some_and(|r| r.chunks_out);
            if !chunks_out && chunks.iter().all(|c| host.publish_settle(c)) {
                if let Some(r) = self.run.as_mut() {
                    r.chunks_out = true;
                }
            }
            if let Some(last) = last {
                let header = last.header();
                let held = (0..last.first as usize).all(|k| book.pending.get(k).and_then(Option::as_ref).is_some_and(|h| h.header == header));
                if held && self.run.as_ref().is_some_and(|r| r.chunks_out || last.first == 0) && host.publish_settle(&last) {
                    if let Some(r) = self.run.as_mut() {
                        r.published = true;
                    }
                }
            }
        }
        out
    }

    /// ⭐ THE RUN'S DRIVE, a batch's or an EarnEpoch's alike: what arrived early, the handshake (re-sent until every peer
    /// confirmed), the engine's start, the confirmations a peer lost, and the pump. `false` while the handshake waits (the
    /// caller publishes nothing yet).
    fn drive<H: DefiHost>(&mut self, host: &H, book: &DefiBook, me: u32, state: Option<CustodianState>, now_ms: u64, out: &mut Vec<DefiMpcMsg>) -> bool {
        let need = book.roster.len().saturating_sub(1);
        if self.run.is_some() && !self.early.is_empty() {
            // replay what arrived before it could be placed (a confirmation before its handshake, engine messages before the
            // engine started); what still cannot be placed is kept again
            for m in std::mem::take(&mut self.early) {
                self.on_msg(&m);
            }
        }
        let Some(run) = self.run.as_mut() else { return false };
        if run.keys.len() < need || !run.started {
            let resend = run.hello_sent_ms == 0 || now_ms.saturating_sub(run.hello_sent_ms) >= HELLO_RESEND_MS;
            if resend {
                run.hello_sent_ms = now_ms.max(1);
                out.push(DefiMpcMsg::Hello { batch: run.batch, from: me, cts: run.cts.clone(), copy: run.copies });
                run.copies = run.copies.wrapping_add(1);
            }
            for (j, cs) in run.cand.iter_mut() {
                for (k, sent) in cs.iter_mut() {
                    if !*sent || resend {
                        *sent = true;
                        out.push(DefiMpcMsg::Confirm { batch: run.batch, from: me, to: *j, tag: confirm_tag(k, run.batch, me, *j) });
                    }
                }
            }
            if run.keys.len() < need {
                return false;
            }
            self.start_engine(host, book, me, state);
            for m in std::mem::take(&mut self.early) {
                self.on_msg(&m);
            }
        }
        // a peer still handshaking after this custodian confirmed its key lost that confirmation: send it again
        if let Some(run) = self.run.as_mut() {
            for (j, (due, last)) in run.reconfirm.iter_mut() {
                let Some(k) = run.keys.get(j) else { continue };
                if *due && now_ms.saturating_sub(*last) >= HELLO_RESEND_MS {
                    *due = false;
                    *last = now_ms;
                    out.push(DefiMpcMsg::Confirm { batch: run.batch, from: me, to: *j, tag: confirm_tag(k, run.batch, me, *j) });
                }
            }
        }
        out.extend(self.pump(me, now_ms));
        true
    }

    /// ⭐⭐ EARN STEP 3 — THE EARNEPOCH LANE's tick (lane index `PAIRS`: its own run slot, so an EarnEpoch never waits on a
    /// pair's batch run, nor a batch on it): once every pair's book has closed a window past the common raise
    /// ([`epoch_due`]), this custodian (by its key's place in the roster) runs [`dcu::run_epoch_party`] with the others over
    /// every pair's closed lines the runtime handed it ([`DefiLane::set_epoch_lines`]), and publishes the EarnEpoch — its
    /// non-closing chunks at once, the closing one once pair 0's book holds the others. A run whose raise folded (or whose
    /// window another custody set raised) is dropped. Nothing here moves state: the fold applies the object.
    /// SAFE AT SCALE: one run per window; its messages and rounds are the rate's fixed search, whatever the users.
    fn epoch_tick<H: DefiHost>(&mut self, host: &mut H, now_ms: u64) -> Vec<DefiMpcMsg> {
        let books = host.books();
        let mut out = Vec::new();
        let Some(b0) = books.first().cloned() else { return out };
        let ek = self.kem.as_ref().map(|k| k.0.clone());
        self.me_index = ek.and_then(|ek| b0.eks.iter().position(|k| *k == ek)).and_then(|i| u32::try_from(i).ok()).filter(|_| b0.is_open());
        let Some(me) = self.me_index else { return out };
        let due = epoch_due(&books);
        if self.run.as_ref().is_some_and(|r| r.epoch != due) {
            self.run = None;
        }
        let lines_held = self.epoch_lines.len() == books.len() && self.epoch_lines.iter().all(Option::is_some);
        if self.run.is_none() {
            match due {
                Some(raise) if lines_held => self.begin_epoch(&b0, me, raise),
                _ => return out,
            }
        }
        // the engine takes no batch state: the closed lines ride `epoch_lines`
        if !self.drive(host, &b0, me, None, now_ms, &mut out) {
            return out;
        }
        if let Some(t) = self.earn_epoch(b0.roster.len()) {
            let Some(mut chunks) = t.chunks(SETTLE_CHUNK_BYTES) else {
                eprintln!("[defi-lane] ⛔ EarnEpoch {}: one custodian's part does not fit a transaction (the window waits for the next run)", t.raise);
                return out;
            };
            let last = chunks.pop();
            let chunks_out = self.run.as_ref().is_some_and(|r| r.chunks_out);
            if !chunks_out && chunks.iter().all(|c| host.publish_epoch(c)) {
                if let Some(r) = self.run.as_mut() {
                    r.chunks_out = true;
                }
            }
            if let Some(last) = last {
                let header = last.header();
                // CHAIN-CARRIES-REVIEWED: pair 0's book state, filled only by the folded chunks the blocks carried
                let held = (0..last.first as usize).all(|k| b0.epoch_pending.get(k).and_then(Option::as_ref).is_some_and(|h| h.header == header));
                if held && self.run.as_ref().is_some_and(|r| r.chunks_out || last.first == 0) && host.publish_epoch(&last) {
                    if let Some(r) = self.run.as_mut() {
                        r.published = true;
                    }
                }
            }
        }
        out
    }

    /// As a new custodian of an open handover: capture this custodian's sub-share from each dealing the blocks carried (opened
    /// with its own key, checked against the dealing's commitment) — a witness captured at arrival (AGENTS.md §6).
    fn handover_capture(&mut self, events: &[DefiEvent], book: &DefiBook) {
        let (Some((ek, dk)), Some(h)) = (self.kem.as_ref(), book.handover.as_ref()) else { return };
        let Some(j) = h.new_eks.iter().position(|k| k == ek) else { return };
        let mut dirty = false;
        for ev in events {
            if let DefiEvent::HandoverDeal { batch, from, sealed } = ev {
                let Some(subs) = h.subs.get(*from as usize).and_then(Option::as_ref) else { continue };
                let probe = crate::defi_handover::DefiHandoverTx::Deal { pair: self.pair, batch: *batch, from: *from, subs: subs.clone(), sealed: sealed.clone(), proof: Vec::new() };
                if let Some(st) = crate::defi_handover::capture(dk, j, &probe) {
                    if !self.file.handover_subs.iter().any(|(f, _)| f == from) {
                        self.file.handover_subs.push((*from, st));
                        dirty = true;
                    }
                }
            }
        }
        if dirty {
            self.save();
        }
    }

    fn absorb(&mut self, events: Vec<DefiEvent>, book: &DefiBook, me: u32) {
        let mut dirty = false;
        if self.file.me.is_none() {
            // the genesis launch: this custodian's pool shares, sealed to its key in the canonical bytes
            let launch = crate::defi_launch::canonical_bytes().and_then(|b| crate::defi_launch::DefiLaunch::decode(&b));
            if let (Some(l), Some((_, dk))) = (launch, self.kem.as_ref()) {
                self.file.me = l.capture(dk, self.pair, me as usize);
                dirty |= self.file.me.is_some();
            }
        }
        for ev in events {
            match ev {
                // ⭐⭐ THE FILE IS A CACHE OF WHAT THE CHAIN SAID, SO A REPEAT OF IT CHANGES NOTHING. A fold re-applies the objects a
                // re-fold walks again, and every re-application pushes its event again (`defi_batch` fold door), so the same
                // `Closed` and `Order` arrive more than once and in a new order. MEASURED 2026-11-09 (launch_trade.py round 18, real
                // nodes): the XMR buy's order reached batch 9's book, a re-fold of two records on one custodian replayed batch 8's
                // close, that custodian started batch 9 holding no share of the order, both custodians named it in the complaint set,
                // and 1 XMR came back refunded. Applied as an idempotent, batch-monotone log (BORROWED: an event-sourced consumer
                // applying each fact once by its key — Kafka's idempotent consumer, Ethereum's STF over a replayed block): an event
                // for a batch this file has moved past is a replay and is ignored; an order already filed is matched by its own
                // sealed bytes, never appended twice, and a re-fold that renumbered it moves its index.
                DefiEvent::Order { batch, index, epoch, epoch_ct, sealed } => {
                    let Some(mine) = sealed.get(me as usize) else { continue };
                    if batch < self.file.batch {
                        continue;
                    }
                    if batch > self.file.batch + 1 {
                        // this file missed a close (its lane was down): the batch the chain names is the open one
                        self.file.batch = batch;
                        self.file.orders.clear();
                        self.file.queued.clear();
                    }
                    // an order of the next batch is queued while this one clears (spec §18.11)
                    let list = if batch == self.file.batch + 1 { &mut self.file.queued } else { &mut self.file.orders };
                    dirty |= file_order(list, (index, epoch, epoch_ct, mine.clone()));
                }
                DefiEvent::HandoverDeal { .. } => {}
                DefiEvent::Closed { batch } => {
                    if batch < self.file.batch {
                        // a replay of a close this file already applied: its orders were moved on then
                        continue;
                    }
                    if let Some((b, st)) = self.file.next.take() {
                        if b == batch && st.is_the_books(book, me as usize) {
                            self.file.me = Some(st);
                        }
                    }
                    if batch == self.file.batch {
                        self.file.orders = std::mem::take(&mut self.file.queued);
                    } else {
                        // a close of a batch past this file's (a missed close): nothing it holds is the next batch's
                        self.file.orders.clear();
                        self.file.queued.clear();
                    }
                    self.file.batch = batch + 1;
                    dirty = true;
                }
            }
        }
        if dirty {
            self.save();
        }
    }

    fn begin(&mut self, book: &DefiBook, me: u32) {
        self.begin_run(book, me, book.batch, None);
    }

    /// ⭐ Earn step 3 — pair 0's lane begins the EarnEpoch completing raise `raise` (run id [`epoch_run_id`]): the same
    /// handshake, links and engine messages as a batch's run, over its own keys.
    fn begin_epoch(&mut self, book: &DefiBook, me: u32, raise: u64) {
        self.begin_run(book, me, epoch_run_id(raise), Some(raise));
    }

    fn begin_run(&mut self, book: &DefiBook, me: u32, run_id: u64, epoch: Option<u64>) {
        let mut ss_to = BTreeMap::new();
        let mut cts = Vec::new();
        for (j, ek) in book.eks.iter().enumerate() {
            let j = j as u32;
            if j == me {
                continue;
            }
            let Some((ss, ct)) = crate::pqkem::encapsulate(ek) else { return };
            let Ok(ss) = <[u8; 32]>::try_from(ss.as_slice()) else { return };
            ss_to.insert(j, ss);
            cts.push((j, ct));
        }
        self.run = Some(Run {
            batch: run_id,
            ss_to,
            cts,
            hello_sent_ms: 0,
            cand: BTreeMap::new(),
            keys: BTreeMap::new(),
            reconfirm: BTreeMap::new(),
            started: false,
            out_rx: None,
            in_tx: BTreeMap::new(),
            next_in: BTreeMap::new(),
            held_in: BTreeMap::new(),
            seq_out: BTreeMap::new(),
            unacked: BTreeMap::new(),
            my_part: None,
            timer_ms: None,
            rto: Rto::new(),
            copies: 0,
            ack_due: false,
            result: None,
            parts: BTreeMap::new(),
            agreed: None,
            epoch,
            eparts: BTreeMap::new(),
            eagreed: None,
            published: false,
            chunks_out: false,
            stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            started_ms: 0,
            placed: 0,
            sent_first: (0, 0),
            sent_again: (0, 0),
            part_sent: (0, 0),
            sent_other: (0, 0),
            queue_wait: (0, 0),
            rtt: (0, 0),
            heard: (0, 0, 0),
        });
        let early: Vec<((u64, u32), Vec<u8>)> = std::mem::take(&mut self.early_hello).into_iter().collect();
        for ((b, from), ct) in early {
            if b == run_id {
                self.accept_hello(me, from, &ct);
            }
        }
    }

    fn accept_hello(&mut self, me: u32, from: u32, ct: &[u8]) {
        let (Some(run), Some((_, dk))) = (self.run.as_mut(), self.kem.as_ref()) else { return };
        let Some(ss_from) = crate::pqkem::decapsulate(ct, dk).and_then(|s| <[u8; 32]>::try_from(s.as_slice()).ok()) else { return };
        let Some(ss_mine) = run.ss_to.get(&from) else { return };
        let k = if me < from { pair_key(run.batch, me, from, ss_mine, &ss_from) } else { pair_key(run.batch, from, me, &ss_from, ss_mine) };
        // a CANDIDATE: the peer's confirmation under it fixes it (a forger's candidate is never confirmed)
        let c = run.cand.entry(from).or_default();
        if !c.iter().any(|(x, _)| *x == k) && c.len() < MAX_CANDIDATES {
            c.push((k, false));
        }
    }

    fn start_engine<H: DefiHost>(&mut self, host: &H, book: &DefiBook, me: u32, state: Option<CustodianState>) {
        let Some((_, dk)) = self.kem.clone() else { return };
        let Some(key) = dcu::custody_entropy() else {
            eprintln!("[defi-lane] ⛔ no entropy: this custodian sits batch {} out (it expires and refunds)", book.batch);
            return;
        };
        let n = book.roster.len();
        // ⭐ Earn step 3 — an EarnEpoch run: the rate engine over every pair's book and this custodian's closed lines
        if let Some(raise) = self.run.as_ref().and_then(|r| r.epoch) {
            let books = host.books();
            let Some(lines) = self.epoch_lines.iter().cloned().collect::<Option<Vec<_>>>() else {
                eprintln!("[defi-lane] ⛔ the EarnEpoch of raise {raise}: this custodian does not hold every pair's closed window (it sits out)");
                return;
            };
            let Some(run) = self.run.as_mut() else { return };
            let comm = Self::link(run, me, n);
            run.started = true;
            run.started_ms = unix_ms();
            run.result = Some(std::thread::spawn(move || {
                let mut p = Party::new(comm, &key);
                dcu::run_epoch_party(&mut p, &books, &lines, raise, &dcu::AUDIT_GATE).map(RunOut::Epoch)
            }));
            return;
        }
        // this custodian's share of each order, opened with its key and the order's epoch key (`None`: a complaint)
        let mut mine: Vec<Option<OrderShare>> = vec![None; book.orders.len()];
        // ⭐ A SHARE IS TIED TO ITS ORDER BY THE ORDER'S OWN COMMITMENT, never by the index it was filed at: the order whose
        // `share_commits[me]` the opened share commits to is its order (the index the file names first, then any other the book
        // holds — a re-fold may renumber a batch's slots). What could not be opened is said with its reason, so a complaint names
        // its cause on the custodian that made it.
        let (mut no_key, mut unopened, mut unmatched) = (0usize, 0usize, 0usize);
        if self.file.batch == book.batch {
            for (index, epoch, epoch_ct, sealed) in &self.file.orders {
                let Some(k) = host.epoch_keys(*epoch).and_then(|(pk, sk)| crate::epoch_key::decapsulate(&pk, &sk, epoch_ct)) else {
                    no_key += 1;
                    continue;
                };
                let Some(s) = dcu::open_epoch_order_share(&dk, &k, me as usize, sealed) else {
                    unopened += 1;
                    continue;
                };
                let names = |k: usize| book.orders.get(k).and_then(|bo| bo.share_commits.get(me as usize)) == Some(&db::order_commit(&s.0, &s.1));
                let at = std::iter::once(*index as usize).chain(0..book.orders.len()).find(|&k| mine.get(k).is_some_and(Option::is_none) && names(k));
                match at {
                    Some(k) => mine[k] = Some(s),
                    None => unmatched += 1,
                }
            }
        }
        let missing = mine.iter().filter(|s| s.is_none()).count();
        if missing > 0 {
            // DIGITAL-CASH-PRIVACY-REVIEWED: failure counts only, on the custodian that complains — the complaint set itself is public in
            // the batch's settlement (`DefiSettleTx::excluded`); no order, share, amount or owner is named.
            eprintln!(
                "[defi-lane] ⛔ batch {}: this custodian holds no share of {missing} of the book's orders — its file names batch {} \
                 ({} filed); {no_key} under an epoch key it does not hold, {unopened} that do not open with its key, {unmatched} that \
                 commit to no order of the book; they refund as the complaint set",
                book.batch,
                self.file.batch,
                self.file.orders.len()
            );
        }
        // a batch run is this custodian's own state's (an EarnEpoch run took the branch above)
        let Some(state) = state else { return };
        let Some(run) = self.run.as_mut() else { return };
        let comm = Self::link(run, me, n);
        let book = book.clone();
        run.started = true;
        run.started_ms = unix_ms();
        run.result = Some(std::thread::spawn(move || {
            let mut p = Party::new(comm, &key);
            dcu::run_party(&mut p, &book, &state, &mine, &dcu::AUDIT_GATE).map(RunOut::Batch)
        }));
    }

    /// A run's links to the engine: its outbox, each peer's inbox, its own loopback.
    fn link(run: &mut Run, me: u32, n: usize) -> LaneComm {
        let (out_tx, out_rx) = std::sync::mpsc::channel();
        let (self_tx, self_rx) = std::sync::mpsc::channel();
        let mut self_rx = Some(self_rx);
        let mut inbox = Vec::with_capacity(n);
        for j in 0..n as u32 {
            if j == me {
                inbox.push(self_rx.take().unwrap_or_else(|| std::sync::mpsc::channel().1));
            } else {
                let (tx, rx) = std::sync::mpsc::channel();
                run.in_tx.insert(j, tx);
                inbox.push(rx);
            }
        }
        run.out_rx = Some(out_rx);
        LaneComm { me: me as usize, n, out: out_tx, inbox, self_tx, stop: run.stop.clone() }
    }

    /// The engine's outgoing messages as gossip; its finished result as this custodian's part; what a peer has not
    /// acknowledged, again; and this custodian's acknowledgements.
    fn pump(&mut self, me: u32, now_ms: u64) -> Vec<DefiMpcMsg> {
        let mut out = Vec::new();
        let departed = self.departed;
        let Some(run) = self.run.as_mut() else { return out };
        // ⭐ §5.1 — A COPY IS TIMED FROM WHEN IT LEFT THIS NODE, never from when it was queued. MEASURED 2026-11-10 on real
        // nodes (round 20, the DeFi rig): this lane's class carried 151 MB through one node's link for four custody runs whose
        // engine payload is 22-45 MB, the queue held 300-600 cells for the whole run, and the BTC pool's batch 1 expired with
        // its custodians' runs at 1,370 s and 2,476 s of 2,700 s. The timer started at queueing, so a ~270-cell message that
        // waited 20-40 s behind this node's own backlog was sent again before its first copy left, and every copy (new bytes:
        // its `copy` number) was relayed again by every node. The timer starts when a copy leaves, if it is not running.
        // (Resolved BEFORE this pump sends anything: a copy it hands over gets its mark from the runtime after this tick.)
        let mut left_now: Option<u64> = None;
        for s in run.unacked.values_mut().chain(run.my_part.as_mut()) {
            if let Some(t) = s.resolve(departed, now_ms) {
                if !s.resent && matches!(s.msg, DefiMpcMsg::Data { .. }) {
                    run.queue_wait.0 += t.saturating_sub(s.copy_ms);
                    run.queue_wait.1 += 1;
                }
                left_now = Some(left_now.map_or(t, |l| l.max(t)));
            }
        }
        if run.timer_ms.is_none() {
            run.timer_ms = left_now;
        }
        if let Some(rx) = run.out_rx.as_ref() {
            while let Ok((to, msg)) = rx.try_recv() {
                let to = to as u32;
                let Some(k) = run.keys.get(&to) else { continue };
                let seq = run.seq_out.entry(to).or_insert(0);
                let body = seal_body(k, &nonce(run.batch, me, to, *seq), &words(&msg));
                let m = DefiMpcMsg::Data { batch: run.batch, from: me, to, seq: *seq, body, copy: 0 };
                run.unacked.insert((to, *seq), Sent::new(m.clone(), now_ms));
                out.push(m);
                *seq += 1;
            }
        }
        // a lost copy is sent again; the receiver places a repeat exactly once (`next_in`), so a re-send never doubles a step.
        // TCP's shape: only the EARLIEST unacknowledged message to each peer is re-sent (the receiver places in order, so a
        // later one cannot be placed before it), and the wait doubles while nothing is acknowledged. Re-sending every
        // unacknowledged message every 5 s filled the cell channel these large messages share with payouts and blocks, which
        // delayed the very acknowledgements that would stop them (MEASURED 2026-11-08, real nodes: the outbound queue at
        // 4,078 of 4,096, 32,214 messages of the class refused at the bound, a batch's run 1,261 s for 26 messages).
        // The timer runs while a copy that LEFT is unacknowledged or this custodian's part is out (§5.1–5.6): it fires a
        // re-send when the measured wait has passed since it started, backs off, and starts again when the new copy leaves.
        // A message whose latest copy is still in this node's queue is never sent again (TCP never retransmits a segment it
        // has not yet transmitted).
        let resend = run.timer_ms.is_some_and(|t| now_ms.saturating_sub(t) >= run.rto.rto_ms);
        if resend {
            let c = run.copies;
            let mut sent_any = false;
            let mut first_to: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
            for ((to, _), s) in run.unacked.iter_mut() {
                if !first_to.insert(*to) {
                    continue; // only the earliest unacknowledged message per peer (the map is ordered by (to, seq))
                }
                if !matches!(s.leave, Leave::Left(_)) {
                    continue; // its latest copy has not left this node yet
                }
                if let DefiMpcMsg::Data { copy, .. } = &mut s.msg {
                    *copy = c;
                }
                s.resent = true;
                s.copy_ms = now_ms;
                s.leave = Leave::Handed;
                out.push(s.msg.clone());
                sent_any = true;
            }
            if let Some(s) = run.my_part.as_mut().filter(|s| matches!(s.leave, Leave::Left(_))) {
                if let DefiMpcMsg::Part { copy, .. } = &mut s.msg {
                    *copy = c;
                }
                s.copy_ms = now_ms;
                s.leave = Leave::Handed;
                out.push(s.msg.clone());
                sent_any = true;
            }
            if sent_any {
                run.copies = run.copies.wrapping_add(1);
                run.rto.backoff(); // §5.5
            }
            run.timer_ms = None; // §5.6: started again when the copy leaves
        }
        if resend || run.ack_due {
            run.ack_due = false;
            let acks: Vec<DefiMpcMsg> = run
                .next_in
                .iter()
                .filter_map(|(j, next)| {
                    let k = run.keys.get(j)?;
                    Some(DefiMpcMsg::Ack { batch: run.batch, from: me, to: *j, next: *next, tag: ack_tag(k, run.batch, me, *j, *next), copy: run.copies })
                })
                .collect();
            out.extend(acks);
        }
        if run.result.as_ref().is_some_and(std::thread::JoinHandle::is_finished) {
            match run.result.take().map(|h| h.join().unwrap_or(Err("the engine panicked"))) {
                Some(Ok(RunOut::Batch(po))) => {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: the public batch number and a duration, to this node's own log.
                    eprintln!("[defi-lane] batch {}: this custodian's run finished in {} s — {}", run.batch, unix_ms().saturating_sub(run.started_ms) / 1000, run.traffic());
                    run.agreed = Some((po.tick, po.sells, po.j_min, po.excluded.clone(), po.phase1.clone()));
                    if let Ok(bytes) = postcard::to_allocvec(&po.part) {
                        let tags = run.keys.iter().map(|(j, k)| (*j, part_tag(k, run.batch, me, &bytes))).collect();
                        let part = DefiMpcMsg::Part { batch: run.batch, from: me, part: bytes, tags, copy: 0 };
                        run.my_part = Some(Sent::new(part.clone(), now_ms));
                        out.push(part);
                    }
                    run.parts.insert(me, po.part);
                    self.file.next = Some((run.batch, po.next));
                    self.save();
                }
                Some(Ok(RunOut::Epoch(eo))) => {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: the public raise number, the public rate it opens and a duration, to
                    // this node's own log. The EarnEpoch moves no custodian state: nothing is saved.
                    eprintln!("[defi-lane] EarnEpoch {}: this custodian's run finished in {} s at rate {} — {}", run.epoch.unwrap_or(0), unix_ms().saturating_sub(run.started_ms) / 1000, eo.dg, run.traffic());
                    run.eagreed = Some((eo.dg, eo.phase1.clone()));
                    if let Ok(bytes) = postcard::to_allocvec(&eo.part) {
                        let tags = run.keys.iter().map(|(j, k)| (*j, part_tag(k, run.batch, me, &bytes))).collect();
                        let part = DefiMpcMsg::Part { batch: run.batch, from: me, part: bytes, tags, copy: 0 };
                        run.my_part = Some(Sent::new(part.clone(), now_ms));
                        out.push(part);
                    }
                    run.eparts.insert(me, eo.part);
                }
                Some(Err(why)) => eprintln!("[defi-lane] this custodian's run of batch {} stopped: {why} (the batch expires and refunds)", run.batch),
                None => {}
            }
        }
        out
    }

    /// ⭐ Earn step 3 — the EarnEpoch, once every custodian's part is here (every custodian builds the same bytes). It is the
    /// chain object this run PUBLISHES — CHAIN-OBJECT: `DefiEarnEpochTx`, which every node's fold verifies against its own
    /// books before anything moves; nothing here changes state.
    fn earn_epoch(&self, n: usize) -> Option<db::DefiEarnEpochTx> {
        let run = self.run.as_ref()?;
        let raise = run.epoch?;
        let (dg, phase1) = run.eagreed.clone()?;
        if run.published || run.eparts.len() != n {
            return None;
        }
        Some(db::DefiEarnEpochTx { raise, dg, phase1, first: 0, parts: run.eparts.values().cloned().collect() })
    }

    /// The settlement, once every custodian's part is here (every custodian builds the same bytes).
    /// CHAIN-OBJECT: the `DefiSettleTx` this run publishes; an EarnEpoch run publishes none.
    fn settlement(&self, book: &DefiBook) -> Option<DefiSettleTx> {
        let run = self.run.as_ref()?;
        if run.epoch.is_some() {
            return None;
        }
        let (tick, sells, j_min, excluded, phase1) = run.agreed.clone()?;
        if run.published || run.parts.len() != book.roster.len() {
            return None;
        }
        // CHAIN-OBJECT: the leaves of the DefiSettleTx built here, which every node re-derives at its fold
        let leaves = db::settle_leaves(book, tick, j_min, sells, &excluded);
        Some(DefiSettleTx { pair: book.pair, batch: run.batch, tick, sells, j_min, excluded, phase1, first: 0, parts: run.parts.values().cloned().collect(), leaves })
    }

    /// ⭐ A LANE MESSAGE FROM THE WIRE: placed if it is for this custodian; `true` when it is new here (relay it once).
    pub fn on_wire(&mut self, bytes: &[u8]) -> bool {
        let Some(m) = DefiMpcMsg::decode(bytes) else { return false };
        if self.seen.len() >= SEEN_MAX {
            self.seen.clear();
        }
        if !self.seen.insert(*blake3::hash(bytes).as_bytes()) {
            if let Some(r) = self.run.as_mut() {
                r.heard.2 += 1;
            }
            return false;
        }
        if let Some(r) = self.run.as_mut() {
            r.heard.0 += 1;
            r.heard.1 += bytes.len() as u64;
        }
        self.on_msg(&m);
        true
    }

    /// The cell channel's departure count, set by the runtime before each [`Self::tick`] (`CellChannel::departed_net`).
    pub fn set_departed(&mut self, departed: i64) {
        self.departed = departed;
    }

    /// ⭐ WHAT THE CELL CHANNEL DID WITH A MESSAGE THIS LANE HANDED IT (the runtime calls this for every message [`Self::tick`]
    /// returned, with its encoding): queued at departure mark `mark`, or refused at the channel's bound (`None` — it counts
    /// as gone at once, so the re-send timer covers it exactly as it covers a lost copy).
    ///
    /// Its bytes are THIS node's own, so a copy heard back from a peer is never relayed again (Bitcoin's shape: a node never
    /// relays its own inventory back to the network). MEASURED 2026-11-10 by code and run 20: a node never recorded its own
    /// lane messages as seen, so on two nodes every message crossed the link three times — sent, relayed back by its
    /// addressee, relayed again by its sender as new.
    pub fn queued(&mut self, m: &DefiMpcMsg, bytes: &[u8], mark: Option<i64>) {
        if self.seen.len() >= SEEN_MAX {
            self.seen.clear();
        }
        self.seen.insert(*blake3::hash(bytes).as_bytes());
        let Some(run) = self.run.as_mut() else { return };
        let len = bytes.len() as u64;
        // a refused copy never entered the queue: the lowest mark, gone at the next look
        let leave = Leave::At(mark.unwrap_or(i64::MIN));
        let count = |c: &mut (u64, u64)| {
            c.0 += 1;
            c.1 += len;
        };
        match m {
            DefiMpcMsg::Data { batch, to, seq, copy, .. } if *batch == run.batch => {
                let Some(s) = run.unacked.get_mut(&(*to, *seq)).filter(|s| matches!(s.msg, DefiMpcMsg::Data { copy: c, .. } if c == *copy)) else {
                    return;
                };
                if s.leave == Leave::Handed {
                    s.leave = leave;
                }
                if s.resent {
                    count(&mut run.sent_again);
                } else {
                    count(&mut run.sent_first);
                }
            }
            DefiMpcMsg::Part { batch, copy, .. } if *batch == run.batch => {
                let Some(s) = run.my_part.as_mut().filter(|s| matches!(s.msg, DefiMpcMsg::Part { copy: c, .. } if c == *copy)) else {
                    return;
                };
                if s.leave == Leave::Handed {
                    s.leave = leave;
                }
                count(&mut run.part_sent);
            }
            _ => count(&mut run.sent_other),
        }
    }

    /// Keep a message that cannot be placed yet (bounded; a repeated copy is kept once).
    fn keep(&mut self, m: &DefiMpcMsg) {
        if self.early.len() < 64 * db::MAX_ROSTER && !self.early.contains(m) {
            self.early.push(m.clone());
        }
    }

    /// ⭐ A GOSSIPED LANE MESSAGE: a handshake to this custodian, an engine message to it, a peer's part. Nothing it says is
    /// believed without its tag under the pair key (a handshake is an encapsulation only this custodian can open).
    /// ⭐ spec §18.12 — keep a buyer's slot for the next batch's slots (once per nullifier; the oldest dropped past the bound).
    /// ⭐ A-F114 — A COMMITTEE MEMBER'S COVER SHARE (audit 23:30): while a batch takes its slots, a member that is NOT the
    /// batch's builder (`batch mod n`) proves `⌈2·SLOTS / n⌉` covers off the tick thread, then submits them as ordinary slots
    /// to every custodian (`DefiMpcMsg::Submit`) and relays their wrappers (`wrapper_relay` → `WireMsg::CanonWrappers`),
    /// holding them itself too. One share a batch. SAFE AT SCALE: a member's work is a constant share of a fixed-size batch.
    /// A share that never arrives costs nothing but time: the builder proves the covers it lacks (`build_slots`).
    fn cover_share_tick<H: DefiHost>(&mut self, host: &mut H, book: &DefiBook, me: u32, out: &mut Vec<DefiMpcMsg>) {
        let n = book.roster.len() as u64;
        if n < 2 || book.batch % n == u64::from(me) || !book.is_open() || book.slotted || book.batch_closed(host.score()) {
            return;
        }
        if let Some((b, rx)) = self.share_job.as_ref() {
            if *b != book.batch {
                self.share_job = None;
            } else {
                match rx.try_recv() {
                    Ok(r) => {
                        self.share_job = None;
                        let Some((claims, orders, ws)) = r else { return };
                        for (claim, body) in claims.iter().map(|c| (true, c.encode())).chain(orders.iter().map(|o| (false, o.encode()))) {
                            if let Some(body) = body {
                                out.push(DefiMpcMsg::Submit { claim, body });
                            }
                        }
                        host.hold_wrappers(ws.iter().map(|(nf, _, w)| (*nf, w.clone())).collect());
                        for (nf, lc, w) in ws {
                            if let Ok(bytes) = postcard::to_allocvec(&(vec![(nf, lc)], w)) {
                                self.wrapper_relay.push(bytes);
                            }
                        }
                        self.share_sent = Some(book.batch);
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => self.share_job = None,
                }
                return;
            }
        }
        if self.share_sent == Some(book.batch) {
            return;
        }
        let (Some(w), Some((epoch, pk)), Some(key)) = (host.canon_cover_window(), host.seal_epoch(), dcu::custody_entropy()) else { return };
        let k = (2 * db::SLOTS).div_ceil(n as usize);
        let (tx, rx) = std::sync::mpsc::channel();
        let book2 = book.clone();
        std::thread::spawn(move || {
            let _ = tx.send(build_cover_share(&book2, epoch, &pk, k, &key, &w));
        });
        self.share_job = Some((book.batch, rx));
    }

    fn take_submission(&mut self, m: &DefiMpcMsg) {
        let DefiMpcMsg::Submit { claim, body } = m else { return };
        if *claim {
            if let Some(c) = db::DefiClaimTx::decode(body) {
                // a slot sent again carries a fresher member leg: it takes the older one's place
                if let Some(p) = self.pending_claims.iter_mut().find(|p| p.nullifier == c.nullifier) {
                    *p = c;
                } else {
                    if self.pending_claims.len() >= DEFI_INTAKE_MAX {
                        self.pending_claims.remove(0);
                    }
                    self.pending_claims.push(c);
                }
            }
        } else if let Some(o) = db::DefiOrderTx::decode(body) {
            if let Some(p) = self.pending_orders.iter_mut().find(|p| p.nullifier == o.nullifier) {
                *p = o;
            } else {
                if self.pending_orders.len() >= DEFI_INTAKE_MAX {
                    self.pending_orders.remove(0);
                }
                self.pending_orders.push(o);
            }
        }
    }

    /// ⭐ THE BATCH'S SLOTS, when this custodian publishes them (spec §18.12): the batch closed for intake, its slots not yet
    /// applied, and this custodian the batch's publisher (`batch mod n`); then every other custodian too, a few fold steps on
    /// (a publisher offline never stalls the batch — the first slots to apply win). The oldest live real slots (their legs
    /// hold here, their nullifiers unspent), then covers to exactly `SLOTS` each.
    fn slots_due<H: DefiHost>(&mut self, host: &H, book: &DefiBook) -> Option<(Vec<db::DefiSlotsTx>, Vec<([u8; 32], Vec<u8>)>)> {
        let me = self.me_index? as u64;
        let n = book.roster.len() as u64;
        let score = host.score();
        if !book.is_open() || book.slotted || !book.batch_closed(score) || self.slots_sent == Some(book.batch) || n == 0 {
            return None;
        }
        // the fallback publishes only into a batch none of whose parts applied: two publishers' parts never mix in one batch
        let late = score >= book.opened_at.saturating_add(db::BATCH_STEPS).saturating_add(SLOTS_FALLBACK_STEPS) && book.slot_parts == 0;
        if book.batch % n != me && !late {
            return None;
        }
        // a build in flight for this batch: its result, when it is ready
        if let Some((b, rx)) = self.slot_job.as_ref() {
            if *b == book.batch {
                return match rx.try_recv() {
                    Ok(t) => {
                        self.slot_job = None;
                        t
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => None,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        self.slot_job = None;
                        None
                    }
                };
            }
        }
        let held = self.pending_orders.len() + self.pending_claims.len();
        // each drop is counted under its kind and its fate, so a slot that leaves the intake says why (MEASURED 2026-11-10,
        // launch_trade.py scoped: a filled BTC buy's claim never landed and both custodians logged only "1 slot(s) can never
        // be carried", which named neither the slot's kind nor which dead branch it took)
        let mut dropped: std::collections::BTreeMap<(&'static str, SlotFate), usize> = std::collections::BTreeMap::new();
        self.pending_orders.retain(|o| {
            let fate = host.slot_fate(&o.member_carrier, &o.member_tuple, o.leaf_commit, o.nullifier);
            // ⭐ EARN STEP 3 — an order made for a batch that opened at another income index is never carried (the slots door
            // refuses it, and the index only rises): it leaves the intake here, so it can never hold a batch's slots back (its
            // note was never spent; its wallet places it again at the open batch's index)
            let stale = o.self_valid(book.t).is_some() || o.index != book.batch_index;
            if fate != SlotFate::Carried || stale {
                *dropped.entry(("order", if stale && fate == SlotFate::Carried { SlotFate::Dead } else { fate })).or_default() += 1;
                return false;
            }
            true
        });
        self.pending_claims.retain(|c| {
            let fate = host.slot_fate(&c.member_carrier, &c.member_tuple, c.leaf_commit, c.nullifier);
            if fate != SlotFate::Carried {
                *dropped.entry(("claim", fate)).or_default() += 1;
                return false;
            }
            true
        });
        let left = self.pending_orders.len() + self.pending_claims.len();
        if left < held {
            // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS by kind and fixed fate only; no order, amount, nullifier or owner.
            eprintln!("[defi-lane] {} slot(s) can never be carried and left this custodian's intake: {dropped:?}", held - left);
        }
        let (epoch, pk) = host.seal_epoch()?;
        let key = dcu::custody_entropy()?;
        // a slot whose leg is still pending here waits for a later batch: the chain would refuse it now
        let orders: Vec<db::DefiOrderTx> = self
            .pending_orders
            .iter()
            .filter(|o| o.share_commits.len() == book.roster.len() && host.slot_live(&o.member_carrier, &o.member_tuple, o.leaf_commit, o.nullifier))
            .take(db::SLOTS)
            .cloned()
            .collect();
        let claims: Vec<db::DefiClaimTx> =
            self.pending_claims.iter().filter(|c| host.slot_live(&c.member_carrier, &c.member_tuple, c.leaf_commit, c.nullifier)).take(db::SLOTS).cloned().collect();
        // ⭐ A-F114: under the constant chain a cover's leg is its wrapper over a window span (no member book, no anchor); a
        // window too short to hold a span gives no batch yet (it waits). ONE END A BATCH (A-F26's class): the batch carries
        // only the real slots whose wrappers name the end most of them name, and its covers are proven to that end; a slot
        // at another end waits for a later batch (its wallet's newest aligned end becomes the common one).
        let (orders, claims, canon) = if crate::canon_chain::canon_live() {
            let mut count: Vec<(crate::spend_frontier::Digest4, usize)> = Vec::new();
            for nf in orders.iter().map(|o| o.nullifier).chain(claims.iter().map(|c| c.nullifier)) {
                if let Some(e) = host.slot_wrapper_end(nf) {
                    match count.iter_mut().find(|(x, _)| *x == e) {
                        Some((_, n)) => *n += 1,
                        None => count.push((e, 1)),
                    }
                }
            }
            let common = count.iter().max_by_key(|(_, n)| *n).map(|(e, _)| *e);
            let at = |nf: [u64; 8]| common.is_some_and(|e| host.slot_wrapper_end(nf) == Some(e));
            let orders: Vec<db::DefiOrderTx> = orders.into_iter().filter(|o| at(o.nullifier)).collect();
            let claims: Vec<db::DefiClaimTx> = claims.into_iter().filter(|c| at(c.nullifier)).collect();
            (orders, claims, Some(host.canon_cover_window_at(common)?))
        } else {
            (orders, claims, None)
        };
        let books = if canon.is_some() {
            Vec::new()
        } else {
            // A-F26: every cover is proven at the batch's epoch anchor so no partition by anchor tells real from cover
            let (anchor_ordinal, anchor_root, anchor_frontier) = host.epoch_anchor_info()?;
            let b = host.cover_books(2 * db::SLOTS - orders.len() - claims.len(), anchor_ordinal, anchor_root, &anchor_frontier);
            if b.is_empty() {
                return None;
            }
            b
        };
        // ⭐ the covers' legs and proofs are built OFF the tick thread (≈ 1–2 s each; ~9 s each under the constant chain, a
        // span and a wrapper): the node keeps producing meanwhile
        let (tx, rx) = std::sync::mpsc::channel();
        let book2 = book.clone();
        std::thread::spawn(move || {
            let _ = tx.send(build_slots(&book2, epoch, &pk, orders, claims, &books, &key, canon.as_ref()));
        });
        self.slot_job = Some((book.batch, rx));
        None
    }

    pub fn on_msg(&mut self, m: &DefiMpcMsg) {
        if matches!(m, DefiMpcMsg::Submit { .. }) {
            self.take_submission(m);
            return;
        }
        let Some(me) = self.me_index else { return };
        let started = self.run.as_ref().is_some_and(|r| r.started);
        match m {
            DefiMpcMsg::Submit { .. } => {}
            DefiMpcMsg::Hello { batch, from, cts, .. } => {
                let Some((_, ct)) = cts.iter().find(|(to, _)| *to == me) else { return };
                if self.run.as_ref().is_some_and(|r| r.batch == *batch) {
                    if let Some(run) = self.run.as_mut() {
                        if run.keys.contains_key(from) {
                            // the peer is still handshaking, so it never received this custodian's confirmation: answer again
                            run.reconfirm.entry(*from).or_insert((false, 0)).0 = true;
                        }
                    }
                    self.accept_hello(me, *from, ct);
                } else if self.early_hello.len() < db::MAX_ROSTER {
                    self.early_hello.entry((*batch, *from)).or_insert_with(|| ct.clone());
                }
            }
            DefiMpcMsg::Confirm { batch, from, to, tag } => {
                if *to != me {
                    return;
                }
                if !self.run.as_ref().is_some_and(|r| r.batch == *batch) {
                    self.keep(m);
                    return;
                }
                let hit = self.run.as_ref().and_then(|run| {
                    if run.keys.contains_key(from) {
                        return None;
                    }
                    run.cand.get(from).and_then(|cs| cs.iter().find(|(k, _)| confirm_tag(k, *batch, *from, me) == *tag).map(|(k, _)| *k))
                });
                if let Some(k) = hit {
                    if let Some(run) = self.run.as_mut() {
                        run.keys.insert(*from, k);
                    }
                } else if !self.run.as_ref().is_some_and(|r| r.keys.contains_key(from)) {
                    // a confirmation that arrived before the handshake it answers (or a forger's): kept for the next pass
                    self.keep(m);
                }
            }
            DefiMpcMsg::Data { batch, from, to, seq, body, .. } => {
                if *to != me {
                    return;
                }
                if !started {
                    self.keep(m);
                    return;
                }
                let Some(run) = self.run.as_mut().filter(|r| r.batch == *batch) else { return };
                let Some(k) = run.keys.get(from) else { return };
                let Some(msg) = open_body(k, &nonce(*batch, *from, *to, *seq), body).and_then(|b| unwords(&b)) else { return };
                let next = *run.next_in.get(from).unwrap_or(&0);
                if *seq < next {
                    run.ack_due = true; // a repeat: the sender missed the acknowledgement
                    return;
                }
                run.held_in.insert((*from, *seq), msg);
                loop {
                    let want = *run.next_in.get(from).unwrap_or(&0);
                    let Some(msg) = run.held_in.remove(&(*from, want)) else { break };
                    if let Some(tx) = run.in_tx.get(from) {
                        let _ = tx.send(msg);
                    }
                    run.next_in.insert(*from, want + 1);
                    run.ack_due = true;
                    run.placed += 1;
                }
            }
            DefiMpcMsg::Ack { batch, from, to, next, tag, .. } => {
                if *to != me {
                    return;
                }
                if let Some(run) = self.run.as_mut().filter(|r| r.batch == *batch) {
                    if run.keys.get(from).is_some_and(|k| ack_tag(k, *batch, *from, *to, *next) == *tag) {
                        let now = unix_ms();
                        // the latest-departed acknowledged message never re-sent: its round trip runs from when it LEFT this
                        // node (§5.1), never from its wait in this node's own queue
                        let mut newest_clean: Option<u64> = None;
                        let before = run.unacked.len();
                        run.unacked.retain(|(j, s), sent| {
                            let acked = *j == *from && *s < *next;
                            if acked && !sent.resent {
                                if let Some(t) = sent.left_at() {
                                    newest_clean = Some(newest_clean.map_or(t, |n| n.max(t)));
                                }
                            }
                            !acked
                        });
                        if run.unacked.len() < before {
                            // new data acknowledged (§5.3): a clean sample updates the estimate, the timer collapses to it
                            // and starts again for what is still out and has left this node (or stops, and starts when it
                            // leaves)
                            match newest_clean {
                                Some(t) => {
                                    let r = now.saturating_sub(t);
                                    run.rto.sample(r);
                                    run.rtt.0 += r;
                                    run.rtt.1 += 1;
                                }
                                None => run.rto.collapse(),
                            }
                            let out_left = run.unacked.values().chain(run.my_part.as_ref()).any(|s| s.left_at().is_some());
                            run.timer_ms = out_left.then_some(now);
                        }
                    }
                }
            }
            DefiMpcMsg::Part { batch, from, part, tags, .. } => {
                if !started {
                    self.keep(m);
                    return;
                }
                let Some(run) = self.run.as_mut().filter(|r| r.batch == *batch) else { return };
                let (Some(k), Some((_, tag))) = (run.keys.get(from), tags.iter().find(|(to, _)| *to == me)) else { return };
                if part_tag(k, *batch, *from, part) != *tag {
                    return;
                }
                // a gossiped part is a wire object: ONE encoding — a tolerated tail would be a second (decode_exact)
                if run.epoch.is_some() {
                    if let Some(p) = crate::chain_object::decode_exact::<db::EpochPart>(part) {
                        run.eparts.entry(*from).or_insert(p);
                    }
                } else if let Some(p) = crate::chain_object::decode_exact::<CustodianPart>(part) {
                    run.parts.entry(*from).or_insert(p);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defi_batch::BookOrder;

    struct TestHost {
        book: DefiBook,
        events: Vec<DefiEvent>,
        epoch: (crate::epoch_key::EpochPublicKey, crate::epoch_key::EpochSecretKey),
        published: Vec<DefiSettleTx>,
        expires: Vec<db::DefiExpireTx>,
        at: u64,
        at_ms: u64,
    }
    impl DefiHost for TestHost {
        fn book(&self) -> DefiBook {
            self.book.clone()
        }
        fn score(&self) -> u64 {
            self.at
        }
        fn chain_ms(&self) -> u64 {
            self.at_ms
        }
        fn drain_defi_events(&mut self) -> Vec<DefiEvent> {
            std::mem::take(&mut self.events)
        }
        fn epoch_keys(&self, epoch: u64) -> Option<(crate::epoch_key::EpochPublicKey, crate::epoch_key::EpochSecretKey)> {
            (epoch == 0).then(|| crate::epoch_release::test_epoch_keypair())
        }
        fn publish_settle(&mut self, t: &DefiSettleTx) -> bool {
            self.published.push(t.clone());
            true
        }
        fn bonded_custody(&self) -> Vec<Vec<u8>> {
            self.book.eks.clone()
        }
        fn publish_handover(&mut self, _t: &crate::defi_handover::DefiHandoverTx) -> bool {
            false
        }
        fn drain_intake(&mut self) -> Vec<(bool, Vec<u8>)> {
            Vec::new()
        }
        fn seal_epoch(&self) -> Option<(u64, crate::epoch_key::EpochPublicKey)> {
            None
        }
        fn epoch_anchor_info(&self) -> Option<(u64, crate::spend_frontier::Digest4, crate::spend_frontier::PoseidonSpendFrontier)> {
            None
        }
        fn cover_books(&self, _k: usize, _ao: u64, _ar: crate::spend_frontier::Digest4, _af: &crate::spend_frontier::PoseidonSpendFrontier) -> Vec<([u8; 32], crate::member_witness::MemberWitnessBook)> {
            Vec::new()
        }
        fn slot_live(&self, _carrier: &[u8], _tuple: &[u8], _leaf_commit: [u64; 8], _nf: [u64; 8]) -> bool {
            true
        }
        fn publish_slots(&mut self, _t: &db::DefiSlotsTx) -> bool {
            false
        }
        fn publish_expire(&mut self, t: &db::DefiExpireTx) -> bool {
            self.expires.push(t.clone());
            true
        }
    }

    /// ⭐ A STOPPED BATCH CANNOT HOLD A POOL: past its window any node publishes the expiry, the expiry passes the door's own verdict, and it goes again if it did not land; within the window nothing is published.
    #[test]
    fn a_batch_past_its_window_is_expired_by_any_node_and_one_within_it_is_not() {
        let book = DefiBook {
            roster: vec![[7u8; 32]],
            eks: vec![vec![1u8; 4]],
            pool_commits: vec![Default::default()],
            fee_commits: db::launch_fee_commits(0, 1),
            t: 0,
            slotted: true,
            opened_ms: 1_000,
            ..DefiBook::default()
        };
        assert!(book.is_open(), "the fixture's pool is open");
        let closed = db::BATCH_STEPS;
        let end_ms = 1_000 + db::EXPIRE_MS;
        let (pk, sk) = crate::epoch_release::test_epoch_keypair();
        let mut host = TestHost { book: book.clone(), events: Vec::new(), epoch: (pk, sk), published: Vec::new(), expires: Vec::new(), at: closed, at_ms: end_ms - 1 };
        let mut lane = DefiLane::new(None, None);
        lane.tick(&mut host, 0);
        assert!(host.expires.is_empty(), "one millisecond inside the window nothing is published");
        host.at_ms = end_ms;
        lane.tick(&mut host, 0);
        assert_eq!(host.expires.len(), 1, "at the window's end the node publishes the expiry");
        assert!(host.expires[0].verdict(&book, closed, end_ms).is_ok(), "and the door takes what it published");
        lane.tick(&mut host, 0);
        assert_eq!(host.expires.len(), 1, "once, not every tick");
        host.at = closed + EXPIRE_RESEND_STEPS;
        lane.tick(&mut host, 0);
        assert_eq!(host.expires.len(), 2, "an expiry that has not landed goes again");
        let tampered = db::DefiExpireTx { pair: book.pair, batch: book.batch + 1, leaves: Vec::new() };
        assert!(tampered.verdict(&book, closed, end_ms).is_err(), "an expiry for another batch is refused");
        assert!(host.expires[0].verdict(&DefiBook { opened_ms: 0, ..book.clone() }, closed, end_ms).is_err(), "never before the open is stamped");
    }

    /// ⭐⭐ FOUR CUSTODIAN LANES SETTLE A BATCH OVER GOSSIP AND A FORGER IS IGNORED: a launch pool dealt to four custodians, two
    /// buys whose sealed shares reach each custodian only as the blocks' events carried them; every lane ticks, every lane
    /// message goes through the others' `on_msg` (gossip: everyone gets everything), each custodian's engine runs on its own
    /// thread — and every lane publishes the SAME settlement, which passes the verdict. A forger gossiping handshakes (AHEAD of
    /// custodian 2's own), confirmations, engine messages and parts in custodian 2's name is ignored: its handshake is only a
    /// candidate no one confirms, and its tags fail under the pair keys it cannot compute.
    #[test]
    fn br15_four_custodian_lanes_settle_a_batch_over_gossip_and_a_forger_is_ignored() {
        let n = 4usize;
        let kems: Vec<(Vec<u8>, Vec<u8>)> = (0..n).map(|_| crate::pqkem::keypair()).collect();
        let eks: Vec<Vec<u8>> = kems.iter().map(|k| k.0.clone()).collect();
        let states = dcu::deal_pool([3_000_000, 1_000_000, 0, 0], n, 1, &[71; 32]);
        let (pk, _) = crate::epoch_release::test_epoch_keypair();
        let mut book = DefiBook {
            roster: eks.iter().map(|k| crate::defi_launch::custody_id(k)).collect(),
            eks: eks.clone(),
            t: 1,
            pool_commits: states.iter().map(CustodianState::commit).collect(),
            fee_commits: states.iter().map(CustodianState::fee_commit).collect(),
            // the batch's slots applied (the events below are what they carried)
            slotted: true,
            ..DefiBook::default()
        };
        let mut events = Vec::new();
        for (k, a) in [25_000u64, 7_777].iter().enumerate() {
            let no_max = usdm_decider::br15_audit::ORDER_BUCKETS - 1;
            let (d, commits, epoch_ct, sealed, _proof) =
                dcu::order_parts(0, false, &eks, 1, 0, &pk, *a, no_max, [0x0D, k as u64, 7, 7, 7, 7, 7, 7], [[k as u64 + 1; 8], [2; 8], [3; 8]], [4; 8], 0, &[72 + k as u8; 32]).expect("deals");
            book.orders.push(BookOrder { amount_commit: d.amount_commit(), limit_commit: d.limit_commit(), share_commits: commits });
            events.push(DefiEvent::Order { batch: 0, index: k as u32, epoch: 0, epoch_ct, sealed });
        }
        let mut hosts: Vec<TestHost> =
            (0..n).map(|_| TestHost { book: book.clone(), events: events.clone(), epoch: crate::epoch_release::test_epoch_keypair(), published: Vec::new(), expires: Vec::new(), at: db::BATCH_STEPS + 1, at_ms: 0 }).collect();
        let _ = &hosts[0].epoch;
        let mut lanes: Vec<DefiLane> = (0..n).map(|i| DefiLane::with_state(kems[i].clone(), states[i].clone())).collect();
        // the forger: its own keys, speaking as custodian 2
        let (forger_ek, _) = crate::pqkem::keypair();
        let forged_cts: Vec<(u32, Vec<u8>)> = (0..n as u32).filter(|j| *j != 2).filter_map(|j| crate::pqkem::encapsulate(&eks[j as usize]).map(|(_, ct)| (j, ct))).collect();
        let _ = forger_ek;
        let t0 = std::time::Instant::now();
        let mut now = 1u64;
        while hosts.iter().any(|h| h.published.is_empty()) && t0.elapsed() < std::time::Duration::from_secs(900) {
            // the forger's gossip rides AHEAD of the honest gossip, every round (it races custodian 2's handshake)
            let mut wire = vec![
                DefiMpcMsg::Hello { batch: 0, from: 2, cts: forged_cts.clone(), copy: 0 },
                DefiMpcMsg::Confirm { batch: 0, from: 2, to: 0, tag: [0x77; TAG] },
                DefiMpcMsg::Data { batch: 0, from: 2, to: 0, seq: 0, body: vec![0x5A; 32 * 3 + TAG], copy: 0 },
                DefiMpcMsg::Part { batch: 0, from: 2, part: vec![1, 2, 3], tags: (0..n as u32).map(|j| (j, [0u8; TAG])).collect(), copy: 0 },
            ];
            for (lane, host) in lanes.iter_mut().zip(hosts.iter_mut()) {
                wire.extend(lane.tick(host, now));
            }
            for m in &wire {
                let bytes = m.encode().expect("encodes");
                let m = DefiMpcMsg::decode(&bytes).expect("one canonical encoding");
                for lane in &mut lanes {
                    lane.on_msg(&m);
                }
            }
            now += 50;
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(hosts.iter().all(|h| !h.published.is_empty()), "⛔ the custodians did not settle within 900 s");
        let first = &hosts[0].published[0];
        assert!(hosts.iter().all(|h| h.published[0] == *first), "⛔ the custodians built different settlements");
        assert_eq!(first.verdict(&book), Ok(first.leaves.clone()), "⛔ the gossiped settlement fails the verdict");
        assert_eq!(first.tick, crate::defi_clear::rule_tick(3_000_000, 1_000_000 + 25_000 + 7_777), "the tick is the rule's");
        assert!(first.excluded.is_empty(), "⛔ an honest order was complained of");
        eprintln!("[br15-lane] four custodian lanes settled batch 0 over gossip in {:.1} s (tick {})", t0.elapsed().as_secs_f64(), first.tick);
    }

    /// A custodian whose confirmation was lost after its own engine started answers the peer's repeated handshake with it
    /// again, so the peer starts too and both publish the batch's settlement (TCP's shape: a repeated SYN gets the SYN-ACK
    /// again).
    /// CHAIN-OBJECT: what the pin reads is each lane's PUBLISHED `DefiSettleTx` — the object a block carries and every
    /// node's fold verdict decides; no lane moves value here.
    /// MEASURED 2026-11-09, real nodes: pair 0's batch 2 closed after 2,340 s — one custodian "1 engine message sent, 0
    /// placed from peers", the other never started — while a slow Tor writer shed Payout-class pages.
    /// CALIBRATION in the same pin: with custodian 0's confirmations to 1 lost for good, nothing is published (the loss is
    /// real and fatal); losing only those sent before custodian 0's engine started is what the real nodes did.
    #[test]
    fn a_lost_confirmation_is_sent_again_when_the_peer_handshakes_again() {
        let n = 2usize;
        let kems: Vec<(Vec<u8>, Vec<u8>)> = (0..n).map(|_| crate::pqkem::keypair()).collect();
        let eks: Vec<Vec<u8>> = kems.iter().map(|k| k.0.clone()).collect();
        let states = dcu::deal_pool([3_000_000, 1_000_000, 0, 0], n, 0, &[81; 32]);
        let book = DefiBook {
            roster: eks.iter().map(|k| crate::defi_launch::custody_id(k)).collect(),
            eks: eks.clone(),
            t: 0,
            pool_commits: states.iter().map(CustodianState::commit).collect(),
            fee_commits: states.iter().map(CustodianState::fee_commit).collect(),
            slotted: true,
            ..DefiBook::default()
        };
        // runs the two lanes; `lost(m, started0)` drops a message before it reaches anyone
        let run = |lost: &dyn Fn(&DefiMpcMsg, bool) -> bool, iters: usize| -> bool {
            let mut hosts: Vec<TestHost> = (0..n)
                .map(|_| TestHost { book: book.clone(), events: Vec::new(), epoch: crate::epoch_release::test_epoch_keypair(), published: Vec::new(), expires: Vec::new(), at: db::BATCH_STEPS + 1, at_ms: 0 })
                .collect();
            let mut lanes: Vec<DefiLane> = (0..n).map(|i| DefiLane::with_state(kems[i].clone(), states[i].clone())).collect();
            let mut now = 1u64;
            // ⛔ THE STEPS ARE A FLOOR, NOT THE VERDICT. The engines are real threads doing the MPC's arithmetic, so on a loaded
            // machine they take longer in WALL time while the lanes' clock above advances by steps. MEASURED 2026-11-10 (load
            // 204-300): both engines ran — "81 engine message(s) sent, 81 placed from peers" on each lane, so the lost confirmation
            // HAD been sent again — and were still computing when 60,000 steps ran out, and the pin read "the peer never started".
            // The run therefore goes on while either lane still places messages from its peer, and ends when both published, or
            // once nothing new was placed for STALL of wall time past the floor. The calibration case still ends: a peer that
            // never starts places nothing.
            const STALL: std::time::Duration = std::time::Duration::from_secs(300);
            let (mut last_placed, mut last_move) = (0u64, std::time::Instant::now());
            let mut step = 0usize;
            loop {
                if hosts.iter().all(|h| !h.published.is_empty()) {
                    return true;
                }
                let placed: u64 = lanes.iter().filter_map(|l| l.run.as_ref()).map(|r| r.placed).sum();
                if placed != last_placed {
                    (last_placed, last_move) = (placed, std::time::Instant::now());
                }
                if step >= iters && last_move.elapsed() > STALL {
                    break;
                }
                step += 1;
                let mut wire = Vec::new();
                for (lane, host) in lanes.iter_mut().zip(hosts.iter_mut()) {
                    wire.extend(lane.tick(host, now));
                }
                let started0 = lanes[0].run.as_ref().is_some_and(|r| r.started);
                for m in wire.iter().filter(|m| !lost(m, started0)) {
                    let m = DefiMpcMsg::decode(&m.encode().expect("encodes")).expect("one canonical encoding");
                    for lane in &mut lanes {
                        lane.on_msg(&m);
                    }
                }
                now += 50;
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            hosts.iter().all(|h| !h.published.is_empty())
        };
        let zero_to_one = |m: &DefiMpcMsg| matches!(m, DefiMpcMsg::Confirm { from: 0, to: 1, .. });
        assert!(
            !run(&|m, _| zero_to_one(m), 2_000),
            "CALIBRATION: with every confirmation from custodian 0 to 1 lost, nothing may be published (else the pin proves nothing)"
        );
        assert!(
            run(&|m, started0| zero_to_one(m) && !started0, 60_000),
            "⛔ custodian 0's confirmation was lost before its engine started and was never sent again: the peer never started"
        );
    }

    /// The re-send timer follows the measured round trip (RFC 6298), never the fixed first guess. CALIBRATION: before any
    /// sample the wait is the 5 s floor — the value that re-sent every message ~4× on a 100 s round trip.
    #[test]
    fn the_resend_wait_follows_the_measured_round_trip() {
        let mut r = Rto::new();
        assert_eq!(r.rto_ms, HELLO_RESEND_MS, "CALIBRATION: no sample yet, the floor");
        r.sample(100_000);
        assert_eq!(r.rto_ms, (100_000 + 4 * 50_000).min(RTO_MAX_MS), "first sample: SRTT + 4·(R/2), held at the maximum");
        for _ in 0..40 {
            r.sample(100_000);
        }
        assert!(r.rto_ms >= 100_000 && r.rto_ms < 110_000, "a steady 100 s round trip waits just over 100 s, not 5 s: {}", r.rto_ms);
        r.backoff();
        assert!(r.rto_ms >= 200_000, "a timeout doubles the wait");
        r.collapse();
        assert!(r.rto_ms < 110_000, "a new acknowledgement collapses the backoff to the estimate");
        for _ in 0..120 {
            r.sample(1_000);
        }
        assert_eq!(r.rto_ms, HELLO_RESEND_MS, "a fast link is held at the floor, never below it");
        for _ in 0..10 {
            r.backoff();
        }
        assert_eq!(r.rto_ms, RTO_MAX_MS, "the backoff stops at the maximum");
    }

    /// ⭐ MEASURED 2026-11-09 (launch_trade.py round 18, real nodes): one custodian re-folded two records, its fold replayed batch
    /// 8's close after the XMR buy's order for batch 9 had moved into its file, the replay emptied the file, batch 9 ran with no
    /// share of the order, and 1 XMR came back refunded. The file applies the chain's events once each, by their keys.
    #[test]
    fn a_replayed_close_or_order_never_drops_or_doubles_a_filed_order() {
        let mut lane = DefiLane::new(None, None);
        let book = DefiBook::default();
        let order = |batch: u64, index: u32, tag: u8| DefiEvent::Order { batch, index, epoch: 7, epoch_ct: vec![tag; 4], sealed: vec![vec![tag; 8]] };
        lane.absorb(vec![DefiEvent::Closed { batch: 7 }], &book, 0);
        assert_eq!(lane.file.batch, 8, "CALIBRATION: a close opens the next batch");
        lane.absorb(vec![order(9, 0, 0xA1), DefiEvent::Closed { batch: 8 }], &book, 0);
        assert_eq!((lane.file.batch, lane.file.orders.len(), lane.file.queued.len()), (9, 1, 0), "CALIBRATION: an order placed while batch 8 cleared is batch 9's once 8 closes");
        // a re-fold walks batch 8's settlement again
        lane.absorb(vec![DefiEvent::Closed { batch: 8 }], &book, 0);
        assert_eq!((lane.file.batch, lane.file.orders.len()), (9, 1), "⛔ a replayed close dropped an order this custodian already holds");
        // ...and the order's slots, and a stale order of the batch that closed
        lane.absorb(vec![order(9, 0, 0xA1), order(8, 3, 0xB2)], &book, 0);
        assert_eq!((lane.file.batch, lane.file.orders.len(), lane.file.queued.len()), (9, 1, 0), "⛔ a replayed order was filed twice, or a stale one moved the file back");
        // a re-fold that put another order's slots first renumbers this one
        lane.absorb(vec![order(9, 1, 0xA1)], &book, 0);
        assert_eq!(lane.file.orders.iter().map(|o| o.0).collect::<Vec<_>>(), vec![1], "⛔ a renumbered order kept its old index or was filed twice");
        // a lane that missed closes takes the batch the chain names
        lane.absorb(vec![order(12, 0, 0xC3)], &book, 0);
        assert_eq!((lane.file.batch, lane.file.orders.len()), (12, 1), "a lane that missed closes files the batch the chain names");
        lane.absorb(vec![DefiEvent::Closed { batch: 11 }], &book, 0);
        assert_eq!((lane.file.batch, lane.file.orders.len()), (12, 1), "⛔ a late close of an older batch dropped the open batch's order");
    }

    /// A lane whose run is past its handshake with custodian 1 (pair key `k`), and its engine's outbox — the send path alone.
    fn running_lane(k: [u8; 32]) -> (DefiLane, std::sync::mpsc::Sender<(usize, Vec<F255>)>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut lane = DefiLane::new(None, None);
        lane.me_index = Some(0);
        lane.run = Some(Run {
            batch: 5,
            ss_to: BTreeMap::new(),
            cts: Vec::new(),
            hello_sent_ms: 1,
            cand: BTreeMap::new(),
            keys: BTreeMap::from([(1, k)]),
            reconfirm: BTreeMap::new(),
            started: true,
            out_rx: Some(rx),
            in_tx: BTreeMap::new(),
            next_in: BTreeMap::new(),
            held_in: BTreeMap::new(),
            seq_out: BTreeMap::new(),
            unacked: BTreeMap::new(),
            my_part: None,
            timer_ms: None,
            rto: Rto::new(),
            copies: 1, // the handshake's copy came first
            ack_due: false,
            result: None,
            parts: BTreeMap::new(),
            agreed: None,
            epoch: None,
            eparts: BTreeMap::new(),
            eagreed: None,
            published: false,
            chunks_out: false,
            stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            started_ms: 0,
            placed: 0,
            sent_first: (0, 0),
            sent_again: (0, 0),
            part_sent: (0, 0),
            sent_other: (0, 0),
            queue_wait: (0, 0),
            rtt: (0, 0),
            heard: (0, 0, 0),
        });
        (lane, tx)
    }

    /// ⭐ MEASURED 2026-11-10 (launch_trade.py round 20, real nodes): the BTC pool's batch 1 expired while both custodians still
    /// ran (1,370 s and 2,476 s of its 2,700 s). This lane's message class carried 151 MB through one node's link for four
    /// runs whose engine payload is 22-45 MB: the re-send timer started when a message was QUEUED, so a deal-sized engine
    /// message waiting behind this node's own backlog was sent again before its first copy had left (each copy new bytes,
    /// relayed again by every node), and a node never recorded its own messages as seen, so each crossed the link three
    /// times. The timer runs from when a copy LEAVES this node (RFC 6298 §5.1), and a node never relays its own message back.
    #[test]
    fn a_lane_message_still_in_this_nodes_queue_is_never_sent_again_and_its_own_echo_is_never_relayed() {
        let k = [7u8; 32];
        let data = |out: &[DefiMpcMsg]| out.iter().filter(|m| matches!(m, DefiMpcMsg::Data { .. })).cloned().collect::<Vec<_>>();
        // CALIBRATION — the shape this lane had: a lane given no departure marks times a copy from its hand-off, so the same
        // message is sent again at the 5 s floor whatever this node's queue still holds, and its own echo is relayed as new
        let (mut old, old_tx) = running_lane(k);
        old_tx.send((1, vec![F255::ONE; 8_192])).expect("the engine's outbox"); // 8,192 elements ≈ 64 cells, a deal-sized message
        let first = data(&old.pump(0, 1_000));
        assert_eq!(first.len(), 1, "CALIBRATION: the engine's message goes out");
        let old_bytes = first[0].encode().expect("encodes");
        let old_again: usize = (1..=30u64).map(|s| data(&old.pump(0, 1_000 + s * 1_000)).len()).sum();
        assert!(old_again >= 1, "CALIBRATION: timed from its hand-off, the copy is sent again within 30 s");
        assert!(old.on_wire(&old_bytes), "CALIBRATION: a lane that never recorded its own message relays it back as new");

        // THE RUNTIME'S SHAPE: every copy's departure mark comes back, and this node's channel has not reached it
        let (mut lane, tx) = running_lane(k);
        tx.send((1, vec![F255::ONE; 8_192])).expect("the engine's outbox");
        lane.set_departed(0);
        let first = data(&lane.pump(0, 1_000));
        assert_eq!(first.len(), 1, "the engine's message goes out");
        let bytes = first[0].encode().expect("encodes");
        lane.queued(&first[0], &bytes, Some(270));
        assert!(!lane.on_wire(&bytes), "⛔ this node's own message, heard back from its peer, was relayed again");
        for s in 1..=300u64 {
            lane.set_departed(269);
            assert!(data(&lane.pump(0, 1_000 + s * 1_000)).is_empty(), "⛔ a message still in this node's own queue was sent again after {s} s");
        }
        // it leaves: the timer starts then, and a copy that left and was never acknowledged is still sent again
        lane.set_departed(270);
        assert!(data(&lane.pump(0, 302_000)).is_empty(), "the timer starts when the copy leaves");
        assert!(data(&lane.pump(0, 302_000 + HELLO_RESEND_MS - 1)).is_empty(), "no re-send before the wait");
        let again = data(&lane.pump(0, 302_000 + HELLO_RESEND_MS));
        assert_eq!(again.len(), 1, "⛔ a copy that left and was never acknowledged was not sent again");
        // the re-sent copy waits for its own departure too
        let b2 = again[0].encode().expect("encodes");
        lane.queued(&again[0], &b2, Some(600));
        for s in 1..=60u64 {
            lane.set_departed(599);
            assert!(data(&lane.pump(0, 302_000 + HELLO_RESEND_MS + s * 10_000)).is_empty(), "⛔ a re-sent copy still queued was sent a third time");
        }
        let r = lane.run.as_ref().expect("the run");
        assert_eq!((r.sent_first.0, r.sent_again.0), (1, 1), "the readout counts one first copy and one copy sent again");
        assert_eq!(r.queue_wait.1, 1, "the readout times the first copy's wait in this node's queue");
        // a copy the channel refused (its bound) counts as gone at once: the timer covers it as it covers a lost copy
        let (mut refused, rtx) = running_lane(k);
        rtx.send((1, vec![F255::ONE; 64])).expect("the engine's outbox");
        refused.set_departed(0);
        let m = data(&refused.pump(0, 1_000));
        refused.queued(&m[0], &m[0].encode().expect("encodes"), None);
        assert!(data(&refused.pump(0, 1_100)).is_empty(), "the refused copy's timer starts at the next look");
        assert_eq!(data(&refused.pump(0, 1_100 + HELLO_RESEND_MS)).len(), 1, "⛔ a copy the channel refused was never sent again");
    }
}

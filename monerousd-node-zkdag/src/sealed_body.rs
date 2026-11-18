// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ SEALED BODIES BY ID (speed lane, 2026-11-10) — A LARGE LANE MESSAGE CROSSES THE MESH THE WAY A BLOCK DOES:
//! announced by id in one small constant-shape cell, pulled by id over the bulk lanes by every node that lacks it.
//!
//! MEASURED (two real nodes, the DeFi lane's own run lines, 2026-11-10, four batches on each of two custody lanes): a
//! custody run sends 65 or 117 engine messages, 2.72 or 5.45 MB — about 42 KB each, eleven cells. Every one rode the
//! paced cell channel (4 cells of 4,096 bytes per 250 ms slot to each peer, shared with block announcements, votes,
//! locks and payouts), waited a MEAN 2.4 to 4.5 s in its own node's outbound queue and came back in a mean 1.6 to
//! 4.4 s; the engine sends its next message when the last is answered, so a run took 424 to 906 s. The same nodes
//! fetch a page of a few kilobytes over a bulk lane in 0.4 to 0.9 s, and those lanes are idle between blocks.
//! (On 2026-11-08, when the lane re-sent every unacknowledged message every 5 s, the same channel's bound refused
//! 32,214 messages of the class in one run; the lane's re-send timer has since been rebuilt, and the queue wait above
//! is what remains.)
//!
//! So a lane message that does not fit ONE cell ([`SEALED_MIN_BYTES`]) is no longer flooded as cells:
//! - its sender keeps the bytes in a bounded relay buffer ([`SealedBodies`]) and floods a 37-byte inventory
//!   (`WireMsg::SealedInv`: lane, id, length — the same shape for every message);
//! - a node that has not seen that id pulls it from the announcer over a bulk lane (`[28][id]`), checks the bytes
//!   against the id and the announced length, and hands them to the SAME intake the cell door hands a lane message to;
//! - only when that intake says "new here: relay it once" does the node keep the bytes and flood the inventory on.
//! Every node still receives every lane message exactly as under the cell flood — who is addressed is not learned from
//! who pulls — and the lane's own tags, numbering and re-send timer are untouched.
//!
//! BORROWED: Bitcoin's `inv` → `getdata` → body (one announcement cell, the body only to a peer that asks), with a
//! `notfound` that moves the ask to the next announcer (Bitcoin Core `TxRequestTracker`); this tree's own band-step
//! pull (kind 22, DB-454) is the same shape.
//!
//! §9.6 — the new ingress path: (1) proof of work: none here and none at the cell door it parallels — a lane message
//! is not a block; (2) the message's own validity: checked by the lane's intake exactly as for a cell-carried copy
//! (`DefiLane::on_wire`: its tags under the pair key); this door adds that the bytes are the ones their id names;
//! (3) value: a lane message moves none — the lane's settlement is a chain object a block carries; (4) replay: an id
//! seen here is never pulled again (`seen`), and the lane's own seen-set and numbering place a message once; (5) work
//! bound: an inventory is 37 bytes exactly, a body at most [`SEALED_BODY_BYTES_MAX`] and exactly its announced length,
//! an answer is decoded only for an id with an ask outstanding, at most [`SEALED_PULLS_MAX`] asks are outstanding and
//! [`SEALED_WANTS_MAX`] waiting, the relay buffer holds at most [`SEALED_HELD_BYTES_MAX`] for at most
//! [`SEALED_HELD_MS`]; (6) parity with the cell door (`WireMsg::DefiMpc`): the same intake decides relay, and nothing
//! is relayed that intake did not accept — plus the id and length checks the cell door has no use for.
//! DIGITAL-CASH-PRIVACY-REVIEWED: an inventory names a lane number, the hash of bytes that are already sealed to their
//! addressee, and their length — less than the cell flood showed every relay (the whole sealed message, with its
//! sender and addressee in its header). Every node pulls every announced body, so a pull says nothing about who a
//! message is for. No log line here carries an id, a length, a peer or a count of anything but this node's own buffer.
//! cons: one bulk round trip per multi-cell message per hop (0.4 to 0.9 s measured for a small page on the rig) where
//! an IDLE cell channel would pass a two-to-six-cell message sooner (62.5 ms a cell) — the measured queue is not idle
//! (2.4 to 4.5 s mean), and a one-cell message still rides its cell; at most [`SEALED_HELD_BYTES_MAX`] of RAM per
//! node while lane runs are live, released [`SEALED_HELD_MS`] after the last one; nothing persisted.

use std::collections::{HashSet, VecDeque};

/// The bulk-lane ask kind: `[28][id 32]`.
pub const BULK_REQ_KIND_SEALED_BODY: u8 = 28;
/// The answer tag: `SEALBODY ‖ id ‖ len u32 LE ‖ bytes`; `SEALBODY ‖ id` alone is the `notfound`.
pub const SEALED_BODY_TAG: &[u8; 8] = b"SEALBODY";
/// An inventory's exact length: `[lane u8][id 32][len u32 LE]`.
pub const SEALED_INV_BYTES: usize = 1 + 32 + 4;
/// The lane number of the DeFi custodian lane's messages (`WireMsg::DefiMpc`'s payload: `[pair] ‖ DefiMpcMsg`).
pub const SEALED_LANE_DEFI: u8 = 1;
/// A message below this rides its ONE cell as before. DERIVED from the cell, not tuned: a lane message goes out as
/// `WireMsg::DefiMpc(bytes)`, whose encoding is the bytes plus a 1-byte variant tag and a 2-byte length, and one cell
/// carries `net::CHUNK_DATA` bytes of a message — so this is the first length that needs a second cell. A message
/// that fits one cell costs the channel exactly what its inventory would; any longer one is announced by one cell and
/// leaves the channel.
pub const SEALED_MIN_BYTES: usize = crate::net::CHUNK_DATA - 2;
/// The largest body: one bulk frame less this answer's header.
pub const SEALED_BODY_BYTES_MAX: usize = crate::arti_transport::BULK_FRAME_MAX - (8 + 32 + 4);
/// Asks outstanding at once: one per bulk lane the transport holds per host.
pub const SEALED_PULLS_MAX: usize = crate::arti_transport::BULK_LANES_PER_HOST;
/// Announced bodies waiting for an ask slot. DERIVED: one message from every custodian of the largest roster a batch
/// admits — the most one step of a run can announce at once; past it the oldest waits for its sender's re-send.
pub const SEALED_WANTS_MAX: usize = crate::defi_batch::MAX_ROSTER;
/// RAM the relay buffer may hold: two bulk frames. A relay BUFFER, never an archive — a body evicted before a peer
/// pulled it is announced again by its sender's own re-send timer, so the bound costs time under overload, never a
/// message.
pub const SEALED_HELD_BYTES_MAX: usize = 2 * crate::arti_transport::BULK_FRAME_MAX;
/// How long a body is held: the lane's longest re-send wait — past it the sender has announced a fresh copy.
pub const SEALED_HELD_MS: u64 = crate::defi_lane::RTO_MAX_MS;
/// Ids remembered so a body is pulled once. DERIVED: every body the buffer can hold at the smallest size this door
/// carries. An id that has left the ring and is announced again (an honest re-send is a NEW id) costs one pull and is
/// then dropped by its lane's own seen-set, never relayed.
pub const SEALED_SEEN_MAX: usize = SEALED_HELD_BYTES_MAX / SEALED_MIN_BYTES;
/// An ask unanswered this long is over (the bulk lane's own header guard has fired long before): the id is asked of its
/// next announcer.
pub const SEALED_ASK_REARM_MS: u64 = 30_000;

/// The id of a body on `lane`: its domain-separated hash. The lane is inside the hash, so an id cannot be replayed onto
/// another lane.
#[must_use]
pub fn id_of(lane: u8, bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MonerousD sealed body id v1");
    h.update(&[lane]);
    h.update(bytes);
    *h.finalize().as_bytes()
}

/// The 37-byte inventory for a body.
#[must_use]
pub fn inv(lane: u8, id: &[u8; 32], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEALED_INV_BYTES);
    out.push(lane);
    out.extend_from_slice(id);
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out
}

/// Parse an inventory: exact length, a length this door carries. Anything else is no inventory.
#[must_use]
pub fn parse_inv(bytes: &[u8]) -> Option<(u8, [u8; 32], usize)> {
    if bytes.len() != SEALED_INV_BYTES {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes[1..33]);
    let len = u32::from_le_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]) as usize;
    (len >= SEALED_MIN_BYTES && len <= SEALED_BODY_BYTES_MAX).then_some((bytes[0], id, len))
}

/// The kind-28 ask for `id`.
#[must_use]
pub fn ask(id: &[u8; 32]) -> Vec<u8> {
    let mut req = Vec::with_capacity(33);
    req.push(BULK_REQ_KIND_SEALED_BODY);
    req.extend_from_slice(id);
    req
}

/// Whether `req` is a sealed-body ask (its exact shape).
#[must_use]
pub fn is_ask(req: &[u8]) -> bool {
    req.len() == 33 && req[0] == BULK_REQ_KIND_SEALED_BODY
}

/// Whether `page` is the `notfound` for `req` (the tag and the asked id alone).
#[must_use]
pub fn is_notfound(req: &[u8], page: &[u8]) -> bool {
    is_ask(req) && page.len() == 8 + 32 && &page[..8] == SEALED_BODY_TAG && page[8..] == req[1..]
}

struct Held {
    id: [u8; 32],
    bytes: Vec<u8>,
    at_ms: u64,
}

struct Want {
    lane: u8,
    id: [u8; 32],
    len: usize,
    /// the links that announced it, in the order heard; the first is asked
    announcers: Vec<Option<u64>>,
    /// when its ask left, if one is outstanding
    asked_ms: Option<u64>,
}

/// What became of an answer.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// the body of an id this node asked for, checked against the id and the announced length: hand it to the lane
    Body { lane: u8, id: [u8; 32], bytes: Vec<u8> },
    /// a `notfound`, or bytes that are not the announced body: that announcer is dropped, the id stays wanted from the
    /// next one (or is forgotten, to be wanted again when it is next announced)
    Refused,
    /// an answer for an id with no ask outstanding: dropped undecoded
    Unasked,
}

/// The relay buffer and the pull book of one node. RAM only, bounded on every axis by this module's constants; a
/// restart drops it and the lane's re-send timer announces whatever was lost.
#[derive(Default)]
pub struct SealedBodies {
    held: VecDeque<Held>,
    held_bytes: usize,
    seen: VecDeque<[u8; 32]>,
    seen_set: HashSet<[u8; 32]>,
    wants: VecDeque<Want>,
}

impl SealedBodies {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn remember(&mut self, id: [u8; 32]) {
        if self.seen_set.insert(id) {
            self.seen.push_back(id);
            while self.seen.len() > SEALED_SEEN_MAX {
                if let Some(old) = self.seen.pop_front() {
                    self.seen_set.remove(&old);
                }
            }
        }
    }

    fn forget(&mut self, id: &[u8; 32]) {
        if self.seen_set.remove(id) {
            self.seen.retain(|s| s != id);
        }
    }

    /// Keep `bytes` to serve and return the inventory to flood — this node's own message, or one its lane accepted for
    /// relay. `None` (nothing kept, nothing to flood) for a size this door does not carry.
    pub fn hold(&mut self, lane: u8, bytes: Vec<u8>, now_ms: u64) -> Option<Vec<u8>> {
        if bytes.len() < SEALED_MIN_BYTES || bytes.len() > SEALED_BODY_BYTES_MAX {
            return None;
        }
        let id = id_of(lane, &bytes);
        let announce = inv(lane, &id, bytes.len());
        self.remember(id);
        self.wants.retain(|w| w.id != id);
        if self.held.iter().any(|h| h.id == id) {
            return Some(announce);
        }
        self.held_bytes += bytes.len();
        self.held.push_back(Held { id, bytes, at_ms: now_ms });
        while self.held_bytes > SEALED_HELD_BYTES_MAX && self.held.len() > 1 {
            if let Some(old) = self.held.pop_front() {
                self.held_bytes -= old.bytes.len();
            }
        }
        Some(announce)
    }

    /// Let go of a body whose inventory could not be queued (the cell channel was at its bound): nobody was told of it,
    /// so nobody can ask for it, and holding it would only fill the buffer. Its id stays seen — the lane's re-send is a
    /// new copy with a new id. Takes the inventory [`Self::hold`] returned.
    pub fn release(&mut self, inventory: &[u8]) {
        let Some((_, id, _)) = parse_inv(inventory) else { return };
        if let Some(pos) = self.held.iter().position(|h| h.id == id) {
            if let Some(gone) = self.held.remove(pos) {
                self.held_bytes -= gone.bytes.len();
            }
        }
    }

    /// An inventory from `link`: `true` when it names a body this node now wants (never seen, a size this door carries).
    pub fn on_inv(&mut self, bytes: &[u8], link: Option<u64>) -> bool {
        let Some((lane, id, len)) = parse_inv(bytes) else { return false };
        if let Some(w) = self.wants.iter_mut().find(|w| w.id == id) {
            // one more announcer of a body still wanted (bounded: one per bulk lane is every ask it can ever spend)
            if w.len == len && w.lane == lane && !w.announcers.contains(&link) && w.announcers.len() < SEALED_PULLS_MAX {
                w.announcers.push(link);
            }
            return false;
        }
        if self.seen_set.contains(&id) {
            return false;
        }
        while self.wants.len() >= SEALED_WANTS_MAX {
            // the oldest waits for its sender's re-send; forgotten, so that announcement is heard
            if let Some(old) = self.wants.pop_front() {
                self.forget(&old.id);
            }
        }
        self.remember(id);
        self.wants.push_back(Want { lane, id, len, announcers: vec![link], asked_ms: None });
        true
    }

    /// The asks to send now, each aimed at the link that announced its body: every waiting want, oldest first, while
    /// fewer than [`SEALED_PULLS_MAX`] are outstanding. Each is marked asked at `now_ms`; a caller whose lane refused
    /// one hands it back with [`Self::ask_did_not_leave`].
    pub fn next_asks(&mut self, now_ms: u64) -> Vec<(Vec<u8>, Option<u64>)> {
        let mut out = Vec::new();
        let mut outstanding = self.wants.iter().filter(|w| w.asked_ms.is_some()).count();
        for w in self.wants.iter_mut() {
            if outstanding >= SEALED_PULLS_MAX {
                break;
            }
            if w.asked_ms.is_some() {
                continue;
            }
            let Some(link) = w.announcers.first().copied() else { continue };
            w.asked_ms = Some(now_ms);
            outstanding += 1;
            out.push((ask(&w.id), link));
        }
        out
    }

    /// The lane refused this ask: it is waiting again (same announcer; nothing was learned about it).
    pub fn ask_did_not_leave(&mut self, req: &[u8]) {
        if !is_ask(req) {
            return;
        }
        if let Some(w) = self.wants.iter_mut().find(|w| w.id[..] == req[1..]) {
            w.asked_ms = None;
        }
    }

    /// The announcer asked for `id` did not deliver it: dropped; the id is asked of the next announcer, or — with none
    /// left — forgotten, so its next announcement makes it wanted again.
    fn announcer_failed(&mut self, id: &[u8; 32]) {
        let Some(pos) = self.wants.iter().position(|w| &w.id == id) else { return };
        let w = &mut self.wants[pos];
        if !w.announcers.is_empty() {
            w.announcers.remove(0);
        }
        w.asked_ms = None;
        if w.announcers.is_empty() {
            self.wants.remove(pos);
            self.forget(id);
        }
    }

    /// An answer page after its tag (`id ‖ [len ‖ bytes]`).
    pub fn on_answer(&mut self, body: &[u8]) -> Answer {
        if body.len() < 32 {
            return Answer::Unasked;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&body[..32]);
        let Some(pos) = self.wants.iter().position(|w| w.id == id && w.asked_ms.is_some()) else {
            return Answer::Unasked;
        };
        let (lane, len) = (self.wants[pos].lane, self.wants[pos].len);
        let rest = &body[32..];
        let carried = (rest.len() >= 4)
            .then(|| (u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize, &rest[4..]))
            .filter(|(l, bytes)| *l == len && bytes.len() == len && id_of(lane, bytes) == id);
        match carried {
            Some((_, bytes)) => {
                self.wants.remove(pos);
                Answer::Body { lane, id, bytes: bytes.to_vec() }
            }
            None => {
                self.announcer_failed(&id);
                Answer::Refused
            }
        }
    }

    /// Serve one ask: the tag and the id, then `len ‖ bytes` when this buffer holds the body.
    #[must_use]
    pub fn serve(&self, req: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32);
        out.extend_from_slice(SEALED_BODY_TAG);
        if !is_ask(req) {
            out.extend_from_slice(&[0u8; 32]);
            return out;
        }
        out.extend_from_slice(&req[1..]);
        if let Some(h) = self.held.iter().find(|h| h.id[..] == req[1..]) {
            out.extend_from_slice(&(h.bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&h.bytes);
        }
        out
    }

    /// Housekeeping, on the lane's tick: a body past its hold time leaves; an ask unanswered past the re-arm moves to
    /// its next announcer.
    pub fn sweep(&mut self, now_ms: u64) {
        while self.held.front().is_some_and(|h| now_ms.saturating_sub(h.at_ms) >= SEALED_HELD_MS) {
            if let Some(old) = self.held.pop_front() {
                self.held_bytes -= old.bytes.len();
            }
        }
        let stale: Vec<[u8; 32]> = self
            .wants
            .iter()
            .filter(|w| w.asked_ms.is_some_and(|t| now_ms.saturating_sub(t) >= SEALED_ASK_REARM_MS))
            .map(|w| w.id)
            .collect();
        for id in stale {
            self.announcer_failed(&id);
        }
    }

    /// Bytes held now (this node's own buffer; the status line's figure).
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.held_bytes
    }

    /// Bodies wanted now, asked or waiting.
    #[must_use]
    pub fn wanted(&self) -> usize {
        self.wants.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add((i % 251) as u8)).collect()
    }

    /// Answer `req` from `server` and hand the page (after its tag) to `asker`, as the bulk lane would.
    fn pull(server: &SealedBodies, asker: &mut SealedBodies, req: &[u8]) -> Answer {
        let page = server.serve(req);
        assert_eq!(&page[..8], SEALED_BODY_TAG);
        asker.on_answer(&page[8..])
    }

    /// ⭐ TWO BUFFERS, ONE BODY: the sender holds and announces; the peer wants it once, asks the announcer, takes the
    /// bytes its id names, and — once its lane accepted them — holds and announces in turn, so a third node pulls from
    /// either. Then every refusal this door owes:
    /// - a second inventory for a seen id wants nothing; an inventory of the wrong length, or naming a size this door
    ///   does not carry, is no inventory;
    /// - an answer for an id never asked is dropped undecoded;
    /// - a `notfound`, bytes of another body, bytes of the wrong length and a body moved by one bit are each REFUSED,
    ///   and the id is then wanted from the next announcer, or again when it is next announced;
    /// - an id cannot be replayed onto another lane.
    /// TWO-PARTY-REVIEWED: sender, relay and third node are separate buffers; every assertion is on what the receiving
    /// buffer holds or hands to its lane.
    #[test]
    fn speed_sealed_a_body_is_announced_pulled_once_checked_and_relayed_and_every_wrong_answer_is_refused() {
        let (mut a, mut b, mut c) = (SealedBodies::new(), SealedBodies::new(), SealedBodies::new());
        let msg = body(7, SEALED_MIN_BYTES + 1000);
        let announce = a.hold(SEALED_LANE_DEFI, msg.clone(), 1_000).expect("a size this door carries");
        assert_eq!(announce.len(), SEALED_INV_BYTES);
        let id = id_of(SEALED_LANE_DEFI, &msg);

        // the peer wants it once
        assert!(b.on_inv(&announce, Some(1)), "a never-seen body is wanted");
        assert!(!b.on_inv(&announce, Some(1)), "⛔ the same inventory wanted the body twice");
        assert!(!a.on_inv(&announce, Some(2)), "⛔ the sender wanted its own body back");
        let asks = b.next_asks(2_000);
        assert_eq!(asks, vec![(ask(&id), Some(1))], "one ask, aimed at the announcer");
        assert!(b.next_asks(2_001).is_empty(), "⛔ an outstanding ask was sent again");
        match pull(&a, &mut b, &asks[0].0) {
            Answer::Body { lane, id: got, bytes } => {
                assert_eq!((lane, got), (SEALED_LANE_DEFI, id));
                assert_eq!(bytes, msg, "the bytes handed to the lane are the sender's");
                // its lane accepted it: the relay holds and announces the same inventory
                assert_eq!(b.hold(lane, bytes, 2_500), Some(announce.clone()));
            }
            other => panic!("the announced body was not delivered: {other:?}"),
        }
        assert_eq!(b.wanted(), 0);
        // a third node pulls from the relay
        assert!(c.on_inv(&announce, Some(9)));
        let asks_c = c.next_asks(3_000);
        assert!(matches!(pull(&b, &mut c, &asks_c[0].0), Answer::Body { .. }), "the relay serves what it holds");

        // malformed inventories
        let mut d = SealedBodies::new();
        assert!(!d.on_inv(&announce[..SEALED_INV_BYTES - 1], Some(1)), "⛔ a short inventory was taken");
        assert!(!d.on_inv(&inv(SEALED_LANE_DEFI, &id, SEALED_MIN_BYTES - 1), Some(1)), "⛔ a size below this door's was wanted");
        assert!(!d.on_inv(&inv(SEALED_LANE_DEFI, &id, SEALED_BODY_BYTES_MAX + 1), Some(1)), "⛔ a size past one frame was wanted");
        assert_eq!(d.wanted(), 0);

        // an answer nobody asked for
        let page = a.serve(&ask(&id));
        assert_eq!(d.on_answer(&page[8..]), Answer::Unasked, "⛔ an unasked answer was decoded");

        // refusals: two announcers, the first lies in four ways; each time the id moves on or is forgotten
        let other = body(9, msg.len());
        let mut liar = SealedBodies::new();
        liar.hold(SEALED_LANE_DEFI, other.clone(), 1_000);
        let wrong_bytes = {
            let mut p = SEALED_BODY_TAG.to_vec();
            p.extend_from_slice(&id);
            p.extend_from_slice(&(other.len() as u32).to_le_bytes());
            p.extend_from_slice(&other);
            p
        };
        let moved_bit = {
            let mut p = a.serve(&ask(&id));
            let last = p.len() - 1;
            p[last] ^= 1;
            p
        };
        let wrong_len = {
            let mut p = SEALED_BODY_TAG.to_vec();
            p.extend_from_slice(&id);
            p.extend_from_slice(&((msg.len() - 1) as u32).to_le_bytes());
            p.extend_from_slice(&msg[..msg.len() - 1]);
            p
        };
        let notfound = liar.serve(&ask(&id));
        assert!(is_notfound(&ask(&id), &notfound), "a buffer that does not hold the id answers the tag and the id alone");
        for (what, page) in [("another body's bytes", wrong_bytes), ("a body moved by one bit", moved_bit), ("a shorter body", wrong_len), ("a notfound", notfound)] {
            let mut e = SealedBodies::new();
            assert!(e.on_inv(&announce, Some(1)));
            assert!(!e.on_inv(&announce, Some(2)), "a second announcer adds no second want");
            assert_eq!(e.next_asks(10).len(), 1);
            assert_eq!(e.on_answer(&page[8..]), Answer::Refused, "⛔ {what} was accepted for the announced id");
            // the id is asked of the second announcer, which serves the real body
            let again = e.next_asks(20);
            assert_eq!(again, vec![(ask(&id), Some(2))], "after {what}: the id moves to its next announcer");
            assert!(matches!(pull(&a, &mut e, &again[0].0), Answer::Body { .. }), "after {what}: the honest announcer's body is taken");
            // with ONE announcer the id is forgotten, and wanted again when next announced
            let mut f = SealedBodies::new();
            assert!(f.on_inv(&announce, Some(1)));
            let _ = f.next_asks(10);
            assert_eq!(f.on_answer(&page[8..]), Answer::Refused);
            assert_eq!(f.wanted(), 0);
            assert!(f.on_inv(&announce, Some(3)), "after {what} from its only announcer the id is wanted again when next announced");
        }

        // an id is its lane's: the same bytes on another lane are another id, so an inventory cannot move a body across
        assert_ne!(id_of(SEALED_LANE_DEFI, &msg), id_of(SEALED_LANE_DEFI + 1, &msg));
        let mut g = SealedBodies::new();
        assert!(g.on_inv(&inv(SEALED_LANE_DEFI + 1, &id, msg.len()), Some(1)));
        let asks_g = g.next_asks(10);
        assert_eq!(pull(&a, &mut g, &asks_g[0].0), Answer::Refused, "⛔ a body was accepted under another lane's inventory");
    }

    /// The bounds hold: the relay buffer never passes its byte bound (the oldest body leaves first, and is then
    /// answered `notfound`), a body leaves at its hold time, at most one ask per bulk lane is outstanding, a waiting
    /// list past its bound drops its oldest (which is wanted again when re-announced), an unanswered ask moves on at
    /// the re-arm, and the seen ring stays inside its bound under a flood of distinct ids.
    #[test]
    fn speed_sealed_every_store_stays_inside_its_bound() {
        let mut a = SealedBodies::new();
        let big = SEALED_HELD_BYTES_MAX / 3;
        let firsts: Vec<Vec<u8>> = (0..5u8).map(|i| body(i, big + usize::from(i))).collect();
        for (i, m) in firsts.iter().enumerate() {
            assert!(a.hold(SEALED_LANE_DEFI, m.clone(), 1_000 + i as u64).is_some());
            assert!(a.held_bytes() <= SEALED_HELD_BYTES_MAX, "⛔ the buffer holds {} byte(s), past its bound", a.held_bytes());
        }
        let oldest = id_of(SEALED_LANE_DEFI, &firsts[0]);
        let newest = id_of(SEALED_LANE_DEFI, &firsts[4]);
        assert!(is_notfound(&ask(&oldest), &a.serve(&ask(&oldest))), "the oldest body left the buffer");
        assert!(!is_notfound(&ask(&newest), &a.serve(&ask(&newest))), "the newest body is served");
        a.sweep(1_004 + SEALED_HELD_MS);
        assert_eq!(a.held_bytes(), 0, "⛔ a body outlived its hold time");

        // asks: one per bulk lane at once; the rest wait
        let mut b = SealedBodies::new();
        for i in 0..(SEALED_PULLS_MAX + 3) {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            id[1] = 0xA5;
            assert!(b.on_inv(&inv(SEALED_LANE_DEFI, &id, SEALED_MIN_BYTES), Some(1)));
        }
        let first = b.next_asks(100);
        assert_eq!(first.len(), SEALED_PULLS_MAX, "one ask per bulk lane");
        assert!(b.next_asks(101).is_empty(), "⛔ more asks left than the lanes hold");
        // a refused ask waits again; an unanswered one moves on at the re-arm (its only announcer: forgotten)
        b.ask_did_not_leave(&first[0].0);
        assert_eq!(b.next_asks(102).len(), 1, "an ask the lane refused is sent again");
        b.sweep(102 + SEALED_ASK_REARM_MS);
        assert_eq!(b.wanted(), 3, "the unanswered asks' ids are forgotten; the waiting ones remain");
        assert_eq!(b.next_asks(200_000).len(), 3);

        // the waiting list and the seen ring under a flood of distinct ids
        let mut c = SealedBodies::new();
        let mut first_id = [0u8; 32];
        for i in 0..(SEALED_SEEN_MAX + SEALED_WANTS_MAX + 50) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            if i == 0 {
                first_id = id;
            }
            c.on_inv(&inv(SEALED_LANE_DEFI, &id, SEALED_MIN_BYTES), Some(1));
            assert!(c.wanted() <= SEALED_WANTS_MAX);
            assert!(c.seen.len() <= SEALED_SEEN_MAX && c.seen_set.len() == c.seen.len());
        }
        assert!(c.on_inv(&inv(SEALED_LANE_DEFI, &first_id, SEALED_MIN_BYTES), Some(1)), "a want dropped at the bound is wanted again when re-announced");
        // the seen ring itself, filled past its bound: the oldest id leaves, the set and the ring stay one size
        let mut d = SealedBodies::new();
        for i in 0..(SEALED_SEEN_MAX + 10) {
            let mut id = [0xEEu8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            d.remember(id);
        }
        assert_eq!(d.seen.len(), SEALED_SEEN_MAX, "⛔ the seen ring passed its bound");
        assert_eq!(d.seen_set.len(), SEALED_SEEN_MAX);
        let mut zeroth = [0xEEu8; 32];
        zeroth[..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(!d.seen_set.contains(&zeroth), "the oldest id left the ring");
    }
}

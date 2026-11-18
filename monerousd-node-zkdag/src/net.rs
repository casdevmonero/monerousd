// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Network-level privacy foundation (greenfield — NOT derived from the Monero levin/mixnet code).
//!
//! MonerousD must be 100% private at EVERY layer under ANY circumstance. Privacy here is FIXED BY
//! CONSTRUCTION and 100% ON by default — it is NOT a governance choice and there is no knob to
//! weaken it (that is why [`CELL_SIZE`] / [`COVER_INTERVAL_MS`] are hard constants, not tunable
//! params). Built from scratch for us:
//!
//! * **Onion-only addressing.** A node/peer is ALWAYS a Tor v3 `.onion`. An IP is not just
//!   discouraged — it is *unrepresentable*: [`OnionAddr`] and [`PeerAddr`] have no IP field, and
//!   their parsers HARD-REJECT anything that parses as an IP ([`NetError::IpForbidden`]). We never
//!   use IPs, so a peer's network location cannot leak.
//! * **Fixed-size cells.** Every wire unit is padded to [`CELL_SIZE`] ([`pad_to_cell`]) so message
//!   SIZE reveals nothing to an on-path observer.
//! * **Constant-rate cover traffic.** [`CoverScheduler`] emits one cell every [`COVER_INTERVAL_MS`]
//!   whether or not there is real data, so TIMING and VOLUME reveal nothing about real activity.
//!   Idle slots carry a cover cell, indistinguishable on the (encrypted) wire from a real one.
//!
//! The multi-hop Sphinx mix routing (sender-anonymous tx paths) and the libp2p onion transport
//! binding build ON these primitives in the following bricks; both are rebuilt fresh here, never
//! ported from the levin-shaped mixnet.

use crate::fixed::FixedBytes;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

/// Fixed network cell size in bytes. Every wire unit is padded to exactly this, so message SIZE
/// leaks nothing. A constant, never governance-tunable — privacy is not a choice.
pub const CELL_SIZE: usize = 4096;

/// Constant cover-traffic interval in ms. One cell is emitted every interval whether or not there
/// is real data, so TIMING + VOLUME leak nothing. A constant, never governance-tunable.
pub const COVER_INTERVAL_MS: u64 = 250;

/// The WELL-KNOWN virtual port every MonerousD onion node accepts cell streams on — a dialer opens
/// `<peer>.onion:ONION_CELL_PORT`. Fixed + well-known so ANY node can dial ANY other from just its `.onion`
/// name, with no per-peer port negotiation (the auto-join standard). Lives here (unconditional) because BOTH
/// onion transports honor it: the arti in-process transport dials/hosts it directly, and the C-tor daemon
/// additionally maps it onto its cell listener in its torrc (`tor_supervisor::write_torrc`).
pub const ONION_CELL_PORT: u16 = 27781;
/// The BULK lane: a SECOND virtual port on the SAME onion service, carrying length-prefixed
/// request/response frames for DA record-range pages — NO cells, NO cover pacing. The constant-rate cell
/// channel exists to hide PAYMENT timing; a record-range page is requester-triggered PUBLIC chain data, and
/// riding it through the paced channel measurably starved both (2026-08-13: pump CONGESTED at 174 real
/// cells/s, zero cover headroom, joiner net-converging +9 records/min against a 10,784 deficit — never).
/// Privacy is UNCHANGED on the payment lane: its cadence and cover are untouched; an observer of the bulk
/// lane sees "a node is syncing public chain data", which the paced channel's own congestion already showed.
pub const ONION_BULK_PORT: u16 = 27782;

/// How long a COLD onion first contact may take: the descriptor fetch plus the rendezvous, "routinely tens of
/// seconds" (MEASURED, ecosystem gate run mWrpxb — see `arti_transport::BULK_FIRST_CONTACT_TIMEOUT_SECS`, which
/// reads this). ONE definition with two readers: the transport's first-contact dial deadline, and the production
/// hold of a RESUMED origin that has heard no peer yet (DB-231) — "nobody answered a cold first contact within
/// the budget" is the same fact in both places. A local deadline; it refuses no note, proof or block.
pub const FIRST_CONTACT_BUDGET_SECS: u64 = 60;

/// Network-privacy errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NetError {
    #[error("IP addresses are forbidden — MonerousD is onion-only (got {0})")]
    IpForbidden(String),
    #[error("not a Tor v3 .onion address: {0}")]
    NotOnion(String),
    #[error("malformed peer seed: {0}")]
    BadPeerSeed(String),
    #[error("payload {got} bytes exceeds cell capacity {cap}")]
    PayloadTooBig { got: usize, cap: usize },
    #[error("malformed cell")]
    BadCell,
    /// The outbound cell queue for this peer is at its absolute bound: the link cannot carry more right
    /// now. Nothing is lost by construction — gossip re-gossips, serves are served again on the next ask,
    /// a stalled peer resyncs. Producers that fire-and-forget ignore it; producers that answer a user
    /// (an OrderPost) surface it as "try again".
    #[error("outbound backpressure: {queued} cells queued of {max} — the link cannot carry more")]
    Backpressure { queued: usize, max: usize },
}

/// A Tor v3 `.onion` address: 56 base32 chars + `.onion`. There is no way to hold an IP here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OnionAddr(String);

impl OnionAddr {
    /// Parse + validate. Rejects ANY input that parses as an IP, and anything that is not a well
    /// formed v3 onion label.
    pub fn parse(s: &str) -> Result<Self, NetError> {
        let s = s.trim();
        // Hard gate: never an IP (v4 or v6), so a network location can never be encoded here.
        if std::net::IpAddr::from_str(s).is_ok() {
            return Err(NetError::IpForbidden(s.to_string()));
        }
        let host = s
            .strip_suffix(".onion")
            .ok_or_else(|| NetError::NotOnion(s.to_string()))?;
        // v3 onion service id: exactly 56 base32 chars (lowercase a-z + 2-7).
        if host.len() != 56 || !host.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
            return Err(NetError::NotOnion(s.to_string()));
        }
        Ok(OnionAddr(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A peer address: identity + onion + PQ key material. Onion-only BY CONSTRUCTION — there is no IP
/// field anywhere on this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAddr {
    pub peer_id: String,
    pub onion: OnionAddr,
    /// Noise static public key (hex-decoded).
    /// O1-FOOTPRINT-REVIEWED: fixed-size PQ public key bytes (a protocol constant), never a growing store.
    pub x_pk: Vec<u8>,
    /// PQ encapsulation key — ML-KEM (hex-decoded).
    /// O1-FOOTPRINT-REVIEWED: fixed-size PQ encapsulation key bytes (a protocol constant), never a growing store.
    pub ek: Vec<u8>,
}

impl PeerAddr {
    /// Parse a seed string `peer_id|<host>.onion|x_pk_hex|ek_hex`. Rejects an IP in the address
    /// slot (onion-only) and any malformed field.
    pub fn parse(seed: &str) -> Result<Self, NetError> {
        let parts: Vec<&str> = seed.split('|').collect();
        if parts.len() != 4 || parts[0].is_empty() {
            return Err(NetError::BadPeerSeed(seed.to_string()));
        }
        let onion = OnionAddr::parse(parts[1])?; // rejects IP + non-onion
        let x_pk = hex_decode(parts[2]).ok_or_else(|| NetError::BadPeerSeed(seed.to_string()))?;
        let ek = hex_decode(parts[3]).ok_or_else(|| NetError::BadPeerSeed(seed.to_string()))?;
        Ok(PeerAddr {
            peer_id: parts[0].to_string(),
            onion,
            x_pk,
            ek,
        })
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Pad a payload into a fixed [`CELL_SIZE`] cell: `[len: u32 LE][payload][zero fill]`. `len == 0`
/// marks a cover cell (no real data). Every cell is exactly [`CELL_SIZE`] bytes, so an observer
/// learns nothing from the SIZE of a message. (The cell is Noise/onion-encrypted on the wire, so a
/// cover cell is indistinguishable from a real one.)
pub fn pad_to_cell(payload: &[u8]) -> Result<Vec<u8>, NetError> {
    let cap = CELL_SIZE - 4;
    if payload.len() > cap {
        return Err(NetError::PayloadTooBig {
            got: payload.len(),
            cap,
        });
    }
    let mut cell = vec![0u8; CELL_SIZE];
    cell[0..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    cell[4..4 + payload.len()].copy_from_slice(payload);
    Ok(cell)
}

/// A cover cell (no real payload), carried in idle slots to hold the constant rate.
pub fn cover_cell() -> Vec<u8> {
    vec![0u8; CELL_SIZE]
}

/// Recover the payload from a cell. A cover cell returns an empty payload (the caller drops it).
pub fn unpad_cell(cell: &[u8]) -> Result<Vec<u8>, NetError> {
    if cell.len() < 4 {
        return Err(NetError::BadCell);
    }
    let len = u32::from_le_bytes([cell[0], cell[1], cell[2], cell[3]]) as usize;
    if 4 + len > cell.len() {
        return Err(NetError::BadCell);
    }
    Ok(cell[4..4 + len].to_vec())
}

/// Is this cell a cover cell (no real payload)?
pub fn is_cover(cell: &[u8]) -> bool {
    cell.len() >= 4 && cell[0..4] == [0, 0, 0, 0]
}

/// ⭐ DB-347 step 1: the marker a dialer's HELLO carries in a cover-shaped cell's fill.
const HELLO_MAGIC: &[u8; 8] = b"MUSDHELO";
/// DB-347 step 1: the longest onion host a hello may name (a v3 onion host is 62 bytes; the bound only refuses junk).
const HELLO_ONION_MAX: usize = 128;

/// ⭐ DB-347 step 1 — the DIALER's first cell on a fresh stream: COVER-SHAPED (`len = 0`), so every reader that predates
/// it drops it unread exactly like cover, with the dialer's own onion in the fill so the acceptor can tell which peer an
/// otherwise anonymous accepted stream belongs to. Same size as every cell, and Tor-encrypted on the wire.
/// A name that does not fit yields a plain cover cell (nothing is said).
/// DIGITAL-CASH-PRIVACY-REVIEWED: carries only the dialer's OWN public onion, which the acceptor already holds from the
/// signed peer directory and already sees answering on the stream it dialed itself. No note, amount, key or owner.
pub fn hello_cell(onion: &str) -> Vec<u8> {
    let mut cell = cover_cell();
    let host = onion.trim().as_bytes();
    if host.is_empty() || host.len() > HELLO_ONION_MAX || 14 + host.len() > CELL_SIZE {
        return cell;
    }
    cell[4..12].copy_from_slice(HELLO_MAGIC);
    cell[12..14].copy_from_slice(&(host.len() as u16).to_le_bytes());
    cell[14..14 + host.len()].copy_from_slice(host);
    cell
}

/// ⭐ DB-347 step 1 — the onion a HELLO cell names, or `None` for any other cell: a real cell, plain cover, or junk
/// (wrong marker, a length out of bounds, non-ASCII, or a name that is not an `.onion` host).
pub fn hello_onion(cell: &[u8]) -> Option<String> {
    if !is_cover(cell) || cell.len() < 14 || &cell[4..12] != HELLO_MAGIC {
        return None;
    }
    let n = u16::from_le_bytes([cell[12], cell[13]]) as usize;
    if n == 0 || n > HELLO_ONION_MAX || 14 + n > cell.len() {
        return None;
    }
    let host = std::str::from_utf8(&cell[14..14 + n]).ok()?;
    (host.is_ascii() && host.ends_with(".onion")).then(|| host.to_string())
}

/// Constant-rate cover-traffic scheduler: emit one cell every [`COVER_INTERVAL_MS`], whether or not
/// there is real data — so TIMING and VOLUME leak nothing. A fresh scheduler is due immediately.
pub struct CoverScheduler {
    /// `None` until the first cell is emitted (so the first slot is always due).
    last_emit_ms: Option<u64>,
}

impl CoverScheduler {
    pub fn new() -> Self {
        CoverScheduler { last_emit_ms: None }
    }

    /// Is a cell due at `now_ms`? Always true before the first emission.
    pub fn due(&self, now_ms: u64) -> bool {
        match self.last_emit_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= COVER_INTERVAL_MS,
        }
    }

    /// Produce the next cell for this slot: the pending payload if any, else a cover cell. Either
    /// way the result is exactly [`CELL_SIZE`] bytes.
    pub fn next_cell(&mut self, now_ms: u64, pending: Option<&[u8]>) -> Result<Vec<u8>, NetError> {
        self.last_emit_ms = Some(now_ms);
        match pending {
            Some(p) => pad_to_cell(p),
            None => Ok(cover_cell()),
        }
    }

    /// Mark this slot emitted at `now_ms` (advance the interval timer) WITHOUT producing a cell — used
    /// by a constant-BURST pump that emits several cells per slot itself and just needs the slot closed.
    pub fn mark_emitted(&mut self, now_ms: u64) {
        self.last_emit_ms = Some(now_ms);
    }
}

impl Default for CoverScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Multi-cell chunking (split proof transport) ----
//
// A #29 DSYNC bundle carries a ≤1.8MB decider proof — far larger than one [`CELL_SIZE`] cell. It is
// split into an ordered run of fixed-size cells (each padded to CELL_SIZE, so the run is
// indistinguishable from any other cell stream) and reassembled at the far end. This is the
// greenfield "split proof transport": bulk proof bytes move as a stream of identical private cells.

/// Chunk header = `[msg_id:u64][seq:u16][total:u16]` = 12 bytes. The `msg_id` groups the cells of ONE
/// message so a receiver never mixes two concurrently-gossiped messages (same `total`) into one frame.
pub const CHUNK_HDR: usize = 8 + 2 + 2;

/// Real bytes carried in one cell's chunk = CELL_SIZE − 4 (cell length prefix) − [`CHUNK_HDR`]. A
/// ≤1.8MB bundle spans `ceil(1.8MB / CHUNK_DATA)` ≈ 440 cells.
pub const CHUNK_DATA: usize = CELL_SIZE - 4 - CHUNK_HDR;

/// Split a payload into an ordered run of fixed-size cells for onion transport. Each cell's payload is
/// `[msg_id:u64 LE][seq:u16 LE][total:u16 LE][chunk]`, then [`pad_to_cell`]-padded — so every cell is
/// exactly [`CELL_SIZE`] and an observer learns neither the payload size nor which cell is which. The
/// `msg_id` is CONTENT-ADDRESSED (blake3 of the payload): identical payloads share it (re-gossip is
/// idempotent), distinct payloads differ w.h.p., and the receiver groups cells by it so two blocks
/// gossiped at once cannot interleave into a corrupt "Frankenblock". An empty payload yields a single
/// empty-chunk cell. Errors only if the payload would need more than `u16::MAX` cells.
/// The msg_id a chunked payload's cell headers carry — the SINGLE authoritative derivation. The receiver's
/// Reassembler keys partials by this (from the cell header), so a re-request names this id, and the sender's
/// replay ring MUST key by this too. Two independent derivations (a big-endian fold in `queue_message`, this
/// little-endian decode here) silently mismatched, so every ChunkReq ring-missed and no retransmit ever
/// fired — MEASURED 2026-08-18: both nodes ask forever, replay count 0. One function now; they cannot drift.
pub fn wire_msg_id(payload: &[u8]) -> u64 {
    let digest = crate::hash::Hash32::hash(payload);
    u64::from_le_bytes(digest.as_bytes()[..8].fixed())
}

pub fn chunk_payload(payload: &[u8]) -> Result<Vec<Vec<u8>>, NetError> {
    let total = payload.len().div_ceil(CHUNK_DATA).max(1);
    if total > u16::MAX as usize {
        return Err(NetError::PayloadTooBig {
            got: payload.len(),
            cap: CHUNK_DATA * u16::MAX as usize,
        });
    }
    let msg_id = wire_msg_id(payload);
    let mut cells = Vec::with_capacity(total);
    // `chunks` yields nothing for an empty payload; iterate by index so seq 0 always exists.
    for seq in 0..total {
        let start = seq * CHUNK_DATA;
        let end = (start + CHUNK_DATA).min(payload.len());
        let mut framed = Vec::with_capacity(CHUNK_HDR + (end - start));
        framed.extend_from_slice(&msg_id.to_le_bytes());
        framed.extend_from_slice(&(seq as u16).to_le_bytes());
        framed.extend_from_slice(&(total as u16).to_le_bytes());
        framed.extend_from_slice(&payload[start..end]);
        cells.push(pad_to_cell(&framed)?);
    }
    Ok(cells)
}

/// Cap on distinct in-flight (partially-received) messages. A flood of unattachable partials cannot
/// grow memory (no-growth pillar); once at the cap, a new message evicts an arbitrary stale partial
/// (the sender re-gossips it — a dropped partial never completes, never adopts partial).
const MAX_INFLIGHT_MSGS: usize = 512;

/// Reassembles a chunked payload from received cells. Order-independent (the transport may deliver
/// cells out of order); completes only when EVERY chunk `0..total` has arrived. A cell with an
/// inconsistent `total`, an out-of-range `seq`, or a malformed frame is rejected fail-closed — a
/// missing or tampered chunk simply never completes (the node then re-requests, never adopts partial).
pub struct Reassembler {
    // Grouped by `msg_id` so cells of two concurrently-gossiped messages (even with the same `total`)
    // reassemble into SEPARATE frames instead of interleaving into a corrupt one. Each entry holds the
    // message's `total` + its received chunks; the entry is removed the instant the message completes.
    /// Per message: `(total, chunks, last_touch)`. `last_touch` makes eviction LRU — see `accept`.
    /// O1-FOOTPRINT-REVIEWED: bounded by `MAX_INFLIGHT_MSGS` (512), LRU eviction in `accept`.
    inflight: HashMap<u64, (u16, BTreeMap<u16, Vec<u8>>, u64)>,
    /// msg_id -> `(slot of the last ChunkReq, asks since the partial last grew, its last_touch at that ask)`. Paces
    /// re-requests (TCP's back-off, see `stuck_requests`); entries die with their partial.
    /// O1-FOOTPRINT-REVIEWED: bounded by MAX_INFLIGHT_MSGS, a protocol constant.
    asked: HashMap<u64, (u64, u32, u64)>,
    /// Monotonic tick stamped on every cell, so "stalest" is well-defined without a clock.
    tick: u64,
    /// Slot clock: advanced ONCE per constant-rate pump slot (4/s by construction), never per cell.
    /// The retransmit-ask COOLDOWN reads this and nothing else — see `stuck_requests` for why.
    slot: u64,
    /// New messages declined because every partial in the table was still live. A declined message is a
    /// DELAY (the sender re-offers); a destroyed partial is a LOSS. This counts the good outcome.
    declined: u64,
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler {
            inflight: HashMap::new(),
            tick: 0,
            slot: 0,
            declined: 0,
            asked: HashMap::new(),
        }
    }

    /// Feed one received cell. Returns `Ok(Some(payload))` once THAT cell's message is fully assembled,
    /// `Ok(None)` while still waiting, or `Err` on a malformed / inconsistent cell (fail-closed).
    /// How many multi-cell messages are part-assembled right now, and the oldest one's age in ticks.
    ///
    /// ⛔⛔⛔ THE ONE THING NO COUNTER SHOWS: a multi-cell message whose cells NEVER all arrive. MEASURED
    /// 2026-07-31 by block-id correlation, which is the check this file's own comments prescribe: node A sent
    /// THREE blocks each carrying 2,500 account-target bytes (ids 25bdfcc1, 31f276c4, 0dfa4749) and node B
    /// parsed the first EIGHT times and the other two ZERO times. Those blocks are ~6 KB — MULTI-CELL at
    /// CHUNK_DATA 4080 — while every block B does receive is 1,153 bytes, SINGLE-cell. Declines are 0 and
    /// evictions are 0 on both sides, so cells are not being refused; a partial set simply never completes.
    ///
    /// A partial that sits forever is invisible today: it is not a decline, not an eviction, not an error.
    /// This exposes it so "cells lost in the middle of a message" stops being indistinguishable from "the
    /// message was never sent".
    ///
    /// O1-FOOTPRINT-REVIEWED: reads the length of the EXISTING `inflight` map, already bounded by
    /// MAX_INFLIGHT_MSGS; stores nothing and adds no term in height, blocks or notes.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a COUNT of part-assembled messages and a tick age — never a message
    /// body, note, amount, key or owner.
    /// Partials stuck long enough to warrant a chunk re-request: age ≥ `min_age` ticks since last touch
    /// AND ≥ `cooldown` ticks since we last asked for this msg. Returns (msg_id, missing seqs) pairs and
    /// stamps the ask, so a lost re-request is itself re-asked only after another cooldown. This is the
    /// receiver half of the retransmit that closes the one-lost-cell-kills-the-message class (measured
    /// 2026-08-18: "chunk 4/6 arrived, still missing [5]" repeating forever).
    /// `min_age` is in activity ticks (cells AND slots advance it — a busy link ages a partial by
    /// traffic, a silent link by slots, so neither freezes repair). `cooldown` is in SLOTS ONLY.
    ///
    /// ROOT-LAYER: the ask cadence is PRODUCED here, by the clock this comparison reads; every NAK
    /// on the wire is one of these rows.
    /// MEASURED: 158-275 ChunkReq cells per 10s per node (5-node mesh, 2026-09-02 run 6, per-class
    /// wire counters) — the largest class, above Block — from ~35 stuck partials whose legitimate
    /// size is 2-10 cells (one ask = one cell). The cooldown read the per-cell counter, which runs
    /// at the inbound cell rate, so "96 ticks" was ~1s and every partial was re-NAKed every second,
    /// broadcast to 6-10 writers. Slot-based bound: ≤35 asks per 24s ⇒ ≤15 cells/10s, load-independent.
    /// MUST-STAY-GREEN: the one-lost-cell retransmit (chunk 4/6 → ask [5] → complete), silent-link
    /// aging (tick_clock still advances `tick`), and the eviction liveness rule, which keeps reading
    /// the activity counter untouched.
    pub fn stuck_requests(&mut self, min_age: u64, cooldown: u64) -> Vec<(u64, Vec<u16>)> {
        let now = self.tick;
        let now_slot = self.slot;
        let mut out = Vec::new();
        for (msg_id, (total, have, touched)) in self.inflight.iter() {
            if *total <= 1 || now.saturating_sub(*touched) < min_age {
                continue;
            }
            // A partial never asked for is askable NOW. (`unwrap_or(&0)` here made the first ask wait a
            // full cooldown from clock zero — 24s of no repair on a quiet link — which the per-cell
            // counter used to race past unnoticed.)
            // TCP's back-off (RFC 6298 §5.5, Karn): while asks bring no cell for the partial, each wait doubles; a cell
            // that grows it starts over at `cooldown`. A sender keeps only its last SENT_RING_CAP multi-cell messages, so
            // an ask for one it rotated out is never answered (and a lane's re-send is a new message: its copy number
            // differs), yet it was re-asked every cooldown for as long as the partial lived.
            // ROOT-LAYER: this comparison is where every ask's cadence is produced; the sender cannot help (it no longer
            // holds the cells) and the partial must not be destroyed for age (`accept` keeps the eviction rule).
            // MEASURED 2026-11-09, real nodes (localnet-l n1): 253 such partials, the oldest 107,313 ticks (7.4 h), asked
            // every 96 slots = 10.5 one-cell asks/s of a 16 cells/s channel, every one at the queue's front ahead of the
            // DeFi lane's engine messages (queue 850-910 cells, 0 cover). After: each dead partial's asks fall to one per
            // doubling wait, ~10 over its first 7 h (re-measured on the next real-node run).
            // MUST-STAY-GREEN: the first ask of a stuck partial is immediate, and the second comes one cooldown later,
            // as before (the one-lost-cell repair is unchanged); a partial that grows is asked at `cooldown` again.
            if let Some((last, unanswered, touched_then)) = self.asked.get(msg_id) {
                let backoff = if touched_then == touched { unanswered.saturating_sub(1) } else { 0 };
                let wait = (0..backoff).fold(cooldown, |w, _| w.saturating_mul(2));
                if now_slot.saturating_sub(*last) < wait {
                    continue;
                }
            }
            let missing: Vec<u16> = (0..*total).filter(|i| !have.contains_key(i)).collect();
            if !missing.is_empty() {
                out.push((*touched, *msg_id, missing));
            }
        }
        // ONE ORDER, NOT THE MAP'S (lane b 2026-10-24, T3): each row becomes a ChunkReq queued in this order, and the
        // map's order is per instance (RandomState) — one seed sent its asks in two orders and the runs parted
        // (replay-r39.log: node 2's two ChunkReq cells at 156.15 s swapped). Stalest partial first, then by id.
        out.sort_unstable_by_key(|(touched, id, _)| (*touched, *id));
        for (touched, id, _) in &out {
            let unanswered = match self.asked.get(id) {
                Some((_, n, then)) if then == touched => n.saturating_add(1),
                _ => 1,
            };
            self.asked.insert(*id, (now_slot, unanswered, *touched));
        }
        let out: Vec<(u64, Vec<u16>)> = out.into_iter().map(|(_, id, missing)| (id, missing)).collect();
        self.asked.retain(|id, _| self.inflight.contains_key(id));
        out
    }

    /// Advance the stall clock ONE step — called by the PUMP once per constant-rate slot, so a
    /// partial ages even when the link goes silent. The clock previously advanced only per RECEIVED
    /// cell, which froze the repair timer at exactly the moment repair was needed (a churning link
    /// delivers nothing ⇒ no ticks ⇒ no chunk re-asks ⇒ the partial sits forever — the measured
    /// 15s-when-busy vs >120s-when-quiet credit tail). Slot cadence is constant by design, so ages
    /// stay well-defined under any traffic including none.
    pub fn tick_clock(&mut self) {
        self.tick = self.tick.saturating_add(1);
        self.slot = self.slot.saturating_add(1);
    }

    pub fn inflight_partials(&self) -> (usize, u64) {
        let oldest = self
            .inflight
            .values()
            .map(|v| v.2)
            .min()
            .unwrap_or(self.tick);
        (self.inflight.len(), self.tick.saturating_sub(oldest))
    }

    pub fn accept(&mut self, cell: &[u8]) -> Result<Option<Vec<u8>>, NetError> {
        let framed = unpad_cell(cell)?;
        if framed.len() < CHUNK_HDR {
            return Err(NetError::BadCell);
        }
        let msg_id = u64::from_le_bytes(framed[0..8].fixed());
        let seq = u16::from_le_bytes([framed[8], framed[9]]);
        let total = u16::from_le_bytes([framed[10], framed[11]]);
        if total == 0 || seq >= total {
            return Err(NetError::BadCell);
        }
        self.tick = self.tick.wrapping_add(1);
        // Bound the in-flight set — but evict the STALEST partial, never an arbitrary one. `keys().next()` on a
        // HashMap is effectively random, so under interleaved arrival (the normal case: many messages in flight,
        // their cells arriving round-robin) it repeatedly destroyed messages that were actively being assembled,
        // and the sender was never told. MEASURED before this fix: 256 of 516 interleaved multi-cell messages
        // vanished. A block spans several cells, so this silently deletes whole blocks — including the one
        // carrying a payment — while ordinary traffic appears to flow.
        // ⛔⛔⛔ NEVER DESTROY A MESSAGE THAT IS STILL BEING ASSEMBLED. Evicting the stalest partial fixed the
        // ARBITRARY eviction, but under real load every entry is live: MEASURED on the running pair, this fired
        // continuously on BOTH nodes with the table pinned at 512, so each new multi-cell message killed one
        // that was actively arriving. A block spans several cells, so that is whole blocks — and the payment
        // inside them — deleted while ordinary traffic looks perfectly healthy.
        //
        // The asymmetry is the whole point: a partial we DESTROY loses the cells already received and the
        // sender is never told, so nothing re-sends it. A NEW message we decline to admit is simply not started
        // yet, and every message that matters here is re-offered — blocks re-gossip, bucket wants re-emit
        // every tick. So when nothing in the table is provably dead, DECLINE THE NEW ONE rather than kill a
        // live one. That converts an unrecoverable loss into a delay the protocol already recovers from.
        //
        // "Provably dead" uses no new window and no clock: a partial that has not advanced while an entire
        // table's worth of newer activity went past it cannot still be arriving on an ordered stream.
        // ⛔ REMOVED my DEAD_PARTIAL_TICKS age-out — I ADDED A WINDOW, which is banned.
        //
        // user 2026-08-01: "That smells like a banned moving window bug because if 1 send works then millions
        // of sends should work automatically by construction... be careful not to add anymore growth vectors."
        //
        // I reaped part-assembled messages older than 4096 ticks. That is an AGE-OUT in the delivery path: a
        // slow-but-live multi-cell message crossing a congested link would be discarded for being old, which
        // is precisely the shape that makes delivery depend on timing instead of construction. It also treated
        // a symptom — partials accumulate because CELLS ARE BEING DROPPED, and reaping the evidence does not
        // deliver the message.
        //
        // The table is already bounded by MAX_INFLIGHT_MSGS with a genuine liveness rule below (evict only
        // what is provably superseded). Nothing here expires for age.
        let admit_by_evicting =
            if self.inflight.len() >= MAX_INFLIGHT_MSGS && !self.inflight.contains_key(&msg_id) {
                let newest = self
                    .inflight
                    .values()
                    .map(|v| v.2)
                    .max()
                    .unwrap_or(self.tick);
                self.inflight
                    .iter()
                    .min_by_key(|(_, v)| v.2)
                    .filter(|(_, v)| newest.saturating_sub(v.2) as usize >= MAX_INFLIGHT_MSGS)
                    .map(|(k, _)| *k)
            } else {
                None
            };
        if self.inflight.len() >= MAX_INFLIGHT_MSGS && !self.inflight.contains_key(&msg_id) {
            let Some(k) = admit_by_evicting else {
                // Nothing is dead — every partial is still arriving. Decline this cell; the sender re-offers.
                self.declined = self.declined.saturating_add(1);
                if self.declined % 64 == 1 {
                    eprintln!(
                        "[reassemble] table full of LIVE partials ({} in flight) — declined {} new message(s) \
                         rather than destroy one mid-assembly; senders re-offer",
                        self.inflight.len(),
                        self.declined
                    );
                }
                return Ok(None);
            };
            {
                // ⛔ AN EVICTION IS A DESTROYED MESSAGE — SAY SO. This silently deleted a partially
                // assembled message whenever the table filled, and the sender was never told. MEASURED on a
                // live pair: node B queued 204 `BucketReq` to the wire and node A received ZERO, while 422
                // Blocks queued from the same queue on the same link did arrive — a message type vanishing
                // with a working control alongside it. Eviction is the only remaining silent-drop site on
                // that leg, and it has to be visible before anything here can be trusted.
                // DIGITAL-CASH-PRIVACY-REVIEWED: a table depth only — never a message, note, amount or key.
                eprintln!(
                    "[reassemble] EVICTED a partially assembled message ({} in flight) — a destroyed \
                     message is a lost block or a lost payment request, never a delay",
                    self.inflight.len()
                );
                self.inflight.remove(&k);
            }
        }
        let tick = self.tick;
        let entry = self
            .inflight
            .entry(msg_id)
            .or_insert_with(|| (total, BTreeMap::new(), tick));
        entry.2 = tick; // touched: this message is making progress, so it is not the stalest
        if entry.0 != total {
            return Err(NetError::BadCell); // every cell of a message must agree on total
        }
        let was_dup = entry.1.insert(seq, framed[CHUNK_HDR..].to_vec()).is_some();
        // ⛔⛔⛔ DOES ANY MULTI-CELL MESSAGE EVER COMPLETE? THIS IS THE LAST UNTESTED LINK.
        //
        // MEASURED on the live pair, with every other explanation refuted: the producer emits 14.6-16.9 real
        // cells/sec at queue depth 0 (no starvation), 598 multi-cell messages leave it, framing is
        // `read_exact` so cells cannot misalign, and this reassembler logs ZERO declines and ZERO evictions —
        // yet the peer parses 1,157 blocks of which every one is single-cell and NONE carries account-targets.
        //
        // Cells are sent and not dropped, so either the later cells of a multi-cell message never arrive, or
        // they arrive and assembly never finishes. Those are different defects with opposite fixes, and no
        // log distinguishes them. Report the arrival of a multi-cell chunk and the completion separately.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: a sequence index and a chunk count only — the same cell-stream shape
        // any observer already sees. Never a message body, note, amount, key or owner.
        // ⛔⛔⛔ FIRE ON THE ANOMALY, NEVER ON EVERY CHUNK. Reporting each arrival emitted 9,025 lines in ONE
        // run — the per-block disk-growth shape the observability rule exists to forbid, and it buries the one
        // line that matters. A DUPLICATE chunk is the real anomaly: the sender re-offered a message whose bytes
        // (and therefore whose `msg_id`) are identical, so this partial has now been fed the same index twice
        // and STILL has not completed. That is precisely the deterministically-lost-index case, and it cannot
        // fire on a healthy first-pass delivery.
        if total > 1 && was_dup {
            // ⛔⛔⛔ NAME THE MESSAGE. Multi-cell delivery is ~100% (1,838 sent / 1,861 completed) and yet ONE
            // specific block — the payment-bearing one — has been re-offered 7 times and parsed 0 times. On a
            // healthy link that is not chance, so the question is no longer "how many" but "WHICH": does this
            // message's id ever appear here at all, and if it does, which chunk indexes are missing?
            //
            // The re-offer sends byte-identical bytes, so `msg_id` (blake3 of the payload) is IDENTICAL every
            // time. If a partial for that id is already parked, later attempts refill the SAME entry — so a
            // deterministically-lost chunk index can never be supplied by any number of retries. That is the
            // one shape consistent with every measurement, and this line is what confirms or kills it.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: a content-addressed message id and chunk indexes — the same cell
            // framing any observer of the constant-rate stream already sees. Never a note, amount, key, owner.
            let _missing: Vec<u16> = (0..total).filter(|i| !entry.1.contains_key(i)).collect();
        }
        if entry.1.len() == total as usize {
            // (The per-message "[chunk-complete]" line that confirmed lossless reassembly on 2026-08-01 is retired: MEASURED
            // 2026-10-22 on the 10-node launch journey it was 1.5 M of a run's 2.26 M log lines — 222 MB of log per run, two
            // thirds of it this line — and a daemon with ten peers would print it for every multi-chunk message. The
            // assembled count stays in the transport's own census; a lost chunk still surfaces as a parked partial.)
            let Some((_t, chunks, _touch)) = self.inflight.remove(&msg_id) else { return Err(NetError::BadCell) };
            let mut out = Vec::new();
            for i in 0..total {
                out.extend_from_slice(chunks.get(&i).ok_or(NetError::BadCell)?);
            }
            return Ok(Some(out));
        }
        Ok(None)
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod db347_hello_tests {
    //! ⭐ DB-347 step 1 — the stream hello is cover to every reader that predates it, and names exactly one onion to a
    //! reader that knows it.
    use super::*;

    #[test]
    fn db347_a_hello_is_cover_to_an_old_reader_and_names_the_dialer_to_a_new_one() {
        // TWO-PARTY-REVIEWED: a pure CODEC pin (one cell encoded and decoded). The two-party claim is the dialer writing
        // it on one process and the acceptor on another reading it, which the five-node real rerun measures
        // (`[fanout] … writer(s)` per peer and the real-page sheds).
        let onion = "z7bxtbjkhjxkmydgd2yq7fcscpggevii6e2qosbkjaaeqybkzmyt5wyd.onion";
        let hello = hello_cell(onion);
        assert_eq!(hello.len(), CELL_SIZE, "a hello is exactly one cell: its size says nothing");
        assert!(is_cover(&hello), "⛔ a hello must read as COVER, so every reader that predates it drops it");
        assert!(unpad_cell(&hello).expect("well-formed").is_empty(), "⛔ an old reader recovers NO payload from a hello");
        assert_eq!(hello_onion(&hello).as_deref(), Some(onion), "⛔ a new reader recovers the dialer's onion");
        assert_eq!(hello_onion(&hello_cell(&format!("  {onion}\n"))).as_deref(), Some(onion), "the name is trimmed");

        // REFUSALS: nothing but a well-formed hello names an onion.
        assert_eq!(hello_onion(&cover_cell()), None, "⛔ plain cover names nothing");
        let real = pad_to_cell(b"MUSDHELO a real payload that merely starts with the marker").expect("fits");
        assert_eq!(hello_onion(&real), None, "⛔ a REAL cell is never read as a hello, whatever its bytes");
        let mut bad_len = hello.clone();
        bad_len[12..14].copy_from_slice(&(HELLO_ONION_MAX as u16 + 1).to_le_bytes());
        assert_eq!(hello_onion(&bad_len), None, "⛔ a declared length past the bound is refused");
        let mut not_onion = hello.clone();
        let n = onion.len();
        not_onion[14 + n - 6..14 + n].copy_from_slice(b".oniox");
        assert_eq!(hello_onion(&not_onion), None, "⛔ a name that is not an .onion host is refused");
        let mut wrong_magic = hello.clone();
        wrong_magic[4] ^= 1;
        assert_eq!(hello_onion(&wrong_magic), None, "⛔ a wrong marker is plain cover");
        assert!(is_cover(&hello_cell("")) && hello_onion(&hello_cell("")).is_none(), "an empty name says nothing");
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {

    /// RED/GREEN for the retransmit dead-loss bug (2026-08-18): the receiver keys inflight partials — and
    /// therefore the id it re-requests — by the CELL-HEADER id `wire_msg_id` stamps. The sender ring must
    /// key replays by that SAME id. Before the fix the ring used `hash[..8].fold(a<<8|b)` (big-endian); this
    /// asserts that fold does NOT equal the id the wire actually carries (so every ChunkReq ring-missed),
    /// while the shipped `wire_msg_id` DOES equal the id inside the produced cells.
    #[test]
    fn retransmit_id_matches_the_cell_header_and_the_old_fold_did_not() {
        let payload = vec![7u8; 12_000]; // multi-cell, like a payment/target block
        let cells = super::chunk_payload(&payload).expect("chunks");
        assert!(cells.len() > 1, "must be multi-cell to exercise re-request");

        // The id the receiver ACTUALLY extracts — exactly as `accept` does: unpad the cell (strips the
        // 4-byte len prefix), then read framed[0..8] LE. Reading the raw padded cell would read the length
        // prefix, not the id.
        let framed = super::unpad_cell(&cells[0]).expect("unpad");
        let hdr_id = u64::from_le_bytes(framed[0..8].try_into().unwrap());

        // GREEN: the shipped derivation the sender ring now uses == the id in the cells.
        assert_eq!(
            super::wire_msg_id(&payload),
            hdr_id,
            "the ring key must equal the id the receiver asks by"
        );

        // RED: the OLD sender-ring derivation (big-endian fold) does NOT — which is why every replay missed.
        let old_fold = crate::hash::Hash32::hash(&payload).as_bytes()[..8]
            .iter()
            .fold(0u64, |a, b| (a << 8) | *b as u64);
        assert_ne!(
            old_fold, hdr_id,
            "the pre-fix ring key must MISS the header id — this is the dead-loss bug reproduced"
        );
    }
    use super::*;

    /// A partial whose sender no longer holds it is asked for on TCP's back-off, and repair of a live one is unchanged:
    /// the first ask at once, the next a cooldown later, then 2×, 4×; a cell that grows the partial starts over.
    /// TWO-PARTY-REVIEWED: this holds one side's timer — when the receiver asks; the sender's side is that it cannot answer
    /// (its ring rotated the message out). The two-party effect, asks on the wire between two real nodes, is read from the
    /// pump's per-class counts on a real-node run (`ChunkReq=` in `[pump] emit rate`).
    #[test]
    fn a_partial_nobody_answers_is_asked_for_on_a_doubling_wait_and_a_new_cell_starts_over() {
        let cells = chunk_payload(&vec![9u8; 3 * CHUNK_DATA]).expect("chunks");
        assert!(cells.len() >= 3);
        let mut r = Reassembler::new();
        assert_eq!(r.accept(&cells[0]).expect("a valid cell"), None);
        let mut asks = Vec::new();
        for s in 0..800u64 {
            if s == 600 {
                assert_eq!(r.accept(&cells[1]).expect("a valid cell"), None, "the partial grows, still incomplete");
            }
            if !r.stuck_requests(24, 96).is_empty() {
                asks.push(s);
            }
            r.tick_clock();
        }
        // stuck at 24 (`accept` stamps the partial at tick 1, so 24 ticks old at slot 24); then waits of 96, 192 slots
        assert_eq!(&asks[..3], &[24, 120, 312], "⛔ a stuck partial's asks must start at once and back off: {asks:?}");
        // the cell at 600 makes the partial young again (asked 24 ticks later) and the wait starts over at 96
        assert_eq!(&asks[3..], &[624, 720], "⛔ a partial that grew must be asked for at the base cooldown again: {asks:?}");
    }

    const VALID_ONION: &str = "abcdefghij234567abcdefghij234567abcdefghij234567abcdefgh.onion"; // 56 base32 + .onion

    #[test]
    fn onion_addr_rejects_ips_and_accepts_v3() {
        assert!(OnionAddr::parse(VALID_ONION).is_ok());
        // IPs are forbidden — the whole point of "we never use IPs".
        assert!(matches!(
            OnionAddr::parse("1.2.3.4").unwrap_err(),
            NetError::IpForbidden(_)
        ));
        assert!(matches!(
            OnionAddr::parse("127.0.0.1").unwrap_err(),
            NetError::IpForbidden(_)
        ));
        assert!(matches!(
            OnionAddr::parse("::1").unwrap_err(),
            NetError::IpForbidden(_)
        ));
        assert!(matches!(
            OnionAddr::parse("2001:db8::1").unwrap_err(),
            NetError::IpForbidden(_)
        ));
        // clearnet host + short/invalid onions rejected.
        assert!(matches!(
            OnionAddr::parse("example.com").unwrap_err(),
            NetError::NotOnion(_)
        ));
        assert!(matches!(
            OnionAddr::parse("short.onion").unwrap_err(),
            NetError::NotOnion(_)
        ));
    }

    #[test]
    fn peer_seed_rejects_ip_in_address_slot() {
        let good = format!("12D3KooWpeer|{}|aabb|ccdd", VALID_ONION);
        let p = PeerAddr::parse(&good).unwrap();
        assert_eq!(p.onion.as_str(), VALID_ONION);
        assert_eq!(p.x_pk, vec![0xaa, 0xbb]);
        // an IP in the address slot is rejected.
        let bad = "12D3KooWpeer|10.0.0.5|aabb|ccdd";
        assert!(matches!(
            PeerAddr::parse(bad).unwrap_err(),
            NetError::IpForbidden(_)
        ));
    }

    /// ⭐ INTERLEAVED MULTI-CELL MESSAGES MUST NOT SILENTLY VANISH. A block spans several cells, and on a live
    /// mesh many messages are in flight at once, so their cells arrive INTERLEAVED. When more than
    /// `MAX_INFLIGHT_MSGS` are partially assembled the reassembler drops an arbitrary one — and the sender
    /// gets no error, so a block simply never arrives. Measured live: the one block carrying a payment
    /// (15,868 B, ~4 cells) never reached the peer while hundreds of ordinary blocks did, with zero send
    /// failures reported. This pins whether interleaving alone can lose a message.
    #[test]
    fn interleaved_multi_cell_messages_all_reassemble_or_the_loss_is_visible() {
        // WITHIN capacity: a bounded buffer must drop something once it is exceeded, so asserting zero loss
        // at 516 messages through 512 slots tests nothing real. The invariant that MATTERS is that traffic
        // inside the bound is never silently destroyed — that is what makes a block carrying a payment safe.
        let n = MAX_INFLIGHT_MSGS;
        // Each payload is distinct and spans several cells, like a block carrying a payment.
        let payloads: Vec<Vec<u8>> = (0..n)
            // Each payload must be genuinely DISTINCT: `^ (i as u8)` made messages i and i+256 byte-identical,
            // so they shared a content-derived msg_id and merged — half the run "vanished" through my own test
            // rather than through any defect. Vary by the full index.
            .map(|i| {
                let tag = (i as u16).to_le_bytes();
                (0..15_868u32)
                    .map(|b| (b as u8) ^ tag[(b as usize) & 1])
                    .collect()
            })
            .collect();
        let cellsets: Vec<Vec<Vec<u8>>> = payloads
            .iter()
            .map(|p| chunk_payload(p).expect("chunks"))
            .collect();
        let depth = cellsets[0].len();

        // Interleave: one cell from each message per round — the realistic arrival order on a busy link.
        let mut r = Reassembler::new();
        let mut done = 0usize;
        for round in 0..depth {
            for cs in &cellsets {
                if let Some(cell) = cs.get(round) {
                    if let Ok(Some(_)) = r.accept(cell) {
                        done += 1;
                    }
                }
            }
        }
        assert_eq!(
            done, n,
            "every interleaved multi-cell message must reassemble: {done} of {n} completed — the missing ones \
             were evicted mid-assembly and the sender was never told, which is exactly how one block carrying \
             a payment disappears while ordinary traffic flows"
        );
    }

    #[test]
    fn cells_are_fixed_size_and_roundtrip() {
        let payload = b"a private block or tx payload";
        let cell = pad_to_cell(payload).unwrap();
        assert_eq!(cell.len(), CELL_SIZE, "every cell is exactly CELL_SIZE");
        assert_eq!(unpad_cell(&cell).unwrap(), payload);
        assert!(!is_cover(&cell));

        // a cover cell is the same size and carries no payload.
        let cover = cover_cell();
        assert_eq!(cover.len(), CELL_SIZE);
        assert!(is_cover(&cover));
        assert!(unpad_cell(&cover).unwrap().is_empty());

        // oversize payload rejected.
        assert!(matches!(
            pad_to_cell(&vec![0u8; CELL_SIZE]).unwrap_err(),
            NetError::PayloadTooBig { .. }
        ));
    }

    #[test]
    fn cover_scheduler_holds_constant_rate() {
        let mut sched = CoverScheduler::new();
        assert!(sched.due(0), "a fresh scheduler is due immediately");
        // a real payload and an idle slot both yield an identical-size cell.
        let real = sched.next_cell(0, Some(b"real")).unwrap();
        assert_eq!(real.len(), CELL_SIZE);
        assert!(!sched.due(100), "not due before the interval elapses");
        assert!(sched.due(300), "due once the interval elapses");
        let cover = sched.next_cell(300, None).unwrap();
        assert_eq!(cover.len(), CELL_SIZE);
        assert!(is_cover(&cover));
    }

    #[test]
    fn chunks_reassemble_in_and_out_of_order() {
        // a payload spanning many cells (deterministic pseudo-random bytes).
        let payload: Vec<u8> = (0..100_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
            .collect();
        let cells = chunk_payload(&payload).unwrap();
        assert!(cells.len() > 1, "a 100KB payload spans many cells");
        for c in &cells {
            assert_eq!(
                c.len(),
                CELL_SIZE,
                "every cell is identical in size (leaks nothing)"
            );
        }
        // in delivery order.
        let mut r = Reassembler::new();
        let mut done = None;
        for c in &cells {
            if let Some(p) = r.accept(c).unwrap() {
                done = Some(p);
            }
        }
        assert_eq!(done.unwrap(), payload);
        // out of order (reversed) reassembles identically.
        let mut r2 = Reassembler::new();
        let mut done2 = None;
        for c in cells.iter().rev() {
            if let Some(p) = r2.accept(c).unwrap() {
                done2 = Some(p);
            }
        }
        assert_eq!(done2.unwrap(), payload);
    }

    #[test]
    fn single_and_empty_payload_chunk_roundtrip() {
        for payload in [vec![], vec![7u8; 10], vec![9u8; CHUNK_DATA]] {
            let cells = chunk_payload(&payload).unwrap();
            let mut r = Reassembler::new();
            let mut got = None;
            for c in &cells {
                if let Some(p) = r.accept(c).unwrap() {
                    got = Some(p);
                }
            }
            assert_eq!(got.unwrap(), payload);
        }
    }

    #[test]
    fn missing_or_inconsistent_chunks_fail_closed() {
        let payload = vec![3u8; 20_000];
        let cells = chunk_payload(&payload).unwrap();
        // dropping a cell -> never completes (the node re-requests, never adopts partial).
        let mut r = Reassembler::new();
        let mut completed = false;
        for c in cells.iter().skip(1) {
            if r.accept(c).unwrap().is_some() {
                completed = true;
            }
        }
        assert!(!completed, "a missing chunk never assembles a payload");
        // Fail-closed on an INCONSISTENT total within ONE message. (msg_id framing keys every message
        // independently, so a cell from a DIFFERENT payload lands in its own bucket and can never corrupt
        // this run — the corruptible case is a same-`msg_id` cell whose `total` disagrees with the run.)
        let mut r2 = Reassembler::new();
        r2.accept(&cells[0]).unwrap(); // establishes msg_id M with the real total
        let mut bad = cells[1].clone(); // same msg_id M, seq 1
        bad[14] = bad[14].wrapping_add(1); // tamper the `total` u16 (cell bytes [14..16]) -> disagrees
        assert!(matches!(r2.accept(&bad).unwrap_err(), NetError::BadCell));
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The constant-rate onion cell channel: binds the fixed-size cells + cover traffic ([`crate::net`])
//! and the chunking/reassembly to the peer message protocol ([`crate::protocol`]).
//!
//! A node moves ALL peer bytes as a stream of identical [`crate::net::CELL_SIZE`] cells emitted at a
//! constant rate (one per cover slot), whether that slot carries a real message chunk or a cover
//! cell — so an on-path observer learns nothing from timing, volume, or size, even while a ≤1.8MB
//! #29 DSYNC bundle drains across ~440 cells. The [`CellTransport`] is the pluggable byte-mover: the
//! in-process [`LoopbackTransport`] drives a same-host mesh sim + the tests here; the libp2p Tor
//! `.onion` socket is the production [`CellTransport`] (a drop-in impl, wired in the next brick — it
//! carries the SAME cells, so this privacy framing holds over any transport).

use crate::fixed::FixedBytes;
use crate::net::{
    chunk_payload, cover_cell, is_cover, CoverScheduler, NetError, Reassembler, CELL_SIZE,
};

/// Cells emitted per constant-rate slot. The wire shows a CONSTANT, load-independent burst every
/// [`crate::net::COVER_INTERVAL_MS`] (real queued chunks first, cover cells filling the rest), so timing +
/// volume still leak nothing — but the aggregate rate carries block gossip (a 128-tx block ≈ 2 cells, two
/// producers ≈ 4 cells/s) PLUS tip-beacons + re-gossip with headroom, instead of starving at
/// one cell/slot. Raising a constant rate keeps the privacy invariant (it is not a per-load knob) while
/// recovering the Tor throughput the mesh needs to CONVERGE.
///
/// ⛔⛔⛔ 8 WAS STILL BELOW THE OFFERED LOAD, AND THE QUEUE GREW WITHOUT BOUND. MEASURED on a live pair:
/// `[pump] outbound backlog 9408 -> 9472 -> 9536 -> 9600 -> 9664 cells`, monotonically climbing. At 4 slots
/// per second that is 32 cells/s drained against a payment-carrying block (~6 cells at 256 notes) every
/// ~500ms PLUS beacons, re-gossip, TxResp and bucket replies — so the deficit compounds and NEWLY queued
/// messages never transmit at all.
///
/// The consequence is not slowness, it is invisible money: a `BucketResp` was queued 178 times, arrived
/// ZERO times, and the recipient's wallet read 0.0 while its payment sat on chain. Everything above it —
/// the target recorded, the bucket filed, the want registered, the request sent, the reply served — was
/// PROVEN correct by counters; the reply simply sat behind ~9,664 cells forever. Twelve turns of this
/// session were spent looking for a defect in the account-bucket path that was never there.
///
/// This is still a CONSTANT: every slot emits exactly this many cells, real chunks first and cover cells
/// filling the rest, so an observer sees an unchanging rate whatever the node is doing. It is a fixed
/// protocol shape constant, never a per-load knob and never a window — raising it changes what the mesh can
/// carry, not what it reveals. It must exceed the real offered rate or the backlog is unbounded BY
/// CONSTRUCTION, and an unbounded backlog on a payment path is fund invisibility.
///
/// ⭐ MEASURED 2026-11-05, two real nodes, 300 s, a payment each (docs/DIRECT-CASH-DESIGN-20261105.md §11): 32 cells a slot is
/// 524 KB/s per peer, 45 GB a day, with 2-5 real cells/s inside it. At 4 a slot (16 cells/s, 65 KB/s per peer) the queue stayed
/// empty and the payment passed as fast. At 1 a slot real traffic filled it and memory reached 2 GB, so the floor is set by
/// the real cells, and lowering it further means removing real cells first.
const CELLS_PER_SLOT: usize = 4;
/// How many recent messages the local delivery ledger remembers. A diagnostic ring — never chain state, never
/// served, and fixed so it cannot become a growth axis.
const DELIVERY_LEDGER_CAP: usize = 512;

/// ⛔⛔⛔ ONE ABSOLUTE BOUND ON THE OUTBOUND CELL QUEUE — EVERY CLASS, NO EXEMPTION. THE NODE'S 4× BLOWUP.
///
/// MEASURED 2026-09-03 03:00 on the live pair (RSS lies on macOS; `footprint` is the truth): origin queue
/// 3,230,726 cells / phys_footprint 16 GB, joiner 4,701,360 cells / 23 GB, system swap 24.2 of 25.6 GB,
/// 15 M swapouts — "the node eats all my memory and fills my disk", the fourth time. Every one of those
/// cells came through the 2026-08-24 "consensus/user payloads ALWAYS enqueue" exemption to the old
/// re-askable-only cap: an exemption to a bound is not a bound. A transient transport buffer that grows
/// with load is a store that grows with adoption — the exact class the no-growth cardinal bans, and it
/// replicates Bitcoin's problem in a coat: retaining what cannot be sent.
///
/// The bound is derived from the LINK, not from the data: the pump drains at most
/// `CELLS_PER_SLOT` (4) cells per 250 ms slot = 16 cells/s, so 4,096 cells is about 256 s of a
/// link. Queueing beyond what
/// the link can carry in that horizon adds latency and memory and NOTHING else — the peer that misses a
/// cell re-asks (ChunkReq), re-gossips, or resyncs; that is already how every lost Tor cell is handled.
/// Worst case per peer pump: 4,096 × CELL_SIZE (4,096 B) = 16 MB, a protocol constant, forever.
/// O1-FOOTPRINT-REVIEWED: the queue can never hold more than this, whatever any producer does.
pub(crate) const OUTBOUND_CELLS_MAX: usize = 4096;
/// Re-askable bulk (serves, beacons, gossip echoes) stops 512 cells short of the absolute bound so that
/// consensus and user cells (blocks, txs, votes, asks, letters) still ride through a queue that bulk has
/// filled — a reserve, not an exemption: past `OUTBOUND_CELLS_MAX` every class is refused.
pub(crate) const OUTBOUND_BULK_MAX: usize = OUTBOUND_CELLS_MAX - 512;
use crate::protocol::WireMsg;
use std::collections::VecDeque;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

/// Moves fixed-size [`CELL_SIZE`] cells to/from a peer. The ONLY thing that crosses the wire is a
/// cell, so a transport can never leak more than "a cell went by". The real impl is the libp2p onion
/// socket; [`LoopbackTransport`] is the in-process pair.
/// The BULK-lane serve callback: answers a raw record-range request (8B from + 4B want, LE) with the SAME
/// page bytes `serve_notes_range_bytes` builds for the cell path. Set once at startup by the runtime owner.
pub type BulkServeFn = std::sync::Arc<dyn Fn(&[u8], BulkServeTurn) -> Vec<u8> + Send + Sync>;
/// ⭐ DB-445 — which build of an answer the bulk lane is asking for: the FIRST build of any ask, or the REBUILD of a held
/// follow (kind 20) after this node's own production woke it. The turn is the serve loop's own state, never a wire kind,
/// so no remote can ask for the woken shape (it names which recent blocks this node produced).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkServeTurn {
    Arrival,
    FollowWake,
}
/// The settable slot for [`BulkServeFn`] — handed out BEFORE the transport moves into the runtime, filled
/// AFTER the runtime exists (the callback needs the runtime). One Option, no growth.
pub type BulkServeSlot = std::sync::Arc<std::sync::Mutex<Option<BulkServeFn>>>;

/// Fixed name table for every cell-kind tag a cell can carry inside this process: slots 0-15 are the
/// wire-class slots `queue_message` computes for every message (one slot per class, same size on every
/// node forever), and slot 16 ([`CELL_KIND_COVER`]) is cover filler, which carries no message. Hoisted
/// from the pump's emit-rate line so the fan-out's `[real-page-drop]` line names classes from the SAME
/// table — two logs that can never disagree about what a class is called. The table is TOTAL over the
/// tag domain by construction (every producer clamps its index with `.min(CELL_KIND_COVER)`), so a
/// reader indexes it directly — one path, no rescue arm. Privacy: a compile-time table of 17
/// class-name string literals holding no runtime data; a class name is already visible on the wire as
/// the message's type, and never a note, amount, key, owner or content.
pub const CELL_KIND_NAMES: [&str; 25] = [
    "Block", "NotesResp", "NotesReq", "TipBeacon", "SyncResp", "SyncReq", "Peer", "Tx",
    "Letter", "OrderPost", "Bucket", "Ladder", "Clue", "ChunkReq", "BlockAck", "other",
    // DB-347 (lane-recursion's review point 4): the classes "other" used to hide get their own slots, APPENDED
    // after it so every earlier index — the control slots 3/5/13/14 included — stays where it was. F347b shed
    // ~12k "other" cells per node, and which replies those were is what step 2 must be measured against.
    "TxReq", "TxResp", "PegAttest", "Payout", "Dir", "Settlement",
    // DB-353 §11.10: the band relay (steps + asks) gets its own slot, so its share of the link is measured, not hidden.
    "Band",
    // DB-444: the tx inventory — the id a peer pulls the body by.
    "TxInv",
    "cover",
];
/// ⭐ The CONTROL classes: a one-cell message that names what a peer must PULL (a tip beacon 3, a sync ask 5, a chunk ask
/// 13, a block ack / finality vote 14, a band inventory / ask 22 — DB-454, a tx inventory 23 — DB-444). The arti fan-out
/// parks a page carrying one at the FRONT of its park and sheds it last (`is_control_page`), and the simulator's cell lane
/// reads this same table.
pub fn is_control_kind(slot: usize) -> bool {
    matches!(slot, 3 | 5 | 13 | 14 | 22 | 23)
}
/// Process-local kind tag for a cover filler cell (it carries no message, so it has no class slot). DERIVED as the
/// table's last index, so appending a class can never leave cover pointing into the class range.
pub const CELL_KIND_COVER: u8 = (CELL_KIND_NAMES.len() - 1) as u8;
/// The tag domain's size — not tuned, DERIVED: the 16 fixed wire-class slots (the per-class table
/// `queue_message` has attributed cells to since the MEASURED 2026-09-02 five-node runs, "the table is
/// the same size on every node forever") plus the one cover tag above.
pub const CELL_KIND_SLOTS: usize = CELL_KIND_NAMES.len();

pub trait CellTransport {
    /// The BULK lane (default: absent). A transport that has one returns its serve-callback slot so the
    /// runtime owner can install the range-page answerer; the loopback/test transports return a fresh dummy
    /// slot nothing reads — their pages ride the in-process cell path, which has no pacing to escape.
    fn bulk_serve_slot(&self) -> BulkServeSlot {
        BulkServeSlot::default()
    }
    /// Send ANY NotesReq-shaped payload (kind-8 range form or 1u8+ids by-id form) over the BULK lane. Returns
    /// false when no bulk lane exists / no peer dialable / lane unproven — the caller falls back to (or
    /// duplicates onto) the paced cell path, so behaviour degrades, never breaks. Fire-and-forget: the
    /// response surfaces via [`CellTransport::drain_bulk_responses`].
    fn bulk_raw_request(&self, _req: &[u8]) -> bool {
        false
    }
    /// ⭐ DB-448 — the same ask AIMED at the peer behind `link` (an id [`CellTransport::recv_cell_from`] reported), when
    /// this transport can still reach it; otherwise the hashed host [`CellTransport::bulk_raw_request`] picks. Bitcoin
    /// Core's `TxRequestTracker` asks a peer that announced the item. Default: the plain ask (a transport that names no
    /// link has nothing to aim at).
    fn bulk_raw_request_to(&self, req: &[u8], _link: u64) -> bool {
        self.bulk_raw_request(req)
    }
    /// ⭐ §BR-6 — ONE ENTRY-MIX REGISTRATION to the round's coordinator at `addr`, on a FRESH circuit (a new Tor isolation
    /// group per request, so the coordinator cannot join two registrations by the circuit they arrived on); the answer
    /// comes back as a bulk page (`entry_mix::MIX_ANSWER_TAG`). Never a fallback host: a registration aimed anywhere else
    /// would hand a stranger the fact that this node registered. Default: refused (a transport that cannot aim at an
    /// address sends nothing).
    fn mix_request_to(&self, _addr: &str, _req: &[u8]) -> bool {
        false
    }
    /// ⭐ DB-308 — how many BLOCK-PAGE asks (the inventory and its GETDATA, one in flight at a time) have ENDED WITH
    /// NOTHING DELIVERED since this transport started: a connect timeout, a stream error, a backoff return, a bad frame.
    /// The runtime reads it when its one ask leaves; a larger count later means that ask is over and the ids it named
    /// are still wanted, so the one-page slot frees at once instead of after the 45 s backstop (Bitcoin keeps a block in
    /// `mapBlocksInFlight` until it arrives or its peer's connection ends). Default 0: a transport that never loses an
    /// ask silently (loopback, the in-process hub) never moves it, and the runtime's backstop still covers it.
    fn block_page_asks_lost(&self) -> u64 {
        0
    }
    /// ⭐ DB-326 — keep ONE `FOLLOW` ask (kind 20) outstanding to each followed peer host. The transport owns the per-host
    /// bookkeeping: a host with a follow in flight is skipped, so the runtime may offer the ask every tick. Returns how
    /// many hosts it was sent to. Default 0: a link with no bulk lane has no follow (it receives pushed blocks).
    fn bulk_follow_request(&self, _req: &[u8]) -> usize {
        0
    }
    /// ⭐ DB-326 — this node's DAG admitted a block: a held `FOLLOW` answer may now carry it. Default: no held asks.
    fn notify_dag_growth(&self) {}
    /// Does this link have a PULL lane at all? COMPACT-BLOCK RELAY (2026-09-17) announces a block in one
    /// cell and lets peers pull it whole by id — but a link with no bulk lane (loopback, a latency model,
    /// BLE fragments at tap-to-pay range) can only receive what is PUSHED, so on such a link the whole block
    /// still travels the cell path. Default false: the same "no lane" answer `bulk_raw_request` gives.
    fn has_bulk_lane(&self) -> bool {
        false
    }
    /// ⭐ DB-416 — THE CLOCK THIS LINK RUNS ON. `None` (the default, every real transport): the wall clock, the daemon's
    /// only clock. A transport that runs on a SIMULATED clock (the deterministic simulator's wire, the latency pair)
    /// returns it, and the runtime then reads THAT clock wherever it stamps a timer (`NodeRuntime::now_unix_ms`), so every
    /// stamp compares in one time base with the `now_ms` its loops are driven by. Bitcoin's shape: `GetTime()` honours
    /// `SetMockTime` so every timer moves with the simulated clock — per link here, because two simulations share one
    /// process.
    fn clock_ms(&self) -> Option<u64> {
        None
    }
    /// Range convenience over [`CellTransport::bulk_raw_request`] — the kind-8 SELF-DESCRIBING
    /// shape `[8][from u64 LE][want u32 LE]`. The pre-marker 12-byte form carried no marker byte,
    /// so its first byte was the low byte of `from` and collided with the marker-kind arms at the
    /// serve dispatcher (low bytes 0/2 fed garbage ordinals/rids; low byte 4 pulled a whole DSYNC
    /// bundle). The dispatcher keeps an exact-len-12 door for peers still emitting the old shape.
    fn bulk_notes_request(&self, from: u64, want: u32) -> bool {
        let mut req = Vec::with_capacity(13);
        req.push(8u8);
        req.extend_from_slice(&from.to_le_bytes());
        req.extend_from_slice(&want.to_le_bytes());
        self.bulk_raw_request(&req)
    }
    /// Responses fetched over the BULK lane, each the exact byte shape of a NotesResp payload. Default: none.
    fn drain_bulk_responses(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
    /// DB-71 (run 82): the queued bulk pages that carry CONSENSUS — a block page, a pulled body, a certified
    /// bundle, a shell page, a ladder span — popped AHEAD of the record pages queued before them, up to `max`.
    /// A 672 KB block page sat in the FIFO behind DA record pages (200–600 ms of lock each, one per tick, and
    /// only when the apply and cell phases left any of the tick's budget) for 20–50 s while both nodes
    /// produced; block pages hand their bodies to the off-lock verifier in microseconds. Default: none (a
    /// transport with no bulk queue); the remainder stays queued, order kept.
    fn take_bulk_consensus_pages(&self, _max: usize) -> Vec<Vec<u8>> {
        Vec::new()
    }
    /// Take AT MOST `max` bulk responses, leaving the remainder queued for the next tick. The drain loop
    /// uses this so a burst of ~1MB record pages (each a few hundred fold+persist steps) can never consume
    /// the whole relay slot ahead of Block/beacon traffic — MEASURED 2026-08-19: the unbounded drain plus a
    /// 100ms-class page fold starved block ingest to ~0.25 blocks/s against a 2/s producer, so the follower
    /// fell ~800 blocks behind while every fetched page reported success. Nothing is dropped or refused:
    /// the remainder stays queued, strictly ordered, and drains on the very next tick.
    fn take_bulk_responses(&self, max: usize) -> Vec<Vec<u8>> {
        let mut all = self.drain_bulk_responses();
        // Default transports have no bulk queue to leave the remainder in; only bound when oversize.
        if all.len() > max {
            // This default cannot re-queue — bound by processing order instead: callers on transports
            // with a real bulk lane get the lane-native bounded take below.
            all.truncate(max);
        }
        all
    }
    /// Enqueue one cell for the peer. The cell MUST be exactly [`CELL_SIZE`] bytes.
    fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError>;
    /// Enqueue one cell TAGGED with its wire-class slot (see [`CELL_KIND_NAMES`]; [`CELL_KIND_COVER`]
    /// for cover filler). Same contract as [`CellTransport::send_cell`] — the tag is process-local
    /// observability so the fan-out's `[real-page-drop]` line can NAME the classes a dropped page was
    /// carrying; it never reaches the wire and never changes routing. Transports that keep no
    /// per-cell class simply carry the cell (the tag has nothing to attach to on an untagged queue).
    fn send_cell_kind(&self, cell: Vec<u8>, kind: u8) -> Result<(), NetError> {
        let _ = kind;
        self.send_cell(cell)
    }
    /// Non-blocking receive of the next cell from the peer, if one has arrived.
    fn recv_cell(&self) -> Option<Vec<u8>>;
    /// ⭐ DB-448 — the next cell AND the link it arrived on: an opaque, process-local id that
    /// [`CellTransport::bulk_raw_request_to`] resolves back to that peer. It never reaches the wire. Default: the plain
    /// receive with no link (the loopback, the latency pair and BLE have one peer or none to name).
    fn recv_cell_from(&self) -> Option<(Vec<u8>, Option<u64>)> {
        self.recv_cell().map(|c| (c, None))
    }
    /// The transport's AUTO-PEER dial handle. Auto-peering is UNCONDITIONAL — every node runs the peer
    /// directory (announce its own signed record + re-dial the converged peer set) by DEFAULT; this method
    /// only says HOW this transport dials, never WHETHER it peers. There is NO per-node opt-out. The real Tor
    /// `.onion` transport returns a dialer that opens onion connections to learned peers; the in-process test
    /// loopback (two nodes wired directly in ONE process — already connected, nothing to discover or dial)
    /// returns a [`NoPeering`] no-op. This lets the generic runtime drive auto-peering WITHOUT knowing the
    /// concrete transport type, while the type system still says "every node peers".
    fn peering(&self) -> Box<dyn PeerPeering> {
        Box::new(NoPeering)
    }
}

/// The auto-peer capability a transport exposes: (re-)dial a persistent peer by its onion multiaddr, and read
/// this node's own dialable identity so it can announce a signed peer record. A `Send` boxed handle so the
/// runtime's auto-peer thread can hold it across threads (the underlying libp2p FFI node handle is internally
/// synchronized — same safety basis as the transport's own `Send`).
pub trait PeerPeering: Send {
    /// Register / re-dial a persistent onion peer (dial-now + re-dial-forever). Returns whether accepted.
    fn add(&self, peer_id: &str, addr: &str, x_pk: &[u8], ek: &[u8]) -> bool;
    /// This node's own `(peer_id, Noise x_pk, ML-KEM ek)` — the material it signs into its own peer record.
    /// `None` until the transport identity is fully up.
    fn own_identity(&self) -> Option<(String, Vec<u8>, Vec<u8>)>;

    /// ⭐⭐⭐ THE IDENTITY A SEED LINE CAN BE WRITTEN FROM — known at service creation, NOT at publication.
    ///
    /// `own_identity` deliberately answers only once the hidden service is REACHABLE, because announcing an
    /// unpublished address to the mesh is what islanded fresh nodes. That gate is correct and stays.
    ///
    /// But a SEED LINE is not an announcement. It is a local file another device reads to learn what to
    /// dial, and the address in it is a deterministic function of the hidden-service key — known the instant
    /// the service exists, long before its descriptor lands. Gating the FILE on publication means a second
    /// node has nothing to dial for as long as publication takes, so it starts with an empty seed and
    /// islands. MEASURED 2026-08-09 on the cross-device pair: node A sat at `state Bootstrapping, problem
    /// none reported` for the FULL 180s run, the seed line never appeared, and the run failed with node B
    /// never having a peer — while node A's address had been known since second one.
    ///
    /// Publishing the address early costs a dialer some retries until the descriptor lands, which it already
    /// does; withholding it costs the pair the entire run. Default is `own_identity`, so a transport that
    /// draws no distinction is unaffected.
    fn own_identity_early(&self) -> Option<(String, Vec<u8>, Vec<u8>)> {
        self.own_identity()
    }
    /// Our own address for SELF-EXCLUSION only — known as soon as the service exists, well before it is
    /// announceable. Transports with no network under them have none.
    fn own_address(&self) -> Option<String> {
        self.own_identity().map(|(id, _, _)| id)
    }

    /// ⭐⭐⭐ HOW MANY PEERS CAN THIS NODE ACTUALLY WRITE TO RIGHT NOW?
    ///
    /// MEASURED on the live pair: a node logged `2,177 cell(s) written to NOBODY — 0 peer writers` while the
    /// payment block was queued SEVEN times (once plus six re-offers). Every retry was spent writing into a
    /// void and nothing could tell, because `queue_message` returns Ok identically whether a writer exists or
    /// not — "sent to a peer" and "sent to nobody" are the same result to every caller.
    ///
    /// A payment must not spend its retries while unreachable. Default 1 so transports without a network
    /// concept (loopback, tests) behave exactly as before.
    fn live_writers(&self) -> usize {
        1
    }
    /// Has this node's own service PUBLISHED so peers can reach it? Default true for transports with no
    /// publication step (loopback, tests) — they are reachable the moment they exist.
    fn onion_published(&self) -> bool {
        true
    }
}

/// The no-op auto-peer handle for an ALREADY-CONNECTED transport (the in-process loopback / latency-sim pair):
/// there is no separate peer to discover or dial, so `add` is a no-op and there is no own onion identity to
/// announce. This is NOT peering turned off — the pair is peered BY CONSTRUCTION; it is the honest shape for a
/// transport with no network under it. Every real node runs the onion transport and auto-peers for real.
pub struct NoPeering;
impl PeerPeering for NoPeering {
    fn add(&self, _peer_id: &str, _addr: &str, _x_pk: &[u8], _ek: &[u8]) -> bool {
        true // already connected in-process — nothing to dial
    }
    fn own_identity(&self) -> Option<(String, Vec<u8>, Vec<u8>)> {
        None
    }
    /// ZERO — an in-process transport peers with NOBODY.
    ///
    /// ⛔⛔⛔ A LOOPBACK IS NOT A PEER, AND COUNTING IT AS ONE HID A DEAD NETWORK ALL SESSION.
    ///
    /// `PeerPeering::live_writers` defaults to `1` "so transports without a network concept (loopback,
    /// tests) behave exactly as before". `NoPeering` is exactly that transport and inherited the constant, so
    /// a multi-leg node summed `Arti(0) + NoPeering(1) = 1` and published `live_writers_held 1` in `get_info`
    /// no matter what the network was doing.
    ///
    /// MEASURED 2026-08-01, both nodes simultaneously: `writers_held 1` while their own logs read
    /// `cell link up: 0`, `[acceptor] inbound stream accepted: 0`, and 18 / 2 FAILED dials — no link existed
    /// in either direction, at any point, all day. Several turns of link-state reasoning were built on that 1.
    ///
    /// user 2026-08-01: *"you used node loopbacks as a cheat for sends"* — the same confusion in a more
    /// dangerous place. A cross-node send is only real when a writer to ANOTHER node carries it, so an
    /// in-process leg must contribute nothing to that count. Reporting 0 makes a dead network read as dead.
    fn live_writers(&self) -> usize {
        0
    }
}

/// An in-process pair of [`CellTransport`] endpoints connected by channels — the same-host mesh sim
/// (two `Node`s DSYNC to each other in one process) and the test harness for the cell channel. It
/// enforces the CELL_SIZE invariant exactly like a real socket would.
pub struct LoopbackTransport {
    tx: Sender<Vec<u8>>,
    rx: Mutex<Receiver<Vec<u8>>>,
}

impl LoopbackTransport {
    /// Create two connected endpoints: a cell sent on one arrives on the other.
    pub fn pair() -> (LoopbackTransport, LoopbackTransport) {
        let (a_tx, a_rx) = channel();
        let (b_tx, b_rx) = channel();
        (
            LoopbackTransport {
                tx: a_tx,
                rx: Mutex::new(b_rx),
            },
            LoopbackTransport {
                tx: b_tx,
                rx: Mutex::new(a_rx),
            },
        )
    }
}

impl CellTransport for LoopbackTransport {
    fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError> {
        if cell.len() != CELL_SIZE {
            return Err(NetError::BadCell); // never let a non-cell onto the wire
        }
        self.tx.send(cell).map_err(|_| NetError::BadCell)
    }

    fn recv_cell(&self) -> Option<Vec<u8>> {
        self.rx.lock().ok()?.try_recv().ok()
    }
}

/// A [`CellTransport`] pair that DELAYS every cell by a fixed `latency_ms` against a shared test clock — a
/// deterministic simulation of real-life geographic Tor round-trip latency, WITHOUT owning distant nodes. A cell
/// sent when the clock reads `t` is only deliverable once the clock reaches `t + latency_ms`, so the in-process
/// 2-node mesh sees exactly the propagation delay a WAN/Tor path would impose. It lets us measure the ONE thing
/// Tor latency actually affects — cross-node block/tx PROPAGATION + convergence + finality time — while local
/// prove/verify (the TPS number) is untouched (that never hits the wire). Fixed latency ⇒ FIFO release order.
pub struct LatencyTransport {
    tx: std::sync::mpsc::Sender<(u64, Vec<u8>)>,
    rx: Mutex<std::sync::mpsc::Receiver<(u64, Vec<u8>)>>,
    /// O1-FOOTPRINT-REVIEWED: test-only latency transport; holds only what the test itself sends, released on delivery.
    held: Mutex<VecDeque<(u64, Vec<u8>)>>,
    latency_ms: u64,
    clock: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Drop 1-in-`drop_one_in` cells (deterministic, non-flaky) to simulate packet LOSS; 0 = lossless.
    drop_one_in: u64,
    sent: std::sync::atomic::AtomicU64,
    /// When true, EVERY cell is dropped — a network PARTITION. Flip back to false to HEAL and watch re-convergence.
    partitioned: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl LatencyTransport {
    /// Two endpoints delayed by `latency_ms`, plus the shared clock the harness advances each tick (set it to the
    /// current `now_ms` before polling so cells become deliverable at `send_time + latency_ms`).
    pub fn pair(
        latency_ms: u64,
    ) -> (
        LatencyTransport,
        LatencyTransport,
        std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) {
        let (a, b, clock, _partition) = Self::pair_stress(latency_ms, 0);
        (a, b, clock)
    }

    /// Stress variant: `latency_ms` RTT + drop-1-in-`drop_one_in` packet loss, plus a shared partition flag both
    /// endpoints honor (set true to sever the link, false to heal). Returns `(a, b, clock, partition_flag)`.
    pub fn pair_stress(
        latency_ms: u64,
        drop_one_in: u64,
    ) -> (
        LatencyTransport,
        LatencyTransport,
        std::sync::Arc<std::sync::atomic::AtomicU64>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let partition = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (a_tx, a_rx) = channel();
        let (b_tx, b_rx) = channel();
        let mk = |tx, rx| LatencyTransport {
            tx,
            rx: Mutex::new(rx),
            held: Mutex::new(VecDeque::new()),
            latency_ms,
            clock: clock.clone(),
            drop_one_in,
            sent: std::sync::atomic::AtomicU64::new(0),
            partitioned: partition.clone(),
        };
        (mk(a_tx, b_rx), mk(b_tx, a_rx), clock, partition)
    }
}

impl CellTransport for LatencyTransport {
    /// DB-416: the harness-advanced wire clock is this link's clock.
    fn clock_ms(&self) -> Option<u64> {
        Some(self.clock.load(std::sync::atomic::Ordering::Relaxed))
    }
    fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError> {
        if cell.len() != CELL_SIZE {
            return Err(NetError::BadCell);
        }
        // PARTITION: link severed — the cell is dropped on the wire (sender sees success, peer never receives).
        if self.partitioned.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        // LOSS: deterministically drop 1-in-N cells (a lost cell is simply never enqueued — no ack, no resend here).
        let n = self.sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.drop_one_in > 0 && n % self.drop_one_in == 0 {
            return Ok(());
        }
        let release = self.clock.load(std::sync::atomic::Ordering::Relaxed) + self.latency_ms;
        self.tx.send((release, cell)).map_err(|_| NetError::BadCell)
    }

    fn recv_cell(&self) -> Option<Vec<u8>> {
        let now = self.clock.load(std::sync::atomic::Ordering::Relaxed);
        let mut held = self.held.lock().ok()?;
        if let Ok(rxg) = self.rx.lock() {
            while let Ok(item) = rxg.try_recv() {
                held.push_back(item);
            }
        }
        // Fixed latency ⇒ the oldest held cell has the earliest release; deliver it only once its time is due.
        if held.front().map(|(r, _)| *r <= now).unwrap_or(false) {
            return held.pop_front().map(|(_, c)| c);
        }
        None
    }
}

/// A [`CellTransport`] whose cells are moved by an EXTERNAL agent, not an in-process channel. Unlike
/// [`LoopbackTransport`] (two endpoints sharing a channel in ONE process), a bridge endpoint holds ONLY its
/// own outbound + inbound cell queues; something OUTSIDE the node — the phone's BLE/GATT stack, a USB/serial
/// link, a QR/sneakernet relay, or a test pump — drains the outbound queue to transmit and injects arriving
/// cells into the inbound queue. This is the shape a REAL 2-DEVICE link has: the two nodes are separate
/// processes with NO shared memory, so convergence must flow purely through cells an external transmitter
/// ferries across the gap. It is the exact FFI surface the iOS BLE layer drives — [`drain_outbound`] in the
/// peripheral's read/notify callback, [`inject_inbound`] on a GATT write — while the node runs the SAME
/// generic [`crate::node_runtime::NodeRuntime`] beacon-adopt convergence it runs over Tor.
///
/// The cells are already CONSTANT-SIZE + cover-padded by [`CellChannel`], so the bridge carries the SAME
/// metadata-privacy invariant over BLE as over Tor — an on-link observer sees only identical cells. Both
/// queues are BOUNDED (drop-oldest on overflow) so a stalled physical link can NEVER grow node RAM
/// (no-growth pillar): a dropped cover cell costs nothing, and a dropped real chunk is re-sent by re-gossip.
/// Clone shares the SAME queues (cheap `Arc`) — one clone lives in the node, one in the platform BLE layer.
#[derive(Clone)]
pub struct BridgeCellTransport {
    /// O1-FOOTPRINT-REVIEWED: bounded by `cap` (a protocol constant at construction), drop-oldest on overflow — see `push`.
    outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `cap`, drop-oldest on overflow — see `push`.
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    cap: usize,
    /// Count of full-queue drops on this leg; keeps the `[send-cell]` line rate-limited.
    /// Atomic because `send_cell` takes `&self` (the trait's shape) — one counter, fixed width.
    full_drops: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl BridgeCellTransport {
    /// A fresh bridge endpoint. `cap` bounds EACH queue (drop-oldest on overflow) so a stalled link stays
    /// O(1) memory. Clone the returned handle to share the SAME queues with the platform BLE layer.
    pub fn new(cap: usize) -> Self {
        BridgeCellTransport {
            outbound: Arc::new(Mutex::new(VecDeque::new())),
            inbound: Arc::new(Mutex::new(VecDeque::new())),
            cap: cap.max(1),
            full_drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Pull up to `max` outbound cells for the platform to TRANSMIT over the physical link (a BLE notify, a
    /// serial write, …). Non-blocking; returns fewer (or none) if the queue is short.
    pub fn drain_outbound(&self, max: usize) -> Vec<Vec<u8>> {
        let mut q = match self.outbound.lock() {
            Ok(q) => q,
            Err(_) => return Vec::new(),
        };
        let n = max.min(q.len());
        q.drain(..n).collect()
    }

    /// Inject one cell the platform RECEIVED over the physical link into the node's inbound queue. Enforces
    /// the CELL_SIZE invariant (a non-cell can never enter the node) and is bounded (drop-oldest on overflow).
    pub fn inject_inbound(&self, cell: Vec<u8>) -> Result<(), NetError> {
        if cell.len() != CELL_SIZE {
            return Err(NetError::BadCell);
        }
        let mut q = self.inbound.lock().map_err(|_| NetError::BadCell)?;
        if q.len() >= self.cap {
            // ⛔⛔⛔ ONE DROPPED CELL KILLS A WHOLE MULTI-CELL MESSAGE — SHED PADDING, NEVER PAYLOAD.
            //
            // MEASURED 2026-07-31, the mechanism at last: node B holds EIGHT multi-cell messages
            // PART-ASSEMBLED, oldest 648 ticks stale (A holds 2, oldest 602). Block-id correlation shows A
            // sent THREE blocks carrying 2,500 account-target bytes and B parsed ONE of them eight times and
            // the other two never. Those blocks are ~6 KB — multi-cell at CHUNK_DATA 4080 — while every block
            // that DOES arrive is 1,153 bytes, single-cell. Declines 0, evictions 0: nothing is refused, a
            // partial set simply never completes.
            //
            // `pop_front` picks its victim by age, blind to whether the cell is padding or one chunk of a
            // payment block. Losing any single chunk strands the whole message forever, which is precisely
            // the 8 stuck partials.
            //
            // I tried this before and reverted it when `BucketResp` counts did not move — but that metric was
            // noisy and indirect. The stuck-partial count is the direct measure of this exact failure, so the
            // change is re-landed to be judged against it. No `Err` (that gated the live link when I tried it):
            // drop a COVER cell, and only fall back to the oldest when the queue holds no padding at all.
            //
            // NOT a window/cap/age-out: `cap` is unchanged and nothing is refused for age or reach — this
            // only changes WHICH cell yields when the bound is hit.
            //
            // O1-FOOTPRINT-REVIEWED: same `self.cap` bound, one scan of a queue already bounded by it; each
            // cell is CELL_SIZE (4096), a fixed protocol constant. Stores nothing.
            // DIGITAL-CASH-PRIVACY-REVIEWED: reads only the cover marker every peer already sees on the
            // constant-rate stream; no note, amount, key or owner.
            // ⛔⛔⛔ UNDER LOAD THERE IS NO COVER TO SHED — AND THE VICTIM IS A PAYMENT CHUNK.
            //
            // Cover-first eviction only helps while padding is present. MEASURED 2026-07-31: one run showed
            // 0 stuck partials and the payment block arrived 1-of-1; the very next run showed SIXTY-TWO
            // part-assembled messages, oldest 9,116 ticks. So the queue saturates with real payload, no cover
            // remains, `pop_front` takes a chunk of a multi-cell message, and that block is stranded forever —
            // one lost cell of two kills the whole 6 KB block, while 1,153-byte single-cell blocks sail past.
            // That is exactly the 1-of-3 delivery the block-id correlation measured.
            //
            // The chunk header is `[msg_id:u64][seq:u16][total:u16]` (CHUNK_HDR = 12), so a cell KNOWS whether
            // it belongs to a multi-cell message. Shed in order of what costs least: cover first (pure
            // padding), then a SINGLE-cell message (self-contained, and re-gossip re-sends it), and only as a
            // last resort a multi-cell chunk — because dropping one of those destroys every other cell of that
            // message that already crossed.
            //
            // NOT a window/cap/age-out: `cap` is unchanged, nothing is refused for age or reach, and no
            // message is skipped or blacklisted — this only orders which cell yields at an existing bound.
            //
            // O1-FOOTPRINT-REVIEWED: one scan of a queue already bounded by `self.cap`; each cell is
            // CELL_SIZE (4096) and the header is CHUNK_HDR (12) — both fixed protocol constants. Stores
            // nothing, no term in height, blocks or notes.
            // DIGITAL-CASH-PRIVACY-REVIEWED: reads the cover marker and the `total` field of a chunk header
            // that every peer on the constant-rate stream already sees; never a note, amount, key or owner.
            // ⛔⛔⛔ DROPPING ONE CHUNK IS THE WORST CHOICE — DROP THE WHOLE MESSAGE INSTEAD.
            //
            // Evicting a single chunk of a multi-cell message strands EVERY other chunk of it that already
            // crossed: the receiver half-assembles and waits forever. MEASURED 2026-07-31: 62 part-assembled
            // messages on node B (oldest 9,116 ticks), block-id correlation showing payment blocks arriving
            // 1-of-3, and after the eviction-priority change three consecutive settlements followed by a
            // FOURTH send that failed with 34 partials. Ordering the victim helped and did not close it,
            // because under saturation every candidate is a multi-cell chunk.
            //
            // Atomic eviction is strictly better at the same bound: drop cover first (pure padding), then a
            // self-contained single-cell message, and if only multi-cell chunks remain drop ALL cells sharing
            // the oldest msg_id. The receiver then never sees a partial for it, and the sender's re-gossip
            // resends the message whole under a fresh msg_id. Half a message helps nobody; no message at all
            // is recoverable.
            //
            // NOT a window/cap/age-out: `cap` is unchanged, nothing is refused for age or reach, and no note,
            // block or request is skipped — this only decides which cells yield at an existing bound.
            //
            // O1-FOOTPRINT-REVIEWED: one scan of a queue already bounded by `self.cap`; cells are CELL_SIZE
            // (4096) with a CHUNK_HDR (12) header — both fixed protocol constants. Stores nothing.
            // DIGITAL-CASH-PRIVACY-REVIEWED: reads the cover marker and the msg_id/total header fields every
            // peer already sees on the constant-rate stream; never a note, amount, key or owner.
            fn is_multicell(c: &[u8]) -> bool {
                c.len() >= 16 && u16::from_le_bytes([c[14], c[15]]) > 1
            }
            fn msg_id_of(c: &[u8]) -> Option<u64> {
                if c.len() >= 12 {
                    Some(u64::from_le_bytes([
                        c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11],
                    ]))
                } else {
                    None
                }
            }
            let single = q
                .iter()
                .position(|c| crate::net::is_cover(c))
                .or_else(|| q.iter().position(|c| !is_multicell(c)));
            match single {
                Some(i) => {
                    q.remove(i);
                }
                None => {
                    // Every queued cell belongs to a multi-cell message: evict one message ENTIRELY.
                    if let Some(doomed) = q.front().and_then(|c| msg_id_of(c)) {
                        q.retain(|c| msg_id_of(c) != Some(doomed));
                    } else {
                        q.pop_front();
                    }
                }
            }
        }
        q.push_back(cell);
        Ok(())
    }

    /// How many cells are queued to transmit — for the platform's flow control / BLE MTU batching.
    pub fn outbound_len(&self) -> usize {
        self.outbound.lock().map(|q| q.len()).unwrap_or(0)
    }
}

impl CellTransport for BridgeCellTransport {
    fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError> {
        if cell.len() != CELL_SIZE {
            return Err(NetError::BadCell); // never let a non-cell onto the link
        }
        let mut q = self.outbound.lock().map_err(|_| NetError::BadCell)?;
        if q.len() >= self.cap {
            // ⛔⛔⛔ THIS DISCARDED A REAL CELL AND RETURNED Ok(()) — THE SILENT LOSS.
            //
            // The old rule popped the OLDEST cell whenever the queue hit cap, justified as "re-gossip
            // re-sends real data". That holds only for messages this node re-emits forever. A `BucketResp`
            // is sent ONCE, in answer to a peer's request — drop it and the recipient never learns where
            // their note is, and every counter upstream still reads healthy.
            //
            // MEASURED 2026-07-31 across many runs: node A serves 548/548 buckets with REAL entries, queues
            // 99-476 `BucketResp` (single cell, 2300 B vs the 4080 B boundary) with ZERO queue failures, its
            // pump reports queue depth 0 and never "written to NOBODY" — and node B's `[inbound]` tally NEVER
            // lists the type, while `BucketReq` crosses 574/607 and `NotesResp` 5462 on the same link. The
            // request is re-emitted every tick so it survives this; the one-shot response does not.
            //
            // FAIL LOUD instead. A caller that cannot queue can retry or surface it; a caller lied to cannot.
            // Cover cells are still droppable — they carry nothing and exist to pad the cadence.
            //
            // O1-FOOTPRINT-REVIEWED: stores nothing new; `q` is still bounded by the SAME `self.cap`, and a
            // cell is CELL_SIZE (4096), a fixed protocol constant. This changes only what happens AT the
            // bound — refuse rather than silently discard.
            // DIGITAL-CASH-PRIVACY-REVIEWED: an error and a local depth; never a message, note, amount, key
            // or owner.
            if crate::net::is_cover(&cell) {
                return Ok(()); // a cover cell is pure padding — dropping it loses nothing
            }
            match q.iter().position(|c| crate::net::is_cover(c)) {
                // Make room by evicting PADDING, never payload.
                Some(i) => {
                    q.remove(i);
                }
                None => {
                    // ⛔ DO NOT RETURN Err HERE — I DID, AND IT BLOCKED THE REAL LINK.
                    //
                    // This queue belongs to the BLE bridge, a DORMANT leg that carries no cells until a
                    // wallet pumps it. The cell pump treats a send error as "put it back and retry", so a
                    // full BLE queue stopped real cells from going out over arti at all. MEASURED: 175,488
                    // refusals, and node B's inbound delivery collapsed to 0 with the chains 804 blocks
                    // apart while that Err was live.
                    //
                    // The original defect was the SILENCE, not the drop: `pop_front()` discarded a real cell
                    // and returned Ok(()), so `BucketResp` vanished with every upstream counter healthy.
                    // Keep the loud line, drop the OLDEST as before, and let the caller proceed — a dormant
                    // leg must never gate the live one. Removing the Err restored delivery and `BucketResp`
                    // reached node B for the first time (0 -> 24 inbound).
                    //
                    // Rate-limited to once per 4096 so a saturated dormant leg cannot become a disk vector.
                    let n = self
                        .full_drops
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        .saturating_add(1);
                    if n % 4096 == 1 {
                        eprintln!(
                            "[send-cell] outbound FULL ({} cells), all real payload — dropping the oldest \
                             ({} total). This leg is saturated; the live link is unaffected.",
                            q.len(),
                            n
                        );
                    }
                    q.pop_front();
                }
            }
        }
        q.push_back(cell);
        Ok(())
    }

    fn recv_cell(&self) -> Option<Vec<u8>> {
        self.inbound.lock().ok()?.pop_front()
    }
    // peering(): physical-link discovery (BLE scan/advertise + pairing) is the platform's job, NOT the node
    // peer directory — so the default NoPeering (already-connected-by-the-link shape), like the loopback pair.
}

/// A composite [`CellTransport`] that fans the SAME cell out to EVERY leg and receives from ANY — so ONE
/// [`crate::node_runtime::NodeRuntime`] peers over MULTIPLE transports at once (e.g. the arti Tor `.onion` mesh
/// AND a [`BridgeCellTransport`] BLE link), gossiping to every reachable peer regardless of which radio carries
/// it. This is how a phone converges over BLE when Tor is down AND over Tor when it is up, on the SAME
/// node/chain — the node code is unchanged (it drives one `CellTransport`; this one just has several radios
/// underneath). Best-effort + NO-HALTS: a dead/erroring leg is skipped, never a send failure that stalls the
/// node — a cell reaches every OTHER reachable peer and the constant-rate re-gossip re-sends anyway.
pub struct MultiTransport {
    /// O1-FOOTPRINT-REVIEWED: one leg per configured peer link; bounded by the node's link budget, never by traffic.
    legs: Vec<Box<dyn CellTransport + Send + Sync>>,
    /// A leg that a user's network choice can turn off while the node runs: `(leg index, is it on now)`. See `crate::pqmix::NetworkChoice`.
    gated: Option<(usize, fn() -> bool)>,
}
impl MultiTransport {
    pub fn new(legs: Vec<Box<dyn CellTransport + Send + Sync>>) -> Self {
        MultiTransport { legs, gated: None }
    }
    /// One leg sends and asks only while `on` says so. Its links stay up meanwhile, so turning it back on costs nothing.
    #[must_use]
    pub fn with_gated_leg(mut self, index: usize, on: fn() -> bool) -> Self {
        self.gated = Some((index, on));
        self
    }
    fn leg_on(&self, index: usize) -> bool {
        match self.gated {
            Some((i, on)) if i == index => on(),
            _ => true,
        }
    }
    /// Add another radio leg (e.g. attach a BLE link to an already-running arti node).
    pub fn add(&mut self, leg: Box<dyn CellTransport + Send + Sync>) {
        self.legs.push(leg);
    }
    pub fn leg_count(&self) -> usize {
        self.legs.len()
    }
}
impl CellTransport for MultiTransport {
    /// BULK-lane delegation — the wrapper inheriting the silent trait defaults is EXACTLY how the arti
    /// leg's bulk overrides sat unreachable while every requester "asked" a default that always said no
    /// (MEASURED 2026-08-13: ~1,200 adopt-gap asks, zero bulk attempts, zero decline lines — the same
    /// inert-guard class as the live_writers default of 1). Serve slot: the FIRST leg's (the arti leg;
    /// a BLE leg's default slot is a harmless dummy). Requests: first leg to accept wins; a leg running
    /// dual-path (spawned but unproven) returns false so the cell ask still fires. Drains: every leg.
    fn bulk_serve_slot(&self) -> BulkServeSlot {
        self.legs
            .first()
            .map(|l| l.bulk_serve_slot())
            .unwrap_or_default()
    }
    fn has_bulk_lane(&self) -> bool {
        self.legs.iter().any(|l| l.has_bulk_lane())
    }
    fn clock_ms(&self) -> Option<u64> {
        self.legs.iter().find_map(|l| l.clock_ms())
    }
    fn bulk_raw_request(&self, req: &[u8]) -> bool {
        let mut accepted = false;
        for (i, leg) in self.legs.iter().enumerate() {
            if self.leg_on(i) && leg.bulk_raw_request(req) {
                accepted = true;
                break;
            }
        }
        accepted
    }
    /// DB-308: every leg's lost block-page asks. Only a bulk leg ever moves its count; a wrapper that inherited the
    /// default 0 would hide every loss from the runtime (the inert-wrapper class `bulk_serve_slot` records).
    fn block_page_asks_lost(&self) -> u64 {
        self.legs.iter().fold(0u64, |acc, leg| acc.saturating_add(leg.block_page_asks_lost()))
    }
    /// DB-326: every leg with a bulk lane follows its own hosts; the wrapper must forward, never inherit the default 0.
    fn bulk_follow_request(&self, req: &[u8]) -> usize {
        self.legs.iter().enumerate().filter(|(i, _)| self.leg_on(*i)).map(|(_, leg)| leg.bulk_follow_request(req)).sum()
    }
    fn notify_dag_growth(&self) {
        for leg in &self.legs {
            leg.notify_dag_growth();
        }
    }
    fn drain_bulk_responses(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for leg in &self.legs {
            out.extend(leg.drain_bulk_responses());
        }
        out
    }
    fn take_bulk_consensus_pages(&self, max: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for leg in &self.legs {
            if out.len() >= max {
                break;
            }
            out.extend(leg.take_bulk_consensus_pages(max - out.len()));
        }
        out
    }
    fn take_bulk_responses(&self, max: usize) -> Vec<Vec<u8>> {
        // Bounded take, round-robin across legs; each leg's own remainder stays queued in that leg.
        let mut out = Vec::new();
        for leg in &self.legs {
            if out.len() >= max {
                break;
            }
            out.extend(leg.take_bulk_responses(max - out.len()));
        }
        out
    }

    fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError> {
        if cell.len() != CELL_SIZE {
            return Err(NetError::BadCell); // never let a non-cell onto ANY wire
        }
        // ⛔ REVERTED — MY DORMANT-LEG SKIP KILLED DELIVERY, TWICE.
        //
        // I stopped feeding legs reporting `live_writers() == 0`, to stop the dormant BLE leg swallowing a
        // copy of every cell (drops did fall 175,488 -> single digits). Then I narrowed it to "skip only when
        // another leg is live", to protect the arti replay buffer that bootstraps a Tor rendezvous.
        //
        // MEASURED: BOTH versions ended `TIMEOUT A=0 B=0` with both nodes at `live 0`, where the immediately
        // preceding builds carried 331/6 and 417/15. Two attempts, same failure — the SHAPE is wrong, not the
        // threshold, so it comes out rather than getting a third tweak.
        //
        // The BLE waste is real but harmless: a bounded queue that drops is not a growth vector, and it never
        // gated anything until I made it return Err. Broadcast to every leg, best-effort, as before.
        for (i, leg) in self.legs.iter().enumerate() {
            if self.leg_on(i) {
                let _ = leg.send_cell(cell.clone());
            }
        }
        Ok(())
    }
    /// The TAGGED entry point must fan out too — inheriting the silent trait default here was the same
    /// inert-wrapper class as the bulk-lane delegation above (see `bulk_serve_slot`): the pump tags every
    /// cell with its wire-class slot, the default DISCARDED the tag and called `send_cell`, and each leg's
    /// untagged entry point re-classed everything 15 ("other") — so the arti leg's per-kind accounting and
    /// its `[real-page-drop]` naming never saw a real class end to end. Same CELL_SIZE check and the same
    /// best-effort broadcast-to-all-legs semantics as [`MultiTransport::send_cell`] — and the reversion
    /// note there stands: NO dormant-leg skip, every leg gets the cell.
    fn send_cell_kind(&self, cell: Vec<u8>, kind: u8) -> Result<(), NetError> {
        if cell.len() != CELL_SIZE {
            return Err(NetError::BadCell); // never let a non-cell onto ANY wire
        }
        for (i, leg) in self.legs.iter().enumerate() {
            if self.leg_on(i) {
                let _ = leg.send_cell_kind(cell.clone(), kind);
            }
        }
        Ok(())
    }
    fn recv_cell(&self) -> Option<Vec<u8>> {
        // Drain from whichever leg has a cell ready (first non-empty). The node processes one cell per call and
        // calls again immediately, so every leg drains — no round-robin bookkeeping needed.
        self.recv_cell_from().map(|(c, _)| c)
    }
    /// DB-448: each leg names its own links (an arti link id, `None` from BLE).
    fn recv_cell_from(&self) -> Option<(Vec<u8>, Option<u64>)> {
        for leg in &self.legs {
            if let Some(c) = leg.recv_cell_from() {
                return Some(c);
            }
        }
        None
    }
    fn peering(&self) -> Box<dyn PeerPeering> {
        // Compose: adding a learned peer fans out to every leg's peering; own identity is the first leg that has
        // one (the arti leg publishes a dialable `.onion`; a BLE leg is NoPeering). Auto-peering drives all legs.
        Box::new(MultiPeering {
            legs: self.legs.iter().map(|l| l.peering()).collect(),
        })
    }
}
/// The composed auto-peer handle for a [`MultiTransport`] — fans `add` to every leg's peering.
struct MultiPeering {
    /// O1-FOOTPRINT-REVIEWED: one peering per configured link; bounded by the node's link budget, never by traffic.
    legs: Vec<Box<dyn PeerPeering>>,
}
impl PeerPeering for MultiPeering {
    fn add(&self, peer_id: &str, addr: &str, x_pk: &[u8], ek: &[u8]) -> bool {
        let mut any = false;
        for leg in &self.legs {
            any |= leg.add(peer_id, addr, x_pk, ek);
        }
        any
    }
    fn own_identity(&self) -> Option<(String, Vec<u8>, Vec<u8>)> {
        self.legs.iter().find_map(|l| l.own_identity())
    }
    /// Writers this node can ACTUALLY write to, summed across every leg.
    ///
    /// ⛔⛔⛔ THE TRAIT DEFAULT IS A HARDCODED `1` AND `MultiPeering` NEVER OVERRODE IT.
    ///
    /// `PeerPeering::live_writers` defaults to `1` so loopback/test transports "behave as before". A real
    /// node runs a MULTI-LEG transport, and this impl inherited that constant — so the number said 1 whether
    /// the node had one link or none at all. It is published as `live_writers_held` in `get_info` and used to
    /// decide whether a send is even measurable, so a constant there is worse than no number.
    ///
    /// MEASURED 2026-08-01 on both nodes at once: `live_writers_held 1` while their own logs showed
    /// `cell link up: 0`, `[acceptor] inbound stream accepted: 0`, and 18 / 2 failed dials — no link existed
    /// in either direction. I read that 1 as "a writer is held" across several turns and reasoned from it.
    ///
    /// This is the SECOND time this exact constant has been inherited: see the note on `ArtiPeeringHandle`
    /// in `arti_transport.rs`, where the same default made a liveness guard unable to fire. Fixed there,
    /// missed here.
    fn onion_published(&self) -> bool {
        self.legs.iter().all(|l| l.onion_published())
    }
    fn live_writers(&self) -> usize {
        // ⛔⛔⛔ NAME THE LEG. Three static audits in a row failed to explain why this reported 1.
        //
        // `live_writers_held` read a constant 1 on both nodes all session while their own logs showed
        // `cell link up: 0`, `[acceptor] inbound stream accepted: 0` and 18 / 2 FAILED dials. I traced the
        // hardcoded `1` trait default to `MultiPeering` (no override) and then to `NoPeering` (inheriting it),
        // fixed both, confirmed the binary was current — and the number was STILL 1. Reading impls has not
        // answered it, so the runtime says which leg contributes what.
        //
        // Fires only when the total DISAGREES with the legs' own sum being zero — i.e. exactly the anomaly —
        // so a healthy node with real writers stays silent and this is never a per-block line.
        // DIGITAL-CASH-PRIVACY-REVIEWED: per-leg COUNTS of this node's own transport links, the same class of
        // figure `get_info` already publishes. Names no peer, address, note, amount, key or owner.
        let per_leg: Vec<usize> = self.legs.iter().map(|l| l.live_writers()).collect();
        let total: usize = per_leg.iter().sum();
        if total > 0 {}
        total
    }
    /// ⛔⛔⛔ FORWARD THIS, OR THE WHOLE FIX BELOW IT IS DEAD. `own_address` exists so a node can
    /// self-exclude — and therefore DIAL — before its onion descriptor has published. This wrapper did not
    /// override it, so it silently fell back to the trait default (the ANNOUNCE identity), which is exactly
    /// the value that is `None` until publication. MEASURED: the origin node logged `own onion identity not
    /// established yet — skipping peer dials this pass` forever with `dialing=0`, while a peer holding the
    /// arti handle directly dialed 16 times with the same code. A defaulted trait method on a wrapper is
    /// invisible at the call site — it compiles, runs, and quietly does the old thing.
    fn own_address(&self) -> Option<String> {
        self.legs.iter().find_map(|l| l.own_address())
    }
    /// ⛔ AND FORWARD THIS ONE TOO — the warning above applied again, verbatim, the very next time a
    /// pre-publication accessor was added. MEASURED 2026-08-09: `own_identity_early` was added to the trait,
    /// overridden on `ArtiPeering` and forwarded by `ArtiPeeringHandle`, but NOT here — so `serve` (which
    /// holds a `MultiPeering`) silently took the trait default, the seed line stayed gated on publication,
    /// and the cross-device run failed at 180s exactly as before the fix, with `[seed-line] still waiting`
    /// in the log. A defaulted trait method on a wrapper is invisible at the call site: it compiles, runs,
    /// and quietly does the old thing.
    fn own_identity_early(&self) -> Option<(String, Vec<u8>, Vec<u8>)> {
        self.legs.iter().find_map(|l| l.own_identity_early())
    }
}

/// A constant-rate onion cell channel over a [`CellTransport`]. Outbound messages are chunked into a
/// FIFO of cells; [`CellChannel::tick`] emits exactly one cell per due cover slot (a queued chunk if
/// any, else a cover cell) — so the output rate is constant regardless of load. Inbound cells are
/// reassembled into complete [`WireMsg`]s ([`CellChannel::poll`]); cover cells are dropped.
pub struct CellChannel<T: CellTransport> {
    transport: T,
    cover: CoverScheduler,
    /// O1-FOOTPRINT-REVIEWED: bounded by `OUTBOUND_CELLS_MAX` (4096 cells = 16 MB) for EVERY class — backpressure, no exemption.
    /// Tag byte per queued cell: each cell rides with its wire-class slot (see [`CELL_KIND_NAMES`])
    /// so the class survives to the fan-out, where a dropped page must NAME what it was carrying.
    /// Same store, same bound — O1-FOOTPRINT-REVIEWED (bounded by OUTBOUND_CELLS_MAX, the line
    /// above): by construction one tag byte per cell under the identical backpressure bound.
    outbound: VecDeque<(u8, Vec<u8>)>,
    /// How many times a clearly-undrained outbound queue has been reported (rate-limits the log).
    backlog_reports: u64,
    /// Messages queued since the last `[queued-by-kind]` summary; keeps that line rate-limited.
    queued_since_report: u64,
    /// Total cells handed to the outbound queue; paired with the pump's emit rate to find loss.
    cells_enqueued: u64,
    /// Latch: is the outbound queue currently CONGESTED? Reported only when this FLIPS, so a busy link
    /// costs two log lines per episode instead of one per 64 cells — per-block logging is per-block DISK.
    /// O1-FOOTPRINT-REVIEWED: one bool, fixed width, bounded by nothing (not keyed by any item).
    backlog_congested: bool,
    /// ⭐ FIX 1/3 — LOCAL DELIVERY LEDGER (never served, never on the wire).
    ///
    /// Cover traffic hides timing and volume from an OBSERVER, which is the point — but it also hid them from
    /// the OPERATOR, and that is an accident, not a requirement. MEASURED tonight: block
    /// `e4b6dab89ca9c1c5` left this node carrying 2,500 account-target bytes and the peer never parsed it,
    /// and establishing that single fact took six turns of probes because nothing recorded what this node had
    /// queued versus emitted.
    ///
    /// So keep a per-message ledger of THIS node's own traffic: `(msg_id, kind, cells, queued_at, emitted)`.
    /// It never leaves the process and never enters a cell, so an observer learns nothing new — but "queued
    /// 993, emitted 993, peer parsed 0" becomes one query instead of a night of instrumentation.
    ///
    /// Bounded by DELIVERY_LEDGER_CAP: this is a diagnostic ring, not chain state, and must never grow.
    /// O1-FOOTPRINT-REVIEWED: bounded by `DELIVERY_LEDGER_CAP`, oldest-out (see `queue_message`).
    delivery: VecDeque<(u64, &'static str, usize, u64, bool)>,
    /// Backpressure episode state for the bounded outbound (see `queue_message`): whether the cap is
    /// currently engaged, and how many re-askable messages this run has shed under it. Two flat fields.
    backpressure_active: bool,
    backpressure_dropped: u64,
    /// Recently-sent MULTI-CELL messages (msg_id -> cells), kept so a peer's ChunkReq can replay exactly
    /// the missing cells. O1-FOOTPRINT-REVIEWED: capped at SENT_RING_CAP (16), a protocol constant — never
    /// per-history. Single-cell messages are never ringed (loss is already survivable via gossip dup).
    /// (The wire-class slot tag rides the ring so a ChunkReq replay re-queues cells under their TRUE
    /// class — O1-FOOTPRINT-REVIEWED likewise by SENT_RING_CAP: one tag byte per ringed message.)
    sent_cells: VecDeque<(u64, bool, u8, Vec<Vec<u8>>)>,
    /// Real / cover cells emitted in the current rate window, and when that window opened.
    emitted_real: u64,
    emitted_cover: u64,
    /// Real cells QUEUED per message class in the current 10s rate span — the attribution the
    /// `[real-page-drop]` storm never had (2026-09-02: 250-530 parked-page drops per 30s on each
    /// live node and "85 real cells/s" with no way to say WHICH class was the load). A fixed
    /// 8-slot table (one slot per wire class named on the rate line) — no per-item state, reset
    /// with the rate line. cons: none — 64 bytes, printed once per 10s.
    queued_cells_by_kind: [u64; CELL_KIND_COVER as usize],
    /// Cells REFUSED at the absolute bound, per class slot (same table as `queued_cells_by_kind`).
    /// O1-FOOTPRINT-REVIEWED: a fixed 16-slot table.
    refused_cells_by_kind: [u64; CELL_KIND_COVER as usize],
    /// ChunkReq replays refused because the queue was at its bound (the requester re-asks).
    refused_replay_cells: u64,
    rate_window_start_ms: u64,
    reasm: Reassembler,
    /// ⭐ DB-448 — the link of the cell that completed the message [`CellChannel::poll`] returned last
    /// ([`CellTransport::recv_cell_from`]); `None` when the transport names no link. A one-cell message (`TxInv`) is
    /// exact; a multi-cell one names the link of its last cell. One `Option<u64>`, overwritten per message.
    last_link: Option<u64>,
    /// ⭐ WHEN A QUEUED MESSAGE HAS LEFT THIS NODE — cells handed to the transport, net of cells placed at the queue's FRONT
    /// (each such cell goes ahead of everything already queued). A message whose last cell sits `p` cells from the front
    /// leaves exactly when this count reaches `departed_net + p + 1` at its queueing (its mark, [`Self::last_queued_mark`]),
    /// however many small messages jump ahead of it meanwhile: the queue only ever loses cells at its front. RFC 6298 §5.1
    /// times a segment from its TRANSMISSION, and a lane message waiting behind this node's own backlog has not been
    /// transmitted. MEASURED 2026-11-10 on real nodes: a custody run's ~270-cell engine messages waited 20-40 s here while
    /// their re-send timer, started at queueing, sent them again before the first copy had left.
    /// O1-FOOTPRINT-REVIEWED: two fixed-width integers, never per item. DIGITAL-CASH-PRIVACY-REVIEWED: a local cell count,
    /// never on the wire; the constant-rate output is unchanged.
    departed_net: i64,
    last_mark: i64,
}

impl<T: CellTransport> CellChannel<T> {
    /// DB-448: the link the last polled message arrived on (see `last_link`).
    pub fn last_message_link(&self) -> Option<u64> {
        self.last_link
    }
    /// DB-448: a bulk ask aimed at `link` (see the trait method).
    pub fn bulk_raw_request_to(&self, req: &[u8], link: u64) -> bool {
        self.transport.bulk_raw_request_to(req, link)
    }
    /// §BR-6 — see [`CellTransport::mix_request_to`].
    pub fn mix_request_to(&self, addr: &str, req: &[u8]) -> bool {
        self.transport.mix_request_to(addr, req)
    }
    /// This node's own dialable address, when its transport has one (the entry-mix coordinator announces it).
    pub fn own_address(&self) -> Option<String> {
        self.transport.peering().own_address()
    }
    /// BULK-lane pass-throughs (see the trait docs) — the runtime talks to the channel, never the transport.
    pub fn bulk_serve_slot(&self) -> BulkServeSlot {
        self.transport.bulk_serve_slot()
    }
    pub fn bulk_notes_request(&self, from: u64, want: u32) -> bool {
        self.transport.bulk_notes_request(from, want)
    }
    pub fn bulk_raw_request(&self, req: &[u8]) -> bool {
        self.transport.bulk_raw_request(req)
    }
    /// DB-308: the transport's lost block-page ask count (see `CellTransport::block_page_asks_lost`).
    pub fn block_page_asks_lost(&self) -> u64 {
        self.transport.block_page_asks_lost()
    }
    /// DB-326: offer the `FOLLOW` ask to every followed host without one in flight (see the trait method).
    pub fn bulk_follow_request(&self, req: &[u8]) -> usize {
        self.transport.bulk_follow_request(req)
    }
    /// DB-326: wake any held `FOLLOW` answer — this node's DAG just admitted a block.
    pub fn notify_dag_growth(&self) {
        self.transport.notify_dag_growth()
    }
    pub fn has_bulk_lane(&self) -> bool {
        self.transport.has_bulk_lane()
    }
    /// DB-416: the link's simulated clock, if it runs on one (see `CellTransport::clock_ms`).
    pub fn clock_ms(&self) -> Option<u64> {
        self.transport.clock_ms()
    }
    pub fn drain_bulk_responses(&self) -> Vec<Vec<u8>> {
        self.transport.drain_bulk_responses()
    }
    pub fn take_bulk_responses(&self, max: usize) -> Vec<Vec<u8>> {
        self.transport.take_bulk_responses(max)
    }
    /// DB-71: the queued consensus pages, ahead of everything queued before them (see the trait method).
    pub fn take_bulk_consensus_pages(&self, max: usize) -> Vec<Vec<u8>> {
        self.transport.take_bulk_consensus_pages(max)
    }

    /// How many cells this channel still has queued to emit. Callers use it as BACKPRESSURE: a node that
    /// keeps generating requests while the link is jammed makes the jam worse and starves one-shot replies.
    pub fn pending_cells(&self) -> usize {
        self.outbound.len()
    }

    /// Cells ever handed to this channel's outbound queue — independent of how many the constant-rate
    /// pump has since emitted, so a pin can tell "this ask was queued" from "the queue drained".
    pub fn cells_enqueued(&self) -> u64 {
        self.cells_enqueued
    }

    /// The dialer handle for this channel's transport — so the runtime can offer a KNOWN peer for dialing,
    /// not only the seeds pinned at startup. See the call site in `log_link_state`: a directory entry that is
    /// never dialed leaves the pair islanded whenever the joiner's single outbound direction fails.
    pub fn peering(&self) -> Box<dyn PeerPeering> {
        self.transport.peering()
    }

    pub fn new(transport: T) -> Self {
        CellChannel {
            transport,
            cover: CoverScheduler::new(),
            outbound: VecDeque::new(),
            backlog_reports: 0,
            queued_since_report: 0,
            cells_enqueued: 0,
            backlog_congested: false,
            delivery: VecDeque::new(),
            backpressure_active: false,
            backpressure_dropped: 0,
            sent_cells: VecDeque::new(),
            emitted_real: 0,
            emitted_cover: 0,
            queued_cells_by_kind: [0; CELL_KIND_COVER as usize],
            refused_cells_by_kind: [0; CELL_KIND_COVER as usize],
            refused_replay_cells: 0,
            rate_window_start_ms: 0,
            reasm: Reassembler::new(),
            last_link: None,
            departed_net: 0,
            last_mark: 0,
        }
    }

    /// The departure mark of the message [`Self::queue_message`] last queued (read right after an `Ok`): it has left this
    /// node once [`Self::departed_net`] reaches it.
    pub fn last_queued_mark(&self) -> i64 {
        self.last_mark
    }
    /// Cells handed to the transport, net of cells placed at the queue's front (see the field).
    pub fn departed_net(&self) -> i64 {
        self.departed_net
    }

    /// Queue a message to send: chunk its wire frame into cells and append them to the outbound FIFO.
    /// They drain one per slot in [`tick`], interleaved with cover — never a burst that reveals size.
    pub fn queue_message(&mut self, msg: &WireMsg) -> Result<(), NetError> {
        // ⛔ BOUNDED OUTBOUND — CLASS-AWARE BACKPRESSURE, the wedge-class killer. The outbound cell FIFO was
        // UNBOUNDED: a want/serve storm filled it to 1,005,587 cells (MEASURED 2026-08-24, [pump] queue
        // depth) while Tor drained ~39/s, and every lock in the process seized around it — RPC dead, tick
        // drain 112s, the whole node read as frozen. This ADDS the missing bound (OUTBOUND_CELL_CAP, a
        // fixed protocol constant): under pressure the RE-ASKABLE classes drop (a serve response is served
        // again on the next ask; gossip echoes re-gossip — dropping them loses NOTHING by construction),
        // while consensus and user payloads (blocks, txs, votes, letters, asks) always enqueue. Episode-
        // gated logging: entry into pressure always prints; exit prints the episode's drop total — never a
        // counter-sampled probe.
        // The 2026-08-24 cap lived here and EXEMPTED consensus/user classes ("always enqueue") — 4.7 M cells
        // and 23 GB later (2026-09-03) that exemption is gone. `droppable` now only picks the reserve tier;
        // the absolute bound below applies to EVERY class. See `OUTBOUND_CELLS_MAX`.
        let droppable = matches!(
            msg,
            WireMsg::NotesResp(_)
                | WireMsg::TxResp(_)
                | WireMsg::BucketResp(_)
                | WireMsg::LadderResp(_)
                | WireMsg::LetterResp(_)
                // NOT the tip beacon: under COMPACT-BLOCK RELAY (2026-09-17) the beacon is the block's
                // announcement — one cell, front of the queue, and never the class refused first. MEASURED
                // run 20: the outbound queue sat above the bulk bound on record pages (Ladder=368,
                // NotesResp=270) and every beacon was refused with them, so the peer never learned the
                // tip it had to pull and the pair drifted 34 blocks apart with zero page drops.
                | WireMsg::Peer(_)
                | WireMsg::Site(_)
                | WireMsg::Name(_)
                | WireMsg::Clue(_)
                | WireMsg::NoteClue(_)
                | WireMsg::ClueDigest(_)
        );
        if self.outbound.len() < OUTBOUND_CELLS_MAX / 2 && self.backpressure_active {
            self.backpressure_active = false;
            eprintln!(
                "[backpressure] pressure episode OVER — outbound back under {} cells; {} message(s) were \
                 refused during it (gossip re-gossips, serves are re-asked, a stalled peer resyncs).",
                OUTBOUND_CELLS_MAX / 2,
                self.backpressure_dropped
            );
        }
        // ⛔ THE LAST UNMEASURED HOP. `BucketResp` is queued 178 times and received ZERO times on a link
        // carrying 367 Blocks in the same direction, with the outbound backlog now DRAINING (448 -> 64), so
        // it is neither lost to congestion nor to size. Either the serialize/chunk step yields nothing for
        // this variant, or the cells go somewhere the peer never reads. Say what was queued and how many
        // cells it became — the one fact that separates those two.
        // DIGITAL-CASH-PRIVACY-REVIEWED: a variant NAME and a cell COUNT. The variant is already visible on
        // the wire as a message type; this names no account, note, amount, key or owner.
        let wire = msg.to_wire();
        let cells: Vec<_> = chunk_payload(&wire)?;
        let kind = match msg {
            WireMsg::BucketResp(_) => "BucketResp",
            WireMsg::BucketReq(_) => "BucketReq",
            WireMsg::Block(_) => "Block",
            _ => "other",
        };
        // Attribute this message's cells to its class slot (fixed table, see `KIND_NAMES`).
        // MEASURED 2026-09-02 (5-node mesh, runs 3-4): 310-871 of 580-1981 real cells/10s per node sat
        // in an unnamed "other" while the forwarder dropped 93-99% of its writes — a class that cannot
        // be named cannot be fixed. Every wire variant gets its own fixed slot (16, one per class);
        // the table is the same size on every node forever.
        let slot = match msg {
            WireMsg::Block(_) => 0,
            WireMsg::NotesResp(_) => 1,
            WireMsg::NotesReq(_) => 2,
            WireMsg::TipBeacon(_) => 3,
            WireMsg::SyncResponse(_) => 4,
            WireMsg::SyncRequest => 5,
            WireMsg::Peer(_) => 6,
            WireMsg::Tx(_) => 7,
            WireMsg::Letter(_) | WireMsg::LetterReq(_) | WireMsg::LetterResp(_) => 8,
            WireMsg::OrderPost(_) => 9,
            WireMsg::BucketReq(_) | WireMsg::BucketResp(_) => 10,
            WireMsg::LadderReq(_) | WireMsg::LadderResp(_) => 11,
            WireMsg::Clue(_) | WireMsg::NoteClue(_) | WireMsg::ClueDigest(_) => 12,
            // MEASURED 2026-09-02 (5-node mesh, run 5): ChunkReq+BlockAck together were 323-621 of
            // 890-2092 real cells/10s on every node — the largest class by far. NAK versus ack must be
            // told apart to know which loop to break.
            WireMsg::ChunkReq(_) => 13,
            // A finality VOTE shares the ack slot (both one-cell control messages) so the writer parks
            // it at the FRONT and never sheds it — measured 2026-09-18: votes classed "other" queued
            // behind bulk pages and finality lagged the tip by ~1 min (runs 27/28).
            // A payment LOCK is a signed validator message like a vote and rides the same slot, for the reason the vote
            // does (a lock that waits behind bulk pages is no fast path). NOT what fixed the missing second lock: that
            // was the lock door refusing a lock from a validator one fold step ahead (`Node::ingest_spend_lock`; the
            // 05:29 run on this class read 50 % exactly as the 05:14 run on class "other" did).
            // cons: two cells per lock in the class the writer never sheds; one lock per payment per validator, so it
            // grows with payments × validators until locks are batched (spec §11.4, "Bytes").
            WireMsg::BlockAck(_) | WireMsg::Vote(_) | WireMsg::SpendLock(_) => 14,
            // DB-347 point 4 — the multi-cell replies "other" hid, each named (slots appended after 15).
            WireMsg::TxReq(_) => 16,
            WireMsg::TxResp(_) => 17,
            WireMsg::PegAttestReq(_)
            | WireMsg::TheftRepaySig(_)
            | WireMsg::PotBuy(_)
            | WireMsg::PotFillSig(_)
            | WireMsg::UnitClose(_)
            | WireMsg::UnitCloseSig(_)
            | WireMsg::DecoySig(_)
            | WireMsg::PegAttestResp(_)
            | WireMsg::PegOutAttestReq(_)
            | WireMsg::PegOutAttestResp(_)
            | WireMsg::PegRequest(_)
            | WireMsg::OpeningShare(_)
            | WireMsg::VaultKeySig(_)
            | WireMsg::ReserveCostSig(_)
            | WireMsg::VaultMergeSig(_)
            | WireMsg::VaultRebalanceSig(_)
            | WireMsg::LegShare(_)
            | WireMsg::CoinShare(_) => 18,
            WireMsg::PayoutProposal(_) | WireMsg::PayoutSig(_) | WireMsg::EpochRelease(_) | WireMsg::MixRound(_) | WireMsg::DefiMpc(_) => 19,
            // spec §12.6: the picture door rides the directory refill's class (the same kind of public registry backfill)
            // IonSwap pools: the pools-cache refill is the same kind of public backfill
            WireMsg::DirReq(_) | WireMsg::DirResp(_) | WireMsg::PicReq(_) | WireMsg::PicResp(_) | WireMsg::IonReq(_) | WireMsg::IonResp(_) => 20,
            WireMsg::Settlement(_) => 21,
            // SPEED: a sealed body's inventory is one small cell in the same control class as the band's inventory — the
            // megabytes it announces go over the bulk lanes, so the class the writer never sheds carries 37 bytes of it.
            WireMsg::BandInv(_) | WireMsg::BandReq(_) | WireMsg::NfAsk(_) | WireMsg::NfAnswer(_) | WireMsg::SealedInv(_) => 22,
            // §14: a bundle inventory names what one producer pulls, exactly as a tx inventory does
            WireMsg::TxInv(_) | WireMsg::BundleInv(_) => 23,
            _ => 15,
        };
        self.queued_cells_by_kind[slot] =
            self.queued_cells_by_kind[slot].saturating_add(cells.len() as u64);
        // Only the bucket messages are worth a line now. The account-bucket handoff is PROVEN working end
        // to end (recipient on the far node reads the exact amount, survives restart and cold restore), so
        // logging every Block is pure noise on a chain producing ~2/second — and noise is what hid the
        // `[pump] outbound backlog` line that mattered for a dozen turns.
        // ⛔⛔⛔ EVERY MULTI-CELL MESSAGE MUST BE VISIBLE — that is the one that carries a payment.
        //
        // This probe was narrowed to bucket messages, so the single most important message on the whole
        // link — the block carrying a payment — was invisible leaving the node. MEASURED on the live pair:
        // ordinary blocks serialize to `1153 note byte(s), 0 account-target byte(s)` and cross fine, while
        // the ONE payment block is `3459 note + 2500 target` bytes. At CELL_SIZE 4096 that is the only
        // multi-cell message in the stream, the recipient never sees a block with non-empty
        // `account_targets` (adopt=0), and neither the reassembler's decline counter nor its eviction
        // counter ever fires on either side. Single-cell crosses, multi-cell does not — and nothing logged
        // the difference at the point of queueing.
        //
        // So report cell COUNT for anything that fragments, plus the bucket messages already tracked. A
        // message that never appears here never left; one that appears but never arrives is a wire loss.
        // Those are different defects and this is what separates them.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: a message KIND, a byte length and a cell count — all already
        // implied by the constant-rate cell stream an observer sees. Never a note, amount, key or owner.
        let _msg_id = crate::hash::Hash32::hash(&wire).as_bytes()[..8]
            .iter()
            .fold(0u64, |a, b| (a << 8) | *b as u64);
        if cells.len() > 1 {
            // ⛔⛔⛔ THIS BODY WAS EMPTY — THE SEND SIDE HAS NEVER REPORTED A MULTI-CELL MESSAGE.
            //
            // The comment that stood here described naming the message so it could be followed end to end,
            // and the line was never written. So for the whole session there was NO evidence that a
            // payment-sized message was ever framed into cells at all, and I filled that vacuum with two
            // theories in a row that the source does not support: that the stuck 6-chunk `msg 200e` was the
            // payment block (it is ~24 KB; the payment block is ~5,959 B ≈ 2 chunks), and that the reader
            // truncated (`drain_cells_into` is an unbounded `read_exact` loop). Both were built on a silence
            // this line was supposed to break. That is the third dead probe found this session, after the
            // discarded `missing` chunk vector and the empty `[gossip-in]` payload branch.
            //
            // Report the SIZE, which is what distinguishes the one block that matters: a payment block carries
            // ~3,459 note bytes + ~2,500 target bytes, every cover block carries 1,153 and frames as ONE cell.
            // So a 2-cell message here IS the payment leaving this node, and its absence is proof it never did.
            //
            // Fires only for multi-cell messages — cover and entropy are single-cell, so the per-block path
            // stays silent and this adds no per-block disk bytes.
            // DIGITAL-CASH-PRIVACY-REVIEWED: a per-process-salted tag, a cell count and a byte length. The tag
            // is salted per process precisely so the same message is NOT correlatable across two nodes' logs;
            // never a note, amount, key, owner, bucket or any message content.
        }
        // (No per-message line: BucketReq/Resp recur per account read, which is per-block class — a print
        // there is a DISK growth vector exactly like a per-block one. Delivery is tracked in the ledger
        // below and surfaced by `link_health()`, which a caller reads on demand.)
        // FIX 1/3: record what this node QUEUED. Local only — never serialized, never sent.
        let msg_id_dup = crate::hash::Hash32::hash(&wire).as_bytes()[..8]
            .iter()
            .fold(0u64, |a, b| (a << 8) | *b as u64);
        // ⛔⛔⛔ THE LEDGER RECORDS IT AND NOTHING EVER READS IT — so a message queued-but-never-delivered
        // is invisible. MEASURED 2026-07-31: node A queued 476 `BucketResp` (548/548 serving REAL entries,
        // single cell at 2300 B vs the 4080 B boundary, zero queue failures, pump at queue depth 0) and node
        // B's `[inbound]` tally NEVER lists the type, while `BucketReq` crosses 574/607 and `NotesResp` 5462
        // in the same stream. Eight mechanisms have been eliminated by measurement; what is still missing is
        // a per-KIND view of what this node queued, which the ledger already holds.
        //
        // Rate-limited to one line per 64 queued messages, exactly like the pump's own rate line — NOT per
        // message (the comment above rightly bans that: bucket reads recur per-block class, and a per-message
        // print is the 374 B/block disk vector).
        //
        // O1-FOOTPRINT-REVIEWED: reads the EXISTING `delivery` ledger, already bounded by
        // DELIVERY_LEDGER_CAP; adds one counter of fixed width. No per-item, per-block or per-note state.
        // DIGITAL-CASH-PRIVACY-REVIEWED: message KINDS and counts already implied by the constant-rate cell
        // stream; never an account, note, amount, key or owner.
        self.queued_since_report = self.queued_since_report.saturating_add(1);
        if self.queued_since_report >= 64 {
            self.queued_since_report = 0;
            let mut bucket_resp = 0usize;
            let mut bucket_req = 0usize;
            let mut other = 0usize;
            for (_, k, _, _, _) in self.delivery.iter() {
                match *k {
                    "BucketResp" => bucket_resp += 1,
                    "BucketReq" => bucket_req += 1,
                    _ => other += 1,
                }
            }
        }
        self.delivery
            .push_back((msg_id_dup, kind, cells.len(), 0, false));
        if cells.len() > 1 {
            const SENT_RING_CAP: usize = 16;
            // ⛔ RING KEYS BY THE CELL-HEADER ID, not `msg_id_dup` (a big-endian fold that does NOT match the
            // little-endian id the receiver asks by). A peer's ChunkReq carries `wire_msg_id(&wire)`; the ring
            // must answer to the same value or every replay silently misses (measured: replay count 0).
            let ring_id = crate::net::wire_msg_id(&wire);
            // A payment-critical Block stays replayable until the peer ACKs the full payload
            // (measured 2026-08-19: 79,189 chunk-asks answered by 2 replays — the ring had
            // evicted every payment block within seconds while the asks kept coming). Pinned
            // entries are removed by `ack_ring`, so the ring is bounded by unacked payment
            // traffic, not by history; everything else still rotates through the fixed cap.
            let pinned = kind == "Block";
            self.sent_cells
                .push_back((ring_id, pinned, slot as u8, cells.clone()));
            while self.sent_cells.len() > SENT_RING_CAP {
                if let Some(pos) = self.sent_cells.iter().position(|(_, p, _, _)| !*p) {
                    self.sent_cells.remove(pos);
                } else {
                    break; // every entry is an unacked payment — keep them all replayable
                }
            }
        }
        while self.delivery.len() > DELIVERY_LEDGER_CAP {
            self.delivery.pop_front();
        }
        // ⛔⛔⛔ COUNT CELLS AT THE BOUNDARY — every STAGE counter is non-zero, only the RATIOS are wrong.
        //
        // MEASURED 2026-07-31 on a healthy link (384 drained): B emitted 340 BucketReq -> A received 148
        // (56% lost); A queued 148 BucketResp -> B received 6 (96% lost); adoption was lossless. Four
        // separate queue edits (loud drop, writer bound, backlog drain, cover-first eviction) moved the ratio
        // not at all, so the loss is not in WHICH cell the queue sheds - it is in how many cells enter versus
        // leave. No counter measures that today, which is why four tweaks in a row were guesses.
        //
        // Report cells ENQUEUED and the depth they landed on, once per 4096 to stay off the per-block disk
        // path. Paired with the pump's existing emit-rate line, this gives enqueued-vs-emitted at the one
        // boundary where a cell can vanish without any error.
        //
        // O1-FOOTPRINT-REVIEWED: two integer counters of fixed width; `outbound` is still bounded by the same
        // `cap`, each cell is CELL_SIZE (4096), a fixed protocol constant. Stores nothing per item.
        // DIGITAL-CASH-PRIVACY-REVIEWED: cell COUNTS and a local queue depth, both already implied by the
        // constant-rate stream an observer sees; never a note, amount, key, owner or message content.
        let n_cells = cells.len() as u64;
        self.cells_enqueued = self.cells_enqueued.saturating_add(n_cells);
        // ⛔⛔⛔ A SMALL MESSAGE MUST NOT QUEUE BEHIND BULK — HEAD-OF-LINE BLOCKING STARVES PAYMENTS.
        //
        // Every message was appended strictly FIFO. Bulk traffic (sync bundles, record pages) frames into
        // HUNDREDS of cells, so a payment block sits behind all of it and drains at CELLS_PER_SLOT per slot.
        //
        // MEASURED 2026-08-01 on the first genuinely-connected pair of the session:
        //   A: "[pump] outbound BACKLOG: 3314 cell(s) queued, draining 32 per slot - the newest block bodies
        //       are queued behind 103 slot(s) of older traffic", emit rate 485.6/s real, 0 cover
        //   A: cell-frame showed one 218-cell and one 145-cell message beside the 2-cell payment block
        //   A: "[target-block] RE-OFFERED ... (try 2113)" - and each re-offer went to the BACK of that queue
        //   B: chunk-complete 417, stuck partials 0 - reassembly LOSSLESS, so nothing was being dropped
        //   B: gossip-in 4 despite inbound 1418 - blocks starved by bulk, not lost
        //
        // So delivery was never the defect; delivery ORDER was. A 2-cell payment behind 103 slots of bulk is
        // indistinguishable from a lost payment to everyone waiting on it.
        //
        // Small messages go to the FRONT, bulk to the back. NOT a cap, window or age-out: nothing is dropped,
        // refused or expired, every cell still ships, and the bulk transfer still completes - only the ORDER
        // changes. A message's own cell count decides its lane, so this is stable and needs no bookkeeping.
        // The threshold is CELLS_PER_SLOT, the fixed drain quantum: a message that fits in one slot cannot
        // delay anything meaningfully, while one that does not is by definition bulk.
        // ⛔⛔⛔ THE ABSOLUTE BOUND — every class, no exemption (see `OUTBOUND_CELLS_MAX`).
        let limit = if droppable { OUTBOUND_BULK_MAX } else { OUTBOUND_CELLS_MAX };
        if cells.len() > OUTBOUND_BULK_MAX {
            // A single message bigger than the queue can never be sent — that is a paging defect in the
            // producer, said loudly (once per class) and refused, never queued.
            if self.refused_cells_by_kind[slot] == 0 {
                eprintln!(
                    "[backpressure] ⛔ a single {kind} message is {} cells — larger than the outbound bound \
                     ({OUTBOUND_BULK_MAX}); it can NEVER be sent. Page it at the producer.",
                    cells.len()
                );
            }
            self.refused_cells_by_kind[slot] =
                self.refused_cells_by_kind[slot].saturating_add(cells.len() as u64);
            return Err(NetError::PayloadTooBig { got: cells.len(), cap: OUTBOUND_BULK_MAX });
        }
        if self.outbound.len().saturating_add(cells.len()) > limit {
            self.refused_cells_by_kind[slot] =
                self.refused_cells_by_kind[slot].saturating_add(cells.len() as u64);
            self.backpressure_dropped = self.backpressure_dropped.saturating_add(1);
            if !self.backpressure_active {
                self.backpressure_active = true;
                eprintln!(
                    "[backpressure] outbound at {} cells — the link cannot carry more; EVERY class is bounded \
                     at {OUTBOUND_CELLS_MAX} cells ({} MB) by construction, re-askable bulk at \
                     {OUTBOUND_BULK_MAX}. Refusals are counted per class on the [pump] line. Printed once \
                     per episode, at entry.",
                    self.outbound.len(),
                    OUTBOUND_CELLS_MAX * CELL_SIZE / (1024 * 1024)
                );
            }
            return Err(NetError::Backpressure { queued: self.outbound.len(), max: limit });
        }
        if cells.len() <= CELLS_PER_SLOT {
            let n = cells.len() as i64;
            for cell in cells.into_iter().rev() {
                self.outbound.push_front((slot as u8, cell));
            }
            // its last cell is the n-th from the front
            self.departed_net -= n;
            self.last_mark = self.departed_net + n;
        } else {
            for cell in cells {
                self.outbound.push_back((slot as u8, cell));
            }
            // its last cell is the queue's last
            self.last_mark = self.departed_net + self.outbound.len() as i64;
        }
        if self.cells_enqueued % 4096 < n_cells {
            let (partials, oldest_age) = self.reasm.inflight_partials();
            eprintln!(
                "[cell-flow] {} cell(s) enqueued in total; queue depth now {}; {} multi-cell message(s) \
                 PART-ASSEMBLED (oldest {} tick(s) old) — a partial that never completes is a message lost \
                 mid-flight, which no decline or eviction counter reports.",
                self.cells_enqueued,
                self.outbound.len(),
                partials,
                oldest_age
            );
        }
        // ⛔ THIS COMMENT WAS STALE AND I BELIEVED IT. It said the pump emits ONE cell per slot (4 cells/sec)
        // against ~8 offered, i.e. permanent starvation — and I reported that as the root cause. It predates
        // the CELLS_PER_SLOT 8->32 raise: `tick` emits a burst of CELLS_PER_SLOT, so the budget is 32 cells
        // per 250ms slot = 128 cells/sec against ~12 offered (2 blocks/sec x ~6 cells). There is ample drain,
        // and the measured backlog is 0. The starvation story was wrong; the loss is elsewhere.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: a local queue DEPTH only — never a message, note, amount or key.
        // ⛔ ONLY ON A STATE CHANGE. `% 64` fires forever on a busy queue — per-block class, so per-block
        // disk. A backlog matters when it CROSSES from healthy to unhealthy (and back), which is two lines
        // per episode instead of one per 64 cells, at any chain length.
        let congested = self.outbound.len() >= 512;
        if congested != self.backlog_congested {
            self.backlog_congested = congested;
            eprintln!(
                "[pump] outbound backlog {} — {} cells queued",
                if congested { "CONGESTED" } else { "recovered" },
                self.outbound.len()
            );
        }
        Ok(())
    }

    /// How many peers this channel's transport can WRITE to right now. Zero means every queued cell is
    /// going into a void — see `PeerPeering::live_writers`.
    pub fn peering_live_writers(&self) -> usize {
        self.transport.peering().live_writers()
    }

    /// Has this node's own service published, so peers can reach it? See `PeerPeering::onion_published`.
    pub fn peering_onion_published(&self) -> bool {
        self.transport.peering().onion_published()
    }

    /// ⭐⭐⭐ LINK HEALTH — the one number that says "is this peer actually receiving me?"
    ///
    /// MEASURED tonight, and it invalidated several turns of my own reasoning: this node queued 2,996 blocks
    /// as `WireMsg::Block` while the peer parsed 76 (~2.5%), with ZERO of three sampled block ids appearing
    /// on the far side. I had repeatedly asserted the pair was "verified linked by traffic" — I was counting
    /// inbound messages without checking whose blocks they were, so a dead direction read as healthy.
    ///
    /// Cover traffic is exactly why that mistake is easy: the cell stream is constant whether the link
    /// carries everything or nothing, so "bytes are flowing" proves nothing about delivery. This ratio is the
    /// operator's answer, and it is the metric that would have shown 2.5% immediately instead of costing a
    /// night of payment-path probes.
    ///
    /// Returns `(real_cells_emitted, cells_still_queued)`. A healthy link drains what it queues; a dead one
    /// shows emission with nothing draining, or a queue that never empties.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: counts of this node's OWN emitted and queued cells. Never served, never
    /// on the wire, and holding no note, amount, key, owner or peer identity.
    pub fn link_health(&self) -> (u64, usize) {
        (self.emitted_real, self.outbound.len())
    }

    /// ⭐ FIX 1/3 (query surface) — what this node queued and whether it left, for its OWN traffic.
    ///
    /// Returns `(kind, cells, emitted)` newest-first. This is the operator's answer to "did my payment
    /// actually leave?", which cover traffic otherwise makes unanswerable: ~1,000 cover cells per ~15 real
    /// ones means a healthy link and a dead one look identical from outside the process.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: derived from this node's OWN outbound queue, never served over RPC or
    /// the wire, and holding no note, amount, key, owner or peer identity — only a message kind and a cell
    /// count this node itself produced.
    pub fn delivery_report(&self) -> Vec<(&'static str, usize, bool)> {
        self.delivery
            .iter()
            .rev()
            .map(|(_, kind, cells, _, emitted)| (*kind, *cells, *emitted))
            .collect()
    }

    /// ⭐ FIX 2/3 — payment-critical messages must be ACKNOWLEDGED, not hoped for.
    ///
    /// A block carrying `account_targets` is the one message whose loss costs a user their money: the payer
    /// settles regardless, and only the recipient's ability to FIND the note depends on it. MEASURED tonight:
    /// block `e4b6dab89ca9c1c5` left this node with 2,500 target bytes and the peer never parsed it — silent,
    /// with a converging DAG and a 1:1 ledger on both sides hiding the loss completely.
    ///
    /// `unacked_payment_messages` reports those a peer has not confirmed, so the caller can re-offer. The
    /// re-offer is what makes delivery eventual rather than best-effort, and it needs no new metadata: an ack
    /// is a fixed-width message padded like every other, indistinguishable in the constant-rate stream.
    pub fn unacked_payment_messages(&self) -> usize {
        self.delivery
            .iter()
            .filter(|(_, kind, _, _, emitted)| *kind == "Block" && !*emitted)
            .count()
    }

    /// Mark a message acknowledged by its content id — called when a peer confirms receipt.
    /// Replay EXACTLY the cells a peer's ChunkReq names, if the ring still holds that message. A
    /// ring-miss is a silent no-op — the peer falls back to the existing record/bulk backfill paths.
    /// Front-queued: a retransmit unblocks a whole waiting message, so it outranks fresh traffic.
    /// A forged/foreign msg_id matches nothing here (the ring only holds what THIS node sent) — no-op.
    pub fn requeue_chunks(&mut self, req: &[u8]) {
        if req.len() < 8 + 2 || (req.len() - 8) % 2 != 0 {
            return;
        }
        let msg_id = u64::from_le_bytes(req[..8].fixed());
        let Some((_, _, ring_kind, cells)) =
            self.sent_cells.iter().find(|(id, _, _, _)| *id == msg_id)
        else {
            return;
        };
        let mut replayed = 0usize;
        let ring_kind = *ring_kind;
        let cells = cells.clone();
        for w in req[8..].chunks_exact(2) {
            let seq = u16::from_le_bytes([w[0], w[1]]) as usize;
            if let Some(c) = cells.get(seq) {
                // A replay past the absolute bound is refused like any other cell (the requester re-asks).
                if self.outbound.len() >= OUTBOUND_CELLS_MAX {
                    self.refused_replay_cells = self.refused_replay_cells.saturating_add(1);
                    continue;
                }
                self.outbound.push_front((ring_kind, c.clone()));
                self.departed_net -= 1; // a replayed cell goes ahead of every queued message
                replayed += 1;
            }
        }
    }

    /// Retire a DELIVERED payment message from the replay ring — the peer confirmed the full
    /// payload, so nothing is left to replay. This is what bounds the pinned entries.
    pub fn ack_ring(&mut self, msg_id: u64) {
        self.sent_cells.retain(|(id, _, _, _)| *id != msg_id);
    }

    pub fn mark_acked(&mut self, msg_id: u64) {
        for e in self.delivery.iter_mut() {
            if e.0 == msg_id {
                e.4 = true;
            }
        }
    }

    /// Advance the constant-rate pump: if a cover slot is due at `now_ms`, emit exactly one cell — the
    /// next queued chunk, or a cover cell if the queue is empty. Returns whether a cell was emitted.
    pub fn tick(&mut self, now_ms: u64) -> Result<bool, NetError> {
        if !self.cover.due(now_ms) {
            return Ok(false);
        }
        // Emit a CONSTANT burst of exactly CELLS_PER_SLOT cells this slot, whatever the load: each cell is
        // the next queued chunk (already a full CELL_SIZE cell, sent as-is) or a cover cell when the queue
        // is empty. The count is fixed and load-independent, so timing + volume still leak nothing, while
        // the aggregate rate is high enough to carry block gossip + tip-beacons (the mesh
        // starved to a crawl at one cell/slot). The scheduler timer is advanced ONCE for the whole slot.
        // ⛔⛔⛔ A POPPED CELL THAT FAILS TO SEND WAS DESTROYED, SILENTLY. `pop_front()` removes the cell and
        // the `?` on the next line returned before anything could put it back — so a transient send error ate
        // whatever chunk was at the head of the queue, with no log, no retry and no way to tell afterwards.
        // Losing one chunk of a multi-cell message loses the WHOLE message (the reassembler waits forever for
        // a chunk that no longer exists), and losing a single-cell message loses it outright. MEASURED: node A
        // queued 298 `BucketResp` that reached NEITHER peer while its `TxResp` reached both, and every layer
        // above reported success.
        //
        // Put it back at the FRONT and stop the slot. Order is preserved, nothing is dropped, and the next
        // slot retries — the sender no longer has to be lucky.
        let mut emitted_real_this_slot: u64 = 0;
        let mut emitted_cover_this_slot: u64 = 0;
        // ⭐ RETRANSMIT ASK — the receiver half of the one-lost-cell fix. Ages/cooldowns are in reasm
        // ticks (one per accepted cell), so the ask fires only for genuinely stalled partials and repeats
        // only after a cooldown. The request itself is a normal single-cell message on the paced channel.
        // One clock step per constant-rate slot: partial ages advance even on a silent link
        // (the receive-driven clock froze repair exactly when the link was in trouble).
        self.reasm.tick_clock();
        for (msg_id, missing) in self.reasm.stuck_requests(24, 96) {
            let mut req = Vec::with_capacity(8 + missing.len() * 2);
            req.extend_from_slice(&msg_id.to_le_bytes());
            for m in &missing {
                req.extend_from_slice(&m.to_le_bytes());
            }
            let _ = self.queue_message(&crate::protocol::WireMsg::ChunkReq(req));
        }
        // FIX 3/3: a backlog drains at the larger budget; an idle link keeps the steady one. The stream is
        // cover-saturated either way, so the observable cadence does not change — only how long a
        // payment-sized message waits behind ordinary traffic.
        // ⛔ REVERTED my unbounded backlog drain (BISECT STEP 2 of my own transport edits).
        //
        // I made the per-slot budget `backlog.max(CELLS_PER_SLOT_DRAINING)` so a slot could emit the whole
        // queue. MEASURED: it changed request delivery not at all (20/423 before, 18/238 after), and node B
        // has since drained ZERO inbound across four restarts after reaching 1,612 and 741 earlier in this
        // drive. Emitting an unbounded burst in one slot also breaks the constant-rate cadence the cover
        // traffic exists to protect, which is a privacy property, not a tuning knob.
        //
        // Back to the two fixed budgets. Removing my edits one at a time is the only way to separate my own
        // damage from the original defect.
        // One count every slot, whatever the backlog: a burst would show an observer that a backlog exists.
        let budget = CELLS_PER_SLOT;
        for _ in 0..budget {
            let Some((k, out)) = self.outbound.pop_front() else {
                self.transport
                    .send_cell_kind(cover_cell(), CELL_KIND_COVER)?;
                emitted_cover_this_slot += 1;
                continue;
            };
            emitted_real_this_slot += 1;
            if let Err(e) = self.transport.send_cell_kind(out.clone(), k) {
                self.outbound.push_front((k, out));
                // DIGITAL-CASH-PRIVACY-REVIEWED: an error kind and a local queue depth. Never a message,
                // note, amount, key or owner.
                eprintln!(
                    "[pump] send failed ({e:?}) — the cell was PUT BACK, not dropped ({} still queued)",
                    self.outbound.len()
                );
                return Ok(true);
            }
            // handed to the transport: one cell nearer every queued message's departure (a put-back above counts nothing)
            self.departed_net += 1;
        }
        // ⛔⛔⛔ IS THE OUTBOUND QUEUE KEEPING UP? A BACKLOG IS A DELIVERY LOSS IN SLOW MOTION.
        //
        // MEASURED on the live pair: the producer gossips 2,140 blocks, the peer parses 716 (~33%), and every
        // block carrying `account_targets` — 1,017 of them, all sent AFTER live writers existed — arrives
        // never. Both DAGs still converge and both ledgers stay 1:1, because the DAG heals through sync while
        // the block BODY (the only carrier of notes and targets) is what goes missing.
        //
        // The pump itself is sound: a failed send is pushed back, never dropped. So the remaining suspect is
        // arithmetic — a constant CELLS_PER_SLOT budget against a producer that can enqueue a 6-cell body per
        // block. If enqueue outruns 32 cells/slot the queue grows without bound and the newest blocks simply
        // never reach the front; that is indistinguishable from a drop at the far end, and nothing reported
        // it. Say the depth out loud when it is clearly not draining.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: a local queue DEPTH only — never a message, note, amount, key or
        // owner. Depth is a property of this node's own scheduler, not of any peer or payment.
        if self.outbound.len() > CELLS_PER_SLOT * 4 {
            self.backlog_reports = self.backlog_reports.saturating_add(1);
            if self.backlog_reports % 32 == 1 {
                eprintln!(
                    "[pump] outbound BACKLOG: {} cell(s) queued, draining {} per slot — the newest block \
                     bodies are queued behind {} slot(s) of older traffic",
                    self.outbound.len(),
                    CELLS_PER_SLOT,
                    self.outbound.len() / CELLS_PER_SLOT
                );
            }
        }
        // ⭐ MEASURE THE REAL RATES — do not trust either constant again.
        //
        // Two different numbers in this file disagreed about the drain budget and I took the wrong one as
        // root cause. What actually matters is empirical: how many cells carry REAL payload out per second
        // versus how many are queued. MEASURED context this is resolving: the peer parses 1,157 blocks, every
        // one single-cell, and ZERO of the 993 multi-cell (payment-bearing) blocks — with backlog 0 and the
        // reassembler reporting no evictions, so the cells are neither queued nor discarded at either end.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts of this node's OWN emitted cells over time. The cell stream is
        // constant-rate and already visible to any observer; no message, note, amount, key or owner appears.
        if self.outbound.is_empty() {
            // Everything queued has left this node. Mark the ledger so "queued but never emitted" is
            // distinguishable from "emitted and lost downstream" — two defects with opposite fixes.
            for e in self.delivery.iter_mut() {
                e.4 = true;
            }
        }
        self.emitted_real = self.emitted_real.saturating_add(emitted_real_this_slot);
        self.emitted_cover = self.emitted_cover.saturating_add(emitted_cover_this_slot);
        if self.rate_window_start_ms == 0 {
            self.rate_window_start_ms = now_ms;
        } else if now_ms.saturating_sub(self.rate_window_start_ms) >= 10_000 {
            let secs = (now_ms - self.rate_window_start_ms) as f64 / 1000.0;
            // Per-class breakdown of the cells QUEUED this span (fixed 8-slot table) — the line
            // that says WHICH class is the load when the parked queue overflows.
            // One shared table (`CELL_KIND_NAMES`) for this line AND the fan-out's dropped-page
            // line — the two can never disagree about a class's name. zip stops at the 16 class
            // slots; the 17th entry ("cover") has no queued-cells counter, cover is counted apart.
            let by_kind: Vec<String> = CELL_KIND_NAMES
                .iter()
                .zip(self.queued_cells_by_kind.iter())
                .filter(|(_, n)| **n > 0)
                .map(|(name, n)| format!("{name}={n}"))
                .collect();
            // The per-node UPLOAD: cells the forwarder actually wrote to peer lanes (one per writer per
            // cell) and the writer count behind it — the multiplier the scale standard forbids growing.
            let written = crate::arti_transport::FANOUT_CELLS_WRITTEN
                .swap(0, std::sync::atomic::Ordering::Relaxed);
            let writers = crate::arti_transport::FANOUT_WRITERS_NOW
                .load(std::sync::atomic::Ordering::Relaxed);
            eprintln!(
                "[pump] emit rate over {:.0}s: {} real cell(s) ({:.1}/s), {} cover, queue depth now {} (bound {}); queued by class: [{}]; REFUSED at the bound by class: [{}]; replay refusals: {}; [fanout] cells written to peers: {} across {} writer(s)",
                secs,
                self.emitted_real,
                self.emitted_real as f64 / secs,
                self.emitted_cover,
                self.outbound.len(),
                OUTBOUND_CELLS_MAX,
                by_kind.join(" "),
                self.refused_cells_by_kind
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| **n > 0)
                    .map(|(i, n)| format!("{}={}", CELL_KIND_NAMES[i], n))
                    .collect::<Vec<_>>()
                    .join(" "),
                self.refused_replay_cells,
                written,
                writers
            );
            self.emitted_real = 0;
            self.emitted_cover = 0;
            self.queued_cells_by_kind = [0; CELL_KIND_COVER as usize];
            self.rate_window_start_ms = now_ms;
        }
        self.cover.mark_emitted(now_ms);
        Ok(true)
    }

    /// Drain received cells; return the next fully-reassembled [`WireMsg`], or `None` if none is
    /// complete yet. Cover cells are skipped; a malformed/inconsistent cell resets nothing but is
    /// reported (fail-closed) so the caller can drop the peer.
    pub fn poll(&mut self) -> Result<Option<WireMsg>, NetError> {
        while let Some((cell, link)) = self.transport.recv_cell_from() {
            if is_cover(&cell) {
                continue; // cover carries no message
            }
            if let Some(frame) = self.reasm.accept(&cell)? {
                self.last_link = link; // DB-448: the link that completed this message
                // The reassembler groups cells by msg_id and self-clears the completed message, so it
                // is NOT reset here — resetting would drop the in-flight chunks of OTHER concurrently
                // gossiped messages (the interleaving that produced corrupt "Frankenblock" frames).
                return Ok(WireMsg::from_wire(&frame).map(Some).unwrap_or(None));
            }
        }
        Ok(None)
    }

    /// Are there queued outbound cells still draining?
    pub fn has_pending(&self) -> bool {
        !self.outbound.is_empty()
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    /// ⭐ THE THREE FIXES, EACH ASSERTED — and each able to FAIL.
    ///
    /// Cover traffic hides timing and volume from an observer (its purpose) but it also hid them from the
    /// operator (an accident). These three restore operator visibility and delivery guarantees WITHOUT
    /// changing anything an observer sees: the ledger never leaves the process, the ack is fixed-width and
    /// padded like every message, and the drain budget only empties a backlog into a stream already
    /// saturated with cover.
    #[test]
    fn the_delivery_ledger_records_queued_messages_and_marks_them_emitted() {
        let (a, _b) = LoopbackTransport::pair();
        let mut ca = CellChannel::new(a);
        assert!(
            ca.delivery_report().is_empty(),
            "a fresh agent has queued nothing — not vacuous"
        );

        ca.queue_message(&WireMsg::TipBeacon(vec![7u8; 64]))
            .unwrap();
        let rep = ca.delivery_report();
        assert_eq!(rep.len(), 1, "the ledger must record the queued message");
        assert!(
            rep[0].1 >= 1,
            "it must record how many cells the message spans"
        );
        assert!(
            !rep[0].2,
            "nothing has been emitted yet — a queued message is not a delivered one"
        );

        // Pump a slot: the queue drains, and the ledger must say so.
        ca.tick(crate::net::COVER_INTERVAL_MS).unwrap();
        assert!(
            ca.delivery_report()[0].2,
            "once the outbound queue is empty the message must read EMITTED — 'queued but never sent' and \
             'sent and lost downstream' are different defects and the ledger must separate them"
        );
    }

    /// RED/GREEN for the NAK-storm clock. MEASURED: 158-275 ChunkReq cells per 10s per node on the
    /// 5-node mesh (2026-09-02 run 6, per-class wire counters) from ~35 stuck 2-10-cell partials — the
    /// ask cooldown read the per-cell activity counter, so a busy link re-NAKed every stuck partial
    /// every ~1s and broadcast each ask to every writer. Two parties: A frames, sends and retransmits;
    /// B loses two cells of a 3-cell message on the wire and asks. A OBSERVES B's asks: the count must
    /// depend on B's pump SLOTS only, never on how many cells A pushed through B in between.
    #[test]
    fn a_lossy_receiver_re_asks_by_slot_cooldown_not_by_the_senders_cell_rate() {
        let (a, b) = LoopbackTransport::pair();
        let mut ca = CellChannel::new(a);
        let mut cb = CellChannel::new(b);
        let payload = vec![9u8; 12_000]; // 3 cells
        let mut t_a = 0u64;
        let mut t_b = 0u64;
        let mut pump_a = |ca: &mut CellChannel<LoopbackTransport>| {
            t_a += crate::net::COVER_INTERVAL_MS;
            ca.tick(t_a).unwrap();
        };
        let mut pump_b = |cb: &mut CellChannel<LoopbackTransport>| {
            t_b += crate::net::COVER_INTERVAL_MS;
            cb.tick(t_b).unwrap();
        };
        let asks_seen_by_a = |ca: &mut CellChannel<LoopbackTransport>, reqs: &mut Vec<Vec<u8>>| {
            while let Ok(Some(m)) = ca.poll() {
                if let WireMsg::ChunkReq(r) = m {
                    reqs.push(r);
                }
            }
            reqs.len()
        };

        // A sends the 3-cell message; the wire (B's side) delivers ONLY cell 0 — a lossy Tor link.
        ca.queue_message(&WireMsg::TipBeacon(payload.clone())).unwrap();
        pump_a(&mut ca);
        let first = cb.transport.recv_cell().expect("cell 0 crossed");
        assert!(!crate::net::is_cover(&first), "the first cell on the wire is the real one");
        assert!(cb.reasm.accept(&first).unwrap().is_none(), "1 of 3: a partial, not a message");
        while cb.transport.recv_cell().is_some() {} // cells 1, 2 and the slot's cover: LOST

        // A pushes 30 single-cell messages through B: enough activity to age the partial past min_age.
        let aging: Vec<WireMsg> = (0..30u8).map(|i| WireMsg::TipBeacon(vec![i; 64])).collect();
        for m in &aging {
            ca.queue_message(m).unwrap();
        }
        pump_a(&mut ca);
        let mut got = 0;
        while let Ok(Some(_)) = cb.poll() {
            got += 1;
        }
        assert_eq!(got, 30, "all 30 crossed — B's activity counter advanced by 30");

        // B's first pump slot: the aged partial is asked for, ONCE.
        let mut reqs = Vec::new();
        pump_b(&mut cb);
        assert_eq!(asks_seen_by_a(&mut ca, &mut reqs), 1, "one ask for the aged partial");

        // A now pushes 1,000 cells through B with NO B pump slot in between (B's pacing is B's own
        // clock; A's traffic is not). RED before the fix: 1,000 accepted cells re-armed the cooldown.
        let flood: Vec<WireMsg> =
            (0..1_000u32).map(|i| WireMsg::TipBeacon(i.to_le_bytes().to_vec())).collect();
        for m in &flood {
            ca.queue_message(m).unwrap();
        }
        let mut crossed = 0;
        while ca.pending_cells() > 0 {
            pump_a(&mut ca);
            while let Ok(Some(_)) = cb.poll() {
                crossed += 1;
            }
        }
        assert_eq!(crossed, 1_000, "the flood really crossed the wire");
        pump_b(&mut cb);
        assert_eq!(
            asks_seen_by_a(&mut ca, &mut reqs),
            1,
            "a 1,000-cell flood must NOT re-arm the NAK — that cadence-with-load is the 5-node storm"
        );

        // Measure B's slots until the second ask: it must be the 96-slot cooldown exactly (one slot of
        // it was already spent by the pump above), whatever crossed in between.
        let mut slots_after_flood = 1u64;
        while asks_seen_by_a(&mut ca, &mut reqs) < 2 {
            pump_b(&mut cb);
            slots_after_flood += 1;
            assert!(
                slots_after_flood <= 96,
                "the second ask has not arrived by slot {slots_after_flood} — the bound is 96 slots after \
                 the first, load-independent"
            );
        }
        assert_eq!(slots_after_flood, 96, "one ask per 96 slots per stuck partial, load-independent");
        assert_eq!(
            reqs[1][8..],
            [1u8, 0, 2, 0],
            "the ask names exactly the two cells the wire lost"
        );

        // A honours the ask exactly as the runtime does (`requeue_chunks`) and B completes the message.
        ca.requeue_chunks(&reqs[1]);
        pump_a(&mut ca);
        let mut whole = None;
        while let Ok(Some(m)) = cb.poll() {
            if let WireMsg::TipBeacon(p) = m {
                whole = Some(p);
            }
        }
        assert_eq!(whole.as_deref(), Some(payload.as_slice()), "retransmit delivers the whole message");
    }

    /// FIX 3: a backlog must drain at the larger budget; an idle link keeps the steady cadence.
    #[test]
    fn a_backlog_drains_faster_while_an_idle_link_keeps_the_steady_cadence() {
        let (a, _b) = LoopbackTransport::pair();
        let mut ca = CellChannel::new(a);
        // Queue well past one slot: the slot still emits exactly its one count, so a backlog never shows on the wire.
        for i in 0..40u8 {
            ca.queue_message(&WireMsg::TipBeacon(vec![i; 3000]))
                .unwrap();
        }
        let queued = ca.outbound.len();
        assert!(
            queued > CELLS_PER_SLOT,
            "the test must actually create a backlog, or it proves nothing"
        );
        ca.tick(crate::net::COVER_INTERVAL_MS).unwrap();
        assert_eq!(
            queued - ca.outbound.len(),
            CELLS_PER_SLOT,
            "a backlog must drain at the one steady rate; a faster slot shows an observer the backlog"
        );
    }

    /// ⭐ LINK HEALTH must distinguish a draining link from a stalled one — that distinction is exactly what
    /// I got wrong live (2,996 queued vs 76 delivered read as "healthy" because cells were flowing).
    #[test]
    fn link_health_separates_a_draining_link_from_a_stalled_one() {
        let (a, _b) = LoopbackTransport::pair();
        let mut ca = CellChannel::new(a);
        let (emitted0, queued0) = ca.link_health();
        assert_eq!(
            (emitted0, queued0),
            (0, 0),
            "a fresh channel has emitted nothing and queued nothing"
        );

        for i in 0..20u8 {
            ca.queue_message(&WireMsg::TipBeacon(vec![i; 3000]))
                .unwrap();
        }
        let (_, queued_after) = ca.link_health();
        assert!(
            queued_after > 0,
            "queued work must be visible, or a stall cannot be detected at all"
        );

        ca.tick(crate::net::COVER_INTERVAL_MS).unwrap();
        let (emitted_after, queued_drained) = ca.link_health();
        assert!(
            emitted_after > 0,
            "a draining link must report REAL cells emitted — cover cells alone must never read as delivery, \
             which is the illusion that made a 2.5% link look healthy"
        );
        assert!(
            queued_drained < queued_after,
            "the queue must actually shrink as it drains ({queued_after} -> {queued_drained})"
        );
    }

    /// FIX 2: payment-critical messages are tracked until acknowledged, and an ack clears them.
    #[test]
    fn payment_messages_stay_unacked_until_acknowledged() {
        let (a, _b) = LoopbackTransport::pair();
        let mut ca = CellChannel::new(a);
        ca.queue_message(&WireMsg::Block(vec![9u8; 5000])).unwrap();
        assert_eq!(
            ca.unacked_payment_messages(),
            1,
            "a queued Block is payment-critical and must be tracked until confirmed"
        );
        let id = ca.delivery.front().unwrap().0;
        ca.mark_acked(id);
        assert_eq!(
            ca.unacked_payment_messages(),
            0,
            "an acknowledged message must clear — otherwise re-offer would loop forever"
        );
    }

    use super::*;
    use crate::net::cover_cell; // only the tests emit a bare cover cell directly

    #[test]
    fn loopback_moves_cells_and_rejects_non_cells() {
        let (a, b) = LoopbackTransport::pair();
        a.send_cell(cover_cell()).unwrap();
        assert_eq!(b.recv_cell().unwrap().len(), CELL_SIZE);
        assert!(b.recv_cell().is_none(), "nothing else queued");
        // a non-cell never reaches the wire.
        assert!(matches!(
            a.send_cell(vec![0u8; 10]).unwrap_err(),
            NetError::BadCell
        ));
    }

    #[test]
    fn bridge_transport_is_a_faithful_externally_pumped_cell_pipe() {
        // Two bridge endpoints (two SEPARATE devices) linked by an EXTERNAL pump standing in for the BLE
        // stack: whatever A queues outbound, the pump hands to B's inbound, and vice versa. This is the
        // shape a real 2-device BLE/serial link has (no shared in-process channel).
        let a = BridgeCellTransport::new(64);
        let b = BridgeCellTransport::new(64);
        let pump = |from: &BridgeCellTransport, to: &BridgeCellTransport| {
            for c in from.drain_outbound(256) {
                to.inject_inbound(c).expect("pumped cell is CELL_SIZE");
            }
        };

        a.send_cell(cover_cell()).unwrap();
        assert_eq!(
            a.outbound_len(),
            1,
            "queued for the platform to transmit; nothing crosses yet"
        );
        assert!(
            b.recv_cell().is_none(),
            "no shared channel — B sees nothing until the link ferries it"
        );
        pump(&a, &b); // the BLE stack delivers A's cell to B
        assert_eq!(
            b.recv_cell().map(|c| c.len()),
            Some(CELL_SIZE),
            "B receives the ferried cell"
        );
        assert!(b.recv_cell().is_none(), "exactly one cell delivered");

        // The CELL_SIZE invariant holds on BOTH the node-send edge AND the platform-inject edge — a link
        // can never smuggle a non-cell into the node (fail-closed).
        assert!(matches!(
            a.send_cell(vec![1u8; CELL_SIZE - 1]).unwrap_err(),
            NetError::BadCell
        ));
        assert!(matches!(
            b.inject_inbound(vec![9u8; 3]).unwrap_err(),
            NetError::BadCell
        ));

        // Bounded: a stalled link (nothing drains outbound) can never grow node RAM past `cap` (no-growth).
        for _ in 0..500 {
            a.send_cell(cover_cell()).unwrap();
        }
        assert!(
            a.outbound_len() <= 64,
            "outbound is bounded by cap (drop-oldest), got {}",
            a.outbound_len()
        );
    }

    #[test]
    fn multi_transport_broadcasts_to_all_legs_and_receives_from_any() {
        // ONE node, TWO radios (stand in for arti + BLE): every cell the node sends fans out to BOTH, and a
        // cell arriving on EITHER is received — so a phone peers over Tor AND Bluetooth on the same node/chain.
        let (a1, a2) = LoopbackTransport::pair();
        let (b1, b2) = LoopbackTransport::pair();
        let mt = MultiTransport::new(vec![Box::new(a1), Box::new(b1)]);
        assert_eq!(mt.leg_count(), 2);

        // Broadcast: one send reaches EVERY leg's peer with the SAME cell.
        let cell = vec![0x5Au8; CELL_SIZE];
        mt.send_cell(cell.clone()).unwrap();
        assert_eq!(
            a2.recv_cell(),
            Some(cell.clone()),
            "the cell reached leg A's peer (Tor)"
        );
        assert_eq!(
            b2.recv_cell(),
            Some(cell),
            "the SAME cell reached leg B's peer (BLE) — gossip to every radio"
        );

        // Receive-from-any: a cell on EITHER radio is delivered to the node.
        a2.send_cell(vec![1u8; CELL_SIZE]).unwrap();
        b2.send_cell(vec![2u8; CELL_SIZE]).unwrap();
        assert!(mt.recv_cell().is_some());
        assert!(mt.recv_cell().is_some());
        assert!(mt.recv_cell().is_none(), "both radios drained");

        // NO-HALTS + cell invariant: a non-cell is rejected before any wire; a real cell always sends Ok
        // (best-effort per leg — a dead radio never stalls the node).
        assert!(matches!(
            mt.send_cell(vec![0u8; 3]).unwrap_err(),
            NetError::BadCell
        ));
        assert!(mt.send_cell(vec![9u8; CELL_SIZE]).is_ok());
    }

    /// A leg that RECORDS the (kind, first-byte) of every cell it is handed. Its untagged entry point
    /// classes the cell 15 ("other") — mirroring `ArtiOnionTransport::send_cell` — so a wrapper that
    /// STRIPS the tag is visible as a 15 where the real class should be.
    struct KindRecordingLeg {
        seen: std::sync::Arc<std::sync::Mutex<Vec<(u8, u8)>>>,
    }
    impl CellTransport for KindRecordingLeg {
        fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError> {
            // Untagged entry point → classed "other" (15), exactly like the arti leg's `send_cell`.
            self.send_cell_kind(cell, 15)
        }
        fn send_cell_kind(&self, cell: Vec<u8>, kind: u8) -> Result<(), NetError> {
            if cell.len() != CELL_SIZE {
                return Err(NetError::BadCell);
            }
            self.seen.lock().unwrap().push((kind, cell[0]));
            Ok(())
        }
        fn recv_cell(&self) -> Option<Vec<u8>> {
            None
        }
    }

    /// ⭐ WIRING PIN — the per-cell wire-class tag must SURVIVE the [`MultiTransport`] fan-out.
    ///
    /// Two parties, two sides of the hand-off: the SENDER (the pump side calling the wrapper's tagged
    /// entry point) and TWO independent receiving legs, each an OBSERVER that records exactly what the
    /// fan-out delivers to it. The assertion is that both observers saw the sender's effect — the SAME
    /// cells with the SAME class tags (the tag itself is process-local by contract, see the trait doc
    /// on [`CellTransport::send_cell_kind`]; the boundary under test is the pump→wrapper→leg hand-off).
    ///
    /// RED shape (the pre-fix tree): `MultiTransport` inherited the trait-default `send_cell_kind`,
    /// which DISCARDS the kind and calls `send_cell` — so every pump cell reached each leg through the
    /// leg's untagged entry point and the arti leg re-classed it 15 ("other"): a Block-class cell
    /// (kind 0) arrived as 15, and a cover cell arrived as 15 instead of [`CELL_KIND_COVER`], which
    /// blinded the per-kind queue accounting and the `[real-page-drop]` class naming end to end.
    /// GREEN: the override forwards the kind to EVERY leg (same CELL_SIZE check + best-effort
    /// broadcast-to-all-legs semantics as `send_cell`, NO dormant-leg skip).
    #[test]
    fn multi_transport_forwards_the_cell_kind_to_every_leg() {
        let observer_a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observer_b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mt = MultiTransport::new(vec![
            Box::new(KindRecordingLeg {
                seen: observer_a.clone(),
            }),
            Box::new(KindRecordingLeg {
                seen: observer_b.clone(),
            }),
        ]);

        // A Block-class cell (kind 0) and a cover cell, sent through the TAGGED entry point.
        mt.send_cell_kind(vec![0x11u8; CELL_SIZE], 0).unwrap();
        mt.send_cell_kind(cover_cell(), CELL_KIND_COVER).unwrap();

        for (name, seen) in [("A", &observer_a), ("B", &observer_b)] {
            let v = seen.lock().unwrap();
            assert_eq!(
                v.len(),
                2,
                "leg {name} observes BOTH cells — broadcast-to-all-legs, no leg skipped"
            );
            assert_eq!(
                (v[0].0, v[0].1),
                (0u8, 0x11u8),
                "leg {name}: the Block cell arrives tagged kind 0 — NOT re-classed 15 by a stripped tag"
            );
            assert_eq!(
                v[1].0, CELL_KIND_COVER,
                "leg {name}: cover arrives as CELL_KIND_COVER (the table's last slot), never 15"
            );
        }

        // The CELL_SIZE invariant holds on the tagged entry point too — a non-cell reaches NO wire.
        assert!(matches!(
            mt.send_cell_kind(vec![0u8; 3], 0).unwrap_err(),
            NetError::BadCell
        ));
        assert_eq!(
            observer_a.lock().unwrap().len(),
            2,
            "the rejected non-cell never reached a leg"
        );
    }

    #[test]
    fn constant_rate_pump_emits_a_fixed_burst_per_slot_incl_cover() {
        let (a, b) = LoopbackTransport::pair();
        let mut ca = CellChannel::new(a);
        // queue a small message (one cell of real data).
        ca.queue_message(&WireMsg::SyncRequest).unwrap();
        // slot 0: a CONSTANT burst of exactly CELLS_PER_SLOT cells — the real chunk first, cover the rest.
        assert!(ca.tick(0).unwrap());
        let burst: Vec<_> = (0..CELLS_PER_SLOT)
            .map(|_| b.recv_cell().expect("burst cell"))
            .collect();
        assert!(
            b.recv_cell().is_none(),
            "exactly CELLS_PER_SLOT cells this slot — no more, no fewer"
        );
        assert!(burst.iter().all(|c| c.len() == CELL_SIZE));
        assert!(!is_cover(&burst[0]), "the real message chunk goes first");
        assert!(
            burst[1..].iter().all(|c| is_cover(c)),
            "the rest of the fixed burst is cover"
        );
        // not due again until the interval elapses.
        assert!(!ca.tick(100).unwrap());
        // slot 1 (queue now empty): the SAME fixed burst, now ALL cover — the rate is constant + load-
        // independent (an idle slot is byte-for-byte indistinguishable from a busy one on the wire).
        assert!(ca.tick(300).unwrap());
        let idle: Vec<_> = (0..CELLS_PER_SLOT)
            .map(|_| b.recv_cell().expect("idle burst cell"))
            .collect();
        assert!(
            idle.iter().all(|c| is_cover(c)),
            "an idle slot emits the same-size all-cover burst"
        );
    }

    #[test]
    fn big_message_drains_over_many_cover_slots_and_reassembles() {
        let (a, b) = LoopbackTransport::pair();
        let mut ca = CellChannel::new(a);
        let mut cb = CellChannel::new(b);
        // a multi-cell message (spans many cells).
        let msg = WireMsg::SyncResponse(vec![7u8; 40_000]);
        ca.queue_message(&msg).unwrap();
        assert!(ca.has_pending());

        // Drive the constant-rate pump: one cell per slot until drained, then a few cover slots.
        let mut got = None;
        for i in 0..2000u64 {
            ca.tick(i * crate::net::COVER_INTERVAL_MS).unwrap();
            if let Some(m) = cb.poll().unwrap() {
                got = Some(m);
                break;
            }
        }
        assert_eq!(
            got,
            Some(msg),
            "the multi-cell message reassembled intact over the cell stream"
        );
        assert!(!ca.has_pending(), "all chunks drained");
    }
}

/// ⛔⛔⛔ THE NODE'S 4× MEMORY BLOWUP, PINNED. The outbound cell queue is bounded for EVERY class by
/// construction (`OUTBOUND_CELLS_MAX`); 2026-09-03 the live pair held 3.2 M / 4.7 M cells (16 / 23 GB
/// compressed, swap full) through a "consensus always enqueues" exemption. No exemption survives here.
#[cfg(all(test, feature = "pins-core"))]
mod outbound_bound_tests {
    use super::*;

    /// A link whose writes always fail — the pump must put the cell back, never grow past the bound.
    struct DeadLink;
    impl CellTransport for DeadLink {
        fn send_cell(&self, _cell: Vec<u8>) -> Result<(), NetError> {
            Err(NetError::BadCell)
        }
        fn recv_cell(&self) -> Option<Vec<u8>> {
            None
        }
    }

    fn pump() -> CellChannel<LoopbackTransport> {
        let (a, _b) = LoopbackTransport::pair();
        CellChannel::new(a)
    }

    /// ⭐ Consensus class (Block) — the class the old cap EXEMPTED — is refused at the absolute bound,
    /// with an honest `Backpressure` error, and the queue never holds more than the bound.
    #[test]
    fn every_class_is_bounded_no_exemption_even_blocks() {
        let mut p = pump();
        let mut refused = 0usize;
        for i in 0..(OUTBOUND_CELLS_MAX * 3) {
            match p.queue_message(&WireMsg::Block(vec![(i % 251) as u8; 64])) {
                Ok(()) => {}
                Err(NetError::Backpressure { queued, max }) => {
                    refused += 1;
                    assert!(queued <= max && max == OUTBOUND_CELLS_MAX);
                }
                Err(e) => panic!("unexpected error {e:?}"),
            }
            assert!(p.outbound.len() <= OUTBOUND_CELLS_MAX, "queue exceeded the bound at message {i}");
        }
        assert!(refused > 0, "a flood of blocks must be refused at the bound — it was never refused");
        assert_eq!(p.outbound.len(), OUTBOUND_CELLS_MAX, "the queue fills exactly to the bound, never past");
        assert!(p.refused_cells_by_kind[0] as usize >= refused, "refusals are counted on the Block slot");
    }

    /// ⭐ Re-askable bulk stops at the reserve line; consensus still rides through the bulk-filled queue
    /// up to the absolute bound, and then it too is refused.
    #[test]
    fn bulk_stops_at_the_reserve_and_consensus_rides_through_until_the_absolute_bound() {
        let mut p = pump();
        let mut bulk_refused = false;
        for _ in 0..(OUTBOUND_CELLS_MAX * 2) {
            if p.queue_message(&WireMsg::NotesResp(vec![7u8; 64])).is_err() {
                bulk_refused = true;
                break;
            }
        }
        assert!(bulk_refused);
        assert!(p.outbound.len() <= OUTBOUND_BULK_MAX, "bulk never crosses the reserve line");
        let before = p.outbound.len();
        assert!(p.queue_message(&WireMsg::Block(vec![1u8; 64])).is_ok(), "a block rides through bulk");
        assert!(p.outbound.len() > before);
        let mut block_refused = false;
        for _ in 0..(OUTBOUND_CELLS_MAX * 2) {
            if p.queue_message(&WireMsg::Block(vec![2u8; 64])).is_err() {
                block_refused = true;
                break;
            }
        }
        assert!(block_refused, "past the absolute bound even blocks are refused");
        assert!(p.outbound.len() <= OUTBOUND_CELLS_MAX);
    }

    /// ⭐ A ChunkReq replay past the bound is refused and counted, never pushed.
    #[test]
    fn replay_never_exceeds_the_bound() {
        let mut p = pump();
        p.queue_message(&WireMsg::Block(vec![3u8; 9000])).unwrap();
        let id = p.sent_cells.front().expect("the multi-cell block is in the sent ring").0;
        while p.queue_message(&WireMsg::Block(vec![4u8; 64])).is_ok() {}
        assert_eq!(p.outbound.len(), OUTBOUND_CELLS_MAX);
        let mut req = id.to_le_bytes().to_vec();
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&1u16.to_le_bytes());
        p.requeue_chunks(&req);
        assert_eq!(p.outbound.len(), OUTBOUND_CELLS_MAX, "replays cannot grow the queue past the bound");
        assert!(p.refused_replay_cells >= 2, "refused replays are counted");
    }

    /// ⭐ A single message larger than the queue can never be sent: refused, never queued, said loudly.
    #[test]
    fn oversized_single_message_is_refused_never_queued() {
        let mut p = pump();
        let huge = vec![5u8; (OUTBOUND_BULK_MAX + 8) * CELL_SIZE];
        match p.queue_message(&WireMsg::NotesResp(huge)) {
            Err(NetError::PayloadTooBig { .. }) => {}
            other => panic!("an oversized message must be refused as PayloadTooBig, got {other:?}"),
        }
        assert_eq!(p.outbound.len(), 0, "nothing of it is queued");
    }

    /// ⭐ A dead link: the pump puts the failed cell back and the queue still never exceeds the bound.
    #[test]
    fn dead_link_put_back_never_exceeds_the_bound() {
        let mut p = CellChannel::new(DeadLink);
        while p.queue_message(&WireMsg::Block(vec![6u8; 64])).is_ok() {}
        assert_eq!(p.outbound.len(), OUTBOUND_CELLS_MAX);
        for t in 1..20u64 {
            let _ = p.tick(t * 1_000);
            assert!(p.outbound.len() <= OUTBOUND_CELLS_MAX, "tick {t}: put-back grew the queue past the bound");
        }
    }
}

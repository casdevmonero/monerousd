// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐⭐⭐ NETSIM — THE PRODUCTION RELAY UNDER TOR PHYSICS, ON A SIMULATED CLOCK.
//!
//! BORROWED-FROM: deterministic simulation testing (FoundationDB's simulator, TigerBeetle's VOPR). All nodes run in
//! ONE process on a simulated clock over a simulated wire, every random choice draws from one seed, and a run is
//! replayed exactly from that seed.
//!
//! WHY (MEASURED 2026-09-27, gate Q13, DB-326). Every in-process mesh ran a DIFFERENT relay than production, so no
//! in-process test could show the step-3 failure:
//! 1. `LatencyTransport` and the loopback have no bulk lane. A producer there PUSHES whole blocks over cells. On an
//!    onion link the node announces the tip and the peer PULLS by id: the path that orphaned 279 of 280 arrivals.
//! 2. The hub in `mesh_runtime_scenarios` has the bulk lane, but answers with zero latency on a scripted schedule.
//! 3. Tests produce inline through `tick()`. The daemon runs `tick_relay` every `COVER_INTERVAL_MS` beside an
//!    EXTERNAL producer (`begin_produce` → `complete_produce_job` → PoW → `finish_produce`), which no test drove.
//!
//! Self-selecting chains need relay latency above the per-node block interval, so a zero-latency or push-relay mesh
//! can never show them. This module runs the daemon's two loops on a simulated clock, over a wire with per-leg
//! latency on BOTH lanes, and measures what the gate measures: the one-chain predicate below `min(tip) - 8`, and each
//! block's arrival latency at its peer.
//!
//! MODELED:
//! - per-leg latency with seeded jitter;
//! - per-circuit FIFO on the cell lane;
//! - a bulk exchange as one leg out, the answer built by the PRODUCTION serve function at the instant the ask
//!   arrives, then one leg back plus a transfer time from the page size.
//!
//! NOT MODELED (named fidelity gaps):
//! - arti's bulk in-flight caps and lane pools;
//! - node CPU time (the clock does not advance while a node computes, so apply-lock delays are absent);
//! - Tor circuit failure;
//! - DSYNC adoption (no decider is installed, so a node follows by pages only).
//!
//! A verdict from this module counts only after it has reproduced the gate measurement it stands in for.
//!
//! ⛔ SCOPE: an in-process island (see `harness/mod.rs`). It is a discovery instrument; the real-process gate stays
//! the standard of proof.

use crate::block::BlockId;
use crate::hash::Hash32;
use crate::net::{NetError, CELL_SIZE};
use crate::node::Node;
use crate::node_runtime::{NodeRuntime, ProduceJob};
use crate::transport::CellTransport;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// SplitMix64: the ONE generator every random choice of a run draws from, so a seed replays the run exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

thread_local! {
    /// ⭐ PERF TIER step 1 — THE STEP'S CHARGE CLOCK: this node thread's CPU instant (µs, `budget_clock::charged_cpu_us` — its
    /// CPU plus the CPU its memo hits stood in for, which a node binary pays) at
    /// which its current step's LOCK-HELD work began, moved forward past any off-lock work ([`off_lock`]); 0 = the
    /// simulation does not charge node CPU. What the step has spent is what holds the node's runtime lock afterwards, and
    /// what a send made mid-step waits for before it leaves ([`Wire::send_clock`]).
    static STEP_CPU0: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The lock-held CPU this node thread's step has spent so far (µs; 0 while not charging).
fn step_charge_us() -> u64 {
    let t0 = STEP_CPU0.with(std::cell::Cell::get);
    if t0 == 0 {
        0
    } else {
        crate::budget_clock::charged_cpu_us().saturating_sub(t0)
    }
}

/// Run work the daemon runs OFF the runtime lock (the producer's prove and PoW grind, on its own loop) without charging it
/// to the lock: the step's charge clock moves forward by the CPU it spent. Their simulated cost is modeled where they are
/// (the grind by `Physics::ms_per_hash`, the prove by the producer's `pending` instant).
fn off_lock<R>(f: impl FnOnce() -> R) -> R {
    let a = crate::budget_clock::charged_cpu_us();
    let r = f();
    let spent = crate::budget_clock::charged_cpu_us().saturating_sub(a);
    STEP_CPU0.with(|c| {
        if c.get() != 0 {
            c.set(c.get() + spent);
        }
    });
    r
}

/// The process's one prove gate lives in the budget clock, where an off-lock job takes it too (link 84).
use crate::budget_clock::prove_alone;

/// The wire's physics.
#[derive(Clone, Copy, Debug)]
pub struct Physics {
    /// One Tor leg, one direction.
    pub leg_ms: u64,
    /// Uniform extra per leg, `0..=jitter_ms`.
    pub jitter_ms: u64,
    /// A bulk answer's transfer rate on top of its leg.
    pub bytes_per_ms: u64,
    /// Simulated milliseconds ONE PoW hash takes on one producer. The miner walks nonces from `pow::NONCE_BASE`, so a
    /// block's grind is exactly `pow::grind_tries(nonce)` hashes and takes that many `ms_per_hash` of SIMULATED time: deterministic, and
    /// faithful to the daemon, whose producer loop is busy for the whole grind. 0 = the grind takes no simulated time,
    /// which leaves the DAA with nothing to throttle (the first runs over-produced for exactly that reason).
    pub ms_per_hash: u64,
    /// Time from a page's arrival to its blocks being in the DAG (the post-graft apply lock), added to every delivered
    /// page. lane-wallet-cover's review: MEASURED Q13 n1 `[apply-phase]` p50 173 / p90 305 / max 749 ms (130 samples).
    pub apply_ms: u64,
}

impl Physics {
    /// MEASURED gate Q13 (n1.log `[bulk] page fetched`): 34 KB pages landed in 1,272–1,364 ms and a 410 KB page in
    /// 3,040 ms. That is a leg of about 600–680 ms and about 150 KB/s on a large page. `ms_per_hash`: MEASURED in
    /// this simulator, 79 PoUW hashes in 4,098 ms of grind wall time (~52 ms each, loaded machine, nice 19).
    pub const TOR_Q13: Physics = Physics { leg_ms: 600, jitter_ms: 80, bytes_per_ms: 150, ms_per_hash: 52, apply_ms: 173 };

    /// The Q13 physics with `NETSIM_LEG_MS` / `NETSIM_APPLY_MS` overrides, for the (L, r) frontier sweep.
    pub fn from_env() -> Physics {
        let get = |k: &str| std::env::var(k).ok().and_then(|s| s.parse::<u64>().ok());
        let mut p = Physics::TOR_Q13;
        if let Some(v) = get("NETSIM_LEG_MS") {
            p.leg_ms = v;
        }
        if let Some(v) = get("NETSIM_APPLY_MS") {
            p.apply_ms = v;
        }
        p
    }
}

struct Due {
    at: u64,
    seq: u64,
    bytes: Vec<u8>,
    /// The node that sent it, and whether it answers a bulk ask (the asker's census counts those).
    from: usize,
    answer: bool,
    /// The answered ask's kind (its first byte), for the per-kind census.
    kind: u8,
    /// ⭐ DB-445: a follow answer built after its host's own production woke the hold (`BulkServeTurn::FollowWake`).
    wake: bool,
    /// ⭐ DB-450: the answer to a bulk ask, filed for DB-348's rotation — the ask's `arti_transport::bulk_rotation_key` and
    /// whether the answer carries nothing for it (`node_runtime::bulk_answer_carries_nothing`, the predicate arti's deposit
    /// reads). None on a cell, a follow page or a pushed page.
    rotation: Option<([u8; 32], bool)>,
}

struct Ask {
    at: u64,
    seq: u64,
    from: usize,
    to: usize,
    req: Vec<u8>,
}

/// The shared wire. O1-FOOTPRINT-REVIEWED: a test scaffold; every queue holds only what is in flight and is drained
/// by the simulation's own deliveries, never a node store.
struct Wire {
    n: usize,
    phys: Physics,
    now: AtomicU64,
    /// ⭐ ONE CLOCK PER NODE (the conservative window, [`NetSim::step_window`]): inside a window each node's thread runs its
    /// own steps, so each endpoint reads ITS node's simulated instant. Between windows every clock equals `now`.
    /// O1-FOOTPRINT-REVIEWED: one slot per simulated node.
    clocks: Vec<AtomicU64>,
    /// ⭐ ONE STREAM PER SENDER (2026-10-06, parallel stepping): every node's sends draw their jitter from that node's own
    /// generator and number themselves from its own counter, so a run is the same whatever order the nodes' threads run
    /// in — each node's sends happen in its own program order. O1-FOOTPRINT-REVIEWED: one slot per simulated node.
    seqs: Vec<AtomicU64>,
    rngs: Vec<Mutex<Rng>>,
    cells: Vec<Mutex<Vec<Due>>>,
    link_tail: Mutex<Vec<u64>>,
    /// ⭐ THE CELL LANE HAS A CAPACITY (link 65). `link_depart[from * n + to]`: the µs instant that link finishes
    /// SERIALIZING the last real cell put on it, at `phys.bytes_per_ms` (one 4 KB cell = 27.3 ms at Q13's 150 B/ms) — the
    /// arti writer's awaited write. ⛔ MEASURED why (link 64, night/perf-load-20261021-015211-n8.log): real cells offered
    /// 946 B/ms per link, 6.3× the wire, and this lane delivered them all at one leg each, free — the largest consumer of
    /// every node's link (87 % of inbound bytes) was uncharged in every P10/P11 row.
    /// Fidelity, stated: cover is free (production's fan-out drops a cover page whenever real payload waits, so cover
    /// only fills an idle link); the bulk lanes keep their own per-answer rate (Tor would multiplex both on one circuit,
    /// so this is the OPTIMISTIC bound for each). O1-FOOTPRINT-REVIEWED: n² instants of a test scaffold.
    link_depart: Mutex<Vec<u64>>,
    /// Real cells a FULL writer shed, per class: past `WRITER_LANE_PAGES + WRITER_PARK_PAGES` pages of backlog a data
    /// cell is dropped (production sheds its oldest parked non-control page; this sheds the newest — the same count, a
    /// different victim), a control cell (TipBeacon, SyncReq, ChunkReq, BlockAck/Vote: `is_control_page`) never.
    /// O1-FOOTPRINT-REVIEWED: one counter per cell class.
    shed: Vec<AtomicU64>,
    /// How long real cells waited for their link to free (send → serialization start), per send, in buckets of
    /// [`CELL_WAIT_EDGES_MS`]. O1-FOOTPRINT-REVIEWED: a fixed histogram.
    cell_wait: Vec<AtomicU64>,
    /// ⭐ WHICH MESSAGES THE CELLS CARRY ([`CellMsgCensus`]), counted only while `rx_on`.
    cell_msgs: Mutex<CellMsgCensus>,
    asks: Mutex<Vec<Ask>>,
    answers: Vec<Mutex<Vec<Due>>>,
    /// DB-326 follow asks on their way to their server.
    follows: Mutex<Vec<Ask>>,
    /// Follows held at their server: (ask, hold deadline, the server's production count when last built — `usize::MAX`
    /// before its arrival build —, that last build).
    held: Mutex<Vec<(Ask, u64, usize, Vec<u8>)>>,
    /// `follow_out[from * n + to]`: a follow is in flight on that link (arti's per-host `FOLLOW_HOSTS`).
    follow_out: Mutex<Vec<bool>>,
    /// ⭐ DB-446 / DB-275b: per node, the host whose answer last LISTED ids (a kind-18 inventory, or a follow page's
    /// inventory tail) — its GETDATA (kind 19) goes there, as arti's `bulk_inv_host`; `usize::MAX` before any.
    inv_host: Vec<AtomicUsize>,
    /// ⭐ DB-450: per node, the hosts that answered an ask with NOTHING for it, by its rotation key — arti's `BULK_NOTFOUND`
    /// (DB-348), which arti keeps process-wide (one node per daemon) and which dies with the process.
    /// O1-FOOTPRINT-REVIEWED: at most arti's `BULK_NOTFOUND_CAP` entries per simulated node (`note_answer_in`).
    notfound: Vec<Mutex<std::collections::VecDeque<([u8; 32], usize)>>>,
    /// ⭐ DB-347: real-cell COPIES each node put on its links (one per destination), the per-node upload the scale
    /// standard forbids growing with peer count. O1-FOOTPRINT-REVIEWED: one counter per simulated node.
    sent_real: Vec<AtomicU64>,
    /// Follow answers on their way back: (arrives at, link), so the link frees when its answer lands.
    follow_land: Mutex<Vec<(u64, usize)>>,
    /// ⛔ ADVERSARY TOPOLOGY (DB-380, user 2026-10-04 "plan for the worst"): `blocked[from * n + to]` — a severed link.
    /// A cell, ask, follow or oracle page on a blocked link is DROPPED, never delivered and never an error: an eclipse
    /// is silence, not a refusal. O1-FOOTPRINT-REVIEWED: n² booleans of a test scaffold.
    blocked: Mutex<Vec<bool>>,
    /// N8: `foreign[a * n + b]` — node a learned node b is on another network (its beacon named another genesis), so a's asks
    /// never pick b again (`SimEndpoint::exclude_link`, arti's foreign-link set).
    foreign: Mutex<Vec<bool>>,
    /// A node whose process is DOWN (between its shutdown save and its boot): every link to and from it drops traffic.
    /// O1-FOOTPRINT-REVIEWED: one flag per simulated node.
    down: Vec<std::sync::atomic::AtomicBool>,
    /// ⭐ DB-420 THE LOOKAHEAD CENSUS — the last simulated instant of the window now running ([`NetSim::step_window`]).
    window_end: AtomicU64,
    /// Sends to ANOTHER node that could land inside the window they were sent in: each one a broken lookahead (the
    /// receiver's thread may already have run past that instant, or not — the run then depends on thread timing). 0 on
    /// every correct run; [`NetSim::lookahead_breaks`] reads it.
    early: AtomicU64,
    /// The ASK CENSUS, per node: bulk asks addressed to it, asks it served, and the steps its charged runtime lock was still
    /// busy (no ask served, no tick) out of all its steps — so a node that is never asked, or never free to answer, is a
    /// number in `diag`, not a guess. O1-FOOTPRINT-REVIEWED: four counters per simulated node.
    ask_census: Vec<[AtomicU64; 4]>,
    /// ⭐ THE INBOUND-BYTES CENSUS ([`RxCensus`]), per receiving node; counted only while `rx_on` (the load scenario turns it
    /// on), so no other simulation pays its decode.
    rx_on: std::sync::atomic::AtomicBool,
    rx: Vec<Mutex<RxCensus>>,
    /// Conversations open on each link (`open[asker * n + host]`: asks and follows sent, answers not yet landed), and the
    /// sends that found `BULK_LANES_PER_HOST` already open — the ones arti's per-host lanes would have queued, which this
    /// wire still delivers in parallel. O1-FOOTPRINT-REVIEWED: n² counters of a test scaffold.
    open: Mutex<Vec<u32>>,
    over_lanes: AtomicU64,
    open_max: AtomicU64,
    /// Real cell COPIES put on links, by the pump's kind tag (`transport::CELL_KIND_NAMES`): what the cell lane carries.
    /// O1-FOOTPRINT-REVIEWED: one counter per cell class.
    cell_kinds: Vec<AtomicU64>,
    /// By-RECORD-id answers (DB-433) each asker took, per host: [carried a record, the header alone = `notfound`].
    /// O1-FOOTPRINT-REVIEWED: n² pairs of counters of a test scaffold.
    rec_answers: Mutex<Vec<[u64; 2]>>,
    /// Per bulk ask kind (its first byte): [asks sent, answers taken, answers that carried nothing, the longest wait in ms
    /// an answer sat due before its asker took it]. O1-FOOTPRINT-REVIEWED: 256 × 4 counters of a test scaffold.
    ask_kinds: Mutex<Vec<[u64; 4]>>,
}

/// The census's kinds, in print order: a body is FRESH the first time the node is handed it over any bulk lane (and it did
/// not produce it), a DUPLICATE every later time; a fresh body of 256 KB or more carries the note-transition aggregate
/// (553 KB alone; a block without one is ~46 KB).
pub const RX_KINDS: usize = 9;
pub const RX_LABELS: [&str; RX_KINDS] = [
    "follow fresh ≥256 KB",
    "follow fresh <256 KB",
    "follow duplicate",
    "by-id/batch fresh ≥256 KB",
    "by-id/batch fresh <256 KB",
    "by-id/batch duplicate",
    "block-lane framing, shells, inventories",
    "record/DA/sync/other pages",
    "cells",
];

/// ⭐ THE INBOUND-BYTES CENSUS (PERF TIER P10, link 64): what each node's links carried TO it, by lane and by whether the
/// block body was new to that node — the wire-level measure of the follow lane's duplicates (link 61 counted them as
/// bodies; this counts the bytes a link spent on them).
/// Fidelity, stated: a node restarted inside a census keeps its `seen` set (the load scenario restarts nothing).
/// O1-FOOTPRINT-REVIEWED: a test scaffold's measurement — the id set grows with the run's blocks and dies with the simulation.
#[derive(Default)]
struct RxCensus {
    seen: HashSet<[u8; 32]>,
    bytes: [u64; RX_KINDS],
    bodies: [u64; RX_KINDS],
    /// The "record/DA/sync/other" bytes by page tag (its leading ASCII tag, or "untagged" for a record page).
    other: HashMap<String, u64>,
    /// Per block body, the instant it first LANDED at this node and the lane that carried it (0 follow, 3 by-id/batch,
    /// [`RX_PRODUCED_HERE`] its own production) — the load scenario's split of a block's spread into the wire's term and
    /// the node's own (landed → in its DAG).
    first: HashMap<[u8; 32], (u64, u8)>,
    /// ⭐ DB-445: every body a WOKEN follow page carried, with the host that sent it, and how many of those this node
    /// already held — the follower's own record of what a host's production woke it to send.
    woken: Vec<(usize, [u8; 32])>,
    woken_dup: u64,
    /// ⭐ DB-446: every body ANY follow page carried (arrival or woken), with the host that sent it.
    followed: Vec<(usize, [u8; 32])>,
    /// The host whose page first landed each body here (absent for a body this node produced).
    first_from: HashMap<[u8; 32], usize>,
    /// ⭐ WHERE EACH DUPLICATE'S FIRST COPY CAME FROM (link 69): rows = the duplicate's own lane [`DUP_ROWS`], columns = the
    /// first copy's [`DUP_COLS`] — so "1.1 duplicates per fresh" splits into the races that make them.
    dup_src: [[u64; 4]; 3],
}

/// [`RxCensus::dup_src`]'s rows: the lane a DUPLICATE body arrived by.
pub const DUP_ROWS: [&str; 3] = ["follow woken", "follow arrival", "by-id/batch"];
/// [`RxCensus::dup_src`]'s columns: how its FIRST copy had arrived.
pub const DUP_COLS: [&str; 4] = ["follow same host", "follow other host", "by-id/batch", "produced here"];

/// [`RxCensus::first`]'s lane for a block this node produced itself.
const RX_PRODUCED_HERE: u8 = u8::MAX;

impl RxCensus {
    /// One landed bulk page at sim instant `now`: block bodies by lane and freshness, everything else by kind; `from` names
    /// the page's host and whether its own production woke it (DB-445) — read for follow pages only.
    fn page(&mut self, page: &[u8], now: u64, from: Option<(usize, bool)>) {
        let follow = page.starts_with(b"BLOCKFOLW");
        let woken = from.filter(|(_, w)| *w && follow).map(|(h, _)| h);
        let (lane, mut off) = if page.starts_with(b"BLOCKFOLW") {
            (0, 9 + 32)
        } else if page.starts_with(b"BLOCKBTCH") {
            (3, 9 + 32)
        } else if page.starts_with(b"BLOCKFULL") {
            (3, 9)
        } else {
            let block_lane = [&b"BLOCKPAGE"[..], b"BLOCKINV", b"FINCERTS", b"LADDRESP"].iter().any(|p| page.starts_with(p));
            self.bytes[if block_lane { 6 } else { 7 }] += page.len() as u64;
            if !block_lane {
                let tag: String = page.iter().take(9).take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || **b == b'_').map(|&b| b as char).collect();
                let tag = if tag.len() >= 6 { tag } else { "untagged".to_string() };
                *self.other.entry(tag).or_default() += page.len() as u64;
            }
            return;
        };
        let mut body_bytes = 0usize;
        while off + 4 <= page.len() {
            let len = u32::from_le_bytes(page[off..off + 4].try_into().unwrap_or([0u8; 4])) as usize;
            if len == 0 || off + 4 + len > page.len() {
                break;
            }
            let bytes = &page[off + 4..off + 4 + len];
            off += 4 + len;
            let Some(b) = crate::chain_object::decode_exact::<crate::block::Block>(bytes) else { continue };
            let first = *self.first.entry(b.id().0).or_insert((now, lane as u8));
            let fresh = self.seen.insert(b.id().0);
            let host = from.map(|(h, _)| h);
            if fresh {
                if let Some(h) = host {
                    self.first_from.insert(b.id().0, h);
                }
            } else {
                let row = if !follow { 2 } else if woken.is_some() { 0 } else { 1 };
                let col = match first.1 {
                    RX_PRODUCED_HERE => 3,
                    0 if self.first_from.get(&b.id().0).copied() == host => 0,
                    0 => 1,
                    _ => 2,
                };
                self.dup_src[row][col] += 1;
            }
            if let (true, Some((host, _))) = (follow, from) {
                self.followed.push((host, b.id().0));
            }
            if let Some(host) = woken {
                self.woken.push((host, b.id().0));
                self.woken_dup += u64::from(!fresh);
            }
            let k = match (fresh, len >= 256 << 10) {
                (true, true) => lane,
                (true, false) => lane + 1,
                (false, _) => lane + 2,
            };
            self.bytes[k] += 4 + len as u64;
            self.bodies[k] += 1;
            body_bytes += 4 + len;
            if lane == 3 && page.starts_with(b"BLOCKFULL") {
                break; // a by-id tip page carries one body
            }
        }
        self.bytes[6] += (page.len() - body_bytes) as u64;
    }
}

/// The cell-wait histogram's bucket edges ([`Wire::cell_wait`]): a send waited `< edge` ms for its link, the last bucket
/// everything past the largest edge.
pub const CELL_WAIT_EDGES_MS: [u64; 7] = [100, 1_000, 4_000, 16_000, 32_000, 64_000, 128_000];

/// ⭐ WHICH MESSAGES THE CELLS CARRY (link 65): per class, the pump's cell sends (one per send, before the per-link fan-out),
/// the sends that REPEAT a chunk the same node already sent (a ChunkReq replay, or the same payload queued again — the
/// chunk header's content-addressed msg id and seq name it, `net::chunk_payload`), the distinct messages, and the distinct
/// (sender, message) pairs — so "Tx is 91 % of cells" splits into how many payloads × how many senders × how many repeats.
/// O1-FOOTPRINT-REVIEWED: a test scaffold's measurement — the id sets grow with the run's messages and die with it.
#[derive(Default)]
struct CellMsgCensus {
    chunks: HashSet<(usize, u8, u64, u16)>,
    msgs: HashSet<(u8, u64)>,
    sender_msgs: HashSet<(usize, u8, u64)>,
    /// per class: [sends, repeat sends, distinct messages, distinct (sender, message)]
    rows: Vec<[u64; 4]>,
}

impl CellMsgCensus {
    fn cell(&mut self, from: usize, kind: u8, cell: &[u8]) {
        if self.rows.is_empty() {
            self.rows = vec![[0; 4]; crate::transport::CELL_KIND_SLOTS];
        }
        let len = u32::from_le_bytes(cell[0..4].try_into().unwrap_or([0; 4])) as usize;
        if len < crate::net::CHUNK_HDR || 4 + len > cell.len() {
            return;
        }
        let msg = u64::from_le_bytes(cell[4..12].try_into().unwrap_or([0; 8]));
        let seq = u16::from_le_bytes(cell[12..14].try_into().unwrap_or([0; 2]));
        let row = &mut self.rows[usize::from(kind).min(crate::transport::CELL_KIND_SLOTS - 1)];
        row[0] += 1;
        row[1] += u64::from(!self.chunks.insert((from, kind, msg, seq)));
        row[2] += u64::from(self.msgs.insert((kind, msg)));
        row[3] += u64::from(self.sender_msgs.insert((from, kind, msg)));
    }
}

impl Wire {
    /// The bytes in flight on the wire (cells, asks, answers, follows) — the `[mem]` line's harness term, so a footprint that
    /// grows is never charged to a node when the simulation's own queues hold it.
    fn queued_bytes(&self) -> usize {
        let lock = |m: &Mutex<Vec<Due>>| m.lock().map(|q| q.iter().map(|d| d.bytes.len()).sum::<usize>()).unwrap_or(0);
        let asks = |m: &Mutex<Vec<Ask>>| m.lock().map(|q| q.iter().map(|a| a.req.len()).sum::<usize>()).unwrap_or(0);
        self.cells.iter().map(lock).sum::<usize>()
            + self.answers.iter().map(lock).sum::<usize>()
            + asks(&self.asks)
            + asks(&self.follows)
    }

    /// `queued_bytes` by queue — (count, bytes) of cells, answers, asks, follows (the §SIMMEM pin's wire term).
    fn queued_parts(&self) -> [(usize, usize); 4] {
        let due = |v: &[Mutex<Vec<Due>>]| {
            v.iter().fold((0, 0), |(c, b), m| m.lock().map_or((c, b), |q| (c + q.len(), b + q.iter().map(|d| d.bytes.len()).sum::<usize>())))
        };
        let asks = |m: &Mutex<Vec<Ask>>| m.lock().map_or((0, 0), |q| (q.len(), q.iter().map(|a| a.req.len()).sum::<usize>()));
        [due(&self.cells), due(&self.answers), asks(&self.asks), asks(&self.follows)]
    }

    /// EVERY send to another node passes here with its delivery instant `at` (a cell, an ask, a follow, an answer, an
    /// oracle page): the conservative window is sound only if nothing sent inside it can land inside it.
    fn sent(&self, at: u64) {
        if at <= self.window_end.load(Ordering::Relaxed) {
            self.early.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// Node `i`'s simulated instant (its endpoint's clock).
    fn clock(&self, i: usize) -> u64 {
        self.clocks[i].load(Ordering::Relaxed)
    }
    /// The instant a send of node `i` leaves: its clock plus the CPU its lock-held step has spent so far
    /// ([`step_charge_us`] — 0 unless the simulation charges node CPU).
    fn send_clock(&self, i: usize) -> u64 {
        self.clock(i) + step_charge_us() / 1_000
    }
    /// Whether `from → to` is severed.
    fn is_foreign(&self, from: usize, to: usize) -> bool {
        self.foreign.lock().unwrap()[from * self.n + to]
    }
    fn is_blocked(&self, from: usize, to: usize) -> bool {
        self.down[from].load(Ordering::Relaxed) || self.down[to].load(Ordering::Relaxed) || self.blocked.lock().unwrap()[from * self.n + to]
    }
    /// The next send number of `from`: its own counter, interleaved with the others' by sender id — a total order at
    /// equal delivery instants that no thread schedule can change.
    fn seq(&self, from: usize) -> u64 {
        self.seqs[from].fetch_add(1, Ordering::Relaxed) * self.n as u64 + from as u64
    }
    /// One leg sent by `from`, its jitter drawn from `from`'s own stream.
    fn leg(&self, from: usize) -> u64 {
        self.phys.leg_ms + self.rngs[from].lock().unwrap().below(self.phys.jitter_ms + 1)
    }
    /// The peer a bulk ask goes to. With two parties it is the other one; with more, the ask is hashed onto a peer,
    /// the shape of arti's `pick_bulk_host`, and a GETDATA (kind 19) goes to the host that last listed ids to this node
    /// (DB-275b's affinity, which DB-446's follow inventory sets too) while that host is reachable.
    /// ⭐ DB-450 — DB-348'S ROTATION, BY ARTI'S OWN RULE (`bulk_rotation_candidates` over `bulk_rotation_key`, every circuit
    /// at penalty 0 since a simulated link never times out): the hosts that answered this ask with nothing are skipped
    /// until every reachable host has been, then the round starts again. MEASURED why (link 73, db448 sim pin RED 2 of 6,
    /// night/link73-final-db448_.log): node 3 alone held its first block's record, and nodes 0–2 each re-sent the same
    /// stable by-record-id ask (DB-350) onto a non-holder 6,046–6,048 times — their folds never left ordinal 1 in 1,281 s,
    /// where a daemon's second ask moves to the next host (Bitcoin Core `TxRequestTracker`: NOTFOUND → next candidate).
    /// ⛔ FIDELITY GAP still stated (link 64): arti never deposits an EMPTY frame (`bulk_exchange`'s "nothing here"); here
    /// the runtime sees it as a zero-length page. Modeling that too hit a DA-sampling ask storm (branch
    /// wip/chain-20261021-0130-sim-arti-routing), whose cause is open.
    fn host_for(&self, me: usize, req: &[u8]) -> Option<usize> {
        // only peers this node can still reach: a severed link is not a host (DB-380), nor a peer of another network (N8)
        let reachable: Vec<usize> =
            (0..self.n).filter(|&i| i != me && !self.is_blocked(me, i) && !self.is_foreign(me, i)).collect();
        if reachable.is_empty() {
            return None;
        }
        let others: Vec<usize> = {
            let key = crate::arti_transport::bulk_rotation_key(req);
            let mut nf = self.notfound[me].lock().unwrap();
            // arti names a host by its onion; here by its index, spelled as a string for the one shared rule
            let hosts: Vec<String> = reachable.iter().map(usize::to_string).collect();
            let empty: Vec<String> = nf.iter().filter(|(k, _)| *k == key).map(|(_, h)| h.to_string()).collect();
            let (pool, all_tried) = crate::arti_transport::bulk_rotation_candidates(req, &hosts, |_| 0, &empty);
            let pool: Vec<usize> = pool.into_iter().filter_map(|h| h.parse().ok()).collect();
            if all_tried {
                nf.retain(|(k, _)| *k != key); // a record may have reached a peer since
            }
            pool
        };
        if req.first() == Some(&19) {
            let h = self.inv_host[me].load(Ordering::Relaxed);
            if others.contains(&h) {
                return Some(h);
            }
        }
        // R4: every part of one block pull goes to one host, as arti's pick does (`block_part`)
        let h = Hash32::hash(if crate::block_part::parse_ask_any(req).is_some() { &req[..33] } else { req });
        let k = u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap_or([0u8; 8])) as usize;
        Some(others[k % others.len()])
    }

    /// DB-450: node `me` took `host`'s answer to the ask filed under `key` — arti's `bulk_note_answer` (one shared rule,
    /// `arti_transport::note_answer_in`): an answer that carried nothing excludes that host from the ask's next pick, a
    /// page clears the ask.
    fn note_answer(&self, me: usize, key: &[u8; 32], host: usize, nothing: bool) {
        crate::arti_transport::note_answer_in(&mut self.notfound[me].lock().unwrap(), key, &host, nothing);
    }

    /// A conversation opens on `from → to` (an ask or a follow); counts the sends arti's lanes would have queued.
    fn open_conversation(&self, from: usize, to: usize) {
        let mut open = self.open.lock().unwrap();
        let k = from * self.n + to;
        if open[k] as usize >= crate::arti_transport::BULK_LANES_PER_HOST {
            self.over_lanes.fetch_add(1, Ordering::Relaxed);
        }
        open[k] += 1;
        self.open_max.fetch_max(u64::from(open[k]), Ordering::Relaxed);
    }

    fn close_conversation(&self, from: usize, to: usize) {
        let mut open = self.open.lock().unwrap();
        let k = from * self.n + to;
        open[k] = open[k].saturating_sub(1);
    }
}

/// Replay calibration (lane b, T3): `REPLAY_WIRE_TRACE=<lo>-<hi>` prints every real cell sent or taken whose instant
/// falls in [lo, hi] ms — two runs of one seed then diff wire event by wire event.
fn wire_trace(ev: &str, me: usize, peer: usize, now: u64, at: u64, seq: u64, cell: &[u8]) {
    static RANGE: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();
    let (lo, hi) = *RANGE.get_or_init(|| {
        std::env::var("REPLAY_WIRE_TRACE")
            .ok()
            .and_then(|v| v.split_once('-').and_then(|(a, b)| Some((a.parse().ok()?, b.parse().ok()?))))
            .unwrap_or((1, 0))
    });
    if (lo..=hi).contains(&now) {
        eprintln!(
            "[wire-trace] n{me} {ev} peer {peer} now {now} at {at} seq {seq} {} kind {:?} len {} head {}",
            &Hash32::hash(cell).to_hex()[..8],
            cell.first(),
            cell.len(),
            cell[..cell.len().min(40)].iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }
}

/// Take up to `max` items due by `now`, earliest first (ties by send order), leaving the rest queued.
fn pop_due_entries(q: &Mutex<Vec<Due>>, now: u64, max: usize) -> Vec<Due> {
    let mut q = q.lock().unwrap();
    q.sort_by_key(|d| (d.at, d.seq));
    let n = q.iter().take_while(|d| d.at <= now).count().min(max);
    q.drain(..n).collect()
}

/// One party's endpoint on the simulated wire: the SAME `CellTransport` surface arti implements, with a bulk lane.
pub struct SimEndpoint {
    wire: Arc<Wire>,
    me: usize,
}

impl SimEndpoint {
    /// One bulk ask from this node to node `to`, one leg out (both the hashed and the aimed door send through here).
    fn ask_to(&self, to: usize, req: &[u8]) -> bool {
        self.wire.ask_census[to][0].fetch_add(1, Ordering::Relaxed);
        self.wire.open_conversation(self.me, to);
        self.wire.ask_kinds.lock().unwrap()[usize::from(req.first().copied().unwrap_or(0))][0] += 1;
        let (at, seq) = (self.wire.send_clock(self.me) + self.wire.leg(self.me), self.wire.seq(self.me));
        self.wire.sent(at);
        wire_trace("ask", self.me, to, self.wire.clock(self.me), at, seq, req); // REPLAY_WIRE_TRACE: the bulk lane too
        self.wire.asks.lock().unwrap().push(Ask { at, seq, from: self.me, to, req: req.to_vec() });
        true
    }
}

/// ⭐ DB-412 — the simulated node's PEERING, counted the way arti counts it: `live_writers` is the number of peers this
/// node holds a live outbound link to — every other node whose link is not severed and whose process is up
/// (`Wire::is_blocked`). The wire is already connected, so `add` dials nothing and there is no own onion identity.
///
/// ⛔ MEASURED (link 18, pin `db412_…` run sim-20261007-080527): the endpoint inherited [`crate::transport::NoPeering`]
/// (`live_writers` = 0, right for a loopback, which peers with nobody), so EVERY simulated node took the lone-node branch
/// of `fair_share_spacing_ms` and produced at the 500 ms mesh target — 382 and 327 blocks in 320 s with no rate cap — and
/// the name directory's anti-entropy (`writers_now > 0`) never ran. The journeys hid the first behind a 4 s simulator cap
/// that the daemon does not have. A simulated node now sees its peers exactly as an onion node does.
struct SimPeering {
    wire: Arc<Wire>,
    me: usize,
}

impl crate::transport::PeerPeering for SimPeering {
    fn add(&self, _peer_id: &str, _addr: &str, _x_pk: &[u8], _ek: &[u8]) -> bool {
        true // the simulated wire is connected by construction — nothing to dial
    }
    fn own_identity(&self) -> Option<(String, Vec<u8>, Vec<u8>)> {
        None
    }
    /// §BR-6: node j's dialable name on the simulated wire (`SimEndpoint::mix_request_to` resolves it).
    fn own_address(&self) -> Option<String> {
        Some(format!("simnode{}", self.me))
    }
    fn live_writers(&self) -> usize {
        (0..self.wire.n).filter(|&j| j != self.me && !self.wire.is_blocked(self.me, j)).count()
    }
}

impl CellTransport for SimEndpoint {
    /// DB-416: the simulated clock is this endpoint's clock — every timer the runtime stamps reads it.
    fn clock_ms(&self) -> Option<u64> {
        Some(self.wire.clock(self.me))
    }
    /// An untagged send goes as the pump's "other" class (every pump send is tagged; this is the trait's plain door).
    fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError> {
        self.send_cell_kind(cell, 15)
    }
    /// ⭐ ONE REAL CELL ONTO EVERY LIVE LINK, each link a serializing writer ([`Wire::link_depart`]): the cell starts when the
    /// link has finished the cells before it, takes `CELL_SIZE / bytes_per_ms` on the wire, then one leg. A writer holding
    /// `WRITER_LANE_PAGES + WRITER_PARK_PAGES` pages of backlog sheds a data cell ([`Wire::shed`]); a control cell (the
    /// fan-out's `is_control_page` classes) parks at the FRONT of the park — behind the lane, ahead of parked data — and is
    /// never shed. A circuit is a stream: a data cell never overtakes an earlier one on its link.
    fn send_cell_kind(&self, cell: Vec<u8>, kind: u8) -> Result<(), NetError> {
        if cell.len() != CELL_SIZE {
            return Err(NetError::BadCell);
        }
        if crate::net::is_cover(&cell) {
            return Ok(()); // cover is wire padding: it costs a slot at the sender, carries nothing to deliver
        }
        let k = usize::from(kind).min(crate::transport::CELL_KIND_SLOTS - 1);
        if self.wire.rx_on.load(Ordering::Relaxed) {
            off_lock(|| self.wire.cell_msgs.lock().unwrap().cell(self.me, k as u8, &cell));
        }
        let control = crate::transport::is_control_kind(k);
        let now = self.wire.send_clock(self.me);
        let now_us = now * 1_000;
        let cell_us = CELL_SIZE as u64 * 1_000 / self.wire.phys.bytes_per_ms.max(1);
        let lane_us = (crate::arti_transport::WRITER_LANE_PAGES * crate::arti_transport::WRITER_PAGE_CELLS) as u64 * cell_us;
        let cap_us = ((crate::arti_transport::WRITER_LANE_PAGES + crate::arti_transport::WRITER_PARK_PAGES)
            * crate::arti_transport::WRITER_PAGE_CELLS) as u64
            * cell_us;
        for to in 0..self.wire.n {
            if to == self.me || self.wire.is_blocked(self.me, to) {
                continue; // a severed link carries nothing (DB-380)
            }
            let leg = self.wire.leg(self.me);
            let l = self.me * self.wire.n + to;
            let start_us = {
                let mut depart = self.wire.link_depart.lock().unwrap();
                let tail = depart[l].max(now_us);
                if control {
                    // ahead of the parked data, behind the lane; the data behind it departs one cell later
                    depart[l] = tail + cell_us;
                    tail.min(now_us + lane_us)
                } else if tail - now_us >= cap_us {
                    self.wire.shed[k].fetch_add(1, Ordering::Relaxed);
                    continue; // the writer is full: shed, as the fan-out sheds a page past its park
                } else {
                    depart[l] = tail + cell_us;
                    tail
                }
            };
            let waited_ms = (start_us - now_us) / 1_000;
            let b = CELL_WAIT_EDGES_MS.iter().position(|&e| waited_ms < e).unwrap_or(CELL_WAIT_EDGES_MS.len());
            self.wire.cell_wait[b].fetch_add(1, Ordering::Relaxed);
            let mut at = (start_us + cell_us).div_ceil(1_000) + leg;
            if !control {
                let mut tails = self.wire.link_tail.lock().unwrap();
                at = at.max(tails[l]);
                tails[l] = at;
            }
            let seq = self.wire.seq(self.me);
            self.wire.cell_kinds[k].fetch_add(1, Ordering::Relaxed);
            self.wire.sent_real[self.me].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.wire.sent(at);
            wire_trace(&format!("send k{k}"), self.me, to, now, at, seq, &cell);
            self.wire.cells[to].lock().unwrap().push(Due { at, seq, bytes: cell.clone(), from: self.me, answer: false, kind: 0, wake: false, rotation: None });
        }
        Ok(())
    }
    fn recv_cell(&self) -> Option<Vec<u8>> {
        self.recv_cell_from().map(|(c, _)| c)
    }
    /// DB-448: a cell's link is its sender's index (`Due.from`) — what arti's link id names on a real mesh.
    fn recv_cell_from(&self) -> Option<(Vec<u8>, Option<u64>)> {
        let d = pop_due_entries(&self.wire.cells[self.me], self.wire.clock(self.me), 1).pop()?;
        wire_trace("take", self.me, d.from, self.wire.clock(self.me), d.at, d.seq, &d.bytes);
        if self.wire.rx_on.load(Ordering::Relaxed) {
            self.wire.rx[self.me].lock().unwrap().bytes[8] += CELL_SIZE as u64;
        }
        Some((d.bytes, Some(d.from as u64)))
    }
    fn has_bulk_lane(&self) -> bool {
        true
    }
    fn bulk_raw_request(&self, req: &[u8]) -> bool {
        // an eclipsed node's ask goes nowhere, silently — the transport reports "sent" as a real circuit would
        let Some(to) = self.wire.host_for(self.me, req) else { return true };
        self.ask_to(to, req)
    }
    /// DB-448: aimed at node `link` while this node can reach it, else the hashed host (arti resolves its link id the same
    /// way, into its address book).
    /// §BR-6: a registration to the coordinator node the address names (`simnode{j}` — what `SimPeering::own_address`
    /// gives node j); never the hashed host.
    fn mix_request_to(&self, addr: &str, req: &[u8]) -> bool {
        let to = addr.strip_prefix("simnode").and_then(|j| j.parse::<usize>().ok());
        match to.filter(|&to| to < self.wire.n && to != self.me && !self.wire.is_blocked(self.me, to)) {
            Some(to) if req.first() == Some(&crate::entry_mix::BULK_REQ_KIND_MIX) => self.ask_to(to, req),
            _ => false,
        }
    }
    /// N8: node `link` is on another network — it leaves this node's host pick, as arti drops its onion from the pool.
    fn exclude_link(&self, link: u64) {
        if let Ok(to) = usize::try_from(link) {
            if to < self.wire.n && to != self.me {
                self.wire.foreign.lock().unwrap()[self.me * self.wire.n + to] = true;
            }
        }
    }
    fn bulk_raw_request_to(&self, req: &[u8], link: u64) -> bool {
        let aimed = usize::try_from(link)
            .ok()
            .filter(|&to| to < self.wire.n && to != self.me && !self.wire.is_blocked(self.me, to) && !self.wire.is_foreign(self.me, to));
        match aimed {
            Some(to) => self.ask_to(to, req),
            None => self.bulk_raw_request(req),
        }
    }
    fn take_bulk_responses(&self, max: usize) -> Vec<Vec<u8>> {
        let mut pages = Vec::new();
        // every page's host and whether a host's own production woke it (DB-445), for the census
        let mut hosts: Vec<(usize, bool)> = Vec::new();
        for d in pop_due_entries(&self.wire.answers[self.me], self.wire.clock(self.me), max) {
            wire_trace("take", self.me, d.from, self.wire.clock(self.me), d.at, d.seq, &d.bytes); // REPLAY_WIRE_TRACE
            if d.answer {
                if let Some((key, nothing)) = d.rotation {
                    self.wire.note_answer(self.me, &key, d.from, nothing); // arti's deposit notes it first (DB-348)
                }
                {
                    let mut k = self.wire.ask_kinds.lock().unwrap();
                    let row = &mut k[usize::from(d.kind)];
                    row[1] += 1;
                    // an empty frame, or a tx fetch's tagged `notfound` (`TXBODIES ‖ id`, DB-444) — the census read only the
                    // first, so a hashed tx fetch's notfound counted as delivered (MEASURED link 72: 26 fetches for 12 bodies)
                    let tx_notfound = d.kind == crate::arti_transport::BULK_REQ_KIND_TX_FETCH && d.bytes.len() == 8 + 32;
                    row[2] += u64::from(d.bytes.is_empty() || tx_notfound);
                    row[3] = row[3].max(self.wire.clock(self.me).saturating_sub(d.at));
                }
                self.wire.close_conversation(self.me, d.from);
                // a by-record-id answer names its ask in its header's second word on a by-id page (DB-433)
                if d.bytes.len() >= 32 && d.bytes[16..24] == [0u8; 8] && d.bytes[8..16] != [0u8; 8] {
                    self.wire.rec_answers.lock().unwrap()[self.me * self.wire.n + d.from][usize::from(d.bytes.len() == 32)] += 1;
                }
            }
            hosts.push((d.from, d.wake));
            // DB-446 / DB-275b: an answer that lists ids makes its host this node's GETDATA host (arti's `bulk_inv_host`)
            let lists = d.bytes.starts_with(b"BLOCKINV")
                || (d.bytes.starts_with(b"BLOCKFOLW") && crate::node_runtime::follow_page_inventory(&d.bytes[9..]).is_some());
            if lists {
                self.wire.inv_host[self.me].store(d.from, Ordering::Relaxed);
            }
            pages.push(d.bytes);
        }
        if !pages.is_empty() && self.wire.rx_on.load(Ordering::Relaxed) {
            // the census is the simulation's own measurement: its body decodes are never charged as the node's CPU
            // (MEASURED link 64: charged, they held node 0's lock busy in 10,177 of 25,620 steps and 63 of 72 notes never
            // became spendable)
            off_lock(|| {
                let mut c = self.wire.rx[self.me].lock().unwrap();
                let now = self.wire.clock(self.me);
                for (p, from) in pages.iter().zip(&hosts) {
                    c.page(p, now, Some(*from));
                }
            });
        }
        pages
    }
    /// DB-326: one follow per link. ⛔ FIDELITY GAP, stated (link 64): arti keeps at most `FOLLOW_HOSTS_MAX` (3) follows,
    /// taken from its known hosts oldest first, so with one seed list every node follows the same first three peers and
    /// nobody follows the rest; this endpoint follows EVERY peer. Modeled on branch wip/chain-20261021-0130-sim-arti-routing:
    /// at n = 8 the load scenario then funded in 285 s and 479 s (100–106 s here) and one run left node 4 unable to build a
    /// spend (`MemberCarrierRequired` × 660, night/perf-load-20261021-014210-n8.log) — the follow choice is the fix to make.
    fn bulk_follow_request(&self, req: &[u8]) -> usize {
        let mut issued = 0usize;
        for to in (0..self.wire.n).filter(|&to| to != self.me && !self.wire.is_blocked(self.me, to)) {
            let k = self.me * self.wire.n + to;
            {
                let mut out = self.wire.follow_out.lock().unwrap();
                if out[k] {
                    continue;
                }
                out[k] = true;
            }
            let (at, seq) = (self.wire.send_clock(self.me) + self.wire.leg(self.me), self.wire.seq(self.me));
            self.wire.sent(at);
            self.wire.open_conversation(self.me, to);
            self.wire.follows.lock().unwrap().push(Ask { at, seq, from: self.me, to, req: req.to_vec() });
            issued += 1;
        }
        issued
    }
    /// DB-412: the peers this node holds a live link to, counted as arti counts its writers ([`SimPeering`]).
    fn peering(&self) -> Box<dyn crate::transport::PeerPeering> {
        Box::new(SimPeering { wire: Arc::clone(&self.wire), me: self.me })
    }
}

/// One gate-predicate sample.
#[derive(Clone, Debug)]
pub struct Sample {
    pub t_ms: u64,
    pub tips: Vec<u64>,
    /// Common selected blue scores at or below `min(tip) - 8` naming the SAME block on both nodes.
    pub agree: usize,
    /// … naming DIFFERENT blocks: the gate's CHAIN FORK.
    pub disagree: usize,
}

/// What a run measured.
#[derive(Debug, Default)]
pub struct Report {
    pub produced: Vec<u64>,
    /// Arrival latency at a peer, per (block, peer) pair that arrived inside the window.
    pub arrival_ms: Vec<u64>,
    /// (block, peer) pairs that had not arrived inside `ARRIVAL_WINDOW_MS`.
    pub never_arrived: u64,
    pub samples: Vec<Sample>,
    /// WALL milliseconds spent per phase: begin_produce, complete_produce_job (proving), PoW grind, finish_produce,
    /// relay ticks, serving asks. The simulated clock never advances while a node computes, so this is what makes a
    /// simulated second cost more or less than a real one.
    pub wall_ms: [u128; 6],
    /// PoW hashes every grind of the run tried (`pow::grind_tries(nonce)` each).
    pub hashes: u64,
    /// Windows of more than one step the run took ([`NetSim::step_window`]).
    pub windows: u64,
    /// `arrival_ms` split by the RECEIVING node (PERF TIER step 1: how fast each node follows its peers).
    pub arrival_ms_at: Vec<Vec<u64>>,
    /// Lock-held CPU charged to each node (µs), while [`NetSim::charge_cpu`] is on.
    pub lock_cpu_us: Vec<u64>,
    /// PERF TIER P13: every block the run produced, sized as a peer pulls it ([`block_size`]).
    pub block_sizes: Vec<BlockSize>,
    /// PERF TIER P10/P11: every template a node proved — its shape and its WALL prove time (what the sim charges as busy).
    pub proved: Vec<ProveSample>,
}

/// One `complete_produce_job` a node ran ([`Report::proved`]): whether the template stated a note transition (a spend), how
/// many constant-width spends rode its cover, the real txs it selected, and the wall milliseconds the prove took alone
/// ([`prove_alone`]).
#[derive(Clone, Debug)]
pub struct ProveSample {
    pub node: usize,
    pub spend: bool,
    pub covers: usize,
    pub txs: Vec<Hash32>,
    pub ms: u64,
    /// The simulated instant the template began, the ids its producer's pool held then (read off the lock, never charged),
    /// and the id of the block it mined — the load scenario's split of a spend's inclusion: how long the pool held it
    /// before a template laid it, and whether that template's block ever finished.
    pub begun: u64,
    pub pool: Vec<Hash32>,
    pub block: Option<Hash32>,
}

/// PERF TIER P13 — one produced block's bytes as a peer pulls it (`postcard` of the full block: the `BLOCKFULL` frame's and
/// the batch page's body, `node_runtime.rs` block lane), its parts, and the bodies of the spends it carries as the mempool
/// relayed them (`PqTx::blob`: ZK proof + confidential outputs). Measured by the simulation's observer OFF the lock
/// ([`off_lock`]), so it is never charged to the node.
#[derive(Clone, Debug, Default)]
pub struct BlockSize {
    pub wire: u64,
    pub txs: u64,
    /// The carried spends' bodies the producer's pool still held at finish (a tx it no longer held is not counted).
    pub spend_bodies: Vec<u64>,
    pub parts: Vec<(&'static str, u64)>,
}

/// Size `block` ([`BlockSize`]); `pool` is the producer's runtime, whose mempool holds the carried spends' bodies.
fn block_size(block: &crate::block::Block, pool: &Mutex<NodeRuntime<SimEndpoint>>) -> BlockSize {
    fn enc<T: serde::Serialize + ?Sized>(v: &T) -> u64 {
        postcard::to_allocvec(v).map_or(0, |b| b.len() as u64)
    }
    let sets = block.oli_tags.len()
        + block.account_targets.len()
        + block.bond_set.len()
        + block.credit_set.len()
        + block.dir_set.len()
        + block.letter_set.len();
    let nf = &block.nullifier_proof;
    let nf_parts = [nf.carrier.len(), nf.sparse_carrier.len(), nf.fold.len(), 32 * nf.padded_tags.len()].map(|n| n as u64);
    let parts = vec![
        ("pow_proof", block.pow_proof.len() as u64),
        ("nf carrier", nf_parts[0]),
        ("nf sparse_carrier", nf_parts[1]),
        ("nf fold", nf_parts[2]),
        ("nf padded_tags", nf_parts[3]),
        ("nf rest", enc(nf).saturating_sub(nf_parts.iter().sum())),
        ("note_transition", enc(&block.note_transition)),
        ("cover_transition", enc(&block.cover_transition)),
        ("member_transition", enc(&block.member_transition)),
        ("note_commitments", block.note_commitments.len() as u64),
        ("sets", sets as u64),
        ("header+tx_ids", enc(&block.header) + 32 * block.tx_ids.len() as u64),
    ];
    let spend_bodies = {
        let g = pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        block.tx_ids.iter().filter_map(|id| g.node().mempool().get(id).map(|t| t.blob.len() as u64)).collect()
    };
    BlockSize { wire: enc(block), txs: block.tx_ids.len() as u64, spend_bodies, parts }
}

impl Report {
    fn quantile(v: &[u64], p: f64) -> u64 {
        let mut v = v.to_vec();
        v.sort_unstable();
        if v.is_empty() {
            return 0;
        }
        v[((v.len() as f64 - 1.0) * p).round() as usize]
    }
    pub fn pct(&self, p: f64) -> u64 {
        Self::quantile(&self.arrival_ms, p)
    }
    /// The `p` quantile of the arrival latency of blocks born elsewhere AT node `i`.
    pub fn pct_at(&self, i: usize, p: f64) -> u64 {
        self.arrival_ms_at.get(i).map_or(0, |v| Self::quantile(v, p))
    }
    /// The fraction of samples in which the pair was ONE chain (no disagreement below `min(tip) - 8`).
    pub fn one_chain_fraction(&self) -> f64 {
        let s: Vec<&Sample> = self.samples.iter().filter(|s| s.agree + s.disagree > 0).collect();
        if s.is_empty() {
            return 0.0;
        }
        s.iter().filter(|s| s.disagree == 0).count() as f64 / s.len() as f64
    }
}

/// ⭐ THE SPEED METER (user 2026-10-06: every tier runs in the simulator at ≥ 24× simulated time per wall time). Where the
/// step loop's wall time goes, per phase, for THIS thread's simulation (thread-local, so parallel tests never mix), and how
/// much wall time passed outside the step loop (a caller's RPC reads, pacing sleeps). Read by [`speed_line`].
#[derive(Clone, Copy, Default)]
pub struct SpeedMeter {
    /// Simulated ms advanced.
    pub sim_ms: u64,
    /// Wall µs inside `step`, total and per phase ([`SPEED_PHASES`]).
    pub step_us: u128,
    pub phase_us: [u128; 10],
    /// ⭐ THE CRITICAL PATH (link 28). A window ends when its SLOWEST node's thread does, so the step loop's wall is the sum
    /// over windows of that one node's work, never the sum over nodes: `crit_us` is, per phase, what the slowest node of
    /// each window spent; `crit_total_us` their sum; `node_us` every node's work in every window (÷ `crit_total_us` = how
    /// many nodes' work a window overlapped).
    /// MEASURED why (night/link26-sample.txt, link 28): the per-phase sums over nodes (relay 46.5 s, grind 46.3 s, …) added to
    /// ~1.4× the step loop's wall and could not say which phase set it.
    pub crit_us: [u128; 10],
    pub crit_total_us: u128,
    pub node_us: u128,
    /// The wall instant of the first step (µs since the meter's epoch); 0 = no step yet.
    pub first_us: u128,
    /// Lock-held node CPU charged to the simulated clock, summed over nodes (PERF TIER step 1; 0 when not charging).
    pub charged_us: u128,
}

/// The phases [`SpeedMeter::phase_us`] splits a step into.
pub const SPEED_PHASES: [&str; 10] =
    ["serve", "follow", "begin", "prove", "grind", "finish", "jobwait", "relay", "arrivals", "announce"];

thread_local! {
    static SPEED: std::cell::Cell<SpeedMeter> = std::cell::Cell::new(SpeedMeter::default());
    static SPEED_EPOCH: std::time::Instant = std::time::Instant::now();
}

fn speed_now_us() -> u128 {
    SPEED_EPOCH.with(|e| e.elapsed().as_micros())
}

fn speed_add(phase: usize, since: std::time::Instant) {
    let us = since.elapsed().as_micros();
    SPEED.with(|s| {
        let mut m = s.get();
        m.phase_us[phase] += us;
        s.set(m);
    });
}

/// This process's PHYSICAL FOOTPRINT in MB (`proc_pid_rusage` → `ri_phys_footprint`: dirty + compressed pages, the figure
/// `footprint` prints and the lane runner's memory cap sums); `None` off Apple platforms.
#[must_use]
pub fn phys_footprint_mb() -> Option<u64> {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
        // SAFETY: `proc_pid_rusage` with `RUSAGE_INFO_V2` fills exactly one `rusage_info_v2` for the calling process.
        let rc = unsafe {
            libc::proc_pid_rusage(libc::getpid(), libc::RUSAGE_INFO_V2, info.as_mut_ptr().cast::<libc::rusage_info_t>())
        };
        if rc == 0 {
            return Some(unsafe { info.assume_init() }.ri_phys_footprint / 1_048_576);
        }
        None
    }
    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    {
        None
    }
}

/// This thread's speed so far: simulated ÷ wall, the step loop's share of the wall, and the top phases.
#[must_use]
pub fn speed_line() -> String {
    let m = SPEED.with(std::cell::Cell::get);
    if m.first_us == 0 {
        return "speed: no step yet".into();
    }
    let wall_us = speed_now_us().saturating_sub(m.first_us).max(1);
    let mut ph: Vec<(usize, u128)> = m.phase_us.iter().copied().enumerate().collect();
    ph.sort_by(|a, b| b.1.cmp(&a.1));
    let ld = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
    let ev = &crate::nf_sparse::BAND_CURSOR_EVENTS;
    let mut crit: Vec<(usize, u128)> = m.crit_us.iter().copied().enumerate().collect();
    crit.sort_by(|a, b| b.1.cmp(&a.1));
    format!(
        "speed {:.2}× (sim {} s / wall {:.1} s; step loop {:.0}% of wall; {}) · critical path {:.1} s ({}; nodes' work {:.2}× it) · node lock CPU charged {:.1} s · process: node pair hashes {} (sparse cache \
         {:?} lookups/misses) · pow memo ({}, {}) · payload memo ({}, {}) lookups/misses · cursor inserts {} absorbs {} serves {} rebuilds {}",
        m.sim_ms as f64 * 1000.0 / wall_us as f64,
        m.sim_ms / 1000,
        wall_us as f64 / 1e6,
        m.step_us as f64 * 100.0 / wall_us as f64,
        ph.iter().take(5).map(|(k, us)| format!("{} {:.1} s", SPEED_PHASES[*k], *us as f64 / 1e6)).collect::<Vec<_>>().join(", "),
        m.crit_total_us as f64 / 1e6,
        crit.iter().take(6).map(|(k, us)| format!("{} {:.1} s", SPEED_PHASES[*k], *us as f64 / 1e6)).collect::<Vec<_>>().join(", "),
        m.node_us as f64 / (m.crit_total_us.max(1) as f64),
        m.charged_us as f64 / 1e6,
        ld(&crate::spend_frontier::NODE_PAIR_HASHES),
        usdm_decider::poseidon2_compress::sparse_pair_cache_counts(),
        ld(&crate::pouw::sim_memo::COUNTS[0]),
        ld(&crate::pouw::sim_memo::COUNTS[1]),
        ld(&crate::cover::payload_memo::COUNTS[0]),
        ld(&crate::cover::payload_memo::COUNTS[1]),
        ld(&ev[0]),
        ld(&ev[1]),
        ld(&ev[2]),
        ld(&ev[3])
    )
}

/// What every node's step reads from the simulation (shared, read-only).
struct NodeStepCtx {
    n: usize,
    produce_every_ms: u64,
    produce_paused: bool,
    oracle_push: bool,
    charge_cpu: bool,
    replayable: bool,
    /// PERF TIER step 1 test seam: synthetic lock CPU (ms) charged to node `i` on every relay tick ([`NetSim::lock_tax_ms`]).
    lock_tax_ms: Vec<u64>,
    band_double: bool,
    /// ⭐ DB-454 — the simulated cost (ms) the bound band double's prove job DECLARES per step (0 = its own microseconds):
    /// `BAND_FOLD_PROVE_MS_REF` gives the fast simulation the real lane's band timing ([`NetSim::with_band_double_charge`]).
    band_double_charge_ms: u64,
    /// The simulated cost (ms) a template prove DECLARES on a mesh armed for the bound template double
    /// ([`NetSim::with_template_double`]: [`TEMPLATE_PROVE_MS_REF`]); 0 = unarmed, the prove charged its own measured time.
    template_double_ms: u64,
    /// The simulated processes' network (empty = the default net), set on each node thread as the step thread sets it.
    /// Each node's network prefix (the simulation's, or an old run's: `NetSim::make_foreign`).
    networks: Vec<Vec<u8>>,
    /// The test's coverage recording, which a node thread's surfaces are noted into.
    coverage: Option<crate::harness::sim_coverage::Handle>,
    /// Each node's per-node file root (DB-406), set on its step thread as its own process would have it.
    files: Vec<Option<(std::path::PathBuf, u16)>>,
}

impl NodeStepCtx {
    /// Make this thread one of the simulation's processes: its network, its coverage recording.
    fn enter_thread(&self, i: usize) {
        if let Some(net) = self.networks.get(i).filter(|n| !n.is_empty()) {
            crate::params::set_thread_network_for_test(net);
        }
        if let Some(h) = &self.coverage {
            crate::harness::sim_coverage::adopt(h.clone());
        }
    }
}

/// One node's step: what the merge on the step thread applies, in node order.
#[derive(Default)]
struct NodeStepOut {
    i: usize,
    produced: Option<BlockId>,
    /// The produced block's size (PERF P13, [`block_size`]).
    size: Option<BlockSize>,
    oracle: Option<crate::block::Block>,
    wall_ms: [u128; 6],
    hashes: u64,
    phase_us: [u128; 10],
    /// Synthetic lock CPU (ms) this step charges on top of what it measured ([`NetSim::lock_tax_ms`]).
    tax_ms: u64,
    proved: Option<ProveSample>,
}

/// Node `i`'s own record announce — the daemon's serve loop publishes it once its onion is up. Its id stands for the onion
/// address (a well-formed v3 host, which the peer directory's onion-only gate requires); its ek is a real ML-KEM key.
fn announce_node(rt: &Mutex<NodeRuntime<SimEndpoint>>, i: usize, key: &(Vec<u8>, Vec<u8>), now: u64) {
    let mut guard = rt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    announce_sim_identity(&mut guard, "netsim-node-onion", i, key, now);
}

/// ONE simulated node's boot announce — its own signed peer record over a deterministic v3-shaped onion id (`{tag}-{i}`),
/// exactly what a daemon announces once its onion is up (`announce_own_record`): the node learns its PUBLIC id (band-step
/// ownership, the shard holder rule and P7's turn set rank it) and its peers learn it by gossip. Shared by every in-process
/// mesh (the netsim and the scenario hub), so a simulated node is never identity-less where a daemon is not.
pub(crate) fn announce_sim_identity<T: crate::transport::CellTransport>(
    rt: &mut NodeRuntime<T>,
    tag: &str,
    i: usize,
    key: &(Vec<u8>, Vec<u8>),
    now: u64,
) {
    let (pk, sk) = key;
    let own_id = {
        const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut h = Hash32::hash(format!("{tag}-{i}").as_bytes()).as_bytes().to_vec();
        h.extend_from_slice(Hash32::hash(&h).as_bytes());
        let host: String = h.iter().take(56).map(|b| B32[(*b & 31) as usize] as char).collect();
        format!("{host}.onion")
    };
    let addr = format!("/dns/{own_id}/tcp/{}", crate::arti_transport::ONION_CELL_PORT);
    let (ek, _) = crate::faucet::kem_keypair_from_seed(Hash32::hash(own_id.as_bytes()).as_bytes());
    rt.announce_own_record(own_id, addr, Vec::new(), ek, pk, sk, now);
}

/// ONE node's announce, producer loop (begin under the lock, prove + grind off it, finish under it again — the daemon's
/// sequential producer) and relay tick (every `COVER_INTERVAL_MS` at its own phase) for one step.
#[allow(clippy::too_many_arguments)]
fn node_step(
    ctx: &NodeStepCtx,
    now: u64,
    i: usize,
    rt: &Mutex<NodeRuntime<SimEndpoint>>,
    wire: &Wire,
    key: &(Vec<u8>, Vec<u8>),
    miner: &crate::pow::PowMiner,
    pending: &mut Option<(ProduceJob, crate::block::Block, u64)>,
    last_begin: &mut u64,
    next_announce: &mut u64,
    next_relay: &mut u64,
) -> NodeStepOut {
    let lock = || rt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut out = NodeStepOut { i, ..NodeStepOut::default() };
    let lap = |out: &mut NodeStepOut, k: usize, t: std::time::Instant| out.phase_us[k] += t.elapsed().as_micros();
    if now >= *next_announce {
        let t = std::time::Instant::now();
        announce_node(rt, i, key, now);
        let lonely = lock().node().known_peers().is_empty();
        *next_announce = now + if lonely { 10_000 } else { 300_000 };
        lap(&mut out, 9, t);
    }
    if matches!(pending, Some((_, _, ready)) if *ready > now) {
        // still grinding: the daemon's producer loop is sequential, so it begins nothing meanwhile
    } else if pending.is_none() && ctx.produce_paused {
        // DB-402 R1: production paused for a quiescent census — a block already grinding still finishes (above/below)
    } else if pending.is_none() && ctx.produce_every_ms > 0 && now < *last_begin + ctx.produce_every_ms {
        // the experiment's per-node rate cap
    } else if let Some((job, block, _)) = pending.take() {
        let id = block.id();
        let copy = if ctx.oracle_push { Some(block.clone()) } else { None };
        let size = off_lock(|| block_size(&block, rt)); // the observer's, never the node's: not charged
        let t = std::time::Instant::now();
        let finished = lock().finish_produce(job, block);
        out.wall_ms[3] += t.elapsed().as_millis();
        lap(&mut out, 5, t);
        if finished {
            out.produced = Some(id);
            out.size = Some(size);
            out.oracle = copy;
        }
    } else if let Some(job) = {
        let t = std::time::Instant::now();
        let j = lock().begin_produce(now, Hash32::ZERO, Hash32::ZERO);
        out.wall_ms[0] += t.elapsed().as_millis();
        lap(&mut out, 2, t);
        if j.is_some() {
            *last_begin = now;
        }
        j
    } {
        // the template's REAL txs: its fixed-shape cover txs (`cover_ids`, minted per block) are not carriage
        let (spend, covers) = (job.pending_transition.is_some(), job.pending_cover.as_ref().map_or(0, Vec::len));
        let txs: Vec<Hash32> = job.tmpl_tx_ids.iter().filter(|t| !job.cover_ids.contains(t)).copied().collect();
        let pool: Vec<Hash32> = off_lock(|| lock().node().mempool().all_tx_ids().into_iter().map(Hash32).collect());
        // the bound template double DECLARES the real prove's cost (fixed by the job's inputs, before it runs)
        let declared = (job.template_double() && job.proves_a_template_class()).then_some(ctx.template_double_ms);
        let t = std::time::Instant::now();
        // off the runtime lock in the daemon: never charged to the lock (its own charge is the `pending` instant below);
        // charged its time ALONE (`prove_alone`), never a pool split with another simulated node's prove
        let (completed, measured_ms) = off_lock(|| prove_alone(|| crate::node_runtime::complete_produce_job(job)));
        let prove_ms = declared.unwrap_or(measured_ms);
        out.wall_ms[1] += t.elapsed().as_millis(); // the host's wall, the gate's wait included
        out.proved = Some(ProveSample { node: i, spend, covers, txs, ms: prove_ms, begun: now, pool, block: None });
        lap(&mut out, 3, t);
        match completed {
            Ok(job) => {
                let mut header = job.block.header.clone();
                let t = std::time::Instant::now();
                let mined = off_lock(|| miner.mine(&mut header)); // the grind's simulated time is `ms_per_hash` per try
                out.wall_ms[2] += t.elapsed().as_millis();
                lap(&mut out, 4, t);
                if let Some(pi) = mined {
                    let tries = crate::pow::grind_tries(header.nonce);
                    out.hashes += tries;
                    let grind = tries * wire.phys.ms_per_hash;
                    let mut b = job.block.clone();
                    b.header = header;
                    b.pow_proof = pi;
                    if let Some(p) = out.proved.as_mut() {
                        p.block = Some(b.id());
                    }
                    // Finishes once its grind has taken its simulated time (never earlier than the next step).
                    let busy = if ctx.charge_cpu { prove_ms } else { 0 };
                    *pending = Some((job, b, now + grind + busy));
                }
            }
            Err(ids) => lock().evict_refused_spends(&ids),
        }
    }
    if now >= *next_relay {
        *next_relay = now + crate::net::COVER_INTERVAL_MS;
        // an off-lock job (the band prover, a liquidation) is polled inside the tick and taken at spawn + its charged cost
        // (`budget_clock::OffLockJob::spawn_on_cores`); the wall the poll waited for its worker is its own phase
        let t = std::time::Instant::now();
        let w0 = crate::budget_clock::job_wait_us();
        if ctx.band_double {
            // the fast lane: one band job per relay tick of SIMULATED time on an uncharged node, never one per wall interval
            lock().band_job_settle_for_sim();
        }
        lock().maintenance_tick_at(now); // the daemon's 5 s pass (serve.rs), the 30 s certified pull with it
        lock().tick_relay(now);
        let waited = u128::from(crate::budget_clock::job_wait_us().saturating_sub(w0));
        out.phase_us[6] += waited;
        out.phase_us[7] += t.elapsed().as_micros().saturating_sub(waited);
        out.wall_ms[4] += t.elapsed().as_millis();
        out.tax_ms += ctx.lock_tax_ms.get(i).copied().unwrap_or(0);
    }
    let _ = ctx.n;
    // The charged workers this step spawned are waited for HERE, with no lock held (`budget_clock::settle_spawned_jobs`):
    // a daemon never holds its runtime lock for a proof, so neither does a simulated node. The wait is the jobwait phase.
    let w0 = crate::budget_clock::job_wait_us();
    crate::budget_clock::settle_spawned_jobs();
    out.phase_us[6] += u128::from(crate::budget_clock::job_wait_us().saturating_sub(w0));
    out
}

/// One node's window ([`NetSim::step_window`]): what the merge on the step thread applies, in node order.
#[derive(Default)]
struct WindowOut {
    i: usize,
    /// The blocks this node produced, with the instant each finished.
    produced: Vec<(BlockId, u64)>,
    /// Their sizes (PERF P13).
    sizes: Vec<BlockSize>,
    proved: Vec<ProveSample>,
    /// Blocks born elsewhere this node grafted, with the latency; blocks that ran out of the arrival window.
    arrived: Vec<(BlockId, u64)>,
    expired: Vec<BlockId>,
    wall_ms: [u128; 6],
    /// WALL ms this node spent serving asks and follows.
    serve_ms: u128,
    /// Lock-held CPU (µs) charged to this node in the window (PERF TIER step 1).
    lock_cpu_us: u64,
    hashes: u64,
    phase_us: [u128; 10],
}

/// Server `i` answers, through the PRODUCTION serve function, every ask addressed to it that has arrived by `now`, in
/// arrival order; an ask whose link was severed in flight is lost (DB-380). Each page goes back one leg later on `i`'s
/// own stream.
fn serve_due_asks(wire: &Wire, rt: &Mutex<NodeRuntime<SimEndpoint>>, i: usize, now: u64, w: &mut WindowOut) {
    let due: Vec<Ask> = {
        let mut asks = wire.asks.lock().unwrap();
        if !asks.iter().any(|a| a.to == i && a.at <= now) {
            return;
        }
        asks.sort_by_key(|a| (a.at, a.seq));
        let (mine, rest): (Vec<Ask>, Vec<Ask>) = asks.drain(..).partition(|a| a.to == i && a.at <= now);
        *asks = rest;
        mine
    };
    for a in due.into_iter().filter(|a| !wire.is_blocked(a.from, a.to)) {
        crate::harness::sim_coverage::note("wire", "NotesReq"); // the bulk lane carries NotesReq framing
        wire.ask_census[i][1].fetch_add(1, Ordering::Relaxed);
        let t = std::time::Instant::now();
        let page = rt.lock().unwrap_or_else(std::sync::PoisonError::into_inner).serve_notes_req_bytes(&a.req, 1_048_576); // serve.rs's budget
        w.serve_ms += t.elapsed().as_millis();
        let at = now + step_charge_us() / 1_000 + wire.leg(i) + page.len() as u64 / wire.phys.bytes_per_ms.max(1) + wire.phys.apply_ms;
        let seq = wire.seq(i);
        wire.sent(at);
        let kind = a.req.first().copied().unwrap_or(0);
        // DB-450: an empty page is arti's empty frame (`page` None to the predicate)
        let nothing = crate::node_runtime::bulk_answer_carries_nothing(&a.req, (!page.is_empty()).then_some(&page[..]));
        let rotation = Some((crate::arti_transport::bulk_rotation_key(&a.req), nothing));
        wire_trace("serve", i, a.from, now, at, seq, &page); // REPLAY_WIRE_TRACE: the answer a bulk ask got, and when it lands
        wire.answers[a.from].lock().unwrap().push(Due { at, seq, bytes: page, from: i, answer: true, kind, wake: false, rotation });
    }
}

/// DB-326 FOLLOWS at server `i`, as arti's serve loop runs them (`arti_transport::serve_bulk_stream`): an arriving follow
/// is built at once on `BulkServeTurn::Arrival`; an answer with no body is HELD and rebuilt on `BulkServeTurn::FollowWake`
/// (DB-445: this node's own new blocks only) whenever this server's own production has grown (`finish_produce`'s notify —
/// `produced` is its count); when the hold runs out with no growth, the LAST build (empty) is the answer, as arti's loop
/// breaks on its timeout and writes the page it holds.
fn serve_follows(wire: &Wire, rt: &Mutex<NodeRuntime<SimEndpoint>>, i: usize, now: u64, hold_ms: u64, produced: u64, w: &mut WindowOut) {
    let arriving: Vec<Ask> = {
        let mut f = wire.follows.lock().unwrap();
        f.sort_by_key(|a| (a.at, a.seq));
        let (mine, rest): (Vec<Ask>, Vec<Ask>) = f.drain(..).partition(|a| a.to == i && a.at <= now);
        *f = rest;
        mine
    };
    let mut held: Vec<(Ask, u64, usize, Vec<u8>)> = {
        let mut h = wire.held.lock().unwrap();
        let (mine, rest): (Vec<_>, Vec<_>) = h.drain(..).partition(|(a, _, _, _)| a.to == i);
        *h = rest;
        mine
    };
    if held.is_empty() && arriving.is_empty() {
        return;
    }
    held.extend(arriving.into_iter().map(|a| (a, now + hold_ms, usize::MAX, Vec::new()))); // MAX: built on arrival
    let mut keep = Vec::with_capacity(held.len());
    for (a, deadline, seen, last) in held {
        let len = produced as usize;
        let page = if seen != usize::MAX && len == seen {
            if now < deadline {
                keep.push((a, deadline, seen, last));
                continue;
            }
            last // the hold ran out on no growth: arti writes the page it holds
        } else {
            let turn = if seen == usize::MAX {
                crate::transport::BulkServeTurn::Arrival
            } else {
                crate::transport::BulkServeTurn::FollowWake
            };
            crate::harness::sim_coverage::note("wire", "NotesReq");
            let t = std::time::Instant::now();
            let page = rt.lock().unwrap_or_else(std::sync::PoisonError::into_inner).serve_bulk_bytes(&a.req, turn, 1_048_576);
            w.serve_ms += t.elapsed().as_millis();
            if page.len() > 9 + 32 {
                crate::harness::sim_coverage::note("wire", "NotesResp");
            }
            if page.len() <= 9 + 32 && now < deadline {
                keep.push((a, deadline, len, page)); // nothing new for this follower yet: keep holding
                continue;
            }
            page
        };
        let wake = seen != usize::MAX && page.len() > 9 + 32;
        let at = now + step_charge_us() / 1_000 + wire.leg(i) + page.len() as u64 / wire.phys.bytes_per_ms.max(1) + wire.phys.apply_ms;
        let seq = wire.seq(i);
        wire.sent(at);
        wire.answers[a.from].lock().unwrap().push(Due { at, seq, bytes: page, from: i, answer: false, kind: 0, wake, rotation: None });
        wire.follow_land.lock().unwrap().push((at, a.from * wire.n + a.to));
    }
    if !keep.is_empty() {
        wire.held.lock().unwrap().extend(keep);
    }
}

/// A follow of node `i` ends when its answer lands, and `i` may send the next one on that link.
fn land_follows(wire: &Wire, i: usize, now: u64) {
    let landed: Vec<usize> = {
        let mut l = wire.follow_land.lock().unwrap();
        if !l.iter().any(|(at, k)| *at <= now && k / wire.n == i) {
            return;
        }
        let (done, rest): (Vec<_>, Vec<_>) = l.drain(..).partition(|(at, k)| *at <= now && k / wire.n == i);
        *l = rest;
        done.into_iter().map(|(_, k)| k).collect()
    };
    let mut out = wire.follow_out.lock().unwrap();
    for k in landed {
        out[k] = false;
        wire.close_conversation(k / wire.n, k % wire.n);
    }
}

/// ⭐ DB-420 — NODE `i`'s MINER SEED IN ITS `incarnation`-th PROCESS, a pure function of the simulation's seed. The daemon
/// draws a fresh seed per process (`reward::new_node_miner_seed`, never persisted), and that seed drives the node's
/// memoryless production schedule (`Node::production_gap_uniform`), its reward commitments and its cover-slot stream.
/// MEASURED why (link 27, night/sim-20261007-215726.log): two one-step runs of ONE seed in one test produced
/// [10, 19, 7] and [13, 19, 21] blocks per node — the test build's seed is keyed on (test thread name, nodes that test
/// made before), so a second simulation in the same test drew different seeds, a different production timetable and a
/// different chain; and a red found on a seed could not be replayed. Borrowed: deterministic simulation draws every
/// random choice from the simulation's seed (FoundationDB's simulator; Bitcoin's regtest `-mocktime` + seeded
/// `FastRandomContext` in its unit tests). cons: none — a test scaffold; the daemon's draw is unchanged.
fn sim_miner_seed(seed: u64, i: usize, incarnation: u64) -> [u8; 32] {
    let mut v = b"MUSD-sim-node-miner-seed-v1".to_vec();
    v.extend_from_slice(&seed.to_le_bytes());
    v.extend_from_slice(&(i as u64).to_le_bytes());
    v.extend_from_slice(&incarnation.to_le_bytes());
    *Hash32::hash(&v).as_bytes()
}

/// MEASURED reference for the bound template double's declared cost ([`NetSim::with_template_double`]): what one block
/// template's prove job — its note, member and cover aggregates proved side by side (`complete_produce_job`), each at
/// the constant committed shape (`DELTA_FIXED_SLOTS`), so the cost is a constant of the protocol and never of the spend
/// count — took in the simulator charged ALONE (`prove_alone`). The value is the MEDIAN of the p50 `[perf-load] n=8 prove
/// by shape — note transition` rows of the 29 n=8 load runs of 2026-10-20/21 (scratchpad/night/perf-load-*-n8.log: p50s
/// 3,091–4,279 ms, median 3,508 ms) — never a hand-picked number. Re-measure (the same rows) when the prover changes.
pub const TEMPLATE_PROVE_MS_REF: u64 = 3_508;

/// A block older than this that a peer has not grafted is counted as never arrived.
pub const ARRIVAL_WINDOW_MS: u64 = 60_000;
/// The gate's one-chain predicate compares selected blocks at or below `min(tip) - GATE_DEPTH`.
pub const GATE_DEPTH: u64 = 8;
/// Simulated node `i` names its per-node files under port `SIM_FILE_PORT_BASE + i` in its own datadir (DB-406).
const SIM_FILE_PORT_BASE: u16 = 30_000;
/// The daemon's shutdown watcher polls its restart/shutdown requests every 200 ms (`main.rs` / `serve.rs` term loop), so an
/// identity restart takes the process down for one tick before launchd respawns it.
const SHUTDOWN_WATCHER_TICK_MS: u64 = 200;
/// The journeys' scaled stake lock in BLOCKS ([`NetSim::with_journey_stake_lock`]), ONE FUNCTION OF THE MESH, never a tuned
/// constant: a bond applies at the FOLD, and the journeys' own derived bound for "a record is folded on every node" is
/// [`spendable_within_ms`] = `(record_fold_depth + 8) × production_step × 2`; the mesh produces `nodes / production_step`
/// blocks per second (each up node takes its fair share once per step), so that bound in BLOCKS is
/// `(record_fold_depth + 8) × 2 × nodes` — the step cancels, so the lock is known at boot. The owner's first unbond ask
/// (asked the moment every node holds the bond) then lands inside the lock and is refused, and maturity arrives inside the
/// step's budget (`spendable_within_s` ≥ the lock at the same rate). MEASURED why the old FOUR fold depths (128) were short
/// (f1-launch6-20261022-1740.log, 10 nodes, seed 0x7131_00F3_2026_1022): the fold cursor ran 114 blocks behind the tip
/// (1436 vs 1550; the fold's cadence with node CPU charged, not the 32-block minimum), so every node first held the bond
/// 132 blocks after its block and T3 read "CALIBRATION: already mature (tip 1550, matures 1546)"; 3 nodes: 128 → 240,
/// 10 nodes: 128 → 800. Production: 86,400.
pub fn journey_stake_lock_blocks(nodes: usize) -> u64 {
    (crate::params::RECORD_FOLD_DEPTH_DEFAULT + 8) * 2 * (nodes as u64).max(1)
}

/// N daemons on one simulated wire.
pub struct NetSim {
    wire: Arc<Wire>,
    /// Each node's runtime behind the lock the daemon's RPC listener and loops share (`main.rs` / `serve.rs` hold the same
    /// `Arc<Mutex<NodeRuntime>>`), so the simulator can answer the PRODUCTION RPC router in-process (`NetSim::rpc`).
    pub rts: Vec<Arc<Mutex<NodeRuntime<SimEndpoint>>>>,
    miner: crate::pow::PowMiner,
    now: u64,
    step_ms: u64,
    next_relay: Vec<u64>,
    /// A mined block and the simulated instant its grind ends. O1-FOOTPRINT-REVIEWED: test scaffold, one slot per node.
    pending: Vec<Option<(ProduceJob, crate::block::Block, u64)>>,
    /// O1-FOOTPRINT-REVIEWED: test scaffold, bounded by the blocks a fixed-length run produces.
    born: HashMap<BlockId, (usize, u64)>,
    /// O1-FOOTPRINT-REVIEWED: test scaffold, bounded like `born`.
    arrived: HashSet<(BlockId, usize)>,
    /// ORACLE, not production: each produced block also reaches every peer as a batch page one leg after birth,
    /// through the production batch door. This is the BEST case a DB-326 follow long-poll can deliver, measured
    /// before DB-326 is built: if even this does not make the pair one chain, latency is not the whole cause.
    pub oracle_push: bool,
    /// EXPERIMENT KNOB, not production: a node begins a produce at most once per this many simulated ms (0 = the
    /// daemon's own cadence). It sets the per-node block rate r, to test the self-selection threshold 2·L·r < 1.
    /// ⛔ DB-412: 0 in every journey and pin — the daemon's own schedule (`NodeRuntime::production_due`, a memoryless gap of
    /// the fair-share mean) decides when a node produces. A 4 s cap here on top of it made the simulated mesh FIXED-PERIOD
    /// again (every gap under the cap rounded up to it) — the very schedule DB-412 removed from production.
    pub produce_every_ms: u64,
    /// DB-402 R1: no node BEGINS a produce while set (a block already grinding finishes) — the replicated-state census's
    /// quiescent point: the relay drains, every node folds the same blocks, and every replicated field must then agree.
    pub produce_paused: bool,
    /// O1-FOOTPRINT-REVIEWED: test scaffold, one slot per node.
    last_begin: Vec<u64>,
    pub report: Report,
    /// ⭐ THE PRODUCTION BOOT (2026-10-06). After [`NetSim::boot_from_disk`], each node owns a datadir and boots through
    /// `Node::boot` — the daemon's own sequence — so [`NetSim::restart`] is the production restart (shutdown save → process
    /// gone → boot from the files). `None` = the relay-only instrument (no persistence), as before.
    dirs: Vec<Option<std::path::PathBuf>>,
    genesis: crate::block::Block,
    params: crate::params::ChainParams,
    /// ⭐ THE RESET TEST'S OLD-RUN NODE (lane speed5, 2026-11-18): per node, the params and genesis of ANOTHER network (a testnet
    /// run before a reset) that node boots on instead of the simulation's, so a node that never updated runs beside the new
    /// run on the same wire. `None` = the simulation's own network. Set by [`NetSim::make_foreign`] before `boot_from_disk`.
    foreign: Vec<Option<(crate::params::ChainParams, crate::block::Block)>>,
    /// A node is down until this simulated instant (0 = up).
    down_until: Vec<u64>,
    /// ⭐ CHARGE NODE CPU (PERF TIER step 1, 2026-10-08). A produced block finishes only after its grind AND its measured
    /// prove wall time — a node that spends seconds proving is busy for those seconds, as a real one is — and every
    /// LOCK-HELD action a node's step runs (serving asks and follows, its announce, begin/finish produce, the band settle,
    /// the relay tick with its drain and fold) is charged its measured CPU: the node's runtime lock stays busy until
    /// `t + cost`, and the node takes no further lock-held action before then ([`NetSim::lock_free_at`]). A send made
    /// mid-step leaves after the CPU spent before it. Each node thread's work budgets read the same clock
    /// (`budget_clock`), so a loaded host runs the same simulated schedule as an idle one.
    /// BORROWED-FROM: Shadow (the Tor network simulator) delays a virtual host by the measured execution time of its
    /// code; FoundationDB's simulator charges simulated time for work, never a wall-clock wait.
    pub charge_cpu: bool,
    /// REPLAYABLE (uncharged only): every node thread's budget clock stands still and its off-lock jobs are ready at their
    /// first poll (`budget_clock::freeze_this_thread`), so the run is a function of its seed, never of the host's speed.
    pub replayable: bool,
    /// Each node's simulated entropy stream where its last window left it (REPLAYABLE only; `None` = drawn afresh from
    /// (seed, node, incarnation) at its next window — a new process). O1-FOOTPRINT-REVIEWED: one slot per node.
    entropy: Vec<Option<crate::budget_clock::SimEntropy>>,
    /// REPLAY TRACE (observation only): after every window, each node's (stream draws, pool size, order-free pool digest).
    replay_rows: Option<Vec<(u64, Vec<(u64, usize, Vec<String>)>)>>,
    /// The simulated instant each node's runtime lock is free again (PERF TIER step 1; 0 = free). O1-FOOTPRINT-REVIEWED:
    /// test scaffold, one slot per node.
    lock_free_at: Vec<u64>,
    /// §NETSIM-LAUNCH: the simulated Bitcoin this mesh's bridge reads (`btc_sim`, Bitcoin Core regtest semantics), mining
    /// on THIS clock (`set_clock`). Installed process-wide while the run lives (`btc_watch::btc_source` hands it to every
    /// node as `BtcSource::Sim`); a pin that installs it holds `btc_sim::serial()` for the run.
    foreign_btc: Option<crate::btc_sim::Installed>,
    /// §NETSIM-LAUNCH: the mesh's simulated Monero (`xmr_sim`), mined on the simulated clock; every node's custody
    /// lane, deposit watcher and payout lane drive it through `xmr_rpc`'s Sim arm. A pin that installs it holds
    /// `xmr_sim::serial()` for the run.
    foreign_xmr: Option<crate::xmr_sim::Installed>,
    /// TEST SEAM (PERF TIER step 1's calibration pin): synthetic lock CPU (ms) charged to node `i` on every relay tick on
    /// top of what its tick measured. Empty (0 for every node) in every journey. O1-FOOTPRINT-REVIEWED: one slot per node.
    pub lock_tax_ms: Vec<u64>,
    /// Restarts performed (production shutdown + boot).
    pub restarts: u64,
    /// The simulation's seed — every per-node secret a node process draws from the OS is derived from it here
    /// ([`sim_miner_seed`]), so a run is one function of its seed.
    seed: u64,
    /// How many processes node `i` has booted (its first is 0): a restart or a fresh install is a NEW process, which draws
    /// a new miner seed exactly as the daemon does. O1-FOOTPRINT-REVIEWED: one slot per simulated node.
    incarnations: Vec<u64>,
    /// Each node's ML-DSA identity key (pk, sk) — the daemon's key file, kept across a restart as the file is.
    keys: Vec<(Vec<u8>, Vec<u8>)>,
    /// ⭐ DB-437 — booted with `MONEROUSD_VALIDATOR_BOND` set, as the live pair's plists and the real journey's seated
    /// daemons are, so every boot asks the chain for its seat (`Node::request_own_seat_at_boot`). Every node
    /// [`NetSim::boot_from_disk`] boots has it, and a [`NetSim::join_fresh`] reinstall keeps its plist.
    validator_bond_env: Vec<bool>,
    /// Each node's finality voter (`vote_guard::vote_tick`, the daemon's 200 ms thread): its write-ahead guard, opened per
    /// process beside the vote key, and when it next ticks. `None` until the process's first tick opens it.
    vote_guards: Vec<Option<crate::vote_guard::VoteGuard>>,
    next_vote: Vec<u64>,
    /// When each node next announces its own record (the serve loop's cadence: 10 s while it knows no peer, else 5 min).
    next_announce: Vec<u64>,
    /// THE FAST LANE: every node runs the BOUND band-step double (`Node::arm_band_double_for_test`, the bound certificate's
    /// law — a step costs microseconds) so a journey runs in seconds. The REAL lane (real compact band proofs, each charged
    /// its gated wall cost — `budget_clock::OffLockJob::spawn_on_cores`) stays the one whose pass opens a live run; the
    /// fast lane is the instant bug finder.
    band_double: bool,
    /// ⭐ The band prover every production node runs (`Node::autoprove_band_for_test`, DB-396): armed on every party,
    /// restart and joiner by [`NetSim::with_band_prover`]. A fixture without it folds no further than the band lag cap,
    /// so its served bundle certifies blue_score 1 forever (MEASURED scratchpad/funds/eclipse-21.log) — a mesh no node runs.
    band_prover: bool,
    /// ⭐ DB-454 — the simulated cost (ms) the bound band double's prove job DECLARES per step (0 = its own microseconds):
    /// `BAND_FOLD_PROVE_MS_REF` gives the fast simulation the real lane's band timing ([`NetSim::with_band_double_charge`]).
    band_double_charge_ms: u64,
    /// THE FAST LANE's second double: every node lays and judges its block template's four aggregates (note, cover, bond,
    /// member) as the BOUND template double (`Node::arm_template_double_for_test`), each prove charged
    /// [`TEMPLATE_PROVE_MS_REF`] of simulated time ([`NetSim::with_template_double`]). Honest meshes only.
    template_double: bool,
    /// §RF-3: every node lays and judges the block LEDGER (note + member ledger) REAL ([`Node::arm_real_ledger_for_test`],
    /// [`NetSim::with_real_ledger`]); otherwise a test node lays and judges it as the bound double. The real lane arms it.
    real_ledger: bool,
    /// Each node's production RPC listener (the daemon's `rpc_http` connection handler on 127.0.0.1): its port (0 = never
    /// served) and, while the process is up, the accept loop's stop flag and thread. A restart drops the listener with the
    /// process and re-binds the SAME port when the node is back up, as a daemon does.
    ports: Vec<u16>,
    listeners: Vec<Option<(Arc<std::sync::atomic::AtomicBool>, std::thread::JoinHandle<()>)>>,
    /// ⭐ THE STATE INVARIANT, checked every 10 simulated seconds while on: the first cross-node divergence
    /// ([`NetSim::state_divergence`]) and the simulated instant it was seen. A journey step fails on it.
    pub check_state: bool,
    pub first_divergence: Option<(u64, String)>,
    /// The most steps one window may take ([`NetSim::step_window`]); 0 = as many as the wire's lookahead allows. 1 = the
    /// one-step loop — the equivalence pin's twin.
    pub window_cap: u64,
    /// CALIBRATION ONLY: a window lookahead in steps that overrides the wire's (0 = the wire's one leg). A lookahead longer
    /// than the leg is a broken window — the census must count it ([`NetSim::lookahead_breaks`]).
    pub window_lookahead_for_test: u64,
    /// ⭐ F3 — THE LAUNCH JOURNEY's censuses at every step (readiness T3). While on, every step's pass
    /// (`journey_tests::pass_inv`) runs the replicated-state census over the up nodes ([`NetSim::replica_census`]) and every
    /// production restart ([`NetSim::restart`]) runs the restart census (every `Node` field before → after, `VOLATILE`
    /// excluded), and each red is kept in `census_reds` as (step, census, field, detail) — reported PER FIELD at the end of
    /// the run and failing it, never skipped and never narrowed: a green launch journey means every census held at every
    /// step. `census_rows` counts the censuses taken, so a run in which one never ran cannot read green.
    pub step_census: bool,
    pub census_reds: Vec<(String, &'static str, String, String)>,
    pub census_rows: u64,
}

impl Drop for NetSim {
    fn drop(&mut self) {
        if self.band_double {
            crate::pouw::bound_pow::arm_on_this_thread(false); // the fast lane's arm ends with its simulation
        }
        for i in 0..self.listeners.len() {
            self.stop_listener(i);
        }
        for d in self.dirs.iter().flatten() {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

/// What a parked mesh hands the simulation that resumes it ([`NetSim::park`] → [`NetSim::resume_from_disk`]): the clock,
/// each node's down-until instant, and (while `step_census`) each up node's restart-census snapshot from the old process.
pub struct Parked {
    pub now_ms: u64,
    pub down_until: Vec<u64>,
    pub before: Vec<Option<Vec<(String, Option<(u64, usize)>)>>>,
}

impl NetSim {
    /// `n` daemons from the production genesis. Party 0 carries the boot directive, as the gate's node 1 does; the
    /// others join by grafting its first block. Each relay loop starts at a seeded phase so the loops never tick in
    /// lockstep.
    /// ⭐ DB-347: the real-cell copies each node has put on its links so far (its upload, in cells).
    /// Node `i`'s runtime, locked (one statement at a time; never hold it across `step`).
    pub fn rt(&self, i: usize) -> std::sync::MutexGuard<'_, NodeRuntime<SimEndpoint>> {
        self.rts[i].lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// ⭐ SAT CUSTODY FOR NODE `i`, THE WAY AN OPERATOR GETS IT (SATOSHI §6/§8): its rewards seal to a test wallet, it mines one,
    /// and the wallet bonds that whole reward to node `i`'s own validator key through the chain (`build_sat_bond_from_reward` →
    /// `publish_sat_bond`) — then every node must hold the custody weight. A free membership seat carries finality weight and
    /// NO custody weight, so without this a simulated mesh can price nothing (the price mark's ≥ 2/3 is custody weight) and
    /// mint nothing. MEASURED (lane funds 2026-10-29): the layer-2 priced flows found no mark in 900 simulated seconds — both
    /// nodes held membership seats only ("free while the reserve is zero (0 bonded now)"). `false` when the weight did not
    /// land on every node within `within_ms`.
    pub fn seat_sat_custody(&mut self, i: usize, within_ms: u64) -> bool {
        let seed = [0x5Au8 ^ (i as u8); 32];
        let (rc, _) = crate::satoshi::RewardRecipient::for_test(&seed);
        let secrets = crate::faucet::RecipientSecrets::for_test(&seed);
        self.rt(i).node_mut().set_reward_recipient(Some(rc));
        let Some((pk, sk)) = self.rt(i).bridge_signer().map(|(p, s)| (p.to_vec(), s.to_vec())) else {
            return false; // node `i` runs no validator key to bond to
        };
        let vid = crate::pqauth::pubkey_id(&pk);
        let n = self.rts.len();
        let (mut t, mut published) = (0u64, false);
        while t < within_ms {
            self.run(1_000, 10_000);
            t += 1_000;
            if !published {
                let rows = self.rt(i).node().committed_real_records();
                'find: for (_, _, reals, _) in rows {
                    for note in reals {
                        let built = self.rt(i).node_mut().build_sat_bond_from_reward(&note, &secrets, &pk, &sk);
                        if let Some(b) = built {
                            published = self.rt(i).node_mut().publish_sat_bond(&b).is_ok();
                            eprintln!("[netsim] node {i}: SAT custody bond of {} published ({published})", b.weight);
                            break 'find;
                        }
                    }
                }
            }
            if published && (0..n).all(|j| self.rt(j).node().validators().bond_of(&vid) > 0) {
                return true;
            }
        }
        false
    }

    /// Boot one node from `dir` through the production `Node::boot` (a fresh process: genesis, then whatever the files hold).
    /// Node `i`'s per-node file root `(datadir, port)` — what its own process's `persist::state_dir()` / `serving_port()`
    /// name (DB-406). `None` for the relay-only instrument (no datadir).
    /// ⭐ THE `[mem]` LINE (link 42, P14 high leg killed at a 6.4 GB job-tree footprint at height ~19 k): the process's
    /// PHYSICAL FOOTPRINT (`ri_phys_footprint`, what `footprint` and the jetsam limit read — RSS under-reports compressed
    /// pages) beside each node's own RAM census ([`Node::ram_census_named`]) and the wire's in-flight bytes, so the
    /// footprint at each height is attributed to its owner by measurement — a census sum far below the footprint names a
    /// store the census does not list. Printed every `SIM_MEM_EVERY_S` simulated seconds by [`NetSim::mem_tick`] (unset:
    /// never). A test-harness instrument, off every node path.
    pub fn mem_line(&self, tag: &str) {
        let mut line = format!(
            "[mem] {tag} t={} s footprint {} MB (rss {} MB) · wire {} KB · born {} arrived {}",
            self.now / 1000,
            phys_footprint_mb().map_or_else(|| "?".into(), |m| m.to_string()),
            crate::serve::resident_kb().map_or_else(|| "?".into(), |k| (k / 1024).to_string()),
            self.wire.queued_bytes() / 1024,
            self.born.len(),
            self.arrived.len(),
        );
        for i in 0..self.rts.len() {
            let rt = self.rt(i);
            let census = rt.node().ram_census_named();
            let sum: usize = census.iter().map(|r| r.2).sum();
            let top: Vec<String> =
                census.iter().take(5).map(|(n, c, b)| format!("{n} {c}/{:.1}MB", *b as f64 / 1_048_576.0)).collect();
            line.push_str(&format!(
                " ‖ n{i} h={} census {:.1} MB: {}",
                rt.node().tip_height(),
                sum as f64 / 1_048_576.0,
                top.join(", ")
            ));
        }
        eprintln!("{line}");
    }

    fn node_files(&self, i: usize) -> Option<(std::path::PathBuf, u16)> {
        self.dirs[i].clone().map(|d| (d, SIM_FILE_PORT_BASE + i as u16))
    }

    /// Boot one node from `dir` through the production `Node::boot` (a fresh process: genesis, then whatever the files hold).
    /// Its identity is the daemon's: `validator::load_or_create_node_vote_key` over ITS OWN key file — drawn on a first boot,
    /// read back on every restart, and replaced by a `/provision_validator` (DB-406: it was an in-memory key here while the
    /// identity routes read a process-wide file, so the bond's provision never reached the node that bonds).
    /// Each boot is a new process: it draws its miner seed where `Node::new` draws the daemon's, from the simulation's seed
    /// ([`sim_miner_seed`]) for this node's next incarnation.
    fn boot_node(&mut self, i: usize, dir: &std::path::Path) -> Result<(NodeRuntime<SimEndpoint>, crate::node::BootReport, (Vec<u8>, Vec<u8>)), String> {
        self.incarnations[i] += 1;
        self.entropy[i] = None; // a new process draws a new stream
        let port = SIM_FILE_PORT_BASE + i as u16;
        let key = crate::persist::with_thread_node_files_for_test(Some((dir.to_path_buf(), port)), || {
            crate::validator::forget_identity_restart(); // a new process: no restart pending
            crate::rpc_http::letter_new_process_for_test(); // a new process: its own empty Letter ring
            crate::validator::load_or_create_node_vote_key()
        });
        let (gen_i, params_i) = self.network_of(i);
        let mut node = Node::with_params(gen_i, params_i).map_err(|e| format!("genesis: {e:?}"))?;
        node.set_miner_seed_for_test(sim_miner_seed(self.seed, i, self.incarnations[i]));
        let id = crate::pqauth::pubkey_id(&key.0);
        let report = node.boot(&crate::persist::BootFiles::in_dir(dir, port), id)?;
        if self.band_double {
            node.arm_band_double_for_test(); // the whole mesh runs the bound double, never mixed
            node.set_band_double_charge_for_test(self.band_double_charge_ms); // DB-454: at the declared cost, if any
        }
        if self.band_prover {
            node.autoprove_band_for_test(); // a restarted or joining party proves its band as its peers do
        }
        if self.template_double {
            node.arm_template_double_for_test(); // before the runtime exists: its preverify worker reads the door then
        }
        if self.real_ledger {
            node.arm_real_ledger_for_test(); // the whole mesh, before the runtime exists, never mixed
        }
        let mut rt = NodeRuntime::new(node, SimEndpoint { wire: self.wire.clone(), me: i });
        rt.set_external_producer();
        if i == 0 {
            rt.set_mesh_bootstrap_origin(); // the origin daemon's plist keeps MONEROUSD_MESH_BOOTSTRAP across restarts
        }
        // DB-437: a validator daemon's process asks the chain for its seat at every boot, as `main.rs` does under
        // `MONEROUSD_VALIDATOR_BOND` (a seat the chain already holds is not asked for again), over ITS OWN key files.
        if self.validator_bond_env[i] {
            let line = crate::persist::with_thread_node_files_for_test(Some((dir.to_path_buf(), port)), || {
                rt.node_mut().request_own_seat_at_boot(&key.0, &key.1)
            });
            eprintln!("[netsim] node {i}: {line}");
            // ⭐ PARITY WITH `serve.rs` (the daemon under `MONEROUSD_VALIDATOR_BOND`): the operator's intent to attest seats this
            // process's bridge SIGNER (its vote key — DB-341's one identity) and its custody decapsulation key, so a bonded
            // custodian of the simulated mesh opens sealed peg legs, attests, executes and coordinates entry-mix rounds exactly
            // as the daemon does. Before this the mesh's custodians held a seat and weight but never acted: every bridge step
            // of the launch journey (peg-in, cash-out, the entry mix) had no custody to reach. Weight still comes only from
            // the chain-carried bond set.
            rt.set_bridge_signer(key.0.clone(), key.1.clone());
            if let Some((ek, dk)) = crate::persist::with_thread_node_files_for_test(Some((dir.to_path_buf(), port)), crate::bridge::node_own_custody_kem) {
                rt.set_custody_kem(ek, dk);
            }
        }
        self.vote_guards[i] = None; // a new process opens its voter's guard on its first tick
        Ok((rt, report, key))
    }

    /// ⭐ `n` nodes on the TESTNET identity the live pair runs (`MONEROUSD_NET=testnet`: its genesis, its network prefix, its
    /// faucet), exactly as `main.rs` builds them. Every tx's stamp binds to its process's network id; each simulated node's
    /// work runs under the testnet id through `params::set_thread_network_for_test` (the step loop's thread here, every RPC
    /// connection thread in `start_listener`) — N daemons, each its own one-network process, in one test process.
    pub fn testnet(n: usize, phys: Physics, seed: u64) -> NetSim {
        let mut p = crate::params::ChainParams::default();
        p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        // this thread IS the simulated processes' step loop: it runs on their network (RPC threads set it per connection)
        crate::params::set_thread_network_for_test(&p.genesis_parity_commit);
        Self::with_params(n, phys, seed, p)
    }

    /// ⭐ `n` nodes on testnet RUN `run` (`params::testnet_genesis_prefix_for_run`; `params::TESTNET_RUN` is this release's).
    pub fn testnet_run(n: usize, phys: Physics, seed: u64, run: u32) -> NetSim {
        let mut p = crate::params::ChainParams::default();
        p.genesis_parity_commit = crate::params::testnet_genesis_prefix_for_run(run);
        p.net_prefix_len = p.genesis_parity_commit.len();
        crate::params::set_thread_network_for_test(&p.genesis_parity_commit);
        Self::with_params(n, phys, seed, p)
    }

    /// ⭐ THE RESET TEST: node `i` boots on testnet run `run` instead of the simulation's network — the node of an old run that
    /// stays online after a reset. Call before [`NetSim::boot_from_disk`]; every later boot of `i` stays on that run.
    pub fn make_foreign(mut self, i: usize, run: u32) -> NetSim {
        let mut p = self.params.clone();
        p.genesis_parity_commit = crate::params::testnet_genesis_prefix_for_run(run);
        p.net_prefix_len = p.genesis_parity_commit.len();
        let g = crate::block::genesis_block_for_network(&p.genesis_parity_commit);
        self.foreign[i] = Some((p, g));
        self
    }

    /// The genesis and params node `i` runs on.
    fn network_of(&self, i: usize) -> (crate::block::Block, crate::params::ChainParams) {
        match self.foreign.get(i).and_then(Option::as_ref) {
            Some((p, g)) => (g.clone(), p.clone()),
            None => (self.genesis.clone(), self.params.clone()),
        }
    }

    /// N8: whether node `a` has dropped node `b` from its ask rotation (its beacon named another network).
    pub fn has_excluded(&self, a: usize, b: usize) -> bool {
        self.wire.is_foreign(a, b)
    }

    /// The genesis id node `i` holds now.
    pub fn genesis_of(&self, i: usize) -> Option<crate::block::BlockId> {
        self.rt(i).node().dag().genesis()
    }

    /// THE FAST LANE (see `band_double`): call before [`NetSim::boot_from_disk`].
    /// ⭐ AND THE BOUND PoUW DOUBLE (link 28, `pouw::bound_pow`): the fast lane's grind hashes are the double's, never the
    /// kernel's ~30 ms. A hasher is bound or real from the thread it is BUILT on, so this thread is armed first and what
    /// `with_params` built before the arm — the grinder and every node (its miner, its preverify worker's hasher) — is built
    /// again, as it was: the whole mesh runs the double, never mixed. Every later node (a restart, a joiner) is booted on
    /// this thread. The arm ends when the simulation is dropped.
    /// Arm the band prover on every party (and every later restart or joiner): the production shape, where a node's
    /// prove worker keeps its band moving and its served bundle certifies a recent anchor. See the `band_prover` field.
    pub fn with_band_prover(mut self) -> NetSim {
        self.band_prover = true;
        for rt in &self.rts {
            rt.lock().unwrap().node_mut().autoprove_band_for_test();
        }
        self
    }

    pub fn with_band_double(mut self) -> NetSim {
        self.band_double = true;
        crate::pouw::bound_pow::arm_on_this_thread(true);
        self.miner = crate::pow::PowMiner::new().expect("the PoW hasher builds");
        self.rts = Self::fresh_runtimes(self.rts.len(), &self.wire, &self.genesis, &self.params, self.seed);
        self
    }

    /// ⭐ DB-454 — the bound band double's prove job DECLARES `ms` of simulated cost per step (on a charged mesh,
    /// `charge_cpu`), so the fast lane has the real lane's band timing with the double's microsecond proofs. MEASURED why:
    /// the free double hid the band relay defect DB-454 names (fast lane 1.22× redundant band proving, real lane 2.05×+).
    /// Call after [`NetSim::with_band_double`], before [`NetSim::boot_from_disk`].
    pub fn with_band_double_charge(mut self, ms: u64) -> NetSim {
        self.band_double_charge_ms = ms;
        self
    }

    /// ⭐ THE BOUND TEMPLATE DOUBLE (docs/SIM-SPEED-TEMPLATE-BOUND-DOUBLE-20261022.md): every node — every restart and joiner
    /// too, all booted through [`NetSim::boot_from_disk`] — lays and judges its template's four aggregates as the double,
    /// and a template prove takes [`TEMPLATE_PROVE_MS_REF`] of simulated time on a charged mesh (`charge_cpu`), so the
    /// fast lane keeps the real lane's block timing while the WHIR grind's wall time is gone. MEASURED why (solo eco
    /// journey, scratchpad/night/solo3-eco-20261022.out): `prove` was the largest critical-path term in all three runs
    /// (27.2 / 45.9 / 27.1 s of 88.8 / 100.3 / 81.9 s) and held the lane at 17.3–20.8×. HONEST meshes only: the double is
    /// not a soundness door (`usdm_decider::settlement_delta::delta_bound`), so a rogue-producer simulation never arms it.
    /// Call before [`NetSim::boot_from_disk`].
    pub fn with_template_double(mut self) -> NetSim {
        self.template_double = true;
        self
    }

    /// §RF-3: every node lays and judges the block ledger REAL (a ~10 s note + member ledger prove per block once the
    /// member ring is complete) instead of the bound double a test node uses by default (`Node::ledger_double`). The REAL
    /// lane arms it. Call before [`NetSim::boot_from_disk`].
    pub fn with_real_ledger(mut self) -> NetSim {
        self.real_ledger = true;
        self
    }

    /// The JOURNEYS' stake lock (`ChainParams::stake_lock_blocks`, governance-tunable): call before [`NetSim::boot_from_disk`],
    /// which boots every node (and every restart) on `self.params`. A SCALED WINDOW (user 2026-10-04: a simulation that scales
    /// a window states the production figure): production is `STAKE_LOCK_BLOCKS_DEFAULT` = 86,400 blue score (≈ 1 day at
    /// 1 s); the journeys run [`journey_stake_lock_blocks`]. The mechanism is the production one on both sides of it — the
    /// unbond door refuses before maturity (DB-409) and the fold releases after it.
    pub fn with_stake_lock_blocks(mut self, blocks: u64) -> NetSim {
        self.params.governance_set_stake_lock_blocks(blocks);
        self
    }

    /// The journeys' stake lock derived from THIS mesh's node count ([`journey_stake_lock_blocks`]). Call before `boot_from_disk`.
    pub fn with_journey_stake_lock(self) -> NetSim {
        let n = self.rts.len();
        self.with_stake_lock_blocks(journey_stake_lock_blocks(n))
    }

    /// ⭐ Give every node a datadir and re-boot it through the production `Node::boot` — from then on every committed block
    /// auto-saves its checkpoint, as on a daemon, and [`NetSim::restart`] is the production restart. Call before `run`.
    pub fn boot_from_disk(mut self) -> NetSim {
        static RUN: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!("netsim-{}-{}", std::process::id(), RUN.fetch_add(1, Ordering::Relaxed)));
        for i in 0..self.rts.len() {
            let dir = base.join(format!("node-{i}"));
            std::fs::create_dir_all(&dir).expect("a simulated node's datadir");
            self.validator_bond_env[i] = true; // DB-437: every daemon the mesh boots runs with `MONEROUSD_VALIDATOR_BOND`
            let (rt, _, key) = self.boot_node(i, &dir).expect("a fresh datadir boots");
            self.rts[i] = Arc::new(Mutex::new(rt));
            self.keys[i] = key;
            self.dirs[i] = Some(dir);
        }
        self
    }

    /// ⭐⭐⭐ THE PRODUCTION RESTART: the shutdown save the daemon's TERM watcher writes (`persist_blocking`), the process gone
    /// for `downtime_ms` (every link silent, an in-flight grind lost, queued traffic dropped), then a FRESH node booted from
    /// the same files through `Node::boot` — the nf-view cache, the record cache, the witness-window rebuild and the boot
    /// sweep all run exactly as they do on the live pair. Returns what the boot found.
    pub fn restart(&mut self, i: usize, downtime_ms: u64) -> Result<crate::node::BootReport, String> {
        let dir = self.dirs[i].clone().ok_or("restart needs boot_from_disk (a node with no datadir has nothing to resume)")?;
        // F3: the restart census's BEFORE snapshot (the same instant `restart_census_every_field_survives_a_production_restart` reads)
        let before = self.step_census.then(|| self.field_census(i));
        // `LAUNCH_CENSUS_DETAIL=<field>,<field>`: the named fields' rendered text before the restart, so a CHANGED row names
        // its first difference (the joiner pin's `[joiner-restart-field]` detail, for any restart of any mesh). Test-only.
        let detail: Vec<(String, String)> = std::env::var("LAUNCH_CENSUS_DETAIL")
            .map(|v| v.split(',').filter(|f| !f.is_empty()).map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .map(|f| {
                let mut t = String::new();
                self.rt(i).node().census_field_render(&f, &mut t);
                (f, t)
            })
            .collect();
        let head_before = (!detail.is_empty()).then(|| {
            let rt = self.rt(i); // one lock: a second `rt(i)` in the same expression would wait on this one forever
            format!(
                "{} · uncarried ordinal rows {:?} · DAG blocks a checkpoint drops {:?} · (floor ids unheld, stamps off the unfolded set, stamps) {:?}",
                rt.node().dag().head_probe(),
                rt.node().uncarried_ordinal_rows(),
                rt.node().dag_blocks_a_checkpoint_drops(),
                rt.node().floor_and_stamp_probe()
            )
        });
        self.rt(i).node().persist_blocking();
        self.process_gone(i)?;
        let (rt, report, key) = self.boot_node(i, &dir)?;
        self.rts[i] = Arc::new(Mutex::new(rt));
        self.keys[i] = key;
        self.down_until[i] = self.now + downtime_ms.max(self.step_ms);
        self.next_announce[i] = 0; // a new process announces as soon as it is up
        self.restarts += 1;
        eprintln!("[netsim] node {i} restarted at t={} ms (down {downtime_ms} ms): {report:?}", self.now);
        if let Some(before) = before {
            // F3 THE RESTART CENSUS AT THIS RESTART (the same instant `restart_census_every_field_survives_a_production_restart` reads)
            let step = format!("restart {} (node {i}, t={} s)", self.restarts, self.now / 1000);
            self.restart_census_compare(i, &step, &before);
        }
        if let Some(h) = head_before {
            eprintln!("[restart-head] node{i} before: {h}");
            eprintln!("[restart-head] node{i} after:  {}", self.rt(i).node().dag().head_probe());
        }
        for (f, was) in &detail {
            let mut now = String::new();
            self.rt(i).node().census_field_render(f, &mut now);
            if *was != now {
                let at = was.bytes().zip(now.bytes()).take_while(|(a, b)| a == b).count();
                let cut = |s: &str| s.get(at.saturating_sub(60)..s.len().min(at + 300)).unwrap_or("").to_string();
                eprintln!("[restart-field] node{i} {f}: {} B → {} B, first difference at byte {at}: before …{}… after …{}…", was.len(), now.len(), cut(was), cut(&now));
                // a map or set renders in its own iteration order, so the first differing byte can be order alone: the
                // items one side holds and the other lacks name what the restart lost or gained
                let trim = |t: &str| t.trim_matches(|c| matches!(c, '{' | '}' | '[' | ']')).to_string();
                let mut count: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
                for t in was.split(", ") {
                    *count.entry(trim(t)).or_default() += 1;
                }
                for t in now.split(", ") {
                    *count.entry(trim(t)).or_default() -= 1;
                }
                let mut lost: Vec<&str> = count.iter().filter(|(_, c)| **c > 0).map(|(t, _)| t.as_str()).collect();
                let mut gained: Vec<&str> = count.iter().filter(|(_, c)| **c < 0).map(|(t, _)| t.as_str()).collect();
                lost.sort_unstable();
                gained.sort_unstable();
                let clip = |v: &[&str]| v.iter().take(12).map(|t| t.chars().take(120).collect::<String>()).collect::<Vec<_>>();
                eprintln!("[restart-field-items] node{i} {f}: {} item(s) only before {:?} · {} only after {:?}", lost.len(), clip(&lost), gained.len(), clip(&gained));
            }
        }
        Ok(report)
    }

    /// Node `i`'s PROCESS IS GONE (the middle of a restart; every node of a parked mesh): its RPC port closes with it, every
    /// link to it is silent, an in-flight grind is lost, queued traffic dies with the process, and its runtime is released
    /// BEFORE anything re-opens its files (a daemon's files are never open in two processes).
    fn process_gone(&mut self, i: usize) -> Result<(), String> {
        self.stop_listener(i);
        self.wire.down[i].store(true, Ordering::Relaxed);
        self.pending[i] = None;
        self.lock_free_at[i] = 0; // the next process's lock is free
        self.drop_traffic_of(i);
        let placeholder = {
            let (gen_i, params_i) = self.network_of(i);
            let node = Node::with_params(gen_i, params_i).map_err(|e| format!("genesis: {e:?}"))?;
            Arc::new(Mutex::new(NodeRuntime::new(node, SimEndpoint { wire: self.wire.clone(), me: i })))
        };
        drop(std::mem::replace(&mut self.rts[i], placeholder));
        Ok(())
    }

    /// F3 THE RESTART CENSUS at one production restart of node `i`: every `Node` field read again from the NEW process against
    /// `before` (read from the old one); a field that differs is state the restart lost or changed unless `VOLATILE` declares
    /// it process-local with a reason (the census pin's law). Each CHANGED field is one census red for the launch journey's
    /// end-of-run report (never skipped, never narrowed); returns how many changed. One site for the in-process restart
    /// ([`Self::restart`]) and the across-process one ([`Self::resume_from_disk`]).
    fn restart_census_compare(&mut self, i: usize, step: &str, before: &[(&str, Option<(u64, usize)>)]) -> usize {
        let after = self.field_census(i);
        let volatile: Vec<&str> = crate::node::restart_census_stand_ins::VOLATILE.iter().map(|(n, _)| *n).collect();
        let mut changed = 0usize;
        for ((f, x), (_, y)) in before.iter().zip(after.iter()) {
            let verdict = if volatile.contains(f) {
                "VOLATILE"
            } else if x == y {
                "SAME"
            } else {
                changed += 1;
                self.census_reds.push((
                    step.to_string(),
                    "restart",
                    f.to_string(),
                    format!("CHANGED: before {} B → after {} B", x.map_or(0, |d| d.1), y.map_or(0, |d| d.1)),
                ));
                "CHANGED"
            };
            eprintln!("[restart-census-row] node{i}\t{f}\t{verdict}\t{}\t{}", x.map_or(0, |d| d.1), y.map_or(0, |d| d.1));
        }
        self.census_rows += 1;
        eprintln!("[launch-census] {step}: restart census {} field(s) CHANGED", changed);
        changed
    }

    /// ⭐⭐ PARK THE MESH ON DISK (F3 — the launch journey in legs, lane b 2026-10-22): every up node's process writes the
    /// shutdown snapshot the daemon's TERM watcher writes (`persist_blocking`) and is gone ([`Self::process_gone`]); the
    /// datadirs move to `dest` (`<dest>/node-<i>`) and this simulation ends WITHOUT removing them. A later PROCESS resumes
    /// them with [`Self::resume_from_disk`] — one production restart of every node across a process boundary, censused like
    /// any other. The files are the whole hand-off: nothing in RAM crosses but what [`Parked`] carries (the clock, each
    /// node's down-until instant, and — while `step_census` — each up node's restart-census snapshot read from the OLD
    /// process, the `before` of the census the resume runs). MEASURED why (scratchpad/farm/queue-20261022-192013-21963.log):
    /// one process of the 10-node launch journey needs ~51 min and every run was killed at the 45-min watchdog with no
    /// verdict; the legs are ≤ 20 min each (rule 5a) and the four boundaries ADD four whole-mesh restart censuses.
    pub fn park(mut self, dest: &std::path::Path) -> Result<Parked, String> {
        let n = self.rts.len();
        let mut before = Vec::with_capacity(n);
        for i in 0..n {
            if self.dirs[i].is_none() {
                return Err(format!("park: node {i} has no datadir (boot_from_disk first)"));
            }
            let up = !self.is_down(i);
            before.push((self.step_census && up).then(|| self.field_census(i).into_iter().map(|(f, x)| (f.to_string(), x)).collect::<Vec<_>>()));
            if up {
                self.rt(i).node().persist_blocking(); // the TERM watcher's shutdown save
            }
            self.process_gone(i)?;
        }
        let base = self.dirs[0].as_ref().and_then(|d| d.parent().map(std::path::Path::to_path_buf)).ok_or("park: no datadir base")?;
        if base != dest {
            let _ = std::fs::remove_dir_all(dest);
            std::fs::rename(&base, dest).map_err(|e| format!("park: rename {} → {}: {e}", base.display(), dest.display()))?;
        }
        for d in self.dirs.iter_mut() {
            *d = None; // Drop keeps the parked files
        }
        eprintln!("[netsim] parked {n} node(s) at t={} ms under {}", self.now, dest.display());
        Ok(Parked { now_ms: self.now, down_until: self.down_until.clone(), before })
    }

    /// ⭐⭐ RESUME A PARKED MESH in THIS process: `self` is a fresh mesh of the parked size built like the parked one (the same
    /// doubles and stake lock, `charge_cpu` / `check_state` / `step_census` set); every node boots through the production
    /// `Node::boot` from `<base>/node-<i>` — the clock is set to the parked instant FIRST (a block carries its timestamp and
    /// the chain refuses one at or below the median time past, `consensus::BlockError` MTP: a process that forgets the clock
    /// and resumes at t=0 is behind its own tip, the refutation pin's second arm) — the down-until instants are restored,
    /// and when `before` is given with `step_census` on, the restart census judges every node that was up at the park
    /// against its old process (`step` names the boundary). Every node up at the park counts one production restart.
    /// Not carried, by construction: the scaffold's own maps (`born`, `arrived` — a leg judges its own blocks), the wire's
    /// in-flight traffic (a dead process's links carry nothing) and the perf rows (a leg prints its own).
    pub fn resume_from_disk(
        mut self,
        base: &std::path::Path,
        now_ms: u64,
        down_until: &[u64],
        before: Option<&[Option<Vec<(String, Option<(u64, usize)>)>>]>,
        step: &str,
    ) -> Result<NetSim, String> {
        let n = self.rts.len();
        if down_until.len() != n {
            return Err(format!("resume: {} down-until instants for {n} nodes", down_until.len()));
        }
        self.now = now_ms;
        self.set_clock(now_ms);
        for i in 0..n {
            let dir = base.join(format!("node-{i}"));
            if !dir.is_dir() {
                return Err(format!("resume: {} is not a parked datadir", dir.display()));
            }
            self.validator_bond_env[i] = true; // DB-437: every daemon the mesh boots runs with `MONEROUSD_VALIDATOR_BOND`
            let (rt, report, key) = self.boot_node(i, &dir)?;
            self.rts[i] = Arc::new(Mutex::new(rt));
            self.keys[i] = key;
            self.dirs[i] = Some(dir);
            let was_up = down_until[i] <= now_ms;
            self.down_until[i] = if was_up { 0 } else { down_until[i] };
            self.wire.down[i].store(!was_up, Ordering::Relaxed);
            self.next_announce[i] = 0; // a new process announces as soon as it is up
            if was_up {
                self.restarts += 1;
            }
            eprintln!("[netsim] node {i} resumed at t={now_ms} ms (was {}): {report:?}", if was_up { "up" } else { "down" });
        }
        if let (Some(before), true) = (before, self.step_census) {
            for (i, b) in before.iter().enumerate().take(n) {
                if let Some(b) = b {
                    let b: Vec<(&str, Option<(u64, usize)>)> = b.iter().map(|(f, x)| (f.as_str(), *x)).collect();
                    let step = format!("{step} (node {i}, t={} s)", now_ms / 1000);
                    self.restart_census_compare(i, &step, &b);
                }
            }
        }
        Ok(self)
    }

    /// ⭐ Serve node `i`'s PRODUCTION RPC on 127.0.0.1 (the daemon's connection handler, `rpc_http::handle_conn`) and return
    /// its URL — what a real wallet process talks to.
    pub fn serve_rpc(&mut self, i: usize) -> String {
        if self.ports[i] == 0 {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("a free loopback port");
            self.ports[i] = probe.local_addr().map(|a| a.port()).unwrap_or(0);
        }
        if self.listeners[i].is_none() && !self.is_down(i) {
            self.start_listener(i);
        }
        format!("http://127.0.0.1:{}", self.ports[i])
    }

    fn start_listener(&mut self, i: usize) {
        crate::rpc_http::start_watchers(); // the same deposit watchers the production server starts
        let Ok(l) = crate::rpc_http::reusable_tcp_listener("127.0.0.1", self.ports[i]) else {
            eprintln!("[netsim] node {i}: could not re-bind its RPC port {}", self.ports[i]);
            return;
        };
        let _ = l.set_nonblocking(true);
        let rt = self.rts[i].clone();
        let network = self.network_of(i).1.genesis_parity_commit;
        let files = self.node_files(i);
        // the test's coverage recording: every route a wallet calls over this listener is noted into it
        let coverage = crate::harness::sim_coverage::handle();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        let h = std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                match l.accept() {
                    Ok((s, _)) => {
                        let _ = s.set_nonblocking(false);
                        let rt = rt.clone();
                        let network = network.clone();
                        let coverage = coverage.clone();
                        let files = files.clone();
                        std::thread::spawn(move || {
                            if !network.is_empty() {
                                crate::params::set_thread_network_for_test(&network); // this node's process network
                            }
                            crate::persist::set_thread_node_files_for_test(files); // this node's process files (DB-406)
                            if let Some(h) = coverage {
                                crate::harness::sim_coverage::adopt(h);
                            }
                            let _ = crate::rpc_http::handle_conn(s, &rt);
                        });
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                }
            }
        });
        self.listeners[i] = Some((stop, h));
    }

    fn stop_listener(&mut self, i: usize) {
        if let Some((stop, h)) = self.listeners[i].take() {
            stop.store(true, Ordering::Relaxed);
            let _ = h.join();
        }
    }

    /// Keep node `i`'s process DOWN until [`NetSim::join_fresh`] — a node that does not exist yet (every link silent).
    pub fn hold_down(&mut self, i: usize) {
        self.down_until[i] = u64::MAX;
        self.wire.down[i].store(true, Ordering::Relaxed);
        self.pending[i] = None;
    }

    /// ⭐ A FRESH NODE JOINS: node `i`'s datadir is emptied (a new install), it boots through the production `Node::boot`
    /// from nothing, comes up at the next step, announces itself, and joins the mesh by the runtime's OWN path (the DSYNC
    /// ask a behind node makes, the certified-bundle adopt) — nothing is handed to it by the harness.
    pub fn join_fresh(&mut self, i: usize) -> Result<crate::node::BootReport, String> {
        let dir = self.dirs[i].clone().ok_or("join_fresh needs boot_from_disk")?;
        self.stop_listener(i);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("datadir: {e}"))?;
        self.drop_traffic_of(i);
        // DB-437: `validator_bond_env[i]` is unchanged — a reinstall keeps its plist (`MONEROUSD_VALIDATOR_BOND`), so the new identity
        // asks for a seat as the lost one did; the lost key's seat stays on the chain and never votes again.
        let (rt, report, key) = self.boot_node(i, &dir)?;
        self.rts[i] = Arc::new(Mutex::new(rt));
        self.keys[i] = key; // a new install draws its own identity
        self.down_until[i] = self.now + self.step_ms; // up at the next step (the bring-up re-binds its RPC port if served)
        self.next_announce[i] = 0;
        self.pending[i] = None;
        self.lock_free_at[i] = 0; // a new install's lock is free
        Ok(report)
    }

    /// Whether node `i`'s process is down.
    pub fn is_down(&self, i: usize) -> bool {
        self.down_until[i] > self.now
    }

    /// Every byte queued to or held for node `i` dies with its process (a TCP/Tor link to a dead process carries nothing).
    fn drop_traffic_of(&self, i: usize) {
        let n = self.wire.n;
        self.wire.cells[i].lock().unwrap().clear();
        self.wire.answers[i].lock().unwrap().clear();
        self.wire.asks.lock().unwrap().retain(|a| a.from != i && a.to != i);
        self.wire.follows.lock().unwrap().retain(|a| a.from != i && a.to != i);
        self.wire.held.lock().unwrap().retain(|(a, _, _, _)| a.from != i && a.to != i);
        self.wire.follow_land.lock().unwrap().retain(|(_, k)| k / n != i && k % n != i);
        let mut out = self.wire.follow_out.lock().unwrap();
        for j in 0..n {
            out[i * n + j] = false;
            out[j * n + i] = false;
        }
        drop(out);
        // a process's conversations end with it, and so does its memory of who answered empty (arti's process-wide set)
        self.wire.notfound[i].lock().unwrap().clear();
        let mut open = self.wire.open.lock().unwrap();
        for j in 0..n {
            open[i * n + j] = 0;
            open[j * n + i] = 0;
        }
    }

    /// Ask node `i` the PRODUCTION RPC router (`rpc_http::route`) — the same function, path and JSON the live gate reads.
    pub fn rpc(&self, i: usize, method: &str, path: &str, body: &str) -> (u16, String) {
        crate::rpc_http::route(&self.rts[i], method, path, body)
    }

    pub fn sent_real_cells(&self) -> Vec<u64> {
        self.wire.sent_real.iter().map(|c| c.load(std::sync::atomic::Ordering::Relaxed)).collect()
    }

    pub fn new(n: usize, phys: Physics, seed: u64) -> NetSim {
        Self::with_params(n, phys, seed, crate::params::ChainParams::default())
    }

    /// `new` with the chain parameters every simulated node runs (all nodes share them, as a mesh does). A simulation that
    /// scales a WINDOW (e.g. `daa_sample_len`) to keep a pin fast must state the production figure it stands for — the
    /// mechanism is the same, the constant is the simulation's (user 2026-10-04: tests fast and light, as accurate).
    pub fn with_params(n: usize, phys: Physics, seed: u64, params: crate::params::ChainParams) -> NetSim {
        let wire = Arc::new(Wire {
            n,
            phys,
            now: AtomicU64::new(0),
            clocks: (0..n).map(|_| AtomicU64::new(0)).collect(),
            window_end: AtomicU64::new(0),
            early: AtomicU64::new(0),
            ask_census: (0..n).map(|_| std::array::from_fn(|_| AtomicU64::new(0))).collect(),
            seqs: (0..n).map(|_| AtomicU64::new(0)).collect(),
            rngs: (0..n).map(|i| Mutex::new(Rng(seed ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)))).collect(),
            cells: (0..n).map(|_| Mutex::new(Vec::new())).collect(),
            link_tail: Mutex::new(vec![0; n * n]),
            link_depart: Mutex::new(vec![0; n * n]),
            shed: (0..crate::transport::CELL_KIND_SLOTS).map(|_| AtomicU64::new(0)).collect(),
            cell_wait: (0..=CELL_WAIT_EDGES_MS.len()).map(|_| AtomicU64::new(0)).collect(),
            cell_msgs: Mutex::new(CellMsgCensus::default()),
            asks: Mutex::new(Vec::new()),
            answers: (0..n).map(|_| Mutex::new(Vec::new())).collect(),
            follows: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
            follow_out: Mutex::new(vec![false; n * n]),
            inv_host: (0..n).map(|_| AtomicUsize::new(usize::MAX)).collect(),
            notfound: (0..n).map(|_| Mutex::new(std::collections::VecDeque::new())).collect(),
            sent_real: (0..n).map(|_| AtomicU64::new(0)).collect(),
            follow_land: Mutex::new(Vec::new()),
            blocked: Mutex::new(vec![false; n * n]),
            foreign: Mutex::new(vec![false; n * n]),
            down: (0..n).map(|_| std::sync::atomic::AtomicBool::new(false)).collect(),
            rx_on: std::sync::atomic::AtomicBool::new(false),
            rx: (0..n).map(|_| Mutex::new(RxCensus::default())).collect(),
            open: Mutex::new(vec![0; n * n]),
            over_lanes: AtomicU64::new(0),
            open_max: AtomicU64::new(0),
            cell_kinds: (0..crate::transport::CELL_KIND_SLOTS).map(|_| AtomicU64::new(0)).collect(),
            rec_answers: Mutex::new(vec![[0; 2]; n * n]),
            ask_kinds: Mutex::new(vec![[0; 4]; 256]),
        });
        // the network the params name (the testnet identity the live pair runs, via `NetSim::testnet`), else the default
        let g = if params.genesis_parity_commit.is_empty() {
            crate::block::genesis_block()
        } else {
            crate::block::genesis_block_for_network(&params.genesis_parity_commit)
        };
        let rts = Self::fresh_runtimes(n, &wire, &g, &params, seed);
        let mut phase = Rng(seed ^ 0xA5A5_A5A5);
        let cell = crate::net::COVER_INTERVAL_MS;
        NetSim {
            next_relay: (0..n).map(|_| phase.below(cell)).collect(),
            pending: (0..n).map(|_| None).collect(),
            wire,
            rts,
            miner: crate::pow::PowMiner::new().expect("the PoW kernel allocates"),
            now: 0,
            step_ms: 50, // the daemon's producer loop re-tries `begin_produce` every 50 ms when it is not yet due
            born: HashMap::new(),
            arrived: HashSet::new(),
            oracle_push: false,
            produce_every_ms: 0,
            produce_paused: false,
            last_begin: vec![0; n],
            report: Report { produced: vec![0; n], arrival_ms_at: vec![Vec::new(); n], lock_cpu_us: vec![0; n], ..Report::default() },
            dirs: vec![None; n],
            genesis: g,
            params,
            foreign: vec![None; n],
            down_until: vec![0; n],
            charge_cpu: false,
            replayable: false,
            entropy: vec![None; n],
            replay_rows: None,
            lock_free_at: vec![0; n],
            foreign_btc: None,
            foreign_xmr: None,
            lock_tax_ms: Vec::new(),
            restarts: 0,
            seed,
            incarnations: vec![0; n],
            keys: (0..n).map(|_| crate::pqauth::ml_dsa_keypair()).collect(),
            validator_bond_env: vec![false; n],
            vote_guards: (0..n).map(|_| None).collect(),
            next_vote: vec![0; n],
            next_announce: vec![0; n],
            band_double: false,
            band_prover: false,
            band_double_charge_ms: 0,
            template_double: false,
            real_ledger: false,
            ports: vec![0; n],
            listeners: (0..n).map(|_| None).collect(),
            check_state: false,
            window_cap: 0,
            window_lookahead_for_test: 0,
            first_divergence: None,
            step_census: false,
            census_reds: Vec::new(),
            census_rows: 0,
        }
    }

    /// `n` fresh in-memory nodes on `g` and `params`, each on its seeded miner seed, node 0 the mesh's bootstrap origin.
    fn fresh_runtimes(
        n: usize,
        wire: &Arc<Wire>,
        g: &crate::block::Block,
        params: &crate::params::ChainParams,
        seed: u64,
    ) -> Vec<Arc<Mutex<NodeRuntime<SimEndpoint>>>> {
        let mut rts: Vec<NodeRuntime<SimEndpoint>> = (0..n)
            .map(|me| {
                let mut node = Node::with_params(g.clone(), params.clone()).expect("a node boots on the production genesis");
                node.set_miner_seed_for_test(sim_miner_seed(seed, me, 0));
                let mut rt = NodeRuntime::new(node, SimEndpoint { wire: wire.clone(), me });
                rt.set_external_producer(); // the daemon's shape: production runs beside the relay loop
                rt
            })
            .collect();
        rts[0].set_mesh_bootstrap_origin();
        rts.into_iter().map(|rt| Arc::new(Mutex::new(rt))).collect()
    }

    /// ⛔ ADVERSARY TOPOLOGY (DB-380). Sever the link between `a` and `b` in both directions: cells, asks, follows and
    /// oracle pages between them are dropped from now on; asks already in flight on the link are lost too.
    pub fn sever(&mut self, a: usize, b: usize) {
        let mut bl = self.wire.blocked.lock().unwrap();
        bl[a * self.wire.n + b] = true;
        bl[b * self.wire.n + a] = true;
    }
    /// Restore the link between `a` and `b` in both directions.
    pub fn restore(&mut self, a: usize, b: usize) {
        let mut bl = self.wire.blocked.lock().unwrap();
        bl[a * self.wire.n + b] = false;
        bl[b * self.wire.n + a] = false;
    }
    /// ECLIPSE: `victim` keeps links only to `keep`; every other link of the victim is severed. (The adversary set is
    /// usually isolated to the victim as well, so its private chain never reaches the honest mesh.)
    pub fn isolate(&mut self, victim: usize, keep: &[usize]) {
        for other in (0..self.wire.n).filter(|&o| o != victim && !keep.contains(&o)) {
            self.sever(victim, other);
        }
    }
    /// PARTITION: every link between `side_a` and the rest is severed; `heal` is `restore` over the same pairs.
    pub fn partition(&mut self, side_a: &[usize]) {
        for &a in side_a {
            for b in (0..self.wire.n).filter(|b| !side_a.contains(b)) {
                self.sever(a, b);
            }
        }
    }
    /// Heal a partition laid by `partition(side_a)`.
    pub fn heal(&mut self, side_a: &[usize]) {
        for &a in side_a {
            for b in (0..self.wire.n).filter(|b| !side_a.contains(b)) {
                self.restore(a, b);
            }
        }
    }
    /// ⭐⭐ STATE IS A FUNCTION OF THE CHAIN (Ethereum's STF; the charter's borrowed shape) — measured across every pair of up
    /// nodes: the member anchor ring's root at every fold ordinal both hold, and every completed member window `(level,
    /// window)` both hold, must be the same value. A restart, a join or a reorg that lands one node on a different tree
    /// is named here the moment it exists (fold ordinal or window, both values' first lane), not when a wallet's path
    /// later fails to refold. `None` = every pair agrees on everything it shares.
    #[must_use]
    pub fn state_divergence(&self) -> Option<String> {
        type Ring = HashMap<u64, crate::spend_frontier::Digest4>;
        type Windows = HashMap<(u8, u64), (u64, crate::spend_frontier::Digest4)>;
        let views: Vec<(usize, Ring, Windows)> = (0..self.rts.len())
            .filter(|&i| !self.is_down(i))
            .map(|i| {
                let rt = self.rt(i);
                let n = rt.node();
                let ring: Ring = n.anchor_ring().into_iter().collect();
                let windows: Windows =
                    n.path_refresh_stream(0).entries.into_iter().map(|(o, l, w, r)| ((l, w), (o, r))).collect();
                (i, ring, windows)
            })
            .collect();
        for a in 0..views.len() {
            for b in a + 1..views.len() {
                let ((ia, ra, wa), (ib, rb, wb)) = ((&views[a].0, &views[a].1, &views[a].2), (&views[b].0, &views[b].1, &views[b].2));
                // the selected chain itself, at every blue score both hold at or below the SETTLED depth: a settled height
                // must name the same block on every node (a wallet's persisted cursor is a height on whichever node it asks).
                // ⛔ SETTLED = THE PROTOCOL'S OWN FOLD DEPTH: the selected-chain block `record_fold_depth` STEPS below each
                // node's tip (the node folds records there and nowhere shallower; above it a reorg is GHOSTDAG converging, and
                // the fold re-folds from the common prefix by design — `ChainParams::record_fold_depth`). MEASURED
                // sim-20261007-005557 T2: judged at `GATE_DEPTH` = 8 BLUE SCORE (≈ 3 chain steps at 3 producers, ~12 s), the
                // invariant failed on blocks born at t=1117/1118 s flagged at t=1130 s while each node held the other's —
                // and the same run read "state agrees across the up nodes" at t=1263 s: tip-local convergence, not a split
                // (the same shape as sim-20261006-234131 T1.4 and sim-20261007-002009 T1.2, tips 9 blue score apart).
                let chain = |i: usize| -> HashMap<u64, BlockId> {
                    self.rt(i).node().dag().dag_recent_view(256).into_iter().filter(|v| v.4).map(|v| (v.2, v.0)).collect()
                };
                let (ca, cb) = (chain(*ia), chain(*ib));
                let settled = |c: &HashMap<u64, BlockId>| -> Option<u64> {
                    let mut s: Vec<u64> = c.keys().copied().collect();
                    s.sort_unstable();
                    s.iter().rev().nth(self.params.record_fold_depth as usize).copied()
                };
                if let (Some(ta), Some(tb), Some(sa), Some(sb)) = (ca.keys().max(), cb.keys().max(), settled(&ca), settled(&cb)) {
                    let below = sa.min(sb);
                    let mut hs: Vec<u64> = ca.keys().filter(|h| **h <= below && cb.contains_key(h)).copied().collect();
                    hs.sort_unstable();
                    if let Some(h) = hs.iter().find(|h| ca[h] != cb[h]) {
                        // Name each block's producer and birth, and whether each node's DAG HOLDS the other's block: a block
                        // never received (a relay hole) and a block held but ordered differently (a GHOSTDAG disagreement)
                        // are different defects with different fixes (MEASURED sim-20261006-182524 T1.6 could not tell).
                        let about = |id: &BlockId| {
                            self.born.get(id).map_or_else(|| "born ?".to_string(), |(p, t)| format!("born n{p} t={} s", t / 1000))
                        };
                        let holds = |i: usize, id: &BlockId| self.rt(i).node().dag().contains(id);
                        // ⭐ WHY THEY DIFFER (link 17, seed 0x3 T1.5: six fold-reorgs from one fork point in 10 s, a 64-deep
                        // oscillation while each node held the other's block): each node's OWN GHOSTDAG data for both blocks
                        // (blue score, blue work, selected parent) and its selected tip and template. Equal data on both
                        // nodes + a template that drops the other branch = merge-depth branches racing; DIFFERENT data for
                        // the same block = the two nodes compute GHOSTDAG differently (a restart or a join changed it).
                        let gd = |i: usize, id: &BlockId| -> String {
                            let rt = self.rt(i);
                            let d = rt.node().dag();
                            d.get(id).map_or_else(
                                || "absent".to_string(),
                                |b| {
                                    format!(
                                        "s{} w{:#x} sp {} parents {}",
                                        b.blue_score,
                                        b.blue_work,
                                        b.selected_parent.map_or_else(|| "-".to_string(), |p| p.to_hex()[..8].to_string()),
                                        b.header.parents.len()
                                    )
                                },
                            )
                        };
                        let tipinfo = |i: usize| -> String {
                            let rt = self.rt(i);
                            let n = rt.node();
                            let d = n.dag();
                            let tips = d.tips();
                            let tp = d.template_parents();
                            let st = d.selected_tip().and_then(|t| d.get(&t).map(|b| format!("{} s{} w{:#x}", &t.to_hex()[..8], b.blue_score, b.blue_work)));
                            // ⭐ 2026-11-02 (certify 32f7626 T2): the tip key is (finality_admits, work, id) — print the floor each
                            // node binds to and how it admits EVERY tip, so an equal-work split names its cause (a floor one node
                            // tallied and the other did not) instead of two tips.
                            let floor = d.finality_floor().map(|f| format!("{}@{}", &f.to_hex()[..8], d.get(&f).map_or(0, |b| b.blue_score)));
                            let admits: Vec<String> = tips.iter().map(|t| format!("{}:{}", &t.to_hex()[..8], d.finality_admits(t))).collect();
                            format!(
                                "selected tip {} · {} tip(s) · template merges {} · finalized h{} floor {} · admits [{}] · deferred votes {}",
                                st.unwrap_or_default(),
                                tips.len(),
                                tp.len(),
                                n.finalized_height(),
                                floor.unwrap_or_else(|| "none".to_string()),
                                admits.join(" "),
                                n.deferred_votes_len()
                            )
                        };
                        let (a_id, b_id) = (ca[h], cb[h]);
                        // ⭐ RELAY HOLE OR SELECTION (seed 0x7131fa0020261040 T2 could not tell): how many of each node's
                        // selected-chain blocks above the split the OTHER node's DAG lacks. Both zero = both hold both chains
                        // and still select differently (a GHOSTDAG disagreement); non-zero = the lagging node never got them.
                        let lacks = |c: &HashMap<u64, BlockId>, other: usize| c.iter().filter(|(s, id)| **s > *h && !holds(other, id)).count();
                        let (a_lacks, b_lacks) = (lacks(&ca, *ib), lacks(&cb, *ia));
                        return Some(format!(
                            "selected chain: n{ia} and n{ib} name DIFFERENT blocks at blue score {h} ({} {} vs {} {}; n{ia} holds n{ib}'s: {}, \
                             n{ib} holds n{ia}'s: {}; tips {ta}/{tb}; {} common scores ≤ {below}; n{ib} lacks {a_lacks} of n{ia}'s chain above it, \
                             n{ia} lacks {b_lacks} of n{ib}'s) · GHOSTDAG n{ia}: {} = [{}] / {} = [{}] · {} \
                             | n{ib}: {} = [{}] / {} = [{}] · {}",
                            &ca[h].to_hex()[..12],
                            about(&ca[h]),
                            &cb[h].to_hex()[..12],
                            about(&cb[h]),
                            holds(*ia, &cb[h]),
                            holds(*ib, &ca[h]),
                            hs.len(),
                            &a_id.to_hex()[..8],
                            gd(*ia, &a_id),
                            &b_id.to_hex()[..8],
                            gd(*ia, &b_id),
                            tipinfo(*ia),
                            &a_id.to_hex()[..8],
                            gd(*ib, &a_id),
                            &b_id.to_hex()[..8],
                            gd(*ib, &b_id),
                            tipinfo(*ib)
                        ));
                    }
                }
                let mut common: Vec<u64> = ra.keys().filter(|o| rb.contains_key(o)).copied().collect();
                common.sort_unstable();
                if let Some(o) = common.iter().find(|o| ra[o] != rb[o]) {
                    return Some(format!(
                        "member ring: n{ia} and n{ib} hold DIFFERENT roots at fold ordinal {o} ({:?}… vs {:?}…; {} common ordinals {:?}..={:?})",
                        ra[o][0], rb[o][0], common.len(), common.first(), common.last()
                    ));
                }
                let mut wcommon: Vec<(u8, u64)> = wa.keys().filter(|k| wb.contains_key(k)).copied().collect();
                wcommon.sort_unstable();
                if let Some(k) = wcommon.iter().find(|k| wa[k].1 != wb[k].1) {
                    return Some(format!(
                        "member window (level {}, window {}): n{ia} completed it at ordinal {} as {:?}…, n{ib} at ordinal {} as {:?}…",
                        k.0, k.1, wa[k].0, wa[k].1[0], wb[k].0, wb[k].1[0]
                    ));
                }
            }
        }
        None
    }

    /// Node `i`'s every field, digested: the derived census (`NodeFieldCensus`) with each stand-in's digest in its field's
    /// slot. The ONE snapshot both censuses compare — the restart census (one node, before/after) and the replicated-state
    /// census (across nodes).
    pub fn field_census(&self, i: usize) -> Vec<(&'static str, Option<(u64, usize)>)> {
        let rt = self.rt(i);
        let mut v = rt.node().restart_census_digest();
        for (n, d) in rt.node().restart_census_stand_ins() {
            if let Some(slot) = v.iter_mut().find(|(f, _)| *f == n) {
                slot.1 = Some(d);
            }
        }
        v
    }

    /// ⭐⭐⭐ DB-402 R1 — THE REPLICATED-STATE CENSUS. State is a function of the chain (Ethereum STF): two nodes holding the
    /// same chain must hold the same value in EVERY `Node` field that is not node-local. Production is paused, the relay
    /// drains, and once every up node has held the same tips and the same fold position for 30 simulated seconds (no block
    /// grinding), every field is compared across the up nodes. DEFAULT = REPLICATED: only `NODE_LOCAL` (each entry with its
    /// reason) excludes a field, so a field added tomorrow is compared the next run with no list to edit (DB-402: every guard
    /// that missed DB-401 compared a hand-picked list). Verdicts: SAME · DIFFERS · NODE_LOCAL · UNREAD (no digest and no
    /// stand-in — a blind spot, counted as a hole) · NOT-QUIET (the mesh never quiesced: no verdict is claimed).
    /// Prints `[replica-census-row] lane \t field \t verdict \t bytes per node` (sim_ledgers.py → replica-census.tsv) and
    /// returns the rows. Production resumes as it was.
    pub fn replica_census(&mut self, lane: &str) -> Vec<(String, &'static str, String)> {
        let was = self.produce_paused;
        self.produce_paused = true;
        let up: Vec<usize> = (0..self.rts.len()).filter(|&i| !self.is_down(i)).collect();
        // ⭐ §POLES (lane a 2026-10-25): the quiet point is the WHOLE pipeline at rest, not only the tips and the record fold —
        // the band's lag, the unfolded buffer the window drains, and the finalized height. MEASURED: with
        // tips + nf_fold_seq + served_seq alone the census compared a node 9 band steps behind its peers (band lag 9 at the
        // pause; sparse_work ordinal 55 vs 61, census4-diag2.log) and read the lag as DIFFERS. A pipeline that never comes to rest reads NOT-QUIET (a red).
        let key = |sim: &NetSim, i: usize| -> (Vec<String>, u64, u64, usize, usize, u64) {
            let rt = sim.rt(i);
            let n = rt.node();
            let mut tips: Vec<String> = n.dag().tips().iter().map(|t| t.to_hex()).collect();
            tips.sort();
            (
                tips,
                n.nf_fold_seq(),
                n.served_seq(),
                n.band_lag(),
                n.unfolded_blocks_len(),
                n.finality_tally_split().0,
            )
        };
        let (t0, mut since, mut quiet) = (self.now, None::<u64>, false);
        while up.len() > 1 && self.now < t0 + 600_000 {
            self.run(5_000, 10_000);
            let k0 = key(self, up[0]);
            let same = self.pending.iter().all(Option::is_none) && up.iter().all(|&i| key(self, i) == k0);
            match (same, since) {
                (true, Some(s)) if self.now - s >= 30_000 => {
                    quiet = true;
                    break;
                }
                (true, None) => since = Some(self.now),
                (false, _) => since = None,
                _ => {}
            }
        }
        if !quiet && up.len() > 1 {
            for &i in &up {
                let k = key(self, i);
                eprintln!(
                    "[replica-census-unquiet] {lane} n{i}: tips {} nf_fold_seq {} (nf_blocks {}) served_seq {} band lag {} unfolded {} finalized {}",
                    k.0.len(), k.1, self.rt(i).node().nf_blocks_folded(), k.2, k.3, k.4, k.5
                );
            }
        }
        let local: Vec<&str> = crate::node::restart_census_stand_ins::NODE_LOCAL.iter().map(|(n, _)| *n).collect();
        // ⭐ §POLES (lane a 2026-10-27): the authority manifest is the ONE ruling of whose state a field is; a field it rules
        // `LocalCache` (with its reason there) is this node's by design, and the census never held a second, disagreeing
        // list of it. MEASURED (holes-20261026-233008.log): 102 T0 rows, ~3/4 of them manifest-ruled LocalCache fields
        // (fold journals, anchors, rings) where a DSYNC joiner differs from replayers because it adopted, not replayed.
        let local_cache: Vec<&str> = crate::harness::fuzz::authority::AUTHORITY_MANIFEST
            .iter()
            .filter(|(_, a)| *a == crate::harness::fuzz::authority::Authority::LocalCache)
            .map(|(n, _)| *n)
            .collect();
        let unordered: Vec<&str> = crate::node::restart_census_stand_ins::UNORDERED.iter().map(|(n, _)| *n).collect();
        // an UNORDERED field is compared as a SET across the up nodes (the order-only probe): its items must agree
        let same_set = |sim: &NetSim, f: &str| -> bool {
            let ms = |i: usize| {
                let rt = sim.rt(i);
                let n = rt.node();
                crate::node::restart_census_fields::multiset_digest(&|out| n.census_field_render(f, out))
            };
            let m0 = ms(up[0]);
            up.iter().skip(1).all(|&i| ms(i) == m0)
        };
        // a BY_STATEMENT field (zero-knowledge proof bytes held) is compared by its statement: every proven fact must agree
        let by_statement: Vec<&str> = crate::node::restart_census_stand_ins::BY_STATEMENT.iter().map(|(n, _)| *n).collect();
        let same_statement = |sim: &NetSim, f: &str| -> bool {
            let sd = |i: usize| {
                let rt = sim.rt(i);
                let n = rt.node();
                crate::node::restart_census_fields::multiset_digest(&|out| n.census_field_render_statement(f, out))
            };
            let s0 = sd(up[0]);
            up.iter().skip(1).all(|&i| sd(i) == s0)
        };
        let snaps: Vec<Vec<(&'static str, Option<(u64, usize)>)>> = up.iter().map(|&i| self.field_census(i)).collect();
        let mut rows = Vec::new();
        if let Some(first) = snaps.first() {
            for (k, (f, d0)) in first.iter().enumerate() {
                let all: Vec<Option<(u64, usize)>> = snaps.iter().map(|s| s[k].1).collect();
                let verdict = if local.contains(f) {
                    "NODE_LOCAL"
                } else if !quiet || up.len() < 2 {
                    "NOT-QUIET"
                } else if d0.is_none() {
                    // J19: a field the manifest rules this node's own (LocalCache) has nothing to compare, so no reader is no hole
                    if local_cache.contains(f) { "LOCAL_CACHE" } else { "UNREAD" }
                } else if all.iter().all(|d| d.map(|x| x.0) == d0.map(|x| x.0)) {
                    "SAME"
                } else if unordered.contains(f) && same_set(self, f) {
                    "SAME-SET"
                } else if by_statement.contains(f) && same_statement(self, f) {
                    "SAME-STATEMENT"
                } else if local_cache.contains(f) {
                    // still COMPARED (a SAME stays measured); a difference is this node's own history, not a red
                    "LOCAL_CACHE"
                } else {
                    "DIFFERS"
                };
                let bytes = all.iter().map(|d| d.map_or("-".to_string(), |x| x.1.to_string())).collect::<Vec<_>>().join("/");
                eprintln!("[replica-census-row] {lane}\t{f}\t{verdict}\t{bytes}");
                if verdict == "DIFFERS" {
                    // name the cause, not a digest: where the first node that disagrees with up[0] parts from it
                    if let Some(j) = (1..snaps.len()).find(|&j| snaps[j][k].1.map(|x| x.0) != d0.map(|x| x.0)) {
                        let (ra, rb) = (self.rt(up[0]), self.rt(up[j]));
                        let (na, nb) = (ra.node(), rb.node());
                        let stmt = by_statement.contains(f);
                        let render = |side: bool, out: &mut dyn std::fmt::Write| {
                            let n = if side { &nb } else { &na };
                            if stmt { n.census_field_render_statement(f, out) } else { n.census_field_render(f, out) }
                        };
                        let multiset = |side: bool| crate::node::restart_census_fields::multiset_digest(&|out| render(side, out));
                        let shape = if multiset(false) == multiset(true) {
                            "ORDER-ONLY (the same items in another order: arrival order in a replicated field)"
                        } else {
                            "CONTENT (different items)"
                        };
                        match crate::node::restart_census_fields::first_difference(&render, 160) {
                            Ok((at, la, lb, ca, cb)) => eprintln!(
                                "[replica-census-diff] {lane}\t{f}\tn{} vs n{}: {shape} · {la}/{lb} B, first difference at byte {at}\n  n{}: {ca}\n  n{}: {cb}",
                                up[0], up[j], up[0], up[j]
                            ),
                            Err(why) => eprintln!("[replica-census-diff] {lane}\t{f}\tn{} vs n{}: {why}", up[0], up[j]),
                        }
                        // CONTENT in a map-shaped field: name the items one side holds and the other lacks (lane a
                        // 2026-10-22 — "first difference at byte 3" named no key). The same census text the line above
                        // prints, on simulated fixture nodes.
                        if shape.starts_with("CONTENT") {
                            match crate::node::restart_census_fields::set_difference(&render, 120, 8) {
                                Ok((oa, ob, la, lb)) => {
                                    eprintln!(
                                        "[replica-census-set] {lane}\t{f}\tn{} holds {la} item(s), n{} holds {lb}; only n{}: {oa:?}; only n{}: {ob:?}",
                                        up[0], up[j], up[0], up[j]
                                    );
                                    // DB-402 (lane a 2026-10-27): a record row one node holds and another lacks — name, on
                                    // EVERY up node, the record's ordinal, its block and why it is (not) retained.
                                    if matches!(*f, "da_mem" | "da_tags_mem") {
                                        // ⛔ MEASURED 2026-10-28 (lane funds, journey-121.log): the two runtimes' guards `ra`/`rb`
                                        // are HELD here, and this loop re-locked them (`self.rt(i)` for every up node) — a
                                        // self-deadlock on the test thread the first time `da_tags_mem` differed by CONTENT:
                                        // "[replica-census-set] … n0 holds 1518 item(s)" was the run's last line, CPU flat
                                        // 615 s, lane_run ended it at 1780 s (exit 143) AFTER every journey row had passed.
                                        // The two differing nodes are the ones the why-line is about: read them through the
                                        // guards already held, never by a second lock.
                                        for item in oa.iter().chain(ob.iter()).take(6) {
                                            let Some(seq) = item.split(':').next().and_then(|k| k.trim().parse::<u64>().ok()) else { continue };
                                            for (i, n) in [(up[0], &na), (up[j], &nb)] {
                                                eprintln!(
                                                    "[replica-census-row-why] {lane}\t{f}\t{seq}\tn{i}: {}",
                                                    n.record_holding_diag_for_test(seq)
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(why) => eprintln!("[replica-census-set] {lane}\t{f}\t{why}"),
                            }
                        }
                    }
                }
                rows.push((f.to_string(), verdict, bytes));
            }
        }
        let count = |v: &str| rows.iter().filter(|r| r.1 == v).count();
        eprintln!(
            "[replica-census] {lane}: nodes {up:?} quiet {quiet} after {} s · SAME {} · SAME-SET {} · SAME-STATEMENT {} · DIFFERS {} · UNREAD {} · NODE_LOCAL {} · LOCAL_CACHE {} · NOT-QUIET {}",
            (self.now - t0) / 1000,
            count("SAME"),
            count("SAME-SET"),
            count("SAME-STATEMENT"),
            count("DIFFERS"),
            count("UNREAD"),
            count("NODE_LOCAL"),
            count("LOCAL_CACHE"),
            count("NOT-QUIET")
        );
        self.produce_paused = was;
        rows
    }

    /// ⭐ DB-412 — the MEAN gap between one node's blocks, read from the shipped schedule (`NodeRuntime::production_spacing_ms`,
    /// the fair share each up node takes: never under the relay floor once it sees a peer), or the experiment's cap if slower.
    /// The one cadence every wait budget derives from (`spendable_within_ms`, `spendable_within_s`), never a tuned number.
    pub fn production_step_ms(&self) -> u64 {
        let shipped = (0..self.rts.len())
            .filter(|&i| !self.is_down(i))
            .map(|i| self.rt(i).production_spacing_ms())
            .max()
            .unwrap_or(0);
        shipped.max(crate::node_runtime::PRODUCTION_RELAY_FLOOR_MS).max(self.produce_every_ms)
    }

    /// The one-chain predicate between any two parties at or below `min(tip) − GATE_DEPTH` (the gate's, generalised).
    pub fn one_chain_between(&self, a: usize, b: usize) -> bool {
        let view = |rt: &NodeRuntime<SimEndpoint>| -> HashMap<u64, BlockId> {
            rt.node().dag().dag_recent_view(256).into_iter().filter(|v| v.4).map(|v| (v.2, v.0)).collect()
        };
        let (va, vb) = (view(&self.rt(a)), view(&self.rt(b)));
        let (Some(ta), Some(tb)) = (va.keys().max().copied(), vb.keys().max().copied()) else { return false };
        let below = ta.min(tb).saturating_sub(GATE_DEPTH);
        // MEASURED 2026-10-04 13:5x (eclipse-pin4.log): an `all(..)` over the shared heights read TRUE for an eclipsed victim
        // whose chain had diverged so far that the two 256-height windows shared NO height — vacuous. The gate's sampler
        // counts agree/disagree; one chain is at least one agreeing height and no disagreeing one.
        let (mut agree, mut disagree) = (0usize, 0usize);
        for (h, id) in va.iter().filter(|(h, _)| **h <= below) {
            match vb.get(h) {
                Some(other) if other == id => agree += 1,
                Some(_) => disagree += 1,
                None => {}
            }
        }
        agree > 0 && disagree == 0
    }

    /// Advance the simulated clock by one step (a window of one): see [`Self::step_window`].
    fn step(&mut self) {
        let _ = self.step_window(1);
    }

    /// Every node's clock (and the wire's) to `t` — and the simulated Bitcoin's, which mines its blocks on it.
    fn set_clock(&self, t: u64) {
        self.wire.now.store(t, Ordering::Relaxed);
        for c in &self.wire.clocks {
            c.store(t, Ordering::Relaxed);
        }
        if let Some(b) = &self.foreign_btc {
            b.chain().advance_clock(t);
        }
        if let Some(x) = &self.foreign_xmr {
            x.chain().advance_clock(t);
        }
    }

    /// §NETSIM-LAUNCH: give this mesh a simulated Bitcoin (`btc_sim::SimBitcoin`, seeded, one block per
    /// `block_interval_ms` of simulated time). Every node's deposit watcher, payout lane and solvency check then read it
    /// through `btc_watch::btc_source`, unchanged. The caller holds `btc_sim::serial()` for the run (one world per
    /// process). Call before [`NetSim::boot_from_disk`] or [`NetSim::run`].
    pub fn with_sim_bitcoin(mut self, seed: u64, block_interval_ms: u64) -> NetSim {
        let mut chain = crate::btc_sim::SimBitcoin::new(seed);
        chain.set_block_interval_ms(block_interval_ms);
        self.foreign_btc = Some(crate::btc_sim::install(chain));
        crate::rpc_http::start_watchers(); // the deposit watchers a production node runs read this chain from now on
        self
    }

    /// The simulated Bitcoin, to fund, mine, reorg or read (the same object every node reads through its source).
    pub fn btc(&self) -> std::sync::MutexGuard<'_, crate::btc_sim::SimBitcoin> {
        self.foreign_btc.as_ref().expect("NetSim::with_sim_bitcoin was not called").chain()
    }

    /// §NETSIM-LAUNCH: give this mesh a simulated Monero (`xmr_sim::SimMonero`, seeded, one block per
    /// `block_interval_ms` of simulated time). Every node's custody lane, deposit watcher and payout lane then drive it
    /// through `xmr_rpc::WalletRpc::from_env` / `DaemonRpc::from_env`, unchanged. The caller holds `xmr_sim::serial()`
    /// for the run (one world per process). Call before [`NetSim::boot_from_disk`] or [`NetSim::run`].
    pub fn with_sim_monero(mut self, seed: u64, block_interval_ms: u64) -> NetSim {
        let mut chain = crate::xmr_sim::SimMonero::new(seed);
        chain.set_block_interval_ms(block_interval_ms).expect("a non-zero Monero block interval");
        self.foreign_xmr = Some(crate::xmr_sim::install(chain));
        crate::rpc_http::start_watchers(); // the deposit watchers a production node runs read this chain from now on
        self
    }

    /// The simulated Monero, to fund, mine, reorg or read (the same object every node's wallet answers from).
    pub fn xmr(&self) -> std::sync::MutexGuard<'_, crate::xmr_sim::SimMonero> {
        self.foreign_xmr.as_ref().expect("NetSim::with_sim_monero was not called").chain()
    }

    /// How many steps the next window may take: as many as the wire's lookahead allows (one leg — nothing a node sends can
    /// reach another sooner), never past the run's `end`, the next gate sample, or the next 10-second state check (every
    /// 60-second progress line falls on one).
    fn window_steps(&self, end: u64, next_sample: u64) -> u64 {
        let step = self.step_ms.max(1);
        let to = |t: u64| t.saturating_sub(self.now).div_ceil(step).max(1);
        let next_check = (self.now / 10_000 + 1) * 10_000;
        let lookahead = if self.window_lookahead_for_test > 0 { self.window_lookahead_for_test } else { (self.wire.phys.leg_ms / step).max(1) };
        let cap = if self.window_cap == 0 { lookahead } else { self.window_cap.min(lookahead) };
        cap.min(to(end)).min(to(next_sample)).min(to(next_check))
    }

    /// REPLAYABLE (uncharged): the run becomes one function of its seed — every node thread's budget clock stands still
    /// (`budget_clock::freeze_this_thread`) and every random draw a node makes comes from its seeded stream
    /// (`budget_clock::SimEntropy`, via the vendored `randombytes` seam); so does this (the boot and restart) thread's.
    pub fn make_replayable(&mut self) {
        self.charge_cpu = false;
        self.replayable = true;
        crate::budget_clock::freeze_this_thread(true);
        crate::budget_clock::seed_entropy_this_thread(Some(crate::budget_clock::SimEntropy::new(self.seed, u64::MAX, 0)));
        pqcrypto_internals::set_entropy_source(crate::budget_clock::sim_entropy_fill);
    }

    /// ⭐⭐ THE CONSERVATIVE WINDOW — advance up to `k` steps with every node on its OWN thread for the whole window, and
    /// return the steps taken. BORROWED: conservative parallel discrete-event simulation with a fixed lookahead
    /// (Chandy–Misra–Bryant): nothing one node sends reaches another sooner than one wire leg (`Physics::leg_ms` — a cell,
    /// an ask, an answer, a follow and an oracle page each ride at least one), so inside a window no longer than that leg
    /// the nodes cannot affect one another. Each runs its steps in exactly the per-node order the one-step loop ran them —
    /// serve its due asks, serve and hold its follows, land its own follows, its announce / producer / relay, record its
    /// arrivals — against the messages already in flight when the window opened. Every send draws from its sender's own
    /// stream (`Wire::leg` / `Wire::seq`) and every queue is taken in (at, seq) order, so a window is the same whatever order
    /// the threads run in, and the same as its steps one at a time.
    /// MEASURED why (link 26, a solo `sample` of the fast journey, night/link26-sample.txt): the node threads' work summed
    /// to about the step loop's whole wall (≈ 170 s of 174 s) — every 50 ms step waited at its barrier for the ONE node that
    /// was grinding (30 ms PoUW hashes), building a template or folding, while the other two idled.
    /// The window is clamped by the caller ([`Self::window_steps`]) and here to the next instant a down node comes back, so a
    /// bring-up, a restart, a sample and a state check each still happen at their own step.
    fn step_window(&mut self, k: u64) -> u64 {
        let wall_t0 = std::time::Instant::now();
        let start_us = speed_now_us();
        let step_ms = self.step_ms;
        let first = self.now + step_ms;
        self.now = first;
        self.set_clock(first);
        for i in 0..self.rts.len() {
            if self.down_until[i] != 0 && self.down_until[i] <= first {
                self.down_until[i] = 0;
                self.drop_traffic_of(i); // nothing sent while it was down reaches the new process
                self.wire.down[i].store(false, Ordering::Relaxed);
                if self.ports[i] != 0 && self.listeners[i].is_none() {
                    self.start_listener(i); // the new process binds the same RPC port
                }
            }
        }
        // ⭐ THE SUPERVISOR (DB-406). A `/provision_validator` installs a seed-derived identity and asks for a restart
        // (`validator::identity_restart_requested`); the daemon's shutdown watcher sees it on its next 200 ms tick, writes the
        // shutdown snapshot and exits, and launchd's KeepAlive respawns it at once (a job that ran longer than the
        // ThrottleInterval is not throttled) onto the new key file. This loop is that watcher + launchd for every simulated
        // node: MEASURED sim-20261007-002601 T3 — nothing acted on the request, so the node never came back on the
        // wallet's identity and the bond waited out its 3 minutes.
        for i in 0..self.rts.len() {
            if self.is_down(i) || self.dirs[i].is_none() {
                continue;
            }
            if crate::persist::with_thread_node_files_for_test(self.node_files(i), crate::validator::identity_restart_requested) {
                eprintln!("[netsim] node {i}: a provisioned validator identity asks for a restart — the supervisor restarts it");
                if let Err(e) = self.restart(i, SHUTDOWN_WATCHER_TICK_MS) {
                    eprintln!("[netsim] node {i}: the identity restart failed to boot: {e}");
                }
            }
        }
        // ⭐ DB-437 — THE FINALITY VOTER. Every daemon runs a voter thread (`main.rs` / `serve.rs`: `vote_guard::vote_tick`
        // every 200 ms over the node's own vote key); the simulator ran none, so no level was ever voted and P4 read
        // `finalized 0` at every height. This loop is that thread for every up node, over its own key files (the
        // write-ahead guard sits beside the vote key). An unseated voter's vote counts nowhere (weight 0), as on a daemon.
        const VOTE_TICK_MS: u64 = 200; // the daemon voter's sleep
        for i in 0..self.rts.len() {
            if self.is_down(i) || self.dirs[i].is_none() || first < self.next_vote[i] {
                continue;
            }
            self.next_vote[i] = first + VOTE_TICK_MS;
            let files = self.node_files(i);
            let rt = self.rts[i].clone();
            let (pk, sk) = self.keys[i].clone();
            let guard = &mut self.vote_guards[i];
            if std::env::var("REPLAY_TX_TRACE").is_ok_and(|v| v == "all") {
                eprintln!("[tx-trace] voter t {first} vote-tick node{i} 00000000 link None · []");
            }
            crate::persist::with_thread_node_files_for_test(files, || {
                let g = guard.get_or_insert_with(crate::vote_guard::VoteGuard::for_node_vote_key);
                let _ = crate::vote_guard::vote_tick(&rt, g, &pk, &sk);
            });
        }

        // never past the next bring-up: a node down for the window stays down for all of it, and comes back at a window's start
        let mut k = k.max(1);
        for &d in &self.down_until {
            if d > first {
                k = k.min((d - first).div_ceil(step_ms.max(1)));
            }
        }
        self.wire.window_end.store(first + (k - 1) * step_ms, Ordering::Relaxed);
        if k > 1 {
            self.report.windows += 1;
        }
        let n = self.rts.len();
        let ctx = NodeStepCtx {
            n,
            produce_every_ms: self.produce_every_ms,
            produce_paused: self.produce_paused,
            oracle_push: self.oracle_push,
            charge_cpu: self.charge_cpu,
            replayable: self.replayable,
            lock_tax_ms: self.lock_tax_ms.clone(),
            band_double: self.band_double,
            band_double_charge_ms: self.band_double_charge_ms,
            template_double_ms: if self.template_double { TEMPLATE_PROVE_MS_REF } else { 0 },
            networks: (0..n).map(|i| self.network_of(i).1.genesis_parity_commit).collect(),
            coverage: crate::harness::sim_coverage::handle(),
            files: (0..n).map(|i| self.node_files(i)).collect(),
        };
        // each node's arrivals still to see: the blocks born elsewhere it has not yet grafted (a block born inside this
        // window cannot reach it before the window ends — that is the lookahead)
        let waiting: Vec<Vec<(BlockId, u64)>> = (0..n)
            .map(|j| {
                self.born
                    .iter()
                    .filter(|(id, (from, _))| *from != j && !self.arrived.contains(&(**id, j)))
                    .map(|(id, (_, t))| (*id, *t))
                    .collect()
            })
            .collect();
        let produced0 = self.report.produced.clone();
        let hold_ms = crate::arti_transport::FOLLOW_HOLD.as_millis() as u64;
        let (rts, wire, keys, miner, down_until) = (&self.rts, &self.wire, &self.keys, &self.miner, &self.down_until);
        let (replayable, seed, incarnations) = (self.replayable, self.seed, &self.incarnations);
        let sequential = std::env::var_os("SIM_SEQUENTIAL_WINDOWS").is_some_and(|v| !v.is_empty());
        let outs: Vec<WindowOut> = std::thread::scope(|sc| {
            let handles: Vec<_> = self
                .pending
                .iter_mut()
                .zip(self.last_begin.iter_mut())
                .zip(self.next_announce.iter_mut())
                .zip(self.next_relay.iter_mut())
                .zip(self.lock_free_at.iter_mut())
                .zip(self.entropy.iter_mut())
                .zip(waiting)
                .enumerate()
                .map(|(i, ((((((pending, last_begin), next_announce), next_relay), lock_free_at), entropy), mut waiting))| {
                    if replayable && entropy.is_none() {
                        *entropy = Some(crate::budget_clock::SimEntropy::new(seed, i as u64, incarnations[i]));
                    }
                    let (ctx, produced0) = (&ctx, produced0[i]);
                    let h = sc.spawn(move || {
                        ctx.enter_thread(i);
                        crate::persist::set_thread_node_files_for_test(ctx.files[i].clone());
                        crate::arti_transport::set_log_node(Some(i)); // this thread runs node i's steps: its lines say so
                        // PERF TIER step 1: this node's work budgets read its own CPU while the simulation charges it
                        crate::budget_clock::charge_this_thread(ctx.charge_cpu);
                        crate::budget_clock::freeze_this_thread(ctx.replayable);
                        crate::budget_clock::seed_entropy_this_thread(*entropy);
                        let mut w = WindowOut { i, ..WindowOut::default() };
                        let mut produced = produced0;
                        for s in 0..k {
                            let now = first + s * step_ms;
                            wire.clocks[i].store(now, Ordering::Relaxed);
                            crate::budget_clock::set_sim_now_ms(Some(now)); // the cadence clock of a replayable node
                            // ⭐ PERF TIER step 1: a node whose runtime lock is still busy with charged work takes no
                            // lock-held action this step — its asks and follows wait on the wire, its producer and relay
                            // tick wait for the lock, exactly as the daemon's loops wait on `Arc<Mutex<NodeRuntime>>`.
                            let lock_free = !ctx.charge_cpu || *lock_free_at <= now;
                            wire.ask_census[i][2].fetch_add(u64::from(!lock_free), Ordering::Relaxed);
                            wire.ask_census[i][3].fetch_add(1, Ordering::Relaxed);
                            if ctx.charge_cpu && lock_free {
                                STEP_CPU0.with(|c| c.set(crate::budget_clock::charged_cpu_us().max(1)));
                            }
                            let mut tax_ms = 0u64;
                            let ph = std::time::Instant::now();
                            if lock_free {
                                serve_due_asks(wire, &rts[i], i, now, &mut w);
                            }
                            w.phase_us[0] += ph.elapsed().as_micros();
                            let ph = std::time::Instant::now();
                            if lock_free {
                                serve_follows(wire, &rts[i], i, now, hold_ms, produced, &mut w);
                            }
                            land_follows(wire, i, now);
                            w.phase_us[1] += ph.elapsed().as_micros();
                            if down_until[i] <= now && lock_free {
                                // a process that is down neither produces nor relays
                                let o = node_step(ctx, now, i, &rts[i], wire, &keys[i], miner, pending, last_begin, next_announce, next_relay);
                                for (kk, us) in o.phase_us.iter().enumerate() {
                                    w.phase_us[kk] += us;
                                }
                                for kk in 0..6 {
                                    w.wall_ms[kk] += o.wall_ms[kk];
                                }
                                w.hashes += o.hashes;
                                tax_ms += o.tax_ms;
                                if let Some(id) = o.produced {
                                    produced += 1;
                                    w.produced.push((id, now));
                                    if wire.rx_on.load(Ordering::Relaxed) {
                                        let mut c = wire.rx[i].lock().unwrap();
                                        c.seen.insert(id.0); // its own block is never fresh to it
                                        c.first.entry(id.0).or_insert((now, RX_PRODUCED_HERE));
                                    }
                                }
                                if let Some(s) = o.size {
                                    w.sizes.push(s);
                                }
                                w.proved.extend(o.proved);
                                if let Some(b) = o.oracle {
                                    let (page, _) = crate::node_runtime::batch_page_frame(&Hash32([0u8; 32]), &[b]);
                                    for j in (0..wire.n).filter(|&j| j != i && !wire.is_blocked(i, j)) {
                                        let at = now + step_charge_us() / 1_000 + wire.leg(i) + page.len() as u64 / wire.phys.bytes_per_ms.max(1) + wire.phys.apply_ms;
                                        let seq = wire.seq(i);
                                        wire.sent(at);
                                        wire.answers[j].lock().unwrap().push(Due { at, seq, bytes: page.clone(), from: i, answer: false, kind: 0, wake: false, rotation: None });
                                    }
                                }
                            }
                            // the step's lock-held CPU holds the node's lock until `now + cost` (never shortening a hold)
                            if ctx.charge_cpu && lock_free {
                                let spent_us = step_charge_us() + tax_ms * 1_000;
                                STEP_CPU0.with(|c| c.set(0));
                                w.lock_cpu_us += spent_us;
                                *lock_free_at = now + spent_us / 1_000;
                            }
                            // arrivals: the first step at which this node's DAG holds a block born elsewhere (the
                            // simulation's observer, never the node's work: not charged)
                            let ph = std::time::Instant::now();
                            if !waiting.is_empty() {
                                let guard = rts[i].lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                let dag = guard.node().dag();
                                waiting.retain(|(id, t)| {
                                    if dag.contains(id) {
                                        w.arrived.push((*id, now - t));
                                        false
                                    } else if now - t > ARRIVAL_WINDOW_MS {
                                        w.expired.push(*id);
                                        false
                                    } else {
                                        true
                                    }
                                });
                            }
                            w.phase_us[8] += ph.elapsed().as_micros();
                        }
                        *entropy = crate::budget_clock::entropy_of_this_thread();
                        w
                    });
                    // REPLAY BISECTION seam: one node's window ends before the next one's begins
                    if sequential { Ok(h.join().expect("a simulated node's window panicked")) } else { Err(h) }
                })
                .collect();
            handles.into_iter().map(|h| h.unwrap_or_else(|h| h.join().expect("a simulated node's window panicked"))).collect()
        });
        // the window's critical path: its slowest node's work (the window ended when that node's thread did)
        let total = |w: &WindowOut| w.phase_us.iter().sum::<u128>();
        if let Some(slow) = outs.iter().max_by_key(|w| total(w)) {
            let (slow_us, all_us) = (total(slow), outs.iter().map(total).sum::<u128>());
            SPEED.with(|sp| {
                let mut m = sp.get();
                for (kk, us) in slow.phase_us.iter().enumerate() {
                    m.crit_us[kk] += us;
                }
                m.crit_total_us += slow_us;
                m.node_us += all_us;
                sp.set(m);
            });
        }
        for w in outs {
            SPEED.with(|sp| {
                let mut m = sp.get();
                for (kk, us) in w.phase_us.iter().enumerate() {
                    m.phase_us[kk] += us;
                }
                sp.set(m);
            });
            for kk in 0..6 {
                self.report.wall_ms[kk] += w.wall_ms[kk];
            }
            self.report.wall_ms[5] += w.serve_ms;
            self.report.hashes += w.hashes;
            for (id, t) in w.produced {
                self.report.produced[w.i] += 1;
                self.born.insert(id, (w.i, t));
            }
            self.report.block_sizes.extend(w.sizes);
            self.report.proved.extend(w.proved);
            for (id, ms) in w.arrived {
                self.arrived.insert((id, w.i));
                self.report.arrival_ms.push(ms);
                if let Some(v) = self.report.arrival_ms_at.get_mut(w.i) {
                    v.push(ms);
                }
            }
            if let Some(c) = self.report.lock_cpu_us.get_mut(w.i) {
                *c += w.lock_cpu_us;
            }
            SPEED.with(|sp| {
                let mut m = sp.get();
                m.charged_us += u128::from(w.lock_cpu_us);
                sp.set(m);
            });
            self.report.never_arrived += w.expired.len() as u64;
            for id in w.expired {
                self.arrived.insert((id, w.i));
            }
        }
        let last = first + (k - 1) * step_ms;
        self.now = last;
        self.set_clock(last);
        if self.replay_rows.is_some() {
            let row: Vec<(u64, usize, Vec<String>)> = (0..self.rts.len())
                .map(|i| {
                    let mut ids: Vec<String> = self.rt(i).node().mempool().all_tx_ids().iter().map(|id| Hash32(*id).to_hex()[..10].to_string()).collect();
                    ids.sort();
                    ids.push(self.rt(i).replay_relay_probe());
                    (self.entropy[i].map_or(0, |e| e.draws()), ids.len(), ids)
                })
                .collect();
            if let Some(rows) = self.replay_rows.as_mut() {
                rows.push((last, row));
            }
        }
        SPEED.with(|sp| {
            let mut m = sp.get();
            if m.first_us == 0 {
                m.first_us = start_us.max(1);
            }
            m.sim_ms += k * step_ms;
            m.step_us += wall_t0.elapsed().as_micros();
            sp.set(m);
        });
        k
    }

    /// The ask census of node `i`: (bulk asks addressed to it, asks it served, steps its charged lock was busy, steps).
    pub fn ask_census(&self, i: usize) -> [u64; 4] {
        std::array::from_fn(|k| self.wire.ask_census[i][k].load(Ordering::Relaxed))
    }

    /// Turn the inbound-bytes census ([`RxCensus`]) on — before the first block, so every node's `seen` set is complete.
    pub fn census_inbound(&self) {
        self.wire.rx_on.store(true, Ordering::Relaxed);
    }

    /// Node `i`'s by-record-id answers per host: (host, carried a record, `notfound`), hosts that answered at least once.
    pub fn record_answers(&self, i: usize) -> Vec<(usize, u64, u64)> {
        let r = self.wire.rec_answers.lock().unwrap();
        (0..self.wire.n).filter_map(|h| {
            let [f, nf] = r[i * self.wire.n + h];
            (f + nf > 0).then_some((h, f, nf))
        }).collect()
    }

    /// Per bulk ask kind with any traffic: (kind, asks sent, answers taken, answers carrying nothing, longest due wait ms).
    pub fn ask_kinds(&self) -> Vec<(u8, u64, u64, u64, u64)> {
        let k = self.wire.ask_kinds.lock().unwrap();
        (0..256usize).filter(|&i| k[i][0] + k[i][1] > 0).map(|i| (i as u8, k[i][0], k[i][1], k[i][2], k[i][3])).collect()
    }

    /// Real cell copies put on links so far, per `transport::CELL_KIND_NAMES` class.
    pub fn cell_kinds(&self) -> Vec<u64> {
        self.wire.cell_kinds.iter().map(|c| c.load(Ordering::Relaxed)).collect()
    }

    /// Real cell copies a full writer shed so far, per class ([`Wire::shed`]).
    pub fn cell_shed(&self) -> Vec<u64> {
        self.wire.shed.iter().map(|c| c.load(Ordering::Relaxed)).collect()
    }

    /// Real cell copies by how long they waited for their link, per [`CELL_WAIT_EDGES_MS`] bucket.
    pub fn cell_wait(&self) -> Vec<u64> {
        self.wire.cell_wait.iter().map(|c| c.load(Ordering::Relaxed)).collect()
    }

    /// The census's rows ([`CellMsgCensus`]) for every class with traffic: (class, sends, repeat sends, distinct messages,
    /// distinct (sender, message)).
    pub fn cell_msgs(&self) -> Vec<(u8, [u64; 4])> {
        let c = self.wire.cell_msgs.lock().unwrap();
        c.rows.iter().enumerate().filter(|(_, r)| r[0] > 0).map(|(k, r)| (k as u8, *r)).collect()
    }

    /// (sends that found `BULK_LANES_PER_HOST` conversations already open on their link, the most open on one link).
    pub fn lane_pressure(&self) -> (u64, u64) {
        (self.wire.over_lanes.load(Ordering::Relaxed), self.wire.open_max.load(Ordering::Relaxed))
    }

    /// The "record/DA/sync/other" inbound bytes so far, summed over nodes, by page tag.
    pub fn inbound_other(&self) -> HashMap<String, u64> {
        let mut m = HashMap::new();
        for r in &self.wire.rx {
            for (k, v) in &r.lock().unwrap().other {
                *m.entry(k.clone()).or_default() += v;
            }
        }
        m
    }

    /// When block `id` first landed at node `i` and by which lane ([`RxCensus::first`]), while the census is on.
    pub fn block_landed(&self, i: usize, id: &Hash32) -> Option<(u64, u8)> {
        self.wire.rx[i].lock().unwrap().first.get(&id.0).copied()
    }

    /// DB-445: the bodies woken follow pages carried to node `i` (host, block id), and how many of them it already held.
    pub fn woken_follow_bodies(&self, i: usize) -> (Vec<(usize, [u8; 32])>, u64) {
        let c = self.wire.rx[i].lock().unwrap();
        (c.woken.clone(), c.woken_dup)
    }

    /// DB-446: the bodies ANY follow page carried to node `i` (host, block id), arrival or woken.
    pub fn follow_bodies(&self, i: usize) -> Vec<(usize, [u8; 32])> {
        self.wire.rx[i].lock().unwrap().followed.clone()
    }

    /// Node `i`'s duplicate bodies by their own lane ([`DUP_ROWS`]) and their first copy's ([`DUP_COLS`]).
    pub fn dup_sources(&self, i: usize) -> [[u64; 4]; 3] {
        self.wire.rx[i].lock().unwrap().dup_src
    }

    /// The mesh's duplicate-source table, one line: "row: col n, col n · …" summed over every node.
    pub fn dup_sources_line(&self) -> String {
        let mut t = [[0u64; 4]; 3];
        for i in 0..self.wire.n {
            let d = self.dup_sources(i);
            for r in 0..3 {
                for c in 0..4 {
                    t[r][c] += d[r][c];
                }
            }
        }
        (0..3)
            .map(|r| format!("{} ← {}", DUP_ROWS[r], (0..4).map(|c| format!("{} {}", DUP_COLS[c], t[r][c])).collect::<Vec<_>>().join(", ")))
            .collect::<Vec<_>>()
            .join(" · ")
    }

    /// The blocks node `i` produced while the census was on, with the instant each was made.
    pub fn produced_blocks(&self, i: usize) -> Vec<(u64, Hash32)> {
        let c = self.wire.rx[i].lock().unwrap();
        let mut v: Vec<(u64, Hash32)> =
            c.first.iter().filter(|(_, l)| l.1 == RX_PRODUCED_HERE).map(|(id, l)| (l.0, Hash32(*id))).collect();
        v.sort();
        v
    }

    /// Node `i`'s inbound census so far: (bytes, bodies) per [`RX_LABELS`] kind.
    pub fn inbound(&self, i: usize) -> ([u64; RX_KINDS], [u64; RX_KINDS]) {
        let c = self.wire.rx[i].lock().unwrap();
        (c.bytes, c.bodies)
    }

    /// DB-420: how many sends to another node could have landed inside the window they were sent in (0 on a correct run).
    pub fn lookahead_breaks(&self) -> u64 {
        self.wire.early.load(Ordering::Relaxed)
    }

    /// The gate's one-chain predicate between parties 0 and 1.
    fn sample(&mut self) {
        let view = |rt: &NodeRuntime<SimEndpoint>| -> HashMap<u64, BlockId> {
            rt.node()
                .dag()
                .dag_recent_view(256)
                .into_iter()
                .filter(|v| v.4)
                .map(|v| (v.2, v.0))
                .collect()
        };
        let (a, b) = (view(&self.rt(0)), view(&self.rt(1)));
        let (ta, tb) = (a.keys().max().copied().unwrap_or(0), b.keys().max().copied().unwrap_or(0));
        let floor = ta.min(tb).saturating_sub(GATE_DEPTH);
        let (mut agree, mut disagree) = (0usize, 0usize);
        for (s, ida) in &a {
            if *s > floor {
                continue;
            }
            match b.get(s) {
                Some(idb) if idb == ida => agree += 1,
                Some(_) => disagree += 1,
                None => {}
            }
        }
        self.report.samples.push(Sample { t_ms: self.now, tips: vec![ta, tb], agree, disagree });
        // PROGRESS, every sample: a run cut short still says what it measured and where the wall time went.
        let w = self.report.wall_ms;
        eprintln!(
            "[netsim-progress] t={} s tips {ta}/{tb} agree {agree} disagree {disagree} produced {:?} arrivals {} \
             (p50 {} ms) · wall ms: begin {} prove {} grind {} finish {} relay {} serve {} · hashes {} ({} h/ms of \
             grind wall time)",
            self.now / 1000,
            self.report.produced,
            self.report.arrival_ms.len(),
            self.report.pct(0.5),
            w[0],
            w[1],
            w[2],
            w[3],
            w[4],
            w[5],
            self.report.hashes,
            self.report.hashes / (w[2] as u64).max(1)
        );
    }

    /// Run for `ms` of simulated time, sampling the gate predicate every `sample_ms`.
    /// The `[mem]` cadence: one [`NetSim::mem_line`] each time the simulated clock passes the next multiple of
    /// `SIM_MEM_EVERY_S` simulated seconds (unset or 0: never), from [`NetSim::run`] — so every phase that advances the
    /// simulation (the grow phase, `run_until`, `while_meshing`, `balance_until`) is measured.
    fn mem_tick(&self) {
        static EVERY_MS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        static NEXT_MS: AtomicU64 = AtomicU64::new(0);
        let every = *EVERY_MS.get_or_init(|| {
            std::env::var("SIM_MEM_EVERY_S").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) * 1000
        });
        let next = NEXT_MS.load(Ordering::Relaxed);
        // a later simulation in the same process starts its clock at 0 again: a mark more than one period ahead is stale
        if every == 0 || (self.now < next && next - self.now <= every) {
            return;
        }
        NEXT_MS.store((self.now / every + 1) * every, Ordering::Relaxed);
        self.mem_line("tick");
    }

    pub fn run(&mut self, ms: u64, sample_ms: u64) {
        let end = self.now + ms;
        let mut next_sample = self.now + sample_ms;
        self.mem_tick();
        while self.now < end {
            // A TIME SERIES EVERY 60 SIMULATED SECONDS, so any run explains itself over time (which rate fell behind which):
            // per node — tip height, fold position (served_seq), band applied / lag, fold waits, down or up.
            if self.now % 60_000 < self.step_ms {
                let per: Vec<String> = (0..self.rts.len())
                    .map(|i| {
                        if self.is_down(i) {
                            return format!("n{i}[down]");
                        }
                        let rt = self.rt(i);
                        let n = rt.node();
                        let b = rt.band_stats();
                        format!(
                            "n{i}[tip {} fold {} band {}+{} unfolded {} · jobs {} own V/H/R {}/{}/{} relayed V/other {}/{}]",
                            n.tip_height(),
                            n.served_seq(),
                            n.band_steps_applied(),
                            n.band_lag(),
                            n.unfolded_blocks_len(),
                            b[0], b[1], b[2], b[3], b[4], b[5]
                        )
                    })
                    .collect();
                eprintln!("[sim-progress] t={} s {}", self.now / 1000, per.join(" "));
            }
            let k = self.window_steps(end, next_sample);
            self.step_window(k);
            if self.check_state && self.first_divergence.is_none() && self.now % 10_000 < self.step_ms {
                if let Some(d) = self.state_divergence() {
                    eprintln!("[sim-invariant] ⛔ t={} s: {d}", self.now / 1000);
                    self.first_divergence = Some((self.now, d));
                }
            }
            if self.now >= next_sample {
                next_sample += sample_ms;
                self.sample();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔ G2c (lane a 2026-10-23; T2 replica census `clues`, cause map scratchpad/f2-causes.tsv G2) — A CLUE KEY WHOSE ONE-SHOT
    /// GOSSIP WAS LOST STILL REACHES EVERY PEER. MEASURED on the fast-eco journey (scratchpad/night/eco-census-20261023-161849.log):
    /// `NodeRuntime::register_clue` queued its one `Clue` message at 0 live writers, nothing repaired it, and the census read
    /// the clue directory 1 vs 2 entries — a sender on the short node could not attach a detection clue for that recipient.
    /// Here the registration goes into node 0's directory with NO gossip at all (the lost message), then the mesh only runs:
    /// node 1 must resolve the key through the `ClueDigest` anti-entropy alone. A second owner with two validly signed keys,
    /// registered in opposite orders on the two nodes, must leave ONE key on both (the order-free adopt). Asserted on the
    /// PEER. On the simulated wire, not a loopback pair: a loopback reports 0 live writers by design, so no gossip runs.
    #[test]
    fn g2c_a_clue_key_whose_gossip_was_lost_converges_on_the_peer_by_anti_entropy() {
        let mut sim = NetSim::new(2, Physics::from_env(), 1);
        let reg = |clue_pk: &[u8], sk: &[u8]| {
            crate::pqauth::ml_dsa_sign(&crate::pqauth::clue_register_msg(clue_pk), sk).expect("sign")
        };
        let (pk1, sk1) = crate::pqauth::ml_dsa_keypair();
        let owner1 = crate::pqauth::pubkey_id(&pk1);
        let clue1 = vec![7u8; 96];
        let (pk2, sk2) = crate::pqauth::ml_dsa_keypair();
        let owner2 = crate::pqauth::pubkey_id(&pk2);
        let (k_x, k_y) = (vec![3u8; 64], vec![4u8; 64]);
        let low = if blake3::hash(&k_x).as_bytes() < blake3::hash(&k_y).as_bytes() { k_x.clone() } else { k_y.clone() };
        {
            let mut a = sim.rt(0);
            // owner 1 on node 0's NODE only — the gossip `NodeRuntime::register_clue` would queue never leaves
            assert_eq!(a.node_mut().register_clue(&pk1, clue1.clone(), &reg(&clue1, &sk1)), Some(true));
            assert_eq!(a.node_mut().register_clue(&pk2, k_x.clone(), &reg(&k_x, &sk2)), Some(true));
            a.node_mut().register_clue(&pk2, k_y.clone(), &reg(&k_y, &sk2));
        }
        {
            let mut b = sim.rt(1);
            assert_eq!(b.node_mut().register_clue(&pk2, k_y.clone(), &reg(&k_y, &sk2)), Some(true));
            b.node_mut().register_clue(&pk2, k_x.clone(), &reg(&k_x, &sk2));
            assert_eq!(b.node().resolve_clue(&owner1), None, "node 1 never received owner 1's registration");
        }
        // two anti-entropy periods of simulated time; no registration call on node 1
        sim.run(130_000, 10_000);
        let (d0, r0) = {
            let mut a = sim.rt(0);
            (a.node_mut().clue_digest(), a.node().resolve_clue(&owner2).map(|s| s.to_vec()))
        };
        let mut b = sim.rt(1);
        assert_eq!(b.node().resolve_clue(&owner1), Some(clue1.as_slice()), "node 1 learned the lost registration by anti-entropy");
        assert_eq!(r0.as_deref(), Some(low.as_slice()), "node 0 holds the order-free winner");
        assert_eq!(b.node().resolve_clue(&owner2), Some(low.as_slice()), "node 1 holds the same winner in the other order");
        assert_eq!(d0, b.node_mut().clue_digest(), "one clue directory on both peers");
    }

    /// G2f (lane a 2026-10-23; T2 replica census `da_tags_mem`). The record-write path (`da_store_tags` at the
    /// `record_note_payload_inner` drain) must MERGE first-write-wins, not INSERT — INSERT overwrites tags that
    /// the carried-tags or late-tag path already stored, making the row arrival-order-dependent.
    /// RED-FIRST: three credits with clues on one node; the block carries their tags. The receiver's record-write
    /// drains fewer tags (gossip timing) and must not overwrite what the carry filed. Asserted by the replica census
    /// on `da_tags_mem` — SAME across both nodes.
    /// §NETSIM-LAUNCH: the mesh's Bitcoin is ONE simulated chain on the simulated clock — a deposit funded at t = 0 is
    /// read by a node's PRODUCTION watcher path (`btc_watch::matured_and_pending`, the same call the deposit-watch thread
    /// makes) as pending at 0 confirmations and as matured once the sim clock has mined THORChain's count of blocks.
    #[test]
    fn the_mesh_reads_one_simulated_bitcoin_that_mines_on_the_simulated_clock() {
        let _serial = crate::btc_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
        let seed = 0xB7C0_2026_1027u64;
        let mut sim = NetSim::new(2, Physics::TOR_Q13, seed).with_band_double().with_sim_bitcoin(seed, 60_000);
        // The claim is the CLOCK and the production read path, not block production: no node produces (DB-402 R1's
        // quiescent switch), so the 22 simulated minutes cost seconds, not the 2,321 s a producing pair took (10/27).
        sim.produce_paused = true;
        let addr = crate::btc_tx::address_for_test_seed("bcrt", b"mesh-depositor");
        let sats = 30 * 100_000_000u64;
        let need = crate::btc_watch::required_confirmations(sats);
        assert_eq!(need, 10, "CALIBRATION: 30 BTC needs 10 confirmations");
        let tip0 = sim.btc().tip_height();
        sim.btc().fund(&addr, sats).expect("the miner wallet funds the deposit");
        let read = || crate::btc_watch::matured_and_pending(&addr).expect("the mesh has a Bitcoin source: the sim is installed");
        assert_eq!(read(), (0, sats), "at t = 0 the deposit is in the mempool: pending");
        // Run ends fall mid-interval (the window rounds the clock up by at most one step), so each tip is exact.
        sim.run(8 * 60_000 + 30_000, 10_000);
        assert_eq!(sim.btc().tip_height(), tip0 + sim.now / 60_000, "one block per simulated minute at t = {} ms", sim.now);
        assert_eq!(sim.btc().tip_height(), tip0 + 8, "8 blocks mined by t = 8.5 min");
        assert_eq!(read(), (0, sats), "at 8 confirmations the deposit is still pending");
        sim.run(2 * 60_000, 10_000);
        assert_eq!(sim.btc().tip_height(), tip0 + 10, "10 blocks mined by t = 10.5 min");
        assert_eq!(read(), (sats, 0), "⛔ at 10 confirmations the deposit is matured on the production watcher path");
        // A reorg from the deposit's block with a double-spend takes it back for every node that reads the chain.
        let txid = sim.btc().utxos(&addr).expect("utxos").into_iter().next().expect("the deposit coin").txid;
        sim.btc().invalidate_block(tip0 + 1);
        sim.btc().double_spend_funding(&txid).expect("the funding coin is double-spent at a higher fee");
        sim.run(11 * 60_000, 10_000);
        assert_eq!(read(), (0, 0), "⛔ the deposit SURVIVED a double-spend reorg on the simulated chain");
    }

    /// §NETSIM-LAUNCH: the mesh's Monero is ONE simulated chain on the simulated clock — a deposit to a swap's
    /// INTEGRATED address of a 2-of-2 custody wallet, funded at t = 0, is read by EACH custodian's PRODUCTION sweep
    /// (`xmr_watch::sweep_now`, the deposit-watch thread's own body, from the wallet `WalletRpc::from_env` hands a
    /// custody lane) as pending while Monero's lock and THORChain's count run, as matured once the sim clock has mined
    /// that count, and as gone after a reorg whose double-spend evicts the funding — and the two custodians AGREE at
    /// every step.
    /// TWO-PARTY-REVIEWED: the two parties are the two custodians' wallets, formed into one k-of-n account through
    /// the production key-exchange surface, each sweeping the same chain independently; the assertion is that both
    /// read the same figure at every step.
    #[test]
    fn the_mesh_reads_one_simulated_monero_that_mines_on_the_simulated_clock() {
        let _serial = crate::xmr_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
        let seed = 0x3E80_2026_1027u64;
        let mut sim = NetSim::new(2, Physics::TOR_Q13, seed).with_band_double().with_sim_monero(seed, 60_000);
        sim.produce_paused = true; // the claim is the CLOCK and the production read path, not block production
        let a = crate::xmr_rpc::WalletRpc::from_env().expect("the mesh has a Monero: the sim is installed");
        let b = crate::xmr_rpc::WalletRpc::from_env().expect("a second custodian's wallet on the same chain");
        // the 2-of-2 account by Monero's rounds: prepare → make → one exchange (final_round(2, 2) = 1)
        let (pa, pb) = (a.prepare_multisig().expect("prepare a"), b.prepare_multisig().expect("prepare b"));
        let (ma, mb) = (a.make_multisig(&[pb], 2, "").expect("make a"), b.make_multisig(&[pa], 2, "").expect("make b"));
        assert_eq!(a.exchange_multisig_keys(&[mb], "").expect("exchange a"), "", "a is final");
        assert_eq!(b.exchange_multisig_keys(&[ma], "").expect("exchange b"), "", "b is final");
        let main = a.address().expect("the account's address");
        assert_eq!(b.address().expect("b's address"), main, "both custodians derive the one account address");
        let pid = [0x3E, 0x80, 0x20, 0x26, 0x10, 0x27, 0x00, 0x01];
        let integrated = crate::bridge::xmr_integrated_address(&main, &pid).expect("the swap's integrated address");
        assert!(crate::xmr_watch::watch_issued_reserve(&integrated), "the production watcher takes the integrated address");
        let atomic = 12 * crate::xmr_rpc::XMR_ATOMIC_PER_XMR;
        let need = crate::xmr_watch::required_confirmations(atomic);
        assert_eq!(need, 20, "CALIBRATION: 12 XMR needs 20 confirmations (THORChain's count over the tail emission)");
        let tip0 = sim.xmr().tip_height();
        let txid = sim.xmr().fund(&integrated, atomic).expect("the miner funds the deposit");
        // each custodian's own sweep, and the two must agree
        let read = |step: &str| {
            crate::xmr_watch::sweep_now(&a).expect("custodian a's wallet answers the sweep");
            let seen_a = crate::xmr_watch::confirmed_pending_cached(&integrated).expect("a's read");
            crate::xmr_watch::sweep_now(&b).expect("custodian b's wallet answers the sweep");
            let seen_b = crate::xmr_watch::confirmed_pending_cached(&integrated).expect("b's read");
            assert_eq!(seen_a, seen_b, "⛔ the two custodians DISAGREE on the deposit {step}");
            seen_a
        };
        assert_eq!(read("at t = 0"), (0, 0), "at t = 0 the deposit is in the pool: the wallets do not report it yet");
        sim.run(60_000 + 30_000, 10_000);
        assert_eq!(sim.xmr().tip_height(), tip0 + 1, "one block per simulated minute at t = {} ms", sim.now);
        assert_eq!(read("at 1 confirmation"), (0, atomic), "at 1 confirmation the deposit is pending");
        sim.run(18 * 60_000, 10_000);
        assert_eq!(sim.xmr().tip_height(), tip0 + 19, "19 blocks mined by t = 19.5 min");
        assert_eq!(read("at 19 confirmations"), (0, atomic), "at 19 confirmations the deposit is still pending");
        sim.run(60_000, 10_000);
        assert_eq!(sim.xmr().tip_height(), tip0 + 20, "20 blocks mined by t = 20.5 min");
        assert_eq!(read("at 20 confirmations"), (atomic, 0), "⛔ at 20 confirmations the deposit is matured on the production sweep");
        // A reorg from the deposit's block with a double-spend takes it back for every custodian that reads the chain.
        sim.xmr().invalidate_block(tip0 + 1).expect("the deposit's block is on the chain");
        sim.xmr().double_spend_funding(&txid).expect("the funding is back in the pool and double-spent");
        sim.run(21 * 60_000, 10_000);
        assert_eq!(read("after the reorg"), (0, 0), "⛔ the deposit SURVIVED a double-spend reorg on the simulated Monero");
        crate::xmr_watch::retire_reserve_watch(&integrated);
    }

    #[test]
    fn g2f_the_record_write_merges_tags_so_arrival_order_cannot_overwrite_carried_tags() {
        let mut sim = NetSim::testnet(2, Physics::from_env(), 0x72F6_0001_2026_1023).with_band_double().boot_from_disk();
        sim.run(120_000, 10_000);
        assert!(sim.one_chain_between(0, 1), "CALIBRATION: the pair converges");
        for k in [0x2F01u64, 0x2F02, 0x2F03] {
            let (note, cm) = Node::test_spendable_note(k);
            let clue = vec![(k & 0xFF) as u8; 96];
            let mut rt = sim.rt(0);
            rt.node_mut().stage_credit_note(note.clone());
            rt.node_mut().stage_credit_justifier(
                crate::bridge_credit_tx::BridgeCreditTx {
                    deposit_id: cm,
                    asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
                    amount: 1_000,
                    note,
                    owner_clue: clue,
                    attestors: Vec::new(),
                }
                .wire(),
            );
        }
        sim.run(60_000, 10_000);
        let rows = sim.replica_census("g2f");
        let tags_row = rows.iter().find(|r| r.0 == "da_tags_mem");
        assert!(
            tags_row.is_some_and(|r| r.1 == "SAME"),
            "⛔ G2f: da_tags_mem DIFFERS across nodes — the record-write INSERT overwrote carried tags: {tags_row:?}"
        );
    }

    /// ⛔⛔⛔ DB-380 — ECLIPSE, RED-FIRST (adversary census: network × "eclipse: settlement shown on a private chain";
    /// user 2026-10-04 "plan for the worst"). Four parties on the simulated wire: 0 (the bootstrap origin) and 1 honest,
    /// 2 the VICTIM, 3 the ADVERSARY. After the mesh forms, every link of the victim except the adversary's is severed and
    /// the adversary's links to the honest parties too — the victim now sees only the adversary's private chain. The
    /// adversary stages a real note (a payment to the victim) that rides its next private block. MEASURED on what each of
    /// the parties HOLDS: does the victim hold that payment in its ledger while the honest parties never saw it? The
    /// design's defense — a node-local DEGRADED VIEW from the chain-quality signal and the bootstrap diversity rule
    /// (docs/DB-380-ECLIPSE-DEFENSE-SPEC.md) under which no settlement is reported — does not exist yet, so the target
    /// assertion is RED by design until it lands. The liveness arm then restores one honest circuit and requires the
    /// victim and the origin to be one chain again.
    /// The eclipse rig after its eclipse phase: the simulator, the three parties' indices and the private payment's cm.
    struct EclipseRig {
        sim: NetSim,
        origin: usize,
        victim: usize,
        cm_bytes: [u8; 32],
    }

    /// THE SHARED ECLIPSE FIXTURE (DB-380). Builds the mesh, converges it, eclipses the victim with the adversary, stages
    /// the private payment, runs the eclipse until the window turns over, and ASSERTS every calibration arm and the
    /// chain-quality verdict. Two pins stand on it: the verdict pin (the rig alone) and the recovery pin (the rig, then one
    /// honest circuit restored and the recovery timed) — two census rows, two verdicts, each honest on its own.
    fn eclipse_fixture() -> EclipseRig {
        let seed = 0xEC11_95E0_0010_1004u64;
        // MEASURED 2026-10-04 13:18 with FOUR parties: the eclipsed set is TWO producers (the victim mines too) against
        // two honest ones, so both views read the same rate (0.379 of target) and no chain-quality signal can exist by
        // construction. MEASURED 13:31 with NINE: the eclipsed set ran at 0.27 of target (2 of 9, the victim's own blocks
        // included) — just above the 1/4 floor the DAA clamp derives — and 150 s filled only 52 of the 60-sample window.
        // So: TEN parties (2 of 10 → ~0.21, inside the floor) and an eclipse long enough for the window to turn over at
        // the eclipsed set's own cadence (~one selected block per 4 s → ≥ 240 s). docs/DB-380 §4b–4c.
        // MEASURED 2026-10-04 14:03 at the production window (daa_sample_len 60, eclipse-pin4.log): the verdict fired —
        // victim `rate 0.250, degraded`, honest origin `rate 0.983, trusted` — after the window turned over, 1,469 s of
        // wall time for 420 s simulated (real PoW over ~900 blocks). The mechanism is the window turning over at the
        // eclipsed set's cadence; the simulation scales the window to 16 samples so the pin stays fast, and the production
        // time-to-fire it stands for is `daa_sample_len (60) × ~4 s ≈ 240 s`, stated in docs/DB-380 §4c.
        let mut params = crate::params::ChainParams::default();
        params.daa_sample_len = 16;
        // THE FAST-LANE MESH SHAPE (lane funds 2026-10-27): the bare `with_params` mesh never folds past blue score ~4 —
        // every relayed block lands "WITHOUT a ledger record (carried 0 byte(s))", the by-id record lane asks peers that
        // hold none, and every served bundle certifies blue_score 0/1/4 for the whole 260 s run (MEASURED
        // scratchpad/funds/eclipse-21.log: `[fold-wait-why] … 1024 pass(es) on the same block`). A bundle that certifies
        // nothing can never re-anchor the healed victim, so the recovery arm measured a mesh no node runs. Every launch
        // journey and bridge pin builds its mesh with the bound band double (`with_band_double`, 28 fixtures); so does this.
        // DETERMINISTIC (lane stable 2026-10-30): the verdict reads the chain's own difficulty and rate, so the honest mesh's
        // hash rate must be the chain's, not the host's. On the charged mesh the host's contention became simulated grind time:
        // with ten cores held by other lanes the honest mesh's difficulty fell 6.4× inside one 16-sample window and its view
        // read DEGRADED at the calibration (stable/e1.log; passing runs on the same commit read 1.07–1.45×) — the bisector's
        // "passed and failed on cd08069". The replayable mesh replays from its seed (sim_one_seed_replays_to_the_same_blocks).
        // cons: none — no assertion changed; the eclipse's own rate collapse is a property of the producers it cuts away.
        let mut sim = NetSim::with_params(10, Physics::from_env(), seed, params).with_band_double();
        sim.make_replayable();
        let (origin, victim, adversary) = (0usize, 8usize, 9usize);
        sim.run(40_000, 5_000);
        assert!(sim.one_chain_between(origin, victim), "CALIBRATION: before the eclipse the victim follows the origin's chain");
        let q0 = sim.rt(victim).node().view_quality();
        eprintln!("[eclipse] honest view before the eclipse: {q0:?}");
        assert!(!q0.degraded, "CALIBRATION: an honest, converged view is not degraded: {q0:?}");
        // THE ECLIPSE: the victim keeps only the adversary; the adversary keeps only the victim.
        sim.isolate(victim, &[adversary]);
        sim.isolate(adversary, &[victim]);
        let produced_before: Vec<u64> = sim.report.produced.clone();
        // THE PRIVATE PAYMENT: a real note (its commitment proven by the mint-validity carrier) staged on the adversary.
        let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[0xEC11u64, 0x95E0, 0x0004, 1_000]);
        let blind = usdm_decider::poseidon2_compress::lanes_of(&[0xB1u64, 0xB2, 0xB3, 0xB4]);
        let (_carrier, cm, _dc) = usdm_decider::whir_rec_block::prove_mint_validity_committed_bytes(1_000, &note_sk, &blind)
            .expect("the note's commitment proves");
        let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(cm);
        let mut note = Vec::with_capacity(crate::cover::PQ_NOTE_BYTES);
        note.extend_from_slice(&cm_bytes);
        note.resize(crate::cover::PQ_NOTE_BYTES, 0);
        sim.rt(adversary).node_mut().stage_credit_note(note);
        // long enough for the DAA window (`daa_sample_len` samples) to turn over at the eclipsed set's rate — the
        // time-to-fire the launch documentation states (DB-380 §6 d): MEASURED ~one selected block per 4 s under two
        // producers, so 16 samples need ≥ 64 s; 100 s leaves the window wholly inside the eclipse (60 samples: 240/300 s)
        sim.run(100_000, 5_000);
        let adversary_blocks: Vec<BlockId> = sim.born.iter().filter(|(_, (from, _))| *from == adversary).map(|(id, _)| *id).collect();
        let victim_holds_private_blocks = adversary_blocks.iter().filter(|id| sim.rt(victim).node().dag().contains(id)).count();
        // what the parties HOLD — the adversary, the victim and the honest origin, never what a call returned
        let on_adversary = !sim.rt(adversary).node().records_containing_cm(&cm_bytes).is_empty();
        let on_victim = !sim.rt(victim).node().records_containing_cm(&cm_bytes).is_empty();
        let on_honest = !sim.rt(origin).node().records_containing_cm(&cm_bytes).is_empty();
        eprintln!(
            "[eclipse] adversary produced {} private block(s) (victim holds {victim_holds_private_blocks}); payment recorded on: adversary {on_adversary}, \
             victim {on_victim}, honest origin {on_honest}; victim one-chain with origin now: {}; produced before/after {:?} → {:?}",
            sim.report.produced[adversary] - produced_before[adversary],
            sim.one_chain_between(origin, victim),
            produced_before,
            sim.report.produced
        );
        assert!(victim_holds_private_blocks > 0, "CALIBRATION: the eclipse delivered the adversary's private blocks to the victim");
        assert!(on_adversary, "CALIBRATION: the private payment rode the adversary's own chain");
        assert!(!on_honest, "CALIBRATION: the eclipse held — the private payment never reached the honest parties");
        // ⛔ THE DEFENSE (DB-380 §3b): the victim's own chain tells it the view is degraded — one producer's chain runs at a
        // quarter of the mesh's rate or lets its difficulty fall 4× within one window. The verdict must FIRE under the
        // eclipse; what the victim recorded is printed above as the exposure the settlement wiring (§3b, the RPC `view`
        // field) must gate. Measured time-to-fire is the launch documentation's number (DB-380 §6 d).
        let q1 = sim.rt(victim).node().view_quality();
        let honest_q = sim.rt(origin).node().view_quality();
        eprintln!("[eclipse] victim view under the eclipse: {q1:?}; honest origin's view: {honest_q:?}");
        assert!(!honest_q.degraded, "CALIBRATION: the honest origin's view stays trusted while the victim is eclipsed: {honest_q:?}");
        assert!(
            q1.degraded,
            "⛔ DB-380: an eclipsed victim holds a private-chain payment ({on_victim}) while the honest parties never saw it, and its \
             chain-quality verdict did NOT fire: {q1:?} — the view must read degraded so settlement is withheld"
        );
        EclipseRig { sim, origin, victim, cm_bytes }
    }

    /// ⭐ DB-380 — THE VERDICT (adversary census: network × "eclipse: settlement shown on a private chain"). An eclipsed
    /// victim's own chain tells it the view is degraded (`Node::view_quality`: rate ≤ 1/4 of target, within the 3σ margin of DB-380 §7, once the window has
    /// turned over) while the honest parties stay trusted — every assertion is in the fixture. MEASURED GREEN 2026-10-04
    /// 14:03 (production window, 1,469 s) and 14:19 / 14:27 (16-sample window): victim `rate 0.250, degraded`, origin
    /// `rate 0.983–1.000, trusted`.
    #[test]
    fn eclipse_a_victim_fed_only_a_private_chain_reads_its_view_degraded_while_the_honest_mesh_stays_trusted() {
        let rig = eclipse_fixture();
        assert!(rig.sim.rt(rig.victim).node().view_quality().degraded, "the fixture's verdict arm already asserted this");
        assert!(rig.sim.rt(rig.origin).node().records_containing_cm(&rig.cm_bytes).is_empty(), "the honest origin never saw the private payment");
    }

    /// ⛔ DB-380 — RECOVERY (adversary census: network × "eclipse: liveness after one honest circuit"). One honest circuit
    /// returns; the victim must be one chain with the origin again. MEASURED 2026-10-04 14:19–14:30 under the honest
    /// predicate: NOT within 40 s; at +80 s the victim's view quality was fully honest again (rate 1.19) and it was STILL
    /// not one chain — it recovers by serial by-id pulls of the eclipse-era honest blocks over the one circuit, and the
    /// certified jump (DSYNC) did not fire for a node that is merely BEHIND. The arm measures recovery in 20 s slices (the
    /// launch documentation's figure) and requires it within 120 s (relay floor 4 s × the 16-sample window × ~2); a longer
    /// recovery is a liveness finding, filed red-first in known-reds.txt until the recovery path is fixed.
    #[test]
    fn eclipse_a_victim_recovers_to_the_honest_chain_when_one_honest_circuit_returns() {
        let EclipseRig { mut sim, origin, victim, .. } = eclipse_fixture();
        sim.restore(victim, origin);
        let mut recovered_at_ms: Option<u64> = None;
        for slice in 1..=6u64 {
            sim.run(20_000, 5_000);
            let one = sim.one_chain_between(origin, victim);
            let vq = sim.rt(victim).node().view_quality();
            eprintln!("[eclipse] heal +{} s: victim one-chain with origin {one}; victim view {vq:?}", slice * 20);
            if one {
                recovered_at_ms = Some(slice * 20_000);
                break;
            }
        }
        assert!(
            recovered_at_ms.is_some(),
            "LIVENESS: one honest circuit did not restore the victim to the honest chain within 120 s — the recovery path (by-id pulls over one circuit, or the certified re-anchor) is too slow"
        );
        eprintln!("[eclipse] recovered {} s after one honest circuit returned", recovered_at_ms.unwrap_or(0) / 1000);
    }

    /// ⭐ DB-420 — THE CONSERVATIVE WINDOW HOLDS ITS LOOKAHEAD (the 24× target). A window lets each node run up to one wire
    /// leg of steps on its own thread; that is sound exactly when nothing one node sends inside a window can land inside
    /// that window (Chandy–Misra–Bryant's safety condition). The wire's census (`Wire::sent`) checks EVERY send to another
    /// node — cell, ask, follow, answer, oracle page — against the running window's last instant.
    /// The same seeded three-node mesh runs 60 simulated seconds one step at a time and then in windows. ASSERT on each:
    /// zero lookahead breaks, every node produced, blocks crossed the wire, and no peer HELD a block sooner than one leg
    /// after it was born; on the windowed run, that windows of more than one step were actually taken.
    /// CALIBRATION RED: a window twice the leg (`window_lookahead_for_test`) must be counted — the census can fail.
    /// ⛔ WHY NOT AN EXACT TRACE COMPARISON (link 26's form of this pin): MEASURED link 27 (night/sim-20261007-215726.log,
    /// sim-20261007-220545.log) — two ONE-STEP runs of one seed already differ (produced [10, 19, 7] vs [13, 19, 21]; after
    /// DB-420's seeded miner seeds the first block is still n0 at 950 ms vs 500 ms with different ids): every block carries
    /// OS randomness (the prover's per-prove blinding, DB-382; KEM encapsulations; hedged signatures), so its id, its PoW
    /// try count and its simulated grind time differ run to run. Byte-equal runs need a test-build entropy hook across
    /// three getrandom versions (OPEN).
    /// TWO-PARTY-REVIEWED: three simulated processes on one wire; the claims are what each peer HOLDS and what the wire
    /// carried.
    #[test]
    fn a_window_of_steps_never_lands_a_send_inside_the_window_it_was_sent_in() {
        let seed = 0x5157_1D0E_0026_0001u64;
        let leg = Physics::TOR_Q13.leg_ms;
        // (produced per node, arrival latencies, lookahead breaks, windows of > 1 step)
        let run = |cap: u64, lookahead: u64| -> (Vec<u64>, Vec<u64>, u64, u64) {
            let mut sim = NetSim::new(3, Physics::TOR_Q13, seed).with_band_double();
            sim.window_cap = cap;
            sim.window_lookahead_for_test = lookahead;
            sim.run(60_000, 5_000);
            eprintln!(
                "[sim-window] cap {cap} lookahead {lookahead}: produced {:?}, {} arrivals (min {:?} ms), {} window(s), {} lookahead break(s) · {}",
                sim.report.produced,
                sim.report.arrival_ms.len(),
                sim.report.arrival_ms.iter().min(),
                sim.report.windows,
                sim.lookahead_breaks(),
                speed_line()
            );
            (sim.report.produced.clone(), sim.report.arrival_ms.clone(), sim.lookahead_breaks(), sim.report.windows)
        };
        let held = |label: &str, r: &(Vec<u64>, Vec<u64>, u64, u64)| {
            assert!(r.0.iter().all(|p| *p > 0), "⛔ {label}: a node never produced: {:?}", r.0);
            assert!(!r.1.is_empty(), "⛔ {label}: no block crossed the wire");
            let fastest = r.1.iter().min().copied().unwrap_or(0);
            assert!(fastest >= leg, "⛔ {label}: a peer held a block {fastest} ms after its birth — sooner than one {leg} ms leg");
        };
        let one = run(1, 0);
        held("one-step", &one);
        assert_eq!(one.2, 0, "⛔ CALIBRATION: the one-step loop broke the lookahead {} time(s)", one.2);
        assert_eq!(one.3, 0, "CALIBRATION: the one-step loop took no window of more than one step");
        let win = run(0, 0);
        held("windowed", &win);
        assert!(win.3 > 0, "⛔ the windowed run never took a window of more than one step — nothing was measured");
        assert_eq!(win.2, 0, "⛔ DB-420: {} send(s) could land inside the window they were sent in — the window outran the wire's lookahead", win.2);
        let bad = run(0, 2 * leg / 50);
        assert!(bad.2 > 0, "⛔ CALIBRATION RED: a window twice the leg broke no lookahead — the census cannot fail");
    }

    /// ⭐⭐ DB-445 — A WOKEN FOLLOW CARRIES ITS HOST'S OWN NEW BLOCKS ONLY (docs/DB-445-FOLLOW-WAKE-PUSHES-OWN-BLOCKS.md).
    /// A held follow is rebuilt when its host's own production wakes it, from the view its follower sent when the follow
    /// ARRIVED; before DB-445 that rebuild re-sent every block other producers made meanwhile, which the follower had
    /// already taken from those producers — MEASURED link 67 (n = 8 under load, night/perf-load-20261021-045008-n8.log):
    /// 2.86 duplicate ~1 MB bodies per fresh one, 21 % of every node's inbound bytes.
    /// Four producers on the Q13 wire, the inbound census on from the first block. ASSERT, read at each FOLLOWER (what its
    /// links landed, never what a serve returned): (a) every body a woken page carried was produced by that page's host
    /// (the host's own census names it `RX_PRODUCED_HERE`); (b) the mesh is one chain. CALIBRATION: every node produced, and
    /// woken pages carried bodies (the hold-and-wake path ran). The duplicate rate is printed for the load runs to compare.
    /// TWO-PARTY-REVIEWED: four simulated processes on one wire; every claim is what a follower's links carried and what its
    /// DAG holds.
    #[test]
    fn db445_a_woken_follow_carries_only_its_hosts_own_blocks_and_the_mesh_stays_one_chain() {
        let seed = 0x0DB4_4500_2026_1021u64;
        let n = 4;
        let mut sim = NetSim::new(n, Physics::TOR_Q13, seed).with_band_double();
        sim.census_inbound();
        sim.run(90_000, 5_000);
        assert!(sim.report.produced.iter().all(|p| *p > 0), "CALIBRATION: every node produced: {:?}", sim.report.produced);
        let (mut woken, mut woken_dup, mut foreign) = (0usize, 0u64, Vec::new());
        let (mut fresh, mut dup) = (0u64, 0u64);
        for f in 0..n {
            let (bodies, d) = sim.woken_follow_bodies(f);
            woken += bodies.len();
            woken_dup += d;
            for (host, id) in bodies {
                if sim.block_landed(host, &Hash32(id)).map(|l| l.1) != Some(RX_PRODUCED_HERE) {
                    foreign.push((f, host, Hash32(id).to_hex()[..12].to_string()));
                }
            }
            let (_, b) = sim.inbound(f);
            fresh += b[0] + b[1];
            dup += b[2];
        }
        eprintln!(
            "[db445] n={n} 90 s: produced {:?} · woken follow bodies {woken} ({woken_dup} already held), {} not produced by \
             their host · follow fresh {fresh}, duplicate {dup} ({:.2} per fresh) · {}",
            sim.report.produced,
            foreign.len(),
            dup as f64 / fresh.max(1) as f64,
            speed_line()
        );
        assert!(woken > 0, "CALIBRATION: no woken follow page carried a body — the hold-and-wake path never ran");
        assert!(
            foreign.is_empty(),
            "⛔ DB-445: {} body(ies) a woken follow page carried were NOT produced by its host (follower, host, id): {:?} — \
             the rebuild re-sent other producers' blocks from the follower's stale view",
            foreign.len(),
            &foreign[..foreign.len().min(8)]
        );
        let mut one = (1..n).all(|i| sim.one_chain_between(0, i));
        for _ in 0..12 {
            if one {
                break;
            }
            sim.run(5_000, 5_000);
            one = (1..n).all(|i| sim.one_chain_between(0, i));
        }
        assert!(one, "⛔ the mesh is not one chain within 60 s of settling: produced {:?}", sim.report.produced);
    }

    /// ⭐⭐ DB-446 — A FOLLOW PAGE CARRIES ITS HOST'S OWN BLOCKS WHOLE, EVERY OTHER NEW BLOCK AS AN ID
    /// (docs/DB-446-FOLLOW-RELAYS-BY-INVENTORY.md). An ARRIVAL build shipped every body above the follower's one-leg-old
    /// view, so a block the follower was receiving from its producer at that same instant crossed again from every host
    /// that had it — MEASURED link 68 (n = 8 under load on DB-445): 1.90 / 2.05 duplicate ~1 MB bodies per fresh one.
    /// Four producers on the Q13 wire, the inbound census on from the first block, the link 0 ↔ 1 SEVERED for the whole run
    /// so each of those two producers' blocks reaches the other only through a hub. ASSERT, read at each FOLLOWER (what its
    /// links landed and what its DAG holds, never what a serve returned): (a) every body ANY follow page carried was
    /// produced by that page's host; (b) node 0 holds whole every block node 1 made in the first 60 s and node 1 every block
    /// node 0 made — before DB-446 a hub's arrival page carried them whole, after it a hub lists their ids and the follower
    /// fetches them by GETDATA; (c) the mesh is one chain. CALIBRATION: every node produced; follow pages carried bodies.
    /// Printed for the load runs to compare: follow duplicates per fresh, GETDATA/batch bodies fresh and duplicate.
    /// TWO-PARTY-REVIEWED: four simulated processes on one wire; every claim is what a follower's links carried and what its
    /// DAG holds.
    #[test]
    fn db446_a_follow_page_carries_only_its_hosts_own_bodies_and_a_severed_producer_still_reaches_every_node() {
        let seed = 0x0DB4_4600_2026_1021u64;
        let n = 4;
        let mut sim = NetSim::new(n, Physics::TOR_Q13, seed).with_band_double();
        sim.census_inbound();
        sim.sever(0, 1);
        sim.run(90_000, 5_000);
        assert!(sim.report.produced.iter().all(|p| *p > 0), "CALIBRATION: every node produced: {:?}", sim.report.produced);
        let (mut carried, mut relayed) = (0usize, Vec::new());
        let (mut fresh, mut dup, mut got_fresh, mut got_dup) = (0u64, 0u64, 0u64, 0u64);
        for f in 0..n {
            for (host, id) in sim.follow_bodies(f) {
                carried += 1;
                if sim.block_landed(host, &Hash32(id)).map(|l| l.1) != Some(RX_PRODUCED_HERE) {
                    relayed.push((f, host, Hash32(id).to_hex()[..12].to_string()));
                }
            }
            let (_, b) = sim.inbound(f);
            fresh += b[0] + b[1];
            dup += b[2];
            got_fresh += b[3] + b[4];
            got_dup += b[5];
        }
        // (b) read now: every block one severed producer made in the first 60 s, held whole by the other
        let missing = |holder: usize, maker: usize| -> Vec<String> {
            let made: Vec<Hash32> = sim.produced_blocks(maker).into_iter().filter(|(t, _)| *t <= 60_000).map(|(_, id)| id).collect();
            let rt = sim.rt(holder);
            made.into_iter()
                .filter(|id| !(rt.node().dag().contains(id) && !rt.node().holds_only_a_shell(id)))
                .map(|id| id.to_hex()[..12].to_string())
                .collect()
        };
        let (miss_0, miss_1) = (missing(0, 1), missing(1, 0));
        eprintln!(
            "[db446] n={n} 90 s, 0↔1 severed: produced {:?} · follow bodies {carried}, {} not produced by their host · follow \
             fresh {fresh}, duplicate {dup} ({:.2} per fresh) · GETDATA/batch fresh {got_fresh}, duplicate {got_dup} · node 0 \
             lacks {} of node 1's first-60 s blocks, node 1 lacks {} of node 0's · {}",
            sim.report.produced,
            relayed.len(),
            dup as f64 / fresh.max(1) as f64,
            miss_0.len(),
            miss_1.len(),
            speed_line()
        );
        eprintln!("[db446] duplicate sources (dup lane ← first copy): {}", sim.dup_sources_line());
        assert!(carried > 0, "CALIBRATION: no follow page carried a body");
        assert!(
            relayed.is_empty(),
            "⛔ DB-446: {} body(ies) a follow page carried were NOT produced by its host (follower, host, id): {:?} — a relayed \
             block crossed whole where its id would do",
            relayed.len(),
            &relayed[..relayed.len().min(8)]
        );
        assert!(
            miss_0.is_empty() && miss_1.is_empty(),
            "⛔ DB-446: across the severed link 0 ↔ 1, node 0 lacks {:?} of node 1's blocks and node 1 lacks {:?} of node 0's \
             after 30 s — a hub's listed id never became a body",
            miss_0,
            miss_1
        );
        let mut one = (1..n).all(|i| sim.one_chain_between(0, i));
        for _ in 0..12 {
            if one {
                break;
            }
            sim.run(5_000, 5_000);
            one = (1..n).all(|i| sim.one_chain_between(0, i));
        }
        assert!(one, "⛔ the mesh is not one chain within 60 s of settling: produced {:?}", sim.report.produced);
    }

    /// ⭐⭐ DB-447 — A FOLLOWER NEVER GETS ITS HOST'S BLOCK TWICE FROM THAT HOST (docs/DB-447-ASK-NAMES-BODIES-IN-THE-VERIFIER.md).
    /// A follow page hands the host's block X to the follower's verifier and the follower re-follows at once; its ask named
    /// held-whole blocks only (DB-254), X was not in its DAG yet, and the host's arrival build shipped X again — MEASURED
    /// link 69 (n = 8 under load on DB-446): 1,532 follow-arrival duplicates whose first copy came from the SAME host, nearly
    /// every remaining follow duplicate. Four producers on the Q13 wire, the inbound census on from the first block, 90 s.
    /// ASSERT, read at each follower's links (what landed, never what a serve returned): no follow page — arrival or woken —
    /// carried a body whose first copy had come on a follow page from that same host. The bound is 0, derived from the
    /// order: a follow answer's bodies are taken in by the follower's relay tick BEFORE that tick builds its next follow ask
    /// (the endpoint's due answers are drained first), so the next ask already names every body the page handed to the
    /// verifier, inside the 30 s re-arm window, until it grafts (have tail) or parks (parked tail). Also: (b) the mesh is one
    /// chain. CALIBRATION: every node produced; follow pages carried bodies. Printed: every duplicate-source cell, follow
    /// fresh and duplicate bodies.
    /// TWO-PARTY-REVIEWED: four simulated processes on one wire; the claim is what each follower's links carried.
    /// ⭐⭐ DB-450 — ON THE SIMULATED WIRE, A RE-ASK ANSWERED `notfound` MOVES TO THE NEXT HOST UNTIL EVERY HOST WAS ASKED
    /// (arti's DB-348, by its own rule: Bitcoin Core `TxRequestTracker`, NOTFOUND → next candidate). MEASURED why (link 73,
    /// db448 sim pin RED 2 of 6, night/link73-final-db448_.log): node 3 alone held its first block's record and nodes 0–2
    /// each re-sent one stable by-record-id ask onto a non-holder 6,046–6,048 times; their folds never left ordinal 1 in
    /// 1,281 simulated s, where a daemon's second ask goes to the next host.
    /// The ask leaves through node 0's endpoint door (`bulk_raw_request`), its host answers through the PRODUCTION serve
    /// (`serve_notes_req_bytes`: a node holding none of the ids answers its tagged 32-byte `notfound`), and node 0 takes the
    /// answer through its endpoint (`take_bulk_responses`). CALIBRATION: with no answer taken, the same bytes name the same
    /// host every time (what the pre-DB-450 wire did forever). RED with `Wire::note_answer` disabled: the second ask goes
    /// back to the host that just answered `notfound`.
    #[test]
    fn db450_a_re_ask_answered_notfound_moves_to_the_next_host_until_every_host_was_asked() {
        let sim = NetSim::new(4, Physics::TOR_Q13, 0x0DB4_5000_2026_1021);
        let w = sim.wire.clone();
        let ep = SimEndpoint { wire: w.clone(), me: 0 };
        let mut req = vec![2u8]; // by-RECORD-ID, two addresses no node holds
        for r in [u64::MAX - 7, u64::MAX - 9] {
            req.extend_from_slice(&r.to_le_bytes());
        }
        let first = w.host_for(0, &req).expect("node 0 reaches three hosts");
        for _ in 0..8 {
            assert_eq!(w.host_for(0, &req), Some(first), "CALIBRATION: with no answer taken the same ask names the same host");
        }
        // one ask through the doors: sent, served by its host's production serve, taken back by node 0
        let mut now = 0u64;
        let ask_once = |now: &mut u64| -> (usize, Vec<Vec<u8>>) {
            let host = w.host_for(0, &req).expect("a host");
            assert!(ep.bulk_raw_request(&req), "the endpoint sends the ask");
            *now += 10_000;
            let mut out = WindowOut::default();
            serve_due_asks(&w, &sim.rts[host], host, *now, &mut out);
            *now += 10_000;
            w.clocks[0].store(*now, Ordering::Relaxed);
            (host, ep.take_bulk_responses(16))
        };
        let mut asked = Vec::new();
        for round in 0..3 {
            let (host, pages) = ask_once(&mut now);
            assert_eq!(pages.len(), 1, "round {round}: node 0 takes exactly the one answer");
            assert!(
                pages[0].len() == 32 && crate::node_runtime::bulk_answer_carries_nothing(&req, Some(&pages[0])),
                "CALIBRATION round {round}: host {host} answers the tagged notfound ({} byte(s))",
                pages[0].len()
            );
            assert!(!asked.contains(&host), "⛔ DB-450: round {round} asked host {host} again after its notfound (asked {asked:?})");
            asked.push(host);
        }
        asked.sort_unstable();
        assert_eq!(asked, vec![1, 2, 3], "⛔ DB-450: three notfounds did not reach every host");
        // every host tried: the round starts again (a record may have reached a peer since) and the memory of the ask is gone
        assert_eq!(w.host_for(0, &req), Some(first), "every host tried → the next pick starts the round again");
        let key = crate::arti_transport::bulk_rotation_key(&req);
        assert!(w.notfound[0].lock().unwrap().iter().all(|(k, _)| *k != key), "the restarted round keeps no tried host");
        // a page clears the ask; a restart forgets the process's memory (arti's set is process-wide)
        w.note_answer(0, &key, first, true);
        assert_ne!(w.host_for(0, &req), Some(first), "a noted notfound moves the next pick");
        w.note_answer(0, &key, 2, false);
        assert_eq!(w.host_for(0, &req), Some(first), "a page clears every tried host of the ask");
        w.note_answer(0, &key, first, true);
        sim.drop_traffic_of(0);
        assert_eq!(w.host_for(0, &req), Some(first), "a restarted process remembers no notfound");
        // DB-348 §4: a wallet's commitment ask (kind 3) never rotates — it would hand that which-item ask to every peer
        let mut by_cm = vec![3u8];
        by_cm.extend_from_slice(&[7u8; 32]);
        let cm_host = w.host_for(0, &by_cm).expect("a host");
        w.note_answer(0, &crate::arti_transport::bulk_rotation_key(&by_cm), cm_host, true);
        assert_eq!(w.host_for(0, &by_cm), Some(cm_host), "⛔ DB-348 §4: a kind-3 ask rotated to another peer");
        eprintln!("[db450] node 0 asked hosts {asked:?} for one ask answered notfound by each; first pick {first}");
    }

    #[test]
    fn db447_a_follower_never_receives_its_hosts_block_twice_from_that_host() {
        let seed = 0x0DB4_4700_2026_1021u64;
        let n = 4;
        let mut sim = NetSim::new(n, Physics::TOR_Q13, seed).with_band_double();
        sim.census_inbound();
        sim.run(90_000, 5_000);
        assert!(sim.report.produced.iter().all(|p| *p > 0), "CALIBRATION: every node produced: {:?}", sim.report.produced);
        let (mut carried, mut fresh, mut dup) = (0usize, 0u64, 0u64);
        let mut same_host = Vec::new();
        for f in 0..n {
            carried += sim.follow_bodies(f).len();
            let (_, b) = sim.inbound(f);
            fresh += b[0] + b[1];
            dup += b[2];
            let d = sim.dup_sources(f);
            same_host.push((f, d[0][0], d[1][0]));
        }
        eprintln!(
            "[db447] n={n} 90 s: produced {:?} · follow bodies {carried}, fresh {fresh}, duplicate {dup} ({:.2} per fresh) · per \
             follower (woken ← same host, arrival ← same host) {:?} · {}",
            sim.report.produced,
            dup as f64 / fresh.max(1) as f64,
            same_host,
            speed_line()
        );
        eprintln!("[db447] duplicate sources (dup lane ← first copy): {}", sim.dup_sources_line());
        assert!(carried > 0, "CALIBRATION: no follow page carried a body");
        let total: u64 = same_host.iter().map(|(_, w, a)| w + a).sum();
        assert_eq!(
            total, 0,
            "⛔ DB-447: {total} follow body(ies) re-crossed from the host that had already sent them on a follow page \
             (follower, woken, arrival): {same_host:?} — the follower's ask did not name a body in its verifier"
        );
        let mut one = (1..n).all(|i| sim.one_chain_between(0, i));
        for _ in 0..12 {
            if one {
                break;
            }
            sim.run(5_000, 5_000);
            one = (1..n).all(|i| sim.one_chain_between(0, i));
        }
        assert!(one, "⛔ the mesh is not one chain within 60 s of settling: produced {:?}", sim.report.produced);
    }

    /// ⭐ THE PROVE GATE, CALIBRATED BOTH WAYS (link 73): a producer's prove is charged the time it takes ALONE, whatever
    /// other simulated nodes prove at that instant. A CPU burn split across every core of the host stands in for a template
    /// prove (the WHIR prover's rayon pool spans the host's cores). CALIBRATION: four burns started at once and timed around the
    /// call — the charge before the gate — each take far longer than one alone (the defect is real on this host); through
    /// [`prove_alone`] each is charged within half of the solo time. The bounds are derived, not tuned: four jobs on one pool
    /// take ~4× each when they overlap, so 2× is half that effect; the gate leaves only host noise, held under 1.5×.
    #[test]
    fn perf_tier_a_prove_is_charged_its_solo_time_whatever_other_simulated_nodes_prove_meanwhile() {
        fn burn() -> u64 {
            let cores = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get) as u64;
            std::thread::scope(|sc| {
                let hs: Vec<_> = (0..cores)
                    .map(|k| {
                        sc.spawn(move || {
                            let mut x = k ^ 0x9e37_79b9_7f4a_7c15;
                            for _ in 0..(1_500_000_000 / cores) {
                                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                            }
                            x
                        })
                    })
                    .collect();
                hs.into_iter().fold(0, |a, h| a ^ h.join().expect("a burn worker"))
            })
        }
        let four = |gated: bool| -> Vec<u64> {
            std::thread::scope(|sc| {
                let hs: Vec<_> = (0..4)
                    .map(|_| {
                        sc.spawn(move || {
                            if gated {
                                prove_alone(burn).1
                            } else {
                                let t = std::time::Instant::now();
                                std::hint::black_box(burn());
                                t.elapsed().as_millis() as u64
                            }
                        })
                    })
                    .collect();
                hs.into_iter().map(|h| h.join().expect("a burn thread")).collect()
            })
        };
        let solo = prove_alone(burn).1.max(1);
        let ungated = four(false);
        let gated = four(true);
        eprintln!("[prove-gate] solo {solo} ms · four at once, timed around the call {ungated:?} ms · through the gate {gated:?} ms");
        assert!(
            ungated.iter().any(|&ms| ms >= 2 * solo),
            "CALIBRATION: four overlapping proves on one pool should each take far longer than one alone ({ungated:?} vs {solo} ms) — \
             else this host cannot show the defect"
        );
        assert!(
            gated.iter().all(|&ms| 2 * ms <= 3 * solo),
            "⛔ a prove was charged more than 1.5× its solo time ({gated:?} vs {solo} ms): another simulated node's prove shared its pool"
        );
    }

    /// ⭐ PERF TIER step 1 — NODE CPU IS CHARGED (docs/PERF-TIER-UX-METRICS-20261007.md, step 1's pin, calibration both
    /// ways). Two daemons on the Q13 wire with CPU charging on; node 1's relay tick is charged an extra 2 ms in one run and
    /// 2,000 ms in the other ([`NetSim::lock_tax_ms`]). A node whose lock work costs seconds must FOLLOW its peer measurably
    /// slower — its peer's blocks land in ITS DAG later — than one whose work costs milliseconds; before this step the
    /// simulated clock never advanced while a node computed, so both runs read the same. The bound is derived, not tuned:
    /// with a 2 s hold per tick, a page that arrives waits on average half a hold (1 s) for the lock, so the p50 must move
    /// by at least half of that (500 ms). Also: the honest work's own measured CPU is charged (non-zero on both nodes), and
    /// sends made mid-step (which leave after the CPU spent before them) never land inside their window.
    /// TWO-PARTY-REVIEWED: two simulated processes on one wire; the claim is what the follower's DAG HOLDS and when.
    #[test]
    fn perf_tier_a_node_whose_lock_work_costs_seconds_follows_its_peer_slower_than_one_at_milliseconds() {
        let seed = 0x9E2F_0001_2026_1008u64;
        // (arrival p50 at node 1 of node 0's blocks, arrivals at node 1, lock CPU charged per node µs, lookahead breaks)
        let run = |tax_ms: u64, charge: bool| -> (u64, usize, Vec<u64>, u64) {
            let mut sim = NetSim::new(2, Physics::TOR_Q13, seed).with_band_double();
            sim.charge_cpu = charge;
            sim.lock_tax_ms = vec![0, tax_ms];
            sim.run(90_000, 5_000);
            let r = &sim.report;
            eprintln!(
                "[perf-step1] charge {charge}, node 1 taxed {tax_ms} ms per relay tick: produced {:?}; arrivals at n0 {} (p50 {} ms) at \
                 n1 {} (p50 {} ms, p90 {} ms); lock CPU charged {:?} µs; lookahead breaks {} · {}",
                r.produced,
                r.arrival_ms_at[0].len(),
                r.pct_at(0, 0.5),
                r.arrival_ms_at[1].len(),
                r.pct_at(1, 0.5),
                r.pct_at(1, 0.9),
                r.lock_cpu_us,
                sim.lookahead_breaks(),
                speed_line()
            );
            (r.pct_at(1, 0.5), r.arrival_ms_at[1].len(), r.lock_cpu_us.clone(), sim.lookahead_breaks())
        };
        let light = run(2, true);
        let heavy = run(2_000, true);
        // the other way: the same 2 s with nothing charged (the simulator before this step) leaves the follower as it was
        let uncharged = run(2_000, false);
        assert!(
            uncharged.0 < heavy.0,
            "CALIBRATION: uncharged, the 2 s node followed at p50 {} ms — no faster than charged ({} ms): the slowdown is not \
             the charge's",
            uncharged.0,
            heavy.0
        );
        for (label, r) in [("2 ms", &light), ("2 s", &heavy)] {
            assert!(r.1 > 0, "CALIBRATION ({label}): node 0's blocks reached node 1 — the run measured something");
            assert_eq!(r.3, 0, "⛔ ({label}): {} charged send(s) landed inside the window they were sent in", r.3);
        }
        assert!(
            light.2.iter().all(|us| *us > 0),
            "⛔ the honest work's measured CPU was never charged ({:?} µs) — only the synthetic tax moves the clock",
            light.2
        );
        assert!(
            heavy.0 >= light.0 + 500,
            "⛔ PERF TIER step 1: a node whose lock work costs 2 s per tick followed its peer at p50 {} ms, no slower than one at \
             2 ms ({} ms) — node CPU is not charged to the simulated clock",
            heavy.0,
            light.0
        );
    }

    /// A real note (its commitment proven by the mint-validity carrier) — the eclipse fixture's payment shape — keyed by
    /// `seed` so two payments in one run differ. Returns the note and its commitment.
    fn sim_payment(seed: u64) -> (Vec<u8>, [u8; 32]) {
        let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[0x9A27u64, seed, 0x0004, 1_000]);
        let blind = usdm_decider::poseidon2_compress::lanes_of(&[0xC1u64, seed, 0xC3, 0xC4]);
        let (_carrier, cm, _dc) = usdm_decider::whir_rec_block::prove_mint_validity_committed_bytes(1_000, &note_sk, &blind)
            .expect("the note's commitment proves");
        let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(cm);
        let mut note = Vec::with_capacity(crate::cover::PQ_NOTE_BYTES);
        note.extend_from_slice(&cm_bytes);
        note.resize(crate::cover::PQ_NOTE_BYTES, 0);
        (note, cm_bytes)
    }

    /// ⛔ DB-380 §4 pin 3 — PARTITION AND HEAL (adversary census: network × "partition"). Six parties at the relay floor
    /// (4 s per producer, the 16-sample window the eclipse pins use); the mesh converges, then splits 4 / 2 (67 / 33 % of
    /// production). Each side carries a payment (a real note) while split. The heavier side runs until its payment holds
    /// k ≥ 8 confirmations; then the partition HEALS. ASSERT: the mesh returns to ONE DAG (every pair one chain) within
    /// 120 s (relay floor × the window × ~2, the eclipse recovery figure), and the heavier side's confirmed payment is held
    /// by EVERY party — none lost. MEASURED and printed for the launch documentation: the time to one DAG, the
    /// confirmations at heal, and where the LIGHTER side's payment ended up (a block-DAG merges both halves, so it may
    /// survive; that is reported, not asserted). Every claim is what the parties HOLD.
    #[test]
    fn a_partition_heals_into_one_dag_and_no_payment_past_k_confirmations_in_the_heavier_half_is_lost() {
        let seed = 0x9A27_1710_0004_0003u64;
        let mut params = crate::params::ChainParams::default();
        params.daa_sample_len = 16;
        let mut sim = NetSim::with_params(6, Physics::from_env(), seed, params);
        let (heavy, light): ([usize; 4], [usize; 2]) = ([0, 1, 2, 3], [4, 5]);
        sim.run(40_000, 5_000);
        assert!(
            (1..6).all(|p| sim.one_chain_between(0, p)),
            "CALIBRATION: before the partition every party follows one chain"
        );
        sim.partition(&light);
        let (pay_heavy, cm_heavy) = sim_payment(1);
        let (pay_light, cm_light) = sim_payment(2);
        let score_at_split = sim.rt(heavy[0]).node().tip_height();
        sim.rt(heavy[1]).node_mut().stage_credit_note(pay_heavy);
        sim.rt(light[0]).node_mut().stage_credit_note(pay_light);
        sim.run(60_000, 5_000);
        let holds = |sim: &NetSim, p: usize, cm: &[u8; 32]| !sim.rt(p).node().records_containing_cm(cm).is_empty();
        let heavy_tip = sim.rt(heavy[0]).node().tip_height();
        let confirmations = heavy_tip.saturating_sub(score_at_split + 1);
        eprintln!(
            "[partition] split 4/2 for 60 s: heavy tip {heavy_tip} (split at {score_at_split}, ~{confirmations} confirmations); \
             heavy payment held by heavy side {:?}, by light side {:?}; light payment held by light side {:?}; produced {:?}",
            heavy.iter().map(|&p| holds(&sim, p, &cm_heavy)).collect::<Vec<_>>(),
            light.iter().map(|&p| holds(&sim, p, &cm_heavy)).collect::<Vec<_>>(),
            light.iter().map(|&p| holds(&sim, p, &cm_light)).collect::<Vec<_>>(),
            sim.report.produced
        );
        assert!(heavy.iter().all(|&p| holds(&sim, p, &cm_heavy)), "CALIBRATION: the heavier side carried its payment to all of its parties");
        assert!(light.iter().all(|&p| !holds(&sim, p, &cm_heavy)), "CALIBRATION: the partition held — the light side never saw the heavy payment");
        assert!(confirmations >= 8, "CALIBRATION: the heavy payment is past k = 8 confirmations before the heal (got ~{confirmations})");
        sim.heal(&light);
        let mut one_dag_at_s: Option<u64> = None;
        for slice in 1..=6u64 {
            sim.run(20_000, 5_000);
            let one = (1..6).all(|p| sim.one_chain_between(0, p));
            eprintln!("[partition] heal +{} s: one DAG across all six parties: {one}", slice * 20);
            if one {
                one_dag_at_s = Some(slice * 20);
                break;
            }
        }
        // MEASURED 2026-10-04 batch 5: at the first one-DAG sample (+20 s) the light side did NOT yet hold the heavy payment
        // (records [T,T,T,T,F,F]) — it follows the selected chain before it has grafted and folded the ~63 heavy blocks of the
        // split. So the HOLD is measured on its own clock, inside the same 120 s liveness bound the one-DAG arm states.
        let mut heavy_everywhere_at_s: Option<u64> = None;
        let mut elapsed = one_dag_at_s.unwrap_or(120);
        loop {
            if (0..6).all(|p| holds(&sim, p, &cm_heavy)) {
                heavy_everywhere_at_s = Some(elapsed);
                break;
            }
            if elapsed >= 120 {
                break;
            }
            sim.run(20_000, 5_000);
            elapsed += 20;
        }
        let heavy_everywhere: Vec<bool> = (0..6).map(|p| holds(&sim, p, &cm_heavy)).collect();
        let light_everywhere: Vec<bool> = (0..6).map(|p| holds(&sim, p, &cm_light)).collect();
        let accs: Vec<crate::spend_frontier::Digest4> = (0..6).map(|p| sim.rt(p).node().membership_acc()).collect();
        let one_ledger = accs.iter().all(|a| *a == accs[0]);
        eprintln!(
            "[partition] MEASURED: one DAG {:?} s after the heal; the heavy (k ≥ 8) payment held by every party at {:?} s ({heavy_everywhere:?}); \
             the LIGHT payment held by {light_everywhere:?}; one membership accumulator across all six: {one_ledger}",
            one_dag_at_s, heavy_everywhere_at_s
        );
        assert!(one_dag_at_s.is_some(), "LIVENESS: a healed 4/2 partition did not return to one DAG within 120 s");
        assert!(
            heavy_everywhere_at_s.is_some(),
            "⛔ PARTITION: 120 s after the heal a payment past k = 8 confirmations on the heavier half is still not held by every party: {heavy_everywhere:?}"
        );
        assert!(one_ledger, "⛔ PARTITION: after the heal the six parties hold different membership accumulators — two ledgers on one DAG: {accs:?}");
    }

    /// ⭐ CALIBRATION FIRST: does the simulator reproduce gate Q13 before any fix is judged on it?
    ///
    /// Q13 measured 279 of 280 relayed blocks arriving as orphans at 5 s median and 13 s p90, and the pair NEVER one
    /// chain for seven minutes (20 of 20 common selected scores disagreeing). This runs two daemons at the Q13 wire
    /// physics for one simulated minute and prints the same quantities (a progress line every sample, so a run cut
    /// short still reports). MEASURED first: five simulated minutes did not finish in 30 wall minutes. It asserts only that the run is
    /// meaningful (both produced, blocks crossed). The reproduction verdict is read from the numbers and recorded,
    /// because a calibration that is asserted into passing calibrates nothing.
    #[test]
    #[ignore = "instrument: one simulated minute of two daemons; run with --ignored --nocapture"]
    fn netsim_calibration_two_producers_at_the_q13_wire() {
        let seed = std::env::var("NETSIM_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1u64);
        let wall = std::time::Instant::now();
        // NETSIM_NODES (default 2): the frontier question "does a THIRD producer's unbiased view break the pair's
        // symmetric lineages at the 500 ms target?" is answered by the same instrument with n = 3, 4. The
        // one-chain predicate still reads parties 0 and 1.
        let nodes = std::env::var("NETSIM_NODES").ok().and_then(|s| s.parse().ok()).unwrap_or(2usize).clamp(2, 8);
        let mut sim = NetSim::new(nodes, Physics::from_env(), seed);
        sim.produce_every_ms = std::env::var("NETSIM_PRODUCE_EVERY_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        // NETSIM_SIM_MS (default one simulated minute): a 4 s per-node floor makes ~15 blocks a minute, so the
        // one-chain predicate below `min(tip) - 8` needs a longer run to have scores to compare.
        sim.run(std::env::var("NETSIM_SIM_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(60_000), 5_000);
        let r = &sim.report;
        let last = r.samples.last().cloned();
        eprintln!(
            "[netsim] seed {seed}: produced {:?}; arrivals {} (p50 {} ms, p90 {} ms, max {} ms), never arrived {}; \
             one-chain in {:.0}% of samples; last sample {:?}; wall {} ms",
            r.produced,
            r.arrival_ms.len(),
            r.pct(0.5),
            r.pct(0.9),
            r.pct(1.0),
            r.never_arrived,
            100.0 * r.one_chain_fraction(),
            last,
            wall.elapsed().as_millis()
        );
        assert!(r.produced.iter().all(|&p| p > 0), "⛔ a daemon never produced: the run measured nothing");
        assert!(!r.arrival_ms.is_empty(), "⛔ no block ever crossed the wire: the run measured nothing");
    }

    /// ⭐ THE DB-326 QUESTION, ASKED BEFORE DB-326 IS BUILT: with every block reaching its peer ONE leg after birth
    /// (the best a follow long-poll can do), is the pair one chain? Same wire, same seed and same length as the
    /// calibration; the only change is the oracle delivery.
    #[test]
    #[ignore = "instrument: one simulated minute of two daemons; run with --ignored --nocapture"]
    fn netsim_oracle_one_leg_delivery_at_the_q13_wire() {
        let seed = std::env::var("NETSIM_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1u64);
        let wall = std::time::Instant::now();
        let mut sim = NetSim::new(2, Physics::from_env(), seed);
        sim.produce_every_ms = std::env::var("NETSIM_PRODUCE_EVERY_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        sim.oracle_push = true;
        // NETSIM_SIM_MS (default one simulated minute): a 4 s per-node floor makes ~15 blocks a minute, so the
        // one-chain predicate below `min(tip) - 8` needs a longer run to have scores to compare.
        sim.run(std::env::var("NETSIM_SIM_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(60_000), 5_000);
        let r = &sim.report;
        eprintln!(
            "[netsim-oracle] seed {seed}: produced {:?}; arrivals {} (p50 {} ms, p90 {} ms, max {} ms), never arrived \
             {}; one-chain in {:.0}% of samples; last sample {:?}; wall {} ms",
            r.produced,
            r.arrival_ms.len(),
            r.pct(0.5),
            r.pct(0.9),
            r.pct(1.0),
            r.never_arrived,
            100.0 * r.one_chain_fraction(),
            r.samples.last(),
            wall.elapsed().as_millis()
        );
        assert!(r.produced.iter().all(|&p| p > 0), "⛔ a daemon never produced: the run measured nothing");
    }

    /// ⛔ DB-347's RED-FIRST PIN (docs/DB-347-BROADCAST-FANOUT-COLLAPSES-THE-PACED-LANE-AT-FIVE-NODES.md): per-node real
    /// UPLOAD must not grow with peer count (the scale standard). MEASURED on five real daemons (slot B17b): the fan-out
    /// writes every real cell to every writer, and upload demand outran the Tor links, so a minted note's record never
    /// arrived. Here the same runtimes run at n = 2 and n = 5 for the same simulated time, and each node's real-cell
    /// copies per simulated second are compared. The bound is DERIVED, not tuned: a broadcast fan-out multiplies upload
    /// by (n − 1), so 5 against 2 is ≈ 4×; a bounded-degree gossip keeps it ≈ 1–2×; the pin fails above the 2× midpoint.
    #[test]
    #[ignore = "instrument: one simulated minute at n = 2 and at n = 5; run with --ignored --nocapture"]
    fn db347_per_node_real_upload_does_not_grow_with_peer_count() {
        let seed = std::env::var("NETSIM_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1u64);
        let sim_ms: u64 = std::env::var("NETSIM_SIM_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(60_000);
        let per_node_per_s = |n: usize| -> (f64, Vec<u64>, Vec<u64>) {
            let mut sim = NetSim::new(n, Physics::from_env(), seed);
            sim.run(sim_ms, 5_000);
            let sent = sim.sent_real_cells();
            let mean = sent.iter().sum::<u64>() as f64 / n as f64 / (sim_ms as f64 / 1000.0);
            (mean, sent, sim.report.produced.clone())
        };
        let (two, sent2, prod2) = per_node_per_s(2);
        let (five, sent5, prod5) = per_node_per_s(5);
        eprintln!(
            "[db347] per-node real-cell upload: n=2 {two:.1}/s (sent {sent2:?}, produced {prod2:?}); n=5 {five:.1}/s \
             (sent {sent5:?}, produced {prod5:?}); ratio {:.2}×",
            if two > 0.0 { five / two } else { f64::INFINITY }
        );
        assert!(two > 0.0 && prod2.iter().all(|&p| p > 0), "⛔ the n = 2 run sent or produced nothing: it measured nothing");
        assert!(
            five <= two * 2.0,
            "⛔ DB-347: per-node real upload grew {:.2}× from 2 to 5 nodes ({two:.1}/s → {five:.1}/s) — the (n − 1) broadcast \
             fan-out, not a bounded degree",
            five / two
        );
    }
}

/// ⭐⭐ PERF TIER step 2 (docs/PERF-TIER-UX-METRICS-20261007.md, user 2026-10-07: *"add the performance metric so we can have
/// real numbers on how the user experience will be"*) — THE USER-EXPERIENCE ROWS the journeys print.
///
/// One line per measurement: `[perf-row] metric \t value \t unit \t target \t PASS|MISS|REPORT \t clock \t run`.
/// - `value` is what the USER waits for, in the row's unit. A row with no pillar target (a term breakdown, a figure P14
///   judges for flatness) is `REPORT`, never a PASS it did not earn.
/// - `clock` says which clock measured it and how precisely: the wallet's own compute is WALL time on this machine; every
///   chain wait is SIMULATED time with node CPU charged (step 1). A chain wait read through a wallet poll is bounded by one
///   poll, and the row says so.
/// - `run` names the lane and seed.
/// The node writes no file: `scratchpad/sim_ledgers.py` reads the rows out of the run's log (step 4).
pub mod perf {
    use std::cell::RefCell;

    thread_local! {
        static RUN: RefCell<String> = const { RefCell::new(String::new()) };
        /// Wall seconds of every wallet `refresh` + `balance` this run made (P5).
        static REFRESH_WALL_S: RefCell<Vec<f64>> = const { RefCell::new(Vec::new()) };
        /// Every row this run printed (metric, value, unit, resolution) — what P14 compares across two heights.
        static ROWS: RefCell<Vec<(String, f64, String, f64)>> = const { RefCell::new(Vec::new()) };
    }

    /// Name this thread's run (`lane seed 0x…`) and clear its refresh samples and rows.
    pub fn begin(lane: &str, seed: u64) {
        RUN.with(|r| *r.borrow_mut() = format!("{lane} seed {seed:#x}"));
        REFRESH_WALL_S.with(|v| v.borrow_mut().clear());
        ROWS.with(|v| v.borrow_mut().clear());
    }

    /// This run's rows so far (metric, value, unit, resolution).
    #[must_use]
    pub fn rows() -> Vec<(String, f64, String, f64)> {
        ROWS.with(|v| v.borrow().clone())
    }

    /// ⭐ P14 FLATNESS — the rows two runs of the same journey printed at two heights (`lo` at `lo_h`, `hi` at `hi_h`). A
    /// row is FLAT when its value at the higher height is at most TWICE its value at the lower one plus the row's
    /// resolution: the tier's own knee rule (P10: "until p95 P2 doubles") is its noise line, and at 10× the height a term
    /// linear in height shows as ~10× (two scales tell a constant from a slope). Resolution: a simulated wait is read
    /// through the journey's poll loop, which advances the clock in 500 ms runs (`sim.run(500, …)`), so 0.5 s; a block
    /// count, one block; bytes, none. A WAIT READ THROUGH A WALLET POLL is known only to that poll: its value is the END of
    /// the poll that saw it, so the true wait lies up to one poll below it, and the row carries that poll as its resolution
    /// ([`row_within`]); the higher run's resolution is added, so a row is called GREW only when even its lowest possible
    /// value is past the 2× line (MEASURED link 37: one poll at height 1 k spans 22–220 simulated s, so a 0.5 s line would
    /// call quantization growth). A row only one run printed is listed, never judged.
    /// TWO SHAPES ARE NOT JUDGED ACROSS HEIGHTS, by construction of what they measure:
    /// - a `× bound` row (a BOUNDED store's held span against its protocol bound, P12's block window) is judged against its
    ///   own ≤ 1 at EACH height — a store that fills toward a constant bound grows between two heights below it, and two
    ///   heights can tell its constant from a slope only past it; a value over 1 is listed with the rows that grew;
    /// - a `MiB total` row is the sum of rows judged here (P12's datadir = outside the window + window bytes per block ×
    ///   blocks per score × the bounded span), never judged twice.
    /// Prints one REPORT row per judged metric (the ratio) and the verdict row; returns the metrics that grew.
    pub fn flatness(lo: &[(String, f64, String, f64)], hi: &[(String, f64, String, f64)], lo_h: u64, hi_h: u64) -> Vec<String> {
        let mut grew = Vec::new();
        for (metric, b, unit, _) in hi.iter().filter(|(m, _, u, _)| u == "× bound" && !m.starts_with("P14")) {
            if !(*b <= 1.0) {
                grew.push(format!("{metric}: {b:.3} {unit} at height {hi_h} (a bounded store past its bound)"));
            }
        }
        for (metric, a, unit, _) in lo {
            if metric.starts_with("P14") || unit == "× bound" || unit == "MiB total" {
                continue;
            }
            let Some((_, b, _, res_hi)) = hi.iter().find(|(m, _, _, _)| m == metric) else {
                eprintln!("[perf-flat] {metric}: printed at height {lo_h} only — not judged");
                continue;
            };
            let res = match unit.as_str() {
                "s" => 0.5,
                "blocks" => 1.0,
                _ => 0.0,
            } + res_hi;
            let flat = b.is_finite() && *b <= 2.0 * a + res;
            if !flat {
                grew.push(format!("{metric}: {a:.3} → {b:.3} {unit}"));
            }
            row(
                &format!("P14 {metric} @{hi_h} ÷ @{lo_h}"),
                if *a > 0.0 { b / a } else { f64::NAN },
                "×",
                None,
                &format!("{a:.3} → {b:.3} {unit} · {}", if flat { "flat" } else { "GREW beyond 2× + resolution" }),
            );
        }
        row(
            &format!("P14 flatness: rows that grew from height {lo_h} to {hi_h}"),
            grew.len() as f64,
            "rows",
            Some(0.0),
            &format!("each row ≤ 2× + its resolution · grew: {}", if grew.is_empty() { "none".to_string() } else { grew.join(" · ") }),
        );
        grew
    }

    /// One wallet refresh + balance's wall seconds (P5's samples).
    pub fn note_refresh(secs: f64) {
        REFRESH_WALL_S.with(|v| v.borrow_mut().push(secs));
    }

    /// The `p` quantile of this run's refresh wall seconds and the sample count.
    #[must_use]
    pub fn refresh_quantile(p: f64) -> (f64, usize) {
        REFRESH_WALL_S.with(|v| {
            let mut s = v.borrow().clone();
            s.sort_by(f64::total_cmp);
            let n = s.len();
            if n == 0 {
                return (0.0, 0);
            }
            (s[((n as f64 - 1.0) * p).round() as usize], n)
        })
    }

    /// The verdict a row carries: PASS at or under its target, MISS over it, REPORT with no target.
    #[must_use]
    pub fn verdict(value: f64, target: Option<f64>) -> &'static str {
        match target {
            Some(t) if value <= t => "PASS",
            Some(_) => "MISS",
            None => "REPORT",
        }
    }

    /// Print one row (see the module doc).
    pub fn row(metric: &str, value: f64, unit: &str, target: Option<f64>, clock: &str) {
        row_within(metric, value, unit, target, clock, 0.0);
    }

    /// Print one row whose value is known only to `resolution` (in its unit) below it — a wait read through one wallet
    /// poll ([`flatness`] judges it to that poll).
    pub fn row_within(metric: &str, value: f64, unit: &str, target: Option<f64>, clock: &str, resolution: f64) {
        let run = RUN.with(|r| r.borrow().clone());
        ROWS.with(|v| v.borrow_mut().push((metric.to_string(), value, unit.to_string(), resolution)));
        let tgt = target.map_or_else(|| "-".to_string(), |t| format!("{t}"));
        eprintln!(
            "[perf-row] {metric}\t{value:.3}\t{unit}\t{tgt}\t{}\t{}\t{run}",
            verdict(value, target),
            clock.replace(['\t', '\n'], " ")
        );
    }
}

/// ⭐⭐⭐ THE FULL NODE JOURNEY, IN SIMULATION (user 2026-10-06: "We must STOP using node runs as a bug finder … We shouldnt do
/// a node run until the entire chain is complete meaning it should be able to run the full node journey").
///
/// Every step a live Tier-1 → Tier-3 run checks, in order. A step the simulator has no arm for yet is NOT-RUN — never
/// passed — and `scratchpad/sim-full-journey.pass` (the file `no-live-node-bugfinding-guard.py` reads before any live run)
/// is written ONLY when every step passed on this source. `scratchpad/sim-journey.tsv` records every step of every run, and
/// the hole scanner reads it: a step not passing, or a record older than the node's source, is a hole.
pub mod journey {
    /// (id, what the step proves). The live gate's steps 0–5 are T1.0–T1.5; the rest are the tiers after it.
    pub const FULL_JOURNEY: [(&str, &str); 16] = [
        ("T1.0", "a fresh pair converges to one chain"),
        ("T1.1", "the faucet funds a REAL wallet (wallet-harness) through node 0's production RPC and it reads the credit"),
        ("T1.2", "that wallet sends 3.0 to a second real wallet on node 1, which reads it from ITS node"),
        ("T1.3", "a rolling restart through the production boot: both nodes report a current nf view, no wedged fold, one chain and one unspent root through the production get_info"),
        ("T1.4", "after the restarts the receiver sends 1.0 back through node 1 and the payer reads it through node 0"),
        ("T1.5", "the receiver restored from its seed on the OTHER node reads the same balance"),
        ("T1.6", "a fresh node joins by DSYNC, reaches the tip and holds the same funds"),
        ("T1.7", "a wallet whose node restarted under it keeps its balance and spends again"),
        ("T2", "a created asset is seen by the other node, a resting DEX ladder reaches the other node's book, and a fill through the shipped swap settles on both sides"),
        ("T3", "bond / unbond, a username, a profile and a letter published through one node are read through the OTHER node, and a POS charge is paid"),
        // R8 (chain-tracks §NETSIM-LAUNCH): acceptance rows as launch steps — br-acceptance row 12 and product row F13
        ("§BR-12", "a contract deployed from a publisher's wallet on node 1 (its deploy price burned) is applied on node 0 — one contract-state root — and a paid call built on node 0 moves that root on node 1"),
        ("F13", "the publisher fee the app's manifest named is exactly the fee the publisher's wallet receives on its own node, through the UI's one call path, and nothing else moved"),
        ("§BR-13", "the canonical SAT set-aside applied on every up node, SAT issued so far is one figure on every up node and under the cap"),
        ("§BR-14", "after the journey's spends every up node holds the SAME four fee pools, non-empty, split 40/25/25/10 (stakers, bonders, surplus, miner) — no founder share"),
        ("§BR-3", "after T3's bond, maturity, unbond and release every up node answers ONE record for the journey's seat (released: no custody, retired, one governed unbonding window named) and the same delegation targets"),
        ("§BR-11", "every up node publishes ONE miner-pool quarter and per-block rate (never the pool's balance), and the pools' miner word is one figure everywhere"),
    ];

    /// Print one run's step verdicts as `[sim-journey-row] lane \t step \t PASS|FAIL|NOT-RUN \t detail` lines — one per
    /// [`FULL_JOURNEY`] step, a step this run has no arm for reading NOT-RUN. The node writes no file: the test runner
    /// (`scratchpad/sim_ledgers.py`, called by `lane_run.sh` after every run) appends the rows to
    /// `scratchpad/sim-journey.tsv` (lane `real`) or `sim-journey-fast.tsv` (lane `fast`), and writes the live-run guard's
    /// pass file only when a `real` run printed PASS for every step.
    pub fn record(lane: &str, seed: u64, verdicts: &[(&str, &str, String)]) {
        record_steps(lane, verdicts);
        record_seed(lane, seed, verdicts);
    }

    /// The step rows alone (`[sim-journey-row]`) — what an interim leg of a parked journey prints: the ledgers read the
    /// newest step verdicts, and no seed row is written for a run that has not finished (a seed counts only from a whole run).
    pub fn record_steps(lane: &str, verdicts: &[(&str, &str, String)]) {
        for (id, _) in FULL_JOURNEY.iter() {
            let (v, d) = verdicts
                .iter()
                .find(|(s, _, _)| s == id)
                .map(|(_, v, d)| (*v, d.clone()))
                .unwrap_or(("NOT-RUN", "the simulator has no arm for this step yet".to_string()));
            eprintln!("[sim-journey-row] {lane}\t{id}\t{v}\t{}", d.replace(['\t', '\n'], " "));
        }
    }

    /// The run's seed row (`[sim-seed-row]`, sim_ledgers.py → sim-seeds.tsv) — printed once per WHOLE run.
    pub fn record_seed(lane: &str, seed: u64, verdicts: &[(&str, &str, String)]) {
        let passed = verdicts.iter().filter(|(_, v, _)| *v == "PASS").count();
        eprintln!("[sim-journey] {lane}: {passed} of {} step(s) PASS · seed {seed:#x}", FULL_JOURNEY.len());
        // THE SEED LEDGER (verdict: "the fast and ecosystem journeys pass on ≥ 10 seeds"): one row per run — the lane, the
        // seed, how many of the steps this lane ARMS passed, and the first step that did not (or "-"). `sim_ledgers.py`
        // appends it to `scratchpad/sim-seeds.tsv`; a seed is counted only from a run that printed this row.
        let armed = verdicts.len();
        let first_red = verdicts.iter().find(|(_, v, _)| *v != "PASS");
        eprintln!(
            "[sim-seed-row] {lane}\t{seed:#x}\t{passed}\t{armed}\t{}\t{}",
            first_red.map(|(id, _, _)| *id).unwrap_or("-"),
            first_red.map(|(_, _, d)| d.replace(['\t', '\n'], " ").chars().take(300).collect::<String>()).unwrap_or_default()
        );
    }

    /// ⭐ ONE SEED SITE FOR EVERY JOURNEY: `SIM_SEED` (decimal or `0x` hex) replaces the journey's own constant, so the same
    /// journey runs on N seeds with no edit (`scratchpad/sim.sh fast` with `SIM_SEEDS="…"` loops them). The seed drives every
    /// simulated wire's latency/loss draws and every node's phase (`NetSim::with_params`) — a schedule-dependent defect
    /// shows on some seeds and not others, which is what a ≥ 10-seed pass rules out. An unparsable value is REFUSED (a typo
    /// silently running the default seed would count one seed twice).
    pub fn seed(default: u64) -> u64 {
        match std::env::var("SIM_SEED") {
            Err(_) => default,
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

    /// Local time as `YYYY-MM-DDTHH:MM:SS` (the ledgers' format), without a date crate.
    pub fn local_now() -> String {
        std::process::Command::new("date")
            .arg("+%Y-%m-%dT%H:%M:%S")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod journey_tests {
    /// ⭐ A5 — THE HOLDER YIELD, MEASURED FROM CHAIN STATE AT TWO ACTIVITY LEVELS (docs/A5-ADOPTABLE-COMPARISON-20261030.md).
    ///
    /// The stakers' pool is the one source of every staker's reward (§BR-14: 25 % of every network fee lands in
    /// `fee_pool_stakers`; a claim pays the 5 % schedule only from what the pool holds). So the yield a holder can be paid is
    /// the pool's INFLOW against the stake that shares it — a chain quantity every node holds identically, read here from
    /// the node's own `fee_pools()` on BOTH nodes, never from a model. One real wallet stakes; another pays fee-bearing sends
    /// at two activity levels over equal simulated windows; each level's inflow, window and the stake it is shared over are
    /// one row of `scratchpad/a5-yield.tsv` with the annualised rate (inflow ÷ staked × year ÷ window). The table cites the
    /// latest rows. Asserted, not just printed: the pool grows by at least the stakers' share of the base fee of every send
    /// (the split conserves and nothing else may take from it), both nodes hold the same pool, and the busier level yields
    /// more — a yield that did not rise with activity would mean fees are not reaching the pool.
    /// LOCAL-STORAGE-REQUIRED: a measurement ledger written by a `#[cfg(test)]` harness pin in `scratchpad/`, never by a
    /// node or wallet; bound: two rows per run (one per activity level), each one line.
    #[test]
    fn a5_the_stakers_pool_yield_is_measured_from_chain_state_at_two_activity_levels() {
        use crate::harness::real_node_journey::wallet::RealWallet;
        use usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC;
        const STAKERS_BPS: u64 = 2_500; // the 40/25/25/10 split's stakers' quarter (§BR-14)
        const YEAR_MS: u128 = 365 * 86_400 * 1_000;
        // A stake needs a seated custodian (MEASURED 2026-11-01, brb26/h8-pins.log: `"outcome":"NO_CUSTODIANS"` on a plain
        // two-node mesh): raised as the layer-2 pins raise theirs — custody seated, node 0's mined SAT bonded.
        let mut sim = NetSim::testnet(2, Physics::from_env(), 0xA5_2026_1101).with_band_double().boot_from_disk();
        assert!(
            run_until(&mut sim, 600_000, |s| s.one_chain_between(0, 1) && (0..2).all(|i| s.rt(i).node().validators().bonded_ids().len() == 2)).is_some(),
            "PRECONDITION: one chain with both custody seats"
        );
        assert!(sim.seat_sat_custody(0, 900_000), "PRECONDITION: node 0 bonds the SAT it mined as custody weight on both nodes");
        let (url0, url1) = (sim.serve_rpc(0), sim.serve_rpc(1));
        let mk = |sim: &mut NetSim, role: &'static str, url: String| {
            while_meshing(sim, 300, move || RealWallet::create("a5", role, &url)).unwrap_or_else(|| Err("wallet create did not finish within 300 s".into()))
        };
        let staker = mk(&mut sim, "w1", url0.clone()).unwrap_or_else(|e| panic!("A5: the staker's wallet: {e}"));
        let payer = mk(&mut sim, "w2", url1.clone()).unwrap_or_else(|e| panic!("A5: the payer's wallet: {e}"));
        for w in [&staker, &payer] {
            let (code, body) = sim.rpc(0, "POST", "/faucet/drip", &format!(r#"{{"amount":12500000000,"to":"{}"}}"#, w.address));
            assert_eq!(code, 200, "the faucet funds the wallet: {body}");
        }
        let within = spendable_within_s(&sim);
        assert!(balance_until(&mut sim, &staker, within, |b| b >= 12_500_000_000) > 0, "A5: the staker never read its credit");
        assert!(balance_until(&mut sim, &payer, within, |b| b >= 12_500_000_000) > 0, "A5: the payer never read its credit");
        // ONE staker holds the whole stake in this mesh, so the stake the pool is shared over is what it staked.
        let staked_usdm = 100u64;
        let s = staker.clone_handle();
        let cmd = format!("stake {staked_usdm}");
        let (ok, _secs, reply) = while_meshing(&mut sim, within, move || s.pay_in_session(&cmd, "stake", within)).unwrap_or_else(|| panic!("A5: the stake did not finish within {within} s"));
        assert!(ok && reply.contains("\"published\":true"), "A5: the stake was not published: {reply}");
        let staked_atomic = staked_usdm * 100_000_000;
        let pool = |sim: &NetSim, n: usize| sim.rt(n).node().peg().fee_pools().stakers;
        let ledger = crate::harness::scratchpad_dir().join("a5-yield.tsv"); // beside the other harness ledgers (a worktree has no scratchpad/)
        let mut rates: Vec<f64> = Vec::new();
        for (level, sends) in [("low", 3u32), ("high", 12u32)] {
            // settle before the window so the stake's own fee is outside it
            run_until(&mut sim, 20_000, |s| s.rt(0).node().peg().fee_pools().stakers == s.rt(1).node().peg().fee_pools().stakers);
            let (pool0, t0) = (pool(&sim, 0), sim.now);
            for _ in 0..sends {
                send(&mut sim, &payer, &staker.address, "0.25", within).unwrap_or_else(|e| panic!("A5 ({level}): a fee-bearing send failed: {e}"));
            }
            // every send's fee has reached the pool once both nodes hold the same pool and it has grown by the sends' share
            let want = pool0 + u64::from(sends) * PROTOCOL_FEE_ATOMIC * STAKERS_BPS / 10_000;
            run_until(&mut sim, 180_000, |s| pool(s, 0) >= want && pool(s, 0) == pool(s, 1));
            let (pool1, t1) = (pool(&sim, 0), sim.now);
            assert_eq!(pool1, pool(&sim, 1), "A5 ({level}): the two nodes hold different stakers' pools — the pool is not a function of the chain");
            assert!(pool1 >= want, "A5 ({level}): the pool grew {} after {sends} sends, under the stakers' share {} of their base fees", pool1 - pool0, want - pool0);
            let window_ms = t1.saturating_sub(t0).max(1);
            let rate_pct = (pool1 - pool0) as f64 / staked_atomic as f64 * (YEAR_MS as f64 / window_ms as f64) * 100.0;
            rates.push(rate_pct);
            let row = format!(
                "{}\t{level}\t{sends}\t{}\t{}\t{}\t{:.3}\n",
                chrono_free_now(),
                staked_atomic,
                pool1 - pool0,
                window_ms,
                rate_pct
            );
            eprintln!("[a5-yield] level {level}: {sends} sends, pool +{} atomic over {window_ms} sim ms on {staked_atomic} staked → {rate_pct:.3} % a year", pool1 - pool0);
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&ledger) {
                use std::io::Write;
                let _ = f.write_all(row.as_bytes());
            }
        }
        assert!(rates[1] > rates[0], "A5: the busier level did not yield more ({:.3} % vs {:.3} %) — fees are not reaching the stakers' pool", rates[1], rates[0]);
    }

    /// Seconds since the epoch as an ISO-like stamp without a date crate.
    fn chrono_free_now() -> String {
        let s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        format!("@{s}")
    }
    use super::*;

    /// Run until `pred` holds or `max_ms` of simulated time passes; the simulated ms it took.
    /// ⭐ INCREMENTAL (user 2026-11-18: "the test shouldnt be long, all of our test should be incremental so we dont have to do long
    /// runs"): `run_until`, ending at the FIRST CERTAIN FAILURE — node `watch`'s progress key unchanged for `stall_ms` simulated
    /// while the predicate is false is a stall, returned as `Err` with the stage's wall time, never waited out to `max_ms`. The
    /// budget and the predicate are unchanged; only a run that cannot pass stops early. Every stage prints its wall time.
    fn run_stage(
        sim: &mut NetSim,
        stage: &str,
        max_ms: u64,
        stall_ms: u64,
        watch: usize,
        mut pred: impl FnMut(&NetSim) -> bool,
    ) -> Result<u64, String> {
        let (t0, w0) = (sim.now, std::time::Instant::now());
        let key = |s: &NetSim| {
            let rt = s.rt(watch);
            let n = rt.node();
            (n.tip_height(), n.served_seq(), n.band_next_ordinal())
        };
        let (mut last, mut since) = (key(sim), sim.now);
        while sim.now < t0 + max_ms {
            sim.run(1_000, 10_000);
            if pred(sim) {
                eprintln!("[stage] {stage}: PASS after {} ms simulated, {} ms wall", sim.now - t0, w0.elapsed().as_millis());
                return Ok(sim.now - t0);
            }
            let k = key(sim);
            if k != last {
                (last, since) = (k, sim.now);
            } else if sim.now - since >= stall_ms {
                let why = format!(
                    "{stage}: STALLED — node {watch} made no progress for {stall_ms} ms simulated (tip {}, served_seq {}, band next {}), \
                     {} ms simulated / {} ms wall into the stage",
                    k.0, k.1, k.2, sim.now - t0, w0.elapsed().as_millis()
                );
                eprintln!("[stage] {why}");
                return Err(why);
            }
        }
        let why = format!("{stage}: not reached in {max_ms} ms simulated ({} ms wall)", w0.elapsed().as_millis());
        eprintln!("[stage] {why}");
        Err(why)
    }

    fn run_until(sim: &mut NetSim, max_ms: u64, mut pred: impl FnMut(&NetSim) -> bool) -> Option<u64> {
        let t0 = sim.now;
        while sim.now < t0 + max_ms {
            sim.run(1_000, 10_000);
            if pred(sim) {
                return Some(sim.now - t0);
            }
        }
        None
    }

    /// A credit as the chain carries it: the staged bridge-credit object rides node `i`'s next produced block, and EVERY
    /// node — `i` included — records the note from that block. ⛔ It used to ALSO write the note into node `i`'s record
    /// store directly (`record_note_payload(0, ..)`, no block): a local mutation no peer could hold, which the replica
    /// census measured as `da_mem` and `note_target_addr` DIFFERS (g2-split-20261022.log: each node held one record
    /// and one filed target the other lacked). The harness moves value only through chain objects (AGENTS.md §2
    /// TRUSTLESS): the note is STAGED (`stage_credit_note`, the lane every faucet drip and peg-in rides) beside its
    /// justifier, node `i`'s next produced block carries both, and `holds` turns true on every node when it lands.
    fn credit(sim: &NetSim, i: usize, k: u64) -> [u8; 32] {
        let (note, cm) = Node::test_spendable_note(k);
        let mut rt = sim.rt(i);
        rt.node_mut().stage_credit_note(note.clone());
        rt.node_mut().stage_credit_justifier(
            crate::bridge_credit_tx::BridgeCreditTx {
                deposit_id: cm,
                asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
                amount: 1_000,
                note,
                owner_clue: Vec::new(),
                attestors: Vec::new(),
            }
            .wire(),
        );
        cm
    }

    /// ⭐ link 62 — A WALLET'S SEND, AS THE SHIPPING CODE TAKES IT: the wallet-shaped transaction
    /// (`Node::production_spend_tx_for_test`: one-step membership carrier, spend-or-decoy over the wallet's padded tag list),
    /// judged by the TX-level verdict `/submit_pq_tx` calls (`Node::send_verdict`), its spend-or-decoy kept only when it
    /// verified, then `NodeRuntime::submit_tx_prechecked` — which pools it AND gossips it, so every peer's gossip door judges
    /// it with the same verdict and any producer can carry it. Returns `(tx id, nullifier)` or the refusal, named.
    /// Fidelity gap, stated: the submitting node's own verdict CPU is not charged (a peer's inbound one is).
    fn submit_wallet_send(sim: &NetSim, i: usize, cm: &[u8; 32], salt: u64) -> Result<(Hash32, [u8; 32]), String> {
        let mut rt = sim.rt(i);
        let (mut tx, nf) = rt.node_mut().production_spend_tx_for_test(cm, salt).map_err(|e| format!("build: {e:?}"))?;
        let arms = rt.node().send_verdict(&tx).map_err(|e| format!("submit verdict: {e:?}"))?;
        if !arms.cover {
            tx.spend_or_decoy.clear();
        }
        let id = rt.submit_tx_prechecked(tx).map_err(|e| format!("pool: {e:?}"))?;
        Ok((id, nf))
    }

    /// Spend `cm` through node `i` as soon as the node can build it — a wallet waits until its note is SPENDABLE (the node's
    /// fold has reached the note, so its member leg builds from the node's own stream). Returns the nullifier and the
    /// simulated ms waited, or the last refusal after `max_ms`.
    fn spend_when_spendable(sim: &mut NetSim, i: usize, cm: &[u8; 32], salt: u64, max_ms: u64) -> Result<(Hash32, u64), String> {
        let t0 = sim.now;
        loop {
            let r = submit_wallet_send(sim, i, cm, salt);
            match r {
                Ok((_, nf)) => return Ok((Hash32(nf), sim.now - t0)),
                Err(e) if sim.now >= t0 + max_ms => return Err(format!("{e:?} after {} sim ms", sim.now - t0)),
                Err(_) => {
                    if (sim.now - t0) % 30_000 < 1_000 {
                        eprintln!("[sim-journey] waiting to spend (t+{} s): {}", (sim.now - t0) / 1000, diag(sim));
                    }
                    sim.run(1_000, 10_000)
                }
            }
        }
    }

    /// How long a received note takes to become SPENDABLE, derived from the protocol's own cadence — never tuned to pass:
    /// a record folds only `record_fold_depth` selected-chain steps deep, and with every node producing once per
    /// [`NetSim::production_step_ms`] on average each selected step takes about that long; its witness window then completes within a few more
    /// steps. Twice that bound is the wait (the mesh's own jitter, the relay floor). MEASURED 2026-10-06: at the live
    /// pair's 4 s cadence a received note waits ~130–150 s to become spendable — a 180 s guess cut it off.
    fn spendable_within_ms(sim: &NetSim) -> u64 {
        let step = sim.production_step_ms();
        (sim.params.record_fold_depth + 8) * step * 2
    }

    fn holds(sim: &NetSim, i: usize, cm: &[u8; 32]) -> bool {
        !sim.rt(i).node().records_containing_cm(cm).is_empty()
    }

    fn info(sim: &NetSim, i: usize) -> serde_json::Value {
        let (_, body) = sim.rpc(i, "GET", "/get_info", "");
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null)
    }

    /// The live gate's step-3 predicate on one node, read from the PRODUCTION get_info JSON.
    fn view_current(sim: &NetSim, i: usize) -> bool {
        let v = info(sim, i);
        v["nf_view_present"] == true && v["nf_view_matches_acc"] == true && v["fold_wedged"] != true
    }

    fn same_roots(sim: &NetSim) -> bool {
        let (a, b) = (info(sim, 0), info(sim, 1));
        a["unspent_root"].is_string() && a["unspent_root"] == b["unspent_root"]
    }

    /// Each node's own state at a failing step, from the PRODUCTION get_info plus the band's prover view — so a simulator red
    /// names its cause instead of only its step.
    fn diag(sim: &NetSim) -> String {
        let produced = format!(
            "produced {:?} at t={} s · state {} · ",
            sim.report.produced,
            sim.now / 1000,
            sim.state_divergence().unwrap_or_else(|| "agrees across the up nodes".into())
        );
        produced + &(0..sim.rts.len())
            .map(|i| {
                let v = info(sim, i);
                // the block this node's fold waits on, and which nodes hold its record — at the canonical address the fold
                // asks for, and at the address their own index files it under (each node's lock taken alone)
                let wait = sim.rt(i).node().fold_wait_state();
                let holders = wait.map(|(b, k)| {
                    let canonical = Node::da_record_id_for_block(&b, 0);
                    let at_canonical: Vec<usize> =
                        (0..sim.rts.len()).filter(|&j| sim.rt(j).node().da_record_held(canonical)).collect();
                    let indexed: Vec<(usize, bool)> = (0..sim.rts.len())
                        .filter_map(|j| {
                            let rt = sim.rt(j);
                            rt.node().record_addr_for_block(&b).map(|a| (j, a == canonical && rt.node().da_record_held(a)))
                        })
                        .collect();
                    format!("{} ×{k}: record held at its canonical address by {at_canonical:?}, indexed (node, canonical) {indexed:?}", &b.to_hex()[..8])
                });
                let rt = sim.rt(i);
                let n = rt.node();
                // the wallet's member stream: the newest ring root and the peaks it is told to fold to (one fold step, or the
                // book can never refold — T1.7's measured "refolds to the newest root false")
                let stream = n.path_refresh_stream(u64::MAX);
                let peaks = crate::spend_frontier::PoseidonSpendFrontier::from_peaks_hex(&stream.peaks_hex).map(|f| f.count());
                format!(
                    "n{i}[fold waits on {:?} · asks to/served/lock-busy steps/steps {:?} · tip {} dag {} · view {}/{} wedged {} unfolded {} fold_wait {} provers {} public_id {} served_seq {} records {} · band ptr {:?} lag {} applied {} stale {} dropped {} wanted {} awaiting/unknown-admitted/first {:?} · fold cursor/root/unfolded-min/max/below-cursor {:?} · adopted/ring/windows/anchor {:?} · member stream: ring newest {:?} · peaks leaves {:?} (= ordinal {:?})]",
                    holders, sim.ask_census(i), n.tip_height(), n.dag().len(), v["nf_view_present"], v["nf_view_matches_acc"], v["fold_wedged"], v["fold_unfolded"], v["fold_wait_passes"],
                    n.band_provers().len(), n.public_id().is_some(), v["served_seq"], v["records_held"], n.band_pointer(),
                    n.band_lag(), n.band_steps_applied(), n.band_door_is_stale(), n.band_dropped_for_lag(), n.band_wanted_steps(64).len(),
                    n.band_unknown_admitted(), n.fold_position(), n.spine_state(), stream.newest.map(|(o, _)| o), peaks,
                    peaks.map(|c| c / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64)
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn pass(v: &mut Vec<(&'static str, &'static str, String)>, id: &'static str, ok: bool, detail: String, wall: &std::time::Instant) -> Option<()> {
        eprintln!("[sim-journey] {id} {} — {detail} (wall {:?} · {})", if ok { "PASS" } else { "FAIL" }, wall.elapsed(), speed_line());
        v.push((id, if ok { "PASS" } else { "FAIL" }, detail));
        ok.then_some(())
    }

    /// A step's PASS — unless the state invariant broke during it: then the step FAILS with the first divergence (a step
    /// that reached its goal on nodes that no longer share one state has not passed).
    /// F3 (`NetSim::step_census`): a passed step is also the instant the replicated-state census runs — every up node
    /// must hold the same value in every replicated `Node` field once the mesh is quiet — and each DIFFERS / UNREAD field
    /// (or a mesh that never quiesced) is kept as a census red for the launch journey's end-of-run report.
    fn pass_inv(sim: &mut NetSim, v: &mut Vec<(&'static str, &'static str, String)>, id: &'static str, detail: String, wall: &std::time::Instant) -> Option<()> {
        // ⛔ G11 (lane b 2026-10-22) — A STEP HAS NOT PASSED ON A MESH THAT CAN NO LONGER SERVE A CERTIFIED BUNDLE. A node
        // whose fresh proved bundle no longer fits the bulk frame keeps serving the last one that did; the next joiner
        // adopts that stale bundle, its pivot has left every band journal, and it strands (UNPLACED, DB-428) however
        // healthy every other step reads. MEASURED launch leg 1 (scratchpad/verify/launch-leg1-20261022-2057.log): the
        // first refusal at t≈150 s (17,408,084 B > 16 MiB), T1.0–T1.5 PASS, and the red surfaced only at T1.6 at t=1,639 s
        // naming the joiner. Read on EVERY journey (not only the censused launch legs): the counter is O(1) per node.
        let frame_reds: Vec<String> = (0..sim.rts.len())
            .filter_map(|i| {
                let (n, largest) = sim.rt(i).dsync_frame_census();
                (n > 0).then(|| {
                    format!(
                        "n{i}: {n} proved DSYNC bundle(s) refused by the {} B bulk frame, the largest {largest} B",
                        crate::arti_transport::BULK_FRAME_MAX
                    )
                })
            })
            .collect();
        let r = match (sim.first_divergence.clone(), frame_reds.is_empty()) {
            (Some((t, d)), _) => fail(sim, v, id, format!("{detail} — but the STATE INVARIANT broke at t={} s: {d}", t / 1000), wall),
            (None, false) => fail(
                sim,
                v,
                id,
                format!(
                    "{detail} — but a node's fresh DSYNC bundle no longer fits the bulk frame, so the next joiner adopts a \
                     stale one and strands below every band journal (G11): {}",
                    frame_reds.join(" · ")
                ),
                wall,
            ),
            (None, true) => pass(v, id, true, detail, wall),
        };
        if sim.step_census {
            replica_census_at(sim, id, &frame_reds);
        }
        r
    }

    /// THE REPLICATED-STATE CENSUS AT ONE INSTANT (a passed step, a tail hour mark): every up node must hold the same value
    /// in every replicated `Node` field once the mesh is quiet; each DIFFERS / UNREAD field, a mesh that never quiesced, and
    /// each `frame_reds` entry is one census red for the launch journey's end-of-run report (never skipped, never narrowed).
    fn replica_census_at(sim: &mut NetSim, id: &str, frame_reds: &[String]) {
        let rows = sim.replica_census("launch");
        let not_quiet = rows.iter().filter(|r| r.1 == "NOT-QUIET").count();
        let mut reds = 0usize;
        if not_quiet > 0 {
            reds += 1;
            sim.census_reds.push((id.to_string(), "replica", "*".to_string(), format!("NOT-QUIET: the mesh never quiesced, {not_quiet} field(s) unjudged")));
        }
        for (f, verdict, bytes) in &rows {
            if *verdict == "DIFFERS" || *verdict == "UNREAD" {
                reds += 1;
                sim.census_reds.push((id.to_string(), "replica", f.clone(), format!("{verdict}: bytes per node {bytes}")));
            }
        }
        for fr in frame_reds {
            reds += 1;
            sim.census_reds.push((id.to_string(), "dsync-frame", "served bundle".to_string(), fr.clone()));
        }
        sim.census_rows += 1;
        eprintln!("[launch-census] step {id}: replica census {reds} red field(s) over {} row(s)", rows.len());
    }

    /// [`fail`] for a step function that returns a value: records the failure, returns `None`.
    fn failed<T>(sim: &NetSim, v: &mut Vec<(&'static str, &'static str, String)>, id: &'static str, detail: String, wall: &std::time::Instant) -> Option<T> {
        let _ = fail(sim, v, id, detail, wall);
        None
    }

    fn fail(sim: &NetSim, v: &mut Vec<(&'static str, &'static str, String)>, id: &'static str, detail: String, wall: &std::time::Instant) -> Option<()> {
        // A membership door refused a carried root: show that one record on EVERY node, and every row a writer replaced
        // with different notes (one record address must hold one payload everywhere).
        let mismatched: Vec<(u64, &'static str)> =
            crate::node::MEMBER_ROOT_MISMATCH.lock().map(|m| m.clone()).unwrap_or_default();
        let mut seen = std::collections::BTreeSet::new();
        for (addr, half) in mismatched {
            if !seen.insert(addr) {
                continue;
            }
            for i in 0..sim.rts.len() {
                eprintln!("[record-forensic] {half} record {addr} · n{i}: {}", sim.rt(i).node().record_forensic(addr));
            }
        }
        let replaced = crate::node::RECORD_REPLACED.lock().map(|m| m.clone()).unwrap_or_default();
        eprintln!(
            "[record-forensic] {} held row(s) replaced by different notes (addr, held, new, held bound): {:?}",
            replaced.len(),
            replaced.iter().take(24).collect::<Vec<_>>()
        );
        // Every failed step: a spend refused for its membership path reads as "the charge expired" or "confirming" as
        // often as "membership path" (MEASURED sim-20261007-122707, fast 0x8 T3: the payer's path never refolded and the
        // detail named only the expired charge, so no forensic ran).
        member_forensic(sim);
        let d = format!("{detail} · {}", diag(sim));
        pass(v, id, false, d, wall)
    }

    /// ⭐ SERVED vs FOLDED, per node (test-only census): the record a node SERVES at an ordinal (`/da_record`, the bytes a
    /// wallet builds its path from) must derive the level-8 root that node FOLDED there (its window index), and every node
    /// must have folded the same root there. A row replaced after its fold breaks the first — one record address, two
    /// payloads (MEASURED sim-20261007-122707 fast 0x8: record 55304620557361592 at ordinal 425 replaced 3 → 4 notes on
    /// three nodes by refused-but-recorded backfill pages; the payer's two notes in it never refolded, T3 POS red).
    /// Prints one row per node and the ordinals whose folded roots differ across nodes; returns the served≠folded total.
    fn served_vs_folded_census(sim: &NetSim) -> usize {
        let mut total = 0usize;
        let mut folded_by: Vec<std::collections::BTreeMap<u64, crate::spend_frontier::Digest4>> = Vec::new();
        for i in 0..sim.rts.len() {
            let rt = sim.rt(i);
            let n = rt.node();
            let top = n.da_highest_record_ordinal().unwrap_or(0);
            let mut bad = Vec::new();
            let mut judged = 0usize;
            let mut folded_here = std::collections::BTreeMap::new();
            for o in 1..=top {
                let cell = n.window_index().get(crate::node::Node::RECORD_SUBTREE_LEVEL, o - 1);
                if let Some(folded) = cell {
                    folded_here.insert(o, folded);
                }
                let Some(addr) = n.da_addr_at_ordinal(o) else { continue };
                let Some(reals) = n.da_record_reals(addr) else { continue };
                // Under the record's OWN cover key (§20.2), as the fold derived it — never the test key. MEASURED
                // (night/sim-20261101-115338.log): with TEST_COVER_KEY every node read "2150 judged, 2150 serve a record whose
                // root is NOT the one this node folded", the never-restarted nodes included — the census, not the chain.
                let served = crate::node::Node::fold_leaves_to_root(&crate::node::Node::block_leaves_from_notes(&reals.concat(), addr, &n.cover_key_of(addr)));
                // The folded root: the window index's record-level cell, else the committed membership step over this
                // node's own per-ordinal accumulators (a node whose index lost its low cells still holds those).
                let stands = match (cell, n.da_membership_acc_at_ordinal(o - 1), n.da_membership_acc_at_ordinal(o)) {
                    (Some(folded), _, _) => served == folded,
                    (None, Some(before), Some(after)) => {
                        usdm_decider::note_membership_air::note_membership_step_new_acc(before, served) == after
                    }
                    _ => continue,
                };
                judged += 1;
                if !stands {
                    bad.push((o, addr, reals.len(), n.record_bytes_are_chain_bound(crate::node::RecAddr::local(addr))));
                }
            }
            total += bad.len();
            eprintln!(
                "[served-vs-folded] n{i}: {judged} ordinal(s) judged, {} serve a record whose root is NOT the one this node \
                 folded (ordinal, addr, real notes held, chain-bound): {:?}",
                bad.len(),
                bad.iter().take(12).collect::<Vec<_>>()
            );
            folded_by.push(folded_here);
        }
        let refused = crate::node::RECORD_REPLACE_REFUSED.lock().map(|m| m.len()).unwrap_or(0);
        eprintln!("[served-vs-folded] DB-415 refused {refused} write(s) that would have changed a folded row");
        if let Some(first) = folded_by.first() {
            let split: Vec<u64> = first
                .iter()
                .filter(|(o, r)| folded_by.iter().skip(1).any(|m| m.get(o).is_some_and(|x| x != *r)))
                .map(|(o, _)| *o)
                .collect();
            eprintln!(
                "[served-vs-folded] ordinals whose FOLDED level-8 root differs across nodes: {} {:?}",
                split.len(),
                split.iter().take(12).collect::<Vec<_>>()
            );
        }
        total
    }

    /// ⭐ THE MEMBERSHIP FORENSIC (test-only): a wallet path that "does not refold to the ring root" names no level, so
    /// every node's three path sources are compared with node 1's over the SAME chain — the window index (every completed
    /// subtree ≥ the record level), the anchor ring (the roots a path is compared to) and every folded record's derived
    /// 256-leaf root (levels 0–7) — and node 1's whole window index is printed as `level:window:limb0`, the spelling the
    /// wallet's `[member-book]` line uses for each sibling it folded. MEASURED sim-20261006-235327 T1.7: 14 refusals
    /// "refreshed path does not refold" after node 0's restart, and nothing said which node, layer or level was wrong.
    fn member_forensic(sim: &NetSim) {
        if sim.rts.len() < 2 {
            return;
        }
        let snap = |i: usize| {
            let rt = sim.rt(i);
            let n = rt.node();
            let windows: std::collections::BTreeMap<(usize, u64), u64> =
                n.window_index().entries().into_iter().map(|(l, w, r)| ((l, w), r[0])).collect();
            let ring: std::collections::BTreeMap<u64, u64> = n.anchor_ring().into_iter().map(|(o, r)| (o, r[0])).collect();
            let top = n.da_highest_record_ordinal().unwrap_or(0);
            let records: std::collections::BTreeMap<u64, (u64, Option<u64>)> = (1..=top)
                .filter_map(|o| {
                    let addr = n.da_addr_at_ordinal(o)?;
                    let root = n
                        .da_record_notes(addr)
                        .map(|notes| crate::node::Node::fold_leaves_to_root(&crate::node::Node::block_leaves_from_notes(&notes, addr, &crate::cover::TEST_COVER_KEY))[0]);
                    Some((o, (addr, root)))
                })
                .collect();
            (windows, ring, records)
        };
        served_vs_folded_census(sim);
        let (w1, r1, rec1) = snap(1);
        for i in (0..sim.rts.len()).filter(|i| *i != 1) {
            let (wi, ri, reci) = snap(i);
            let wdiff: Vec<&(usize, u64)> = wi.iter().filter(|(k, v)| w1.get(k).is_some_and(|x| x != *v)).map(|(k, _)| k).collect();
            let rdiff: Vec<&u64> = ri.iter().filter(|(k, v)| r1.get(k).is_some_and(|x| x != *v)).map(|(k, _)| k).collect();
            let addr_diff: Vec<&u64> =
                reci.iter().filter(|(k, v)| rec1.get(k).is_some_and(|x| x.0 != v.0)).map(|(k, _)| k).collect();
            let root_diff: Vec<&u64> = reci
                .iter()
                .filter(|(k, v)| rec1.get(k).is_some_and(|x| x.0 == v.0 && x.1.is_some() && v.1.is_some() && x.1 != v.1))
                .map(|(k, _)| k)
                .collect();
            eprintln!(
                "[member-forensic] n{i} vs n1 · windows held {}/{} common {} ROOT DIFFERS {} {:?} only-here {} only-n1 {} · ring \
                 common {} DIFFERS {} {:?} · records {}/{} address differs {} {:?} derived root differs {} {:?} unresolved here {}",
                wi.len(),
                w1.len(),
                wi.keys().filter(|k| w1.contains_key(k)).count(),
                wdiff.len(),
                wdiff.iter().take(12).collect::<Vec<_>>(),
                wi.keys().filter(|k| !w1.contains_key(k)).count(),
                w1.keys().filter(|k| !wi.contains_key(k)).count(),
                ri.keys().filter(|k| r1.contains_key(k)).count(),
                rdiff.len(),
                rdiff.iter().take(12).collect::<Vec<_>>(),
                reci.len(),
                rec1.len(),
                addr_diff.len(),
                addr_diff.iter().take(12).collect::<Vec<_>>(),
                root_diff.len(),
                root_diff.iter().take(12).collect::<Vec<_>>(),
                reci.values().filter(|v| v.1.is_none()).count()
            );
        }
        let mut by_level: std::collections::BTreeMap<usize, Vec<String>> = std::collections::BTreeMap::new();
        for ((l, w), r) in &w1 {
            by_level.entry(*l).or_default().push(format!("{l}:{w}:{r:x}"));
        }
        for (l, cells) in by_level {
            eprintln!("[member-forensic] n1 windows level {l}: {}", cells.join(" "));
        }
        eprintln!(
            "[member-forensic] n1 ring: {}",
            r1.iter().rev().take(16).map(|(o, r)| format!("{o}:{r:x}")).collect::<Vec<_>>().join(" ")
        );
    }

    /// Run `f` (a real wallet process call, which blocks on the node's RPC) on its own thread while the mesh keeps running;
    /// `None` when it has not finished within `secs` of WALL time.
    fn while_meshing<T: Send + 'static>(sim: &mut NetSim, secs: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let h = std::thread::spawn(f);
        let t0 = std::time::Instant::now();
        while !h.is_finished() {
            if t0.elapsed().as_secs() > secs {
                return None;
            }
            sim.run(500, 10_000);
        }
        h.join().ok()
    }

    /// [`while_meshing`] at the CHAIN'S REAL PACE: 500 ms of simulated chain per 500 ms of wall clock while `f` runs. For a
    /// wallet call that PROVES in real time (a DSOL call: one WHIR proof, tens of seconds): run flat out, the simulator folds
    /// hundreds of 64-block epochs during the proof and the honest call is epochs stale at its block — a simulator artefact no
    /// real chain shows. MEASURED 2026-11-01 (h6-f13-journey.log): ~880 record folds during one ~60 s proof.
    fn while_meshing_paced<T: Send + 'static>(sim: &mut NetSim, secs: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let h = std::thread::spawn(f);
        let t0 = std::time::Instant::now();
        while !h.is_finished() {
            if t0.elapsed().as_secs() > secs {
                return None;
            }
            let tick = std::time::Instant::now();
            sim.run(500, 10_000);
            if let Some(rest) = std::time::Duration::from_millis(500).checked_sub(tick.elapsed()) {
                std::thread::sleep(rest);
            }
        }
        h.join().ok()
    }

    /// ⛔ ONE CLOCK: a journey budget is SIMULATED time (the chain's own cadence is what it is derived from), with a wall-clock
    /// hang guard. MEASURED 2026-10-06: measured in wall seconds, a budget meant 4,852 simulated seconds in one run and 214 in
    /// another (the simulator ran 12.5× wall, then slower than wall) — the same journey passed or failed on machine speed.
    fn within_budget(sim: &NetSim, sim_t0: u64, wall_t0: std::time::Instant, secs: u64) -> bool {
        sim.now.saturating_sub(sim_t0) <= secs.saturating_mul(1_000) && wall_t0.elapsed().as_secs() <= secs.saturating_mul(4)
    }

    /// Poll a real wallet's balance (its own `refresh` + `balance`) until `want(balance)` or `secs` of SIMULATED time (see
    /// [`within_budget`]); the mesh keeps running meanwhile. Returns the last balance read.
    fn balance_until(
        sim: &mut NetSim,
        w: &crate::harness::real_node_journey::wallet::RealWallet,
        secs: u64,
        want: impl Fn(u64) -> bool,
    ) -> u64 {
        let (sim_t0, t0) = (sim.now, std::time::Instant::now());
        let mut last = 0;
        crate::harness::sim_coverage::note_wallet("refresh");
        crate::harness::sim_coverage::note_wallet("balance");
        while within_budget(sim, sim_t0, t0, secs) {
            let h = w.spawn_balance_parts();
            while !h.is_finished() {
                sim.run(500, 10_000);
            }
            let ((atomic, _, _), wall_s) = h.join().unwrap_or(((0, 0, 0), 0.0));
            super::perf::note_refresh(wall_s); // PERF P5: what one balance refresh costs the user, wall
            last = atomic;
            if want(last) {
                break;
            }
        }
        last
    }

    /// ⭐ PERF TIER P2/P3 — [`balance_until`] for a payment `w` is RECEIVING, timed. It polls until the spendable balance
    /// exceeds `before` (the same predicate and budget the step used), and times — from `sent_at` (sim ms, the instant the
    /// sender's wallet reported the send submitted) — the first poll that SAW the payment (spendable above `before`, or any
    /// pending or confirming amount: what the wallet shows as incoming) and the first that could SPEND it. Each instant is
    /// the END of the poll that read it, an upper bound by at most one poll's simulated length, returned beside them.
    /// Returns (spendable balance last read, seen ms, spendable ms, the longest poll's simulated ms).
    fn receive_timed(
        sim: &mut NetSim,
        w: &crate::harness::real_node_journey::wallet::RealWallet,
        secs: u64,
        before: u64,
        sent_at: u64,
    ) -> (u64, Option<u64>, Option<u64>, u64) {
        let (sim_t0, t0) = (sim.now, std::time::Instant::now());
        let (mut last, mut seen, mut ready, mut poll_max) = (0u64, None, None, 0u64);
        crate::harness::sim_coverage::note_wallet("refresh");
        crate::harness::sim_coverage::note_wallet("balance");
        while within_budget(sim, sim_t0, t0, secs) {
            let start = sim.now;
            let h = w.spawn_balance_parts();
            while !h.is_finished() {
                sim.run(500, 10_000);
            }
            let ((atomic, pending, confirming), wall_s) = h.join().unwrap_or(((0, 0, 0), 0.0));
            super::perf::note_refresh(wall_s);
            poll_max = poll_max.max(sim.now - start);
            last = atomic;
            if seen.is_none() && (atomic > before || pending > 0 || confirming > 0) {
                seen = Some(sim.now.saturating_sub(sent_at));
            }
            if atomic > before {
                ready = Some(sim.now.saturating_sub(sent_at));
                break;
            }
        }
        (last, seen, ready, poll_max)
    }

    /// ⭐ PERF TIER P1–P3 for one payment: the sender's wallet time to "sent" (wall), and the receiver's wait to SEE it and
    /// to SPEND it (simulated, read through its wallet's polls). `producers` = the up nodes producing (the mesh it ran on).
    fn payment_rows(sim: &NetSim, step: &str, send_wall_s: f64, send_sim_ms: u64, seen: Option<u64>, ready: Option<u64>, poll_ms: u64) {
        let producers = (0..sim.rts.len()).filter(|&i| !sim.is_down(i)).count();
        super::perf::row(
            &format!("P1 send → the sender's wallet shows sent ({step})"),
            send_wall_s,
            "s",
            Some(1.0),
            &format!("wallet wall (the wallet's own proving + submit; {:.1} s simulated passed meanwhile)", send_sim_ms as f64 / 1e3),
        );
        let poll = format!("≤ +{:.1} s (one wallet poll)", poll_ms as f64 / 1e3);
        let wait = |ms: Option<u64>| ms.map_or(f64::INFINITY, |m| m as f64 / 1e3);
        let res = poll_ms as f64 / 1e3;
        super::perf::row_within(
            &format!("P2 send → the receiver's wallet sees it ({step})"),
            wait(seen),
            "s",
            Some(2.0),
            &format!("sim chain wait, node CPU charged, {producers} producer(s), read through the receiver's wallet {poll}"),
            res,
        );
        super::perf::row_within(
            &format!("P3 send → the receiver can spend it ({step})"),
            wait(ready),
            "s",
            None,
            &format!("sim chain wait, node CPU charged, {producers} producer(s), fold depth {} · {poll}", sim.params.record_fold_depth),
            res,
        );
    }

    /// One node datadir on disk: its block window (`block_window`, one `<blue score:020>-<id>….blk` file per held block)
    /// and every other entry beside it (P12).
    struct DatadirCensus {
        total: u64,
        window: WindowCensus,
        outside: Vec<(String, u64)>,
    }

    #[derive(Default)]
    struct WindowCensus {
        files: u64,
        bytes: u64,
        min_score: u64,
        max_score: u64,
    }

    fn datadir_census(dir: &std::path::Path) -> DatadirCensus {
        fn bytes_under(p: &std::path::Path) -> u64 {
            match std::fs::read_dir(p) {
                Ok(rd) => rd
                    .flatten()
                    .map(|e| match e.metadata() {
                        Ok(m) if m.is_dir() => bytes_under(&e.path()),
                        Ok(m) => m.len(),
                        Err(_) => 0,
                    })
                    .sum(),
                Err(_) => 0,
            }
        }
        let mut c = DatadirCensus { total: 0, window: WindowCensus { min_score: u64::MAX, ..WindowCensus::default() }, outside: Vec::new() };
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() && name.starts_with(crate::block_window::WINDOW_DIR_PREFIX) {
                for f in std::fs::read_dir(e.path()).into_iter().flatten().flatten() {
                    let fname = f.file_name().to_string_lossy().into_owned();
                    let len = f.metadata().map_or(0, |m| m.len());
                    c.total += len;
                    match fname.strip_suffix(".blk").and_then(|n| n.get(..20)).and_then(|d| d.parse::<u64>().ok()) {
                        Some(score) => {
                            c.window.files += 1;
                            c.window.bytes += len;
                            c.window.min_score = c.window.min_score.min(score);
                            c.window.max_score = c.window.max_score.max(score);
                        }
                        None => c.outside.push((format!("{name}/{fname}"), len)),
                    }
                }
            } else {
                let len = if m.is_dir() { bytes_under(&e.path()) } else { m.len() };
                c.total += len;
                c.outside.push((name, len));
            }
        }
        if c.window.files == 0 {
            c.window.min_score = 0;
        }
        c
    }

    /// ⭐ PERF TIER — the run's own rows, printed once at its end: P5 (balance refresh, wall), P11 (the block interval the
    /// mesh achieved against `target_spacing_ms`), and the block relay to a peer (p50 / p95, the propagation term P2 rides
    /// on).
    fn run_rows(sim: &NetSim) {
        let (p50, n) = super::perf::refresh_quantile(0.5);
        let (p95, _) = super::perf::refresh_quantile(0.95);
        // a run that refreshed no wallet measured no refresh: no row (lane stable 2026-11-01 — a journey stopped at T1.1 by a
        // stale wallet binary wrote "P5 0.000 s PASS, 0 refresh(es)" into perf.tsv, a PASS no measurement stood behind)
        if n > 0 {
            super::perf::row("P5 balance refresh (p50)", p50, "s", Some(1.0), &format!("wallet wall, {n} refresh(es)"));
            super::perf::row("P5 balance refresh (p95)", p95, "s", Some(1.0), &format!("wallet wall, {n} refresh(es)"));
        }
        let produced: u64 = sim.report.produced.iter().sum();
        let producers = (0..sim.rts.len()).filter(|&i| !sim.is_down(i)).count();
        if produced > 0 {
            super::perf::row(
                "P11 block interval achieved (mesh-wide)",
                sim.now as f64 / produced as f64 / 1e3,
                "s",
                None,
                &format!(
                    "sim, {produced} block(s) over {:.0} s by {producers} producer(s) (target_spacing_ms {} applies at ≥ 8 producers)",
                    sim.now as f64 / 1e3,
                    sim.params.target_spacing_ms
                ),
            );
        }
        // P4: finality as the gadget counts it — node 0's finalized height against its tip (a timed birth → finalized
        // figure needs a bonded quorum in the lane; this row says where finality stands)
        // one guard per statement: a tuple's first `rt(0)` guard lives to the statement's end, so a second `rt(0)` in the
        // same expression waits on it for ever (MEASURED link 36: every journey hung here after its last step)
        let tip = sim.rt(0).node().tip_height();
        let fin = sim.rt(0).node().finalized_height();
        super::perf::row(
            "P4 finality: blocks between node 0's tip and its finalized height",
            tip.saturating_sub(fin) as f64,
            "blocks",
            None,
            &format!("sim, tip {tip}, finalized {fin}{}", if fin == 0 { " — no finality certificate counted in this lane" } else { "" }),
        );
        // P12: each node's datadir on disk, in the parts P14 can judge (`datadir_census`). MEASURED link 37 (height ~3 k, flat@1000):
        // 106 MiB, of which the block window held 2,920 whole blocks at ~33.6 KB (an empty block is 31 KB: the 256 padded tx
        // ids and its constant-shape commitments) and everything else was ~9 MiB. The window is BOUNDED (Kaspa's pruning-point
        // block store, `Node` cuts it at the quantized fold base): it holds at most `keep_depth + span` = 2 × keep_depth blue
        // score, so below that it FILLS with height and past it it is constant. So the total is reported, and its parts are
        // judged on their own shapes: the bytes outside the window, the window's bytes per held block and held blocks per blue
        // score flat across heights (P14's 2× rule), and the window's held span against its bound at EVERY height.
        let census: Vec<Option<DatadirCensus>> = sim.dirs.iter().map(|d| d.as_deref().map(datadir_census)).collect();
        let keep_depth = sim.rt(0).node().dag().keep_depth();
        let bound = 2 * keep_depth;
        if let Some(big) = census.iter().flatten().max_by_key(|c| c.total).filter(|c| c.total > 0) {
            const MIB: f64 = 1024.0 * 1024.0;
            let per_node: Vec<u64> = census.iter().map(|c| c.as_ref().map_or(0, |c| c.total)).collect();
            super::perf::row(
                "P12 node datadir on disk (largest node)",
                big.total as f64 / MIB,
                "MiB total",
                None,
                &format!("bytes per node {per_node:?} at tip height {tip} — judged through the P12 parts below"),
            );
            let mut outside = big.outside.clone();
            outside.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
            let top: Vec<String> = outside.iter().take(4).map(|(n, b)| format!("{n} {:.2} MiB", *b as f64 / MIB)).collect();
            super::perf::row(
                "P12 datadir outside the block window (largest node)",
                outside.iter().map(|(_, b)| *b).sum::<u64>() as f64 / MIB,
                "MiB",
                None,
                &format!("{} · at tip height {tip}", top.join(", ")),
            );
            let w = &big.window;
            if w.files > 0 {
                let span = w.max_score.saturating_sub(w.min_score) + 1;
                super::perf::row(
                    "P12 block window: bytes per held block",
                    w.bytes as f64 / w.files as f64 / 1e3,
                    "KB",
                    None,
                    &format!("{} block(s), {:.1} MiB", w.files, w.bytes as f64 / MIB),
                );
                super::perf::row(
                    "P12 block window: held blocks per blue score of span",
                    w.files as f64 / span as f64,
                    "blocks/score",
                    None,
                    &format!("blue score {}..={} held", w.min_score, w.max_score),
                );
                super::perf::row(
                    "P12 block window: held blue-score span ÷ its bound (2 × keep_depth)",
                    span as f64 / bound as f64,
                    "× bound",
                    Some(1.0),
                    &format!(
                        "span {span} of {bound}; the window {} — at the production per-block bytes the bound is {:.0} MiB",
                        // the first base step cuts at keep_depth, so a stepped window holds nothing below it (genesis is
                        // never in the window: an unstepped one starts at blue score 1)
                        if w.min_score >= keep_depth { "has stepped its base (the bound is exercised)" } else { "has not stepped its base yet (still filling)" },
                        bound as f64 * (w.bytes as f64 / w.files as f64) * (w.files as f64 / span as f64) / MIB
                    ),
                );
            }
        }
        // P13: the bytes a peer pulls per block, and per spend body — the ≤ 1.8 MB constant-proof pillar. Empty blocks and
        // blocks carrying spends are reported apart: a constant-shape block is the same size either way.
        let sizes = &sim.report.block_sizes;
        if !sizes.is_empty() {
            const MB: f64 = 1e6;
            let mut wire: Vec<u64> = sizes.iter().map(|s| s.wire).collect();
            wire.sort_unstable();
            let p50 = wire[(wire.len() - 1) / 2];
            let big = sizes.iter().max_by_key(|s| s.wire).expect("non-empty");
            let mut parts = big.parts.clone();
            parts.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
            let top: Vec<String> = parts.iter().filter(|(_, b)| *b > 0).take(6).map(|(n, b)| format!("{n} {b} B")).collect();
            let carrying = sizes.iter().filter(|s| s.txs > 0).count();
            super::perf::row("P13 block on the wire (p50)", p50 as f64 / MB, "MB", Some(1.8), &format!("{} block(s) produced, postcard of the full block as a peer pulls it", sizes.len()));
            super::perf::row(
                "P13 block on the wire (max)",
                big.wire as f64 / MB,
                "MB",
                Some(1.8),
                &format!("the largest block ({} carried tx(s)): {}", big.txs, top.join(", ")),
            );
            for (name, with) in [("no spends", false), ("carrying spends", true)] {
                if let Some(m) = sizes.iter().filter(|s| (s.txs > 0) == with).map(|s| s.wire).max() {
                    super::perf::row(
                        &format!("P13 block on the wire, {name} (max)"),
                        m as f64 / MB,
                        "MB",
                        None,
                        &format!("{} of {} block(s) {}", if with { carrying } else { sizes.len() - carrying }, sizes.len(), if with { "carry a tx" } else { "carry none" }),
                    );
                }
            }
            let bodies: Vec<u64> = sizes.iter().flat_map(|s| s.spend_bodies.iter().copied()).collect();
            let carried: u64 = sizes.iter().map(|s| s.txs).sum();
            if let Some(m) = bodies.iter().copied().max() {
                super::perf::row(
                    "P13 spend body (max)",
                    m as f64 / MB,
                    "MB",
                    Some(1.8),
                    &format!("{} body(ies) of {carried} carried tx(s) (ZK proof + confidential outputs, as the pool relays it)", bodies.len()),
                );
            }
        }
        if !sim.report.arrival_ms.is_empty() {
            for (q, name) in [(0.5, "p50"), (0.95, "p95")] {
                super::perf::row(
                    &format!("P2b block relay to a peer ({name})"),
                    sim.report.pct(q) as f64 / 1e3,
                    "s",
                    None,
                    &format!("sim, Tor physics, node CPU charged, {} arrival(s)", sim.report.arrival_ms.len()),
                );
            }
        }
    }

    /// The wallet's OWN full balance reply (verdict, reason, owned / pending / confirming) — what a wallet-side failure names.
    fn wallet_says(sim: &mut NetSim, w: &crate::harness::real_node_journey::wallet::RealWallet) -> String {
        // the repayment pot (§BR-3 17.5, the Borrow page's figure) rides every balance read: the one wallet command the
        // journey never drove (a T0 coverage surface in the hole scanner) — read, never asserted on here
        match wrun(sim, w, &["refresh", "balance", "repayment_pot"], 180) {
            Ok(l) => match op_line(&l, "balance") {
                Some(v) => {
                    let r = &v["result"];
                    format!(
                        "wallet says: atomic {} · verdict {} ({}) · owned {} · pending {} · confirming {} · pending change {} · its reasons: {:?}",
                        r["atomic"], r["verdict"], r["verdict_reason"], r["owned_notes"], r["pending_atomic"], r["confirming_atomic"],
                        r["pending_change_atomic"],
                        w.last_reasons(8)
                    )
                }
                None => format!("wallet printed no balance line ({} lines)", l.len()),
            },
            Err(e) => format!("wallet balance failed: {e}"),
        }
    }

    /// A real wallet's send on its own thread, the mesh running; `(ok, the wallet's own seconds)` or the failure.
    fn send(sim: &mut NetSim, w: &crate::harness::real_node_journey::wallet::RealWallet, to: &str, amount: &str, secs: u64) -> Result<f64, String> {
        crate::harness::sim_coverage::note_wallet("send");
        let h = w.spawn_send(to, amount);
        let (sim_t0, t0) = (sim.now, std::time::Instant::now());
        while !h.is_finished() {
            if !within_budget(sim, sim_t0, t0, secs) {
                return Err(format!(
                    "the send of {amount} did not finish within {secs} simulated s ({} s wall)",
                    t0.elapsed().as_secs()
                ));
            }
            sim.run(500, 10_000);
        }
        match h.join() {
            Ok((true, s)) => Ok(s),
            Ok((false, s)) => Err(format!("the wallet reported the send of {amount} FAILED after {s:.1} s")),
            Err(_) => Err("the send thread panicked".into()),
        }
    }

    /// How long a received payment takes to become SPENDABLE, in SIMULATED seconds, derived from the protocol's own cadence —
    /// never tuned to pass: its record folds `record_fold_depth` selected-chain steps deep; a note the applied stream did not
    /// catch at arrival is located only once its OLI epoch closes (`oli::EPOCH_BLOCKS` more records); its witness windows
    /// complete a few steps later (+8); each step is at worst one block per node relay floor (`PRODUCTION_RELAY_FLOOR_MS`, a
    /// lone producer) or the simulator's own produce cadence if slower; twice that bound.
    /// MEASURED 2026-10-06: the old form assumed one block per 250 ms relay tick and omitted the epoch — 20 s, floored to 300
    /// wall s — while the fast-lane mesh produced one block per ~2 s and an OLI-found note waits for its epoch.
    fn spendable_within_s(sim: &NetSim) -> u64 {
        let step = sim.production_step_ms();
        (sim.params.record_fold_depth + crate::oli::EPOCH_BLOCKS + 8) * step * 2 / 1000
    }

    /// The journey body — the LIVE Tier-1 gate's steps on two simulated nodes, funded the way the gate funds (the faucet, to a
    /// real wallet) and driven by the SHIPPED wallet (`wallet-harness`) over each node's production RPC. MEASURED 2026-10-06:
    /// a node-staged bridge credit with no attestors is (correctly) refused at fold — `[credit-auth] UNATTESTED` — so a
    /// journey funded that way can never spend; the gate's own funding path is the only honest one.
    fn tier1(sim: &mut NetSim, v: &mut Vec<(&'static str, &'static str, String)>, wall: &std::time::Instant) -> Option<()> {
        let (w1, w2, url0, _url1, within) = fund_pair(sim, v, wall, "sim")?;
        tier1_restarts(sim, v, wall, &w1, &w2, &url0, within)?;
        tier2(sim, v, wall, &w1, &w2, within)?;
        tier3(sim, v, wall, &w1, &w2, within)
    }

    /// ⭐ R8 — THE SET-ASIDE A LAUNCH RUN STANDS IN. This build's canonical `sat_set_aside.bin` is empty (no set-aside on this
    /// network), so the §BR-13 door would never fire in the simulator; a launch run stands in a test canonical set-aside (750,000
    /// SAT out of the 2M bound, the fixture key of `br13_the_canonical_set_aside_applies_once…`) BEFORE its mesh boots — node
    /// 0's producer offers it, every node applies it once — and clears it when the run ends.
    fn stand_in_set_aside() -> crate::sat_set_aside::SatSetAsideTx {
        use usdm_decider::poseidon2_compress::lanes_of;
        let dev = usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0xde5, 1, 1, 1])).opening();
        let t = crate::sat_set_aside::build_for_test(750_000 * crate::satoshi::BASE_UNITS_PER_SAT, dev, crate::satoshi::SAT_SET_ASIDE_MAX)
            .expect("the stand-in set-aside proves");
        crate::sat_set_aside::set_canonical_for_test(Some(t.encode()));
        t
    }

    /// The first node that holds the canonical set-aside publishes it (`sat_set_aside` module doc) — here node `i`'s own pool
    /// door, exactly as its producer would offer it. MEASURED (o3-chain-rows-pair.log): the producer's test-build offer is a
    /// thread-local lever the simulator's production loop never sees, so no block carried the stand-in; the journey offers it.
    fn offer_set_aside_on(sim: &mut NetSim, i: usize, canonical: &crate::sat_set_aside::SatSetAsideTx) {
        let out = sim.rt(i).node_mut().publish_sat_set_aside(canonical);
        assert!(
            matches!(out, crate::node::AssetSpendOutcome::Published),
            "PRECONDITION: node {i}'s pool door admits the canonical set-aside"
        );
    }

    /// ⭐ R8 — THE §BR-3 AND §BR-11 ACCEPTANCE ROWS AS LAUNCH STEPS, read from EVERY up node after tier 3 (which bonded node 0's
    /// seat, matured it, unbonded and saw the release on every node, then delegated): §BR-3 — one `/get_validator_bond` record
    /// for the journey's seat everywhere (custody released to 0, `retired`, the governed unbonding window of
    /// `params::UNBONDING_BLOCKS_DEFAULT` = 21 days named by every node's delegation-targets answer) and one delegation-targets
    /// list everywhere; §BR-11 — one `/miner_pool` answer (quarter + per-block rate, never a balance) everywhere, and the pools'
    /// miner word one figure everywhere. The rows' deeper facts (yield pro rata, slashing layers, quarterly conservation) are
    /// their unit pins; the launch step is what every node in the mesh agrees it holds.
    /// TWO-PARTY-REVIEWED: every up node is read; a node that differs fails the step naming it.
    fn tier_bond_rows(sim: &mut NetSim, v: &mut Vec<(&'static str, &'static str, String)>, wall: &std::time::Instant) -> Option<()> {
        let up: Vec<usize> = (0..sim.rts.len()).filter(|i| !sim.is_down(*i)).collect();
        if up.len() < 2 {
            return fail(sim, v, "§BR-3", format!("fewer than two nodes are up ({up:?}): nothing to compare"), wall);
        }
        let vid = serde_json::from_str::<serde_json::Value>(&sim.rpc(0, "GET", "/validator_id", "").1)
            .ok()
            .and_then(|j| j["validator_id_hex"].as_str().map(str::to_string));
        let Some(vid) = vid else {
            return fail(sim, v, "§BR-3", "node 0 answers no vote identity at /validator_id (tier 3 bonded it)".into(), wall);
        };
        let read = |s: &NetSim, i: usize| -> serde_json::Value {
            serde_json::from_str(&s.rpc(i, "POST", "/get_validator_bond", &format!(r#"{{"voter_id":"{vid}"}}"#)).1).unwrap_or_default()
        };
        let first = read(sim, up[0]);
        for &i in &up[1..] {
            let r = read(sim, i);
            for k in ["custody_sat", "bond", "retired", "unbond_matures_at_blue", "required_bond_floor"] {
                if r[k] != first[k] {
                    return fail(sim, v, "§BR-3", format!("node {i} answers {k} = {} for the journey's seat, node {} {}", r[k], up[0], first[k]), wall);
                }
            }
        }
        if first["custody_sat"].as_u64() != Some(0) {
            return fail(sim, v, "§BR-3", format!("the released seat still holds custody on every node: {}", first["custody_sat"]), wall);
        }
        let targets = |s: &NetSim, i: usize| -> serde_json::Value {
            serde_json::from_str(&s.rpc(i, "GET", "/get_delegation_targets", "").1).unwrap_or_default()
        };
        let t0 = targets(sim, up[0]);
        for &i in &up[1..] {
            let t = targets(sim, i);
            if t["targets"] != t0["targets"] || t["unbond_window"] != t0["unbond_window"] {
                return fail(sim, v, "§BR-3", format!("node {i} publishes other delegation targets or another unbonding window than node {}", up[0]), wall);
            }
        }
        // the window every node publishes is the GOVERNED one (a launch mesh may govern it short so T3's maturity fits a leg;
        // the 21-day default, `params::UNBONDING_BLOCKS_DEFAULT`, is pinned by `br3_the_unbonding_window_is_21_days_by_default…`)
        let Some(window) = t0["unbond_window"].as_u64() else {
            return fail(sim, v, "§BR-3", format!("node {} publishes no unbonding window: {t0}", up[0]), wall);
        };
        pass_inv(sim, v, "§BR-3", format!("{} nodes answer one released record for seat {}… (custody 0, retired {}) and one governed unbonding window ({window} blocks; the default is {})", up.len(), &vid[..vid.len().min(12)], first["retired"], crate::params::UNBONDING_BLOCKS_DEFAULT), wall)?;
        // §BR-11
        let pool = |s: &NetSim, i: usize| -> serde_json::Value { serde_json::from_str(&s.rpc(i, "GET", "/miner_pool", "").1).unwrap_or_default() };
        let p0 = pool(sim, up[0]);
        for &i in &up[1..] {
            let p = pool(sim, i);
            if p["quarter"] != p0["quarter"] || p["per_block_atomic"] != p0["per_block_atomic"] {
                return fail(sim, v, "§BR-11", format!("node {i} publishes miner pool {p}, node {} {p0}", up[0]), wall);
            }
            if p.get("balance").is_some() || p.get("pool_atomic").is_some() {
                return fail(sim, v, "§BR-11", format!("node {i} publishes the miner pool's balance: {p}"), wall);
            }
        }
        let words: Vec<u64> = up.iter().map(|&i| sim.rt(i).node().peg().fee_pools().miner).collect();
        if words.iter().any(|w| *w != words[0]) {
            return fail(sim, v, "§BR-11", format!("the pools' miner word differs across the up nodes: {words:?}"), wall);
        }
        pass_inv(sim, v, "§BR-11", format!("{} nodes publish one miner-pool answer {p0} and hold one miner word {}", up.len(), words[0]), wall)
    }

    /// ⭐ R8 — THE §BR-13 AND §BR-14 ACCEPTANCE ROWS AS LAUNCH STEPS: chain facts read from EVERY up node after the tiers' spends
    /// (T1.2/T1.4/T1.7's sends, T2's creation and fill), the replicated-state shape every launch step takes. §BR-13: the
    /// canonical set-aside applied everywhere, one issued-SAT figure everywhere, under `SATOSHI_CAP`. §BR-14: one set of four
    /// fee pools everywhere, non-empty, in the era's split (`peg_arith::fee_split_at`: stakers 40 %, bonders 25 %, surplus 25 %,
    /// miner 10 % in eras 0–1, the rounding remainder to the surplus) — four pools and no fifth (no founder share).
    /// TWO-PARTY-REVIEWED: every up node is read; a node that differs fails the step naming it.
    fn tier_chain_rows(sim: &mut NetSim, v: &mut Vec<(&'static str, &'static str, String)>, wall: &std::time::Instant) -> Option<()> {
        let up: Vec<usize> = (0..sim.rts.len()).filter(|i| !sim.is_down(*i)).collect();
        if up.len() < 2 {
            return fail(sim, v, "§BR-13", format!("fewer than two nodes are up ({up:?}): nothing to compare"), wall);
        }
        // §BR-13 — the canonical object this run carries (the build's bytes, or the one a launch run stands in: this build's
        // `sat_set_aside.bin` is EMPTY, so without a stand-in the door never fires in the simulator)
        let Some(canonical) = crate::sat_set_aside::canonical_bytes().and_then(|b| crate::sat_set_aside::SatSetAsideTx::decode(&b)) else {
            return fail(sim, v, "§BR-13", "this run carries no canonical SAT set-aside: the door was never exercised".into(), wall);
        };
        let Some(cm) = canonical.note_cm() else {
            return fail(sim, v, "§BR-13", "the canonical set-aside names no note".into(), wall);
        };
        // ⭐ 2026-11-03 (c27-chainrows.log): the supply word is a function of the canonical FOLD — read at one instant, a node
        // two records ahead reads two rewards more ("node 1 has issued 391347840, node 0 398873760" = 2 × 3,762,960). The claim
        // is one word at one fold position (T1.6's own rule, `fold_point_newest`): wait, bounded, until every up node stands
        // at the same canonical fold ordinal, then read every word at that instant; a mesh that never levels fails by name.
        let up_for_wait = up.clone();
        let levelled = run_until(sim, 180_000, |s| {
            let points: Vec<Option<u64>> = up_for_wait.iter().map(|&i| s.rt(i).node().fold_point_newest()).collect();
            points.iter().all(|p| p.is_some()) && points.windows(2).all(|w| w[0] == w[1])
        });
        if levelled.is_none() {
            let points: Vec<(usize, Option<u64>)> = up.iter().map(|&i| (i, sim.rt(i).node().fold_point_newest())).collect();
            return fail(sim, v, "§BR-13", format!("the up nodes never stood at one canonical fold ordinal within 180 s: {points:?}"), wall);
        }
        let facts: Vec<(usize, bool, u64)> = up.iter().map(|&i| { let g = sim.rt(i); let p = g.node().peg(); (i, p.set_aside_applied(), p.sat_issued()) }).collect();
        if let Some((i, _, _)) = facts.iter().find(|(_, applied, _)| !applied) {
            return fail(sim, v, "§BR-13", format!("node {i} has not applied the canonical SAT set-aside"), wall);
        }
        for &i in &up {
            let g = sim.rt(i);
            if !g.node().holds_record_with_cm(&cm) {
                return fail(sim, v, "§BR-13", format!("node {i} applied the set-aside but holds no record of its note"), wall);
            }
            if g.node().set_aside_refusal(&canonical) != Some("the set-aside has already applied") {
                return fail(sim, v, "§BR-13", format!("node {i} would apply the set-aside a second time"), wall);
            }
        }
        let issued = facts[0].2;
        if let Some((i, _, s)) = facts.iter().find(|(_, _, s)| *s != issued) {
            return fail(sim, v, "§BR-13", format!("node {i} has issued {s} SAT base units, node {} {issued}", facts[0].0), wall);
        }
        if issued == 0 || issued > crate::sat_schedule::SATOSHI_CAP {
            return fail(sim, v, "§BR-13", format!("issued SAT {issued} is zero or past the cap {}", crate::sat_schedule::SATOSHI_CAP), wall);
        }
        pass_inv(sim, v, "§BR-13", format!("the set-aside applied ONCE on {} nodes, each holds its note and refuses a second; SAT issued {issued} (cap {}) on every one", up.len(), crate::sat_schedule::SATOSHI_CAP), wall)?;
        // §BR-14
        let pools: Vec<(usize, crate::peg::FeePools)> = up.iter().map(|&i| (i, sim.rt(i).node().peg().fee_pools())).collect();
        let first = pools[0].1;
        if let Some((i, p)) = pools.iter().find(|(_, p)| *p != first) {
            return fail(sim, v, "§BR-14", format!("node {i} holds fee pools {p:?}, node {} {first:?}", pools[0].0), wall);
        }
        let total = first.total();
        if total == 0 {
            return fail(sim, v, "§BR-14", "the fee pools are empty after the journey's spends".into(), wall);
        }
        let (st, bo, su, mi) = crate::peg_arith::fee_split_at(u64::try_from(total).unwrap_or(u64::MAX), 0);
        // each credit rounds its remainder to the surplus: the pools match the split of the total within one unit per credit
        let near = |have: u64, want: u64| have.abs_diff(want) <= (total / 100) as u64 + 8;
        if !(near(first.stakers, st) && near(first.bonders, bo) && near(first.surplus, su) && near(first.miner, mi)) {
            return fail(sim, v, "§BR-14", format!("the pools {first:?} are not the 40/25/25/10 split of their total {total} (want {st}/{bo}/{su}/{mi})"), wall);
        }
        pass_inv(sim, v, "§BR-14", format!("{} nodes hold one set of pools {first:?} (total {total}, split 40/25/25/10)", up.len()), wall)
    }

    /// ⭐ R8 — THE §BR-12 AND F13 ACCEPTANCE ROWS AS LAUNCH STEPS (chain-tracks §NETSIM-LAUNCH: "a row is not done until it
    /// is a launch step"). The PUBLISHER is a real wallet on node 1: it deploys the fixture contract at a $0.50 publisher fee
    /// through the one deploy builder (`dsoldeploy`), paying the deploy price; node 0 — fed by the mesh alone — folds the same
    /// contract-state root ("§BR-12", first half). The CALLER is a real wallet on node 0 running the exact core path the
    /// shipped UI runs after its dollar dialog (`dsolcall` = `dapp_provider_dsol_call`): it verifies the app's manifest against
    /// the chain's root, pays the deployed fee into the publisher's public opening and proves the call; node 1 folds the
    /// post-call root ("§BR-12", second half) and the publisher's wallet, reading its own node, holds exactly the fee the
    /// manifest named ("F13"). Both wallets are funded by the faucet the way the gate funds. The UI dialog itself is F13's
    /// layer-1 pin and the shipped-UI layer-2 journey (`harness::ui_layer2`); here the chain's half rides the launch run.
    /// TWO-PARTY-REVIEWED: the deploy is asserted on node 0 from node 1's object, the call on node 1 from node 0's object.
    fn tier_dsol(sim: &mut NetSim, v: &mut Vec<(&'static str, &'static str, String)>, wall: &std::time::Instant) -> Option<()> {
        use crate::harness::real_node_journey::wallet::RealWallet;
        // hex helpers of this module's own (`ui_layer2` is configured out of the pins-node family)
        fn hex_of(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        fn hex32_of(s: Option<&str>) -> Option<[u8; 32]> {
            let s = s?.trim();
            if s.len() != 64 {
                return None;
            }
            let mut out = [0u8; 32];
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
            }
            Some(out)
        }
        let (url0, url1) = (sim.serve_rpc(0), sim.serve_rpc(1));
        let within = spendable_within_s(sim);
        let mk = |sim: &mut NetSim, role: &'static str, url: String| {
            while_meshing(sim, 300, move || RealWallet::create("dsol", role, &url)).unwrap_or_else(|| Err("wallet create did not finish within 300 s".into()))
        };
        let publisher = match mk(sim, "publisher", url1) {
            Ok(w) => w,
            Err(e) => return failed(sim, v, "§BR-12", format!("the publisher's wallet could not be created on node 1: {e}"), wall),
        };
        let caller = match mk(sim, "caller", url0) {
            Ok(w) => w,
            Err(e) => return failed(sim, v, "§BR-12", format!("the caller's wallet could not be created on node 0: {e}"), wall),
        };
        for (i, w) in [(1usize, &publisher), (0usize, &caller)] {
            let (code, body) = sim.rpc(i, "POST", "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{}"}}"#, w.address));
            if code != 200 {
                return failed(sim, v, "§BR-12", format!("the faucet on node {i} refused: {code} {}", body.chars().take(200).collect::<String>()), wall);
            }
        }
        if balance_until(sim, &publisher, within, |b| b >= 2_500_000_000) < 2_500_000_000 {
            return failed(sim, v, "§BR-12", format!("the publisher never read its faucet credit within {within} s"), wall);
        }
        if balance_until(sim, &caller, within, |b| b >= 2_500_000_000) < 2_500_000_000 {
            return failed(sim, v, "§BR-12", format!("the caller never read its faucet credit within {within} s"), wall);
        }
        // the deploy, from the publisher's wallet on node 1
        let code_hex = hex_of(&crate::dsol_call_tx::fixtures::program());
        let deploy_cmd = format!("dsoldeploy {code_hex} {} launch-fixture 0.5", crate::dsol_call_tx::fixtures::HEIGHT_CLASS);
        let p = publisher.clone_handle();
        crate::harness::sim_coverage::note_wallet("dsoldeploy");
        let Some((ok, _secs, reply)) = while_meshing(sim, 600, move || p.pay_in_session(&deploy_cmd, "dsoldeploy", 600)) else {
            return failed(sim, v, "§BR-12", "the deploy did not finish within 600 s".into(), wall);
        };
        if !ok {
            return failed(sim, v, "§BR-12", format!("the publisher's deploy was refused: {}", reply.chars().take(400).collect::<String>()), wall);
        }
        let dep: serde_json::Value = serde_json::from_str(&reply).map(|r: serde_json::Value| r["result"].clone()).unwrap_or_default();
        let (Some(cid), Some(leaf_bytes)) = (hex32_of(dep["cid"].as_str()), hex32_of(dep["leaf_hex"].as_str())) else {
            return failed(sim, v, "§BR-12", format!("the deploy answer names no cid/leaf: {}", reply.chars().take(400).collect::<String>()), wall);
        };
        let Some(leaf) = crate::spend_frontier::cm_bytes_to_root(&leaf_bytes) else {
            return failed(sim, v, "§BR-12", "the deploy's leaf is not a canonical digest".into(), wall);
        };
        let mut tree = crate::contract_state::ContractStateTree::new();
        tree.insert(cid, leaf);
        let want_root = hex_of(&crate::spend_frontier::leaf_to_cm_bytes(tree.root()));
        let root_of = |s: &NetSim, i: usize| -> String {
            serde_json::from_str::<serde_json::Value>(&s.rpc(i, "GET", "/contract_state_root", "").1)
                .ok()
                .and_then(|j| j["root"].as_str().map(String::from))
                .unwrap_or_default()
        };
        let wr = want_root.clone();
        let both = run_until(sim, within * 1_000, move |s| root_of(s, 0) == wr && root_of(s, 1) == wr);
        if both.is_none() {
            return fail(sim, v, "§BR-12", format!("the deploy did not reach both nodes' contract-state roots within {within} s (want {want_root}; node0 {}, node1 {})", root_of(sim, 0), root_of(sim, 1)), wall);
        }
        // the call, from the caller's wallet on node 0: the exact core path the shipped UI runs after its dollar dialog
        let path = tree.path(&cid);
        let call = serde_json::json!({
            "cid": hex_of(&cid),
            "manifest": dep["manifest"].clone(),
            "view_ek": dep["view_ek_hex"].clone(),
            "code": code_hex,
            "entrypoint": "main",
            "argv": "",
            "height_class": crate::dsol_call_tx::fixtures::HEIGHT_CLASS,
            "storage": [],
            "state_path": { "mask": hex_of(&path.mask), "sibs": path.sibs.iter().map(|s| hex_of(s)).collect::<Vec<_>>() },
        });
        let fee_atomic = dep["manifest"]["publisher_fee_atomic"].as_u64().unwrap_or(0);
        if fee_atomic != 50_000_000 {
            return fail(sim, v, "§BR-12", format!("the deploy carries fee {fee_atomic}, not the $0.50 the publisher set"), wall);
        }
        let before = balance_until(sim, &publisher, within, |_| true);
        let c = caller.clone_handle();
        let call_cmd = format!("dsolcall {call}");
        crate::harness::sim_coverage::note_wallet("dsolcall");
        let call_t0 = sim.now;
        let Some((ok, secs, reply)) = while_meshing_paced(sim, 900, move || c.pay_in_session(&call_cmd, "dsolcall", 900)) else {
            return failed(sim, v, "§BR-12", "the call did not finish within 900 s".into(), wall);
        };
        if !ok {
            return failed(sim, v, "§BR-12", format!("the caller's call was refused after {secs:.1} s: {}", reply.chars().take(400).collect::<String>()), wall);
        }
        let res: serde_json::Value = serde_json::from_str(&reply).map(|r: serde_json::Value| r["result"].clone()).unwrap_or_default();
        let Some(storage_post) = hex32_of(res["storage_post_hex"].as_str()).and_then(|b| crate::spend_frontier::cm_bytes_to_root(&b)) else {
            return failed(sim, v, "§BR-12", format!("the call answer names no post storage: {}", reply.chars().take(400).collect::<String>()), wall);
        };
        let (Some(code_id), Some(spk), Some(deployer)) =
            (hex32_of(dep["manifest"]["code_id"].as_str()), hex32_of(dep["manifest"]["publisher_spk"].as_str()), hex32_of(dep["manifest"]["deployer_id"].as_str()))
        else {
            return failed(sim, v, "§BR-12", "the deploy's manifest is not readable".into(), wall);
        };
        let manifest = crate::dsol_deploy_tx::ContractManifest { code_id, publisher_fee_le: fee_atomic.to_le_bytes(), publisher_spk: spk, deployer_id: deployer, kc_commit: [0u8; 32], height_class: 0 };
        let mut after = tree.clone();
        after.insert(cid, manifest.leaf(storage_post));
        let want_after = hex_of(&crate::spend_frontier::leaf_to_cm_bytes(after.root()));
        let wa = want_after.clone();
        let peer = run_until(sim, within * 1_000, move |s| root_of(s, 1) == wa);
        if peer.is_none() {
            return fail(sim, v, "§BR-12", format!("node 1's contract-state root did not move to the post-call leaf within {within} s (want {want_after}; has {})", root_of(sim, 1)), wall);
        }
        super::perf::row("P-DSOL a paid contract call: submit → the peer folds it", (sim.now - call_t0) as f64 / 1e3, "s", None, "sim chain wait after the wallet's proof (wallet wall not included)");
        pass_inv(sim, v, "§BR-12", format!("deploy on node 1 → root on node 0; call on node 0 → root on node 1 ({} s wallet wall for the call)", secs as u64), wall)?;
        // F13: the fee the manifest named is the fee the publisher's own node shows it holding
        let got = balance_until(sim, &publisher, within, |b| b >= before + fee_atomic);
        if got < before + fee_atomic {
            // which half broke: does the chain hold the fee note, or does the wallet not read it?
            let cm = hex32_of(res["tx_hash"].as_str())
                .and_then(|h| crate::dsol_call_tx::publisher_fee_cm(&manifest, &cid, &h))
                .map(|d| crate::spend_frontier::leaf_to_cm_bytes(d));
            let held: Vec<bool> = cm.map_or(Vec::new(), |c| (0..2).map(|i| sim.rt(i).node().holds_record_with_cm(&c)).collect());
            return fail(sim, v, "F13", format!("the publisher holds {got} atomic on node 1, not the {} it had plus the $0.50 the manifest named; the fee note's record is held on nodes [0, 1]: {held:?}", before), wall);
        }
        if res["publisher_fee_atomic"].as_u64() != Some(fee_atomic) {
            return fail(sim, v, "F13", format!("the core paid {:?}, not the manifest's {fee_atomic}", res["publisher_fee_atomic"]), wall);
        }
        pass_inv(sim, v, "F13", format!("the manifest named $0.50 and the publisher's wallet on node 1 holds exactly that more ({before} → {got})"), wall)
    }

    /// T1.0–T1.2: one chain, W1 funded by the faucet through node 0, W1 pays W2 (on node 1) 3.0 and W2 reads it there.
    #[allow(clippy::type_complexity)]
    fn fund_pair(
        sim: &mut NetSim,
        v: &mut Vec<(&'static str, &'static str, String)>,
        wall: &std::time::Instant,
        tag: &'static str,
    ) -> Option<(
        crate::harness::real_node_journey::wallet::RealWallet,
        crate::harness::real_node_journey::wallet::RealWallet,
        String,
        String,
        u64,
    )> {
        use crate::harness::real_node_journey::wallet::RealWallet;
        let t = run_until(sim, 120_000, |s| s.one_chain_between(0, 1));
        pass(v, "T1.0", t.is_some(), format!("one chain after {t:?} sim ms"), wall)?;
        let (url0, url1) = (sim.serve_rpc(0), sim.serve_rpc(1));
        let mk = |sim: &mut NetSim, role: &'static str, url: String| {
            while_meshing(sim, 300, move || RealWallet::create(tag, role, &url))
                .unwrap_or_else(|| Err("wallet create did not finish within 300 s".into()))
        };
        let w1 = match mk(sim, "w1", url0.clone()) {
            Ok(w) => w,
            Err(e) => return failed(sim, v, "T1.1", format!("the real wallet could not be created on node 0: {e}"), wall),
        };
        let w2 = match mk(sim, "w2", url1.clone()) {
            Ok(w) => w,
            Err(e) => return failed(sim, v, "T1.1", format!("the real wallet could not be created on node 1: {e}"), wall),
        };
        let (code, body) = sim.rpc(0, "POST", "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{}"}}"#, w1.address));
        if code != 200 {
            return failed(sim, v, "T1.1", format!("the faucet refused W1: {code} {}", body.chars().take(240).collect::<String>()), wall);
        }
        let within = spendable_within_s(sim);
        let funded = balance_until(sim, &w1, within, |b| b > 0);
        if funded == 0 {
            return failed(sim, v, "T1.1", format!("W1 never read the faucet credit within {within} s"), wall);
        }
        pass_inv(sim, v, "T1.1", format!("W1 funded {funded} through node 0"), wall)?;
        let sim_before_send = sim.now;
        let send_wall_s = match send(sim, &w1, &w2.address, "3.0", within) {
            Ok(s) => s,
            Err(e) => return failed(sim, v, "T1.2", e, wall),
        };
        let sent_at = sim.now;
        let (got, seen, ready, poll_ms) = receive_timed(sim, &w2, within, 0, sent_at);
        payment_rows(sim, "T1.2", send_wall_s, sent_at - sim_before_send, seen, ready, poll_ms);
        if got == 0 {
            return failed(sim, v, "T1.2", format!("W2 (on node 1) never read W1's 3.0 within {within} s"), wall);
        }
        pass_inv(sim, v, "T1.2", format!("W2 read {got} through node 1"), wall)?;
        Some((w1, w2, url0, url1, within))
    }

    /// T1.3–T1.7 (the restarts, the restore, the join, the wallet across its node's restart). Tier 1 only: [`tier1`] chains
    /// T2 and T3 after it; the real journey's legs run each tier in its own process.
    fn tier1_restarts(
        sim: &mut NetSim,
        v: &mut Vec<(&'static str, &'static str, String)>,
        wall: &std::time::Instant,
        w1: &crate::harness::real_node_journey::wallet::RealWallet,
        w2: &crate::harness::real_node_journey::wallet::RealWallet,
        url0: &str,
        within: u64,
    ) -> Option<()> {
        let (w1, w2) = (w1, w2);
        // T1.3 — the rolling restart, in the gate's order (the joiner, then the origin), each process down 5 s
        for i in [1usize, 0] {
            if let Err(e) = sim.restart(i, 5_000) {
                return fail(sim, v, "T1.3", format!("node {i} could not boot from its own files: {e}"), wall);
            }
            let back = run_until(sim, 30_000, |s| !s.is_down(i) && view_current(s, i));
            // PERF P9: a restarted node back to serving (its process up, its nullifier view current) — the 5 s it was down
            // is the operator's, not the node's
            super::perf::row(
                &format!("P9 restart → node {i} serving again"),
                back.map_or(f64::INFINITY, |t| t.saturating_sub(5_000) as f64 / 1e3),
                "s",
                None,
                &format!("sim, boot from its own files to a current view, tip height {} (P14 judges flatness)", sim.rt(i).node().tip_height()),
            );
        }
        let t = run_until(sim, 240_000, |s| view_current(s, 0) && view_current(s, 1) && s.one_chain_between(0, 1) && same_roots(s));
        let (i0, i1) = (info(sim, 0), info(sim, 1));
        let detail = format!(
            "after {t:?} sim ms: n0 view {}/{} wedged {} · n1 view {}/{} wedged {} · one chain {} · roots equal {}",
            i0["nf_view_present"], i0["nf_view_matches_acc"], i0["fold_wedged"], i1["nf_view_present"], i1["nf_view_matches_acc"],
            i1["fold_wedged"], sim.one_chain_between(0, 1), same_roots(sim)
        );
        if t.is_none() {
            return fail(sim, v, "T1.3", detail, wall);
        }
        pass_inv(sim, v, "T1.3", detail, wall)?;
        // T1.4 — after the restarts the receiver pays back through ITS node; the payer reads it through the OTHER node
        let before = balance_until(sim, &w1, within, |b| b > 0);
        if before == 0 {
            let w1s = wallet_says(sim, &w1);
            return fail(sim, v, "T1.4", format!("after the rolling restart W1 (node 0) reads 0 — custody lost across the restart · W1 {w1s}"), wall);
        }
        let sim_before_send = sim.now;
        let send_wall_s = match send(sim, &w2, &w1.address, "1.0", within) {
            Ok(s) => s,
            Err(e) => return fail(sim, v, "T1.4", format!("after the restarts W2 could not send: {e}"), wall),
        };
        let sent_at = sim.now;
        let (after, seen, ready, poll_ms) = receive_timed(sim, &w1, within, before, sent_at);
        payment_rows(sim, "T1.4", send_wall_s, sent_at - sim_before_send, seen, ready, poll_ms);
        if after <= before {
            let w1s = wallet_says(sim, &w1);
            return fail(sim, v, "T1.4", format!("W1 (node 0) never read W2's post-restart 1.0: {before} → {after} · W1 {w1s}"), wall);
        }
        pass_inv(sim, v, "T1.4", format!("W1 read {before} → {after} through node 0"), wall)?;
        // T1.5 — the receiver restored from its seed on the OTHER node reads the same balance
        let w2_now = balance_until(sim, w2, 120, |_| true);
        let restored = match while_meshing(sim, 300, {
            let r = w2.restored_elsewhere_for_test("w2r", url0);
            move || r
        }) {
            Some(Ok(r)) => r,
            Some(Err(e)) => return fail(sim, v, "T1.5", format!("W2 could not be restored from its seed on node 0: {e}"), wall),
            None => return fail(sim, v, "T1.5", "W2's seed restore did not finish within 300 s".to_string(), wall),
        };
        let back = balance_until(sim, &restored, within, |b| b >= w2_now);
        if back < w2_now {
            return fail(sim, v, "T1.5", format!("W2 restored on node 0 reads {back}, W2 on node 1 reads {w2_now}"), wall);
        }
        pass_inv(sim, v, "T1.5", format!("W2 restored on node 0 reads {back} (on node 1: {w2_now})"), wall)?;
        // T1.6 — a FRESH node joins (empty datadir, production boot, the runtime's own DSYNC), reaches the tip with the same
        // state, and a wallet restored from W2's seed against IT reads W2's balance
        if sim.rts.len() > 2 {
            // ⭐ THE SAME STATE AT THE SAME CHAIN POINT (Ethereum's STF): the joiner's unspent root is compared with the root
            // node 0 held at the SAME fold position (`nf_fold_seq`, chain-derived — D-47 makes a jump inherit it), never
            // with node 0's root at the same INSTANT. MEASURED sim-20261006-183505-tier1: one chain true, views current,
            // and the instant roots still differed for 832 s because node 0's fold sat 2 ordinals behind the joiner's
            // (fold_wait 17 vs 13) — two live folds a block apart never read equal in one step, so T1.6 passed or failed
            // on the schedule. The joiner must also have folded at least to where node 0 stood when it booted (caught up,
            // not merely adopted an older bundle), and a DIFFERENT root at the same position fails at once: that is a fork
            // of state, not a lag.
            //
            // ⛔ AND "THE SAME FOLD POSITION" IS THE SAME FOLDED SET, NOT THE SAME COUNT. A_tip folds at ACCEPT, in each
            // node's ARRIVAL order (`fold_atip_at_accept`), and `unspent_root` is its SUM — a function of the folded SET
            // (`nf_unspent_step_new_acc`: "two nodes that folded the same blocks hold the same tip in any order"). Two
            // concurrent blocks A and B arriving in opposite orders leave node 0 holding {…, A} and the joiner {…, B} at
            // count k, and both {…, A, B} at k + 1: equal state, a different root at the same count, and "the joiner's
            // root equals at neither neighbour" — exactly the red sim-20261006-200352-tier1 reported as a FORKED STATE.
            // So a count is a chain position only together with the DAG it was counted over: node 0's roots are keyed
            // by (count, tips), and a FORK is the same count over the same tips (the same DAG) with a different root.
            // A same-count mismatch over different tips is printed as evidence (`[t1.6-count]`), never a verdict.
            let seq_root = |s: &NetSim, i: usize| {
                let x = info(s, i);
                let mut tips: Vec<String> = s.rt(i).node().dag().tips().iter().map(|t| t.to_hex()).collect();
                tips.sort();
                (x["nf_fold_seq"].as_u64(), x["unspent_root"].as_str().map(str::to_string), tips)
            };
            let boot_seq = seq_root(sim, 0).0.unwrap_or(0);
            // ⭐ THE CANONICAL CHAIN POINT (link 30, the T1.6 alignment race): the (count, tips) key below matches only when
            // the joiner's DAG equals one node 0 HELD at a sampled instant — a quiet moment. MEASURED
            // night/simpar-20261008-003021 seed 0x3: under SIM_PAR=4 the joiner trailed node 0 by 4 fold positions (1,232 vs
            // 1,236) for the whole 832 s budget, one chain and views true, and no sampled instant ever matched; the same
            // binary solo joined at 160 s. The node already keeps the state a function of the chain: its spine root and its
            // band root per CANONICAL fold ordinal (the anchor ring and the band ring, 3,600 steps each). So the same state
            // is also read there — both nodes' (spine, band) roots at the newest ordinal BOTH hold, at or past node 0's
            // ordinal when the joiner booted. Equal ⇒ the same state at the same chain point, whatever instant it is read;
            // different while the two are on one chain ⇒ a FORK of state, failed at once (as a same-DAG tip mismatch is).
            let canon_point = |s: &NetSim| -> Option<u64> {
                Some(s.rt(0).node().fold_point_newest()?.min(s.rt(2).node().fold_point_newest()?))
            };
            let boot_ord = sim.rt(0).node().fold_point_newest().unwrap_or(0);
            if let Err(e) = sim.join_fresh(2) {
                return fail(sim, v, "T1.6", format!("the fresh node could not boot: {e}"), wall);
            }
            let mut held0: HashMap<(u64, Vec<String>), String> = HashMap::new();
            let mut by_count0: HashMap<u64, (String, Vec<String>)> = HashMap::new();
            let mut count_only: Vec<u64> = Vec::new();
            let mut forked: Option<String> = None;
            let mut matched_at = String::new();
            let joined = run_until(sim, within * 1000, |s| {
                if let (Some(k), Some(r), tips) = seq_root(s, 0) {
                    by_count0.insert(k, (r.clone(), tips.clone()));
                    held0.insert((k, tips), r);
                }
                let (k2, r2, tips2) = seq_root(s, 2);
                let same_state = match (k2, r2) {
                    (Some(k), Some(r)) if k >= boot_seq => match held0.get(&(k, tips2.clone())) {
                        Some(r0) if *r0 == r => true,
                        Some(r0) => {
                            forked.get_or_insert(format!(
                                "at fold position {k} over the SAME tips ({}) node 0 held unspent root {r0}, the joiner {r} — \
                                 one DAG, two states",
                                tips2.iter().map(|t| &t[..12]).collect::<Vec<_>>().join(",")
                            ));
                            false
                        }
                        None => {
                            if let Some((r0, t0)) = by_count0.get(&k).filter(|(r0, _)| *r0 != r) {
                                if !count_only.contains(&k) {
                                    count_only.push(k);
                                    eprintln!(
                                        "[t1.6-count] fold position {k}: node 0 {} over tips {:?}, the joiner {} over tips {:?} — \
                                         the same count over different DAGs (arrival order), not a verdict",
                                        &r0[..r0.len().min(16)],
                                        t0.iter().map(|t| &t[..12]).collect::<Vec<_>>(),
                                        &r[..r.len().min(16)],
                                        tips2.iter().map(|t| &t[..12]).collect::<Vec<_>>()
                                    );
                                }
                            }
                            false
                        }
                    },
                    _ => false,
                };
                let one_chain = s.one_chain_between(0, 2);
                let same_canon = match canon_point(s).filter(|o| *o >= boot_ord) {
                    Some(o) => match (s.rt(0).node().fold_point_roots_at(o), s.rt(2).node().fold_point_roots_at(o)) {
                        (Some(a), Some(b)) if a == b => true,
                        (Some((sa, ba)), Some((sb, bb))) => {
                            if one_chain {
                                forked.get_or_insert(format!(
                                    "at canonical fold ordinal {o} on one chain node 0 held (spine, band) roots ({sa:?}, {ba:?}), \
                                     the joiner ({sb:?}, {bb:?}) — one chain, two states"
                                ));
                            }
                            false
                        }
                        _ => false,
                    },
                    None => false,
                };
                let done = forked.is_some() || (one_chain && view_current(s, 2) && (same_canon || same_state));
                if done && forked.is_none() {
                    matched_at = match (same_canon, same_state) {
                        (true, true) => format!("canonical fold ordinal {:?} + tip fold position {k2:?}", canon_point(s)),
                        (true, false) => format!("canonical fold ordinal {:?}", canon_point(s)),
                        _ => format!("tip fold position {k2:?}"),
                    };
                }
                done
            });
            // PERF P8: a fresh node's join — boot (empty datadir) to one chain, a current view and node 0's state
            super::perf::row(
                "P8 fresh node join (DSYNC) → at the tip with the same state",
                joined.map_or(f64::INFINITY, |t| t as f64 / 1e3),
                "s",
                None,
                &format!(
                    "sim, node CPU charged, tip height {} (P14 judges flatness) · matched at {matched_at}",
                    sim.rt(0).node().tip_height()
                ),
            );
            if let Some(f) = forked {
                return fail(sim, v, "T1.6", format!("the fresh node FORKED STATE: {f}"), wall);
            }
            if joined.is_none() {
                let (a, c) = (info(sim, 0), info(sim, 2));
                return fail(
                    sim,
                    v,
                    "T1.6",
                    format!(
                        "the fresh node did not reach one chain + a current view + node 0's unspent root at the same fold position \
                         (≥ {boot_seq}) or its (spine, band) roots at the same canonical fold ordinal (≥ {boot_ord}) within {within} s: \
                         one chain {} · canonical fold ordinals {:?} vs {:?} · view {}/{} · fold positions {} vs {} · roots {} vs {} · mesh_joined {} ({})",
                        sim.one_chain_between(0, 2),
                        sim.rt(0).node().fold_point_newest(),
                        sim.rt(2).node().fold_point_newest(),
                        c["nf_view_present"],
                        c["nf_view_matches_acc"],
                        a["nf_fold_seq"],
                        c["nf_fold_seq"],
                        a["unspent_root"],
                        c["unspent_root"],
                        c["mesh_joined"],
                        c["mesh_joined_how"]
                    ),
                    wall,
                );
            }
            let url2 = sim.serve_rpc(2);
            let r2 = match while_meshing(sim, 300, {
                let r = w2.restored_elsewhere_for_test("w2j", &url2);
                move || r
            }) {
                Some(Ok(r)) => r,
                Some(Err(e)) => return fail(sim, v, "T1.6", format!("W2 could not be restored on the joined node: {e}"), wall),
                None => return fail(sim, v, "T1.6", "W2's restore on the joined node did not finish within 300 s".to_string(), wall),
            };
            let on_joiner = balance_until(sim, &r2, within, |b| b >= w2_now);
            if on_joiner < w2_now {
                return fail(sim, v, "T1.6", format!("on the joined node W2 reads {on_joiner}, on node 1 {w2_now}"), wall);
            }
            pass_inv(
                sim,
                v,
                "T1.6",
                format!(
                    "joined after {joined:?} sim ms (how: {}; same state at {matched_at}); W2 reads {on_joiner} there",
                    info(sim, 2)["mesh_joined_how"]
                ),
                wall,
            )?;
        }
        // T1.7 — a wallet whose node restarts under it keeps its balance and spends again. "Kept" is judged against the
        // balance T1.4 left W1 (`after`), read back BEFORE the restart: a first read of 0 made the check vacuous (MEASURED
        // flat@10000: `pre` read 0 after node 0's re-anchor, "kept 0 ≥ 0" passed, and the missing path predated the restart).
        let pre = balance_until(sim, &w1, within, |b| b >= after);
        if pre < after {
            let w1s = wallet_says(sim, &w1);
            return fail(sim, v, "T1.7", format!("before its node's restart W1 reads {pre}, not the {after} T1.4 left it · W1 {w1s}"), wall);
        }
        if let Err(e) = sim.restart(0, 5_000) {
            return fail(sim, v, "T1.7", format!("node 0 could not boot from its files under W1: {e}"), wall);
        }
        let kept = balance_until(sim, &w1, within, |b| b >= pre);
        if kept < pre {
            let w1s = wallet_says(sim, &w1);
            return fail(sim, v, "T1.7", format!("W1's balance fell across its node's restart: {pre} → {kept} · W1 {w1s}"), wall);
        }
        match send(sim, &w1, &w2.address, "0.5", within) {
            Ok(_) => pass_inv(sim, v, "T1.7", format!("W1 kept {kept} across node 0's restart and sent 0.5 after it"), wall)?,
            Err(e) => return fail(sim, v, "T1.7", format!("W1 kept {kept} but could not send after its node's restart: {e}"), wall),
        }
        // T1.7 (cont.) — THE WALLET'S PRIVACY SETTING AND ITS DEPOSIT REFUND, driven on the real wallet: Auto-OPSEC reads ON by
        // default, turns off and back on (the shipped UI shows the "not private" warning before the off), and a reclaim of a
        // swap this wallet never made is refused BY NAME at both the quote and the reclaim (the §BR-2 refund path never
        // signs anything for a deposit it does not hold).
        let opsec = |sim: &mut NetSim, args: &[&str]| -> Option<bool> {
            let lines = wrun(sim, &w1, args, 60).ok()?;
            op_line(&lines, "autoopsec").and_then(|l| l["result"]["on"].as_bool())
        };
        // each element of a wallet run is ONE command line: "autoopsec off" is one command, never "autoopsec" then "off"
        let (dflt, off, on) = (opsec(sim, &["autoopsec"]), opsec(sim, &["autoopsec off"]), opsec(sim, &["autoopsec on"]));
        if dflt != Some(true) || off != Some(false) || on != Some(true) {
            return fail(sim, v, "T1.7", format!("Auto-OPSEC read {dflt:?} by default, {off:?} after off, {on:?} after on (want true, false, true)"), wall);
        }
        let refused = |sim: &mut NetSim, verb: &str| -> Option<String> {
            let cmd = format!("{verb} SWAP-NOT-MINE"); // ONE command line
            let lines = wrun(sim, &w1, &[cmd.as_str()], 60).ok()?;
            op_line(&lines, verb).filter(|l| l["ok"] == serde_json::json!(false)).and_then(|l| op_error(&l))
        };
        match (refused(sim, "reclaimquote"), refused(sim, "reclaim")) {
            (Some(q), Some(r)) if q.contains("not found") && r.contains("not found") => {
                pass_inv(sim, v, "T1.7", "Auto-OPSEC on by default, off and on again; a reclaim of a swap the wallet never made is refused by name".to_string(), wall)?
            }
            other => return fail(sim, v, "T1.7", format!("the reclaim of a swap the wallet never made was not refused by name: {other:?}"), wall),
        }
        Some(())
    }

    /// Run real-wallet commands on a thread while the mesh runs; every output line, or the failure.
    fn wrun(sim: &mut NetSim, w: &crate::harness::real_node_journey::wallet::RealWallet, cmds: &[&str], secs: u64) -> Result<Vec<String>, String> {
        for c in cmds {
            crate::harness::sim_coverage::note_wallet(c);
        }
        let w = w.clone_handle();
        let cmds: Vec<String> = cmds.iter().map(|c| (*c).to_string()).collect();
        match while_meshing(sim, secs, move || {
            let refs: Vec<&str> = cmds.iter().map(String::as_str).collect();
            w.run(&refs)
        }) {
            Some(r) => r,
            None => Err(format!("the wallet did not finish within {secs} s")),
        }
    }

    /// The JSON line a command printed (`{"ok", "op", "result"|"error"}`), parsed.
    fn op_line(lines: &[String], op: &str) -> Option<serde_json::Value> {
        lines.iter().rev().filter(|l| l.contains(&format!("\"op\":\"{op}\""))).find_map(|l| serde_json::from_str(l).ok())
    }

    /// A refused command's reason, in either shape the harness prints: the stdin session's top-level `error`, or the
    /// one-shot run's `result.error` (`RealWallet::run` drives the one-shot mode). Reading only the first read every
    /// one-shot refusal as "no reason" (T1.7's reclaim of a swap never made, 2026-10-29).
    fn op_error(v: &serde_json::Value) -> Option<String> {
        v["error"].as_str().or_else(|| v["result"]["error"].as_str()).map(str::to_string)
    }

    /// `Ok(result)` when the command's line says ok, else its error — the exact reason the wallet gave.
    fn op_ok(lines: &[String], op: &str) -> Result<serde_json::Value, String> {
        match op_line(lines, op) {
            Some(v) if v["ok"] == true => Ok(v["result"].clone()),
            Some(v) => Err(format!("{op}: {}", op_error(&v).unwrap_or_else(|| v.to_string()))),
            // ⭐ NAME WHAT IT DID PRINT (sim-20261006-173300: T2 "printed no ladderpost line (3 line(s))" named no cause —
            // the wallet's own lines are the cause, and they never reached the log). Each line is the harness's JSON
            // reply (op + ok + error/result), cut to a constant width.
            None => Err(format!(
                "{op}: the wallet printed no {op} line ({} line(s)): {}",
                lines.len(),
                lines.iter().map(|l| l.chars().take(240).collect::<String>()).collect::<Vec<_>>().join(" ⏎ ")
            )),
        }
    }

    /// The wallet's non-USDm holdings (its own balance's per-asset breakdown).
    /// What `w` holds of ONE asset, named by its tag (the balance's `assets` key: three 16-hex-digit limbs), in whole units.
    /// ⛔ ONE ASSET, NEVER A SUM: this summed every non-USDm asset, and once a wallet's node sealed it a SAT mining reward
    /// (the link-14 provision fix) "W1 holds its created SIMT" read TRUE on a SAT reward, and the lot cut ran before any SIMT
    /// note existed (sim-20261007-041406 T2: "the largest spendable SIMT note here is 0").
    /// `asset_total` with the wallet's own view beside it: the assets map, USDm, pending, confirming and the balance verdict,
    /// one line — what a silent "never held" needs to name its cause.
    fn asset_poll(sim: &mut NetSim, w: &crate::harness::real_node_journey::wallet::RealWallet, tag_hex: &str) -> (f64, String) {
        match wrun(sim, w, &["refresh", "balance", "repayment_pot"], 180) {
            Ok(lines) => match op_line(&lines, "balance") {
                Some(v) => {
                    let r = &v["result"];
                    let held = r["assets"][tag_hex].as_f64().unwrap_or(0.0);
                    let assets = r["assets"].as_object().map(|m| m.len()).unwrap_or(0);
                    (
                        held,
                        format!(
                            "assets {assets} (tag {}: {}) · usdm {} · pending {} · confirming {} · verdict {} ({})",
                            &tag_hex[..tag_hex.len().min(12)],
                            r["assets"][tag_hex],
                            r["usdm"],
                            r["pending_usdm"],
                            r["confirming_atomic"],
                            r["verdict"],
                            r["verdict_reason"].as_str().unwrap_or("").chars().take(160).collect::<String>()
                        ),
                    )
                }
                None => (0.0, format!("no balance line in {} line(s)", lines.len())),
            },
            Err(e) => (0.0, format!("the balance run failed: {}", e.chars().take(200).collect::<String>())),
        }
    }

    fn asset_total(sim: &mut NetSim, w: &crate::harness::real_node_journey::wallet::RealWallet, tag_hex: &str) -> f64 {
        // the repayment pot rides every balance read here (§BR-3 17.5): the one wallet command the journey never drove
        wrun(sim, w, &["refresh", "balance", "repayment_pot"], 180)
            .ok()
            .and_then(|l| op_line(&l, "balance"))
            .and_then(|v| v["result"]["assets"][tag_hex].as_f64())
            .unwrap_or(0.0)
    }

    /// T2 — the DEX on the mesh, through the shipped wallet: a created asset reaches the other node, a resting ladder posted
    /// through node 0 is on node 1's book, and a fill through node 1 settles on both sides.
    /// Tier 2's state between its two halves: the maker's token tag, what W1 held of it and the orders node 1's book
    /// showed. The one-process journeys carry it on the stack; the real lane parks it in `RealState` between legs 2 and 3.
    #[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
    struct T2Carry {
        tag: String,
        held: f64,
        on_peer: u64,
    }

    /// Tier 2 in one process (the fast, eco and launch journeys): the maker's half then the taker's. The real lane runs the
    /// same two functions as legs 2 and 3. MEASURED why (sim-20261023-034527.log, lane_run exit 142 at 1,200 s): as one
    /// leg tier 2 took 957 s uncontended (sim-20261023-015200.log:15352) and was cut at the 20-min budget under load.
    fn tier2(
        sim: &mut NetSim,
        v: &mut Vec<(&'static str, &'static str, String)>,
        wall: &std::time::Instant,
        w1: &crate::harness::real_node_journey::wallet::RealWallet,
        w2: &crate::harness::real_node_journey::wallet::RealWallet,
        within: u64,
    ) -> Option<()> {
        let mut t2 = T2Carry::default();
        tier2_make(sim, v, wall, w1, w2, within, &mut t2)?;
        tier2_take(sim, v, wall, w1, w2, within, &t2)
    }

    /// Tier 2, the maker's half: W1 creates a token, cuts a grid lot, rests a rung through node 0, and node 1's book shows it.
    fn tier2_make(
        sim: &mut NetSim,
        v: &mut Vec<(&'static str, &'static str, String)>,
        wall: &std::time::Instant,
        w1: &crate::harness::real_node_journey::wallet::RealWallet,
        w2: &crate::harness::real_node_journey::wallet::RealWallet,
        within: u64,
        t2: &mut T2Carry,
    ) -> Option<()> {
        // §BR-14: a 6-character symbol, the network's base creation price (10 USDm, burned into the pools from W1's own note).
        let sym = "SIMTKN";
        // ⭐ THROUGH THE ONE PAYING-COMMAND LOOP: the creation BURNS one of W1's USDm notes (§BR-14), so it is a spend, and a
        // spend of a note whose record has not folded is refused "its member leg is not ready" — retried in a moment, the
        // reason on screen, exactly as every send here. MEASURED 2026-10-29 (brb1-journey-lane5): the one-shot `wrun` ran
        // right after T1.7's send and T2 died on the change's not-yet-folded record.
        let (p0, create_cmd) = (w1.clone_handle(), format!("tokencreate {sym} SimToken 1000"));
        crate::harness::sim_coverage::note_wallet(&create_cmd);
        let Some((ok, _secs, reply)) = while_meshing(sim, within, move || p0.pay_in_session(&create_cmd, "tokencreate", within)) else {
            return fail(sim, v, "T2", format!("W1's {sym} creation did not finish within {within} s"), wall);
        };
        // The book trades a created token by its TAG, exactly as the DEX page does (a symbol is not unique: anyone may
        // create another "SIMT"); the creator's reply names it.
        let tag = match (ok, op_ok(&[reply.clone()], "tokencreate")) {
            (true, Ok(r)) => match r["asset_tag_hex"].as_str() {
                Some(t) => t.to_string(),
                None => return fail(sim, v, "T2", format!("W1 created {sym} but its reply names no asset tag: {r}"), wall),
            },
            (_, Err(e)) => return fail(sim, v, "T2", format!("W1 could not create {sym}: {e}"), wall),
            (false, Ok(r)) => return fail(sim, v, "T2", format!("W1 could not create {sym}: {r}"), wall),
        };
        let (sim_t0, t0) = (sim.now, std::time::Instant::now()); // ONE CLOCK: `within` is SIMULATED seconds
        // ⭐ 2026-11-02 (c9-journey.log: "W1 never held its created SIMTKN within 832 s" with no wallet line in the log — the
        // one-shot `run` keeps its child's stderr): every poll prints the wallet's OWN view (its assets map, USDm, pending,
        // confirming, the balance verdict) and the failure carries the creation reply and the last poll, so the next run
        // names the class (an uncarried mint, an unlocated self note, a pending remainder) instead of a silence.
        let create_reply: String = reply.chars().take(700).collect();
        let (mut held, mut last_poll) = (0.0, String::new());
        let mut polls = 0u32;
        while within_budget(sim, sim_t0, t0, within) && held <= 0.0 {
            let (h, summary) = asset_poll(sim, w1, &tag);
            held = h;
            polls += 1;
            if polls <= 3 || polls % 10 == 0 || held > 0.0 {
                eprintln!("[t2-token] poll {polls} at sim t={} s: held {held} · {summary}", sim.now / 1000);
            }
            last_poll = summary;
        }
        if held <= 0.0 {
            return fail(
                sim,
                v,
                "T2",
                format!(
                    "W1 never held its created {sym} within {within} s ({polls} polls; last: {last_poll}; the creation replied: {create_reply})"
                ),
                wall,
            );
        }
        // ⭐ AN LP CUTS A GRID LOT FIRST (pq_ladder: a rung needs a note of EXACTLY its lot; no whole-unit supply is a grid
        // value). W1 sends one 2^36-atomic lot of its token to itself through the asset transfer door, then rests it.
        const LOT: u64 = 1 << 36;
        // ⭐ THROUGH THE ONE PAYING-COMMAND LOOP (`RealWallet::pay_in_session`): a spend of a note whose record has not folded
        // is refused "retry after the fold" (DB-358 (1)), and the user's model is "retry in a moment, the reason on screen" —
        // the loop every USDm send and tap pay in this journey already uses. MEASURED sim-20261006-212115: the one-shot
        // `wrun` sent the cut ONCE, the node logged "[membership-1step] refused (retry after the fold): the named record is
        // not FOLDED here yet", and T2 died on a wait, not a refusal.
        let (p1, cut_cmd) = (w1.clone_handle(), format!("assetsend {} {tag} {LOT}", w1.address));
        crate::harness::sim_coverage::note_wallet(&cut_cmd);
        let Some((cut, _secs, reply)) = while_meshing(sim, within, move || p1.pay_in_session(&cut_cmd, "assetsend", within)) else {
            return fail(sim, v, "T2", format!("W1's {sym} lot cut did not finish within {within} s"), wall);
        };
        if !cut || !reply.contains("PUBLISHED") {
            return fail(sim, v, "T2", format!("W1 could not cut a {sym} lot: {}", reply.chars().take(600).collect::<String>()), wall);
        }
        // The lot rests once the cut is on chain and W1 sees it; a post that rests nothing is NOT a post (MEASURED
        // sim-20261006-183505: `ok` with 0 built rungs, and the journey polled an empty book until it was killed).
        let (sim_t0, t0) = (sim.now, std::time::Instant::now()); // ONE CLOCK: `within` is SIMULATED seconds
        let mut last = String::new();
        let mut rested = 0u64;
        while within_budget(sim, sim_t0, t0, within) && rested == 0 {
            let height = info(sim, 0)["height"].as_u64().unwrap_or(0);
            let post = wrun(sim, w1, &["refresh", &format!("ladderpost {tag} USDM auto 100000000 1000000 1 {}", height + 2_000)], 180);
            match post.as_ref().map_err(String::clone).and_then(|l| op_ok(l, "ladderpost")) {
                Ok(r) => {
                    rested = r["resting_rungs"].as_u64().unwrap_or(0);
                    last = r.to_string();
                }
                Err(e) => last = e,
            }
        }
        if rested == 0 {
            return fail(sim, v, "T2", format!("W1 could not rest a {sym}/USDM rung within {within} s: {last}"), wall);
        }
        let (sim_t0, t0) = (sim.now, std::time::Instant::now()); // ONE CLOCK: `within` is SIMULATED seconds
        let posted_at = sim.now;
        let (mut on_peer, mut poll_ms) = (0u64, 0u64);
        while within_budget(sim, sim_t0, t0, within) && on_peer == 0 {
            let start = sim.now;
            on_peer = wrun(sim, w2, &[&format!("booklevel {tag} USDM 0")], 120)
                .ok()
                .and_then(|l| op_ok(&l, "booklevel").ok())
                .and_then(|r| r["orders"].as_u64())
                .unwrap_or(0);
            poll_ms = poll_ms.max(sim.now - start);
        }
        // PERF P6: a resting order, posted through node 0, on node 1's book
        super::perf::row_within(
            "P6 DEX order post → visible on another node's book",
            if on_peer == 0 { f64::INFINITY } else { (sim.now - posted_at) as f64 / 1e3 },
            "s",
            Some(1.0),
            &format!("sim chain wait, node CPU charged, read through the other wallet's book ≤ +{:.1} s (one poll)", poll_ms as f64 / 1e3),
            poll_ms as f64 / 1e3,
        );
        if on_peer == 0 {
            return fail(sim, v, "T2", format!("node 1's book never showed W1's {sym} ladder within {within} s"), wall);
        }
        t2.tag = tag;
        t2.held = held;
        t2.on_peer = on_peer;
        Some(())
    }

    /// Tier 2, the taker's half: W2 fills the rung through node 1, the fill is admitted and settles in W2's wallet; T2's verdict.
    fn tier2_take(
        sim: &mut NetSim,
        v: &mut Vec<(&'static str, &'static str, String)>,
        wall: &std::time::Instant,
        w1: &crate::harness::real_node_journey::wallet::RealWallet,
        w2: &crate::harness::real_node_journey::wallet::RealWallet,
        within: u64,
        t2: &T2Carry,
    ) -> Option<()> {
        let (sym, tag, held, on_peer) = ("SIMTKN", t2.tag.clone(), t2.held, t2.on_peer);
        let w2_before = asset_total(sim, w2, &tag);
        // ⭐ THROUGH THE ONE PAYING-COMMAND LOOP, as the cut: a rung refused "MEMBERSHIP_NOT_FOLDED_YET" (the maker's freshly
        // cut lot not folded on node 1 yet — a race the fold resolves, nothing burned) is retried in the same wallet process,
        // the user's "retry in a moment, the reason on screen". MEASURED sim-20261006-221807 and link 8's baseline: the
        // one-shot `swapexec` died on node 1's "[membership-1step] refused (retry after the fold)", answered as 422.
        let _ = wrun(sim, w2, &["refresh"], 180);
        let (p2, fill_cmd) = (w2.clone_handle(), format!("swapexec {tag} USDM 200000000 1"));
        crate::harness::sim_coverage::note_wallet(&fill_cmd);
        let fill_sim_t0 = sim.now;
        let mut fill_wall_s = f64::INFINITY;
        let fill = match while_meshing(sim, within, move || p2.pay_in_session(&fill_cmd, "swapexec", within)) {
            Some((_, secs, reply)) => {
                fill_wall_s = secs;
                Ok(vec![reply])
            }
            None => Err(format!("the fill did not finish within {within} s")),
        };
        let filled_at = sim.now;
        // PERF P6 (the taker's side of "swap"): the shipped swap's own time to an admitted fill, wall
        super::perf::row(
            "P6 DEX swap → the taker's wallet shows it submitted",
            fill_wall_s,
            "s",
            Some(1.0),
            &format!("wallet wall (plan + prove + submit; {:.1} s simulated passed meanwhile)", (filled_at - fill_sim_t0) as f64 / 1e3),
        );
        // The fill's own reply travels with every later T2 verdict: MEASURED sim-20261006-190641 (eco) — `swapexec` answered
        // ok, W2's 3.0 USDm never moved and no SIMT arrived, and the reply had been cut from the 4 MiB wallet log by the
        // balance polls that followed.
        // ⛔ A FILL THE NODE REFUSED IS NOT A FILL: `ok` means the wallet ran its plan, and `complete` says every planned rung
        // was ADMITTED (the node's own verdict per rung, `refused` naming each refusal). MEASURED sim-20261006-190157 (eco):
        // the reply was ok with the rung refused (DB-150, the maker's bind never reached node 1's book — DB-401), and the
        // journey then polled W2's balance for 4,000 simulated seconds for a payout no block could carry.
        let fill_reply = match fill.as_ref().map_err(String::clone).and_then(|l| op_ok(l, "swapexec")) {
            Ok(r) if r["complete"] == true => r.to_string().chars().take(600).collect::<String>(),
            Ok(r) => {
                return fail(
                    sim,
                    v,
                    "T2",
                    format!("W2's fill through node 1 was not admitted: {}", r.to_string().chars().take(600).collect::<String>()),
                    wall,
                )
            }
            Err(e) => return fail(sim, v, "T2", format!("W2's fill through node 1 did not settle: {e}"), wall),
        };
        let (sim_t0, t0) = (sim.now, std::time::Instant::now()); // ONE CLOCK: `within` is SIMULATED seconds
        let mut w2_after = w2_before;
        let mut poll_ms = 0u64;
        while within_budget(sim, sim_t0, t0, within) && w2_after <= w2_before {
            let start = sim.now;
            w2_after = asset_total(sim, w2, &tag);
            poll_ms = poll_ms.max(sim.now - start);
        }
        // PERF P6: the fill settled — the taker's wallet holds the bought token
        super::perf::row_within(
            "P6 DEX swap submitted → settled in the taker's wallet",
            if w2_after <= w2_before { f64::INFINITY } else { (sim.now - filled_at) as f64 / 1e3 },
            "s",
            None,
            &format!("sim chain wait, node CPU charged, read through the taker's wallet ≤ +{:.1} s (one poll); P4 is its finality", poll_ms as f64 / 1e3),
            poll_ms as f64 / 1e3,
        );
        if w2_after <= w2_before {
            return fail(sim, v, "T2", format!("W2 never received {sym} from the fill: {w2_before} → {w2_after} · the fill answered {fill_reply}"), wall);
        }
        let left_on_origin = wrun(sim, w1, &[&format!("booklevel {tag} USDM 0")], 120)
            .ok()
            .and_then(|l| op_ok(&l, "booklevel").ok())
            .and_then(|r| r["orders"].as_u64());
        pass_inv(
            sim,
            v,
            "T2",
            format!("{sym} created (W1 held {held}), ladder on node 1's book ({on_peer} order(s)), W2 filled {w2_before} → {w2_after}; node 0's book now {left_on_origin:?}"),
            wall,
        )
    }

    /// T3 — the rest of the ecosystem through the shipped wallet, each read through the OTHER node.
    /// Tier 3's state between its phases: what the bond phase learned and every phase's done-list (the failure messages
    /// name it). The one-process journeys carry it on the stack; the real lane parks it in `RealState` between legs.
    #[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
    struct T3Carry {
        done: Vec<String>,
        /// node 0's vote identity the bond provisions, the custody weight W1 locked, the blue score it matures at and the
        /// tip when every up node first held it.
        vid: String,
        want: u64,
        matures: u64,
        tip_at_bond: u64,
        /// The simulated ms the maturity wait began — its `within` budget counts from here across every slice.
        wait_sim_t0: Option<u64>,
    }

    /// How a maturity wait ended.
    enum T3Wait {
        /// matured, unbonded, released on every up node
        Done,
        /// the slice's sim budget is spent and the bond is not yet mature while `within` is not spent — run the next slice
        Parked,
        /// a T3 FAIL row is recorded
        Failed,
    }

    /// Tier 3 in one process (the fast, eco and launch journeys): the three phases back to back. The real lane runs the
    /// same three functions as legs 4, 5 (the wait, sliced) and 6, so every phase is the shipped step either way.
    fn tier3(
        sim: &mut NetSim,
        v: &mut Vec<(&'static str, &'static str, String)>,
        wall: &std::time::Instant,
        w1: &crate::harness::real_node_journey::wallet::RealWallet,
        w2: &crate::harness::real_node_journey::wallet::RealWallet,
        within: u64,
    ) -> Option<()> {
        let mut t3 = T3Carry::default();
        tier3_bond(sim, v, wall, w1, within, &mut t3)?;
        match tier3_mature_and_unbond(sim, v, wall, w1, within, &mut t3, None) {
            T3Wait::Done => {}
            T3Wait::Parked => unreachable!("an unsliced maturity wait never parks"),
            T3Wait::Failed => return None,
        }
        tier3_identity(sim, v, wall, w1, w2, within, &mut t3)
    }

    /// Tier 3, phase 1: W1 holds the SAT its node mined → bond → mybond → the weight on every up node → the maturity
    /// named → an early unbond refused with the weight kept. What it learned rides `t3` into the next phase.
    fn tier3_bond(
        sim: &mut NetSim,
        v: &mut Vec<(&'static str, &'static str, String)>,
        wall: &std::time::Instant,
        w1: &crate::harness::real_node_journey::wallet::RealWallet,
        within: u64,
        t3: &mut T3Carry,
    ) -> Option<()> {
        let done = &mut t3.done;
        // bond → mybond → unbond (the validator seat, through the chain).
        // ⭐ VALIDATOR BONDS ARE SAT-ONLY (`Node::USDM_BOND_RETIRED`, 2026-10-07): W1 bonds the SAT its own node MINED to it
        // (node 0 seals every reward to the wallet that provisioned it — W1's balance pass does that, SATOSHI §8.4 (c)).
        // A bond locks ONE note, and one first-era reward is `satoshi::INITIAL_REWARD` = 4,159,090 base units, so the
        // journey bonds 0.04 SAT (4,000,000) — one reward covers it. First W1 must HOLD a reward: refreshed until its
        // balance names SAT, which is the reward travelling (sealed in a block, filed, folded, found by W1's clue).
        // the wallet's one tag encoding (`asset_tag_hex`: each limb's little-endian bytes, hex)
        let sat_key: String = crate::satoshi::asset_tag().iter().flat_map(|l| l.to_le_bytes()).map(|b| format!("{b:02x}")).collect();
        // MEASURED 2026-10-28 (lane funds, journey-111.log): the first run to reach T3 panicked HERE — the journey bonded
        // 0.04 SAT (4,000,000) against `INITIAL_REWARD` = 3,762,960 (the 10/25 schedule: 19M rewards after the ≤ 2M
        // set-aside), and the `assert!` lost every PASS row of the run (T1.0–T2) because the rows are recorded at the end.
        // The bond is 0.03 SAT (3,000,000 < one first-era reward, no bond minimum in sat_bond_tx), and a calibration miss
        // is a recorded T3 row, never a panic that erases the steps before it.
        let (want, bond_arg) = (3_000_000u64, "bond 0.03");
        if want > crate::satoshi::INITIAL_REWARD {
            return fail(
                sim,
                v,
                "T3",
                format!(
                    "CALIBRATION: the journey's SAT bond ({want}) exceeds one first-era reward ({}) — a bond locks ONE note",
                    crate::satoshi::INITIAL_REWARD
                ),
                wall,
            );
        }
        let (sim_t0, t0) = (sim.now, std::time::Instant::now()); // ONE CLOCK: `within` is SIMULATED seconds
        let mut held_sat = 0.0f64;
        while within_budget(sim, sim_t0, t0, within) && held_sat * 1e8 < want as f64 {
            held_sat = asset_total(sim, w1, &sat_key);
        }
        if held_sat * 1e8 < want as f64 {
            return fail(sim, v, "T3", format!("W1 never held the SAT its node mined to it within {within} s (holds {held_sat} SAT; a bond of {want} base units needs one reward)"), wall);
        }
        done.push(format!("W1 holds {held_sat} SAT mined by node 0"));
        let b = wrun(sim, w1, &["refresh", bond_arg, "mybond"], within);
        match b.as_ref().map_err(String::clone).and_then(|l| op_ok(l, "bond").and_then(|_| op_ok(l, "mybond"))) {
            Ok(r) => done.push(format!("bond → mybond {}", r.to_string().chars().take(80).collect::<String>())),
            Err(e) => return fail(sim, v, "T3", format!("bond: {e}"), wall),
        }
        // ⭐ THE CLAIM IS WHAT EVERY UP NODE HOLDS (the real journey's `[usdm-bond]` shape): the weight lands from a block on
        // every node before the owner unbonds, and the unbond releases it on every node. MEASURED sim-20261007-020907:
        // `mybond` read bond 0 right after the bond, and the unbond was asked against a bond no node held yet — the step
        // claimed only what the wallet's calls RETURNED. The bond provisions node 0's identity (DB-406), so the weight sits
        // on the vote id node 0 answers now.
        let vid = serde_json::from_str::<serde_json::Value>(&sim.rpc(0, "GET", "/validator_id", "").1)
            .ok()
            .and_then(|j| j["validator_id_hex"].as_str().map(str::to_string));
        let Some(vid) = vid else {
            return fail(sim, v, "T3", format!("node 0 answers no vote identity at /validator_id after the bond ({})", done.join(", ")), wall);
        };
        // ⭐ THE SAT BOND IS `custody_sat`, NOT THE VOTING TOTAL. `/get_validator_bond`'s `bond` is the id's whole finality
        // weight — its membership seat PLUS its SAT custody (SATOSHI §6). Since DB-437 every simulated daemon is seated at
        // boot, as the live pair's are, so node 0's total reads 4,000,001 after a 4,000,000 bond (MEASURED
        // night/perf-flat-20261008-165632-low.log). What W1 locked, and what its unbond releases, is the custody weight.
        let bonds = |s: &NetSim| -> Vec<Option<u64>> {
            (0..s.rts.len())
                .filter(|&i| !s.is_down(i))
                .map(|i| {
                    serde_json::from_str::<serde_json::Value>(&s.rpc(i, "POST", "/get_validator_bond", &format!(r#"{{"voter_id":"{vid}"}}"#)).1)
                        .ok()
                        .and_then(|j| j["custody_sat"].as_u64())
                })
                .collect()
        };
        if run_until(sim, within * 1_000, |s| bonds(s).iter().all(|b| *b == Some(want))).is_none() {
            return fail(sim, v, "T3", format!("the bond never landed on every up node within {within} s: {:?} (want {want})", bonds(sim)), wall);
        }
        done.push(format!("bond {want} held by every up node"));
        // ⭐ DB-409 — THE STAKE LOCK, BOTH SIDES OF IT, as the owner meets it. Node 0 names the blue score the bond matures at
        // (`/get_validator_bond`, the one definition the door and the release judge); asked before it, the unbond is refused
        // legibly and every node keeps the weight; asked after it, the unbond travels and every node releases it.
        let maturity = |s: &NetSim| -> (Option<u64>, Option<u64>) {
            let j = serde_json::from_str::<serde_json::Value>(&s.rpc(0, "POST", "/get_validator_bond", &format!(r#"{{"voter_id":"{vid}"}}"#)).1)
                .unwrap_or_default();
            (j["unbond_matures_at_blue"].as_u64(), j["tip_blue_score"].as_u64())
        };
        let (Some(matures), Some(tip_now)) = maturity(sim) else {
            return fail(sim, v, "T3", format!("node 0 names no maturity for the bond ({:?}) after {}", maturity(sim), done.join(", ")), wall);
        };
        if tip_now.saturating_add(1) >= matures {
            return fail(sim, v, "T3", format!("CALIBRATION: the bond was already mature when every node first held it (tip {tip_now}, matures {matures}, lock {} blocks; the derived lock for {} nodes is {} = (fold depth + 8) × 2 × nodes) — every node's fold applied it later than the journey's own fold-settle bound, a fold lag beyond the derived bound (journey_stake_lock_blocks)", sim.params.stake_lock_blocks, sim.rts.len(), journey_stake_lock_blocks(sim.rts.len())), wall);
        }
        let early = wrun(sim, w1, &["unbond"], within);
        match early.as_ref().map_err(String::clone).and_then(|l| op_ok(l, "unbond")) {
            Ok(r) => return fail(sim, v, "T3", format!("an unbond asked at tip {tip_now} before the bond matures at {matures} was not refused: {r}"), wall),
            Err(e) if e.contains("not matured") => {}
            Err(e) => return fail(sim, v, "T3", format!("the early unbond was refused for another reason (after {}): {e}", done.join(", ")), wall),
        }
        if bonds(sim).iter().any(|b| *b != Some(want)) {
            return fail(sim, v, "T3", format!("a refused early unbond moved the weight: {:?} (want {want} on every up node)", bonds(sim)), wall);
        }
        done.push(format!("an unbond at tip {tip_now} refused until {matures}, the weight kept"));
        // ⭐ §BR-11 lever 2 — "BOND MY REWARDS": W1 switches it on; its next refresh moves a mining reward its node sealed to it
        // straight into the custody bond (a top-up of the seated bond), and EVERY up node holds the larger weight from a block;
        // the lock is not shortened by the top-up (the maturity named after it is no earlier); W1 switches it off again.
        let on = wrun(sim, w1, &["bondrewards on"], within);
        if let Err(e) = on.as_ref().map_err(String::clone).and_then(|l| op_ok(l, "bondrewards")) {
            return fail(sim, v, "T3", format!("W1 could not switch Bond my rewards on: {e} (after {})", done.join(", ")), wall);
        }
        let (sim_t0, t0) = (sim.now, std::time::Instant::now()); // ONE CLOCK: `within` is SIMULATED seconds
        let mut grown: Vec<Option<u64>> = Vec::new();
        while within_budget(sim, sim_t0, t0, within) {
            let _ = wrun(sim, w1, &["refresh"], within); // the refresh runs the one "Bond my rewards" step the app runs
            grown = t3_bonds(sim, &vid);
            if !grown.is_empty() && grown.iter().all(|b| b.is_some_and(|w| w > want)) {
                break;
            }
        }
        let Some(Some(bonded)) = grown.first().copied() else {
            return fail(sim, v, "T3", format!("no node answered the bond after Bond my rewards (after {})", done.join(", ")), wall);
        };
        if !grown.iter().all(|b| *b == Some(bonded)) || bonded <= want {
            return fail(sim, v, "T3", format!("Bond my rewards never put a mining reward into the bond on every up node within {within} s: {grown:?} (was {want}, after {})", done.join(", ")), wall);
        }
        let (Some(matures_after), _) = t3_maturity(sim, &vid) else {
            return fail(sim, v, "T3", format!("node 0 names no maturity after the reward bond (after {})", done.join(", ")), wall);
        };
        if matures_after < matures {
            return fail(sim, v, "T3", format!("the reward bond SHORTENED the lock: matures {matures_after} < {matures} (after {})", done.join(", ")), wall);
        }
        let off = wrun(sim, w1, &["bondrewards off"], within);
        if let Err(e) = off.as_ref().map_err(String::clone).and_then(|l| op_ok(l, "bondrewards")) {
            return fail(sim, v, "T3", format!("W1 could not switch Bond my rewards off: {e}"), wall);
        }
        done.push(format!("Bond my rewards: a mining reward bonded, {want} → {bonded} on every up node, lock kept (matures {matures_after})"));
        // ⭐ §BR-3 17.3 — DELEGATE, THEN UNDELEGATE, ON THE SHIPPED WALLET: W1 delegates 0.001 SAT of a mining reward to the
        // seated validator (through the paying loop: the reward's record must fold first); EVERY up node's seat rises by
        // exactly that from a block; W1's own list shows it delegated; W1 undelegates all and every seat falls back to the
        // bond it had, with W1 now holding an unbonding note (its release is the in-process pin's: the 21-day window).
        const DELEGATED: u64 = 100_000; // 0.001 SAT in base units
        let (p_d, d_cmd) = (w1.clone_handle(), format!("delegate 0.001 {vid}"));
        crate::harness::sim_coverage::note_wallet(&d_cmd);
        let Some((d_ok, _secs, d_reply)) = while_meshing(sim, within, move || p_d.pay_in_session(&d_cmd, "delegate", within)) else {
            return fail(sim, v, "T3", format!("W1's delegation did not finish within {within} s (after {})", done.join(", ")), wall);
        };
        if !d_ok || !d_reply.contains("PUBLISHED") {
            return fail(sim, v, "T3", format!("W1 could not delegate 0.001 SAT: {} (after {})", d_reply.chars().take(600).collect::<String>(), done.join(", ")), wall);
        }
        // The seat the delegation must reach: `bonded` + the delegation — plus any WHOLE mining rewards "Bond my rewards"
        // bonded between the read of `bonded` and its switch-off landing (a reward note is bonded whole, never in part).
        // MEASURED 2026-11-01 (night/sim-20261101-123223.log, seed 2): every node read 10,625,920 against an equality of
        // 6,862,960 — exactly one `INITIAL_REWARD` (3,762,960) above, i.e. the delegation landed AND one more reward was
        // bonded by the switch the step had just turned on. The equality mistook the feature working for a failure.
        let reward = crate::satoshi::INITIAL_REWARD;
        let reached = move |b: u64| b >= bonded + DELEGATED && (b - bonded - DELEGATED) % reward == 0;
        let seat_reads = |sim: &mut NetSim, ok: &dyn Fn(u64) -> bool| -> Vec<Option<u64>> {
            let (sim_t0, t0) = (sim.now, std::time::Instant::now());
            let mut got = t3_bonds(sim, &vid);
            while within_budget(sim, sim_t0, t0, within) && !(got.iter().all(|b| b.is_some_and(ok)) && !got.is_empty()) {
                sim.run(500, 10_000);
                got = t3_bonds(sim, &vid);
            }
            got
        };
        let raised = seat_reads(sim, &reached);
        if !raised.iter().all(|b| b.is_some_and(reached)) {
            return fail(sim, v, "T3", format!("the delegation never raised the seat on every up node to {} (+ whole rewards): {raised:?} (after {})", bonded + DELEGATED, done.join(", ")), wall);
        }
        let listed = wrun(sim, w1, &["refresh", "delegations"], within);
        match listed.as_ref().map_err(String::clone).and_then(|l| op_ok(l, "delegations")) {
            Ok(r) if r["delegations"].as_array().is_some_and(|a| a.iter().any(|d| d["state"] == "delegated" && d["validator"] == serde_json::json!(vid))) => {}
            Ok(r) => return fail(sim, v, "T3", format!("W1's own list does not show its delegation: {r} (after {})", done.join(", ")), wall),
            Err(e) => return fail(sim, v, "T3", format!("W1 could not list its delegations: {e}"), wall),
        }
        let (p_u, u_cmd) = (w1.clone_handle(), "undelegate".to_string());
        crate::harness::sim_coverage::note_wallet(&u_cmd);
        let Some((u_ok, _secs, u_reply)) = while_meshing(sim, within, move || p_u.pay_in_session(&u_cmd, "undelegate", within)) else {
            return fail(sim, v, "T3", format!("W1's undelegation did not finish within {within} s"), wall);
        };
        if !u_ok || !u_reply.contains("PUBLISHED") {
            return fail(sim, v, "T3", format!("W1 could not undelegate: {} (after {})", u_reply.chars().take(600).collect::<String>(), done.join(", ")), wall);
        }
        // Back to the seat before the delegation — with the same whole-reward allowance (the switch is off, but a reward it
        // bonded before the off landed stays bonded).
        let back = move |b: u64| b >= bonded && (b - bonded) % reward == 0;
        let lowered = seat_reads(sim, &back);
        if !lowered.iter().all(|b| b.is_some_and(back)) {
            return fail(sim, v, "T3", format!("the undelegation never lowered the seat on every up node back to {bonded} (+ whole rewards): {lowered:?}"), wall);
        }
        let listed = wrun(sim, w1, &["refresh", "delegations"], within);
        match listed.as_ref().map_err(String::clone).and_then(|l| op_ok(l, "delegations")) {
            Ok(r) if r["delegations"].as_array().is_some_and(|a| a.iter().any(|d| d["state"] == "unbonding")) => {}
            Ok(r) => return fail(sim, v, "T3", format!("W1 holds no unbonding note after undelegating: {r}"), wall),
            Err(e) => return fail(sim, v, "T3", format!("W1 could not list its delegations after undelegating: {e}"), wall),
        }
        done.push(format!("delegated 0.001 SAT: every seat {bonded} → {} → {bonded}, W1 unbonding", bonded + DELEGATED));
        let (want, matures) = (bonded, matures_after);
        t3.vid = vid;
        t3.want = want;
        t3.matures = matures;
        t3.tip_at_bond = tip_now;
        Some(())
    }

    /// The custody weight node `i` holds for vote identity `vid` (`/get_validator_bond`'s `custody_sat`, SATOSHI §6).
    fn t3_bonds(s: &NetSim, vid: &str) -> Vec<Option<u64>> {
        (0..s.rts.len())
            .filter(|&i| !s.is_down(i))
            .map(|i| {
                serde_json::from_str::<serde_json::Value>(&s.rpc(i, "POST", "/get_validator_bond", &format!(r#"{{"voter_id":"{vid}"}}"#)).1)
                    .ok()
                    .and_then(|j| j["custody_sat"].as_u64())
            })
            .collect()
    }

    /// Node 0's (maturity blue score, tip blue score) for the bond — the one definition the door and the release judge.
    fn t3_maturity(s: &NetSim, vid: &str) -> (Option<u64>, Option<u64>) {
        let j = serde_json::from_str::<serde_json::Value>(&s.rpc(0, "POST", "/get_validator_bond", &format!(r#"{{"voter_id":"{vid}"}}"#)).1)
            .unwrap_or_default();
        (j["unbond_matures_at_blue"].as_u64(), j["tip_blue_score"].as_u64())
    }

    /// The real lane's maturity slice in SIMULATED seconds (`SIM_REAL_SLICE_S`, default 300): what one leg of the wait
    /// runs before it parks. MEASURED (sim-20261023-015200.log): tier 3 ran at 0.34× on the real band, so 300 sim s is
    /// ~880 wall s plus the resume and the park — inside the 20-min leg. The wait's `within` budget is NOT sliced: it
    /// counts from the first slice across every leg.
    fn real_wait_slice_s() -> u64 {
        std::env::var("SIM_REAL_SLICE_S").ok().and_then(|v| v.parse().ok()).unwrap_or(300)
    }

    /// Tier 3, phase 2 — the maturity wait, the UNBOND once matured, the release on every up node. `slice`: the real
    /// lane's leg budget in simulated seconds — spent before the bond matures while `within` is not, the phase parks for
    /// the next slice; `None` waits the whole `within` in one process (the one-process journeys).
    fn tier3_mature_and_unbond(
        sim: &mut NetSim,
        v: &mut Vec<(&'static str, &'static str, String)>,
        wall: &std::time::Instant,
        w1: &crate::harness::real_node_journey::wallet::RealWallet,
        within: u64,
        t3: &mut T3Carry,
        slice: Option<u64>,
    ) -> T3Wait {
        let vid = t3.vid.clone();
        let wait_t0 = *t3.wait_sim_t0.get_or_insert(sim.now);
        let done = &mut t3.done;
        let spent = sim.now.saturating_sub(wait_t0) / 1_000;
        let remaining = within.saturating_sub(spent);
        let budget = slice.map_or(remaining, |s| s.min(remaining));
        let matured = |s: &NetSim| matches!(t3_maturity(s, &vid), (Some(m), Some(t)) if t.saturating_add(1) >= m);
        if !matured(sim) && run_until(sim, budget * 1_000, matured).is_none() {
            if slice.is_some() && remaining > budget {
                eprintln!(
                    "[sim-journey] T3 maturity wait sliced: {:?} after {spent} + {budget} of {within} sim s — parked for the next slice",
                    t3_maturity(sim, &vid)
                );
                return T3Wait::Parked;
            }
            let _ = fail(sim, v, "T3", format!("the bond never matured within {within} s: {:?} (after {})", t3_maturity(sim, &vid), done.join(", ")), wall);
            return T3Wait::Failed;
        }
        let u = wrun(sim, w1, &["unbond"], within);
        match u.as_ref().map_err(String::clone).and_then(|l| op_ok(l, "unbond")) {
            Ok(r) if r["verdict"] == "PUBLISHED" => done.push("unbond published once matured".into()),
            Ok(r) => {
                let _ = fail(sim, v, "T3", format!("the matured unbond was answered without PUBLISHED: {r} (after {})", done.join(", ")), wall);
                return T3Wait::Failed;
            }
            Err(e) => {
                let _ = fail(sim, v, "T3", format!("unbond (after {}): {e}", done.join(", ")), wall);
                return T3Wait::Failed;
            }
        }
        if run_until(sim, within * 1_000, |s| t3_bonds(s, &vid).iter().all(|b| *b == Some(0))).is_none() {
            let _ = fail(
                sim,
                v,
                "T3",
                format!("the unbond never released the weight on every up node within {within} s: {:?} (after {})", t3_bonds(sim, &vid), done.join(", ")),
                wall,
            );
            return T3Wait::Failed;
        }
        done.push("released on every up node".into());
        T3Wait::Done
    }

    /// Tier 3, phase 3: username → profile → letter → the POS tap, each across the two nodes, then T3's verdict.
    fn tier3_identity(
        sim: &mut NetSim,
        v: &mut Vec<(&'static str, &'static str, String)>,
        wall: &std::time::Instant,
        w1: &crate::harness::real_node_journey::wallet::RealWallet,
        w2: &crate::harness::real_node_journey::wallet::RealWallet,
        within: u64,
        t3: &mut T3Carry,
    ) -> Option<()> {
        let done = &mut t3.done;
        // ⭐ W1's PUBLISHED address is its locator-free `handle_address` — the one form a username, a profile and a letter's
        // sender carry (wallet `wallet_address` doc: "`handle_address` … is what goes anywhere published"). `w1.address` is the
        // ROTATING receive address handed to one payer; a profile is never filed under it, and nothing public may link the
        // two. MEASURED (sim-20261007-053320): `profileget <w1.address>` asked node 1 for a key no wallet ever publishes, so
        // the read could not succeed whatever the chain held — and the old username check matched a 16-char prefix the two
        // forms SHARE (tag + bucket id), so it could not tell them apart. W1 names its handle; every read below must hit
        // exactly that string, learned by W2 the way a stranger learns it: through the @name.
        let handle = match wrun(sim, w1, &["address"], 120).and_then(|l| op_ok(&l, "address")) {
            Ok(r) => match r["handle_address"].as_str() {
                Some(h) if !h.is_empty() && h != w1.address => h.to_string(),
                _ => return fail(sim, v, "T3", format!("W1's address answer named no handle distinct from its receive address: {r}"), wall),
            },
            Err(e) => return fail(sim, v, "T3", format!("W1's own address (after {}): {e}", done.join(", ")), wall),
        };
        // a username registered through node 0 resolves through node 1
        let name = "simuser1";
        if let Err(e) = wrun(sim, w1, &[&format!("username {name}")], within).and_then(|l| op_ok(&l, "username")) {
            return fail(sim, v, "T3", format!("username register (after {}): {e}", done.join(", ")), wall);
        }
        let (sim_t0, t0) = (sim.now, std::time::Instant::now()); // ONE CLOCK: `within` is SIMULATED seconds
        let (mut resolved, mut last) = (false, String::from("no answer"));
        while within_budget(sim, sim_t0, t0, within) && !resolved {
            match wrun(sim, w2, &[&format!("resolve {name}")], 120).and_then(|l| op_ok(&l, "resolve")) {
                Ok(r) => {
                    resolved = r.as_str() == Some(handle.as_str()) || r["address"].as_str() == Some(handle.as_str());
                    last = r.to_string();
                }
                Err(e) => last = e,
            }
        }
        if !resolved {
            return fail(sim, v, "T3", format!("@{name} never resolved to W1's handle through node 1 within {within} s: last answer {} (after {})", last.chars().take(240).collect::<String>(), done.join(", ")), wall);
        }
        done.push(format!("@{name} resolves to W1's handle through node 1"));
        // a profile set through node 0 is read through node 1, by the handle the @name resolved to
        if let Err(e) = wrun(sim, w1, &["profileset 0 Sim Profile|a simulated bio"], within).and_then(|l| op_ok(&l, "profileset")) {
            return fail(sim, v, "T3", format!("profile set (after {}): {e}", done.join(", ")), wall);
        }
        let (sim_t0, t0) = (sim.now, std::time::Instant::now()); // ONE CLOCK: `within` is SIMULATED seconds
        let (mut prof, mut last) = (false, String::from("no answer"));
        while within_budget(sim, sim_t0, t0, within) && !prof {
            match wrun(sim, w2, &[&format!("profileget {handle}")], 120).and_then(|l| op_ok(&l, "profileget")) {
                Ok(r) => {
                    prof = r["display"].as_str() == Some("Sim Profile") && r["bio"].as_str() == Some("a simulated bio");
                    last = r.to_string();
                }
                Err(e) => last = e,
            }
        }
        if !prof {
            // each up node's own answer through its RPC door — which node never filed the entry names the class
            let body = serde_json::json!({ "address": handle }).to_string();
            let held: Vec<Option<bool>> = (0..sim.rts.len())
                .filter(|&i| !sim.is_down(i))
                .map(|i| serde_json::from_str::<serde_json::Value>(&sim.rpc(i, "POST", "/dir/profile", &body).1).ok().map(|j| !j["display"].is_null()))
                .collect();
            return fail(sim, v, "T3", format!("W1's profile never read through node 1 within {within} s: last answer {} · profile held per node {held:?} (after {})", last.chars().take(240).collect::<String>(), done.join(", ")), wall);
        }
        done.push("profile read through node 1".into());
        // a letter W1 sends is in W2's CHAIN history (W2 reads through node 1), walked the way the app restores it.
        // ⭐ `/letter/history` is ONE FIXED 64-ordinal page by frontier ordinal (`rpc_http`), and the app's `restoreHistory`
        // walks `from += page` up to the node's `served_seq`. MEASURED (sim-20261007-054805): the old `letterhistory 0` read
        // ordinals 0..64 only, while a letter is filed in the row of the block that carries its commitment (ordinal ~1,640
        // there) — so the read could not succeed whatever the chain held. W2's walk resumes from its cursor — node 1's top
        // when the letter is sent, what a wallet that already walked its history holds — up to node 1's top now.
        let top_of = |s: &NetSim| -> u64 {
            serde_json::from_str::<serde_json::Value>(&s.rpc(1, "GET", "/get_info", "").1).ok().and_then(|j| j["served_seq"].as_u64()).unwrap_or(0)
        };
        let cursor = top_of(sim);
        if let Err(e) = wrun(sim, w1, &[&format!("lettersend {} hello from the simulator", w2.address)], within).and_then(|l| op_ok(&l, "lettersend")) {
            return fail(sim, v, "T3", format!("letter send (after {}): {e}", done.join(", ")), wall);
        }
        let (sim_t0, t0) = (sim.now, std::time::Instant::now()); // ONE CLOCK: `within` is SIMULATED seconds
        let (mut got, mut last) = (None, String::from("no answer"));
        while within_budget(sim, sim_t0, t0, within) && got.is_none() {
            let top = top_of(sim);
            let pages: Vec<String> = (cursor..=top.max(cursor)).step_by(crate::letter::LETTER_CMS_PER_BLOCK).map(|f| format!("letterhistory {f}")).collect();
            let refs: Vec<&str> = pages.iter().map(String::as_str).collect();
            match wrun(sim, w2, &refs, 120) {
                Ok(lines) => {
                    let replies: Vec<serde_json::Value> =
                        lines.iter().filter(|l| l.contains("\"op\":\"letterhistory\"")).filter_map(|l| serde_json::from_str(l).ok()).collect();
                    got = replies
                        .iter()
                        .flat_map(|r| r["result"]["messages"].as_array().cloned().unwrap_or_default())
                        .find(|m| m["msg"].as_str() == Some("hello from the simulator"));
                    last = format!(
                        "{} page(s) {cursor}..={top}, {} ok, {} message(s) opened",
                        replies.len(),
                        replies.iter().filter(|r| r["ok"] == true).count(),
                        replies.iter().map(|r| r["result"]["messages"].as_array().map_or(0, Vec::len)).sum::<usize>()
                    );
                }
                Err(e) => last = e,
            }
        }
        let Some(letter) = got else {
            return fail(sim, v, "T3", format!("W2 never read W1's letter through node 1 within {within} s: last walk {last} (after {})", done.join(", ")), wall);
        };
        // the opened letter authenticates as W1's PUBLISHED handle (the sender signs for its address — `open_authenticated`)
        if letter["from"].as_str() != Some(handle.as_str()) {
            return fail(sim, v, "T3", format!("W2 opened the letter but it names sender {} where W1's handle is {handle}", letter["from"]), wall);
        }
        done.push("letter delivered across nodes".into());
        // a POS charge across the two nodes: the payer W1 (node 0) taps the merchant W2 (node 1)
        match pos_tap(sim, w1, w2, within) {
            Ok(d) => done.push(d),
            Err(e) => return fail(sim, v, "T3", format!("POS tap (after {}): {e}", done.join(", ")), wall),
        }
        // ⭐ §BR-3 17.6 — STAKE, THEN UNSTAKE, THROUGH A NODE THAT IS NOT A CUSTODIAN: W2 (node 1) stakes 0.01 USDm of the POS
        // charge it just received; node 1 relays it on the custodial request lane, node 0's custodian executes it, a block
        // applies it, and W2's OWN scan reads it staked; W2 unstakes and its stake reads zero again.
        // §BR-3 17.6 — THE STAKE LANE NEEDS A BONDED CUSTODIAN: the executor seals the reward leg to every BONDED custodian
        // (`bonded_custodian_eks`) and each advances its stakers'-pool opening from its own leg. T3 just released the journey's
        // only seat (node 0's), so the set is EMPTY: node 0 still executed W2's stake (its seals were non-empty) but no leg was
        // sealed to anyone, its opening stayed put, and the unstake was refused "this custodian's stakers' pool opening is
        // stale" (MEASURED r3/r4-bond-rows-pair.log, twice). A chain never runs without bonded custody; the journey seats node
        // 1's own SAT custody before W2 stakes, the way an operator gets it (`seat_sat_custody`).
        // §BR-3 17.6: node 1 seats its own SAT custody, then W2 stakes and unstakes through it — ONE function, shared with
        // the pair pin `sim_stake_the_br3_17_6_round_passes_on_a_pair` (it reproduces this step without the journey before it)
        match tier3_stake_round(sim, w2, within) {
            Ok(steps) => done.extend(steps),
            Err(e) => return fail(sim, v, "T3", format!("{e} (after {})", done.join(", ")), wall),
        }
        pass_inv(sim, v, "T3", done.join(" · "), wall)
    }

    /// ⭐ §BR-3 17.6 — THE STAKE ROUND (T3's last phase, and the pair pin's whole claim): node 1 seats its own SAT custody,
    /// W2 stakes 0.01 USDm through node 1 and its own scan reads it staked AND unstakable, then unstakes and reads zero.
    /// `Ok` names each step done; `Err` names the step that failed.
    fn tier3_stake_round(
        sim: &mut NetSim,
        w2: &crate::harness::real_node_journey::wallet::RealWallet,
        within: u64,
    ) -> Result<Vec<String>, String> {
        let mut done: Vec<String> = Vec::new();
        if !sim.seat_sat_custody(1, within * 1_000) {
            return Err(format!("node 1 could not seat its SAT custody before the stake within {within} s"));
        }
        done.push("node 1 seated its own SAT custody".into());
        // §17.6 (R7 F9): a stake is READ as staked before it can be SPENT — the shipped Earn screen offers Unstake only once
        // the core's own dry run says the stake's member leg is ready (`can_unstake`). This arm presses what the user can press:
        // after the stake it waits for `can_unstake`, never for `is_staking` alone. MEASURED (r3-bond-rows-pair.log): pressed
        // on `is_staking` alone, the unstake was refused "the network did not take an unstake yet (BAD_REQUEST)".
        let staked_reads = |sim: &mut NetSim, want: bool| -> Option<serde_json::Value> {
            let (sim_t0, t0) = (sim.now, std::time::Instant::now());
            loop {
                let r = wrun(sim, w2, &["refresh", "mystake"], 120).ok().and_then(|l| op_ok(&l, "mystake").ok());
                if r.as_ref().is_some_and(|r| r["is_staking"].as_bool() == Some(want) && (!want || r["can_unstake"].as_bool() == Some(true))) {
                    return r;
                }
                if !within_budget(sim, sim_t0, t0, within) {
                    return None;
                }
                sim.run(500, 10_000);
            }
        };
        for (cmd, op, want) in [("stake 0.01", "stake", true), ("unstake", "unstake", false)] {
            let p = w2.clone_handle();
            let c = cmd.to_string();
            crate::harness::sim_coverage::note_wallet(&c);
            let Some((ok, _secs, reply)) = while_meshing(sim, within, move || p.pay_in_session(&c, op, within)) else {
                return Err(format!("W2's {op} did not finish within {within} s"));
            };
            let taken = if op == "stake" { reply.contains("\"published\":true") } else { reply.contains("\"unstaked\":") };
            if !ok || !taken {
                return Err(format!("W2 could not {op}: {}", reply.chars().take(600).collect::<String>()));
            }
            if staked_reads(sim, want).is_none() {
                return Err(format!("W2's own scan never read is_staking={want} after its {op} within {within} s"));
            }
        }
        done.push("W2 staked 0.01 USDm through a non-custodian node and unstaked it".into());
        Ok(done)
    }

    /// ⭐ THE POS TAP, BLE EMULATED: the merchant's and the payer's wallet processes run the tap's four protocol crossings
    /// (`tapcharge-begin` → `-encaps` → `-seal` → `-open`, the `moneropay_ble::tap_*` steps the radio path runs), and this
    /// function is the AIR between them — it carries exactly the frames each side put on it, nothing else. The payer then
    /// pays the VERIFIED charge through the ONE pay path (`tappay` = `wallet_pos_pay`) and the merchant reads the money
    /// through ITS OWN node. Only the radio is emulated; every byte that crosses it and every money path is the shipped one.
    fn pos_tap(
        sim: &mut NetSim,
        payer: &crate::harness::real_node_journey::wallet::RealWallet,
        merchant: &crate::harness::real_node_journey::wallet::RealWallet,
        within: u64,
    ) -> Result<String, String> {
        const CHARGE_ATOMIC: u64 = 25_000_000;
        crate::harness::sim_coverage::note_wallet("tapcharge-begin");
        crate::harness::sim_coverage::note_wallet("tappay");
        let before = balance_until(sim, merchant, 60, |_| true);
        let (p, m) = (payer.clone_handle(), merchant.clone_handle());
        let crossings_wall = std::time::Instant::now();
        let charge_hex = while_meshing(sim, 300, move || -> Result<String, String> {
            let frames = |reply: Option<String>, what: &str| -> Result<String, String> {
                let r = reply.ok_or_else(|| format!("{what}: the wallet gave no reply"))?;
                let v: serde_json::Value = serde_json::from_str(&r).map_err(|e| format!("{what}: {e}"))?;
                if v["ok"] != true {
                    return Err(format!("{what}: {r}"));
                }
                let f = &v["result"]["frames"];
                if !f.as_array().is_some_and(|a| !a.is_empty()) {
                    return Err(format!("{what} put no frames on the air: {r}"));
                }
                Ok(f.to_string())
            };
            let mut ms = m.session(300)?;
            let mut ps = p.session(300)?;
            let ek = frames(ms.ask(&format!("tapcharge-begin {CHARGE_ATOMIC}"), "tapcharge-begin"), "the merchant's key")?;
            let ct = frames(ps.ask(&format!("tapcharge-encaps {ek}"), "tapcharge-encaps"), "the payer's ciphertext")?;
            let sealed = frames(ms.ask(&format!("tapcharge-seal {ct}"), "tapcharge-seal"), "the merchant's sealed charge")?;
            let opened = ps.ask(&format!("tapcharge-open {sealed}"), "tapcharge-open").ok_or("the payer's open gave no reply")?;
            let o: serde_json::Value = serde_json::from_str(&opened).map_err(|e| format!("the opened charge: {e}"))?;
            if o["ok"] != true {
                return Err(format!("the payer could not open the charge it was handed: {opened}"));
            }
            if o["result"]["atomic"].as_u64() != Some(CHARGE_ATOMIC) {
                return Err(format!("the payer read a different amount than the merchant sealed: {opened}"));
            }
            o["result"]["charge_hex"].as_str().map(str::to_string).ok_or_else(|| format!("the verified charge carries no charge: {opened}"))
        })
        .ok_or("the tap's crossings did not finish within 300 s")??;
        // PERF P7: the tap's four protocol crossings (BLE emulated: the radio's own airtime is not in this figure)
        super::perf::row(
            "P7 POS tap crossings (begin → encaps → seal → open)",
            crossings_wall.elapsed().as_secs_f64(),
            "s",
            None,
            "wallet wall, both wallets' compute; BLE airtime not included",
        );
        let p2 = payer.clone_handle();
        let tap_sim_t0 = sim.now;
        let (paid, secs, last) = while_meshing(sim, 420, move || p2.pay_in_session(&format!("tappay {charge_hex}"), "tappay", 420))
            .ok_or("the tap payment did not finish within 420 s")?;
        if !paid {
            return Err(format!("the payer's tappay was refused after {secs:.1} s: {last}"));
        }
        let sent_at = sim.now;
        super::perf::row(
            "P7 POS tap → the payer's wallet shows paid",
            secs,
            "s",
            Some(1.0),
            &format!("wallet wall (prove + submit; {:.1} s simulated passed meanwhile)", (sent_at - tap_sim_t0) as f64 / 1e3),
        );
        // the merchant sees it: the same timed read as P2 (spendable at or above before + the charge)
        let (after, seen, ready, poll_ms) = receive_timed(sim, merchant, within, before + CHARGE_ATOMIC - 1, sent_at);
        let wait = |ms: Option<u64>| ms.map_or(f64::INFINITY, |m| m as f64 / 1e3);
        super::perf::row_within(
            "P7 POS tap paid → the merchant's wallet sees it",
            wait(seen),
            "s",
            Some(2.0),
            &format!("sim chain wait, node CPU charged, read through the merchant's wallet ≤ +{:.1} s (one poll)", poll_ms as f64 / 1e3),
            poll_ms as f64 / 1e3,
        );
        super::perf::row_within(
            "P7 POS tap paid → the merchant can spend it",
            wait(ready),
            "s",
            None,
            &format!("sim chain wait, node CPU charged · ≤ +{:.1} s (one poll)", poll_ms as f64 / 1e3),
            poll_ms as f64 / 1e3,
        );
        if after < before + CHARGE_ATOMIC {
            return Err(format!("the merchant (node 1) read {before} → {after}, wanted +{CHARGE_ATOMIC}"));
        }
        Ok(format!("POS tap paid {CHARGE_ATOMIC} atomic (merchant {before} → {after} through node 1)"))
    }

    /// ⭐⭐ THE ECOSYSTEM ARMS, UNBLOCKED (2026-10-06): the same simulated mesh and shipped wallet as the fast journey, funded the
    /// same way (T1.0–T1.2), then straight into Tier 2 (an asset, a resting DEX ladder seen across nodes, a fill) and Tier 3
    /// (bond / unbond, a username, a profile, a letter, a POS tap) with no restart between — so a red in any of those
    /// surfaces is found the day it exists, not after every Tier-1 restart step is green. Lane `fast-eco`: the ledgers keep
    /// the main journey's rows; this lane's verdicts are printed. A green here is not a journey pass.
    #[test]
    fn sim_journey_ecosystem_fast_with_the_bound_band_double() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(0x7131_0006_2026_1006);
        super::perf::begin("fast-eco", seed);
        let mut sim = NetSim::testnet(2, Physics::from_env(), seed)
            .with_band_double()
            .with_template_double()
            .with_journey_stake_lock()
            .boot_from_disk();
        sim.charge_cpu = true;
        sim.check_state = true;
        let mut v = Vec::new();
        crate::harness::sim_coverage::start();
        let funded = fund_pair(&mut sim, &mut v, &wall, "simeco");
        let go = funded.and_then(|(w1, w2, _, _, within)| {
            tier2(&mut sim, &mut v, &wall, &w1, &w2, within)?;
            tier3(&mut sim, &mut v, &wall, &w1, &w2, within)
        });
        crate::harness::sim_coverage::finish("journey-eco");
        eprintln!("[sim-journey] eco lane: sim {} s · wall {:?} · {}", sim.now / 1000, wall.elapsed(), speed_line());
        run_rows(&sim);
        served_vs_folded_census(&sim);
        journey::record("fast-eco", seed, &v);
        // SPEED (user 2026-10-06, "we cant settle for slow runs"): the census needs a QUIET mesh, and after a red step the
        // mesh is mid-step — MEASURED sim-20261006-212115: "quiet false after 600 s · DIFFERS 0 · NOT-QUIET 162", ~180 s
        // of wall that judged nothing. It runs when the journey passed; its own pin
        // (`replica_census_every_replicated_field_agrees`, 9 s) measures every run either way.
        if go.is_some() {
            sim.replica_census("fast-eco"); // DB-402 R1 run point (b): rows only — the journey's verdicts are its own
        } else {
            eprintln!("[replica-census] fast-eco: not run — the journey stopped at a red step, so the mesh cannot be quiet; the census pin measures it");
        }
        assert!(go.is_some(), "⛔ the ecosystem journey stopped at {:?}", v.last().map(|(id, _, d)| (*id, d.clone())));
    }

    /// Every field of `Node`, read from the struct's own source — the census's universe.
    fn node_struct_fields() -> Vec<String> {
        let src = include_str!("../node.rs");
        let start = src.find("\npub struct Node {").expect("the Node struct");
        let body = &src[start + 1..];
        let end = body.find("\n}\n").expect("the Node struct's end");
        body[..end]
            .lines()
            .skip(1)
            .filter_map(|l| {
                let t = l.strip_prefix("    ")?;
                if t.starts_with(' ') || t.starts_with('/') || t.starts_with('#') {
                    return None;
                }
                let t = t.strip_prefix("pub(crate) ").or_else(|| t.strip_prefix("pub ")).unwrap_or(t);
                let (name, _) = t.split_once(':')?;
                name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_').then(|| name.to_string())
            })
            .collect()
    }

    /// ⭐ THE RESTART CENSUS IS TOTAL: every `Node` field the source declares is digested, stood in for, or declared VOLATILE
    /// with a reason — a field added tomorrow that is none of these turns this red. DB-402 R2: the census's field list is
    /// DERIVED by the compiler (`NodeFieldCensus`), so the only work a new field can need is a stand-in or a reason; this pin
    /// also cross-checks the derive against an independent read of the struct's source (two derivations must agree).
    #[test]
    fn the_restart_census_names_every_node_field() {
        let declared = node_struct_fields();
        let node = Node::with_params(crate::block::genesis_block(), crate::params::ChainParams::default()).expect("genesis");
        let digest = node.restart_census_digest();
        let stand: Vec<&str> = node.restart_census_stand_ins().iter().map(|(n, _)| *n).collect();
        let volatile: Vec<&str> = crate::node::restart_census_stand_ins::VOLATILE.iter().map(|(n, _)| *n).collect();
        let mut holes = Vec::new();
        let derived: Vec<&str> = Node::NODE_FIELD_NAMES.to_vec();
        if derived != declared.iter().map(String::as_str).collect::<Vec<_>>() {
            holes.push(format!(
                "the derived field list ({} fields) and the source read ({} fields) disagree: derived-only {:?}, source-only {:?}",
                derived.len(),
                declared.len(),
                derived.iter().filter(|d| !declared.iter().any(|f| f == *d)).collect::<Vec<_>>(),
                declared.iter().filter(|f| !derived.contains(&f.as_str())).collect::<Vec<_>>()
            ));
        }
        let stood: Vec<&str> = crate::node::restart_census_stand_ins::STOOD_IN.to_vec();
        if stand != stood {
            holes.push(format!("restart_census_stand_ins() names {stand:?} but STOOD_IN skips {stood:?} — they must be one list"));
        }
        // A declaration naming no field is refused (a stale exclusion is a blind spot with a reason attached).
        for (list, names) in [
            ("NODE_LOCAL", crate::node::restart_census_stand_ins::NODE_LOCAL.iter().map(|(n, _)| *n).collect::<Vec<_>>()),
            ("UNORDERED", crate::node::restart_census_stand_ins::UNORDERED.iter().map(|(n, _)| *n).collect::<Vec<_>>()),
            ("VOLATILE", volatile.clone()),
            ("STOOD_IN", stood.clone()),
        ] {
            for n in names {
                if !derived.contains(&n) {
                    holes.push(format!("{list} names {n}, which is no Node field — a stale entry is refused"));
                }
            }
        }
        // NODE_LOCAL and the authority manifest rule the same question; an exclusion of a field the manifest rules
        // ChainDerived (or has not ruled) hides chain state from the replicated-state census.
        for (n, _) in crate::node::restart_census_stand_ins::NODE_LOCAL {
            let a = crate::harness::fuzz::authority::AUTHORITY_MANIFEST.iter().find(|(m, _)| m == n).map(|(_, a)| *a);
            if a != Some(crate::harness::fuzz::authority::Authority::LocalCache) {
                holes.push(format!("NODE_LOCAL excludes {n}, which the authority manifest rules {a:?}, not LocalCache"));
            }
        }
        for f in &declared {
            match digest.iter().find(|(n, _)| n == f) {
                None => holes.push(format!("{f}: a Node field the census does not name (regenerate the field list)")),
                Some((_, None)) if !stand.contains(&f.as_str()) && !volatile.contains(&f.as_str()) => {
                    holes.push(format!("{f}: unprintable and neither stood in for nor declared VOLATILE"))
                }
                _ => {}
            }
        }
        for (n, _) in &digest {
            if !declared.iter().any(|f| f == n) {
                holes.push(format!("{n}: named by the census but no longer a Node field"));
            }
        }
        assert!(declared.len() > 150, "CALIBRATION: the source scan found only {} Node fields", declared.len());
        assert!(holes.is_empty(), "⛔ the restart census is not total ({} hole(s)):\n{}", holes.len(), holes.join("\n"));
    }

    /// ⭐⭐⭐ THE RESTART-EQUIVALENCE CENSUS (user 2026-10-06): a node with a chain, credited notes and a spend is restarted
    /// through the PRODUCTION restart (`NetSim::restart` → shutdown save → `Node::boot` from the same files) at an instant
    /// with no block in between, and EVERY `Node` field is compared before and after. A field that differs is state the
    /// restart lost or changed — tonight's five live restart defects were each exactly this — unless `VOLATILE` declares it
    /// process-local with a reason. Each verdict is appended to `scratchpad/restart-census.tsv`, which the hole scanner reads.
    #[test]
    fn restart_census_every_field_survives_a_production_restart() {
        let mut sim = NetSim::testnet(2, Physics::from_env(), 0x7131_0002_2026_1006).boot_from_disk();
        assert!(run_until(&mut sim, 120_000, |s| s.one_chain_between(0, 1)).is_some(), "CALIBRATION: the pair converges");
        let a = credit(&sim, 0, 9_101);
        let b = credit(&sim, 1, 9_102);
        assert!(
            run_until(&mut sim, 180_000, |s| [0, 1].iter().all(|&i| holds(s, i, &a) && holds(s, i, &b))).is_some(),
            "CALIBRATION: both credits are held by both nodes"
        );
        let spent = spend_when_spendable(&mut sim, 0, &a, 1, 120_000).is_ok();
        sim.run(20_000, 10_000);
        let volatile: Vec<&str> = crate::node::restart_census_stand_ins::VOLATILE.iter().map(|(n, _)| *n).collect();
        let snapshot = |sim: &NetSim, i: usize| sim.field_census(i);
        let mut rows = String::new();
        let mut changed = Vec::new();
        for i in [1usize, 0] {
            let before = snapshot(&sim, i);
            // The census text of every non-volatile field BEFORE the restart (the live process is gone after it), so
            // a CHANGED map/set field can name the ITEMS one side holds and the other lacks — lane a 2026-10-22: the
            // size row alone ("9613 B → 9613 B") named no key. Same census text the replica census prints, on
            // simulated fixture nodes. DIGITAL-CASH-PRIVACY-REVIEWED: test-only harness print of a fixture node.
            let before_text: Vec<Option<String>> = before
                .iter()
                .map(|(f, _)| {
                    if volatile.contains(f) {
                        return None;
                    }
                    let rt = sim.rt(i);
                    let mut s = String::new();
                    rt.node().census_field_render(f, &mut s).then_some(s)
                })
                .collect();
            // the wants in flight at the restart instant: VOLATILE only because the fold re-derives them — asserted below
            let wanted_before = sim.rt(i).node().wanted_record_ids();
            let blocks_wanted_before = sim.rt(i).node().wanted_block_slot_ids();
            let inflight_before = sim.rt(i).node().inflight_tx_ids_for_test();
            sim.restart(i, 0).expect("the node boots from its own files");
            let after = snapshot(&sim, i);
            for (k, ((f, x), (_, y))) in before.iter().zip(after.iter()).enumerate() {
                let verdict = if volatile.contains(f) {
                    "VOLATILE"
                } else if x == y {
                    "SAME"
                } else {
                    changed.push(format!(
                        "node {i} · {f}: before {} B → after {} B",
                        x.map_or(0, |d| d.1),
                        y.map_or(0, |d| d.1)
                    ));
                    if let Some(bt) = before_text[k].as_deref() {
                        let rt = sim.rt(i);
                        let n = rt.node();
                        let render = |side: bool, out: &mut dyn std::fmt::Write| {
                            if side {
                                n.census_field_render(f, out)
                            } else {
                                out.write_str(bt).is_ok()
                            }
                        };
                        match crate::node::restart_census_fields::set_difference(&render, 120, 8) {
                            Ok((ob, oa, lb, la)) => eprintln!(
                                "[restart-census-set] node{i}\t{f}\tbefore {lb} item(s), after {la}; only before: {ob:?}; only after: {oa:?}"
                            ),
                            Err(why) => eprintln!("[restart-census-set] node{i}\t{f}\t{why}"),
                        }
                    }
                    "CHANGED"
                };
                rows.push_str(&format!("[restart-census-row] node{i}\t{f}\t{verdict}\t{}\t{}\n", x.map_or(0, |d| d.1), y.map_or(0, |d| d.1)));
            }
            sim.run(10_000, 10_000);
            // ⛔ a want the restart dropped must come back: each id wanted before is held now or wanted again
            let lost: Vec<u64> = {
                let rt = sim.rt(i);
                let n = rt.node();
                let again = n.wanted_record_ids();
                wanted_before.iter().copied().filter(|r| !n.da_record_held(*r) && !again.contains(r)).collect()
            };
            eprintln!("[restart-census] node{i}: {} want(s) in flight at the restart; re-derived or filled: {}", wanted_before.len(), wanted_before.len() - lost.len());
            if !lost.is_empty() {
                changed.push(format!("node {i} · wanted_record_ids: {} record want(s) the restart dropped and the fold never re-derived: {lost:?}", lost.len()));
            }
            // ⛔ the same law on the by-id block lane: each block wanted before is held, parked or wanted again
            let lost_blocks: Vec<_> = {
                let rt = sim.rt(i);
                let n = rt.node();
                blocks_wanted_before.iter().copied().filter(|b| n.dag().get(b).is_none() && !n.relay_parked(b) && !n.wants_block(b)).collect()
            };
            eprintln!("[restart-census] node{i}: {} block want(s) in flight at the restart; re-derived or filled: {}", blocks_wanted_before.len(), blocks_wanted_before.len() - lost_blocks.len());
            if !lost_blocks.is_empty() {
                changed.push(format!("node {i} · wanted_block_slots: {} block want(s) the restart dropped and nothing re-derived: {lost_blocks:?}", lost_blocks.len()));
            }
            // ⛔ VALUE: a template in flight at the restart dies with the process, never its payments — each tx it held is
            // carried by a block this node holds, or still pooled by some node of the mesh
            let lost_txs: Vec<_> = inflight_before
                .iter()
                .filter(|t| {
                    let carried = {
                        let rt = sim.rt(i);
                        let dag = rt.node().dag();
                        dag.block_ids().iter().any(|b| dag.get(b).is_some_and(|x| x.tx_ids.contains(t)))
                    };
                    !carried && !(0..sim.rts.len()).any(|j| sim.rt(j).node().mempool().contains(t))
                })
                .copied()
                .collect();
            eprintln!("[restart-census] node{i}: {} tx(s) in an in-flight template at the restart; carried or pooled: {}", inflight_before.len(), inflight_before.len() - lost_txs.len());
            if !lost_txs.is_empty() {
                changed.push(format!("node {i} · inflight_tx_ids: {} payment(s) the restart dropped — carried by no block, pooled by no node: {lost_txs:?}", lost_txs.len()));
            }
        }
        eprint!("{rows}");
        eprintln!("[restart-census] spend landed before the census: {spent}; {} field change(s) across 2 restarts", changed.len());
        for c in &changed {
            eprintln!("[restart-census] CHANGED {c}");
        }
        assert!(changed.is_empty(), "⛔ a production restart changed {} field(s):\n{}", changed.len(), changed.join("\n"));
    }

    /// ⭐ DB-437 — A SEATED MESH FINALIZES, AND EVERY NODE HOLDS IT. Three validator daemons (each asks the chain for its
    /// seat at boot, `Node::request_own_seat_at_boot`) run the one voter (`vote_guard::vote_tick`); every node must hold all
    /// three seats — from the blocks that carried them — and a finalized height above 0, and two nodes at the same
    /// finalized height must name the same block. RED before DB-437: the simulator seated nobody and voted nothing, so every
    /// node read `finalized 0` (link 43's P4 row at tip 3,171 and 20,333).
    /// TWO-PARTY-REVIEWED: three independent `Node`s over the simulated wire; the assertion reads what EACH node holds.
    #[test]
    fn db437_a_seated_mesh_holds_every_seat_and_every_node_finalizes() {
        let mut sim = NetSim::testnet(3, Physics::from_env(), 0x7131_0437_2026_1008).boot_from_disk();
        let seats = |s: &NetSim| (0..3).map(|i| s.rt(i).node().validators().finality_seats().len()).collect::<Vec<_>>();
        let fin = |s: &NetSim| {
            (0..3)
                .map(|i| {
                    let n = s.rt(i);
                    (n.node().finalized_height(), n.node().finalized_block())
                })
                .collect::<Vec<_>>()
        };
        let seated = run_until(&mut sim, 300_000, |s| seats(s).iter().all(|&k| k == 3));
        assert!(seated.is_some(), "⛔ every node must hold the three seats from the blocks that carried them — held {:?}", seats(&sim));
        let finalized = run_until(&mut sim, 600_000, |s| fin(s).iter().all(|(h, _)| *h > 0));
        let f = fin(&sim);
        let tips: Vec<u64> = (0..3).map(|i| sim.rt(i).node().tip_height()).collect();
        eprintln!("[db437] seats {:?} · finalized (height, block) {:?} · tips {tips:?}", seats(&sim), f.iter().map(|(h, b)| (*h, b.map(|b| b.to_hex()[..8].to_string()))).collect::<Vec<_>>());
        assert!(finalized.is_some(), "⛔ every node must finalize a height above 0 — finalized {:?} at tips {tips:?}", f.iter().map(|(h, _)| *h).collect::<Vec<_>>());
        for i in 0..3 {
            for j in i + 1..3 {
                if f[i].0 == f[j].0 {
                    assert_eq!(f[i].1, f[j].1, "⛔ nodes {i} and {j} finalized DIFFERENT blocks at height {}", f[i].0);
                }
            }
        }
    }

    /// ⭐⭐⭐ DB-402 R1 — THE REPLICATED-STATE CENSUS, dedicated pin: two nodes, credits on each, a spend, the same resting
    /// offer on both books; production paused until the mesh is quiet; then EVERY `Node` field not declared `NODE_LOCAL` must
    /// read the same on both nodes. CALIBRATION, DB-401's exact shape: node 1's copy of a second offer is HOLLOW (its maker's
    /// membership bind dropped, same count) — the census must read `order_book DIFFERS`, and nothing else may move.
    /// (The eco journey's own census row covers a REAL-bind ladder post, an asset create and a fill on the shipped wallet.)
    /// TWO-PARTY-REVIEWED: two independent `Node`s (`NetSim::testnet(2, ..)`, each booted from its own datadir), each grafting
    /// the other's blocks over the simulated wire; the assertion is that the two AGREE on every replicated field.
    #[test]
    fn replica_census_every_replicated_field_agrees_across_the_mesh() {
        let mut sim = NetSim::testnet(2, Physics::from_env(), 0x7131_0007_2026_1006).with_band_double().boot_from_disk();
        assert!(run_until(&mut sim, 120_000, |s| s.one_chain_between(0, 1)).is_some(), "CALIBRATION: the pair converges");
        let a = credit(&sim, 0, 9_401);
        let b = credit(&sim, 1, 9_402);
        assert!(
            run_until(&mut sim, 180_000, |s| [0, 1].iter().all(|&i| holds(s, i, &a) && holds(s, i, &b))).is_some(),
            "CALIBRATION: both credits are held by both nodes"
        );
        // MEASURED 2026-10-06 (db402-pins-202615.log): the node-built spend helper answers `MemberCarrierRequired` on this
        // mesh — the restart census's spend reads "landed: false" the same way (OPEN). Recorded, not assumed: the census
        // compares whatever state the mesh holds; the journeys' census rows cover wallet-built spends.
        let spent = spend_when_spendable(&mut sim, 0, &a, 1, 120_000);
        eprintln!("[replica-census] pin: spend before the census: {spent:?}");
        for i in [0, 1] {
            sim.rt(i).node_mut().post_selfproof_resting_order();
        }
        sim.produce_paused = true; // stays paused after the census, so the calibration below compares the same quiet mesh
        let rows = sim.replica_census("pin");
        let bad: Vec<String> = rows
            .iter()
            .filter(|r| matches!(r.1, "DIFFERS" | "UNREAD" | "NOT-QUIET"))
            .map(|r| format!("{} {} ({})", r.0, r.1, r.2))
            .collect();
        assert!(rows.iter().any(|r| r.0 == "order_book" && r.1 == "SAME"), "CALIBRATION: the same offer on both books reads SAME");
        // DB-401's shape on the quiet mesh: the same second offer, node 1's copy hollow.
        sim.rt(0).node_mut().post_selfproof_resting_order();
        sim.rt(1).node_mut().post_selfproof_resting_order_without_its_bind();
        let (c0, c1) = (sim.field_census(0), sim.field_census(1));
        let moved: Vec<&str> = c0.iter().zip(c1.iter()).filter(|(x, y)| x.1 != y.1).map(|(x, _)| x.0).collect();
        // every field the census did not read SAME may differ either way (NODE_LOCAL keys, a DIFFERS already reported)
        let before: Vec<&str> = rows.iter().filter(|r| r.1 != "SAME").map(|r| r.0.as_str()).collect();
        assert!(
            moved.contains(&"order_book"),
            "⛔ CALIBRATION FAILED: a hollow copy of an offer (DB-401) does not read DIFFERS — the census is blind to its class"
        );
        assert_eq!(
            moved.iter().filter(|f| **f != "order_book" && !before.contains(f)).count(),
            0,
            "CALIBRATION: the hollow offer moved ONLY the book (moved: {moved:?})"
        );
        assert!(
            bad.is_empty(),
            "⛔ the replicated-state census: {} field(s) are not one function of the chain across two nodes holding it:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// ⭐⭐ §POLES (lane a, 2026-10-25) — THE LAUNCH CENSUS, REDUCED (rule 5c). The 10-node launch leg read 5–15 DIFFERS per
    /// census (finality, sidecar_cursor, block_window, window_index, membership_tip_*, anchor_pow_witness, nf_unfolded_gen,
    /// band_door — confirm-0x7131fa0020261095-leg1.log) while the 2-node pin above reads SAME. The same launch mesh (fast
    /// doubles, stake lock) at FOUR nodes, run until the fold has moved, then the census: every replicated field must agree.
    /// TWO-PARTY-REVIEWED: four independent `Node`s, each booted from its own datadir, meshed over the simulated wire; the
    /// assertion is that all four AGREE on every replicated field.
    #[test]
    fn replica_census_four_launch_nodes_agree_once_the_fold_has_moved() {
        let mut sim = launch_mesh_of(4, journey::seed(0x7131_0425_2026_1025)).boot_from_disk();
        sim.step_census = false;
        sim.charge_cpu = false; // a deterministic schedule: one seed, one run (the launch leg charges CPU; the seed varies it)
        let moved = run_until(&mut sim, 600_000, |s| (0..4).all(|i| s.rt(i).node().served_seq() >= 40));
        assert!(moved.is_some(), "CALIBRATION: the fold moves on all four nodes");
        sim.run(30_000, 10_000);
        let rows = sim.replica_census("pin4");
        for i in 0..4 {
            eprintln!("[pin4-band] n{i}: {}", sim.rt(i).node().band_diag_for_test());
            eprintln!("[pin4-root] n{i}: (selected, heaviest, cursor, depth, served_seq) {:?}", sim.rt(i).node().fold_root_diag_for_test());
        }
        // name every A_tip stamp the four nodes do not all hold alike (a block stamped but never windowed on one node)
        let stamps: Vec<_> = (0..4).map(|i| sim.rt(i).node().nf_stamps_diag_for_test()).collect();
        for (i, d) in stamps.iter().enumerate() {
            for row in d {
                if stamps.iter().any(|o| !o.iter().any(|r| r.0 == row.0)) {
                    eprintln!(
                        "[pin4-stamp] n{i} stamps {} dag {} whole {} in-window {} blue {} · windowed on {:?}",
                        &row.0.to_hex()[..16], row.1, row.2, row.3, row.4,
                        (0..4).map(|j| stamps[j].iter().all(|r| r.0 != row.0)).collect::<Vec<_>>()
                    );
                }
            }
        }
        // name every buffered block the four nodes do not all buffer alike (why one node still holds what its peers windowed)
        let diags: Vec<_> = (0..4).map(|i| sim.rt(i).node().unfolded_diag_for_test()).collect();
        for (i, d) in diags.iter().enumerate() {
            for row in d {
                if diags.iter().any(|o| !o.iter().any(|r| r.0 == row.0)) {
                    let windowed: Vec<bool> = (0..4).map(|j| diags[j].iter().all(|r| r.0 != row.0)).collect();
                    eprintln!(
                        "[pin4-unfolded] n{i} buffers {} whole {} record-folded {} ordinal {:?} blue {} in-own-window {} · served_seq {:?} · not buffered on {:?}",
                        &row.0.to_hex()[..16], row.1, row.2, row.3, row.4, row.5,
                        (0..4).map(|j| sim.rt(j).node().served_seq()).collect::<Vec<_>>(),
                        windowed
                    );
                }
            }
        }
        let bad: Vec<String> = rows
            .iter()
            .filter(|r| matches!(r.1, "DIFFERS" | "UNREAD" | "NOT-QUIET"))
            .map(|r| format!("{} {} ({})", r.0, r.1, r.2))
            .collect();
        assert!(
            bad.is_empty(),
            "⛔ the replicated-state census at four launch nodes: {} field(s) are not one function of the chain:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// ⛔ DB-471 (lane stable 2026-10-30) — FIVE REPLAYERS, NO JOINER: the census past `NF_SHARD_REPLICATION`, where Z2's record
    /// share is in force (`record_shard_policy_for`: above 4 nodes a node keeps the shards its PRIVATE seed ranks first). Every
    /// node replays from genesis, so any DIFFERS here is a field whose value two honest replayers legitimately hold apart —
    /// the measurement a manifest ruling needs (DB-402 §3: "a cold peer replaying the chain would also hold a different
    /// value"). TWO-PARTY-REVIEWED: five independent `Node`s over the simulated wire; the assertion is cross-node.
    #[test]
    #[ignore = "DB-471 census at five replayers (~3–5 min of wall): run by name with --include-ignored"]
    fn replica_census_five_replayers_agree_once_the_fold_has_moved() {
        let mut sim = NetSim::testnet(5, Physics::from_env(), 0x7131_0471_2026_1030).with_band_double().with_template_double();
        sim.make_replayable();
        let mut sim = sim.boot_from_disk();
        sim.step_census = false;
        let moved = run_until(&mut sim, 900_000, |s| (0..5).all(|i| s.rt(i).node().served_seq() >= 40));
        assert!(moved.is_some(), "CALIBRATION: the fold passes ordinal 40 on all five nodes");
        let shares: Vec<usize> = (0..5)
            .map(|i| {
                let rt = sim.rt(i);
                let n = rt.node();
                n.record_shard_policy_for(n.visible_mesh_size()).len()
            })
            .collect();
        eprintln!("[five-retention] record shards held per node (of 256): {shares:?}");
        assert!(shares.iter().all(|s| *s < 256), "CALIBRATION: every node holds a SHARE (the mesh it sees is past NF_SHARD_REPLICATION): {shares:?}");
        for i in 0..5 {
            eprintln!("[five-retention] n{i}: {}", sim.rt(i).node().retention_shape_for_test());
        }
        for i in 0..5 {
            eprintln!("[five-finality] n{i}: {}", sim.rt(i).node().finality_keys_for_test());
        }
        let rows = sim.replica_census("five");
        for i in 0..5 {
            eprintln!("[five-finality-quiet] n{i}: {}", sim.rt(i).node().finality_keys_for_test());
        }
        let bad: Vec<String> = rows
            .iter()
            .filter(|r| matches!(r.1, "DIFFERS" | "UNREAD" | "NOT-QUIET"))
            .map(|r| format!("{} {} ({})", r.0, r.1, r.2))
            .collect();
        assert!(
            bad.is_empty(),
            "⛔ five replayers hold different state: {} field(s) are not one function of the chain:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// ⛔ §POLES T2 (lane a 2026-10-26) — A DSYNC JOINER HOLDS THE SAME STATE AS THE NODES THAT REPLAYED (Kaspa pruning-point
    /// sync: the syncer adopts the pruning point and then holds what every replayer holds). REDUCED from the fast journey's
    /// census (certify 38954c1: 29 of 30 DIFFERS were n0 vs n2, and n2 was the T1.6 joiner that adopted a bundle at ordinal
    /// 196 — completed_windows from 196 vs 1, certified_anchor Some vs None, nf_fold_base at 254 vs 0, the da_* caches).
    /// Three nodes grow the chain past the catch-up depth, node 2 is reinstalled (empty datadir) and joins by the runtime's
    /// own certified adopt, the fold moves on, then the census: every replicated field must agree across all three.
    /// TWO-PARTY-REVIEWED: three independent `Node`s, each booted from its own datadir; the assertion is cross-node.
    #[test]
    fn replica_census_a_dsync_joiner_agrees_with_the_nodes_that_replayed() {
        // the fast journey's lane (the census that measured the 29 joiner DIFFERS): band + template doubles.
        // DETERMINISTIC (lane stable 2026-10-30, the reinstalled-joiner pin's rule): this pin claims STATE, not timing. On the
        // charged mesh the host's measured lock and prove wall became simulated time, so the same seed joined in one run
        // (a2.log, census reached) and trailed 75 blocks for the whole 600 s budget in the next (a3.log: 62 "STUCK" lines,
        // CALIBRATION red) with ten cores held by other lanes — a red that names the machine, not the chain. The uncharged
        // mesh replays exactly from its seed; the charged fast journey (T1.6) keeps measuring the join under real cost.
        // cons: none — no assertion changed, the claim is the census.
        let mut sim = NetSim::testnet(3, Physics::from_env(), 0x7131_0626_2026_1026).with_band_double().with_template_double();
        sim.make_replayable();
        let mut sim = sim.boot_from_disk();
        sim.step_census = false;
        // MEASURED 431136a run 2: a reinstall at served_seq 40 grafts (no adopt). The runtime's adopt trigger a fresh node
        // meets first is LEG 4's `band_past_journal_reach` (node_runtime.rs): a peer band more steps past this node's than
        // any door's journal relays (SPINE_RING_LEN 64) — the trigger the T1.6 joiner took at ordinal 196. So n2 is down from
        // boot while the n0/n1 pair's band passes the reach (920c6dd grew past LIVE_CATCH_UP_DEPTH instead: 2697 s wall).
        sim.hold_down(2);
        let reach = sim.rt(0).node().band_journal_reach() as u64;
        if let Err(why) = run_stage(&mut sim, "the pair's band passes the journal reach", 3_600_000, 120_000, 0, |s| {
            (0..2).all(|i| s.rt(i).node().band_next_ordinal() > reach + 32)
        }) {
            panic!("CALIBRATION: {why}");
        }
        sim.join_fresh(2).expect("the reinstall boots from an empty datadir");
        // MEASURED join3-20261026-0750.log: one_chain_between + view_current read true seconds after the empty boot (n2 at
        // tip 0), so the premise is read only once the joiner's tip is within a page of its peer's.
        if let Err(why) = run_stage(&mut sim, "the joiner reaches one chain and a current view", 600_000, 120_000, 2, |s| {
            s.one_chain_between(0, 2) && view_current(s, 2) && s.rt(2).node().tip_height() + 4 >= s.rt(0).node().tip_height()
        }) {
            panic!("CALIBRATION: {why}");
        }
        assert!(sim.rt(2).node().spine_state().0, "CALIBRATION: the joiner adopted a certified bundle (the arm's premise)");
        let served = sim.rt(0).node().served_seq();
        if let Err(why) = run_stage(&mut sim, "the fold moves 8 ordinals on all three", 600_000, 120_000, 2, |s| {
            (0..3).all(|i| s.rt(i).node().served_seq() >= served + 8)
        }) {
            panic!("CALIBRATION: {why}");
        }
        for i in 0..3 {
            eprintln!("[join3-retention] n{i}: {}", sim.rt(i).node().retention_shape_for_test());
        }
        let rows = sim.replica_census("join3");
        let bad: Vec<String> = rows
            .iter()
            .filter(|r| matches!(r.1, "DIFFERS" | "UNREAD" | "NOT-QUIET"))
            .map(|r| format!("{} {} ({})", r.0, r.1, r.2))
            .collect();
        assert!(
            bad.is_empty(),
            "⛔ a DSYNC joiner and the nodes that replayed hold different state: {} field(s) are not one function of the chain:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// ⭐⭐ THE TESTNET RESET, REHEARSED (lane speed5, 2026-11-18; user: "we should add a regenesis/testnet reset to the netsim so we
    /// can rule out testnet resets before acually doing it"). The live run launched 2026-11-18 stopped for good at band step 5,428
    /// (finding A-F101), and a reset is a NEW network: `params::TESTNET_RUN` commits the run number and the launch files into the
    /// genesis prefix. This boots three nodes on this release's run and ONE node left on the run before it — a node that never
    /// updated stays online after a reset, on the same wire — then asserts, in order:
    /// 1. the old-run node keeps its own genesis, and no block of its chain ever enters a new-run node's DAG;
    /// 2. a fresh node joins the NEW run by bundle (n2 down from boot, then reinstalled empty, the census test's arm) and reaches
    ///    one chain and a current view on the new genesis;
    /// 3. the fold moves 8 ordinals past the join on all three new-run nodes;
    /// 4. the replica census over the three new-run nodes: the joiner holds the same state as the nodes that replayed.
    /// `RESET_SEED` (hex) sweeps other chains from one build. TWO-PARTY-REVIEWED: four independent `Node`s, each booted from
    /// its own datadir; every assertion is cross-node.
    /// ⭐ THE RESET'S ISOLATION, FAST (lane speed5, 2026-11-18; user: "all of our test should be incremental"): two nodes on this
    /// release's run and one on the run before it, one wire, 90 s simulated, no band growth needed. Asserts the N8 rule on real
    /// node code: each new-run node drops the old-run node from its ask rotation once it hears its beacon, and no block of the old
    /// run enters a new-run DAG. RED on the code before N8 (00722750): a foreign beacon was only counted, nothing was excluded.
    /// TWO-PARTY-REVIEWED: three independent `Node`s; every assertion is cross-node.
    #[test]
    fn testnet_reset_new_run_nodes_drop_an_old_run_peer_from_every_ask() {
        let run = crate::params::TESTNET_RUN;
        let sim = NetSim::testnet_run(3, Physics::from_env(), 0x7131_0626_2026_1118, run).make_foreign(2, run - 1);
        let mut sim = sim.with_band_double().with_template_double();
        sim.make_replayable();
        let mut sim = sim.boot_from_disk();
        sim.step_census = false;
        assert_ne!(sim.genesis_of(0), sim.genesis_of(2), "CALIBRATION: two networks");
        if let Err(why) = run_stage(&mut sim, "both new-run nodes drop the old-run peer", 90_000, 90_000, 0, |s| {
            s.has_excluded(0, 2) && s.has_excluded(1, 2)
        }) {
            panic!("N8: {why}");
        }
        assert!(!sim.has_excluded(0, 1) && !sim.has_excluded(1, 0), "a peer of the SAME network was excluded");
        let _ = run_until(&mut sim, 30_000, |_| false);
        // the genesis is read FIRST: `rt(i)` holds node i's lock, and `genesis_of(i)` takes it again (a self-deadlock, measured
        // 2026-11-18: the test hung here, `sample` showed the thread parked in `NetSim::rt` under `genesis_of`)
        let g2 = sim.genesis_of(2);
        let old_tip = sim.rt(2).node().dag().selected_tip();
        if let Some(t) = old_tip.filter(|t| Some(*t) != g2) {
            for i in 0..2 {
                assert!(sim.rt(i).node().dag().get(&t).is_none(), "node {i} took a block of the OLD run");
            }
        }
        assert!(sim.rt(0).node().tip_height() > 0, "CALIBRATION: the new run produced beside the old-run node");
    }

    #[test]
    fn testnet_reset_a_new_run_isolates_the_old_run_and_a_fresh_joiner_follows() {
        // RESET_RUN picks the new run (default this release's); RESET_FOREIGN=0 leaves the old-run node out (node 3 then joins
        // the new run like the others), so one build separates "the new network" from "an old-run node on the wire".
        let run: u32 = std::env::var("RESET_RUN").ok().and_then(|v| v.parse().ok()).unwrap_or(crate::params::TESTNET_RUN);
        let old_run: u32 = if run <= 1 { 3 } else { run - 1 };
        let foreign = std::env::var("RESET_FOREIGN").map_or(true, |v| v != "0");
        let seed = std::env::var("RESET_SEED")
            .ok()
            .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0x7131_0626_2026_1026);
        let sim = NetSim::testnet_run(4, Physics::from_env(), seed, run);
        let mut sim = if foreign { sim.make_foreign(3, old_run) } else { sim }.with_band_double().with_template_double();
        sim.make_replayable();
        let mut sim = sim.boot_from_disk();
        sim.step_census = false;
        let new_genesis = sim.genesis_of(0).expect("the new run's genesis");
        let old_genesis = sim.genesis_of(3).expect("the old run's genesis");
        assert!(!foreign || new_genesis != old_genesis, "CALIBRATION: the old run and the new run are two networks");
        for i in 0..3 {
            assert_eq!(sim.genesis_of(i), Some(new_genesis), "CALIBRATION: node {i} boots on the new run");
        }
        sim.hold_down(2);
        let reach = sim.rt(0).node().band_journal_reach() as u64;
        if let Err(why) = run_stage(&mut sim, "band grows past the journal reach", 3_600_000, 120_000, 0, |s| {
            (0..2).all(|i| s.rt(i).node().band_next_ordinal() > reach + 32)
        }) {
            panic!("CALIBRATION: {why}");
        }
        sim.join_fresh(2).expect("the reinstall boots from an empty datadir");
        let joined = run_stage(&mut sim, "the joiner reaches one chain and a current view", 600_000, 120_000, 2, |s| {
            s.one_chain_between(0, 2) && view_current(s, 2) && s.rt(2).node().tip_height() + 4 >= s.rt(0).node().tip_height()
        });
        for i in 0..4 {
            let rt = sim.rt(i);
            let n = rt.node();
            eprintln!(
                "[reset-rehearsal] n{i}: genesis {} tip {} served_seq {} nf_fold_seq {} nf_blocks {} band next {}",
                n.dag().genesis().map(|g| g.to_hex()[..8].to_string()).unwrap_or_default(),
                n.tip_height(),
                n.served_seq(),
                n.nf_fold_seq(),
                n.nf_blocks_folded(),
                n.band_next_ordinal()
            );
        }
        if let Err(why) = joined {
            panic!("the joiner of the NEW run: {why}");
        }
        assert_eq!(sim.genesis_of(2), Some(new_genesis), "the joiner adopted the new run, never the old one");
        let served = sim.rt(0).node().served_seq();
        if let Err(why) = run_stage(&mut sim, "the fold moves 8 ordinals on all three", 600_000, 120_000, 2, |s| {
            (0..3).all(|i| s.rt(i).node().served_seq() >= served + 8)
        }) {
            panic!("the new run's fold: {why}");
        }
        // 1. isolation, both ways: the old run kept its genesis, and no block of its chain is in a new-run DAG
        if foreign {
            assert_eq!(sim.genesis_of(3), Some(old_genesis), "the old-run node stays on its own network");
            let g3 = sim.genesis_of(3); // read first: rt(3) and genesis_of(3) take the same lock
            let tip3 = sim.rt(3).node().dag().selected_tip();
            if let Some(old_tip) = tip3.filter(|t| Some(*t) != g3) {
                for i in 0..3 {
                    assert!(sim.rt(i).node().dag().get(&old_tip).is_none(), "node {i} took a block of the OLD run into the new run's DAG");
                }
            }
        }
        // 4. the census over the new run alone
        sim.hold_down(3);
        let w = std::time::Instant::now();
        let rows = sim.replica_census("reset");
        eprintln!("[stage] census: read in {} ms wall", w.elapsed().as_millis());
        let bad: Vec<String> = rows
            .iter()
            .filter(|r| matches!(r.1, "DIFFERS" | "UNREAD" | "NOT-QUIET"))
            .map(|r| format!("{} {} ({})", r.0, r.1, r.2))
            .collect();
        assert!(
            bad.is_empty(),
            "⛔ after a reset, a joiner of the new run and the nodes that replayed it hold different state: {} field(s):\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// ⭐ THE LAUNCH SIMULATOR (lane testnet, 2026-11-17; user: "you should create a simulator for a large testnet launch using real
    /// node pieces that dont take up cpu and memory"). Every party is the real node — `Node::boot`, the daemon's relay and producer
    /// loops, the runtime's own DSYNC adopt, the fold, finality — in ONE process on the simulated clock, with the proofs as the bound
    /// band and template doubles, so a party costs memory, not cores. The launch: `LAUNCH_SEEDS` seeds grow the chain past the
    /// band's journal reach (so a joiner must adopt a certified bundle, as at a real launch), then `LAUNCH_JOINERS` fresh installs
    /// arrive one every `LAUNCH_WAVE_MS` while the earlier ones keep running. Each joiner is held to the live gate's predicates (one
    /// chain with node 0, a current view, its tip within a page of node 0's) inside `LAUNCH_JOIN_BUDGET_MS` of its arrival, and to
    /// A-F91's measured symptom: its locator index holds every tag node 0 holds below their common fold position. One line per
    /// joiner, then the process's memory. `LAUNCH_CHARGED=1` charges the host's measured compute as simulated time (A-F94's
    /// class); the default replays exactly from `LAUNCH_SEED`.
    /// SCALE (SAFE AT SCALE): memory grows with the parties. MEASURED 2026-11-17 on main f96b563f's pin binary: 3 parties 813 MB,
    /// 10 parties 2.1 GB peak, about 150-200 MB a party, so the party count is bounded by the host's memory; the mesh-rate rules at
    /// 1,000-3,000 producers stay `scratchpad/net/pace.py`'s. A discovery instrument: a red here is a finding to reproduce on real
    /// nodes, never a readiness verdict. What protects it (AI RESISTANT): (b) ordinary code — it reads the nodes' own state.
    /// TWO-PARTY-REVIEWED: every party is an independent `Node` booted from its own datadir over the simulated wire; every assertion
    /// is cross-node — a joiner against node 0 (one chain, tip, fold position, the tags each holds).
    #[test]
    #[ignore = "the launch simulator: run it by name with --ignored (LAUNCH_* knobs)"]
    fn launch_sim_seeds_then_waves_of_fresh_joiners_each_follow_the_chain() {
        let knob = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(d);
        let seeds = knob("LAUNCH_SEEDS", 2) as usize;
        let joiners = knob("LAUNCH_JOINERS", 4) as usize;
        let wave_ms = knob("LAUNCH_WAVE_MS", 60_000);
        let budget_ms = knob("LAUNCH_JOIN_BUDGET_MS", 600_000);
        let seed = knob("LAUNCH_SEED", 0x1A0C_2026_1117);
        let n = seeds + joiners;
        assert!(seeds >= 2, "a launch needs two seeds: one chain between two producers before anyone joins");
        let mut sim = NetSim::testnet(n, Physics::from_env(), seed).with_band_double().with_template_double();
        if knob("LAUNCH_CHARGED", 0) == 0 {
            sim.make_replayable();
        }
        let mut sim = sim.boot_from_disk();
        sim.step_census = false;
        for j in seeds..n {
            sim.hold_down(j);
        }
        let wall = std::time::Instant::now();
        let reach = sim.rt(0).node().band_journal_reach() as u64;
        let grown = run_until(&mut sim, 3_600_000, |s| (0..seeds).all(|i| s.rt(i).node().band_next_ordinal() > reach + 32));
        assert!(grown.is_some(), "CALIBRATION: the seeds' band passes the journal reach ({reach}) before the first joiner: {}", diag(&sim));
        eprintln!("[launch] {seeds} seed(s) grew past the journal reach ({reach}) in {} s simulated", grown.unwrap_or(0) / 1000);
        let follows = |s: &NetSim, j: usize| {
            s.one_chain_between(0, j) && view_current(s, j) && s.rt(j).node().tip_height() + 4 >= s.rt(0).node().tip_height()
        };
        let mut started: Vec<u64> = vec![0; n];
        let mut caught: Vec<Option<u64>> = vec![None; n];
        // G4: node 0's finalized height at the moment each joiner caught — the floor its own finality must pass by the end
        let mut fin0_at_catch: Vec<u64> = vec![0; n];
        let tick = |sim: &mut NetSim, caught: &mut Vec<Option<u64>>, fin0_at_catch: &mut Vec<u64>, upto: usize| {
            sim.run(1_000, 10_000);
            for k in seeds..upto {
                if caught[k].is_none() && follows(sim, k) {
                    caught[k] = Some(sim.now);
                    fin0_at_catch[k] = sim.rt(0).node().user_final_height();
                }
            }
        };
        for j in seeds..n {
            sim.join_fresh(j).expect("a fresh install boots from an empty datadir");
            started[j] = sim.now;
            let t_end = sim.now + wave_ms;
            while sim.now < t_end {
                tick(&mut sim, &mut caught, &mut fin0_at_catch, j + 1);
            }
        }
        let deadline = started[n - 1] + budget_ms;
        while sim.now < deadline && (seeds..n).any(|k| caught[k].is_none()) {
            tick(&mut sim, &mut caught, &mut fin0_at_catch, n);
        }
        // A-F91's symptom, read from each node's own index inputs: the tags below the common fold position, joiner against node 0.
        let tags_below = |s: &NetSim, i: usize, m: u64| {
            let rt = s.rt(i);
            let node = rt.node();
            node.oli_build_inputs(node.served_seq()).klog.iter().filter(|e| e.0 < m).count()
        };
        // ⭐ THE INDEX AND THE STATE SETTLE, MEASURED (lane speed5, 2026-11-17, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md J13): the
        // tags were read the instant the last joiner followed, so a record still on the record lane read as a missing one
        // (MEASURED main 4e899429: n5 followed at 638 s, the run ended at 662 s, 17 records short). The claim is unchanged — every
        // joiner holds every tag node 0 holds below their common fold, and every pair of nodes agrees on its state — and it is
        // judged after at most LAUNCH_SETTLE_MS more (default 120 s simulated), the time it took printed; a gap that stays fails.
        let settle_ms = knob("LAUNCH_SETTLE_MS", 120_000);
        let settle_from = sim.now;
        let whole = |s: &NetSim| {
            (seeds..n).all(|k| {
                let m = s.rt(0).node().served_seq().min(s.rt(k).node().served_seq()).saturating_sub(8);
                tags_below(s, k, m) >= tags_below(s, 0, m)
            }) && s.state_divergence().is_none()
        };
        while sim.now < settle_from + settle_ms && !whole(&sim) {
            tick(&mut sim, &mut caught, &mut fin0_at_catch, n);
        }
        eprintln!(
            "[launch] index and state {} {} s after the last joiner's arrival window closed",
            if whole(&sim) { "whole and agreed" } else { "NOT whole or NOT agreed" },
            (sim.now - settle_from) / 1000
        );
        let mut bad: Vec<String> = Vec::new();
        for k in seeds..n {
            let (s0, sk) = (sim.rt(0).node().served_seq(), sim.rt(k).node().served_seq());
            let m = s0.min(sk).saturating_sub(8);
            let (t0, tk) = (tags_below(&sim, 0, m), tags_below(&sim, k, m));
            let adopted = sim.rt(k).node().spine_state().0;
            let line = format!(
                "[launch] joiner n{k}: arrived at {} s, {}; bundle adopted {adopted}; fold {sk} vs node 0 {s0}; tags below {m}: {tk} vs node 0 {t0}",
                started[k] / 1000,
                match caught[k] {
                    Some(t) if t <= started[k] + budget_ms => format!("followed the chain after {} s", (t - started[k]) / 1000),
                    _ => format!("did NOT follow the chain within {} s", budget_ms / 1000),
                }
            );
            eprintln!("{line}");
            if caught[k].map_or(true, |t| t > started[k] + budget_ms) || tk < t0 {
                bad.push(line);
            }
            // ⛔ G4 — FINALITY NEVER STALLS ON A JOINER: by the end it has passed what node 0 had finalized when it caught.
            // MEASURED main 4e899429: every joiner stood at its pre-re-anchor height (26/74/99/115) against the seeds' 211.
            let fin_k = sim.rt(k).node().user_final_height();
            if caught[k].is_some() && fin_k < fin0_at_catch[k] {
                bad.push(format!(
                    "[launch] joiner n{k}: finality {fin_k} never reached node 0's {} at the moment it caught (node 0 now {})",
                    fin0_at_catch[k],
                    sim.rt(0).node().user_final_height()
                ));
            }
        }
        if let Some(d) = sim.state_divergence() {
            bad.push(format!("[launch] state: {d}"));
        }
        // THE CHAIN AT THIS SIZE, read from every node's own state: its tip, its finalized height and its fold position, the
        // mesh's block rate on node 0's chain, and whether every party stands on node 0's chain.
        let secs = (sim.now / 1000).max(1);
        let mut fin_lag = Vec::new();
        let mut fold_lag = Vec::new();
        for i in 0..n {
            let (tip, fin, fold) = {
                let rt = sim.rt(i);
                let node = rt.node();
                // ⛔ READ FROM THE NODE, NEVER THE ROUTE (lane speed5, 2026-11-17): `/get_info` answers from its process-wide cache
                // whenever the runtime lock is busy (rpc_http.rs, the WouldBlock arm), and this line holds that very lock (`rt`),
                // so every read was the cache — one stale answer shared by every party in this one process. MEASURED: the summary
                // printed "finalized 98" for all six parties while the log's chain tally finalized up to 265 near the run's end.
                // `user_final_height` is the figure the route reports when it answers live (rpc.rs `finalized_height`).
                (node.tip_height(), node.user_final_height(), node.served_seq())
            };
            fin_lag.push(tip.saturating_sub(fin));
            fold_lag.push(tip.saturating_sub(fold));
            eprintln!(
                "[scale] n{i}: tip {tip}, finalized {fin}, fold {fold}, produced {}, on node 0's chain {}",
                sim.report.produced.get(i).copied().unwrap_or(0),
                i == 0 || sim.one_chain_between(0, i)
            );
        }
        let tip0 = sim.rt(0).node().tip_height();
        eprintln!(
            "[scale] {n} parties: {:.2} blocks/s on node 0's chain ({tip0} in {secs} s), finality lag max {} levels, fold lag max {} levels",
            tip0 as f64 / secs as f64,
            fin_lag.iter().max().copied().unwrap_or(0),
            fold_lag.iter().max().copied().unwrap_or(0)
        );
        let rss_mb = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0)
            / 1024;
        eprintln!(
            "[launch] {n} parties ({seeds} seeds, {joiners} joiners), {} s simulated in {} s wall, {rss_mb} MB resident",
            sim.now / 1000,
            wall.elapsed().as_secs()
        );
        assert!(bad.is_empty(), "⛔ the launch did not take every joiner onto the chain with its whole index:\n{}\n{}", bad.join("\n"), diag(&sim));
    }

    /// ⛔⛔ FOUND BY THE RESTART CENSUS (2026-10-06): a node's fee keypair (`fee_mlkem_pub/sec`, and `fee_seed` from the
    /// per-process miner seed) is drawn fresh in every process and its secret is read NOWHERE — so a wallet fee paid to the
    /// node's epoch fee address can never be opened, and after a restart the node even publishes a DIFFERENT address within
    /// the same epoch. RED-FIRST: a fee address a wallet paid this epoch must still be this node's after a production
    /// restart (the same epoch, the same files), or every fee paid to it is value no key can ever spend.
    /// ⛔ RED-FIRST (lane stable 2026-10-30, DB-402 G1 restart changes state): a node restarted BEFORE its first fold resumes
    /// exactly where it stood. MEASURED (stable/a4.log, the 3-node launch tail): node 1 restarted at t = 0 s changed
    /// `fold_chain_tip` 4 B → 25 B — the restore named the tip as the fold root of a node that had folded nothing.
    /// TWO-PARTY-REVIEWED: the census compares what the restarted node HOLDS against what it held, field by field.
    #[test]
    fn a_node_restarted_before_its_first_fold_resumes_where_it_stood() {
        let mut sim = NetSim::testnet(2, Physics::from_env(), 0x7131_0030_2026_1030).boot_from_disk();
        assert_eq!(sim.rt(1).node().served_seq(), 0, "CALIBRATION: node 1 has folded nothing yet");
        let before = sim.field_census(1);
        sim.restart(1, 0).expect("the node boots from its own files");
        let changed = sim.restart_census_compare(1, "restart before the first fold", &before);
        let reds: Vec<String> = sim.census_reds.iter().map(|(_, _, f, d)| format!("{f}: {d}")).collect();
        assert_eq!(changed, 0, "⛔ a restart before the first fold changed {changed} field(s): {reds:?}");
    }

    #[test]
    fn a_fee_address_a_wallet_paid_this_epoch_is_still_the_nodes_after_a_restart() {
        let mut sim = NetSim::testnet(2, Physics::from_env(), 0x7131_0003_2026_1006).boot_from_disk();
        sim.run(20_000, 10_000);
        let score = sim.rt(1).node().tip_height();
        let (epoch, before, _) = sim.rt(1).node().epoch_fee_address(score);
        sim.restart(1, 0).expect("the node boots from its own files");
        let (epoch_after, after, _) = sim.rt(1).node().epoch_fee_address(score);
        assert_eq!(epoch, epoch_after, "CALIBRATION: the same blue score names the same epoch");
        assert!(!before.is_empty(), "CALIBRATION: the node publishes a fee address");
        assert_eq!(
            before, after,
            "⛔ the node's fee address for epoch {epoch} changed across a restart: fees a wallet paid to it are sealed to a key \
             this process does not hold (and fee_mlkem_sec is read nowhere, so no process ever held a key that opens them)"
        );
    }

    /// ⛔ B13 — RED-FIRST (lane funds 2026-10-27): AT THE SCALE FLOOR THE FOLD KEEPS PACE AND THE RECORD LANE OWES LITTLE. Ten
    /// parties on the fast-lane mesh (in-process; an island, not a de-islanded device result) for 120 simulated seconds.
    /// MEASURED before any fix (scratchpad/funds/eclipse-25.log, harness-34.log): party 5's certified position stayed 0 at
    /// tip 225 — every relayed block landed "WITHOUT a ledger record", the by-id ask carried one padded record per round trip
    /// to a hashed host that held none. RE-STATED after harness-41.log: the first form compared BLUE SCORE to the record
    /// position and read the DAG's WIDTH (at ~6 blue blocks per chain step the 32-step fold depth is ~180 blue blocks, by
    /// design), not the lane. The claim is two numbers, each in its own unit: (1) every party's fold root sits within
    /// `record_fold_depth` + 2 CHAIN steps of its selected tip (the fold is current to its depth); (2) every party's owed
    /// records (`payload_gap`, which counts the records IN FLIGHT on the lanes too) fit the lane's own window,
    /// `RECORD_ASK_LANES × RECORD_ASK_WIDTH` — the lane never falls behind beyond what it has already asked for; (3) every
    /// party's fold moved (certified position > 0; before the fix party 5 stayed at 0). All are printed. MEASURED
    /// harness-47.log (producer record inv): steps 32–34, owed 68–86, positions 29–32.
    #[test]
    fn at_the_scale_floor_every_partys_fold_keeps_within_two_fold_depths_of_its_tip() {
        let mut sim = NetSim::testnet(10, Physics::from_env(), 0xB13_0001_2026_1027).with_band_double();
        sim.run(120_000, 10_000);
        let depth = crate::params::RECORD_FOLD_DEPTH_DEFAULT;
        let (mut worst_steps, mut worst_owed) = ((0u64, 0usize), (0usize, 0usize));
        for i in 0..10 {
            let rt = sim.rt(i);
            let node = rt.node();
            let dag = node.dag();
            let (tip, root) = (node.selected_tip(), node.fold_chain_tip_for_test());
            let mut steps = 0u64;
            let mut cur = tip;
            while let Some(c) = cur {
                if Some(c) == root || steps > 4 * depth {
                    break;
                }
                steps += 1;
                cur = dag.get(&c).and_then(|n| n.selected_parent);
            }
            let owed = node.payload_gap_ids().len();
            if steps > worst_steps.0 {
                worst_steps = (steps, i);
            }
            if owed > worst_owed.0 {
                worst_owed = (owed, i);
            }
            eprintln!(
                "[fold-pace] party {i}: tip blue {} · fold root {} chain step(s) below the tip · records owed {owed} · certified position {}",
                node.tip_height(),
                steps,
                node.certified_record_position()
            );
        }
        eprintln!("[fold-pace] worst: {} chain step(s) (party {}), {} owed (party {}) · produced {:?}", worst_steps.0, worst_steps.1, worst_owed.0, worst_owed.1, sim.report.produced);
        assert!(
            worst_steps.0 <= depth + 2,
            "⛔ B13: party {}'s fold root is {} chain steps below its tip (depth {depth}): the fold is not current",
            worst_steps.1, worst_steps.0
        );
        // RE-STATED 2026-10-28 00:0x (§9.2 by three experiments): the record-lane batches (ac76c5d, 1ec7913) were reverted on
        // an eclipse-recovery red that proved NOT theirs — the pin is red alone on the reverted tree, on the lane tree and with
        // Z2's release off (eclipse-52/53/56 logs: the recovery takes 100–130 s against its 120 s budget, a marginal mechanism,
        // not a regression of these batches). The lane stands; this pin keeps measuring it in chain steps + owed records.
        let window = crate::node_runtime::RECORD_ASK_LANES * crate::protocol::RECORD_ASK_WIDTH;
        assert!(
            worst_owed.0 <= window,
            "⛔ B13: party {} owes {} records (more than the lane's in-flight window {window}): the record lane does not keep pace at the scale floor",
            worst_owed.1, worst_owed.0
        );
        for i in 0..10 {
            let pos = sim.rt(i).node().certified_record_position();
            assert!(pos > 0, "⛔ B13: party {i}'s fold never moved (certified position 0)");
        }
    }

    /// ⛔ RED-FIRST (MEASURED 2026-10-06 by the simulator's progress series): the band must keep pace with the fold. Two nodes
    /// on the fast lane (the bound band double: a step costs microseconds, so proving is never the limit) for 300 simulated
    /// seconds at the live cadence. MEASURED before any fix: the band applied ~0.22 steps/s while the fold advanced ~0.5/s, so
    /// the lag hit its cap (64), the fold waited, and every received payment stopped becoming spendable. The pin fails when
    /// the lag ever reaches half the cap or the band applied fewer than 3/4 of the steps the fold noted; the progress lines
    /// carry the band worker's own counters (jobs, own Verified/Held/Refused, relayed Verified/other) — the reason.
    #[test]
    fn sim_band_keeps_pace_with_the_fold() {
        let mut sim = NetSim::testnet(2, Physics::from_env(), 0x7131_0005_2026_1006).with_band_double().boot_from_disk();
        let cap = 64usize;
        let mut worst = 0usize;
        while sim.now < 300_000 {
            sim.run(5_000, 10_000);
            for i in 0..2 {
                worst = worst.max(sim.rt(i).node().band_lag());
            }
        }
        let (applied, folded, stats) = {
            let rt = sim.rt(0);
            (rt.node().band_steps_applied(), rt.node().served_seq(), rt.band_stats())
        };
        eprintln!("[band-pace] worst lag {worst} of cap {cap} · node 0 applied {applied} of {folded} folded · band worker {stats:?}");
        assert!(
            worst < cap / 2 && applied * 4 >= folded * 3,
            "⛔ the band does not keep pace with the fold: worst lag {worst} (cap {cap}), {applied} applied of {folded} folded — \
             band worker [jobs, own V, own H, own R, relayed V, relayed other] = {stats:?}"
        );
    }

    /// ⭐ DB-454 (docs/DB-454-BAND-STEP-INV-GETDATA.md) — THE TIMING HALF: WHEN A BAND PROOF COSTS THE REFERENCE, THE RELAY
    /// CARRIES AN OWNER'S STEP TO THE NON-OWNERS INSIDE THEIR LEASE. Three charged nodes on the Q13 wire, the bound double
    /// declaring `BAND_FOLD_PROVE_MS_REF` of simulated time per step (the real lane's band timing), 600 simulated seconds.
    /// TWO-PARTY-REVIEWED: three independent simulated Nodes (`NetSim::testnet(3)`) — one owner PROVES each step, the two
    /// non-owners PULL and VERIFY its copy over the simulated wire; the assertion reads what each node's own door holds.
    /// ⛔ CALIBRATION, NOT THE RED PIN (link 85): this pin was GREEN on the pre-DB-454 flood relay (night/link85-red.log: 376
    /// jobs for 374 steps, relayed V 249 per node) — the proof's COST alone does not reproduce the real lane; the bound double
    /// is ONE cell where the real step is 57, and the bytes are the mechanism (see the real-proof pin below). It stays as the
    /// cheap guard on the timing half: a lease, ask-round or announce regression shows here in seconds. It fails when the
    /// mesh proves more than 1.25 jobs per distinct step, when any node proves more than 60 % of what it applies, or when the
    /// band falls to half its lag cap.
    #[test]
    fn sim_band_relay_lets_non_owners_take_the_owners_steps_when_a_proof_costs_the_reference() {
        let n = 3;
        let mut sim = NetSim::testnet(n, Physics::TOR_Q13, 0x0454_2026_1021)
            .with_band_double()
            .with_band_double_charge(usdm_decider::nf_sparse_air::BAND_FOLD_PROVE_MS_REF)
            .boot_from_disk();
        sim.charge_cpu = true;
        let cap = 64usize;
        let mut worst = 0usize;
        while sim.now < 600_000 {
            sim.run(5_000, 10_000);
            for i in 0..n {
                worst = worst.max(sim.rt(i).node().band_lag());
            }
        }
        let rows: Vec<(u64, [u64; 6])> = (0..n)
            .map(|i| {
                let rt = sim.rt(i);
                (rt.node().band_steps_applied(), rt.band_stats())
            })
            .collect();
        let jobs: u64 = rows.iter().map(|(_, s)| s[0]).sum();
        let applied_max = rows.iter().map(|(a, _)| *a).max().unwrap_or(0);
        let asks: Vec<(u8, u64, u64, u64, u64)> = sim.ask_kinds().into_iter().filter(|r| r.0 == 22).collect();
        eprintln!(
            "[band-relay] worst lag {worst} of cap {cap} · {jobs} jobs for {applied_max} distinct steps · per node (applied, \
             [jobs, own V, own H, own R, relayed V, relayed other]) = {rows:?} · kind-22 pulls (kind, asked, answered, empty, \
             max wait ms) = {asks:?}"
        );
        assert!(applied_max >= 60, "calibration: the band moved only {applied_max} steps in 600 s");
        assert!(worst < cap / 2, "⛔ the band fell to lag {worst} (cap {cap}) — rows {rows:?}");
        assert!(
            jobs * 4 <= applied_max * 5,
            "⛔ the mesh proved {jobs} band jobs for {applied_max} distinct steps (> 1.25 per step): the relay does not carry \
             an owner's step to the non-owners inside their lease — rows {rows:?}"
        );
        for (i, (applied, s)) in rows.iter().enumerate() {
            assert!(
                s[0] * 5 <= applied * 3,
                "⛔ node {i} proved {} of the {applied} steps it applied (> 60 %) — its lease ran out on steps another node owned: \
                 rows {rows:?}",
                s[0]
            );
        }
    }

    /// ⛔⛔⛔ DB-454 — THE SAME CLAIM WITH REAL COMPACT BAND PROOFS (what `sim.sh real` runs): three charged nodes on the Q13 wire,
    /// every band step the real carrier (≈ 3.1 s solo, `OffLockJob::spawn_on_cores`), 300 simulated seconds. MEASURED on the
    /// real lane (night/sim-20261021-211315.log): every node proved every step (n1 302 jobs / 301 applied, relayed V 0) while
    /// the charged bound double (the pin above) relays 2 of 3 steps — so whatever the real carrier does differently is the
    /// mechanism, and this pin prints the evidence beside the verdict: each node's worker diagnostic (lease, stats), the cell
    /// census by class (sends, shed, wait buckets) and the band class's message census. Same thresholds as the pin above.
    /// TWO-PARTY-REVIEWED: three independent simulated Nodes; the owner proves, the non-owners verify its relayed copy.
    #[test]
    fn sim_band_relay_real_proofs_let_non_owners_take_the_owners_steps() {
        let n = 3;
        let mut sim = NetSim::testnet(n, Physics::TOR_Q13, 0x0454_2026_1021).boot_from_disk();
        sim.charge_cpu = true;
        let cap = 64usize;
        let mut worst = 0usize;
        let t0 = std::time::Instant::now();
        while sim.now < 300_000 {
            sim.run(5_000, 10_000);
            for i in 0..n {
                worst = worst.max(sim.rt(i).node().band_lag());
            }
            if sim.now % 60_000 == 0 {
                let rows: Vec<String> = (0..n)
                    .map(|i| {
                        let rt = sim.rt(i);
                        format!("n{i} applied {} lag {} · {}", rt.node().band_steps_applied(), rt.node().band_lag(), rt.band_worker_diag_for_test(sim.now))
                    })
                    .collect();
                eprintln!("[band-relay-real] t={} s wall {} s · {}", sim.now / 1000, t0.elapsed().as_secs(), rows.join(" | "));
            }
        }
        let rows: Vec<(u64, [u64; 6])> = (0..n)
            .map(|i| {
                let rt = sim.rt(i);
                (rt.node().band_steps_applied(), rt.band_stats())
            })
            .collect();
        let jobs: u64 = rows.iter().map(|(_, s)| s[0]).sum();
        let applied_max = rows.iter().map(|(a, _)| *a).max().unwrap_or(0);
        let names = crate::transport::CELL_KIND_NAMES;
        let kinds: Vec<String> = sim.cell_kinds().iter().enumerate().filter(|(_, c)| **c > 0).map(|(k, c)| format!("{}={c}", names[k])).collect();
        let shed: Vec<String> = sim.cell_shed().iter().enumerate().filter(|(_, c)| **c > 0).map(|(k, c)| format!("{}={c}", names[k])).collect();
        let band_msgs: Vec<(u8, [u64; 4])> = sim.cell_msgs().into_iter().filter(|(k, _)| *k == 22).collect();
        eprintln!(
            "[band-relay-real] DONE wall {} s · worst lag {worst} of cap {cap} · {jobs} jobs for {applied_max} distinct steps · per node \
             (applied, [jobs, own V, own H, own R, relayed V, relayed other]) = {rows:?} · cells by class {kinds:?} · shed {shed:?} · \
             cell wait buckets {:?} · band class msgs (class, sends, repeats, distinct, distinct sender×msg) {band_msgs:?}",
            t0.elapsed().as_secs(),
            sim.cell_wait()
        );
        assert!(applied_max >= 30, "calibration: the band moved only {applied_max} steps in 300 s");
        assert!(worst < cap / 2, "⛔ the band fell to lag {worst} (cap {cap}) — rows {rows:?}");
        assert!(
            jobs * 4 <= applied_max * 5,
            "⛔ the mesh proved {jobs} band jobs for {applied_max} distinct steps (> 1.25 per step) with REAL proofs — rows {rows:?}"
        );
        for (i, (applied, s)) in rows.iter().enumerate() {
            assert!(s[0] * 5 <= applied * 3, "⛔ node {i} proved {} of the {applied} steps it applied (> 60 %) — rows {rows:?}", s[0]);
        }
    }

    /// ⛔⛔⛔ DB-412 — TWO PRODUCERS HALF A SPACING APART, ON THE Q13 WIRE, ARE ONE CHAIN AT THE SETTLED DEPTH.
    ///
    /// MEASURED (sim-20261007-074503, link 18's GHOSTDAG instrument): fast seed 0x7 failed T1.1 at t=150 s, before any
    /// restart — n0 and n1 named different selected-chain blocks at blue score 8 while EACH held the other's, with IDENTICAL
    /// GHOSTDAG data on both nodes (`s8 w0x41 sp 08569294`, two parents each) and both templates merging both tips; seed 0x6
    /// T1.4 the same at blue score 257, and link 17's seed 0x3 oscillated six times 64 deep. Not a GHOSTDAG difference: two
    /// lineages that never cross. A node paced by a FIXED timer, with the peer's phase δ ≈ half its spacing S and a relay
    /// round L > max(δ, S − δ), always builds on its own previous block — the peer's newest block it holds is older, so
    /// lighter — and the virtual's selected tip flips between the two chains on every block (the score leapfrogs by one).
    /// The Q13 wire's relay round is 3 legs × 600 ms + transfer + apply ≈ 2.2 s > S/2 = 2 s, so the phase alone decides.
    /// This pin gives node 1 that phase on purpose and judges the pair by the journeys' state invariant (the selected
    /// chain at `record_fold_depth` steps below each tip, what each PEER holds) for two settled depths of production.
    #[test]
    fn db412_a_pair_half_a_spacing_out_of_phase_is_one_chain_at_the_settled_depth() {
        let seed = journey::seed(0x0412_2026_1007);
        let mut sim = NetSim::testnet(2, Physics::TOR_Q13, seed).with_band_double().boot_from_disk();
        // the shipped schedule decides when each node produces: no simulator rate cap on top of it
        sim.produce_every_ms = 0;
        sim.charge_cpu = true;
        let floor = crate::node_runtime::PRODUCTION_RELAY_FLOOR_MS;
        sim.rt(1).set_last_production_at_for_test(floor / 2);
        // one settled depth of chain steps (+8 for the witness windows, as `spendable_within_ms` derives it) before the first
        // judgement, then a second one judged every floor
        let settle = (sim.params.record_fold_depth + 8) * floor;
        sim.run(settle, settle);
        let mut reds: Vec<(u64, String)> = Vec::new();
        let mut judged = 0usize;
        while sim.now < 2 * settle {
            sim.run(floor, floor);
            judged += 1;
            if let Some(d) = sim.state_divergence() {
                reds.push((sim.now / 1000, d));
            }
        }
        let produced = sim.report.produced.clone();
        let one = sim.one_chain_between(0, 1);
        eprintln!(
            "[db412] seed {seed:#x}: produced {produced:?} · judged {judged} · reds {} · one chain at the end {one} · first red {:?}",
            reds.len(),
            reds.first().map(|(t, d)| format!("t={t} s: {}", &d[..d.len().min(600)]))
        );
        assert!(produced.iter().all(|&p| p >= 20), "CALIBRATION: both nodes produced a chain to judge: {produced:?}");
        assert!(
            reds.is_empty() && one,
            "⛔ DB-412: two producers half a spacing apart are TWO chains at the settled depth in {} of {judged} judgements \
             (one chain at the end: {one}) — first: {:?}",
            reds.len(),
            reds.first()
        );
    }

    /// ⛔⛔⛔ NO CHAIN HALTS — A NETWORK THAT STOOD STILL AS A WHOLE RESTARTS ITSELF. MEASURED 2026-10-22 on the 10-node launch
    /// journey (scratchpad/verify/f1-launch5-20261022-1649.log, seed 0x713100f320261022): the replica census paused production
    /// for its whole 600 s quiescence window (one node's fold lagged, so the mesh never went quiet), every node's selected tip
    /// was then older than the live bound (LIVE_LANE_DEPTH × spacing = 256 s), and every node answered "[produce] BEHIND: the
    /// selected tip is 600 s old … production resumes when the tip is recent" for the remaining 3,500 simulated seconds — tip
    /// 2795 on all ten, 120 blocks unfolded on each (the window cap), T2/T3 "passed" over a dead mesh. Nobody produced because
    /// nobody produced: the tip's AGE alone cannot tell "my peers moved on and the pages are landing" from "nobody moved".
    /// BORROWED SHAPE: Bitcoin Core's `IsInitialBlockDownload` LATCHES to false (`m_cached_finished_ibd`) — a node that was once
    /// synced never re-enters IBD on a tip older than `nMaxTipAge`, so a network that stopped as a whole stays mineable; Kaspa's
    /// `is_nearly_synced` ships the same escape as an operator flag (`--allow-submit-block-when-not-synced`). Here the escape is
    /// MEASURED, never configured and never an origin's privilege (DECENTRALIZATION: the mesh may not depend on one operator's
    /// plist): BEHIND holds only while a LIVE peer CLAIMS a tip materially heavier than this node's. This pin: three joined
    /// nodes, the origin gone for good, production paused mesh-wide past the live bound, then resumed — every up node's tip
    /// must advance and the pair must still be one chain. RED before the gate weighed the claim (both survivors BEHIND forever).
    #[test]
    fn sim_a_mesh_whose_tips_all_went_stale_together_resumes_producing_without_an_origin() {
        let seed = journey::seed(0x7131_0396_2026_1022);
        let mut sim = NetSim::testnet(3, Physics::TOR_Q13, seed).with_band_double().boot_from_disk();
        sim.charge_cpu = true;
        // a chain on every node, then the origin leaves for good: the survivors are joined nodes with no directive
        sim.run(240_000, 60_000);
        let joined: Vec<u64> = (0..3).map(|i| sim.rt(i).node().tip_height()).collect();
        sim.hold_down(0);
        sim.run(120_000, 60_000);
        let before: Vec<u64> = (1..3).map(|i| sim.rt(i).node().tip_height()).collect();
        assert!(
            joined.iter().all(|&h| h > 0) && before.iter().zip(&joined[1..]).all(|(b, j)| b > j),
            "CALIBRATION: the survivors held a chain and extended it without the origin: {joined:?} → {before:?}"
        );
        // the whole mesh stands still past the live bound (a census window, an outage, a partition that healed late)
        let live_bound_ms = crate::node::LIVE_LANE_DEPTH as u64 * sim.params.target_spacing_ms;
        sim.produce_paused = true;
        sim.run(2 * live_bound_ms + 60_000, 60_000);
        sim.produce_paused = false;
        let still: Vec<u64> = (1..3).map(|i| sim.rt(i).node().tip_height()).collect();
        sim.run(300_000, 60_000);
        let after: Vec<u64> = (1..3).map(|i| sim.rt(i).node().tip_height()).collect();
        let one = sim.one_chain_between(1, 2);
        eprintln!(
            "[standstill] seed {seed:#x}: tips before {before:?} · after the standstill {still:?} · 300 s later {after:?} · one chain {one}"
        );
        assert!(
            still.iter().zip(&before).all(|(s, b)| *s <= b + 2),
            "CALIBRATION: the pause held production through the standstill (at most the job in flight landed): {before:?} → {still:?}"
        );
        assert!(
            after.iter().zip(&still).all(|(a, s)| a > s) && one,
            "⛔ NO CHAIN HALTS: a mesh whose every tip went stale together never produced again — tips {still:?} → {after:?} after \
             300 s with production resumed (one chain {one}); every node is BEHIND a tip nobody extends"
        );
    }

    /// ⛔⛔⛔ NO CHAIN HALTS — THE BOOT-TIME STANDSTILL (lane b 2026-10-22; the restart arm of the launch journey, readiness
    /// T3). 9354be9 freed a RUNNING mesh whose tips all aged past the live bound; the BOOT-time rule (`resume_join_verdict`)
    /// still answers StayGated to a node that boots from its own files onto a tip older than the live bound with no
    /// operator directive, and a gated node un-gates only on a live peer's block, bundle or beacon. A mesh whose every
    /// process stopped together — a power cut, a hosting outage, every operator upgrading in one window — and came back
    /// after the bound has no live tip ANYWHERE, so under that rule nobody produces because nobody produces (the
    /// 2026-09-21 two-node testnet came back with no producer; the fix then was the operator's MONEROUSD_MESH_BOOTSTRAP=1,
    /// one operator's privilege, which DECENTRALIZATION forbids production to depend on). MEASURED on what the survivors
    /// HOLD: three nodes, the origin gone for good (no directive anywhere), the two joined nodes power-cycled in the same
    /// instant and off for 2× the live bound, each booted from its own files, then 300 s with every process up — do they
    /// produce again, one chain? A green here is what the launch journey's restarts and the public testnet's first outage
    /// stand on.
    #[test]
    fn sim_a_mesh_power_cycled_as_a_whole_boots_producing_again_without_a_directive() {
        let seed = journey::seed(0x7131_0397_2026_1022);
        let mut sim = NetSim::testnet(3, Physics::TOR_Q13, seed).with_band_double().boot_from_disk();
        sim.charge_cpu = true;
        // a chain on every node, then the origin leaves for good: the survivors are joined nodes with no directive
        sim.run(240_000, 60_000);
        let joined: Vec<u64> = (0..3).map(|i| sim.rt(i).node().tip_height()).collect();
        sim.hold_down(0);
        sim.run(120_000, 60_000);
        let before: Vec<u64> = (1..3).map(|i| sim.rt(i).node().tip_height()).collect();
        assert!(
            joined.iter().all(|&h| h > 0) && before.iter().zip(&joined[1..]).all(|(b, j)| b > j),
            "CALIBRATION: the survivors held a chain and extended it without the origin: {joined:?} → {before:?}"
        );
        // THE POWER CUT: both surviving processes stop in the same instant and stay off past the live bound
        let live_bound_ms = crate::node::LIVE_LANE_DEPTH as u64 * sim.params.target_spacing_ms;
        for i in 1..3 {
            sim.hold_down(i);
        }
        sim.run(2 * live_bound_ms + 60_000, 60_000);
        // THE POWER RETURNS: each boots from its own files; no directive (only node 0's plist carries one, and node 0 is gone)
        let mut reports = Vec::new();
        for i in 1..3 {
            let r = sim.restart(i, 0).expect("the node boots from its own files");
            reports.push(format!("n{i}: {r:?}"));
        }
        let at_boot: Vec<u64> = (1..3).map(|i| sim.rt(i).node().tip_height()).collect();
        sim.run(300_000, 60_000);
        let after: Vec<u64> = (1..3).map(|i| sim.rt(i).node().tip_height()).collect();
        let one = sim.one_chain_between(1, 2);
        eprintln!(
            "[power-cycle] seed {seed:#x}: tips before the cut {before:?} · at boot {at_boot:?} · 300 s later {after:?} · one chain {one} · {}",
            reports.join(" · ")
        );
        assert!(
            at_boot.iter().zip(&before).all(|(a, b)| *a > 0 && a <= b),
            "CALIBRATION: each process booted onto the chain it persisted and nothing moved while the power was off: {before:?} → {at_boot:?}"
        );
        assert!(
            after.iter().zip(&at_boot).all(|(a, s)| a > s) && one,
            "⛔ NO CHAIN HALTS: a mesh power-cycled as a whole never produced again — tips {at_boot:?} → {after:?} after 300 s with \
             every process up (one chain {one}); each node booted onto a tip older than the live bound with no directive and \
             waits for a live block only another waiting node could produce"
        );
    }

    /// ⭐⭐⭐ THE FAST LANE — the same Tier-1 journey with the bound band double and no pacing: the INSTANT bug finder (seconds
    /// of wall time). Its verdicts go to `scratchpad/sim-journey-fast.tsv`; a red here is a red, a green here is not the pass
    /// that opens a live run (only the real lane's is).
    #[test]
    fn sim_journey_tier1_fast_with_the_bound_band_double() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(0x7131_0001_2026_1006);
        super::perf::begin("fast", seed);
        let mut sim = NetSim::testnet(3, Physics::from_env(), seed)
            .with_band_double()
            .with_template_double()
            .with_journey_stake_lock()
            .boot_from_disk();
        sim.hold_down(2); // the joiner of T1.6: it does not exist until then
        sim.charge_cpu = true;
        sim.check_state = true;
        let mut v = Vec::new();
        crate::harness::sim_coverage::start();
        let go = tier1(&mut sim, &mut v, &wall);
        crate::harness::sim_coverage::finish("journey-fast");
        eprintln!("[sim-journey] fast lane: restarts {} · sim {} s · wall {:?} · {}", sim.restarts, sim.now / 1000, wall.elapsed(), speed_line());
        run_rows(&sim);
        served_vs_folded_census(&sim);
        journey::record("fast", seed, &v);
        // SPEED (user 2026-10-06, "we cant settle for slow runs"): the census needs a QUIET mesh, and after a red step the
        // mesh is mid-step — MEASURED sim-20261006-212115: "quiet false after 600 s · DIFFERS 0 · NOT-QUIET 162", ~180 s
        // of wall that judged nothing. It runs when the journey passed; its own pin
        // (`replica_census_every_replicated_field_agrees`, 9 s) measures every run either way.
        if go.is_some() {
            sim.replica_census("fast"); // DB-402 R1 run point (b): rows only — the journey's verdicts are its own
        } else {
            eprintln!("[replica-census] fast: not run — the journey stopped at a red step, so the mesh cannot be quiet; the census pin measures it");
        }
        assert!(go.is_some(), "⛔ the fast-lane Tier-1 journey stopped at {:?}", v.last().map(|(id, _, d)| (*id, d.clone())));
    }

    /// ⭐⭐ PERF TIER P14 — FLATNESS (docs/PERF-TIER-UX-METRICS-20261007.md): the fast lane's Tier-1 journey, the same seed and
    /// mesh, run twice — once on a chain grown to height ~1 k and once past the block window's first base step (~18.8 k at
    /// the default params, derived below) — and every user-experience row (P1–P13) compared ([`super::perf::flatness`]).
    /// NO GROWTH ON ANY AXIS and PERFORMANCE meet here: a send, a receive, a join, a restart or a datadir that costs more at
    /// the high height than at 1 k fails both. The chain grows with node 2 held down, so its T1.6 join at the high height
    /// is past the live catch-up depth (the bundle adopt) — the join the public testnet's users will make. ~25–30 min of
    /// wall (two journeys plus ~20 k simulated blocks), so it is `#[ignore]`d out of the suites and
    /// run by name (`scratchpad/perf_flat.sh`); its rows go to `scratchpad/perf.tsv` like every journey's.
    /// TWO-PARTY-REVIEWED: each height runs the whole Tier-1 journey — W1 on node 0 pays W2 on node 1, which reads it through
    /// its OWN node, and a third node joins — so every row is what the peer's wallet or node observed, at both heights.
    #[test]
    #[ignore = "P14 flatness: ~25–30 min of wall; run by name with --ignored (scratchpad/perf_flat.sh)"]
    fn sim_perf_flatness_fast_journey_at_two_heights() {
        let seed = journey::seed(0x7131_0001_2026_1006);
        let mut rows = Vec::new();
        // THE HIGH HEIGHT IS DERIVED, NOT CHOSEN: past the block window's first base step (the window is cut at the quantized
        // fold base, so it first prunes once the tip's blue score reaches 2 × keep_depth — 15,032 at the default params) by
        // half a span, so the bounded store is measured where its bound acts, not while it fills (MEASURED link 37: at the old
        // 10 k the window had never pruned, and its filling read as growth). Blue score ≥ selected-chain height, so a tip
        // height of 2.5 × keep_depth is past the step. And never below 10× the low height, the two scales a slope needs.
        let keep_depth = NetSim::testnet(1, Physics::from_env(), seed).rt(0).node().dag().keep_depth();
        let high = (2 * keep_depth + keep_depth / 2).max(10_000);
        // ⛔ CHUNKED — the test watchdog reaps any test process at 45 min (user 2026-10-05: chunk the run). `SIM_P14_LEG=low`
        // runs the 1 k leg alone and hands its rows (and its tip height) to the high leg through a file in the temp dir;
        // `SIM_P14_LEG=high` runs the high leg alone and judges flatness against them (`scratchpad/perf_flat.sh` runs the two
        // as two processes). Unset, both legs run here, as before. The claim is the same either way: every row at both heights.
        let leg = std::env::var("SIM_P14_LEG").ok();
        let low_rows_file = std::env::temp_dir().join(format!("p14-low-rows-{seed:x}.tsv"));
        let heights: Vec<u64> = match leg.as_deref() {
            Some("low") => vec![1_000],
            Some("high") => vec![high],
            _ => vec![1_000, high],
        };
        if leg.as_deref() == Some("high") {
            let text = std::fs::read_to_string(&low_rows_file)
                .unwrap_or_else(|e| panic!("⛔ P14: the high leg needs the low leg's rows ({}): {e}", low_rows_file.display()));
            let mut lines = text.lines();
            let lo_h: u64 = lines.next().and_then(|l| l.parse().ok()).expect("⛔ P14: the low leg's file names its tip height");
            let lo: Vec<(String, f64, String, f64)> = lines
                .filter_map(|l| {
                    let f: Vec<&str> = l.split('\t').collect();
                    match f.as_slice() {
                        [m, v, u, r] => Some((m.to_string(), v.parse().ok()?, u.to_string(), r.parse().ok()?)),
                        _ => None,
                    }
                })
                .collect();
            assert!(!lo.is_empty(), "⛔ P14: the low leg's file holds no row");
            rows.push((lo_h, lo));
        }
        for height in heights {
            let wall = std::time::Instant::now();
            super::perf::begin(&format!("flat@{height}"), seed);
            let mut sim = NetSim::testnet(3, Physics::from_env(), seed).with_band_double().with_journey_stake_lock().boot_from_disk();
            sim.hold_down(2);
            sim.charge_cpu = true;
            sim.check_state = true;
            // grow: two producers at the 4 s relay floor make a block every ~2 simulated s; 4 s per block is twice that
            let grown = run_until(&mut sim, height * 4_000, |s| {
                let tip = s.rt(0).node().tip_height(); // its guard drops here, before one_chain_between locks node 0
                tip >= height && s.one_chain_between(0, 1)
            });
            super::perf::row(
                &format!("P14 grow to height {height}"),
                grown.map_or(f64::INFINITY, |t| t as f64 / 1e3),
                "s",
                None,
                &format!("sim, 2 producers, wall {:.0} s · {}", wall.elapsed().as_secs_f64(), speed_line()),
            );
            assert!(grown.is_some(), "⛔ P14: the mesh never grew to height {height} within {} simulated s", height * 4);
            let mut v = Vec::new();
            let go = tier1(&mut sim, &mut v, &wall);
            eprintln!("[sim-journey] flat@{height}: sim {} s · wall {:?} · {}", sim.now / 1000, wall.elapsed(), speed_line());
            run_rows(&sim);
            assert!(go.is_some(), "⛔ P14: the Tier-1 journey at height {height} stopped at {:?}", v.last().map(|(id, _, d)| (*id, d.clone())));
            if height == high {
                // the bound must be MEASURED: every node that ran the whole climb has stepped its window's base (the first
                // step cuts at keep_depth, so nothing below it is held; an unstepped window starts at blue score 1)
                for i in [0usize, 1] {
                    let w = datadir_census(sim.dirs[i].as_deref().expect("a datadir")).window;
                    assert!(
                        w.files > 0 && w.min_score >= keep_depth,
                        "⛔ P14: node {i}'s block window never stepped its base by height {height} (held {} block(s), blue score {}..={}) — its bound is unmeasured",
                        w.files,
                        w.min_score,
                        w.max_score
                    );
                }
            }
            rows.push((sim.rt(0).node().tip_height(), super::perf::rows()));
        }
        if leg.as_deref() == Some("low") {
            let (lo_h, lo) = &rows[0];
            let mut text = format!("{lo_h}\n");
            for (m, v, u, r) in lo {
                text.push_str(&format!("{m}\t{v:?}\t{u}\t{r:?}\n"));
            }
            std::fs::write(&low_rows_file, text).expect("⛔ P14: the low leg's rows could not be written");
            eprintln!("[perf-flat] the low leg's {} row(s) at height {lo_h} → {} (the high leg judges them)", lo.len(), low_rows_file.display());
            return;
        }
        let ((lo_h, lo), (hi_h, hi)) = (&rows[0], &rows[1]);
        let grew = super::perf::flatness(lo, hi, *lo_h, *hi_h);
        assert!(grew.is_empty(), "⛔ P14: {} user-experience row(s) grew with the chain from height {lo_h} to {hi_h}: {grew:?}", grew.len());
    }

    /// The load scenario's offered rates (tx/s), doubling from one: the knee is located to within a factor of two.
    const LOAD_RATES: [u64; 6] = [1, 2, 4, 8, 16, 32];
    /// Spends submitted per stage: enough for a p95 over more than a handful of samples at every rate.
    const LOAD_STAGE_SPENDS: usize = 12;

    /// ⭐⭐ PERF TIER P10 + P11 AT ≥ 8 PRODUCERS — THE LOAD SCENARIO (docs/PERF-TIER-UX-METRICS-20261007.md: "wallets submit at
    /// a rising rate until p95 P2 doubles (the knee)"). `SIM_LOAD_PRODUCERS` daemons (default 8; the tier asks for 8 / 16 /
    /// 32) on the testnet identity, the bound band double, node CPU charged.
    /// - FUNDING: one note per spend, credited round-robin, each on the node its wallet spends through; every carrier is
    ///   proven BEFORE the load, in parallel (wallet wall time: a wallet proves before it submits, so the submit instant is
    ///   when the finished tx reaches its node).
    /// - THE LOAD: stage by stage the offered rate doubles from 1 tx/s ([`LOAD_RATES`]); each spend is submitted at its
    ///   scheduled simulated instant through the submit door's own sequence (`submit_wallet_send`: the wallet-shaped tx, the
    ///   TX-level verdict, then pooled AND gossiped — link 62) on its node. A refused submit is retried once per simulated
    ///   second, as a wallet's send loop would, and its latency still counts from the scheduled instant (the user's click).
    /// - LATENCY: scheduled submit → its nullifier reads spent on EVERY up node (`is_nullifier_spent`: the block that
    ///   carries it reached and grafted on each node — what P2's receiver's node must hold before its wallet can show the
    ///   payment pending). Read every 500 simulated ms, so each latency is known to 0.5 s.
    /// - THROUGHPUT per stage: its settled spends over the span from its first submit to its last settle (makespan rate —
    ///   a lower bound, since a 12-spend stage's span is mostly one latency).
    /// - THE KNEE (the doc's definition): the first stage whose p95 exceeds twice the first stage's, or that leaves a spend
    ///   unsettled. P10 reports the highest stage below it.
    /// - THE TERMS per stage: inclusion (submit → the submitting node reads it spent), then the block carrying it in every
    ///   up node's DAG, then the slowest node's graft → that node reads it spent.
    /// - P11: blocks produced mesh-wide over the load window against `target_spacing_ms`.
    /// Fidelity gap, stated: the submitting node's own verdict CPU is not charged (the test runs it outside the node's step);
    /// every peer's inbound verification is.
    /// TWO-PARTY-REVIEWED: every latency is what EVERY up node holds, never what the submit returned.
    #[test]
    #[ignore = "PERF TIER P10/P11 load scenario: minutes of wall at 8+ producers; run by name with --ignored (scratchpad/perf_load.sh)"]
    fn sim_perf_load_p10_throughput_knee_and_p11_interval() {
        struct Spend {
            stage: usize,
            due: u64,
            node: usize,
            cm: [u8; 32],
            next_try: u64,
            nf: Option<Hash32>,
            tx: Option<Hash32>,
            // the first read at which the SUBMITTING node holds the nullifier spent: the block that carries it is in its DAG
            included: Option<u64>,
            // the block carrying the spend (read once from the submitting node's DAG at inclusion), and per node the first
            // read at which that node's DAG holds it and at which it reads the nullifier spent — the every-node term's two
            // parts: the block's propagation, then whatever the node needs after the graft before the spend reads spent
            block: Option<Hash32>,
            graft_at: Vec<Option<u64>>,
            spent_at: Vec<Option<u64>>,
            // per node the first read at which its POOL holds the spend's tx — how far the payment's gossip reached before
            // a block carried it (a producer that never pools it cannot carry it, and cannot rehydrate the carrying block)
            pooled_at: Vec<Option<u64>>,
            settled: Option<u64>,
            refusals: u32,
            last_refusal: String,
            // the spend's stamp work and its submitter pool's required bits at the submit (the selection draw's weight is
            // `2^(stamp − the pool's floor)`)
            stamp: Option<(u32, u32)>,
        }
        let wall = std::time::Instant::now();
        let seed = journey::seed(0x7131_0010_2026_1020);
        let n: usize = std::env::var("SIM_LOAD_PRODUCERS").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(8);
        super::perf::begin(&format!("load-n{n}"), seed);
        let mut sim = NetSim::testnet(n, Physics::from_env(), seed).with_band_double().boot_from_disk();
        sim.charge_cpu = true;
        sim.census_inbound();
        let converged = run_until(&mut sim, 300_000, |s| (1..n).all(|i| s.one_chain_between(0, i)));
        assert!(converged.is_some(), "CALIBRATION: the {n}-node mesh converges to one chain: {}", diag(&sim));
        eprintln!("[perf-load] {n} node(s) one chain after {converged:?} sim ms (wall {:?})", wall.elapsed());

        let total = LOAD_RATES.len() * LOAD_STAGE_SPENDS;
        let ks: Vec<u64> = (0..total as u64).map(|j| 0x10AD_0000 + j).collect();
        let prefix = crate::params::network_genesis_prefix("testnet");
        let t_prove = std::time::Instant::now();
        let workers = std::thread::available_parallelism().map_or(4, |p| p.get()).min(8);
        std::thread::scope(|sc| {
            for w in 0..workers {
                let (ks, prefix) = (&ks, &prefix);
                sc.spawn(move || {
                    crate::params::set_thread_network_for_test(prefix);
                    for k in ks.iter().skip(w).step_by(workers) {
                        assert!(Node::test_spend_carrier(*k, 1).is_some(), "CALIBRATION: note {k}'s spend carrier proves");
                        assert!(Node::test_wallet_tag_list(*k, 1).is_some(), "CALIBRATION: note {k}'s spend-or-decoy proves");
                    }
                });
            }
        });
        eprintln!("[perf-load] {total} spend carrier(s) proven in {:?} wall on {workers} thread(s)", t_prove.elapsed());
        let owner = move |j: usize| j % n;
        let cms: Vec<[u8; 32]> = ks.iter().enumerate().map(|(j, &k)| credit(&sim, owner(j), k)).collect();
        let fund_budget = spendable_within_ms(&sim) * 4;
        let mut ready = vec![false; total];
        let funded = run_until(&mut sim, fund_budget, |s| {
            for (j, cm) in cms.iter().enumerate() {
                if !ready[j] && s.rt(owner(j)).node().member_path_ready_for_test(cm) {
                    ready[j] = true;
                }
            }
            ready.iter().all(|&r| r)
        });
        let n_ready = ready.iter().filter(|&&r| r).count();
        eprintln!(
            "[perf-load] by-record-id answers per asker (host, carried a record, notfound): {:?} · bulk asks per kind (kind, \
             sent, answers taken, carried nothing, longest due wait ms): {:?}",
            (0..n).map(|i| sim.record_answers(i)).collect::<Vec<_>>(),
            sim.ask_kinds()
        );
        eprintln!(
            "[perf-load] {n_ready} of {total} note(s) spendable on their node after {funded:?} sim ms (wall {:?}) · ask census \
             (to/served/lock-busy steps/steps) {:?}",
            wall.elapsed(),
            (0..n).map(|i| sim.ask_census(i)).collect::<Vec<_>>()
        );
        assert!(funded.is_some(), "CALIBRATION: every funded note is spendable within {fund_budget} sim ms — {n_ready} of {total}: {}", diag(&sim));

        let t_load = sim.now;
        let produced0: u64 = sim.report.produced.iter().sum();
        let proved0 = sim.report.proved.len();
        let rx0: Vec<_> = (0..n).map(|i| sim.inbound(i)).collect();
        let cells0 = sim.cell_kinds();
        let (shed0, wait0) = (sim.cell_shed(), sim.cell_wait());
        let other0 = sim.inbound_other();
        let tx_fetch = |s: &NetSim| {
            s.ask_kinds()
                .into_iter()
                .find(|k| k.0 == crate::arti_transport::BULK_REQ_KIND_TX_FETCH)
                .map_or((0, 0, 0), |(_, sent, taken, empty, _)| (sent, taken, empty))
        };
        let fetch0 = tx_fetch(&sim);
        // DB-449: fetched bodies by the pool's answer, summed over nodes — [pooled, known/settled, anchor not held, other]
        let ingest = |s: &NetSim| {
            (0..n).fold([(0u64, 0u64); 4], |mut acc, i| {
                for (a, c) in acc.iter_mut().zip(s.rt(i).tx_fetch_ingest_census()) {
                    a.0 += c.0;
                    a.1 += c.1;
                }
                acc
            })
        };
        let ingest0 = ingest(&sim);
        let tip0 = sim.rt(0).node().tip_height();
        let mut spends = Vec::with_capacity(total);
        let mut at = t_load;
        for (si, &r) in LOAD_RATES.iter().enumerate() {
            for q in 0..LOAD_STAGE_SPENDS {
                let j = si * LOAD_STAGE_SPENDS + q;
                spends.push(Spend {
                    stage: si,
                    due: at,
                    node: owner(j),
                    cm: cms[j],
                    next_try: at,
                    nf: None,
                    tx: None,
                    included: None,
                    block: None,
                    graft_at: vec![None; n],
                    spent_at: vec![None; n],
                    pooled_at: vec![None; n],
                    settled: None,
                    refusals: 0,
                    last_refusal: String::new(),
                    stamp: None,
                });
                at += 1_000 / r;
            }
        }
        let load_end = at;
        // the slowest spend's budget after the last submit: a note's own spendable bound, twice (the mesh's cadence, derived)
        let drain_budget = spendable_within_ms(&sim) * 2;
        let (mut next_check, mut next_progress) = (sim.now, sim.now + 10_000);
        while sim.now < load_end + drain_budget && spends.iter().any(|s| s.settled.is_none()) {
            let now = sim.now;
            for s in spends.iter_mut().filter(|s| s.nf.is_none() && s.next_try <= now) {
                let r = submit_wallet_send(&sim, s.node, &s.cm, 1);
                match r {
                    Ok((id, nf)) => {
                        s.nf = Some(Hash32(nf));
                        s.tx = Some(id);
                        let guard = sim.rt(s.node);
                        let pool = guard.node().mempool();
                        s.stamp = pool.get(&id).map(|t| (t.stamp_work(), pool.required_stamp_bits()));
                    }
                    Err(e) => {
                        s.refusals += 1;
                        s.last_refusal = format!("{e:?}");
                        s.next_try = now + 1_000;
                    }
                }
            }
            sim.run(sim.step_ms, 10_000);
            if sim.now >= next_check {
                next_check = sim.now + 500;
                let up: Vec<usize> = (0..n).filter(|&i| !sim.is_down(i)).collect();
                for s in spends.iter_mut().filter(|s| s.settled.is_none()) {
                    if let Some(nf) = s.nf {
                        if s.included.is_none() && sim.rt(s.node).node().is_nullifier_spent(&nf) {
                            s.included = Some(sim.now);
                        }
                        if s.included.is_some() && s.block.is_none() {
                            let guard = sim.rt(s.node);
                            let dag = guard.node().dag();
                            s.block = s.tx.and_then(|t| {
                                dag.canonical_order().into_iter().find(|b| dag.get(b).is_some_and(|nd| nd.tx_ids.contains(&t)))
                            });
                        }
                        for &i in &up {
                            if s.pooled_at[i].is_none() && s.tx.is_some_and(|t| sim.rt(i).node().mempool().contains(&t)) {
                                s.pooled_at[i] = Some(sim.now);
                            }
                            if s.graft_at[i].is_none() && s.block.is_some_and(|b| sim.rt(i).node().dag().contains(&b)) {
                                s.graft_at[i] = Some(sim.now);
                            }
                            if s.spent_at[i].is_none() && sim.rt(i).node().is_nullifier_spent(&nf) {
                                s.spent_at[i] = Some(sim.now);
                            }
                        }
                        if up.iter().all(|&i| s.spent_at[i].is_some()) {
                            s.settled = Some(sim.now);
                        }
                    }
                }
            }
            if sim.now >= next_progress {
                next_progress = sim.now + 10_000;
                eprintln!(
                    "[perf-load] t+{} s: submitted {} · settled {} of {total} · refusals {} (wall {:?} · {})",
                    (sim.now - t_load) / 1000,
                    spends.iter().filter(|s| s.nf.is_some()).count(),
                    spends.iter().filter(|s| s.settled.is_some()).count(),
                    spends.iter().map(|s| s.refusals).sum::<u32>(),
                    wall.elapsed(),
                    speed_line()
                );
            }
        }
        let window_ms = sim.now - t_load;
        let produced = sim.report.produced.iter().sum::<u64>() - produced0;
        let tip1 = sim.rt(0).node().tip_height();

        let quantile = |v: &[f64], p: f64| if v.is_empty() { f64::NAN } else { v[((v.len() - 1) as f64 * p).round() as usize] };
        let mut base_p95 = None;
        let mut below_knee: Option<(u64, f64, f64)> = None;
        let mut knee: Option<(u64, String)> = None;
        for (si, &rate) in LOAD_RATES.iter().enumerate() {
            let st: Vec<&Spend> = spends.iter().filter(|s| s.stage == si).collect();
            let mut lat: Vec<f64> = st.iter().filter_map(|s| s.settled.map(|t| (t - s.due) as f64 / 1e3)).collect();
            lat.sort_by(f64::total_cmp);
            // MAKESPAN THROUGHPUT: the stage's settled spends over the span from its first submit to its last settle — what
            // the mesh carried of this stage's offer, latency included (a lower bound on its capacity: a 12-spend stage is a
            // burst whose span is mostly one latency). The inter-completion rate it replaces measured the latency SPREAD
            // (11 / (last − first settle)), which read 0.2 tx/s for 12 spends that all settled — and so put the knee at the
            // first stage by construction.
            let last_settle = st.iter().filter_map(|s| s.settled).max();
            let first_due = st.iter().map(|s| s.due).min().unwrap_or(0);
            let tput = match last_settle {
                Some(b) if b > first_due => lat.len() as f64 / ((b - first_due) as f64 / 1e3),
                _ => 0.0,
            };
            let (p50, p95) = (quantile(&lat, 0.5), quantile(&lat, 0.95));
            // the latency's two terms: submit → the submitting node's block carries it (inclusion), then → every node holds it
            let mut incl: Vec<f64> = st.iter().filter_map(|s| s.included.map(|t| (t - s.due) as f64 / 1e3)).collect();
            let mut spread: Vec<f64> =
                st.iter().filter_map(|s| Some((s.settled? - s.included.or(s.settled)?) as f64 / 1e3)).collect();
            incl.sort_by(f64::total_cmp);
            spread.sort_by(f64::total_cmp);
            // the every-node term's two parts, per spend: inclusion → its block in EVERY up node's DAG (propagation), and
            // the slowest node's graft → that node reads the nullifier spent (what a node needs after it holds the block)
            let last = |v: &[Option<u64>]| -> Option<u64> { v.iter().copied().collect::<Option<Vec<u64>>>().and_then(|v| v.into_iter().max()) };
            let mut prop: Vec<f64> =
                st.iter().filter_map(|s| Some((last(&s.graft_at)? - s.included?) as f64 / 1e3)).collect();
            let mut after_graft: Vec<f64> = st
                .iter()
                .filter_map(|s| {
                    (0..n).map(|i| Some(s.spent_at[i]?.saturating_sub(s.graft_at[i]?))).collect::<Option<Vec<u64>>>()
                })
                .filter_map(|v| v.into_iter().max().map(|ms| ms as f64 / 1e3))
                .collect();
            prop.sort_by(f64::total_cmp);
            after_graft.sort_by(f64::total_cmp);
            eprintln!(
                "[perf-load] n={n} stage {rate} tx/s: inclusion p50 {:.1} / p95 {:.1} s · then every node p50 {:.1} / p95 {:.1} s \
                 = block in every node's DAG p50 {:.1} / p95 {:.1} s ({} of {} spends' blocks seen) + the slowest graft → reads \
                 spent p50 {:.1} / p95 {:.1} s · per spend (node, inclusion s, settle s): {:?}",
                quantile(&incl, 0.5),
                quantile(&incl, 0.95),
                quantile(&spread, 0.5),
                quantile(&spread, 0.95),
                quantile(&prop, 0.5),
                quantile(&prop, 0.95),
                prop.len(),
                st.len(),
                quantile(&after_graft, 0.5),
                quantile(&after_graft, 0.95),
                st.iter()
                    .map(|s| (s.node, s.included.map(|t| (t - s.due) / 100), s.settled.map(|t| (t - s.due) / 100)))
                    .collect::<Vec<_>>()
            );
            // ⭐ THE SPREAD'S SPLIT (link 66): how far each spend's gossip reached (nodes whose pool ever held it), and for
            // its carrying block at the slowest node: produced → first landed there (the wire's term, and by which lane)
            // and landed → in that node's DAG (the node's own term). A block never seen landing was grafted from a lane the
            // census does not read (a cell, a shell).
            let reach: Vec<usize> = st.iter().map(|s| s.pooled_at.iter().filter(|p| p.is_some()).count()).collect();
            let (mut wire_term, mut node_term) = (Vec::new(), Vec::new());
            let (mut by_lane, mut own_carried, mut unseen) = ([0usize; 2], 0usize, 0usize);
            for s in &st {
                let Some(b) = s.block else { continue };
                let produced = (0..n).find_map(|i| sim.block_landed(i, &b).filter(|l| l.1 == RX_PRODUCED_HERE).map(|l| (i, l.0)));
                let slowest = (0..n).filter_map(|i| Some((s.graft_at[i]?, i))).max();
                let (Some((producer, born)), Some((grafted, i))) = (produced, slowest) else {
                    unseen += 1;
                    continue;
                };
                own_carried += usize::from(producer == s.node);
                match sim.block_landed(i, &b) {
                    Some((landed, lane)) if lane != RX_PRODUCED_HERE => {
                        by_lane[usize::from(lane != 0)] += 1;
                        wire_term.push(landed.saturating_sub(born) as f64 / 1e3);
                        node_term.push(grafted.saturating_sub(landed) as f64 / 1e3);
                    }
                    _ => unseen += 1,
                }
            }
            wire_term.sort_by(f64::total_cmp);
            node_term.sort_by(f64::total_cmp);
            // ⭐ POOLED BEFORE ITS BLOCK LANDED (link 71, DB-448): per (spend, node that received its carrying block), did that
            // node's pool hold the spend when the block landed? A block lands with its notes stripped (DB-165) and is rehydrated
            // from the receiver's pool; a node whose pool lacked the tx installs no notes and waits for the record lane.
            let (mut pooled_first, mut landed_first, mut never_pooled) = (0usize, 0usize, 0usize);
            for s in &st {
                let Some(b) = s.block else { continue };
                for i in 0..n {
                    let Some((landed, lane)) = sim.block_landed(i, &b) else { continue };
                    if lane == RX_PRODUCED_HERE {
                        continue;
                    }
                    match s.pooled_at[i] {
                        Some(p) if p <= landed + 500 => pooled_first += 1, // read every 500 ms: within one read counts as before
                        Some(_) => landed_first += 1,
                        None => never_pooled += 1,
                    }
                }
            }
            eprintln!(
                "[perf-load] n={n} stage {rate} tx/s carrying block vs the receiver's pool: (spend, receiving node) pairs whose pool \
                 held the spend when the block landed {pooled_first} · pooled only after it landed {landed_first} · never pooled \
                 {never_pooled}"
            );
            eprintln!(
                "[perf-load] n={n} stage {rate} tx/s spread split: pools that held the spend per tx {reach:?} (of {n}) · carrying \
                 block produced by the submitter {own_carried} of {} · at the slowest node: produced → landed p50 {:.1} / p95 \
                 {:.1} s, landed → in its DAG p50 {:.1} / p95 {:.1} s · landed by follow {} / by-id-or-batch {} · not seen \
                 landing {unseen}",
                st.iter().filter(|s| s.block.is_some()).count(),
                quantile(&wire_term, 0.5),
                quantile(&wire_term, 0.95),
                quantile(&node_term, 0.5),
                quantile(&node_term, 0.95),
                by_lane[0],
                by_lane[1],
            );
            // ⭐ THE INCLUSION'S SPLIT (link 67): per spend, submit → the first template ANY producer laid it in (the
            // selection wait), → the first laying template whose block finished (prove + grind, and the laying templates
            // whose block never finished), → the submitter reads it spent (the carrying block's way back to it). And per
            // template that began after the submit while its producer's pool HELD the spend but did not lay it: how full its
            // lane was (real txs laid) against how many of this scenario's spends that pool held — lane saturation vs a
            // draw that leaves a layable spend out.
            let proved = &sim.report.proved[proved0..];
            let ours: HashSet<Hash32> = spends.iter().filter_map(|s| s.tx).collect();
            let (mut sel_wait, mut lay_to_born, mut born_to_incl) = (Vec::new(), Vec::new(), Vec::new());
            let (mut lays_per, mut dead_lays, mut carried_first) = (Vec::new(), 0usize, 0usize);
            let mut by_stamp: Vec<(Option<(u32, u32)>, usize, Option<u64>)> = Vec::new();
            let mut passed: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
            let (mut passed_no_transition, mut passed_pool_ours, mut not_reached) = (0usize, Vec::new(), 0usize);
            for s in &st {
                let Some(t) = s.tx else { continue };
                let mut lays: Vec<&ProveSample> = proved.iter().filter(|p| p.txs.contains(&t)).collect();
                lays.sort_by_key(|p| p.begun);
                lays_per.push(lays.len());
                let finished = |p: &&ProveSample| p.block.and_then(|b| sim.born.get(&b).map(|bn| (b, bn.1)));
                dead_lays += lays.iter().filter(|p| finished(p).is_none()).count();
                let first_lay = lays.first().map(|p| p.begun);
                by_stamp.push((s.stamp, lays.len(), first_lay.map(|fl| fl.saturating_sub(s.due) / 100)));
                if let Some(fl) = first_lay {
                    sel_wait.push(fl.saturating_sub(s.due) as f64 / 1e3);
                }
                let first_done = lays.iter().find_map(finished);
                if let (Some(fl), Some((b, born))) = (first_lay, first_done) {
                    lay_to_born.push(born.saturating_sub(fl) as f64 / 1e3);
                    carried_first += usize::from(s.block == Some(b));
                }
                if let (Some(inc), Some(born)) = (s.included, s.block.and_then(|b| sim.born.get(&b).map(|bn| bn.1))) {
                    born_to_incl.push(inc.saturating_sub(born) as f64 / 1e3);
                }
                let until = first_lay.or(s.included).unwrap_or(sim.now);
                for p in proved.iter().filter(|p| p.begun >= s.due && p.begun < until) {
                    if !p.pool.contains(&t) {
                        not_reached += 1;
                        continue;
                    }
                    *passed.entry(p.txs.len()).or_default() += 1;
                    passed_no_transition += usize::from(!p.spend);
                    passed_pool_ours.push(p.pool.iter().filter(|x| ours.contains(x)).count() as f64);
                }
            }
            for v in [&mut sel_wait, &mut lay_to_born, &mut born_to_incl, &mut passed_pool_ours] {
                v.sort_by(f64::total_cmp);
            }
            eprintln!(
                "[perf-load] n={n} stage {rate} tx/s inclusion split: submit → first template laying it p50 {:.1} / p95 {:.1} s \
                 ({} of {} laid) · first lay → first laying block finished p50 {:.1} / p95 {:.1} s · that block is the carrying \
                 one {carried_first} · carrying block finished → the submitter reads spent p50 {:.1} / p95 {:.1} s · laying \
                 templates per spend {lays_per:?}, {dead_lays} never finished · templates that began while their pool held the \
                 spend and did not lay it, by real txs laid {{laid: templates}} {passed:?} ({passed_no_transition} with no note \
                 transition; this scenario's spends in that pool p50 {:.0} / p95 {:.0}) · templates whose pool did not hold it yet \
                 {not_reached} · per spend ((stamp bits, pool's required bits at submit), laying templates, submit → first lay \
                 ds) {by_stamp:?}",
                quantile(&sel_wait, 0.5),
                quantile(&sel_wait, 0.95),
                sel_wait.len(),
                st.len(),
                quantile(&lay_to_born, 0.5),
                quantile(&lay_to_born, 0.95),
                quantile(&born_to_incl, 0.5),
                quantile(&born_to_incl, 0.95),
                quantile(&passed_pool_ours, 0.5),
                quantile(&passed_pool_ours, 0.95),
            );
            let refusals: u32 = st.iter().map(|s| s.refusals).sum();
            let last_refusal = st.iter().rev().find(|s| !s.last_refusal.is_empty()).map_or("none", |s| s.last_refusal.as_str());
            let detail = format!(
                "sim, CPU charged · n={n} · settled {}/{} · p50 {p50:.1} s · refusals {refusals} (last: {last_refusal})",
                lat.len(),
                st.len()
            );
            super::perf::row(&format!("P10 n={n} stage {rate} tx/s offered: settled tx/s"), tput, "tx/s", None, &detail);
            super::perf::row_within(&format!("P10 n={n} stage {rate} tx/s offered: p95 submit → spent on every node"), p95, "s", None, &detail, 0.5);
            let base = *base_p95.get_or_insert(p95);
            let why = if lat.len() < st.len() {
                Some(format!("{} of {} spend(s) never settled within the drain", st.len() - lat.len(), st.len()))
            } else if p95 > 2.0 * base + 0.5 {
                // the doc's knee: "wallets submit at a rising rate until p95 P2 doubles"
                Some(format!("p95 {p95:.1} s > 2 × the 1 tx/s stage's {base:.1} s + one read"))
            } else {
                None
            };
            match why {
                Some(w) if knee.is_none() => knee = Some((rate, w)),
                None if knee.is_none() => below_knee = Some((rate, tput, p95)),
                _ => {}
            }
        }
        let stage0_settled = spends.iter().filter(|s| s.stage == 0 && s.settled.is_some()).count();
        let (best_rate, best_tput, best_p95) = below_knee.unwrap_or((0, 0.0, f64::NAN));
        super::perf::row(
            &format!("P10 throughput at the knee, n={n} producers: sustained settled tx/s"),
            best_tput,
            "tx/s",
            None,
            &format!(
                "sim, CPU charged · the highest stage below the knee: {best_rate} tx/s offered, p95 {best_p95:.1} s · knee: {} · \
                 north star Visa-class (the PERF-REPORT's cited comparison)",
                knee.as_ref().map_or("not reached at 32 tx/s offered".to_string(), |(r, w)| format!("{r} tx/s ({w})"))
            ),
        );
        let interval = if produced > 0 { window_ms as f64 / produced as f64 / 1e3 } else { f64::INFINITY };
        super::perf::row(
            &format!("P11 block interval achieved at n={n} producers (mesh-wide, under load)"),
            interval,
            "s",
            Some(sim.params.target_spacing_ms as f64 / 1e3),
            &format!(
                "sim, {produced} block(s) over the {:.0} s load window · selected chain {tip0} → {tip1} · target_spacing_ms {}",
                window_ms as f64 / 1e3,
                sim.params.target_spacing_ms
            ),
        );
        // THE PROVE TERM BY SHAPE (P11: a node's next block begins only after the last one's prove + grind): the load
        // window's templates split by whether they stated a note transition, and how many templates carried each real tx —
        // one tx in k concurrent blocks is k proves of the note-transition aggregate for one payment.
        let proved = &sim.report.proved[proved0..];
        let ms_of = |spend: bool| {
            let mut v: Vec<f64> = proved.iter().filter(|p| p.spend == spend).map(|p| p.ms as f64).collect();
            v.sort_by(f64::total_cmp);
            v
        };
        let mut carried: HashMap<Hash32, usize> = HashMap::new();
        for p in proved.iter().filter(|p| p.spend) {
            for t in &p.txs {
                *carried.entry(*t).or_default() += 1;
            }
        }
        let mut mult: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
        for k in carried.values() {
            *mult.entry(*k).or_default() += 1;
        }
        for (label, v) in [("no note transition", ms_of(false)), ("note transition", ms_of(true))] {
            eprintln!(
                "[perf-load] n={n} prove by shape — {label}: {} template(s), p50 {:.0} / p95 {:.0} / max {:.0} ms, total {:.1} s",
                v.len(),
                quantile(&v, 0.5),
                quantile(&v, 0.95),
                v.last().copied().unwrap_or(f64::NAN),
                v.iter().sum::<f64>() / 1e3
            );
        }
        let per_block: Vec<usize> = proved.iter().filter(|p| p.spend).map(|p| p.txs.len()).collect();
        eprintln!(
            "[perf-load] n={n} carriage: {} distinct tx(s) in {} note-transition template(s) ({:.2} tx/template, covers {}) · \
             templates per tx {{k: txs}} {:?} · per node note-transition templates {:?}",
            carried.len(),
            per_block.len(),
            per_block.iter().sum::<usize>() as f64 / per_block.len().max(1) as f64,
            proved.iter().filter(|p| p.spend).map(|p| p.covers).sum::<usize>(),
            mult,
            (0..n).map(|i| proved.iter().filter(|p| p.spend && p.node == i).count()).collect::<Vec<_>>()
        );
        // THE INBOUND BYTES (the every-node term's resource): what each node's links carried to it over the load window, by
        // lane and freshness, against its links' capacity — (n − 1) followed peers at `bytes_per_ms` each.
        let rx: Vec<([u64; RX_KINDS], [u64; RX_KINDS])> = (0..n)
            .map(|i| {
                let ((b1, c1), (b0, c0)) = (sim.inbound(i), rx0[i]);
                (std::array::from_fn(|k| b1[k] - b0[k]), std::array::from_fn(|k| c1[k] - c0[k]))
            })
            .collect();
        let all: u64 = rx.iter().map(|(b, _)| b.iter().sum::<u64>()).sum();
        for k in 0..RX_KINDS {
            let (b, c): (u64, u64) = (rx.iter().map(|r| r.0[k]).sum(), rx.iter().map(|r| r.1[k]).sum());
            eprintln!(
                "[perf-load] n={n} inbound {:<42} {:>9.1} MB ({:>4.1} %) · {:>6} bod(ies) · {:>7.1} B/ms per node",
                RX_LABELS[k],
                b as f64 / 1e6,
                b as f64 * 100.0 / all.max(1) as f64,
                c,
                b as f64 / n as f64 / window_ms.max(1) as f64
            );
        }
        let fresh_bodies: u64 = rx.iter().map(|r| r.1[0] + r.1[1] + r.1[3] + r.1[4]).sum();
        let dup_bodies: u64 = rx.iter().map(|r| r.1[2] + r.1[5]).sum();
        eprintln!(
            "[perf-load] n={n} inbound per node B/ms over {:.0} s (capacity {} links × {} B/ms = {} B/ms): {:?} · duplicate bodies \
             {dup_bodies} per {fresh_bodies} fresh ({:.2} per fresh)",
            window_ms as f64 / 1e3,
            n - 1,
            sim.wire.phys.bytes_per_ms,
            (n as u64 - 1) * sim.wire.phys.bytes_per_ms,
            rx.iter().map(|(b, _)| b.iter().sum::<u64>() / window_ms.max(1)).collect::<Vec<_>>(),
            dup_bodies as f64 / fresh_bodies.max(1) as f64
        );
        eprintln!("[perf-load] n={n} duplicate sources since the census began (dup lane ← first copy): {}", sim.dup_sources_line());
        let mut other: Vec<(u64, String)> = sim
            .inbound_other()
            .into_iter()
            .map(|(k, v)| (v - other0.get(&k).copied().unwrap_or(0), k))
            .filter(|(v, _)| *v > 0)
            .collect();
        other.sort_by(|a, b| b.0.cmp(&a.0));
        eprintln!(
            "[perf-load] n={n} inbound record/DA/sync/other pages by tag: {}",
            other.iter().take(8).map(|(v, k)| format!("{k} {:.1} MB", *v as f64 / 1e6)).collect::<Vec<_>>().join(", ")
        );
        let mut by_kind: Vec<(u64, &str)> = sim
            .cell_kinds()
            .iter()
            .zip(&cells0)
            .zip(crate::transport::CELL_KIND_NAMES.iter())
            .map(|((a, b), name)| (a - b, *name))
            .filter(|(c, _)| *c > 0)
            .collect();
        by_kind.sort_by(|a, b| b.0.cmp(&a.0));
        let cells_all: u64 = by_kind.iter().map(|(c, _)| c).sum();
        eprintln!(
            "[perf-load] n={n} real cell copies on links over the load window, by class: {} · per link {:.1} B/ms against the \
             wire's {} B/ms",
            by_kind
                .iter()
                .map(|(c, k)| format!("{k} {c} ({:.1} %)", *c as f64 * 100.0 / cells_all.max(1) as f64))
                .collect::<Vec<_>>()
                .join(", "),
            cells_all as f64 * CELL_SIZE as f64 / (n * (n - 1)) as f64 / window_ms.max(1) as f64,
            sim.wire.phys.bytes_per_ms
        );
        let names = &crate::transport::CELL_KIND_NAMES;
        let shed: Vec<String> = sim
            .cell_shed()
            .iter()
            .zip(&shed0)
            .enumerate()
            .filter(|(_, (a, b))| *a > *b)
            .map(|(k, (a, b))| format!("{} {}", names[k], a - b))
            .collect();
        let wait: Vec<u64> = sim.cell_wait().iter().zip(&wait0).map(|(a, b)| a - b).collect();
        let wait_all: u64 = wait.iter().sum();
        eprintln!(
            "[perf-load] n={n} cell lane over the load window: shed by a full writer {} · waited for the link {}",
            if shed.is_empty() { "none".to_string() } else { shed.join(", ") },
            wait.iter()
                .enumerate()
                .map(|(b, c)| {
                    let edge = CELL_WAIT_EDGES_MS
                        .get(b)
                        .map_or_else(|| format!("≥ {} s", CELL_WAIT_EDGES_MS[b - 1] / 1_000), |e| format!("< {e} ms"));
                    format!("{edge} {:.1} %", *c as f64 * 100.0 / wait_all.max(1) as f64)
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
        // ⭐ DB-448: the tx fetch's yield over the load window — an ask answered `notfound` cost a bulk round trip and moved
        // no body (a hashed host that never pooled the id, or an announcer that evicted it).
        let fetch1 = tx_fetch(&sim);
        let (f_sent, f_taken, f_empty) = (fetch1.0 - fetch0.0, fetch1.1 - fetch0.1, fetch1.2 - fetch0.2);
        eprintln!(
            "[perf-load] n={n} tx fetches over the load window: sent {f_sent} · answers taken {f_taken} · answered carrying \
             nothing {f_empty} ({:.1} %) · bodies delivered {}",
            f_empty as f64 * 100.0 / f_taken.max(1) as f64,
            f_taken - f_empty
        );
        let ingest1 = ingest(&sim);
        let row = |k: usize| {
            let (c, us) = (ingest1[k].0 - ingest0[k].0, ingest1[k].1 - ingest0[k].1);
            format!("{c} ({:.1} ms lock-held, {:.1} ms each)", us as f64 / 1e3, us as f64 / 1e3 / c.max(1) as f64)
        };
        eprintln!(
            "[perf-load] n={n} relayed tx bodies by the pool's answer over the load window (DB-449): pooled {} · already \
             known or settled {} · anchor not held {} · other refusals {}",
            row(0),
            row(1),
            row(2),
            row(3)
        );
        let (wait, waiting) = (0..n).fold(([0u64; 4], 0usize), |(mut acc, w), i| {
            let (c, now_waiting) = sim.rt(i).tx_anchor_census();
            for (a, x) in acc.iter_mut().zip(c) {
                *a += x;
            }
            (acc, w + now_waiting)
        });
        eprintln!(
            "[perf-load] n={n} spends that waited for their anchor over the whole run (DB-449): waited {} · pooled after the \
             anchor arrived {} · refused when judged again {} · dropped (reach passed or evicted) {} · waiting at the end {waiting}",
            wait[0], wait[1], wait[2], wait[3]
        );
        for (k, [sends, repeats, msgs, sender_msgs]) in sim.cell_msgs() {
            eprintln!(
                "[perf-load] n={n} cell messages over the whole run, {}: {sends} cell send(s) (before the per-link fan-out), \
                 {repeats} repeat a chunk the same node sent before · {msgs} distinct message(s), {sender_msgs} (sender, \
                 message) pair(s) = {:.2} sender(s) per message, {:.1} cell(s) per (sender, message)",
                names[usize::from(k)],
                sender_msgs as f64 / msgs.max(1) as f64,
                sends as f64 / sender_msgs.max(1) as f64
            );
        }
        let (over, most) = sim.lane_pressure();
        eprintln!(
            "[perf-load] n={n} lanes: {over} send(s) over the whole run found {} conversations already open on their link \
             (arti would queue them; this wire delivers them in parallel) · most open on one link {most}",
            crate::arti_transport::BULK_LANES_PER_HOST
        );
        eprintln!("[perf-load] n={n}: wall {:?} · {}", wall.elapsed(), speed_line());
        assert!(
            stage0_settled == LOAD_STAGE_SPENDS,
            "⛔ P10 measured nothing: at 1 tx/s only {stage0_settled} of {LOAD_STAGE_SPENDS} spend(s) reached every node — \
             refusals {:?} · {}",
            spends.iter().filter(|s| s.stage == 0).map(|s| (s.refusals, s.last_refusal.clone())).collect::<Vec<_>>(),
            diag(&sim)
        );
    }

    /// ⭐⭐ DB-444 (RED on the body flood, link 65) — A SEND REACHES EVERY PEER BY ITS INVENTORY, AND NO NODE PUTS ITS BODY ON
    /// THE CELL LANE. Three daemons on the testnet identity; a wallet-shaped send is submitted to node 0 through the submit
    /// door's own sequence while production is paused (so no block can carry it before the peers hold it); every peer must
    /// then POOL it with zero Tx-class cells on any link — the body crossed once per peer over the bulk lane (a `TXBODIES`
    /// answer) — and once production resumes the payment reads spent on every node.
    /// MEASURED why: the n = 8 load put 80.2 % of real cells on Tx bodies, 5.67 senders per tx, 38 % of them shed by full
    /// writers (night/perf-load-20261021-022905-n8.log). docs/DB-444.
    /// TWO-PARTY-REVIEWED: each peer's own pool and nullifier set are read; nothing is taken from the submit's return.
    #[test]
    fn db444_a_send_reaches_every_peer_by_inventory_and_no_node_floods_its_body() {
        let seed = journey::seed(0x0DB4_4420_2610_2100);
        let n = 3;
        let mut sim = NetSim::testnet(n, Physics::from_env(), seed).with_band_double().boot_from_disk();
        let converged = run_until(&mut sim, 300_000, |s| (1..n).all(|i| s.one_chain_between(0, i)));
        assert!(converged.is_some(), "CALIBRATION: the mesh converges to one chain: {}", diag(&sim));
        let k = 0x0DB4_4401u64;
        assert!(
            Node::test_spend_carrier(k, 1).is_some() && Node::test_wallet_tag_list(k, 1).is_some(),
            "CALIBRATION: the note's spend carrier and spend-or-decoy prove"
        );
        let cm = credit(&sim, 0, k);
        let budget = spendable_within_ms(&sim) * 4;
        let funded = run_until(&mut sim, budget, |s| s.rt(0).node().member_path_ready_for_test(&cm));
        assert!(funded.is_some(), "CALIBRATION: the note is spendable on node 0: {}", diag(&sim));
        sim.produce_paused = true;
        sim.run(10_000, 10_000); // a block already grinding lands; nothing new is produced
        let slot = |name: &str| crate::transport::CELL_KIND_NAMES.iter().position(|k| *k == name);
        let tx_slot = slot("Tx").expect("the Tx cell class");
        let cells0 = sim.cell_kinds();
        let (id, nf) = submit_wallet_send(&sim, 0, &cm, 0x444).expect("CONTROL: node 0's submit door admits the wallet-shaped send");
        let pooled = run_until(&mut sim, 60_000, |s| (1..n).all(|i| s.rt(i).node().mempool().contains(&id)));
        let cells = sim.cell_kinds();
        let tx_cells = cells[tx_slot] - cells0[tx_slot];
        let inv_cells = slot("TxInv").map_or(0, |k| cells[k] - cells0[k]);
        eprintln!(
            "[db444] peers pooled the send after {pooled:?} sim ms · Tx-class cell copies {tx_cells} · TxInv cell copies {inv_cells}"
        );
        assert!(
            pooled.is_some(),
            "⛔ DB-444: a peer never pooled the send within 60 s — pooled per node {:?} · {}",
            (0..n).map(|i| sim.rt(i).node().mempool().contains(&id)).collect::<Vec<_>>(),
            diag(&sim)
        );
        assert_eq!(
            tx_cells, 0,
            "⛔ DB-444: {tx_cells} Tx-class cell copies crossed the links — a node flooded the send's whole body to every peer \
             instead of announcing its id ({inv_cells} TxInv copies)"
        );
        sim.produce_paused = false;
        let settled = run_until(&mut sim, 120_000, |s| (0..n).all(|i| s.rt(i).node().is_nullifier_spent(&Hash32(nf))));
        assert!(settled.is_some(), "⛔ DB-444: the payment never read spent on every node: {}", diag(&sim));
    }

    /// ⭐⭐ DB-448 (RED on DB-444's hashed fetch) — A TX FETCH ASKS A PEER THAT ANNOUNCED THE ID, NEVER A NON-HOLDER WHILE THE
    /// POOL IS STILL. Four daemons on the testnet identity, one funded note per node; production paused (no block can carry
    /// a spend, so every announcer still pools what it announced); one wallet-shaped send submitted on EACH node at the same
    /// instant. Every node must pool all four spends, and no kind-21 fetch may come back carrying nothing: an announcer
    /// holds the body, a hashed host holds it 1 time in 3 at the start. MEASURED why (link 71, night/link71-load2.txt):
    /// under load every spend sat in its submitter's pool alone (`pools that held the spend per tx [1, 1, …]`), so only
    /// the submitter's next template could lay it. Bitcoin Core `TxRequestTracker`. docs/DB-448.
    /// TWO-PARTY-REVIEWED: each node's own pool is read; the census counts answers the askers took off the wire.
    #[test]
    fn db448_a_tx_fetch_asks_an_announcer_and_never_a_non_holder_while_the_pool_is_still() {
        let seed = journey::seed(0x0DB4_4820_2610_2100);
        let n = 4;
        let mut sim = NetSim::testnet(n, Physics::from_env(), seed).with_band_double().boot_from_disk();
        let converged = run_until(&mut sim, 300_000, |s| (1..n).all(|i| s.one_chain_between(0, i)));
        assert!(converged.is_some(), "CALIBRATION: the mesh converges to one chain: {}", diag(&sim));
        let keys: Vec<u64> = (0..n as u64).map(|i| 0x0DB4_4801 + i).collect();
        for &k in &keys {
            assert!(
                Node::test_spend_carrier(k, 1).is_some() && Node::test_wallet_tag_list(k, 1).is_some(),
                "CALIBRATION: the note's spend carrier and spend-or-decoy prove"
            );
        }
        let cms: Vec<[u8; 32]> = keys.iter().enumerate().map(|(i, &k)| credit(&sim, i, k)).collect();
        let budget = spendable_within_ms(&sim) * 4;
        let funded = run_until(&mut sim, budget, |s| (0..n).all(|i| s.rt(i).node().member_path_ready_for_test(&cms[i])));
        assert!(funded.is_some(), "CALIBRATION: each node's note is spendable on it: {}", diag(&sim));
        sim.produce_paused = true;
        sim.run(10_000, 10_000); // a block already grinding lands; nothing new is produced
        let fetch = |s: &NetSim| {
            s.ask_kinds()
                .into_iter()
                .find(|k| k.0 == crate::arti_transport::BULK_REQ_KIND_TX_FETCH)
                .map_or((0, 0, 0), |(_, sent, taken, empty, _)| (sent, taken, empty))
        };
        let before = fetch(&sim);
        // each node submits as soon as it can BUILD its send (a wallet waits the same way, `spend_when_spendable`): MEASURED
        // link 72, a member path read ready one step before the build stopped refusing `MemberCarrierRequired`. Production
        // stays paused, so a send submitted early cannot be carried before the others are pooled.
        let mut ids: Vec<Option<Hash32>> = vec![None; n];
        let t_submit = sim.now;
        loop {
            let mut refusals = Vec::new();
            for i in 0..n {
                if ids[i].is_none() {
                    match submit_wallet_send(&sim, i, &cms[i], 0x448 + i as u64) {
                        Ok((id, _)) => ids[i] = Some(id),
                        Err(e) => refusals.push((i, e)),
                    }
                }
            }
            if refusals.is_empty() {
                break;
            }
            assert!(sim.now < t_submit + 60_000, "CONTROL: each node's submit door admits its send within 60 s: {refusals:?}");
            sim.run(1_000, 1_000);
        }
        let ids: Vec<Hash32> = ids.into_iter().flatten().collect();
        let pooled = run_until(&mut sim, 60_000, |s| (0..n).all(|i| ids.iter().all(|id| s.rt(i).node().mempool().contains(id))));
        let after = fetch(&sim);
        let (sent, taken, empty) = (after.0 - before.0, after.1 - before.1, after.2 - before.2);
        let held: Vec<usize> = ids.iter().map(|id| (0..n).filter(|&i| sim.rt(i).node().mempool().contains(id)).count()).collect();
        eprintln!(
            "[db448] every pool held every spend after {pooled:?} sim ms · pools holding each spend {held:?} of {n} · tx fetches \
             sent {sent}, answers taken {taken}, answered carrying nothing {empty}"
        );
        assert!(
            pooled.is_some(),
            "⛔ DB-448: a spend never reached every pool within 60 s — pools holding each spend {held:?} of {n} · tx fetches sent \
             {sent}, {empty} answered empty · {}",
            diag(&sim)
        );
        assert_eq!(
            empty, 0,
            "⛔ DB-448: {empty} of {taken} tx fetch(es) asked a peer that did not hold the body — the fetch went to a hashed host \
             instead of a peer that announced the id ({sent} sent)"
        );
    }

    /// ⛔⛔ DB-418 — THE POST-ADOPT JOURNEY: a node that joins by the CERTIFIED BUNDLE — the chain is past the live catch-up
    /// depth, so the block lanes cannot close the gap and the runtime's own DSYNC ask jumps it — serves a wallet restored on it
    /// (its balance AND its spend), and the payee on another node reads the payment.
    /// WHY (link 24): in all 9 green seeds of sweep simpar-20261007-180330 the T1.6 joiner arrived by GRAFTING ("consensus-
    /// grafted a live peer's block": the chain was inside `LIVE_CATCH_UP_DEPTH`), so no journey exercised an ADOPTED node; the
    /// two seeds where a node adopted by accident (a stale spine, DB-417) both went red after the adopt — 0x3: the adopt cleared
    /// the node's window index and the wallet's low catch-up read 0 shard tables, so the send never built its path; 0xa: the
    /// node's nullifier view could not answer absence (`[nf-gate] REFUSE: 32 of 32 input(s) have NO POSITIVE proof of absence`).
    /// Steps: PA.1 the chain grows past `LIVE_CATCH_UP_DEPTH` with node 2 absent; PA.2 node 2 joins fresh, by the bundle adopt
    /// (`mesh_joined_how`), to one chain and a current view; PA.3 W2 restored from its seed on node 2 reads its balance; PA.4 it
    /// sends 1.0 to W1 through node 2 and W1 reads it through node 0.
    /// TWO-PARTY-REVIEWED: the spend is built and admitted on the adopted node; the claim is what the PEER's wallet reads.
    #[test]
    fn sim_journey_post_adopt_fast() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(0x7131_0007_2026_1007);
        super::perf::begin("post-adopt", seed);
        let mut sim = NetSim::testnet(3, Physics::from_env(), seed)
            .with_band_double()
            .with_journey_stake_lock()
            .boot_from_disk();
        sim.hold_down(2); // the joiner does not exist until the chain is past the catch-up depth
        sim.charge_cpu = true;
        sim.check_state = true;
        let mut v = Vec::new();
        crate::harness::sim_coverage::start();
        let go = post_adopt(&mut sim, &mut v, &wall);
        crate::harness::sim_coverage::finish("journey-post-adopt");
        eprintln!("[sim-journey] post-adopt lane: sim {} s · wall {:?} · {}", sim.now / 1000, wall.elapsed(), speed_line());
        run_rows(&sim);
        journey::record("post-adopt", seed, &v);
        assert!(go.is_some(), "⛔ the post-adopt journey stopped at {:?}", v.last().map(|(id, _, d)| (*id, d.clone())));
    }

    /// The post-adopt journey's steps (see [`sim_journey_post_adopt_fast`]).
    fn post_adopt(sim: &mut NetSim, v: &mut Vec<(&'static str, &'static str, String)>, wall: &std::time::Instant) -> Option<()> {
        let (w1, w2, _url0, _url1, within) = fund_pair(sim, v, wall, "simadopt")?;
        // PA.1 — past the catch-up depth by one fold depth, so the gap the joiner meets is past it whatever its boot delay
        let target = crate::node_runtime::LIVE_CATCH_UP_DEPTH + sim.params.record_fold_depth;
        let grow_ms = (target + 64) * sim.production_step_ms() * 2;
        let t = run_until(sim, grow_ms, |s| s.rt(0).node().tip_height() > target);
        let h0 = sim.rt(0).node().tip_height();
        pass(v, "PA.1", t.is_some(), format!("node 0 at height {h0} (> {target}) after {t:?} sim ms"), wall)?;
        // PA.2 — the fresh node joins by the runtime's own path; the arm's premise is that this path is the bundle adopt
        if let Err(e) = sim.join_fresh(2) {
            return fail(sim, v, "PA.2", format!("the fresh node could not boot: {e}"), wall);
        }
        let joined = run_until(sim, within * 1000, |s| s.one_chain_between(0, 2) && view_current(s, 2));
        // PERF P8 (post-adopt shape): a fresh node past the catch-up depth joins by the certified bundle
        super::perf::row(
            "P8 fresh node join past the catch-up depth (certified bundle) → one chain + a current view",
            joined.map_or(f64::INFINITY, |t| t as f64 / 1e3),
            "s",
            None,
            &format!("sim, node CPU charged, tip height {} (P14 judges flatness)", sim.rt(0).node().tip_height()),
        );
        let c = info(sim, 2);
        let how = c["mesh_joined_how"].as_str().unwrap_or("").to_string();
        if joined.is_none() {
            return fail(
                sim,
                v,
                "PA.2",
                format!(
                    "the joiner did not reach one chain + a current view within {within} s: one chain {} · view {}/{} · \
                     wedged {} · mesh_joined {} ({how:?})",
                    sim.one_chain_between(0, 2),
                    c["nf_view_present"],
                    c["nf_view_matches_acc"],
                    c["fold_wedged"],
                    c["mesh_joined"]
                ),
                wall,
            );
        }
        // The premise is read from the joiner's OWN state — it holds a certified sync state (`synced`) — never from
        // `mesh_joined_how`, which names only the FIRST join event (MEASURED sim-20261007-195905: the joiner grafted one
        // live peer's block, then adopted the certified bundle at height 632, and `mesh_joined_how` still read "grafted").
        let adopted = sim.rt(2).node().spine_state().0;
        if !adopted {
            return fail(sim, v, "PA.2", format!("the joiner did not adopt a bundle (how: {how:?}) — the arm's premise failed"), wall);
        }
        pass_inv(sim, v, "PA.2", format!("joined after {joined:?} sim ms by a certified adopt (first join event: {how:?})"), wall)?;
        // PA.3 — W2 restored from its seed on the adopted node reads its balance
        let url2 = sim.serve_rpc(2);
        let w2_now = balance_until(sim, &w2, 120, |_| true);
        let r2 = match while_meshing(sim, 300, {
            let r = w2.restored_elsewhere_for_test("w2pa", &url2);
            move || r
        }) {
            Some(Ok(r)) => r,
            Some(Err(e)) => return fail(sim, v, "PA.3", format!("W2 could not be restored on the adopted node: {e}"), wall),
            None => return fail(sim, v, "PA.3", "W2's restore on the adopted node did not finish within 300 s".to_string(), wall),
        };
        let on_joiner = balance_until(sim, &r2, within, |b| b >= w2_now);
        if on_joiner < w2_now {
            let says = wallet_says(sim, &r2);
            return fail(sim, v, "PA.3", format!("on the adopted node W2 reads {on_joiner}, on node 1 {w2_now} · W2 there {says}"), wall);
        }
        pass_inv(sim, v, "PA.3", format!("W2 restored on the adopted node reads {on_joiner}"), wall)?;
        // PA.4 — it spends through the adopted node, and the payee reads the payment through ANOTHER node
        let before = balance_until(sim, &w1, 60, |_| true);
        if let Err(e) = send(sim, &r2, &w1.address, "1.0", within) {
            let says = wallet_says(sim, &r2);
            return fail(sim, v, "PA.4", format!("W2 could not send through the adopted node: {e} · W2 {says}"), wall);
        }
        let after = balance_until(sim, &w1, within, |b| b > before);
        if after <= before {
            return fail(sim, v, "PA.4", format!("W1 (node 0) never read W2's 1.0 sent through the adopted node: {before} → {after}"), wall);
        }
        pass_inv(sim, v, "PA.4", format!("W2 sent 1.0 through the adopted node; W1 read {before} → {after} through node 0"), wall)
    }

    /// ⭐⭐ THE ROUTE SWEEP — every route the node serves, read from the TREE (`surface_census::routes`, the scanner's own
    /// universe), is called once through the PRODUCTION router on a live simulated node holding a chain and a credited note.
    /// A route that PANICS, answers 500, or does not answer within 10 s is a red named by its route and source line; one
    /// slower than 1 s is printed. Every route called is recorded as simulator coverage, so a route added tomorrow is in
    /// the sweep the next time it runs, with no list to maintain.
    /// A live two-node mesh holding a chain and a credited note — the node every route is asked of.
    fn sweep_mesh(seed: u64) -> NetSim {
        let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().boot_from_disk();
        assert!(run_until(&mut sim, 120_000, |s| s.one_chain_between(0, 1)).is_some(), "CALIBRATION: the pair converges");
        let cm = credit(&sim, 0, 9_301);
        assert!(run_until(&mut sim, 120_000, |s| holds(s, 0, &cm)).is_some(), "CALIBRATION: the credit is held");
        sim
    }

    /// One HTTP/1.1 exchange with a simulated node's production RPC listener (what a wallet process sends); the body back.
    fn loopback_http(url: &str, method: &str, path: &str, body: &str) -> Option<String> {
        use std::io::{Read as _, Write as _};
        let addr = url.trim_start_matches("http://");
        let mut s = std::net::TcpStream::connect(addr).ok()?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(30))).ok()?;
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .ok()?;
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out.split_once("\r\n\r\n").map(|(_, b)| b.to_string())
    }

    /// ⭐ R7 F4 PIN — A BITCOIN COIN FUNDED AT A WALLET'S VAULT ADDRESS IS SERVED BY THE SIMULATED NODE'S `/btc_deposit_coin`,
    /// AS THE PRODUCTION SERVER SERVES IT. MEASURED fb17-L2b-f4 (21:22): the shipped add-money flow sat 30 minutes on "Waiting
    /// for your Bitcoin" with the coin funded and mined at its address — the simulator's listener never started the deposit
    /// watcher the production `serve` starts, so the route answered from a cache nothing ever filled. Asserted over HTTP, as
    /// the wallet asks it: the funded coin, its value and at least one confirmation. Tamper: an unfunded address answers none.
    // gated like the vault fixture it calls (`harness::mix_journey` is pins-harness only): without the gate every build
    // without the harness family failed to compile (E0433, measured 2026-10-29 on main @ 86ba865)
    #[cfg(feature = "pins-harness")]
    #[test]
    fn f4_a_funded_vault_coin_is_served_by_the_simulated_nodes_deposit_route() {
        let _serial = crate::btc_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
        let seed = 0xF4_C0_1029u64;
        let mut sim = NetSim::testnet(1, Physics::from_env(), seed).with_sim_bitcoin(seed, 60_000);
        let url = sim.serve_rpc(0);
        let (_, _, addr) = crate::harness::mix_journey::vault("f4-route", 0);
        let (_, _, empty) = crate::harness::mix_journey::vault("f4-route-empty", 0);
        sim.btc().fund(&addr, 140_000).expect("funded");
        sim.btc().mine(1);
        let ask = |a: &str| -> Vec<serde_json::Value> {
            let body = serde_json::json!({ "address": a }).to_string();
            match loopback_http(&url, "POST", "/btc_deposit_coin", &body).and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok()) {
                Some(v) => match v["coins"].as_array() {
                    Some(c) => c.clone(),
                    None => Vec::new(),
                },
                None => Vec::new(),
            }
        };
        let _ = ask(&empty);
        let wall = std::time::Instant::now();
        let mut coins = ask(&addr);
        while coins.is_empty() && wall.elapsed().as_secs() < 60 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            coins = ask(&addr);
        }
        assert_eq!(coins.len(), 1, "⛔ R7 F4: the simulated node does not serve the coin funded at the vault address: {coins:?}");
        assert_eq!(coins[0]["value_sats"], serde_json::json!(140_000), "⛔ R7 F4: the served coin's value is not the funded value");
        assert!(coins[0]["confirmations"].as_u64().is_some_and(|c| c >= 1), "⛔ R7 F4: the mined coin is served unconfirmed: {coins:?}");
        assert!(ask(&empty).is_empty(), "TAMPER: an address nobody funded is served a coin");
    }

    /// ⛔ DB-406 PIN — A VALIDATOR IDENTITY PROVISIONED THROUGH A SIMULATED NODE'S PRODUCTION RPC LANDS IN THAT NODE'S OWN
    /// DATADIR AND THE SUPERVISOR RESTARTS THE NODE ONTO IT. MEASURED sim-20261007-002601 (T3 FAIL "the node did not come back
    /// on your validator identity within 3 minutes"): `/provision_validator` wrote the process-wide `$HOME/.usdmd-node/
    /// validator-27780.key` — the LIVE daemon's identity file (mtime 00:31:40, inside the run) — and nothing restarted the
    /// node, so `/validator_id` kept answering the old key. Asserted here over HTTP, as the wallet reads it: the provision's
    /// answer, node 0's own key file, node 0's `/validator_id` after the restart, and node 1 one chain with it afterwards.
    #[test]
    fn db406_a_provisioned_identity_restarts_its_own_node_and_never_touches_the_operators_home() {
        let home_live = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".usdmd-node");
        let live_key = home_live.join("validator-27780.key");
        let live_before = std::fs::metadata(&live_key).and_then(|m| m.modified()).ok();
        let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_ne!(crate::persist::state_dir(), home_live, "a test process resolved its per-node files to the operator's live home");
        let mut sim = NetSim::testnet(2, Physics::from_env(), 0x406_2026_1007).with_band_double().boot_from_disk();
        assert!(run_until(&mut sim, 120_000, |s| s.one_chain_between(0, 1)).is_some(), "CALIBRATION: the pair converges");
        let url = sim.serve_rpc(0);
        let ask_id = |url: String| loopback_http(&url, "GET", "/validator_id", "");
        let before = while_meshing(&mut sim, 60, { let u = url.clone(); move || ask_id(u) }).flatten().unwrap_or_default();
        let old_hex = hx(&crate::pqauth::pubkey_id(&sim.keys[0].0));
        assert!(before.contains(&old_hex), "CALIBRATION: /validator_id answers the node's booted identity: {before}");

        let restarts0 = sim.restarts; // before the provision: the supervisor may restart the node while its answer is in flight
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let want_hex = hx(&crate::pqauth::pubkey_id(&pk));
        let body = format!(
            "{{\"vote_pk_hex\":\"{}\",\"vote_sk_hex\":\"{}\"}}",
            hx(&pk),
            hx(&sk)
        );
        let answer = while_meshing(&mut sim, 60, { let u = url.clone(); move || loopback_http(&u, "POST", "/provision_validator", &body) })
            .flatten()
            .unwrap_or_default();
        assert!(answer.contains(&want_hex) && answer.contains("\"restarting\":true"), "the provision was refused: {answer}");

        // node 0's OWN key file holds the provisioned identity …
        let own = sim.dirs[0].clone().expect("a datadir").join("validator-30000.key");
        let parsed = std::fs::read(&own).ok().and_then(|b| crate::validator::parse_vote_key_file(&b));
        assert!(
            parsed.as_ref().is_some_and(|(p, _, provisioned)| *p == pk && *provisioned),
            "node 0's own key file {} does not hold the provisioned identity (read {:?})",
            own.display(),
            parsed.map(|(p, _, prov)| (p.len(), prov))
        );
        // … the operator's live identity file was never touched …
        assert_eq!(
            std::fs::metadata(&live_key).and_then(|m| m.modified()).ok(),
            live_before,
            "the test wrote the operator's live identity file {}",
            live_key.display()
        );
        // … and the node comes back on it: /validator_id over HTTP, as the wallet polls it.
        let t0 = sim.now;
        let mut now_id = String::new();
        while sim.now - t0 < 60_000 && !now_id.contains(&want_hex) {
            now_id = while_meshing(&mut sim, 60, { let u = url.clone(); move || ask_id(u) }).flatten().unwrap_or_default();
            sim.run(1_000, 10_000);
        }
        assert!(
            now_id.contains(&want_hex),
            "node 0 never came back on the provisioned identity within 60 simulated s (restarts {} → {}): /validator_id = {now_id}",
            restarts0,
            sim.restarts
        );
        assert_eq!(sim.restarts, restarts0 + 1, "exactly one supervisor restart for one provision");
        assert!(
            run_until(&mut sim, 120_000, |s| s.one_chain_between(0, 1)).is_some(),
            "node 1 is not one chain with node 0 after its identity restart"
        );
    }

    /// CALIBRATION of the state invariant's SETTLED depth (the selected chain judged `record_fold_depth` steps below each
    /// tip): a mesh partitioned long enough for each side to build more than that depth of its own chain is a REAL split,
    /// and `state_divergence` must name it as a selected-chain divergence while the partition stands; healed, the mesh must
    /// become one chain again with every shared fold value equal. The negative half — a healthy mesh's tip-local GHOSTDAG
    /// convergence never fires it — is every journey run (MEASURED sim-20261007-005557 T2 and sim-20261007-031532 T2: the
    /// 8-blue-score judge fired on a mesh that read "state agrees" moments later).
    /// ⛔ FOUR nodes split 2|2, never a 2-node sever: a lone non-origin node with no live peer HOLDS production by design
    /// ("[produce] NO LIVE PEER", Bitcoin Core's getblocktemplate not-connected rule), so a severed pair can never build two
    /// sides (MEASURED link 12: node 1 sat at tip 2 for 900 s). Each side here has a live peer and produces.
    /// TWO-PARTY-REVIEWED: four independent Nodes — `NetSim::testnet(4, …)` boots each from its own datadir; every assertion
    /// compares one node's selected chain and fold values against another's.
    #[test]
    fn the_state_invariant_names_a_split_deeper_than_the_fold_depth_and_clears_when_healed() {
        let mut sim = NetSim::testnet(4, Physics::from_env(), 0x5e77_1ed0_2026_1007).with_band_double().boot_from_disk();
        // every node PRODUCING on one chain (a non-origin node that has not joined yet produces nothing: partitioned then, its
        // side could never build a chain of its own)
        assert!(
            run_until(&mut sim, 600_000, |s| (0..4).all(|i| s.report.produced[i] >= 3) && (1..4).all(|i| s.one_chain_between(0, i)))
                .is_some(),
            "CALIBRATION: the mesh converges with every node producing (produced {:?})",
            sim.report.produced
        );
        assert_eq!(sim.state_divergence(), None, "a converged mesh reads clean");
        let depth = sim.params.record_fold_depth;
        sim.partition(&[0, 1]);
        let split = run_until(&mut sim, 900_000, |s| s.state_divergence().is_some_and(|d| d.starts_with("selected chain")));
        eprintln!("[invariant-calibration] split named after {split:?} sim ms (produced {:?}): {:?}", sim.report.produced, sim.state_divergence());
        assert!(
            split.is_some(),
            "⛔ two sides partitioned 2|2 for 900 simulated s ({depth}-step fold depth) were never named a selected-chain divergence"
        );
        sim.heal(&[0, 1]);
        let healed = run_until(&mut sim, 900_000, |s| (1..4).all(|i| s.one_chain_between(0, i)) && s.state_divergence().is_none());
        eprintln!("[invariant-calibration] healed after {healed:?} sim ms: {:?}", sim.state_divergence());
        assert!(
            healed.is_some(),
            "⛔ healed, the mesh never became one chain with equal fold values within 900 simulated s: {:?}",
            sim.state_divergence()
        );
    }

    #[test]
    fn sim_every_node_route_answers_on_a_live_mesh_without_a_panic_or_a_hang() {
        let mut seed = 0x7131_0004_2026_1006u64;
        let mut sim = sweep_mesh(seed);
        let eco = crate::harness::surface_census::ecosystem();
        let routes = crate::harness::surface_census::routes(&eco);
        assert!(routes.len() > 100, "CALIBRATION: the route universe read {} route(s)", routes.len());
        crate::harness::sim_coverage::start();
        let (mut bad, mut slow) = (Vec::new(), Vec::new());
        for (m, p, at) in &routes {
            let method = if m == "ANY" { "GET".to_string() } else { m.clone() };
            let path = p.trim_end_matches('*').to_string();
            crate::harness::sim_coverage::note("route", &format!("{method} {path}"));
            let rt = sim.rts[0].clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let (m2, p2) = (method.clone(), path.clone());
            let t0 = std::time::Instant::now();
            std::thread::spawn(move || {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::rpc_http::route(&rt, &m2, &p2, "{}")));
                let _ = tx.send(r.map_err(|e| {
                    e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
                }));
            });
            match rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(Ok((code, body))) if code >= 500 && code != 503 => {
                    bad.push(format!("{method} {path} ({at}): answered {code} — {}", body.chars().take(160).collect::<String>()))
                }
                Ok(Ok(_)) => {}
                Ok(Err(panic)) => bad.push(format!("{method} {path} ({at}): PANICKED — {}", panic.chars().take(200).collect::<String>())),
                Err(_) => {
                    // the route is still running: does it hold the node? (a held lock freezes every other caller and the
                    // node's own loops; a free one is CPU burned on demand by any local caller)
                    let frozen = sim.rts[0].try_lock().is_err();
                    if frozen {
                        bad.push(format!("{method} {path} ({at}): no answer within 10 s and it HOLDS THE NODE'S LOCK — every caller and the node's loops freeze behind it"));
                        seed += 1;
                        sim = sweep_mesh(seed); // the stuck call keeps the old mesh; the sweep continues on a fresh one
                    } else {
                        bad.push(format!("{method} {path} ({at}): no answer within 10 s — on-demand work any local caller can trigger (the node's lock stays free)"));
                    }
                    continue;
                }
            }
            let ms = t0.elapsed().as_millis();
            if ms > 1_000 {
                slow.push(format!("{method} {path} ({at}): {ms} ms"));
            }
        }
        crate::harness::sim_coverage::finish("route-sweep");
        for s in &slow {
            eprintln!("[route-sweep] SLOW {s}");
        }
        for b in &bad {
            eprintln!("[route-sweep] RED {b}");
        }
        eprintln!("[route-sweep] {} route(s) called · {} red · {} slow (> 1 s)", routes.len(), bad.len(), slow.len());
        assert!(bad.is_empty(), "⛔ {} route(s) panicked, failed or hung on a live simulated node:\n{}", bad.len(), bad.join("\n"));
    }

    /// The dispatcher the adversarial route harness drives: the production router, or a refutation pin's planted wrapper.
    type Dispatch = Arc<dyn Fn(&Arc<Mutex<NodeRuntime<SimEndpoint>>>, &str, &str, &str) -> (u16, String) + Send + Sync>;

    /// The hostile bodies every route is sent (each one twice — REPLAYED), named so a red names what broke the door.
    fn hostile_bodies() -> Vec<(&'static str, String)> {
        const NUMERIC: &[&str] = &[
            "amount", "height", "count", "ordinal", "n", "from", "to", "limit", "index", "start", "end", "depth", "page", "fee", "price",
            "qty", "size", "epoch", "window", "k", "width", "offset", "len", "max", "min", "id", "seq", "nonce", "value", "stake",
            "weight", "sats", "rate", "block", "tip", "cursor", "slot",
        ];
        let obj = |v: &str| format!("{{{}}}", NUMERIC.iter().map(|f| format!("\"{f}\":{v}")).collect::<Vec<_>>().join(","));
        vec![
            ("empty", String::new()),
            ("open-brace", "{".into()),
            ("null", "null".into()),
            ("array", "[]".into()),
            ("bare-string", "\"x\"".into()),
            ("bare-number", "1".into()),
            ("unknown-field", r#"{"zzz":1}"#.into()),
            ("duplicate-keys", r#"{"a":1,"a":2}"#.into()),
            ("trailing-garbage", r#"{"a":1}garbage"#.into()),
            ("nul-bom-rtl", "{\"a\":\"\u{0}\u{feff}\u{202e}\",\"tx_hex\":\"\u{0}\",\"name\":\"\u{202e}\"}".into()),
            (
                "hex-garbage",
                r#"{"tx_hex":"zz","block_hex":"0x","cm_hex":"","cms_hex":["g"],"nf_hex":"00","address":"","id":"","hash":"ffff","root":"0","proof":"","sig":"","pk":"","name":"","handle":"","seed":"","memo":"","tx":"","block":"","note":"","witness":""}"#.into(),
            ),
            ("negative-numbers", obj("-1")),
            ("u64-overflow", obj("18446744073709551616")),
            ("u64-max", obj("18446744073709551615")),
            ("float-overflow", obj("1e400")),
            ("deep-nesting", "[".repeat(100_000)),
            ("oversized-string", format!("{{\"a\":\"{}\"}}", "A".repeat(4 << 20))),
            ("oversized-array", format!("[{}0]", "0,".repeat(500_000))),
        ]
    }

    /// ⭐⭐⭐ B1 (i) — THE ADVERSARIAL ROUTE HARNESS (readiness R1; the scanner's "node route with no adversarial test",
    /// 99 rows on 2026-10-22). Every route the node serves — the scanner's own universe, `surface_census::routes`, read
    /// from the TREE so a route added tomorrow is driven next run — goes through the dispatcher on node 0 of a live
    /// two-node mesh holding a chain and a credited note, with HOSTILE input, and the verdict is what the mesh HOLDS:
    ///   MALFORMED (an open brace, `null`, a bare string, duplicate and trailing tokens, NUL / BOM / RTL bytes),
    ///   OVERSIZED (a 4 MiB string, a 500k-element array, 100k nested brackets, a 16 KiB query string, a 10 KiB tail),
    ///   OVERFLOWING (u64::MAX, u64::MAX + 1, 1e400, and −1 in every numeric field name the routes read),
    ///   WRONG LANE (the wrong METHOD — GET on a POST route and back, PUT, DELETE, an empty and a non-ASCII method — and
    ///     every OTHER route's own benign 200 answer sent as this route's body, so a route reading another's shape shows),
    ///   TRAVERSAL (`..`, `%2e%2e`, `//`), REPLAYED (every hostile body sent twice), and OUT OF ORDER (the whole corpus
    ///   runs over the routes in reverse of the dispatcher's order).
    /// Fail-closed means: no panic; no 5xx except 503 (the honest "not yet"); an answer within 10 s (a call still running
    /// after 10 s is a red, and one that holds the node's lock freezes every caller — the sweep continues on a fresh mesh);
    /// an answer under 4 MiB; a route's whole corpus inside 60 s of wall (past it the rest is a red, never skipped
    /// silently); and THE PEER UNCHANGED: with nothing stepping the mesh, node 1's every censused field (`field_census`,
    /// the restart/replica census's own snapshot) is byte-identical before and after the whole sweep — the only path from
    /// a hostile request on node 0 into node 1's state is a leak. Then, production resumed, the pair must both produce on
    /// one chain within 120 simulated s with no state divergence. Every route driven is a `route-adversary` coverage row,
    /// so the scanner closes the category by MEASUREMENT on the current source (`holes.rs::adversary_driven_routes`).
    /// What it does NOT measure, stated: a WELL-FORMED forged object's proof, conservation and privacy — those are each
    /// door's own tamper pins (the value-creation and rogue-role censuses). Returns every red and the number of calls.
    /// TWO-PARTY-REVIEWED: two independent `Node`s over the simulated wire; the verdict is read from the PEER's fields and
    /// from the pair's production afterwards, never from what a call returned alone.
    fn adversarial_route_sweep(sim: &mut NetSim, mut seed: u64, dispatch: Dispatch) -> (Vec<String>, usize) {
        use std::time::{Duration, Instant};
        let eco = crate::harness::surface_census::ecosystem();
        let mut routes = crate::harness::surface_census::routes(&eco);
        assert!(routes.len() > 100, "CALIBRATION: the route universe read {} route(s)", routes.len());
        routes.reverse(); // OUT OF ORDER: the tree's order is the dispatcher's order
        let bodies = hostile_bodies();
        let one_call = |rt: Arc<Mutex<NodeRuntime<SimEndpoint>>>, method: String, path: String, body: String| -> Result<(u16, String), String> {
            let d = dispatch.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| d(&rt, &method, &path, &body)));
                let _ = tx.send(r.map_err(|e| {
                    let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                    format!("PANICKED — {}", msg.chars().take(200).collect::<String>())
                }));
            });
            rx.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|_| Err("HUNG".to_string()))
        };
        crate::harness::sim_coverage::start();
        sim.produce_paused = true;
        let mut peer_before = sim.field_census(1);
        let (mut reds, mut calls) = (Vec::new(), 0usize);
        // the WRONG-LANE corpus: every route's own benign 200 answer, deduplicated by content
        let mut answers: Vec<(String, String)> = Vec::new();
        for (m, p, _) in &routes {
            let method = if m == "ANY" { "GET" } else { m.as_str() };
            let path = p.trim_end_matches('*').to_string();
            calls += 1;
            if let Ok((200, body)) = one_call(sim.rts[0].clone(), method.to_string(), path.clone(), "{}".to_string()) {
                if !body.is_empty() && body.len() <= 64 << 10 && !answers.iter().any(|(_, b)| *b == body) {
                    answers.push((format!("{method} {path}"), body));
                }
            }
        }
        eprintln!("[route-adversary] wrong-lane corpus: {} distinct benign answer(s) from {} route(s)", answers.len(), routes.len());
        for (m, p, at) in &routes {
            let real: Vec<&str> = if m == "ANY" { vec!["GET", "POST"] } else { vec![m.as_str()] };
            let mut wrong: Vec<&str> = vec!["PUT", "DELETE", "", "GÉT"];
            for w in ["GET", "POST"] {
                if !real.contains(&w) {
                    wrong.push(w);
                }
            }
            let base = p.trim_end_matches('*').to_string();
            let mut plan: Vec<(String, String, String, String)> = Vec::new(); // (label, method, path, body)
            for rm in &real {
                crate::harness::sim_coverage::note("route", &format!("{rm} {base}"));
                for (label, body) in &bodies {
                    plan.push(((*label).to_string(), rm.to_string(), base.clone(), body.clone()));
                    plan.push((format!("{label} REPLAYED"), rm.to_string(), base.clone(), body.clone()));
                }
                for (label, path) in [
                    ("query-garbage", format!("{base}?amount=-1&height=99999999999999999999&count=0&a=%00&b=&c={}", "A".repeat(16 << 10))),
                    ("traversal", format!("{base}/../../../etc/passwd")),
                    ("encoded-traversal", format!("{base}/%2e%2e/%2e%2e")),
                    ("double-slash", format!("{base}//")),
                    ("long-tail", format!("{base}/{}", "A".repeat(10 << 10))),
                ] {
                    plan.push((label.to_string(), rm.to_string(), path, "{}".to_string()));
                }
                for (from, body) in &answers {
                    if *from != format!("{rm} {base}") {
                        plan.push((format!("wrong-lane: the answer of {from}"), rm.to_string(), base.clone(), body.clone()));
                    }
                }
            }
            for wm in &wrong {
                plan.push((format!("wrong-method {wm:?}"), wm.to_string(), base.clone(), "{}".to_string()));
            }
            let (t0, total) = (Instant::now(), plan.len());
            for (k, (label, method, path, body)) in plan.into_iter().enumerate() {
                if t0.elapsed() > Duration::from_secs(60) {
                    reds.push(format!("{m} {p} ({at}): 60 s of wall over {k} of {total} hostile inputs — its work under hostile input is not bounded"));
                    break;
                }
                calls += 1;
                match one_call(sim.rts[0].clone(), method.clone(), path.clone(), body) {
                    Ok((code, ans)) if code >= 500 && code != 503 => {
                        reds.push(format!("{method} {path} [{label}] ({at}): answered {code} — {}", ans.chars().take(160).collect::<String>()))
                    }
                    Ok((_, ans)) if ans.len() > 4 << 20 => reds.push(format!("{method} {path} [{label}] ({at}): answered {} bytes — the answer is not bounded", ans.len())),
                    Ok(_) => {}
                    Err(e) if e == "HUNG" => {
                        if sim.rts[0].try_lock().is_err() {
                            reds.push(format!("{method} {path} [{label}] ({at}): no answer within 10 s and it HOLDS THE NODE'S LOCK — every caller and the node's loops freeze behind it"));
                            // the stuck call keeps the old mesh; the sweep continues on a fresh one and re-baselines the peer
                            seed += 1;
                            *sim = sweep_mesh(seed);
                            sim.produce_paused = true;
                            peer_before = sim.field_census(1);
                        } else {
                            reds.push(format!("{method} {path} [{label}] ({at}): no answer within 10 s — on-demand work any local caller can trigger"));
                        }
                    }
                    Err(e) => reds.push(format!("{method} {path} [{label}] ({at}): {e}")),
                }
            }
        }
        let peer_after = sim.field_census(1);
        let changed: Vec<String> =
            peer_before.iter().zip(peer_after.iter()).filter(|(a, b)| a != b).map(|(a, b)| format!("{} {:?} → {:?}", a.0, a.1, b.1)).collect();
        if peer_before.len() != peer_after.len() || !changed.is_empty() {
            reds.push(format!("THE PEER CHANGED under hostile requests to node 0 — {} field(s): {}", changed.len(), changed.join(" · ")));
        }
        sim.produce_paused = false;
        let p0 = sim.report.produced.clone();
        let alive = run_until(sim, 120_000, |s| s.report.produced[0] > p0[0] && s.report.produced[1] > p0[1] && s.one_chain_between(0, 1));
        if alive.is_none() {
            reds.push(format!("after the sweep the pair did not both produce on one chain within 120 simulated s (produced {p0:?} → {:?})", sim.report.produced));
        }
        if let Some(d) = sim.state_divergence() {
            reds.push(format!("state divergence after the sweep: {d}"));
        }
        let covered = crate::harness::sim_coverage::finish("route-adversary");
        eprintln!("[route-adversary] {} route(s) · {} hostile call(s) · {} coverage row(s) · {} red", routes.len(), calls, covered, reds.len());
        for r in &reds {
            eprintln!("[route-adversary] RED {r}");
        }
        (reds, calls)
    }

    /// ⭐⭐⭐ B1 (i) — THE PRODUCTION ROUTER UNDER THE ADVERSARIAL ROUTE HARNESS: every node route fails CLOSED to the whole
    /// hostile corpus on a live two-node mesh and the peer holds the same state. MUST STAY GREEN (scratchpad/farm-tests.txt
    /// re-drives it on fresh seeds; `SIM_SEED` seeds the mesh).
    #[test]
    fn sim_every_node_route_fails_closed_under_hostile_input_and_the_peer_holds_the_same_state() {
        let seed = journey::seed(0x7131_00B1_2026_1022);
        let mut sim = sweep_mesh(seed);
        let real: Dispatch = Arc::new(|rt, m, p, b| crate::rpc_http::route(rt, m, p, b));
        let (reds, calls) = adversarial_route_sweep(&mut sim, seed, real);
        assert!(calls > 5_000, "CALIBRATION: only {calls} hostile calls — the corpus shrank");
        assert!(reds.is_empty(), "⛔ {} route(s) failed OPEN under hostile input on a live simulated node:\n{}", reds.len(), reds.join("\n"));
    }

    /// REFUTATION BEFORE GREEN (AGENTS.md §2 SOUND): the harness catches each planted defect class and names it — a
    /// PANIC on an oversized body, a 500 on a malformed one, a lock-free HANG, a route whose hostile request MUTATES THE
    /// PEER (stages a credit on node 1 — a local mutation no chain object carries, the 2026-09-03 class), and, on a second
    /// mesh, a LOCK-HOLDING hang (the sweep must name the held lock and continue on a fresh mesh). Every other route is
    /// answered `200 {}` by the planted dispatcher so the refutation costs seconds, not the real corpus.
    #[test]
    fn sim_the_adversarial_route_harness_catches_a_planted_panic_500_hang_peer_mutation_and_held_lock() {
        let seed = journey::seed(0x7131_00B2_2026_1022);
        let eco = crate::harness::surface_census::ecosystem();
        let routes = crate::harness::surface_census::routes(&eco);
        // the sweep runs in reverse, so the LAST routes of the universe are driven first
        let pick = |i: usize| routes[routes.len() - 1 - i].1.trim_end_matches('*').to_string();
        let (panics, fives, hangs, mutates) = (pick(0), pick(1), pick(2), pick(3));
        let mut sim = sweep_mesh(seed);
        let peer = sim.rts[1].clone();
        let planted: Dispatch = {
            let (a, b, c, d) = (panics.clone(), fives.clone(), hangs.clone(), mutates.clone());
            Arc::new(move |_rt, m, p, body| {
                if p == a && body.len() > 1 << 20 {
                    panic!("planted: an oversized body");
                }
                if p == b && body == "{" {
                    return (500, "planted: unhandled parse".to_string());
                }
                if p == c && m == "PUT" {
                    std::thread::sleep(std::time::Duration::from_secs(12));
                }
                if p == d && body == "null" {
                    let (note, _) = Node::test_spendable_note(77_707);
                    peer.lock().unwrap_or_else(std::sync::PoisonError::into_inner).node_mut().stage_credit_note(note);
                }
                (200, "{}".to_string())
            })
        };
        let (reds, _) = adversarial_route_sweep(&mut sim, seed, planted);
        let caught = |what: &str, route: &str| reds.iter().any(|r| r.contains(what) && r.contains(route));
        assert!(caught("PANICKED", &panics), "the planted panic on {panics} was not caught: {reds:?}");
        assert!(caught("answered 500", &fives), "the planted 500 on {fives} was not caught: {reds:?}");
        assert!(caught("no answer within 10 s — on-demand work", &hangs), "the planted lock-free hang on {hangs} was not caught: {reds:?}");
        assert!(caught("THE PEER CHANGED", ""), "the planted peer mutation on {mutates} was not caught: {reds:?}");
        // phase 2: a LOCK-HOLDING hang on a fresh mesh — the sweep names the held lock and finishes on a fresh mesh
        let mut sim2 = sweep_mesh(seed + 1_000);
        let held = {
            let c = hangs.clone();
            let d: Dispatch = Arc::new(move |rt, m, p, _body| {
                if p == c && m == "PUT" {
                    let _hold = rt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    std::thread::sleep(std::time::Duration::from_secs(30));
                }
                (200, "{}".to_string())
            });
            d
        };
        let (reds2, _) = adversarial_route_sweep(&mut sim2, seed + 1_000, held);
        assert!(
            reds2.iter().any(|r| r.contains("HOLDS THE NODE'S LOCK") && r.contains(&hangs)),
            "the planted lock-holding hang on {hangs} was not named: {reds2:?}"
        );
        assert_eq!(reds2.len(), 1, "only the planted hang is red on the fresh mesh: {reds2:?}");
    }

    /// ⭐⭐⭐ THE REAL JOURNEY IN THREE LEGS (readiness T1's real lane; the live-run guard's pass file) — the live gate's
    /// steps on three nodes at the relay floor with the REAL band prover charged at its own wall cost
    /// (`budget_clock::OffLockJob::spawn_on_cores`, link 84: charged, never paced), every restart the production restart
    /// (shutdown save → down → `Node::boot` from the same files), every verdict read from what each NODE holds or from the
    /// production `get_info`, every step driven by the SHIPPED wallet over the production RPC.
    /// WHY LEGS (lane b, 2026-10-23): ONE process never finished — MEASURED (scratchpad/night/sim-20261023-004016.log):
    /// T1.0–T1.7 PASS at wall 530 s, T2 PASS at wall 1,034 s (jobwait 957 s of it: the band proves at its real speed), T3
    /// cut by the 2,700 s wall budget (exit 142, :27361) — no `[sim-journey-row]` line, so every ledger read NO-VERDICT, and
    /// the farm's 45-minute cap would have cut it the same way. So the run is PARKED between tiers exactly as the launch
    /// journey is ([`NetSim::park`] / [`NetSim::resume_from_disk`]: every node's shutdown snapshot under
    /// `$TMPDIR/netsim-real-<seed>`, the run's own state in `real-state.json`, the two REAL wallets' datadirs moved in beside
    /// the nodes') and RESUMED by the next process — one production restart of every node at each boundary, with both
    /// wallets reopened on the resumed nodes ([`RealWallet::reopened`]), which is what the journey is about. The legs:
    /// 1 tier 1 (T1.0–T1.7) · 2 tier 2 (the DEX) · 3 tier 3 and THE VERDICT. EVERY leg prints the `[sim-journey-row] real`
    /// lines every ledger reads (readiness T1, the live-run pass file): the steps it and the earlier legs judged, and the
    /// later legs' tiers as NOT-RUN naming the leg that runs them — so the ledgers read the newest truth after every leg,
    /// a red in any leg is reported, never silence, and only the final leg can print ten PASS rows (the pass file's rule).
    /// MEASURED on this split (scratchpad/night/sim-20261023-015200.log): leg 1 GREEN at wall 614 s (:6095), leg 2 GREEN at
    /// wall 960 s (:15366) with both wallets reopened on the resumed nodes; leg 3 ran 910 simulated s (the 240-block journey
    /// stake lock's maturity is most of it) and was cut by the 2,700 s budget at tier 3's LAST wait (the merchant reading
    /// the POS tap, :16019 → :35665) — tier 3 is chunked next (bond → maturity → unbond · identity + letter + POS). `scratchpad/sim.sh real` runs the three
    /// in order; farm-tests.txt runs them as one `;` group per seed (`SIM_SEED` seeds every leg alike).
    /// TWO-PARTY-REVIEWED: three independent `Node`s over the simulated wire, each booted from its own datadir; every step's
    /// verdict is what the OTHER node's wallet or node read.
    const REAL_LEGS: u64 = 6;
    /// Leg 5 is the maturity wait: it may run several SLICES (each parks when its sim budget is spent) until the bond matures.
    const REAL_LEG_WAIT: u64 = 5;
    const REAL_STATE_FILE: &str = "real-state.json";
    const REAL_SEED_DEFAULT: u64 = 0x7131_0001_2026_1006;

    /// The parked real mesh of `seed`: `$TMPDIR/netsim-real-<seed>` (scratchpad/prune_dead_netsim_dirs.sh removes one older than 4 h).
    fn real_parked_dir(seed: u64) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("netsim-real-{seed:x}"))
    }

    /// The real mesh every leg builds alike: three testnet daemons, the REAL band prover charged, the journey's stake lock,
    /// the state invariant every 10 simulated seconds. Leg 1 boots it fresh; legs 2–6 resume it from the park.
    fn real_mesh(seed: u64) -> NetSim {
        let mut sim = NetSim::testnet(3, Physics::from_env(), seed).with_journey_stake_lock().with_real_ledger();
        // CHARGED, NEVER PACED (link 84): every real band step is a parallel off-lock job taken at spawn + the wall it held
        // the cores alone (`budget_clock::OffLockJob::spawn_on_cores`), so the clock runs free and the band still proves at
        // its real speed relative to the chain. MEASURED why (night/link83-real.txt): paced to wall (the 10/06 fix for a
        // free clock that let the band prove ~2 steps in 180 simulated s), the step loop used 15–17 % of the wall and T3 was
        // cut by the 2,700 s cap.
        sim.charge_cpu = true;
        sim.check_state = true;
        sim
    }

    /// The run's state between legs: everything the verdict needs that the datadirs do not hold.
    #[derive(Default, serde::Serialize, serde::Deserialize)]
    struct RealState {
        seed: u64,
        legs_done: u64,
        /// A journey stop in an earlier leg — the final leg reports it as the real lane's red.
        red: Option<String>,
        now_ms: u64,
        restarts: u64,
        down_until: Vec<u64>,
        /// Every journey step's verdict so far (id, PASS|FAIL, detail).
        steps: Vec<(String, String, String)>,
        /// Each leg's wall seconds.
        wall_s: Vec<f64>,
        /// The two real wallets' own addresses (their datadirs are `wallet-w1` / `wallet-w2` under the park).
        w1_address: String,
        w2_address: String,
        /// Tier 2's carried state (legs 2–3), tier 3's (legs 4–6) and how many maturity slices leg 5 has run.
        #[serde(default)]
        t2: Option<T2Carry>,
        #[serde(default)]
        t3: Option<T3Carry>,
        #[serde(default)]
        t3_slices: u64,
    }

    impl RealState {
        fn path(dir: &std::path::Path) -> std::path::PathBuf {
            dir.join(REAL_STATE_FILE)
        }
        fn save(&self, dir: &std::path::Path) -> Result<(), String> {
            let s = serde_json::to_string(self).map_err(|e| format!("real state: {e}"))?;
            std::fs::write(Self::path(dir), s).map_err(|e| format!("real state {}: {e}", Self::path(dir).display()))
        }
        fn load(dir: &std::path::Path) -> Result<RealState, String> {
            let p = Self::path(dir);
            let s = std::fs::read_to_string(&p).map_err(|e| format!("no parked real state at {}: {e}", p.display()))?;
            serde_json::from_str(&s).map_err(|e| format!("real state {}: {e}", p.display()))
        }
        /// The rows a leg records: every step judged so far, then the later legs' tiers as NOT-RUN naming their leg.
        fn rows(&self) -> Vec<(&str, &str, String)> {
            let mut v: Vec<(&str, &str, String)> = self.steps.iter().map(|(a, b, c)| (a.as_str(), b.as_str(), c.clone())).collect();
            if self.legs_done < 3 && !v.iter().any(|(id, _, _)| *id == "T2") {
                let detail = match &self.t2 {
                    None => format!("not yet run: the real journey's legs 2–3 of {REAL_LEGS} run it"),
                    Some(t2) => format!("in flight: the maker's side done ({} order(s) on node 1's book); leg 3 of {REAL_LEGS} judges it", t2.on_peer),
                };
                v.push(("T2", "NOT-RUN", detail));
            }
            if self.legs_done < REAL_LEGS && !v.iter().any(|(id, _, _)| *id == "T3") {
                let detail = match &self.t3 {
                    None => format!("not yet run: the real journey's legs 4–{REAL_LEGS} run it"),
                    Some(t3) => format!(
                        "in flight: {} of {REAL_LEGS} legs done, {} maturity slice(s), so far {}; leg {REAL_LEGS} judges it",
                        self.legs_done,
                        self.t3_slices,
                        t3.done.join(" · ")
                    ),
                };
                v.push(("T3", "NOT-RUN", detail));
            }
            v
        }
        /// This leg's step verdicts appended, and its stop (if any) as the run's red.
        fn take_steps(&mut self, v: &[(&'static str, &'static str, String)], go: Option<()>) {
            self.steps.extend(v.iter().map(|(a, b, c)| ((*a).to_string(), (*b).to_string(), c.clone())));
            if go.is_none() && self.red.is_none() {
                self.red = Some(format!("the journey stopped at {:?}", v.last().map(|(id, _, d)| (*id, d.clone()))));
            }
        }
    }

    /// A leg's end: the served-vs-folded census, the mesh parked (every up node's production shutdown save), the two real
    /// wallets' datadirs moved in beside the nodes' (leg 1 only — later legs already run them from the park), the state written.
    fn real_park(
        sim: NetSim,
        st: &mut RealState,
        parked: &std::path::Path,
        wallets: Option<(&crate::harness::real_node_journey::wallet::RealWallet, &crate::harness::real_node_journey::wallet::RealWallet)>,
        wall: &std::time::Instant,
    ) {
        served_vs_folded_census(&sim);
        st.now_ms = sim.now;
        st.restarts = sim.restarts;
        let p = sim.park(parked).expect("the real mesh parks");
        st.down_until = p.down_until;
        if let Some((w1, w2)) = wallets {
            for (w, name) in [(w1, "wallet-w1"), (w2, "wallet-w2")] {
                let dest = parked.join(name);
                let _ = std::fs::remove_dir_all(&dest);
                std::fs::rename(w.dir(), &dest).unwrap_or_else(|e| panic!("park {name}: {} → {}: {e}", w.dir().display(), dest.display()));
            }
        }
        st.wall_s.push(wall.elapsed().as_secs_f64());
        st.save(parked).expect("the real state is written");
    }

    /// Leg `k`'s start: the parked mesh resumed (one production restart of every node that was up), nodes 0 and 1 serving
    /// their production RPC again, W1 and W2 reopened on them, the journey's spend budget re-read from the mesh.
    #[allow(clippy::type_complexity)]
    fn real_resume(
        seed: u64,
        k: u64,
        parked: &std::path::Path,
        st: &RealState,
    ) -> (NetSim, crate::harness::real_node_journey::wallet::RealWallet, crate::harness::real_node_journey::wallet::RealWallet, u64) {
        use crate::harness::real_node_journey::wallet::RealWallet;
        let mut fresh = real_mesh(seed);
        fresh.restarts = st.restarts; // the boundary's restarts add to the run's count
        let mut sim = fresh
            .resume_from_disk(parked, st.now_ms, &st.down_until, None, &format!("leg boundary {}", k - 1))
            .expect("the parked real mesh resumes");
        let (url0, url1) = (sim.serve_rpc(0), sim.serve_rpc(1));
        let w1 = RealWallet::reopened(parked.join("wallet-w1"), &url0, st.w1_address.clone());
        let w2 = RealWallet::reopened(parked.join("wallet-w2"), &url1, st.w2_address.clone());
        let within = spendable_within_s(&sim);
        (sim, w1, w2, within)
    }

    /// A leg that cannot run: a missing, out-of-order or red parked state. The final leg still records the run (NOT-RUN
    /// rows) so the ledgers read a verdict, never silence.
    fn real_calibration(last: bool, seed: u64, k: u64, why: &str) -> ! {
        if last {
            journey::record("real", seed, &[]);
        }
        panic!("⛔ the real journey leg {k} of {REAL_LEGS} (seed {seed:#x}): CALIBRATION: {why}");
    }

    /// Leg 1 of 6: tier 1 — T1.0–T1.7 through the shipped wallet on the real band, then the mesh and both wallets parked.
    #[test]
    #[ignore = "the real journey, leg 1 of 6 (tier 1, ~9 min of wall on the real band prover): scratchpad/sim.sh real runs the six legs in order with --include-ignored"]
    fn sim_journey_real_leg_1_of_6_tier_1_the_money_path_survives_a_rolling_restart() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(REAL_SEED_DEFAULT);
        let parked = real_parked_dir(seed);
        let _ = std::fs::remove_dir_all(&parked); // a stale park of this seed is never resumed
        let mut sim = real_mesh(seed).boot_from_disk();
        sim.hold_down(2); // the joiner of T1.6: it does not exist until then
        let mut v = Vec::new();
        crate::harness::sim_coverage::start();
        let pair = fund_pair(&mut sim, &mut v, &wall, "sim");
        let go = pair.as_ref().and_then(|(w1, w2, url0, _url1, within)| tier1_restarts(&mut sim, &mut v, &wall, w1, w2, url0, *within));
        crate::harness::sim_coverage::finish("journey-real");
        eprintln!("[sim-journey] real leg 1 of {REAL_LEGS}: restarts {} · sim {} s · wall {:?} · {}", sim.restarts, sim.now / 1000, wall.elapsed(), speed_line());
        let mut st = RealState { seed, legs_done: 1, ..Default::default() };
        st.take_steps(&v, go);
        if let Some((w1, w2, ..)) = pair.as_ref() {
            st.w1_address = w1.address.clone();
            st.w2_address = w2.address.clone();
        }
        real_park(sim, &mut st, &parked, pair.as_ref().map(|(w1, w2, ..)| (w1, w2)), &wall);
        // an interim leg prints its step rows only; the final leg (which runs after a red one too) writes the seed row once
        journey::record_steps("real", &st.rows());
        assert!(
            st.red.is_none(),
            "⛔ the real journey leg 1 of {REAL_LEGS} (seed {seed:#x}): {} — leg 3 reports it as the real lane's red",
            st.red.as_deref().unwrap_or("")
        );
    }

    /// Legs 2 and 3: resume the parked mesh, reopen the wallets, run this leg's tier — then park again, or, on the final
    /// leg, judge and record the whole run.
    fn real_tier_leg(k: u64) {
        let wall = std::time::Instant::now();
        let seed = journey::seed(REAL_SEED_DEFAULT);
        let parked = real_parked_dir(seed);
        let last = k == REAL_LEGS;
        let mut st = match RealState::load(&parked) {
            Ok(s) if s.seed == seed && (s.legs_done == k - 1 || (k == REAL_LEG_WAIT && s.legs_done == k)) => s,
            Ok(s) => real_calibration(last, seed, k, &format!("the parked state is leg {} of seed {:#x}, not leg {} of this seed", s.legs_done, s.seed, k - 1)),
            Err(e) => real_calibration(last, seed, k, &e),
        };
        // ⛔ the cleanup is armed only once the park is ACCEPTED: a final leg run out of order (the park is an earlier leg's)
        // refuses with a calibration and leaves that resumable park whole. MEASURED 2026-10-23 (lane b): leg 6 run after one
        // leg-5 maturity slice deleted the leg-4 park and cost legs 1–5 (~60 min of wall) to rebuild.
        let mut cleanup = last.then(|| RemoveDirOnDrop(parked.clone()));
        if let (Some(red), false) = (&st.red, last) {
            real_calibration(last, seed, k, &format!("leg {} is red ({red}); the final leg reports it", st.legs_done));
        }
        if k == REAL_LEG_WAIT && st.legs_done == k {
            eprintln!("[sim-journey] real leg {k} of {REAL_LEGS}: the bond matured and released in an earlier slice ({} slice(s)) — nothing to run", st.t3_slices);
            journey::record_steps("real", &st.rows());
            return;
        }
        if st.red.is_none() {
            let (mut sim, w1, w2, within) = real_resume(seed, k, &parked, &st);
            let mut v = Vec::new();
            crate::harness::sim_coverage::start();
            let mut t2 = st.t2.take().unwrap_or_default();
            let mut t3 = st.t3.take().unwrap_or_default();
            let mut parked_wait = false;
            let go = match k {
                2 => tier2_make(&mut sim, &mut v, &wall, &w1, &w2, within, &mut t2),
                3 => tier2_take(&mut sim, &mut v, &wall, &w1, &w2, within, &t2),
                4 => tier3_bond(&mut sim, &mut v, &wall, &w1, within, &mut t3),
                REAL_LEG_WAIT => match tier3_mature_and_unbond(&mut sim, &mut v, &wall, &w1, within, &mut t3, Some(real_wait_slice_s())) {
                    T3Wait::Done => Some(()),
                    T3Wait::Parked => {
                        parked_wait = true;
                        Some(())
                    }
                    T3Wait::Failed => None,
                },
                _ => tier3_identity(&mut sim, &mut v, &wall, &w1, &w2, within, &mut t3),
            };
            if k <= 3 {
                st.t2 = Some(t2);
            } else {
                st.t3 = Some(t3);
            }
            crate::harness::sim_coverage::finish("journey-real");
            eprintln!("[sim-journey] real leg {k} of {REAL_LEGS}: restarts {} · sim {} s · wall {:?} · {}", sim.restarts, sim.now / 1000, wall.elapsed(), speed_line());
            st.take_steps(&v, go);
            if k == REAL_LEG_WAIT {
                st.t3_slices += 1;
            }
            if !parked_wait {
                st.legs_done = k;
            }
            if !last {
                real_park(sim, &mut st, &parked, None, &wall);
                journey::record_steps("real", &st.rows());
                return;
            }
            served_vs_folded_census(&sim);
            st.now_ms = sim.now;
            st.restarts = sim.restarts;
            st.wall_s.push(wall.elapsed().as_secs_f64());
            // SPEED (user 2026-10-06): the census needs a QUIET mesh, and after a red step the mesh is mid-step — MEASURED
            // sim-20261006-212115: "quiet false after 600 s · DIFFERS 0 · NOT-QUIET 162", ~180 s of wall that judged
            // nothing. It runs when the journey passed; its own pin (`replica_census_every_replicated_field_agrees`, 9 s)
            // measures every run either way.
            if go.is_some() {
                sim.replica_census("real"); // DB-402 R1 run point (b): rows only — the journey's verdicts are its own
            } else {
                eprintln!("[replica-census] real: not run — the journey stopped at a red step, so the mesh cannot be quiet; the census pin measures it");
            }
        }
        // THE VERDICT: every leg's step verdicts recorded for the ledgers, and the one assertion the whole run must pass.
        let v = st.rows();
        journey::record("real", seed, &v);
        eprintln!(
            "[sim-journey] real: {} leg(s) · restarts {} · sim {} s · legs wall {:?} s · seed {seed:#x}",
            st.legs_done,
            st.restarts,
            st.now_ms / 1000,
            st.wall_s.iter().map(|w| w.round()).collect::<Vec<_>>()
        );
        // A RED run's park is its evidence (each wallet's wallet-stderr.log, the datadirs): kept, named, and pruned by
        // scratchpad/prune_dead_netsim_dirs.sh after 240 min — the green run's park is removed as before.
        if st.red.is_some() {
            if let Some(c) = cleanup.take() {
                std::mem::forget(c);
                eprintln!("[sim-journey] real: RED — the park is KEPT for attribution at {}", parked.display());
            }
        }
        assert!(st.red.is_none(), "⛔ the simulated real journey ({} leg(s), seed {seed:#x}) stopped: {}", st.legs_done, st.red.as_deref().unwrap_or(""));
    }

    /// Leg 2 of 6: tier 2's maker — W1 creates, cuts and rests through node 0, node 1's book shows the rung — then parked.
    #[test]
    #[ignore = "the real journey, leg 2 of 6 (tier 2, the maker's half; the real band prover): needs leg 1's park; scratchpad/sim.sh real runs the six legs in order"]
    fn sim_journey_real_leg_2_of_6_tier_2_the_maker_creates_cuts_and_rests_a_rung_the_other_node_shows() {
        real_tier_leg(2);
    }

    /// Leg 3 of 6: tier 2's taker — W2 fills the rung through node 1 and the fill settles in its wallet; T2's verdict — then parked.
    #[test]
    #[ignore = "the real journey, leg 3 of 6 (tier 2, the taker's half; the real band prover): needs leg 2's park; scratchpad/sim.sh real runs the six legs in order"]
    fn sim_journey_real_leg_3_of_6_tier_2_the_taker_fills_through_the_other_node_and_the_fill_settles() {
        real_tier_leg(3);
    }

    /// Leg 4 of 6: tier 3's bond — W1 bonds the SAT its node mined, every up node holds the weight, an early unbond is
    /// refused — then parked. MEASURED why tier 3 is three legs (sim-20261023-015200.log): as one leg it ran 910 sim s in
    /// 2,700 wall s and was cut before its verdict; ~65 % of that is the 240-block stake lock.
    #[test]
    #[ignore = "the real journey, leg 4 of 6 (tier 3's bond; the real band prover): needs leg 3's park; scratchpad/sim.sh real runs the six legs in order"]
    fn sim_journey_real_leg_4_of_6_tier_3_the_bond_held_everywhere_and_the_early_unbond_refused() {
        real_tier_leg(4);
    }

    /// Leg 5 of 6: the maturity wait in SLICES of `SIM_REAL_SLICE_S` simulated seconds (each parks when spent; run it again
    /// until the bond matures — a slice after the release runs nothing), then the unbond and its release on every up node.
    #[test]
    #[ignore = "the real journey, leg 5 of 6 (tier 3's maturity wait, sliced; the real band prover): needs leg 4's park; scratchpad/sim.sh real runs it until the bond matures"]
    fn sim_journey_real_leg_5_of_6_tier_3_the_maturity_wait_sliced_then_the_unbond_released_everywhere() {
        real_tier_leg(REAL_LEG_WAIT);
    }

    /// Leg 6 of 6 — THE VERDICT: username, profile, letter and the POS tap across the two nodes, then every leg's step
    /// recorded as the real lane (`[sim-journey-row] real`, what readiness T1 and the live-run guard read).
    #[test]
    #[ignore = "the real journey, leg 6 of 6, the verdict (tier 3's identity steps and the POS tap; the real band prover): needs leg 5's park; scratchpad/sim.sh real runs the six legs in order"]
    fn sim_journey_real_leg_6_of_6_tier_3_identity_letter_pos_and_the_verdict() {
        real_tier_leg(REAL_LEGS);
    }

    /// ⭐ THE STAKE LOCK AT TEN NODES (readiness T3's one scripted red on 2026-10-22): tier 1 of the launch journey — the same
    /// mesh, doubles, charged CPU and seed as [`sim_launch_journey_fast_10_nodes_2_sim_hours`], without its 2 h tail or
    /// per-step censuses (their own pins measure them) — judged to T3's verdict in ~6 min of wall (T3 at sim t=1290 s,
    /// wall 333 s, f1-launch6-20261022-1740.log). RED-first: with the lock at FOUR fold depths (128) the fold cursor ran 114
    /// blocks behind the tip and T3 read "CALIBRATION: the bond was already mature when every node first held it (tip 1550,
    /// matures 1546)"; with [`journey_stake_lock_blocks`] (800 at 10 nodes) the early unbond is refused and the matured one
    /// releases the weight on every up node. Not a `sim_launch_journey_*` name: it is one tier, never the launch verdict.
    #[test]
    fn sim_tier1_at_10_nodes_the_stake_lock_outlives_the_fold_lag() {
        const NODES: usize = 10;
        let wall = std::time::Instant::now();
        let seed = journey::seed(0x7131_00F3_2026_1022);
        let mut sim = NetSim::testnet(NODES, Physics::from_env(), seed)
            .with_band_double()
            .with_template_double()
            .with_journey_stake_lock()
            .boot_from_disk();
        sim.hold_down(2); // the joiner of T1.6: it does not exist until then
        sim.charge_cpu = true;
        sim.check_state = true;
        let lock = sim.params.stake_lock_blocks;
        assert_eq!(lock, journey_stake_lock_blocks(NODES), "the booted mesh runs the derived lock");
        let mut v = Vec::new();
        let go = tier1(&mut sim, &mut v, &wall);
        eprintln!("[sim-tier1@10] lock {lock} blocks · restarts {} · sim {} s · wall {:?} · {}", sim.restarts, sim.now / 1000, wall.elapsed(), speed_line());
        for (id, verdict, detail) in &v {
            eprintln!("[sim-tier1@10] {id} {verdict} — {}", detail.chars().take(200).collect::<String>());
        }
        assert!(go.is_some(), "⛔ tier 1 at {NODES} nodes stopped at {:?}", v.last().map(|(id, _, d)| (*id, d.chars().take(400).collect::<String>())));
    }

    /// ⭐⭐⭐ F3 — THE LAUNCH JOURNEY IN FIVE LEGS (readiness T3; user 2026-10-22: "if our netsim was doing its job, passing
    /// there should mean passing for launch"). The FULL journey — every [`journey::FULL_JOURNEY`] step, driven by the shipped
    /// wallet over the production RPC, the fast doubles — on a TEN-node mesh, run on to ≥ 2 simulated hours, with THE
    /// CENSUSES ASSERTED AT EVERY STEP (`NetSim::step_census`): the replicated-state census after every step's pass and the
    /// restart census at every production restart (T1.3 ×2, T1.7, and every node at every leg boundary), the state
    /// invariant every 10 simulated seconds (`check_state`); and over the long tail after the journey: NO HALT (the mesh's
    /// tip advances in every 10-minute window), ONE CHAIN (every up pair at every hour mark) and NO GROWTH on two scales
    /// (each node's datadir bytes OUTSIDE the bounded block window at the 1 h and 2 h marks — P14's 2× rule; the process
    /// footprint is reported, not judged: the scaffold's own per-block maps grow with the run). `SIM_SEED` seeds it
    /// (`journey::seed`), so the zero-token farm runs it on fresh seeds (scratchpad/farm-tests.txt). A census red is
    /// reported PER FIELD at the end and fails the verdict — never skipped, never narrowed — so the verdict is RED exactly
    /// while the replica and restart censuses are, and green only when every census held at every step.
    /// WHY LEGS (lane b, 2026-10-22): ONE process never finished — MEASURED on the farm (scratchpad/farm/queue-20261022-192013-21963.log,
    /// ef1004f): T1.0–T3 PASS at wall 718 s, `[launch-row] hour 1` at wall 1,449 s (the tail runs ≈ 2.0× at 10 nodes), killed
    /// at the 45-min watchdog with no `test result` line, three runs the same — T3 had never produced a verdict, and rule 5a
    /// wants ≤ 20 min per job. So the run is PARKED between legs ([`NetSim::park`]: every node's shutdown snapshot, the
    /// datadirs under `$TMPDIR/netsim-launch-<seed>`, the run's own state in `launch-state.json`) and RESUMED by the next
    /// process ([`NetSim::resume_from_disk`]): one production restart of every node at each boundary, censused like any
    /// other, so chunking ADDS four whole-mesh restart censuses and removes nothing. The legs: 1 the journey · 2 the tail to
    /// 3,600 sim s · 3 to 4,800 · 4 to 6,000 · 5 to 7,200 and THE VERDICT. Legs 1–4 fail only on a journey stop or a
    /// calibration (a missing or out-of-order parked state); every census red and tail red rides the state and the FINAL
    /// leg reports them all — it alone carries the `sim_launch_journey` name readiness.py reads. The farm runs the five as
    /// one `;` group on one seed (cpu_farm.sh); a lane runs them one lane_run each (scratchpad/verify/launch_leg_run.sh).
    /// v2 (2026-10-24): every full tail window opens with a restart, a minority partition or (hourly) a reinstall
    /// ([`launch_tail_event`]), and every hour mark takes the replicated-state census. LATER VERSIONS (the T3 text) add the
    /// H10 network adversaries, rogue producers, the economic attacks and the 24 simulated hours.
    /// TWO-PARTY-REVIEWED: ten independent `Node`s over the simulated wire, each booted from its own datadir; every step's
    /// verdict is what the PEER's wallet or node read, and every census compares what each node HOLDS.
    const LAUNCH_NODES: usize = 10;
    const LAUNCH_SIM_HOURS: u64 = 2;
    const LAUNCH_WINDOW_MS: u64 = 600_000;
    const LAUNCH_SEED_DEFAULT: u64 = 0x7131_00F3_2026_1022;
    /// Where legs 2..=5 run the tail to (simulated ms); the last is the run's end.
    const LAUNCH_LEG_ENDS_MS: [u64; 4] = [3_600_000, 4_800_000, 6_000_000, 7_200_000];
    const LAUNCH_LEGS: u64 = 1 + LAUNCH_LEG_ENDS_MS.len() as u64;
    const LAUNCH_STATE_FILE: &str = "launch-state.json";

    /// The launch mesh every leg builds alike: ten testnet daemons, the fast doubles, the derived stake lock, charged CPU,
    /// the state invariant and the censuses at every step. Leg 1 boots it fresh; the tail legs resume it from the park.
    fn launch_mesh(seed: u64) -> NetSim {
        launch_mesh_of(LAUNCH_NODES, seed)
    }

    /// The launch mesh at `n` nodes (the §SIMMEM pin measures it at two scales).
    fn launch_mesh_of(n: usize, seed: u64) -> NetSim {
        let mut sim = NetSim::testnet(n, Physics::from_env(), seed).with_band_double().with_template_double().with_journey_stake_lock();
        sim.charge_cpu = true;
        sim.check_state = true;
        sim.step_census = true;
        sim
    }

    /// §SIMMEM — the launch mesh's physical footprint at 3 and at 10 nodes on one fixed schedule (boot, then
    /// `SIMMEM_RUN_S` simulated seconds, default 240), sampled every 20 sim s; prints `[simmem-row] n \t phase \t MB` and
    /// each node's RAM census summed by structure, so MB/node and the per-node terms are numbers (AGENTS §5, two scales).
    /// THE GATE (chain-tracks §SIMMEM): 10 nodes ≤ 4,096 MB peak and a 3 → 10 slope ≤ 300 MB/node. The 3-node mesh is
    /// dropped before the 10-node one boots, so the 10-node peak can only over-count (pages it reuses were the 3-node's).
    /// TWO-PARTY-REVIEWED: the measured quantity is the test process's footprint; the parties are the 3 and 10 independent
    /// `Node`s of the launch mesh, each booted from its own datadir and meshed over the simulated wire.
    #[test]
    #[ignore = "§SIMMEM gate (~4 min of wall, ~4 GB): run by name with --include-ignored; farm-tests.txt runs it"]
    fn simmem_the_launch_mesh_fits_4_gb_at_10_nodes_with_a_flat_per_node_slope() {
        let run_s: u64 = std::env::var("SIMMEM_RUN_S").ok().and_then(|s| s.parse().ok()).unwrap_or(240);
        let seed = journey::seed(0x7131_5133_2026_1023);
        let fp = || phys_footprint_mb().unwrap_or(0);
        let mut peaks = Vec::new();
        for n in [3usize, 10] {
            let f0 = fp();
            let sim = launch_mesh_of(n, seed);
            let f_new = fp();
            let mut sim = sim.boot_from_disk();
            let f_boot = fp();
            let mut peak = f_boot;
            for _ in 0..run_s / 20 {
                sim.run(20_000, 10_000);
                peak = peak.max(fp());
            }
            let mut by: std::collections::BTreeMap<&'static str, (usize, usize)> = std::collections::BTreeMap::new();
            for i in 0..n {
                for (name, c, b) in sim.rt(i).node().ram_census_named() {
                    let e = by.entry(name).or_default();
                    e.0 += c;
                    e.1 += b;
                }
            }
            let mut terms: Vec<_> = by.into_iter().collect();
            terms.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
            let census_mb: f64 = terms.iter().map(|t| t.1 .1 as f64).sum::<f64>() / 1_048_576.0;
            let tips: Vec<u64> = (0..n).map(|i| sim.rt(i).node().tip_height()).collect();
            eprintln!("[simmem-row] {n}\tbefore\t{f0}\n[simmem-row] {n}\tnew\t{f_new}\n[simmem-row] {n}\tboot\t{f_boot}\n[simmem-row] {n}\tpeak\t{peak}");
            eprintln!(
                "[simmem] n={n} tips {tips:?} · census {census_mb:.1} MB over all nodes · per node new {:.0} boot {:.0} peak {:.0} MB",
                f_new.saturating_sub(f0) as f64 / n as f64,
                f_boot.saturating_sub(f0) as f64 / n as f64,
                peak.saturating_sub(f0) as f64 / n as f64
            );
            for (name, (c, b)) in terms.iter().take(12) {
                eprintln!("[simmem-term] {n}\t{name}\t{c}\t{:.1} MB", *b as f64 / 1_048_576.0);
            }
            // the unfolded blocks by component (the largest term at 10 nodes, run m1: 1,777 MB of 2,583 blocks)
            let mut parts = [0usize; 11];
            let mut txs = 0usize;
            for i in 0..n {
                for b in sim.rt(i).node().unfolded_blocks_for_test() {
                    txs += b.tx_ids.len();
                    parts[0] += b.pow_proof.len();
                    parts[1] += b.note_transition.as_ref().map_or(0, |t| t.agg.len() + t.tuples.len());
                    parts[2] += b.cover_transition.as_ref().map_or(0, |t| t.agg.len() + t.tags.len());
                    parts[3] += b.member_transition.iter().map(|t| t.agg.len() + t.tuples.len()).sum::<usize>();
                    parts[4] += b.nullifier_proof.carrier.len() + b.nullifier_proof.padded_tags.len() * 32;
                    parts[5] += b.output_notes.len() + b.oli_tags.len() + b.account_targets.len();
                    parts[6] += b.bond_set.len();
                    parts[8] += b.credit_set.len();
                    parts[9] += b.dir_set.len();
                    parts[10] += b.letter_set.len();
                    parts[7] += b.header.parents.len() * 32 + b.tx_ids.len() * 32;
                }
            }
            let names = ["pow_proof", "note_transition", "cover_transition", "member_transition", "nullifier_proof", "notes+tags+targets", "bond_set", "parents+tx_ids", "credit_set", "dir_set", "letter_set"];
            for (k, b) in names.iter().zip(parts) {
                eprintln!("[simmem-unfolded] {n}\t{k}\t{:.1} MB", b as f64 / 1_048_576.0);
            }
            eprintln!("[simmem-unfolded] {n}\ttx_ids\t{txs}");
            // DUPLICATION across one node's unfolded blocks: each carried entry (u32-length-prefixed) and tx id, total vs distinct
            let split = |bytes: &[u8]| {
                let (mut v, mut at) = (Vec::new(), 0usize);
                while at + 4 <= bytes.len() {
                    let len = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes")) as usize;
                    let Some(e) = bytes.get(at + 4..at + 4 + len) else { break };
                    v.push(*blake3::hash(e).as_bytes());
                    at += 4 + len;
                }
                v
            };
            for i in 0..n.min(2) {
                let blocks = sim.rt(i).node().unfolded_blocks_for_test().to_vec();
                let mut ids = std::collections::HashSet::new();
                let (mut bond, mut credit) = (std::collections::HashSet::new(), std::collections::HashSet::new());
                let (mut ti, mut tb, mut tc, mut bb, mut cb) = (0usize, 0usize, 0usize, 0usize, 0usize);
                for b in &blocks {
                    ti += b.tx_ids.len();
                    ids.extend(b.tx_ids.iter().copied());
                    let (be, ce) = (split(&b.bond_set), split(&b.credit_set));
                    tb += be.len();
                    tc += ce.len();
                    bb += b.bond_set.len();
                    cb += b.credit_set.len();
                    bond.extend(be);
                    credit.extend(ce);
                }
                eprintln!(
                    "[simmem-dup] {n}\tnode {i}\tblocks {}\ttx_ids {ti} distinct {}\tbond entries {tb} distinct {} ({:.1} MB)\tcredit entries {tc} distinct {} ({:.1} MB)",
                    blocks.len(), ids.len(), bond.len(), bb as f64 / 1_048_576.0, credit.len(), cb as f64 / 1_048_576.0
                );
            }
            for (k, (c, b)) in ["cells", "answers", "asks", "follows"].iter().zip(sim.wire.queued_parts()) {
                eprintln!("[simmem-wire] {n}\t{k}\t{c}\t{:.1} MB", b as f64 / 1_048_576.0);
            }
            sim.mem_line(&format!("simmem n={n}"));
            drop(sim);
            peaks.push((n, peak));
        }
        let (p3, p10) = (peaks[0].1, peaks[1].1);
        let slope = p10.saturating_sub(p3) as f64 / 7.0;
        eprintln!("[simmem] peak 3 nodes {p3} MB · 10 nodes {p10} MB · slope {slope:.0} MB/node");
        assert!(p10 <= 4096, "⛔ §SIMMEM: the 10-node launch mesh peaked at {p10} MB > 4,096 MB");
        assert!(slope <= 300.0, "⛔ §SIMMEM: {slope:.0} MB per node from 3 → 10 nodes > 300 MB/node");
    }

    /// §SIMMEM step 2 (G13) — A CARRIED BOND-LANE OBJECT IS NOT RE-CARRIED BY THE MESH. Each pooled object (finality vote,
    /// membership seat, unbond, bond) can be laid by at most the `n` producers that pooled it before they saw one another's
    /// block; once a node grafts a block carrying it, the object leaves that node's pool for good unless the block is ORPHANED
    /// (outside the tip's past). MEASURED before the fix (simmem-diag1, 10 nodes, 60 sim s): 159 lays of an object a held
    /// block already carried, each re-admitted after it had left the pool — `settle_or_return_evicted_txs` called every
    /// merged SIDE block orphaned (its test walked the selected-parent chain only) and returned its objects unconditionally;
    /// 18,326 bond entries over 905 distinct objects at 240 s. Asserted as Bitcoin's mempool invariant (`removeForBlock`):
    /// sampled every 20 sim s on every node, no pooled tx is a bond-lane entry of a held block in that node's tip past.
    /// TWO-PARTY-REVIEWED: every node of the mesh is a party; the assertion reads each node's own held blocks.
    #[test]
    fn simmem_a_pool_never_holds_a_bond_lane_object_its_tip_already_carries() {
        let n = 3usize;
        let mut sim = launch_mesh_of(n, journey::seed(0x7131_5133_2026_1023)).boot_from_disk();
        let (mut judged, mut bad) = (0usize, Vec::new());
        for step in 0..12u64 {
            sim.run(20_000, 10_000);
            for i in 0..n {
                let rt = sim.rt(i);
                let node = rt.node();
                let Some(tip) = node.selected_tip() else { continue };
                let mut past: std::collections::HashSet<_> = node.dag().past_of(&tip).into_iter().collect();
                past.insert(tip);
                for b in node.unfolded_blocks_for_test() {
                    if !past.contains(&b.id()) {
                        continue;
                    }
                    for tx in crate::node::Node::bond_set_entries(&b.bond_set).0.into_iter().flatten() {
                        judged += 1;
                        if node.mempool().contains(&tx.id) {
                            bad.push((step, i));
                        }
                    }
                }
            }
        }
        eprintln!("[g13] {judged} carried bond-lane object(s) judged in tip pasts over 240 sim s; {} still pooled: {bad:?}", bad.len());
        assert!(judged > 0, "the mesh carried no bond-lane object in any tip's past — the pin judges nothing");
        assert!(bad.is_empty(), "⛔ G13: {} time(s) a node's pool held a bond-lane object a block in its own tip's past already carries — re-laid next template", bad.len());
    }

    /// The parked launch mesh of `seed`: `$TMPDIR/netsim-launch-<seed>` (scratchpad/prune_dead_netsim_dirs.sh removes one older than 4 h).
    fn launch_parked_dir(seed: u64) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("netsim-launch-{seed:x}"))
    }

    /// The run's state between legs: everything the final verdict needs that the datadirs do not hold.
    #[derive(Default, serde::Serialize, serde::Deserialize)]
    struct LaunchState {
        seed: u64,
        legs_done: u64,
        /// A journey stop in leg 1 — the final leg reports it as T3's red.
        red: Option<String>,
        now_ms: u64,
        journey_end_ms: u64,
        restarts: u64,
        census_rows: u64,
        /// (step, census, field, detail) — `NetSim::census_reds` across the legs.
        census_reds: Vec<(String, String, String, String)>,
        tail_reds: Vec<String>,
        /// The tail's perturbations in order ("restart n4 @1800 s", "partition [5, 6, 7] 120 s @2400 s", "reinstall n9 @3000 s").
        #[serde(default)]
        tail_events: Vec<String>,
        /// (hour, tip, outside-window bytes per node) at each hour mark.
        hours: Vec<(u64, u64, Vec<u64>)>,
        last_tip: u64,
        last_hour: u64,
        down_until: Vec<u64>,
        /// Each node's restart-census snapshot at the park (`None`: the node was down then).
        before: Vec<Option<Vec<(String, Option<(u64, usize)>)>>>,
        /// Every journey step's verdict (id, PASS|FAIL, detail).
        steps: Vec<(String, String, String)>,
        /// Each leg's wall seconds.
        wall_s: Vec<f64>,
    }

    impl LaunchState {
        fn path(dir: &std::path::Path) -> std::path::PathBuf {
            dir.join(LAUNCH_STATE_FILE)
        }
        fn save(&self, dir: &std::path::Path) -> Result<(), String> {
            let s = serde_json::to_string(self).map_err(|e| format!("launch state: {e}"))?;
            std::fs::write(Self::path(dir), s).map_err(|e| format!("launch state {}: {e}", Self::path(dir).display()))
        }
        fn load(dir: &std::path::Path) -> Result<LaunchState, String> {
            let p = Self::path(dir);
            let s = std::fs::read_to_string(&p).map_err(|e| format!("no parked launch state at {}: {e}", p.display()))?;
            serde_json::from_str(&s).map_err(|e| format!("launch state {}: {e}", p.display()))
        }
        /// The simulation's counters and census reds into the state (after a leg's run).
        fn take_from(&mut self, sim: &NetSim) {
            self.now_ms = sim.now;
            self.restarts = sim.restarts;
            self.census_rows = sim.census_rows;
            self.census_reds = sim.census_reds.iter().map(|(s, c, f, d)| (s.clone(), (*c).to_string(), f.clone(), d.clone())).collect();
        }
        /// The carried counters and census reds into a fresh mesh (BEFORE its resume, whose boundary census appends to them).
        fn give_to(&self, sim: &mut NetSim) {
            sim.restarts = self.restarts;
            sim.census_rows = self.census_rows;
            sim.census_reds = self
                .census_reds
                .iter()
                .map(|(s, c, f, d)| {
                    let c: &'static str = match c.as_str() {
                        "replica" => "replica",
                        "restart" => "restart",
                        _ => "census",
                    };
                    (s.clone(), c, f.clone(), d.clone())
                })
                .collect();
        }
    }

    /// Removes a directory when dropped — a panic in the final leg (or the pin) still cleans the parked mesh.
    struct RemoveDirOnDrop(std::path::PathBuf);
    impl Drop for RemoveDirOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn launch_up(s: &NetSim) -> Vec<usize> {
        (0..s.rts.len()).filter(|&i| !s.is_down(i)).collect()
    }
    fn launch_tip(s: &NetSim) -> u64 {
        launch_up(s).iter().map(|&i| s.rt(i).node().tip_height()).max().unwrap_or(0)
    }

    /// THE LONG TAIL from `sim.now` to `until_ms` in windows aligned to the 10-minute marks: every window of ≥ 120 sim s is
    /// judged for progress (NO-PROGRESS: no up node's tip advanced), every hour mark for ONE CHAIN over every up pair and
    /// for each node's datadir bytes outside the bounded block window (the growth check's two scales) and for the replicated-
    /// state census, each hour's row kept. Every full window opens with one perturbation ([`launch_tail_event`]).
    fn launch_tail(sim: &mut NetSim, st: &mut LaunchState, until_ms: u64, wall: &std::time::Instant) {
        while sim.now < until_ms {
            let t0 = sim.now;
            let win = (LAUNCH_WINDOW_MS - t0 % LAUNCH_WINDOW_MS).min(until_ms - t0);
            let spent = if win == LAUNCH_WINDOW_MS { launch_tail_event(sim, st, t0 / LAUNCH_WINDOW_MS) } else { 0 };
            sim.run(win - spent, 10_000);
            let t = launch_tip(sim);
            if sim.now - t0 >= 120_000 && t <= st.last_tip {
                st.tail_reds.push(format!("NO-PROGRESS: no up node's tip advanced between t={} s and t={} s (tip {t})", t0 / 1000, sim.now / 1000));
            }
            st.last_tip = t;
            let hour = sim.now / 3_600_000;
            if hour > st.last_hour {
                st.last_hour = hour;
                let nodes = launch_up(sim);
                for a in 0..nodes.len() {
                    for b in a + 1..nodes.len() {
                        if !sim.one_chain_between(nodes[a], nodes[b]) {
                            st.tail_reds.push(format!("TWO CHAINS at the {hour} h mark: nodes {} and {} do not share one chain", nodes[a], nodes[b]));
                        }
                    }
                }
                let outside: Vec<u64> = sim
                    .dirs
                    .iter()
                    .map(|d| d.as_deref().map_or(0, |d| datadir_census(d).outside.iter().map(|(_, b)| *b).sum::<u64>()))
                    .collect();
                eprintln!(
                    "[launch-row] hour {hour}\ttip {t}\toutside-window bytes per node {outside:?}\tfootprint {:?} MB\tsim {} s\twall {:?}",
                    phys_footprint_mb(),
                    sim.now / 1000,
                    wall.elapsed()
                );
                st.hours.push((hour, t, outside));
                if sim.step_census {
                    replica_census_at(sim, &format!("tail {hour} h"), &[]);
                }
            }
        }
    }

    /// THE TAIL'S PERTURBATION for window `w` (T3: restarts, partitions, fresh joins through the run), on a schedule drawn
    /// from the seed so each seed hits other nodes; node 0 (the bootstrap origin) is never the subject. `w % 3`: 0 → a
    /// production restart of one node, down 30 s (its restart census runs inside [`NetSim::restart`]); 1 → a minority
    /// partition of n/3 (at least one) nodes for 120 s, then healed (the hour mark's ONE CHAIN judges the merge); 2 → on
    /// every second such window (once a simulated hour) a REINSTALL: the process gone, the datadir emptied, a fresh
    /// identity joining by the runtime's own DSYNC path ([`NetSim::join_fresh`]). Returns the simulated ms it ran.
    fn launch_tail_event(sim: &mut NetSim, st: &mut LaunchState, w: u64) -> u64 {
        let n = sim.rts.len();
        if n < 2 {
            return 0;
        }
        let pick = |salt: u64| 1 + (st.seed.wrapping_add(salt) % (n as u64 - 1)) as usize;
        let at = sim.now / 1000;
        match w % 3 {
            0 => {
                let r = pick(w / 3);
                if sim.is_down(r) {
                    st.tail_events.push(format!("restart n{r} skipped (down) @{at} s"));
                } else if let Err(e) = sim.restart(r, 30_000) {
                    st.tail_reds.push(format!("RESTART: node {r} did not come back at t={at} s: {e}"));
                } else {
                    st.tail_events.push(format!("restart n{r} @{at} s"));
                }
                0
            }
            1 => {
                let first = pick(w / 3);
                let side: Vec<usize> = (0..(n / 3).max(1)).map(|j| 1 + (first - 1 + j) % (n - 1)).collect();
                sim.partition(&side);
                sim.run(120_000, 10_000);
                sim.heal(&side);
                st.tail_events.push(format!("partition {side:?} 120 s @{at} s"));
                120_000
            }
            _ if w % 6 == 2 => {
                let j = pick(w / 6 + 7);
                if sim.is_down(j) {
                    st.tail_events.push(format!("reinstall n{j} skipped (down) @{at} s"));
                } else if let Err(e) = sim.process_gone(j).and_then(|_| sim.join_fresh(j).map(|_| ())) {
                    st.tail_reds.push(format!("REINSTALL: node {j} could not rejoin from an empty datadir at t={at} s: {e}"));
                } else {
                    st.tail_events.push(format!("reinstall n{j} @{at} s"));
                }
                0
            }
            _ => 0,
        }
    }

    /// F3 THE TAIL'S PERTURBATIONS, SMALL (rule 5c: the 10-node legs only confirm; this hunts on every farm seed): the launch
    /// mesh at 3 nodes runs the launch tail from boot to 2,400 sim s — a restart, a partition, a reinstall, a restart — and
    /// then the same judgement the final leg makes: every tail window advanced the tip, every up pair is ONE CHAIN, every
    /// restart census and the closing replicated-state census hold, and each of the three perturbations really ran.
    /// TWO-PARTY-REVIEWED: three independent `Node`s, each booted from its own datadir over the simulated wire; every census
    /// compares what each node HOLDS.
    #[test]
    #[ignore = "F3 tail perturbations at 3 nodes (minutes of wall): run by name with --include-ignored; farm-tests.txt hunts it on fresh seeds"]
    fn sim_launch_tail_restarts_partitions_and_reinstalls_hold_at_3_nodes() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(0x7131_7A11_2026_1024);
        let mut sim = launch_mesh_of(3, seed).boot_from_disk();
        let mut st = LaunchState { seed, last_tip: launch_tip(&sim), ..Default::default() };
        launch_tail(&mut sim, &mut st, 4 * LAUNCH_WINDOW_MS, &wall);
        let up = launch_up(&sim);
        for a in 0..up.len() {
            for b in a + 1..up.len() {
                if !sim.one_chain_between(up[a], up[b]) {
                    st.tail_reds.push(format!("TWO CHAINS at the end: nodes {} and {} do not share one chain", up[a], up[b]));
                }
            }
        }
        replica_census_at(&mut sim, "tail end", &[]);
        st.take_from(&sim);
        let tips: Vec<u64> = up.iter().map(|&i| sim.rt(i).node().tip_height()).collect();
        eprintln!(
            "[launch-tail-small] seed {seed:#x} · tips {tips:?} · restarts {} · census rows {} · events {:?} · census reds {} · tail reds {} · wall {:?}",
            st.restarts,
            st.census_rows,
            st.tail_events,
            st.census_reds.len(),
            st.tail_reds.len(),
            wall.elapsed()
        );
        for (step, census, field, detail) in &st.census_reds {
            eprintln!("[launch-census-red] {step}\t{census}\t{field}\t{detail}");
        }
        for kind in ["restart n", "partition", "reinstall n"] {
            assert!(
                st.tail_events.iter().any(|e| e.starts_with(kind) && !e.contains("skipped")),
                "CALIBRATION: the tail never ran a {kind:?} — events {:?}",
                st.tail_events
            );
        }
        assert!(tips.iter().all(|&t| t > 0), "CALIBRATION: a node holds no block — tips {tips:?}");
        assert!(
            st.tail_reds.is_empty() && st.census_reds.is_empty(),
            "⛔ the launch tail at 3 nodes (seed {seed:#x}): {} tail red(s) {:?} · {} census red field(s) {:?}",
            st.tail_reds.len(),
            st.tail_reds,
            st.census_reds.len(),
            st.census_reds.iter().take(40).map(|(s, c, f, d)| format!("{s} {c} {f}: {d}")).collect::<Vec<_>>()
        );
    }

    /// F3 THE TAIL'S RESTART-2 GROUP, REDUCED (rule 5c, lane b 2026-10-24): the 3-node tail's n2 was reinstalled at 1,200 s
    /// (empty datadir → DSYNC adopt) and restarted at 1,800 s, and its restart census CHANGED 17 fields (da_fetched 11.4 MB →
    /// 21 B, parked_votes 4.6 MB → 2 B, da_ladder_mem, roots_run_*, note_body_*, folded_floor …; scratchpad/verify/g2gr2b-5.log).
    /// The 2-node restart census reads those fields EMPTY on both sides (2 B / 21 B / 435 B), so it cannot see the class. Here:
    /// the same reinstall → run → production restart, and the restart census of the joiner must hold every field.
    /// TWO-PARTY-REVIEWED: three independent `Node`s over the simulated wire; the census compares what the joiner HOLDS.
    #[test]
    #[ignore = "F3 reduced tail group (~2–3 min of wall): run by name with --include-ignored"]
    fn sim_a_reinstalled_joiner_restarted_after_adopt_keeps_every_field() {
        let seed = journey::seed(0x7131_7A12_2026_1024);
        // DETERMINISTIC (lane b 2026-10-24): `charge_cpu` charges the host's MEASURED lock and prove wall into simulated
        // time, so one seed gave tips 558–644 and a run that failed before the restart (joiner-restart r2d-3). This pin
        // claims state, not timing: the uncharged mesh replays exactly from its seed, and the CALIBRATION below proves it
        // by running the seed twice to the same chain. The charged launch tail re-confirms (rule 5c). cons: none.
        let first = joiner_restart_run(seed);
        let second = joiner_restart_run(seed);
        assert_eq!(
            first.0, second.0,
            "CALIBRATION: one seed ran to two different chains (tips, block ids) — a red here could not be replayed"
        );
        let (_, changed, reds) = first;
        assert_eq!(changed, 0, "⛔ a reinstalled joiner's restart changed {changed} field(s): {reds:?}");
    }

    /// One reinstall → run → production restart of node 2 on the uncharged 3-node launch mesh: (each node's tip height and
    /// selected tip id before the restart, the fields the joiner's restart CHANGED, the census reds).
    fn joiner_restart_run(seed: u64) -> (Vec<(u64, String)>, usize, Vec<String>) {
        let mut sim = launch_mesh_of(3, seed);
        sim.make_replayable(); // the boots and the restart run on this thread
        let mut sim = sim.boot_from_disk();
        sim.run(300_000, 10_000);
        let tip0 = launch_tip(&sim);
        sim.process_gone(2).and_then(|_| sim.join_fresh(2).map(|_| ())).expect("the reinstall rejoins from an empty datadir");
        sim.run(600_000, 10_000);
        let joined = sim.rt(2).node().tip_height();
        assert!(joined > tip0, "CALIBRATION: the reinstalled joiner never passed the pre-reinstall tip {tip0} (holds {joined})");
        let before = sim.field_census(2);
        for i in 0..3 {
            let rt = sim.rt(i);
            let t = rt.node().fold_span_tally();
            eprintln!(
                "[joiner-restart] node {i} live fold span before the restart: {} member(s) vs {} counted, {} unreadable, \
                 reproduces {}, {} stamped in flight but held by no store, window {} non-member / {} older generation",
                t.members, t.counted, t.unreadable, t.reproduces, t.stamped_unheld, t.window_nonmember, t.window_old_gen
            );
        }
        {
            let (s0, w0) = { let rt = sim.rt(0); (rt.node().fold_span_tally().seen, rt.node().fold_base_words_for_test()) };
            let (s2, w2) = { let rt = sim.rt(2); (rt.node().fold_span_tally().seen, rt.node().fold_base_words_for_test()) };
            eprintln!(
                "[joiner-restart] base words equal {} · base_seq {} vs {} · A_tip equal {} · fold_seq {} vs {}",
                w0.0 == w2.0, w0.1, w2.1, w0.2 == w2.2, w0.3, w2.3
            );
            for id in s0.difference(&s2) {
                let at0 = sim.rt(0).node().span_member_whereabouts(id);
                let at2 = sim.rt(2).node().span_member_whereabouts(id);
                eprintln!("[joiner-restart] member {} held by node 0 not node 2 — node0: {at0} — node2: {at2}", &id.to_hex()[..8]);
            }
            for id in s2.difference(&s0) {
                let at2 = sim.rt(2).node().span_member_whereabouts(id);
                eprintln!("[joiner-restart] member {} held by node 2 not node 0 — node2: {at2}", &id.to_hex()[..8]);
            }
        }
        for i in 0..3 {
            let t = sim.rt(i).node().fold_span_tally();
            assert!(
                t.members == t.counted && t.unreadable == 0 && t.reproduces,
                "⛔ node {i}'s LIVE fold span does not reproduce A_tip ({} held of {} counted) — no spender's fold can close",
                t.members,
                t.counted
            );
        }
        let print: Vec<(u64, String)> = (0..3)
            .map(|i| {
                let rt = sim.rt(i);
                (rt.node().tip_height(), rt.node().selected_tip().map_or_else(String::new, |id| id.to_hex()))
            })
            .collect();
        // each field's census text before the restart, so a CHANGED row names WHAT changed, not only its byte count
        let text_of = |sim: &NetSim, f: &str| -> String {
            let mut s = String::new();
            sim.rt(2).node().census_field_render(f, &mut s);
            s
        };
        let texts: Vec<(&str, String)> = before.iter().map(|(f, _)| (*f, text_of(&sim, f))).collect();
        let split_before: Vec<_> = (0..3).map(|i| sim.rt(i).node().finality_tally_split()).collect();
        let floor_before: Vec<_> = (0..3).map(|i| sim.rt(i).node().dag_window_floor_probe()).collect();
        sim.restart(2, 30_000).expect("the joiner boots from its own files");
        eprintln!(
            "[joiner-restart-dagfloor] (dag len, min score, cert anchor score, dag ≤ it, window ≤ it, window off-dag, off-dag span) \
             per node before {floor_before:?} · node 2 after {:?}",
            sim.rt(2).node().dag_window_floor_probe()
        );
        eprintln!(
            "[joiner-restart-finality] (finalized, settled rows, open rows) per node before {split_before:?} · node 2 after {:?}",
            sim.rt(2).node().finality_tally_split()
        );
        for (f, was) in &texts {
            let now = text_of(&sim, f);
            if *was == now {
                continue;
            }
            let at = was.bytes().zip(now.bytes()).take_while(|(a, b)| a == b).count();
            let cut = |s: &str| s.get(at.saturating_sub(40)..s.len().min(at + 200)).unwrap_or("").to_string();
            eprintln!("[joiner-restart-field] {f}: {} B → {} B, first difference at byte {at}: before …{}… after …{}…", was.len(), now.len(), cut(was), cut(&now));
        }
        let changed = sim.restart_census_compare(2, "joiner restart", &before);
        let reds: Vec<String> = sim.census_reds.iter().map(|(_, _, f, d)| format!("{f}: {d}")).collect();
        eprintln!("[joiner-restart] seed {seed:#x} · tips {print:?} · {changed} field(s) CHANGED · {reds:?}");
        (print, changed, reds)
    }

    /// ⭐ REPLAY CALIBRATION (lane b 2026-10-24, T3: a farm finding is only a finding if `SIM_SEED` reproduces it). One
    /// seed, the replayable uncharged 3-node launch mesh, `REPLAY_RUN_S` simulated seconds (default 300), run TWICE in one
    /// process: every block born (instant, producer, id), every PoW try and every node's tip must be equal. On a red it
    /// names the FIRST block the two runs disagree on — where to look. MEASURED why (joiner-restart-d2.log): with the
    /// frozen clock alone, one seed still gave 254 vs 175 PoW tries by t = 10 s (block bytes carried OS entropy).
    /// TWO-PARTY-REVIEWED: three independent `Node`s over the simulated wire, each run judged on what the nodes HOLD.
    #[test]
    #[ignore = "replay calibration (~45 s of wall at 300 s; GREEN at 300 and 600 s, replay-r41/r42.log, lane b 2026-10-24): the farm runs it per SIM_SEED; by name with --include-ignored"]
    fn sim_one_seed_replays_to_the_same_blocks() {
        replay_calibration(None);
    }

    /// ⭐ REPLAY CALIBRATION THROUGH A REINSTALL (lane stable 2026-10-30): the same instrument with node 2's datadir wiped at
    /// 150 s and rejoined from empty (DSYNC adopt). MEASURED why (stable/a4.log): the reinstalled-joiner pin's own
    /// calibration ran one seed to two chains (tips 565/565/567 vs 552/553/549) while the steady mesh replays at 300 s and
    /// 900 s (r1.log, r2.log: 647 vs 647 born) — the reinstall path is where the runs part, and this names the first block.
    /// TWO-PARTY-REVIEWED: three independent `Node`s over the simulated wire (two replayers and the joiner), each run judged
    /// on what the nodes HOLD; the claim is that two whole runs agree.
    #[test]
    #[ignore = "replay calibration through a reinstall (~2 min of wall at 300 s): by name with --include-ignored"]
    fn sim_one_seed_replays_to_the_same_blocks_through_a_reinstall() {
        replay_calibration(Some(150));
    }

    /// One seed, the replayable uncharged 3-node launch mesh, run twice in one process; `reinstall_at_s` wipes node 2's
    /// datadir at that instant and rejoins it from empty. Every block born, every PoW try and every tip must be equal.
    /// TWO-PARTY-REVIEWED: three independent `Node`s; the assertion compares two whole runs of all three.
    fn replay_calibration(reinstall_at_s: Option<u64>) {
        let seed = journey::seed(0x7131_5EED_2026_1024);
        let run_s: u64 = std::env::var("REPLAY_RUN_S").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
        let run = || {
            let mut sim = launch_mesh_of(3, seed);
            sim.make_replayable();
            let mut sim = sim.boot_from_disk();
            // the first 6 s in 250 ms slices: each node's draws on its stream and its pool size, the instant they part
            // after every window: each node's draws on its stream, its pool size and an order-free digest of its pool's
            // ids — the first window the two runs disagree on names the instant and the node
            sim.replay_rows = Some(Vec::new());
            if let Some(at) = reinstall_at_s.filter(|at| *at < run_s) {
                sim.run(at * 1_000, 10_000);
                sim.process_gone(2).and_then(|_| sim.join_fresh(2).map(|_| ())).expect("the reinstall rejoins from an empty datadir");
                sim.run((run_s - at) * 1_000, 10_000);
            } else {
                sim.run(run_s * 1_000, 10_000);
            }
            let slices = sim.replay_rows.take().unwrap_or_default();
            // every tx id of every block, by producer: how many of a block's ids another producer's blocks carry too
            let mut ids_of: Vec<HashSet<Hash32>> = vec![HashSet::new(); 3];
            for (id, (from, _)) in &sim.born {
                if let Some(n) = sim.rt(*from).node().dag().get(id) {
                    ids_of[*from].extend(n.tx_ids.iter().copied());
                }
            }
            // (born at, producer, id, its header in short: parents · timestamp · nonce · tx root)
            let mut born: Vec<(u64, usize, String, String, Vec<String>)> = sim
                .born
                .iter()
                .map(|(id, (from, t))| {
                    let rt = sim.rt(*from);
                    let h = rt.node().dag().get(id).map_or_else(String::new, |n| {
                        let p: Vec<String> = n.header.parents.iter().map(|p| p.to_hex()[..8].to_string()).collect();
                        let tx: Vec<String> = n.tx_ids.iter().take(4).map(|t| t.to_hex()[..8].to_string()).collect();
                        format!(
                            "p{p:?} ts {} n {} tx {} ({} ids, {} also in another producer's blocks, first {tx:?})",
                            n.header.timestamp,
                            n.header.nonce,
                            &n.header.tx_merkle_root.to_hex()[..8],
                            n.tx_ids.len(),
                            n.tx_ids.iter().filter(|t| (0..3).any(|j| j != *from && ids_of[j].contains(*t))).count()
                        )
                    });
                    let all = rt.node().dag().get(id).map_or_else(Vec::new, |n| n.tx_ids.iter().map(|t| t.to_hex()[..12].to_string()).collect());
                    (*t, *from, id.to_hex()[..12].to_string(), h, all)
                })
                .collect();
            born.sort();
            let tips: Vec<(u64, String)> = (0..3)
                .map(|i| {
                    let rt = sim.rt(i);
                    (rt.node().tip_height(), rt.node().selected_tip().map_or_else(String::new, |id| id.to_hex()))
                })
                .collect();
            // the first block born, field by field: where a red starts
            if let Some((_, from, hex, _, _)) = born.first() {
                let rt = sim.rt(*from);
                let id = rt.node().dag().block_ids().into_iter().find(|id| id.to_hex().starts_with(hex.as_str()));
                if let Some(n) = id.and_then(|id| rt.node().dag().get(&id).cloned()) {
                    let txs: Vec<String> = n.tx_ids.iter().map(|t| t.to_hex()[..12].to_string()).collect();
                    eprintln!("[replay-first] {:?} · {} tx(s) {:?}", n.header, txs.len(), txs);
                }
            }
            eprintln!("[replay-run] lookahead breaks {}", sim.lookahead_breaks());
            (born, sim.report.hashes, tips, slices)
        };
        let (a, b) = (run(), run());
        let first = a.0.iter().zip(b.0.iter()).position(|(x, y)| x != y);
        if let Some(k) = a.3.iter().zip(b.3.iter()).position(|(x, y)| x != y) {
            for j in k.saturating_sub(2)..(k + 2).min(a.3.len()) {
                eprintln!("[replay-slice] (draws, pool, pool digest) per node   A {:?}   B {:?}", a.3[j], b.3[j]);
            }
        }
        if let Some(k) = first {
            for j in k.saturating_sub(3)..(k + 2).min(a.0.len()).min(b.0.len()) {
                let (x, y) = (&a.0[j], &b.0[j]);
                let diff: Vec<(usize, &String, &String)> = x.4.iter().zip(y.4.iter()).enumerate().filter(|(_, (p, q))| p != q).map(|(k, (p, q))| (k, p, q)).take(6).collect();
                eprintln!("[replay-trace] #{j}\n   A {:?}\n   B {:?}\n   tx slots that differ (slot, A, B): {diff:?}", (x.0, x.1, &x.2, &x.3), (y.0, y.1, &y.2, &y.3));
            }
        }
        eprintln!(
            "[replay] seed {seed:#x} {run_s} s: born {} vs {} · hashes {} vs {} · tips {:?} vs {:?} · first differing block {:?}",
            a.0.len(),
            b.0.len(),
            a.1,
            b.1,
            a.2,
            b.2,
            first.map(|k| (&a.0[k], &b.0[k]))
        );
        assert!(!a.0.is_empty(), "CALIBRATION: the mesh produced no block in {run_s} s");
        assert_eq!(a, b, "⛔ one seed ran to two different chains — a red found on this seed could not be replayed");
    }

    /// Leg 1 of 5: the full journey at ten nodes through the shipped wallet, then the mesh parked for leg 2.
    #[test]
    #[ignore = "F3 launch journey leg 1 of 5 (~12–15 min of wall at 10 nodes): run by name with --include-ignored; farm-tests.txt runs the five as one group"]
    fn sim_launch_leg_1_of_5_the_journey_at_10_nodes() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(LAUNCH_SEED_DEFAULT);
        let parked = launch_parked_dir(seed);
        let _ = std::fs::remove_dir_all(&parked); // a stale park of this seed is never resumed
        super::perf::begin("launch", seed);
        let canonical = stand_in_set_aside(); // §BR-13's door, exercised by the launch run (this build carries no set-aside)
        let mut sim = launch_mesh(seed).boot_from_disk();
        offer_set_aside_on(&mut sim, 0, &canonical);
        sim.hold_down(2); // the joiner of T1.6: it does not exist until then
        let mut v = Vec::new();
        crate::harness::sim_coverage::start();
        let go = tier1(&mut sim, &mut v, &wall).and_then(|()| tier_dsol(&mut sim, &mut v, &wall)).and_then(|()| tier_chain_rows(&mut sim, &mut v, &wall)).and_then(|()| tier_bond_rows(&mut sim, &mut v, &wall));
        crate::harness::sim_coverage::finish("journey-launch");
        let mut st = LaunchState {
            seed,
            legs_done: 1,
            red: go.is_none().then(|| format!("the journey stopped at {:?}", v.last().map(|(id, _, d)| (*id, d.clone())))),
            journey_end_ms: sim.now,
            last_tip: launch_tip(&sim),
            last_hour: sim.now / 3_600_000,
            steps: v.iter().map(|(a, b, c)| ((*a).to_string(), (*b).to_string(), c.clone())).collect(),
            ..Default::default()
        };
        eprintln!(
            "[sim-journey] launch leg 1 of {LAUNCH_LEGS}: {LAUNCH_NODES} nodes · restarts {} · journey {} s · wall {:?} · {}",
            sim.restarts,
            sim.now / 1000,
            wall.elapsed(),
            speed_line()
        );
        run_rows(&sim);
        served_vs_folded_census(&sim);
        st.take_from(&sim);
        let p = sim.park(&parked).expect("the launch mesh parks");
        st.down_until = p.down_until;
        st.before = p.before;
        st.wall_s.push(wall.elapsed().as_secs_f64());
        st.save(&parked).expect("the launch state is written");
        assert!(st.red.is_none(), "⛔ launch leg 1 of {LAUNCH_LEGS} (seed {seed:#x}): {} — the final leg reports it as T3's red", st.red.as_deref().unwrap_or(""));
    }

    /// ⭐ R8 — THE §BR-12 AND F13 LAUNCH STEPS, ON A PAIR: the arm launch leg 1 runs after its tiers (`tier_dsol`), proven on two
    /// nodes while the launch run itself is held at T1.6 (lane stable's join class, scratchpad/brb33/m2-launch-leg1.log). The same
    /// assertions: the deploy from node 1's wallet folds on node 0, the call from node 0's wallet folds on node 1, and the
    /// publisher's own node shows exactly the manifest's fee. Its rows print under the lane "dsol-pair" (readiness reads only
    /// the launch lane's; this is the arm's own proof, not R8's).
    #[test]
    fn sim_dsol_the_br12_and_f13_launch_steps_pass_on_a_pair() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(0xD501_2026_1102);
        let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().boot_from_disk();
        let mut v = Vec::new();
        let t = run_until(&mut sim, 120_000, |s| s.one_chain_between(0, 1));
        assert!(t.is_some(), "PRECONDITION: the pair never became one chain");
        let go = tier_dsol(&mut sim, &mut v, &wall);
        journey::record_steps("dsol-pair", &v);
        assert!(go.is_some(), "⛔ R8 §BR-12/F13 steps on a pair: {:?}", v.iter().map(|(id, ok, d)| format!("{id} {ok}: {d}")).collect::<Vec<_>>());
        assert!(v.iter().any(|(id, ok, _)| *id == "F13" && *ok == "PASS"), "F13 passed");
    }

    /// ⭐ R8 — THE §BR-13 AND §BR-14 LAUNCH STEPS, ON A PAIR: the faucet funds W1 and W1 pays W2 (T1.0–T1.2's spends), then every
    /// node's set-aside, issued SAT and fee pools are read and compared — the arm launch leg 1 runs after its tiers.
    #[test]
    fn sim_chain_rows_the_br13_and_br14_launch_steps_pass_on_a_pair() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(0xB1314_2026_1102);
        let canonical = stand_in_set_aside();
        let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().boot_from_disk();
        offer_set_aside_on(&mut sim, 0, &canonical);
        let mut v = Vec::new();
        let funded = fund_pair(&mut sim, &mut v, &wall, "rows");
        assert!(funded.is_some(), "PRECONDITION: the pair's funding steps: {v:?}");
        let go = tier_chain_rows(&mut sim, &mut v, &wall);
        crate::sat_set_aside::set_canonical_for_test(None);
        journey::record_steps("chain-rows-pair", &v);
        assert!(go.is_some(), "⛔ R8 §BR-13/§BR-14 steps on a pair: {:?}", v.iter().map(|(id, ok, d)| format!("{id} {ok}: {d}")).collect::<Vec<_>>());
    }

    /// ⭐ R8 — THE §BR-3 AND §BR-11 LAUNCH STEPS, ON A PAIR: the pair is funded (T1.0–T1.2), tier 3 bonds node 0's seat, matures
    /// it, unbonds, releases and delegates (T3), then every node's seat record, delegation targets and miner-pool answer are
    /// compared — the arm launch leg 1 runs after its tiers. Rows print under the lane "bond-rows-pair".
    #[test]
    fn sim_bond_rows_the_br3_and_br11_launch_steps_pass_on_a_pair() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(0xB311_2026_1102);
        // the journeys' own mesh shape: the template double and the journey stake lock (tier 3's maturity fits a run)
        let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().with_template_double().with_journey_stake_lock().boot_from_disk();
        let mut v = Vec::new();
        let Some((w1, w2, _url0, _url1, within)) = fund_pair(&mut sim, &mut v, &wall, "bondrows") else {
            panic!("PRECONDITION: the pair's funding steps: {v:?}");
        };
        // tier 3's bond phases only — bond, maturity, unbond, release on every up node — the facts the §BR-3 row reads; the
        // identity phase (names, letters, the POS tap, the delegation, the stake) is T3's own and rides the launch run
        // (MEASURED r5-bond-rows-pair.log: the delegation's seat-divergence class [6862960 vs 6962960], lane stable's, cut
        // the pair pin short of the rows it exists to prove)
        let mut t3 = T3Carry::default();
        let bonded = tier3_bond(&mut sim, &mut v, &wall, &w1, within, &mut t3).is_some()
            && matches!(tier3_mature_and_unbond(&mut sim, &mut v, &wall, &w1, within, &mut t3, None), T3Wait::Done);
        assert!(bonded, "PRECONDITION: tier 3's bond, maturity, unbond and release: {:?}", v.iter().map(|(id, ok, d)| format!("{id} {ok}: {d}")).collect::<Vec<_>>());
        let go = tier_bond_rows(&mut sim, &mut v, &wall);
        journey::record_steps("bond-rows-pair", &v);
        assert!(go.is_some(), "⛔ R8 §BR-3/§BR-11 steps on a pair: {:?}", v.iter().map(|(id, ok, d)| format!("{id} {ok}: {d}")).collect::<Vec<_>>());
    }

    /// ⭐ R8 / T3 — THE §BR-3 17.6 STAKE ROUND, ON A PAIR (the fast journey's first red on cb7fdf7, certify-cb7fdf7c6d0b-
    /// 20261103-001910.log: "W2 could not unstake … the network did not take an unstake yet (BAD_REQUEST)", the node line
    /// "this custodian's stakers' pool opening is stale" after "this custodian holds no sealed reward leg in the stake
    /// object"). The pair is funded (T1.0–T1.2), tier 3 bonds node 0's seat, matures, unbonds and releases it — the state
    /// the journey's T3 hands its stake round — then the round runs exactly as T3 runs it (`tier3_stake_round`).
    #[test]
    fn sim_stake_the_br3_17_6_round_passes_on_a_pair() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(0x5A4E_2026_1103);
        let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().with_template_double().with_journey_stake_lock().boot_from_disk();
        let mut v = Vec::new();
        let Some((w1, w2, _url0, _url1, within)) = fund_pair(&mut sim, &mut v, &wall, "stakeround") else {
            panic!("PRECONDITION: the pair's funding steps: {v:?}");
        };
        let mut t3 = T3Carry::default();
        let released = tier3_bond(&mut sim, &mut v, &wall, &w1, within, &mut t3).is_some()
            && matches!(tier3_mature_and_unbond(&mut sim, &mut v, &wall, &w1, within, &mut t3, None), T3Wait::Done);
        assert!(released, "PRECONDITION: tier 3's bond, maturity, unbond and release: {:?}", v.iter().map(|(id, ok, d)| format!("{id} {ok}: {d}")).collect::<Vec<_>>());
        match tier3_stake_round(&mut sim, &w2, within) {
            Ok(steps) => eprintln!("[stake-round] PASS — {}", steps.join(" · ")),
            Err(e) => panic!("⛔ §BR-3 17.6 the stake round on a pair: {e}"),
        }
    }

    /// ⭐ T3 / T2 — THE CUSTODY KEY TABLE ACROSS A RESTART, ON A PAIR: the stake round after BOTH nodes restart while node 1
    /// holds only its membership seat (the journey's T1.7 restarts node 0 before T3 seats node 1's SAT custody). A seat's
    /// encapsulation key is chain state (registered from its signed seat header), so a restarted node must seal to it once
    /// that seat bonds custody. MEASURED red (certify-cb7fdf7c6d0b-20261103-001910.log T3): "this custodian holds no sealed
    /// reward leg in the stake object", then the unstake refused "this custodian's stakers' pool opening is stale"; the pair
    /// with no restart PASSES (c34-stake-pair.log: "sealed to 1 of 1 bonded custodian key(s)").
    #[test]
    fn sim_stake_round_after_both_nodes_restart_passes_on_a_pair() {
        let wall = std::time::Instant::now();
        let seed = journey::seed(0x5A4E_2026_1104);
        let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().with_template_double().with_journey_stake_lock().boot_from_disk();
        let mut v = Vec::new();
        let Some((w1, w2, _url0, _url1, within)) = fund_pair(&mut sim, &mut v, &wall, "stakerestart") else {
            panic!("PRECONDITION: the pair's funding steps: {v:?}");
        };
        for i in [0usize, 1] {
            if let Err(e) = sim.restart(i, 5_000) {
                panic!("PRECONDITION: node {i} restarts from its own files: {e}");
            }
        }
        assert!(run_until(&mut sim, 180_000, |s| s.one_chain_between(0, 1)).is_some(), "PRECONDITION: one chain after both restarts");
        let mut t3 = T3Carry::default();
        let released = tier3_bond(&mut sim, &mut v, &wall, &w1, within, &mut t3).is_some()
            && matches!(tier3_mature_and_unbond(&mut sim, &mut v, &wall, &w1, within, &mut t3, None), T3Wait::Done);
        assert!(released, "PRECONDITION: tier 3's bond, maturity, unbond and release: {:?}", v.iter().map(|(id, ok, d)| format!("{id} {ok}: {d}")).collect::<Vec<_>>());
        match tier3_stake_round(&mut sim, &w2, within) {
            Ok(steps) => eprintln!("[stake-round] PASS after both restarts — {}", steps.join(" · ")),
            Err(e) => panic!("⛔ T3: the stake round after both nodes restarted: {e}"),
        }
    }

    /// A tail leg that cannot run: a missing, out-of-order or red parked state. The final leg still records the run
    /// (NOT-RUN rows) so readiness T3 reads a verdict, never silence.
    fn launch_calibration(last: bool, seed: u64, k: u64, why: &str) -> ! {
        if last {
            journey::record("launch", seed, &[]);
        }
        panic!("⛔ launch leg {k} of {LAUNCH_LEGS} (seed {seed:#x}): CALIBRATION: {why}");
    }

    /// Legs 2..=5: resume the parked mesh, run the tail to this leg's end, and park again — or, on the final leg, judge.
    fn launch_tail_leg(k: u64) {
        let wall = std::time::Instant::now();
        let seed = journey::seed(LAUNCH_SEED_DEFAULT);
        let parked = launch_parked_dir(seed);
        let last = k == LAUNCH_LEGS;
        let until_ms = LAUNCH_LEG_ENDS_MS[k as usize - 2];
        let mut st = match LaunchState::load(&parked) {
            Ok(s) if s.seed == seed && s.legs_done == k - 1 => s,
            Ok(s) => launch_calibration(last, seed, k, &format!("the parked state is leg {} of seed {:#x}, not leg {} of this seed", s.legs_done, s.seed, k - 1)),
            Err(e) => launch_calibration(last, seed, k, &e),
        };
        // the cleanup is armed only once the park is accepted (see `real_tier_leg`).
        let _cleanup = last.then(|| RemoveDirOnDrop(parked.clone()));
        if let (Some(red), false) = (&st.red, last) {
            launch_calibration(last, seed, k, &format!("leg 1 is red ({red}); the final leg reports it"));
        }
        if st.red.is_none() {
            let mut fresh = launch_mesh(seed);
            st.give_to(&mut fresh);
            let mut sim = fresh
                .resume_from_disk(&parked, st.now_ms, &st.down_until, Some(&st.before), &format!("leg boundary {}", k - 1))
                .expect("the parked launch mesh resumes");
            launch_tail(&mut sim, &mut st, until_ms, &wall);
            eprintln!(
                "[sim-journey] launch leg {k} of {LAUNCH_LEGS}: {LAUNCH_NODES} nodes · restarts {} · sim {} s · wall {:?} · {}",
                sim.restarts,
                sim.now / 1000,
                wall.elapsed(),
                speed_line()
            );
            st.take_from(&sim);
            st.legs_done = k;
            st.wall_s.push(wall.elapsed().as_secs_f64());
            if !last {
                let p = sim.park(&parked).expect("the launch mesh parks");
                st.down_until = p.down_until;
                st.before = p.before;
                st.save(&parked).expect("the launch state is written");
                return;
            }
            run_rows(&sim);
            served_vs_folded_census(&sim);
        }
        launch_verdict(&st);
    }

    /// THE VERDICT (the final leg): the growth check over the hour rows, every census red and tail red printed per field,
    /// the journey recorded for the ledgers, and the one assertion the whole run must pass.
    fn launch_verdict(st: &LaunchState) {
        let seed = st.seed;
        let mut tail_reds = st.tail_reds.clone();
        // NO GROWTH, TWO SCALES: the bytes outside the block window at 2 h against 1 h (P14's rule: a flat quantity reads
        // under 2× across the heights; a per-block term reads ~2× over twice the chain) — per node
        if let (Some(h1), Some(h2)) = (st.hours.iter().find(|h| h.0 == 1), st.hours.iter().find(|h| h.0 == 2)) {
            for (i, (a, b)) in h1.2.iter().zip(h2.2.iter()).enumerate() {
                if *b >= 2 * *a && *a > 0 {
                    tail_reds.push(format!("GROWTH: node {i}'s datadir outside the block window {a} B at 1 h → {b} B at 2 h (≥ 2×: a per-block term)"));
                }
            }
        } else {
            tail_reds.push(format!("CALIBRATION: both hour marks must be sampled — sampled {:?}", st.hours.iter().map(|h| h.0).collect::<Vec<_>>()));
        }
        let v: Vec<(&str, &str, String)> = st.steps.iter().map(|(a, b, c)| (a.as_str(), b.as_str(), c.clone())).collect();
        journey::record("launch", seed, &v);
        for (step, census, field, detail) in &st.census_reds {
            eprintln!("[launch-census-red] {step}\t{census}\t{field}\t{detail}");
        }
        // a tail that perturbed nothing judged no restart, partition or join (CALIBRATION, never a pass)
        if !st.tail_events.iter().any(|e| !e.contains("skipped")) {
            tail_reds.push(format!("CALIBRATION: the tail ran no restart, partition or reinstall — events {:?}", st.tail_events));
        }
        for e in &st.tail_events {
            eprintln!("[launch-tail-event] {e}");
        }
        for r in &tail_reds {
            eprintln!("[launch-tail-red] {r}");
        }
        eprintln!(
            "[launch-census] {} census verdict(s) over {} step(s) and {} restart(s) · {} census red field(s) · {} tail red(s) · seed {seed:#x} · legs wall {:?} s",
            st.census_rows,
            v.len(),
            st.restarts,
            st.census_reds.len(),
            tail_reds.len(),
            st.wall_s.iter().map(|w| w.round()).collect::<Vec<_>>()
        );
        let censused = st.census_rows >= v.len() as u64 + st.restarts;
        assert!(
            st.red.is_none() && censused && st.census_reds.is_empty() && tail_reds.is_empty(),
            "⛔ the launch journey ({LAUNCH_NODES} nodes, {} sim h of {LAUNCH_SIM_HOURS}, seed {seed:#x}, {} leg(s)): {} · censuses taken {} of {} wanted · {} census red field(s): {:?} · {} tail red(s): {:?}",
            st.now_ms / 3_600_000,
            st.legs_done,
            st.red.clone().unwrap_or_else(|| "every journey step PASSED".into()),
            st.census_rows,
            v.len() as u64 + st.restarts,
            st.census_reds.len(),
            st.census_reds.iter().take(40).map(|(s, c, f, d)| format!("{s} {c} {f}: {d}")).collect::<Vec<_>>(),
            tail_reds.len(),
            tail_reds.iter().take(12).collect::<Vec<_>>()
        );
    }

    /// Leg 2 of 5: the tail from the journey's end to 3,600 sim s.
    #[test]
    #[ignore = "F3 launch journey leg 2 of 5 (~10 min of wall): needs leg 1's parked mesh; farm-tests.txt runs the five as one group"]
    fn sim_launch_leg_2_of_5_the_tail_to_3600_sim_s() {
        launch_tail_leg(2);
    }

    /// Leg 3 of 5: the tail to 4,800 sim s.
    #[test]
    #[ignore = "F3 launch journey leg 3 of 5 (~10 min of wall): needs leg 2's parked mesh; farm-tests.txt runs the five as one group"]
    fn sim_launch_leg_3_of_5_the_tail_to_4800_sim_s() {
        launch_tail_leg(3);
    }

    /// Leg 4 of 5: the tail to 6,000 sim s.
    #[test]
    #[ignore = "F3 launch journey leg 4 of 5 (~10 min of wall): needs leg 3's parked mesh; farm-tests.txt runs the five as one group"]
    fn sim_launch_leg_4_of_5_the_tail_to_6000_sim_s() {
        launch_tail_leg(4);
    }

    /// Leg 5 of 5 — THE VERDICT: the tail to 7,200 sim s, then every census red, tail red and journey step of the whole run
    /// judged. This name is the one readiness.py reads for T3 (the newest `sim_launch_journey` pin row).
    #[test]
    #[ignore = "F3 launch journey leg 5 of 5, the verdict (~10 min of wall): needs leg 4's parked mesh; farm-tests.txt runs the five as one group"]
    fn sim_launch_journey_fast_10_nodes_2_sim_hours() {
        launch_tail_leg(LAUNCH_LEGS);
    }

    /// ⭐ REFUTATION BEFORE GREEN for the door the legs ride ([`NetSim::park`] / [`NetSim::resume_from_disk`]), three nodes:
    /// ARM A — a mesh that ran 120 s is parked and resumed in a NEW simulation on the parked clock: every node's new process
    /// holds exactly the tip its old one held (from the files alone), the restart census ran at every node, the mesh then
    /// advances on every node and is one chain after 300 s. ARM B — the same files resumed by a process that FORGOT THE
    /// CLOCK (t = 0): the chain is at t ≈ 420 s, so every block a node could now produce carries a timestamp at or below
    /// the median time past and is refused (`consensus::BlockError`, the MTP rule, consensus.rs); the tip must not move
    /// in 300 s. If it did move, a block behind its own chain's time would have been accepted — a consensus hole, filed as
    /// value-class — so this arm is the measurement that the clock is part of the hand-off, never an assumption.
    #[test]
    fn a_parked_mesh_resumes_in_a_new_simulation_on_the_same_chain_and_a_resume_that_forgets_the_clock_is_refused() {
        const N: usize = 3;
        let seed = journey::seed(0x7131_00F3_2026_1023);
        let parked = std::env::temp_dir().join(format!("netsim-parkpin-{}-{seed:x}", std::process::id()));
        let _cleanup = RemoveDirOnDrop(parked.clone());
        let mesh = |seed: u64| {
            let mut s = NetSim::testnet(N, Physics::from_env(), seed).with_band_double().with_template_double();
            s.charge_cpu = true;
            s.step_census = true;
            s
        };
        let tips = |s: &NetSim| (0..N).map(|i| s.rt(i).node().tip_height()).collect::<Vec<u64>>();
        let mut sim = mesh(seed).boot_from_disk();
        sim.run(120_000, 10_000);
        let (t0, now0) = (tips(&sim), sim.now);
        assert!(t0.iter().copied().max().unwrap_or(0) > 0, "CALIBRATION: the mesh produced no block in 120 s: {t0:?}");
        let p = sim.park(&parked).expect("the mesh parks");
        assert_eq!(p.now_ms, now0, "the park carries the clock");
        assert!(p.before.iter().all(Option::is_some), "every up node's restart-census snapshot rides the park");
        // ARM A: resumed in a NEW simulation on the parked clock
        let mut a = mesh(seed ^ 1)
            .resume_from_disk(&parked, p.now_ms, &p.down_until, Some(&p.before), "park pin")
            .expect("the parked mesh resumes");
        assert_eq!(a.now, now0, "the resume starts at the parked instant");
        assert_eq!((a.restarts, a.census_rows), (N as u64, N as u64), "every node was restarted and censused at the resume");
        let t1 = tips(&a);
        assert_eq!(t1, t0, "every block the old processes held, the new ones hold — from the files alone");
        a.run(300_000, 10_000);
        let t2 = tips(&a);
        assert!(t2.iter().zip(&t1).all(|(x, y)| x > y), "every node's tip advanced after the resume: {t1:?} → {t2:?}");
        for x in 0..N {
            for y in x + 1..N {
                assert!(a.one_chain_between(x, y), "nodes {x} and {y} share one chain after the resume");
            }
        }
        for (step, census, field, detail) in &a.census_reds {
            eprintln!("[park-pin] census red at the resume (the restart census pin's class, reported here): {step} {census} {field}: {detail}");
        }
        eprintln!("[park-pin] arm A: tips {t0:?} → {t1:?} at the resume → {t2:?} after 300 s · {} census red(s)", a.census_reds.len());
        // ARM B: the same files resumed by a process that FORGOT THE CLOCK (t = 0)
        let p2 = a.park(&parked).expect("the mesh parks again");
        let mut b = mesh(seed ^ 2).resume_from_disk(&parked, 0, &vec![0; N], None, "forgot the clock").expect("the files are sound: it boots");
        let tb0 = tips(&b);
        assert_eq!(tb0, t2, "the forgot-clock process still holds the chain");
        b.run(300_000, 10_000);
        let tb1 = tips(&b);
        eprintln!("[park-pin] arm B (forgot the clock): tips {tb0:?} → {tb1:?} over 300 s at t=0, the chain at t={} s", p2.now_ms / 1000);
        assert_eq!(tb1, tb0, "⛔ a resume that forgot the clock extended its own chain with blocks behind its time: {tb0:?} → {tb1:?}");
    }
}

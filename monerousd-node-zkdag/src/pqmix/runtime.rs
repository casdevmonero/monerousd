// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The running mix on one node: links over carriers, the sending pump, the delay pool, record gossip, and asks with their
//! replies. Every store has a constant bound, and the spec lists them.
//!
//! BORROWED: Loopix's Poisson sending, per-hop delay and loop/drop cover; Bitcoin Core's `addr` relay; Bitcoin's in-flight
//! block tracking, which is the guard the bulk ask shares with the Tor lane.
//!
//! Disk arithmetic: `mix-records.bin` is 1,024 records x 7.6 KB = 7.8 MB at most, rewritten whole once a minute, and
//! `mix-status.json` is one small file overwritten in place. cons: none for growth, since both are f(fixed constants), never f(history).

use super::carrier::{self, BoxStream, CarrierAddr};
use super::link::{self, LinkKeys, Me};
use super::packet::{self, HopKey, KemSecret, NodeId, Peeled, Refused, INNER};
use super::record::{self, epoch_now, Identity, Record};
use super::replay::ReplayBloom;
use super::rng::Rng;
use super::view::{Admit, View};
use crate::arti_transport::{BulkInbox, InflightGuard};
use crate::transport::BulkServeSlot;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// The standby rate: a node keeps its links and its cover going, and its Tor carries the real traffic.
pub const STANDBY_PPS: f64 = 2.0;
/// The active rate. A protocol constant, never a load figure.
pub const ACTIVE_PPS: f64 = 128.0;
/// How many packets a relay should hold at once, so a packet leaves among others. Loopix calls `λ/µ ≥ 2` a good choice.
const POOL_TARGET: f64 = 8.0;
const DELAY_MIN_MS: f64 = 40.0;
const DELAY_MAX_MS: f64 = 1000.0;

const LINKS_MAX: usize = 64;
const LINKS_TARGET: usize = 8;
const FANOUT: usize = 4;
const LINK_QUEUE: usize = 128;
const POOL_MAX: usize = 512;
const CELLS_OUT_MAX: usize = 2048;
const BULK_OUT_MAX: usize = 8192;
const CELLS_IN_MAX: usize = 2048;
const PSEUDONYMS_MAX: usize = 4096;
const PSEUDONYMS_PER_LINK: usize = 256;
const PSEUDONYM_TTL_MS: u64 = 90_000;
const ASSEMBLING_MAX: usize = 256;
const ASSEMBLE_TTL_MS: u64 = 30_000;
const ASK_FRAGS_MAX: usize = 16;
/// A transaction push carries a whole transaction: about 500 KB measured, so about 120 fragments; this allows twice that.
const PUSH_FRAGS_MAX: usize = 256;
/// Pushes assembling at once on this node, so a flood of large asks is bounded at about 4 × 256 × 4.3 KB, 4.4 MB.
const PUSHES_ASSEMBLING_MAX: usize = 4;
const PARKED_PER_TARGET: usize = 8;
const PARKED_TARGETS: usize = 32;
const INTAKE_PPS: f64 = 512.0;
const BAD_STREAK_MAX: u32 = 32;
const RECORDS_PER_MINUTE: u32 = 64;
const SERVES_MAX: usize = 16;
const HANDSHAKES_PENDING_MAX: usize = 32;
const LINK_IDLE_SECS: u64 = 120;
const PRIMARY_DOWN_AFTER_MS: u64 = 20_000;
/// Tor has to stay up this long before this node stops carrying private traffic itself, so a Tor under attack does not flap the node.
const PRIMARY_UP_AFTER_MS: u64 = 60_000;
const PEER_NEED_MS: u64 = 120_000;
const DIAL_SECS: u64 = 10;

const F_PACKET: u8 = 1;
const F_RECORD: u8 = 2;
const F_REGISTER: u8 = 4;
const F_DELIVER: u8 = 5;
// The relay plane: public chain data, one hop, spec section 4. A block is broadcast to everyone, so taking it through a mix hides nothing.
const F_RELAY_CELL: u8 = 6;
const F_RELAY_ASK: u8 = 7;
const F_RELAY_PAGE: u8 = 8;
// ⭐ O5 — EVERY NODE A RELAY (lane af57, 2026-11-16; user: "If we have 500 nodes on tor then we should have 500 relays
// automatically which would increase the anonyminity set automatically" · "Just make sure users ips arent exposed and able to be
// linked" · "it should get infinitely more private as more nodes join"). A node with no address of its own (no relay face) is a
// HOP through the relay face it already dials, its GATEWAY: it registers a hop identity over that one link, its record names the
// gateway (`CarrierAddr::Via`) and no address, and a packet for it goes to the gateway, which forwards it down the hop's link.
//   - F_HOP: the hop's signed record, naming `Via(<this gateway>)` and nothing else.
//   - F_HOP_PROOF: the hop key's ML-DSA signature over `hop_statement(link binding, hop id, epoch)`, the next frame on the same
//     link. A record copied off the network cannot be registered by anyone else: the binding is this link's alone.
//   - F_VIA: `hop id ‖ packet`, sent to a hop's gateway by whoever's next hop it is.
// Who learns what: the gateway, which already sees the hop's IP as the far end of a link the hop dialled, learns that this IP
// relays as this hop identity. No one else learns any address. The hop identity is minted per gateway (`mix-hop.key`), so two
// gateways that compare notes cannot follow one machine from address to address by its hop id, and a hidden node no longer
// sends its long-term record on any link (it used to be the first frame of every link it dialled: each relay it dialled learned
// that IP's long-term id).
// Scale (SAFE AT SCALE): a gateway holds at most one hop per link, so `LINKS_MAX` hops, 48 bytes each; a hop sends two frames
// (~9.8 KB) to its gateway once an epoch; a hop record floods like any record. Every node that has no address becomes routable,
// so the crowd (`View::crowd`) grows with the nodes; the traffic through hops passes through relay faces twice (into the hop,
// and the hop's onward send to the next relay face), so hop throughput is bounded by the relay faces' links — a named bound.
// AI resistance: (a)+(b) — a registration needs a signature by the hop key over this link's binding, which no copied record
// carries; a gateway that drops a hop's packets is a relay dropping packets, seen by the hop's own loops.
const F_HOP: u8 = 9;
const F_HOP_PROOF: u8 = 10;
const F_VIA: u8 = 11;
/// How long a hop keeps waiting for its gateway's link to come back before it moves to another gateway (and a new hop identity).
const HOP_GATEWAY_LOST_MS: u64 = 60_000;
/// How often a hop re-sends its unchanged registration: ~9.8 KB per 5 min to one gateway, ~33 B/s.
const HOP_REFRESH_MS: u64 = 300_000;
const RELAY_RID: usize = 16;
const RELAY_PAGE_HDR: usize = RELAY_RID + 4 + 4;
const RELAY_PAGE_DATA: usize = link::FRAME_BODY - RELAY_PAGE_HDR;

const K_DROP: u8 = 0;
const K_LOOP: u8 = 1;
const K_CELL: u8 = 2;
const K_ASK: u8 = 3;
const K_REPLY: u8 = 4;

const INNER_HDR: usize = 3;
const ASK_HDR: usize = 16 + 32 + 32 + 2 + 2;
const ASK_FRAG: usize = INNER - INNER_HDR - ASK_HDR;
const REPLY_CIPHER: usize = INNER - INNER_HDR - 16 - 16 - 32;
const REPLY_HDR: usize = 4 + 4 + 2;
const REPLY_DATA: usize = REPLY_CIPHER - REPLY_HDR;

/// The most relay-face records one kind-30 answer carries, and the most one admission takes. A record is about 6.5 KB
/// (ML-DSA-65 key and signature, ML-KEM-768 key), so an answer stays near 104 KB, one bulk page.
pub const RELAY_FACES_ANSWER_MAX: usize = 16;

/// The ONE source every relay face learned outside this network counts against in [`View::admit`]: answers over Tor, from any
/// number of peers, fill at most `view::SOURCE_MAX` entries together. Not a node id (a node id is a blake3 of an ML-DSA key).
pub const LEARNED_OUTSIDE: NodeId = *b"relay faces learned outside mix!";

/// The running mix of this process, for the node's doors that read or feed it (the kind-30 ask and answer, `/get_relay_faces`).
/// One mix runs per daemon process; the first one spawned is the one named here.
static RUNNING: std::sync::OnceLock<Weak<Shared>> = std::sync::OnceLock::new();

/// The running mix, if this process started one.
pub(crate) fn running() -> Option<Arc<Shared>> {
    RUNNING.get().and_then(Weak::upgrade)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    }
}

pub fn now_ms() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as u64,
        Err(_) => 0,
    }
}

/// How long an ask of `len` bytes takes to leave at the slowest rate this node ever sends at: its fragments take every other
/// slot (the pump alternates cells and bulk), so `fragments × 2 / STANDBY_PPS` seconds. A caller that sends again must wait at
/// least this, or it queues a second copy behind the first.
#[must_use]
pub fn ask_upload_ms(len: usize) -> u64 {
    let frags = len.div_ceil(ASK_FRAG).max(1) as f64;
    (frags * 2.0 * 1000.0 / STANDBY_PPS) as u64
}

/// The mean per-hop delay at a rate: long enough that a relay holds [`POOL_TARGET`] packets, given that each node relays
/// about `hops × rate` packets a second. Derived, never tuned to a result.
pub fn mean_delay_ms(rate_pps: f64) -> f64 {
    (POOL_TARGET * 1000.0 / (packet::HOPS as f64 * rate_pps)).clamp(DELAY_MIN_MS, DELAY_MAX_MS)
}

struct EpochKey {
    epoch: u64,
    kem_pk: Vec<u8>,
    sk: KemSecret,
    replay: ReplayBloom,
}

fn fresh_key(epoch: u64) -> EpochKey {
    let (kem_pk, sk) = packet::kem_keypair();
    EpochKey { epoch, kem_pk, sk, replay: ReplayBloom::new() }
}

struct Keys {
    cur: EpochKey,
    /// Held one more epoch for packets built just before the turn, then destroyed with its replay set.
    prev: Option<EpochKey>,
}

enum Action {
    Send(NodeId, Vec<u8>),
    Deliver(Vec<u8>),
}

struct Delayed {
    due_ms: u64,
    seq: u64,
    action: Action,
}
impl PartialEq for Delayed {
    fn eq(&self, o: &Self) -> bool {
        self.seq == o.seq
    }
}
impl Eq for Delayed {}
impl PartialOrd for Delayed {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Delayed {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (o.due_ms, o.seq).cmp(&(self.due_ms, self.seq))
    }
}

struct LinkTx {
    generation: u64,
    tx: mpsc::Sender<(u8, Vec<u8>)>,
    /// This link's binding (`LinkKeys::binding`): what a hop signs to register over it.
    binding: [u8; 32],
}

/// O5: this node as a hop through its gateway, while it has no address of its own.
struct HopSelf {
    ident: Identity,
    gateway: NodeId,
    /// (epoch, nonce): the hop identity's epoch rent.
    rent: (u64, u64),
    /// (gateway link generation, epoch) the gateway holds a registration for.
    registered: Option<(u64, u64)>,
    /// The last record and proof sent, and when: re-sent unchanged every `HOP_REFRESH_MS` on the same link and epoch, so a
    /// registration the gateway lost (a restart, a refused pairing) heals without a new record flooding the network.
    sent: Option<(Vec<u8>, Vec<u8>)>,
    sent_at_ms: u64,
    /// When the gateway's link went away, 0 while it is up.
    lost_since_ms: u64,
}

/// What a hop signs to register with its gateway over one link.
fn hop_statement(binding: &[u8; 32], hop: &NodeId, epoch: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(96);
    m.extend_from_slice(b"monerousd mix v1 hop registration");
    m.extend_from_slice(binding);
    m.extend_from_slice(hop);
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

struct Ask {
    guard: InflightGuard,
    key: Zeroizing<[u8; 32]>,
    parts: HashMap<u32, Vec<u8>>,
    total: u32,
    last_ms: u64,
    idle_ms: u64,
}

struct Assembling {
    gateway: NodeId,
    key: Zeroizing<[u8; 32]>,
    total: u16,
    parts: HashMap<u16, Vec<u8>>,
    /// When the last fragment arrived. An ask is dropped after `ASSEMBLE_TTL_MS` with no fragment, never for its total age: a
    /// 500 KB transaction push takes about 60 s at the standby rate, and timing it from the first fragment dropped every one.
    last_ms: u64,
}

/// Fixed-size counters, written to one status file. They name no peer, address, note, amount, key or owner.
#[derive(Default)]
pub struct Counters {
    pub sent_real: AtomicU64,
    pub sent_cover: AtomicU64,
    pub relayed: AtomicU64,
    pub delivered: AtomicU64,
    pub cells_in: AtomicU64,
    pub cells_out: AtomicU64,
    pub bad_mac: AtomicU64,
    pub replays: AtomicU64,
    pub tagged: AtomicU64,
    pub wrong_size: AtomicU64,
    pub records_new: AtomicU64,
    pub records_refused: AtomicU64,
    pub loops_sent: AtomicU64,
    pub loops_back: AtomicU64,
    pub loop_ms_sum: AtomicU64,
    pub asks_sent: AtomicU64,
    pub asks_answered: AtomicU64,
    pub asks_timed_out: AtomicU64,
    pub asks_served: AtomicU64,
    pub replies_relayed: AtomicU64,
    pub dropped_pool: AtomicU64,
    pub dropped_link: AtomicU64,
    pub dropped_queue: AtomicU64,
    pub links_up: AtomicU64,
    pub dials_failed: AtomicU64,
    pub handshakes_failed: AtomicU64,
    pub links_closed_bad: AtomicU64,
    pub frames_unknown: AtomicU64,
    /// O5: hop registrations this node accepted as a gateway, refused (bad record, bad proof, full), and packets it forwarded to a hop.
    pub hops_registered: AtomicU64,
    pub hops_refused: AtomicU64,
    pub hop_forwarded: AtomicU64,
}

pub struct Config {
    pub state_dir: PathBuf,
    pub seeds: Vec<CarrierAddr>,
    pub unix_listen: Option<PathBuf>,
    /// This node's relay face, if its operator opened one: a reachable address it listens on and states in its record.
    pub relay_face: Option<CarrierAddr>,
    pub serve: BulkServeSlot,
    /// Whether this node's Tor is carrying traffic. This layer never touches Tor: this is the one fact it reads about it.
    pub primary_up: Box<dyn Fn() -> bool + Send + Sync>,
}

pub struct Shared {
    me: Weak<Shared>,
    pub id: Identity,
    view: Mutex<View>,
    keys: Mutex<Keys>,
    epoch_nonce: Mutex<(u64, u64)>,
    links: Mutex<HashMap<NodeId, LinkTx>>,
    link_generation: AtomicU64,
    /// O5 at a gateway: hop id → (the link it registered on, that link's generation). One per link, so at most `LINKS_MAX`.
    /// O1-FOOTPRINT-REVIEWED: bounded by LINKS_MAX entries of 48 bytes, whatever the size of the network.
    hops: Mutex<HashMap<NodeId, (NodeId, u64)>>,
    /// O5 on a node with no address: itself as a hop.
    hop: Mutex<Option<HopSelf>>,
    /// Frames waiting for a link to their target: (kind, body), so a packet for a hop waits for its gateway as `F_VIA`.
    parked: Mutex<HashMap<NodeId, Vec<(u8, Vec<u8>)>>>,
    dialing: Mutex<HashSet<NodeId>>,
    seeds_dialing: Mutex<HashSet<CarrierAddr>>,
    seeds_linked: Mutex<HashMap<CarrierAddr, NodeId>>,
    pub cells_in: Mutex<VecDeque<Vec<u8>>>,
    pub(crate) inbox: Arc<BulkInbox>,
    asks: Mutex<HashMap<[u8; 16], Ask>>,
    pseudonyms: Mutex<HashMap<[u8; 16], (NodeId, u64)>>,
    assembling: Mutex<HashMap<[u8; 16], Assembling>>,
    out_cells: Mutex<VecDeque<(NodeId, Vec<u8>)>>,
    out_bulk: Mutex<VecDeque<(NodeId, Vec<u8>)>>,
    pool: Mutex<BinaryHeap<Delayed>>,
    pool_seq: AtomicU64,
    primary_up: Box<dyn Fn() -> bool + Send + Sync>,
    primary_down_since_ms: AtomicU64,
    primary_up_since_ms: AtomicU64,
    peer_need_until_ms: AtomicU64,
    pub primary_down: AtomicBool,
    pub active: AtomicBool,
    pub counters: Counters,
    rng: Mutex<Rng>,
    relay_face: Option<CarrierAddr>,
    own_unix: Option<PathBuf>,
    seeds: Vec<CarrierAddr>,
    serve: BulkServeSlot,
    serves: Arc<tokio::sync::Semaphore>,
    state_dir: PathBuf,
    handshakes_pending: AtomicUsize,
    handle: tokio::runtime::Handle,
    active_pps: f64,
}

fn frame_inner(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(INNER_HDR + data.len());
    v.push(kind);
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    v
}

fn read_inner(inner: &[u8]) -> Option<(u8, &[u8])> {
    let kind = *inner.first()?;
    let len = u16::from_le_bytes([*inner.get(1)?, *inner.get(2)?]) as usize;
    Some((kind, inner.get(INNER_HDR..INNER_HDR + len)?))
}

fn reply_keystream(key: &[u8; 32], nonce: &[u8], out: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"stream");
    h.update(nonce);
    let mut ks = vec![0u8; out.len()];
    h.finalize_xof().fill(&mut ks);
    for (b, k) in out.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
}

/// `blake3::Hash` compares in constant time.
fn reply_mac(key: &[u8; 32], rid: &[u8], nonce: &[u8], ct: &[u8]) -> blake3::Hash {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"mac");
    h.update(rid);
    h.update(nonce);
    h.update(ct);
    h.finalize()
}

/// The inner framing's parser on hostile bytes, for the fuzz doors and the hostile-bytes pin. No state is read or written.
pub fn hostile_inner_parse(bytes: &[u8]) -> bool {
    read_inner(bytes).is_some()
}

impl Shared {
    pub fn links_count(&self) -> usize {
        lock(&self.links).len()
    }

    fn arc(&self) -> Arc<Self> {
        self.me.upgrade().expect("the mix is alive while its own tasks run")
    }

    fn rate(&self) -> f64 {
        if self.active.load(Ordering::Relaxed) {
            self.active_pps
        } else {
            STANDBY_PPS
        }
    }

    pub fn own_carriers(&self) -> Vec<CarrierAddr> {
        let mut c = Vec::new();
        if let Some(a) = &self.relay_face {
            c.push(a.clone());
        }
        if let Some(p) = &self.own_unix {
            if let Some(text) = p.to_str() {
                if let Some(a) = CarrierAddr::parse(&format!("unix:{text}")) {
                    c.push(a);
                }
            }
        }
        c
    }

    /// This node's own signed record, when it has an address to state (a relay face, or a local path on a rig). A node with no
    /// address publishes none (O5): its long-term id routes nowhere, and sending it was the first frame of every link it
    /// dialled, so each relay it dialled learned which long-term id that IP holds. It is reached as a hop instead (`tick_hop`).
    fn build_own_record(&self) -> Option<Vec<u8>> {
        let carriers = self.own_carriers();
        if carriers.is_empty() {
            return None;
        }
        let (epoch, kem_pk) = {
            let k = lock(&self.keys);
            (k.cur.epoch, k.cur.kem_pk.clone())
        };
        let (nonce_epoch, epoch_nonce) = *lock(&self.epoch_nonce);
        if nonce_epoch != epoch {
            return None;
        }
        let r = Record {
            dsa_pk: self.id.dsa_pk.clone(),
            epoch,
            kem_pk,
            carriers,
            seq: now_ms() / 1000,
            pow_nonce: self.id.pow_nonce,
            epoch_nonce,
        };
        record::encode_signed(&r, &self.id.dsa_sk).map(|raw| {
            lock(&self.view).admit(r, raw.clone(), now_ms(), now_ms(), self.id.id);
            raw
        })
    }

    fn publish_own(&self) {
        if let Some(raw) = self.build_own_record() {
            self.flood(F_RECORD, &raw, None);
        }
    }

    fn flood(&self, kind: u8, body: &[u8], except: Option<NodeId>) {
        let links = lock(&self.links);
        for (id, l) in links.iter() {
            if Some(*id) != except && l.tx.try_send((kind, body.to_vec())).is_err() {
                self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// `link_send`, but only on the link of this generation: a hop's link that closed and was replaced is not its registration's.
    fn link_send_gen(&self, to: &NodeId, generation: u64, kind: u8, body: Vec<u8>) -> bool {
        match lock(&self.links).get(to).filter(|l| l.generation == generation) {
            Some(l) => l.tx.try_send((kind, body)).is_ok(),
            None => false,
        }
    }

    /// The id loops go to: this node's own when it has an address, its hop id once its gateway holds it, else none.
    fn loop_dest(&self) -> Option<NodeId> {
        if !self.own_carriers().is_empty() {
            return Some(self.id.id);
        }
        lock(&self.hop).as_ref().filter(|h| h.registered.is_some()).map(|h| h.ident.id)
    }

    fn link_send(&self, to: &NodeId, kind: u8, body: Vec<u8>) -> bool {
        match lock(&self.links).get(to) {
            Some(l) => {
                if l.tx.try_send((kind, body)).is_err() {
                    self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
                    false
                } else {
                    true
                }
            }
            None => false,
        }
    }

    /// Queues one message to a destination. Bounded: past the cap a cell is dropped, and the layers above re-ask.
    pub fn queue_cell(&self, dest: NodeId, inner: Vec<u8>) {
        let mut q = lock(&self.out_cells);
        if q.len() >= CELLS_OUT_MAX {
            self.counters.dropped_queue.fetch_add(1, Ordering::Relaxed);
            q.pop_front();
        }
        q.push_back((dest, inner));
    }

    /// One public cell, to every neighbour, one hop. Nothing here says who made it, and neighbours pass on what they verify.
    pub fn relay_cell(&self, cell: &[u8]) {
        let txs: Vec<mpsc::Sender<(u8, Vec<u8>)>> = lock(&self.links).values().map(|l| l.tx.clone()).collect();
        for tx in txs {
            if tx.try_send((F_RELAY_CELL, cell.to_vec())).is_err() {
                self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.counters.cells_out.fetch_add(1, Ordering::Relaxed);
    }

    fn take_cell(&self, cell: Vec<u8>) {
        let mut q = lock(&self.cells_in);
        if q.len() >= CELLS_IN_MAX {
            q.pop_front();
            self.counters.dropped_queue.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(cell);
        self.counters.cells_in.fetch_add(1, Ordering::Relaxed);
    }

    /// Asks a neighbour for public chain data, one hop. False when no neighbour could take it, so the caller's other paths run.
    pub fn relay_ask(&self, req: &[u8], link: Option<NodeId>, follow_host: Option<String>, idle_ms: u64) -> bool {
        if req.is_empty() || req.len() > link::FRAME_BODY - RELAY_RID {
            return false;
        }
        let mut rng = lock(&self.rng);
        let peer = match link {
            Some(l) => l,
            None => {
                let peers: Vec<NodeId> = lock(&self.links).keys().copied().collect();
                if peers.is_empty() {
                    return false;
                }
                peers[rng.below(peers.len())]
            }
        };
        let mut rid = [0u8; RELAY_RID];
        rng.fill(&mut rid);
        drop(rng);
        let mut body = Vec::with_capacity(RELAY_RID + req.len());
        body.extend_from_slice(&rid);
        body.extend_from_slice(req);
        if !self.link_send(&peer, F_RELAY_ASK, body) {
            return false;
        }
        crate::arti_transport::bulk_inflight_acquire(req);
        let mut guard = InflightGuard::new(req);
        guard.follow_host = follow_host;
        lock(&self.asks).insert(rid, Ask { guard, key: Zeroizing::new([0u8; 32]), parts: HashMap::new(), total: 0, last_ms: now_ms(), idle_ms });
        self.counters.asks_sent.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// The neighbours a follow can be held open on.
    pub fn linked_peers(&self, n: usize) -> Vec<NodeId> {
        lock(&self.links).keys().take(n).copied().collect()
    }

    /// Answers a neighbour's public ask. Past the serve limit it is dropped on the spot, and the asker re-asks. The sends wait on the
    /// link's own queue, so a slow neighbour holds one of the bounded serve permits and nothing else.
    fn relay_serve(&self, peer: NodeId, rid: [u8; RELAY_RID], req: Vec<u8>) {
        let Ok(permit) = self.serves.clone().try_acquire_owned() else {
            self.counters.dropped_queue.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let me = self.arc();
        self.handle.spawn(async move {
            let _permit = permit;
            let page = crate::arti_transport::bulk_answer(&req, &me.serve).await;
            me.counters.asks_served.fetch_add(1, Ordering::Relaxed);
            let Some(tx) = lock(&me.links).get(&peer).map(|l| l.tx.clone()) else { return };
            let frags = page.len().div_ceil(RELAY_PAGE_DATA).max(1);
            for i in 0..frags {
                let chunk: &[u8] = if page.is_empty() { &[] } else { &page[i * RELAY_PAGE_DATA..((i + 1) * RELAY_PAGE_DATA).min(page.len())] };
                let mut body = Vec::with_capacity(RELAY_PAGE_HDR + chunk.len());
                body.extend_from_slice(&rid);
                body.extend_from_slice(&(i as u32).to_le_bytes());
                body.extend_from_slice(&(frags as u32).to_le_bytes());
                body.extend_from_slice(chunk);
                if tx.send((F_RELAY_PAGE, body)).await.is_err() {
                    return;
                }
            }
        });
    }

    /// One fragment of a page this node asked a neighbour for. The rid is random and only this node and that neighbour hold it.
    fn relay_page(&self, body: &[u8]) {
        let mut rid = [0u8; RELAY_RID];
        rid.copy_from_slice(&body[..RELAY_RID]);
        let idx = u32::from_le_bytes([body[16], body[17], body[18], body[19]]);
        let total = u32::from_le_bytes([body[20], body[21], body[22], body[23]]);
        let max_frags = (crate::arti_transport::BULK_FRAME_MAX / RELAY_PAGE_DATA + 1) as u32;
        if total == 0 || total > max_frags || idx >= total {
            return;
        }
        let finished = {
            let mut asks = lock(&self.asks);
            let Some(a) = asks.get_mut(&rid) else { return };
            if a.total != 0 && a.total != total {
                return;
            }
            a.total = total;
            a.last_ms = now_ms();
            a.parts.insert(idx, body[RELAY_PAGE_HDR..].to_vec());
            if a.parts.len() == total as usize {
                asks.remove(&rid)
            } else {
                None
            }
        };
        if let Some(a) = finished {
            self.finish_ask(a);
        }
    }

    fn finish_ask(&self, mut a: Ask) {
        let mut page = Vec::new();
        for i in 0..a.total {
            match a.parts.remove(&i) {
                Some(p) => page.extend_from_slice(&p),
                None => return,
            }
        }
        self.counters.asks_answered.fetch_add(1, Ordering::Relaxed);
        // The same accounting as the Tor lane: an empty answer delivers nothing, and a page takes its ask's key with it.
        if !page.is_empty() {
            a.guard.delivered = true;
            a.guard.deposited = self.inbox.deposit(page, Some(a.guard.key));
        }
    }

    /// One real cell from the node above, to the cell fanout.
    pub fn send_cell(&self, cell: &[u8]) {
        let dests = lock(&self.view).fanout(epoch_now(now_ms()), FANOUT);
        let need = self.primary_down.load(Ordering::Relaxed) as u8;
        let mut data = Vec::with_capacity(1 + cell.len());
        data.push(need);
        data.extend_from_slice(cell);
        let inner = frame_inner(K_CELL, &data);
        for d in dests {
            self.queue_cell(d, inner.clone());
        }
        self.counters.cells_out.fetch_add(1, Ordering::Relaxed);
    }

    fn take_next(&self, turn: bool) -> Option<(NodeId, Vec<u8>)> {
        if turn {
            if let Some(x) = lock(&self.out_cells).pop_front() {
                return Some(x);
            }
            lock(&self.out_bulk).pop_front()
        } else {
            if let Some(x) = lock(&self.out_bulk).pop_front() {
                return Some(x);
            }
            lock(&self.out_cells).pop_front()
        }
    }

    /// One slot of the pump: the next real message, else cover. A real message is never sent ahead of its slot and no slot
    /// goes empty, so the sending rate says nothing about the load.
    fn emit_one(&self, turn: bool, mean_delay: f64) {
        let now = now_ms();
        let epoch = epoch_now(now);
        let next = self.take_next(turn);
        let loop_to = if next.is_none() { self.loop_dest() } else { None };
        let mut rng = lock(&self.rng);
        let (dest, inner, real) = match next {
            Some((d, i)) => (d, i, true),
            None => {
                // Half loops to this node, half drops to a random one. Loops also tell this node the mix is working. A node with
                // no way back to it yet (no address, its gateway not holding it) drops instead, so its slot never goes empty.
                if let (Some(me), 0) = (loop_to, rng.below(2)) {
                    let data = now.to_le_bytes();
                    self.counters.loops_sent.fetch_add(1, Ordering::Relaxed);
                    (me, frame_inner(K_LOOP, &data), false)
                } else {
                    match lock(&self.view).random_other(epoch, &mut rng) {
                        Some(d) => (d, frame_inner(K_DROP, &[]), false),
                        None => return,
                    }
                }
            }
        };
        let route = lock(&self.view).route(&dest, now, mean_delay, &mut rng);
        let Some(route) = route else {
            if real {
                self.counters.dropped_queue.fetch_add(1, Ordering::Relaxed); // counted, so a lost message is never silent
            }
            return;
        };
        let Some(pkt) = packet::build(&route, &inner, &mut rng) else { return };
        let first = route[0].id;
        drop(rng);
        if real {
            self.counters.sent_real.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.sent_cover.fetch_add(1, Ordering::Relaxed);
        }
        self.send_packet(first, pkt);
    }

    /// The ONE place a packet leaves for its next hop (ROOT-LAYER for O5): to this node itself, down a registered hop's link
    /// (this node is its gateway), down a link to it, through its gateway as `F_VIA` when it is a hop elsewhere, or parked while
    /// a link to whichever of those is dialled.
    fn send_packet(&self, next: NodeId, pkt: Vec<u8>) {
        if next == self.id.id || lock(&self.hop).as_ref().is_some_and(|h| h.ident.id == next) {
            self.handle_packet(&pkt);
            return;
        }
        let held = lock(&self.hops).get(&next).copied();
        if let Some((link, generation)) = held {
            if self.link_send_gen(&link, generation, F_PACKET, pkt) {
                self.counters.hop_forwarded.fetch_add(1, Ordering::Relaxed);
            } else {
                self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        let linked = lock(&self.links).contains_key(&next);
        if linked {
            self.link_send(&next, F_PACKET, pkt);
            return;
        }
        let via = lock(&self.view).via_of(&next);
        let (target, kind, body) = match via {
            // This node is the gateway its record names, but holds no registration for it (it left, or has not registered yet).
            Some(g) if g == self.id.id => {
                self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Some(g) => {
                let mut b = Vec::with_capacity(32 + pkt.len());
                b.extend_from_slice(&next);
                b.extend_from_slice(&pkt);
                (g, F_VIA, b)
            }
            None => (next, F_PACKET, pkt),
        };
        if lock(&self.links).contains_key(&target) {
            self.link_send(&target, kind, body);
            return;
        }
        {
            let mut p = lock(&self.parked);
            if p.len() >= PARKED_TARGETS && !p.contains_key(&target) {
                self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let q = p.entry(target).or_default();
            if q.len() >= PARKED_PER_TARGET {
                self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
                return;
            }
            q.push((kind, body));
        }
        self.dial_soon(target);
    }

    /// O5 at a gateway: one `F_VIA` frame, `hop id ‖ packet`, down the hop's own link. Nothing is peeled here; an id this
    /// gateway holds no registration for is dropped and counted.
    fn forward_via(&self, body: &[u8]) {
        let mut x = [0u8; 32];
        x.copy_from_slice(&body[..32]);
        let held = lock(&self.hops).get(&x).copied();
        match held {
            Some((link, generation)) if self.link_send_gen(&link, generation, F_PACKET, body[32..].to_vec()) => {
                self.counters.hop_forwarded.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// O5 at a gateway, the F_HOP door. (1) work: `verify_record` checks the identity's work and this epoch's rent; (2) the
    /// record's own ML-DSA signature, by `verify_record`; (3) no value moves here; (4) a replay: the record's (epoch, seq) is
    /// refused as Old by the view, and the registration needs the proof over THIS link's binding; (5) work bounded by the link's
    /// record budget (`RECORDS_PER_MINUTE`, shared with F_RECORD); (6) parity with F_RECORD: the same `verify_record` and the
    /// same view door, plus: it must name this node as its only carrier. (7) scale: one hop per link, `LINKS_MAX` at most.
    /// (8) a proof (a signature only the hop key can make over this link's binding); a lying record gains nothing past it.
    fn check_hop_record(&self, raw: &[u8]) -> Option<Record> {
        let r = record::verify_record(raw, Some(epoch_now(now_ms()))).ok()?;
        let only_me = r.carriers.len() == 1 && r.carriers[0] == CarrierAddr::Via(self.id.id);
        (only_me && record::id_of(&r.dsa_pk) != self.id.id).then_some(r)
    }

    /// O5 at a gateway, the F_HOP_PROOF door: the hop key's signature over this link's binding. Then the hop is held, one per
    /// link, and its record goes into the view and out to the network like any new record.
    fn register_at_gateway(&self, peer: NodeId, generation: u64, binding: &[u8; 32], r: Record, raw: Vec<u8>, sig: &[u8]) {
        let id = record::id_of(&r.dsa_pk);
        if !crate::pqauth::ml_dsa_verify(&hop_statement(binding, &id, r.epoch), &r.dsa_pk, sig) {
            self.counters.hops_refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
        {
            let mut hops = lock(&self.hops);
            hops.retain(|k, v| *k == id || *v != (peer, generation));
            if !hops.contains_key(&id) && hops.len() >= LINKS_MAX {
                self.counters.hops_refused.fetch_add(1, Ordering::Relaxed);
                return;
            }
            hops.insert(id, (peer, generation));
        }
        self.counters.hops_registered.fetch_add(1, Ordering::Relaxed);
        let now = now_ms();
        if lock(&self.view).admit(r, raw.clone(), now, now, id) == Admit::New {
            self.counters.records_new.fetch_add(1, Ordering::Relaxed);
            self.flood(F_RECORD, &raw, Some(peer));
        }
    }

    /// O5 on a node with no address: be a hop through a relay face this node is linked to. Picks a gateway (the saved hop
    /// identity's, when it is linked; else one at random), mints a hop identity for it (per gateway, never reused across
    /// gateways), pays that identity's epoch rent, and registers over the gateway's link once per epoch and per link. A gateway
    /// gone for `HOP_GATEWAY_LOST_MS` is replaced, with a new hop identity.
    /// cons: disk — one file, `mix-hop.key`, 32 + 1,952 + 8 + 4,032 ≈ 6.0 KB, rewritten only when this node changes gateway
    /// (at most once per HOP_GATEWAY_LOST_MS = 60 s, in practice once per lost gateway): f(fixed constants), never f(history).
    /// CPU — one identity mint per new gateway (2^24 blake3 calls, ~2 s) and one epoch rent per hour (2^22, under a second).
    /// Wire — two frames (~9.8 KB) to the gateway once an hour.
    async fn tick_hop(self: Arc<Self>) {
        if !self.own_carriers().is_empty() || super::network_choice() == super::NetworkChoice::TorOnly {
            if lock(&self.hop).take().is_some() {
                lock(&self.view).set_alias(None);
            }
            return;
        }
        let now = now_ms();
        let epoch = lock(&self.keys).cur.epoch;
        let links: Vec<(NodeId, u64, [u8; 32])> = lock(&self.links).iter().map(|(id, l)| (*id, l.generation, l.binding)).collect();
        let faces: Vec<(NodeId, u64, [u8; 32])> = {
            let v = lock(&self.view);
            links
                .into_iter()
                .filter(|(id, _, _)| v.get(id).is_some_and(|e| e.record.carriers.iter().any(|c| matches!(c, CarrierAddr::Relay(_)))))
                .collect()
        };
        let gateway = lock(&self.hop).as_ref().map(|h| h.gateway);
        let mut target = None;
        if let Some(gw) = gateway {
            if let Some(f) = faces.iter().find(|f| f.0 == gw) {
                if let Some(h) = lock(&self.hop).as_mut() {
                    h.lost_since_ms = 0;
                }
                target = Some(*f);
            } else {
                let mut g = lock(&self.hop);
                let Some(h) = g.as_mut() else { return };
                if h.lost_since_ms == 0 {
                    h.lost_since_ms = now;
                }
                if now.saturating_sub(h.lost_since_ms) < HOP_GATEWAY_LOST_MS || faces.is_empty() {
                    return;
                }
            }
        }
        let (gw, generation, binding) = match target {
            Some(f) => f,
            None => {
                if faces.is_empty() {
                    return;
                }
                let path = self.state_dir.join("mix-hop.key");
                // O1-INFINITY-REVIEWED: this node's own hop key, one fixed-size file (32 + ~6 KB); no chain state is read from it.
                let saved = std::fs::read(&path).ok();
                let pick = saved
                    .as_ref()
                    .and_then(|b| b.get(..32))
                    .and_then(|g| faces.iter().find(|f| f.0[..] == *g))
                    .copied()
                    .unwrap_or_else(|| {
                        let i = lock(&self.rng).below(faces.len());
                        faces[i]
                    });
                let gw = pick.0;
                let minted = tokio::task::spawn_blocking(move || {
                    if let Some(b) = saved {
                        if b.len() > 32 && b[..32] == gw[..] {
                            if let Some(i) = Identity::from_file_bytes(&b[32..]) {
                                return i;
                            }
                        }
                    }
                    let i = Identity::mint();
                    let mut out = Zeroizing::new(gw.to_vec());
                    out.extend_from_slice(&i.file_bytes());
                    // LOCAL-STORAGE-REQUIRED: this node's own hop key (no proof or wire field can hold a private key).
                    // bound: one file of ~6.0 KB, rewritten in place on a gateway change — never a term in height, blocks or notes.
                    record::save_secret(&path, &out, "the hop identity");
                    i
                })
                .await;
                let Ok(ident) = minted else { return };
                lock(&self.view).set_alias(Some(ident.id));
                *lock(&self.hop) =
                    Some(HopSelf { ident, gateway: gw, rent: (u64::MAX, 0), registered: None, sent: None, sent_at_ms: 0, lost_since_ms: 0 });
                pick
            }
        };
        let resend = {
            let g = lock(&self.hop);
            match g.as_ref() {
                Some(h) if h.registered == Some((generation, epoch)) => {
                    if now.saturating_sub(h.sent_at_ms) < HOP_REFRESH_MS {
                        return;
                    }
                    h.sent.clone()
                }
                _ => None,
            }
        };
        if let Some((raw, proof)) = resend {
            let tx = lock(&self.links).get(&gw).filter(|l| l.generation == generation).map(|l| l.tx.clone());
            if let Some(tx) = tx {
                if tx.try_send((F_HOP, raw)).is_ok() && tx.try_send((F_HOP_PROOF, proof)).is_ok() {
                    if let Some(h) = lock(&self.hop).as_mut() {
                        h.sent_at_ms = now;
                    }
                }
            }
            return;
        }
        let rent_for = lock(&self.hop).as_ref().and_then(|h| (h.rent.0 != epoch).then(|| h.ident.dsa_pk.clone()));
        if let Some(pk) = rent_for {
            let Ok(n) = tokio::task::spawn_blocking(move || record::mine_epoch_work(&pk, epoch)).await else { return };
            if let Some(h) = lock(&self.hop).as_mut() {
                h.rent = (epoch, n);
            }
        }
        self.register_hop(gw, generation, binding, epoch);
    }

    /// Sends this node's hop record and its proof over the gateway's link, in order, and holds the record in its own view (the
    /// destination of its own loops). Never on any other link.
    fn register_hop(&self, gw: NodeId, generation: u64, binding: [u8; 32], epoch: u64) {
        let kem_pk = {
            let k = lock(&self.keys);
            if k.cur.epoch != epoch {
                return;
            }
            k.cur.kem_pk.clone()
        };
        let (raw, proof, rec, id) = {
            let g = lock(&self.hop);
            let Some(h) = g.as_ref() else { return };
            if h.gateway != gw || h.rent.0 != epoch {
                return;
            }
            // The hop's packets peel under this node's own epoch key: the long-term record that held the same key is never
            // published (`build_own_record`), so nothing ties the two.
            let r = Record {
                dsa_pk: h.ident.dsa_pk.clone(),
                epoch,
                kem_pk,
                carriers: vec![CarrierAddr::Via(gw)],
                seq: now_ms() / 1000,
                pow_nonce: h.ident.pow_nonce,
                epoch_nonce: h.rent.1,
            };
            let Some(raw) = record::encode_signed(&r, &h.ident.dsa_sk) else { return };
            let Some(proof) = crate::pqauth::ml_dsa_sign(&hop_statement(&binding, &h.ident.id, epoch), &h.ident.dsa_sk) else { return };
            (raw, proof, r, h.ident.id)
        };
        let Some(tx) = lock(&self.links).get(&gw).filter(|l| l.generation == generation).map(|l| l.tx.clone()) else { return };
        let proof_copy = proof.clone();
        if tx.try_send((F_HOP, raw.clone())).is_err() || tx.try_send((F_HOP_PROOF, proof)).is_err() {
            self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let now = now_ms();
        lock(&self.view).admit(rec, raw.clone(), now, now, id);
        if let Some(h) = lock(&self.hop).as_mut() {
            h.registered = Some((generation, epoch));
            h.sent = Some((raw, proof_copy));
            h.sent_at_ms = now;
        }
    }

    fn dial_soon(&self, target: NodeId) {
        if !lock(&self.dialing).insert(target) {
            return;
        }
        let me = self.arc();
        self.handle.spawn(async move {
            let addrs = lock(&me.view).carriers_of(&target);
            let mut ok = false;
            for a in addrs {
                if let Some(stream) = me.dial(&a).await {
                    ok = me.clone().initiate_link(stream, Some(target)).await.is_some();
                    if ok {
                        break;
                    }
                }
            }
            lock(&me.dialing).remove(&target);
            if !ok {
                me.counters.dials_failed.fetch_add(1, Ordering::Relaxed);
                lock(&me.parked).remove(&target);
            }
        });
    }

    async fn dial(&self, addr: &CarrierAddr) -> Option<BoxStream> {
        // A direct connection answers or fails within seconds, with no router or descriptor to wait on.
        let budget = std::time::Duration::from_secs(DIAL_SECS);
        tokio::time::timeout(budget, carrier::dial(addr, self.own_unix.as_ref())).await.ok()?
    }

    async fn initiate_link(self: Arc<Self>, mut stream: BoxStream, expect: Option<NodeId>) -> Option<NodeId> {
        match link::initiate(&mut stream, expect).await {
            Some((peer, keys)) if peer != self.id.id => {
                self.clone().install_link(stream, peer, keys);
                Some(peer)
            }
            _ => {
                self.counters.handshakes_failed.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    async fn respond_link(self: Arc<Self>, mut stream: BoxStream) {
        if lock(&self.links).len() >= LINKS_MAX || super::network_choice() == super::NetworkChoice::TorOnly {
            return;
        }
        let pending = self.handshakes_pending.fetch_add(1, Ordering::Relaxed);
        if pending >= HANDSHAKES_PENDING_MAX {
            self.handshakes_pending.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        let me = Me { dsa_pk: &self.id.dsa_pk, dsa_sk: &self.id.dsa_sk, pow_nonce: self.id.pow_nonce };
        let mut rng = Rng::new();
        let res = link::respond(&mut stream, &me, link::puzzle_bits(pending), &mut rng).await;
        self.handshakes_pending.fetch_sub(1, Ordering::Relaxed);
        match res {
            Some((peer, keys)) if peer != self.id.id => self.clone().install_link(stream, peer, keys),
            _ => {
                self.counters.handshakes_failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn install_link(self: Arc<Self>, stream: BoxStream, peer: NodeId, keys: LinkKeys) {
        let (tx, mut rx) = mpsc::channel::<(u8, Vec<u8>)>(LINK_QUEUE);
        let generation = self.link_generation.fetch_add(1, Ordering::Relaxed);
        let binding = keys.binding;
        lock(&self.links).insert(peer, LinkTx { generation, tx: tx.clone(), binding });
        self.counters.links_up.fetch_add(1, Ordering::Relaxed);
        let keys = Arc::new(Mutex::new(keys));
        let (mut r, mut w) = tokio::io::split(stream);

        // On a new link: this node's record, a sample of what it knows, then whatever was waiting for this neighbour.
        if let Some(raw) = self.build_own_record() {
            if tx.try_send((F_RECORD, raw)).is_err() {
                self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.share_sample(&tx, 8);
        if let Some(waiting) = lock(&self.parked).remove(&peer) {
            for (kind, p) in waiting {
                if tx.try_send((kind, p)).is_err() {
                    self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let wkeys = keys.clone();
        tokio::spawn(async move {
            let mut rng = Rng::new();
            while let Some((kind, body)) = rx.recv().await {
                let frame = link::seal(&mut lock(&wkeys), kind, &body, &mut rng);
                let Some(frame) = frame else { continue };
                if w.write_all(&frame).await.is_err() || w.flush().await.is_err() {
                    break;
                }
            }
        });

        let me = self.clone();
        tokio::spawn(async move {
            let mut wire = vec![0u8; link::FRAME_WIRE];
            let (mut tokens, mut last) = (INTAKE_PPS, std::time::Instant::now());
            let mut bad_streak = 0u32;
            let (mut rec_budget, mut rec_at) = (RECORDS_PER_MINUTE, std::time::Instant::now());
            // O5: the latest hop record on this link, waiting for its proof.
            let mut hop_pending: Option<(Record, Vec<u8>)> = None;
            loop {
                let read = tokio::time::timeout(std::time::Duration::from_secs(LINK_IDLE_SECS), r.read_exact(&mut wire)).await;
                if !matches!(read, Ok(Ok(_))) {
                    break;
                }
                let opened = link::open(&mut lock(&keys), &wire);
                let Some((kind, body)) = opened else { break };
                // The proof pairs with the latest hop record on this link; other frames may come between (one queue, many senders).
                let pending = if kind == F_HOP_PROOF { hop_pending.take() } else { None };
                match kind {
                    F_PACKET => {
                        tokens = (tokens + last.elapsed().as_secs_f64() * INTAKE_PPS).min(INTAKE_PPS);
                        last = std::time::Instant::now();
                        if tokens < 1.0 {
                            me.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        tokens -= 1.0;
                        if me.handle_packet(&body) {
                            bad_streak = 0;
                        } else {
                            bad_streak += 1;
                            if bad_streak >= BAD_STREAK_MAX {
                                me.counters.links_closed_bad.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                    F_RECORD => {
                        if rec_at.elapsed().as_secs() >= 60 {
                            rec_budget = RECORDS_PER_MINUTE;
                            rec_at = std::time::Instant::now();
                        }
                        if rec_budget > 0 {
                            rec_budget -= 1;
                            me.handle_record(&body, peer);
                        }
                    }
                    F_REGISTER if body.len() == 16 => {
                        let mut rid = [0u8; 16];
                        rid.copy_from_slice(&body);
                        let mut p = lock(&me.pseudonyms);
                        // One neighbour cannot fill the table and shut out the others.
                        let held = p.values().filter(|v| v.0 == peer).count();
                        if p.len() < PSEUDONYMS_MAX && held < PSEUDONYMS_PER_LINK {
                            p.insert(rid, (peer, now_ms() + PSEUDONYM_TTL_MS));
                        }
                    }
                    F_DELIVER if body.len() > 16 => {
                        let mut rid = [0u8; 16];
                        rid.copy_from_slice(&body[..16]);
                        me.handle_reply(&rid, &body[16..]);
                    }
                    // The relay plane. Whatever arrives here faces the same doors as from Tor: the node above verifies every cell and
                    // page, and neither side's identity plays any part.
                    F_RELAY_CELL if body.len() == crate::net::CELL_SIZE => me.take_cell(body),
                    F_RELAY_ASK if body.len() > RELAY_RID => {
                        let mut rid = [0u8; RELAY_RID];
                        rid.copy_from_slice(&body[..RELAY_RID]);
                        me.relay_serve(peer, rid, body[RELAY_RID..].to_vec());
                    }
                    F_RELAY_PAGE if body.len() >= RELAY_PAGE_HDR => me.relay_page(&body),
                    // O5, at a gateway. A hop record costs the link's record budget like any record.
                    F_HOP => {
                        if rec_at.elapsed().as_secs() >= 60 {
                            rec_budget = RECORDS_PER_MINUTE;
                            rec_at = std::time::Instant::now();
                        }
                        hop_pending = None;
                        if rec_budget > 0 {
                            rec_budget -= 1;
                            match me.check_hop_record(&body) {
                                Some(r) => hop_pending = Some((r, body)),
                                None => {
                                    me.counters.hops_refused.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    F_HOP_PROOF => match pending {
                        Some((r, raw)) => me.register_at_gateway(peer, generation, &binding, r, raw, &body),
                        None => {
                            me.counters.hops_refused.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    // A packet for a hop this node is the gateway of. It costs the sender's intake like a packet.
                    F_VIA if body.len() == 32 + packet::PACKET => {
                        tokens = (tokens + last.elapsed().as_secs_f64() * INTAKE_PPS).min(INTAKE_PPS);
                        last = std::time::Instant::now();
                        if tokens < 1.0 {
                            me.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        tokens -= 1.0;
                        me.forward_via(&body);
                    }
                    // A frame kind from a newer version, or a malformed one: ignored, so nodes upgrade one at a time. It
                    // costs the sender a frame of its intake and nothing else.
                    _ => {
                        me.counters.frames_unknown.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            {
                let mut links = lock(&me.links);
                if links.get(&peer).is_some_and(|l| l.generation == generation) {
                    links.remove(&peer);
                }
            }
            // A hop registered on this link is held no longer: its packets are dropped here until it registers again.
            lock(&me.hops).retain(|_, v| *v != (peer, generation));
        });
    }

    fn share_sample(&self, tx: &mpsc::Sender<(u8, Vec<u8>)>, n: usize) {
        // Never this node's own hop record: only its gateway learns it first-hand (O5).
        let raws: Vec<Vec<u8>> = lock(&self.view).sample_raws();
        if raws.is_empty() {
            return;
        }
        let mut rng = lock(&self.rng);
        for _ in 0..n.min(raws.len()) {
            let i = rng.below(raws.len());
            if tx.try_send((F_RECORD, raws[i].clone())).is_err() {
                self.counters.dropped_link.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn handle_record(&self, raw: &[u8], source: NodeId) {
        let now = now_ms();
        match record::verify_record(raw, Some(epoch_now(now))) {
            Ok(r) => {
                // Its own records, under either name, come back through gossip: never re-admitted or passed on from here.
                if lock(&self.view).is_self(&record::id_of(&r.dsa_pk)) {
                    return;
                }
                if lock(&self.view).admit(r, raw.to_vec(), now, now, source) == Admit::New {
                    self.counters.records_new.fetch_add(1, Ordering::Relaxed);
                    self.flood(F_RECORD, raw, Some(source));
                }
            }
            Err(_) => {
                self.counters.records_refused.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn peel_here(&self, pkt: &[u8]) -> Result<Peeled, Refused> {
        let mut k = lock(&self.keys);
        let Keys { cur, prev } = &mut *k;
        match prev {
            Some(p) => {
                let mut held = [HopKey { sk: &cur.sk, replay: &mut cur.replay }, HopKey { sk: &p.sk, replay: &mut p.replay }];
                packet::peel(pkt, &mut held)
            }
            None => {
                let mut held = [HopKey { sk: &cur.sk, replay: &mut cur.replay }];
                packet::peel(pkt, &mut held)
            }
        }
    }

    /// One packet at this hop. Answers whether it was good: a refused one goes nowhere and nothing about it is sent back.
    fn handle_packet(&self, pkt: &[u8]) -> bool {
        match self.peel_here(pkt) {
            Ok(Peeled::Forward { next, delay_ms, packet }) => {
                self.counters.relayed.fetch_add(1, Ordering::Relaxed);
                self.schedule(delay_ms, Action::Send(next, packet));
                true
            }
            Ok(Peeled::Deliver { delay_ms, inner }) => {
                self.counters.delivered.fetch_add(1, Ordering::Relaxed);
                self.schedule(delay_ms, Action::Deliver(inner));
                true
            }
            Err(e) => {
                let c = match e {
                    Refused::BadMac => &self.counters.bad_mac,
                    Refused::Replay => &self.counters.replays,
                    Refused::Tagged => &self.counters.tagged,
                    Refused::WrongSize => &self.counters.wrong_size,
                };
                c.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn schedule(&self, delay_ms: u32, action: Action) {
        let mut pool = lock(&self.pool);
        if pool.len() >= POOL_MAX {
            self.counters.dropped_pool.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let seq = self.pool_seq.fetch_add(1, Ordering::Relaxed);
        pool.push(Delayed { due_ms: now_ms() + delay_ms as u64, seq, action });
    }

    fn run_due(&self) {
        let now = now_ms();
        loop {
            let item = {
                let mut pool = lock(&self.pool);
                match pool.peek() {
                    Some(top) if top.due_ms <= now => pool.pop(),
                    _ => None,
                }
            };
            let Some(item) = item else { return };
            match item.action {
                Action::Send(next, p) => self.send_packet(next, p),
                Action::Deliver(inner) => self.handle_inner(&inner),
            }
        }
    }

    fn handle_inner(&self, inner: &[u8]) {
        let Some((kind, data)) = read_inner(inner) else { return };
        match kind {
            K_DROP => {}
            K_LOOP if data.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(data);
                self.counters.loops_back.fetch_add(1, Ordering::Relaxed);
                self.counters.loop_ms_sum.fetch_add(now_ms().saturating_sub(u64::from_le_bytes(b)), Ordering::Relaxed);
            }
            K_CELL if data.len() == crate::net::CELL_SIZE + 1 => {
                if data[0] == 1 {
                    self.peer_need_until_ms.store(now_ms() + PEER_NEED_MS, Ordering::Relaxed);
                }
                self.take_cell(data[1..].to_vec());
            }
            K_ASK if data.len() > ASK_HDR => self.handle_ask_frag(data),
            K_REPLY if data.len() > 16 => {
                let mut rid = [0u8; 16];
                rid.copy_from_slice(&data[..16]);
                let held = lock(&self.pseudonyms).get(&rid).map(|x| x.0);
                match held {
                    Some(client) => {
                        self.counters.replies_relayed.fetch_add(1, Ordering::Relaxed);
                        self.link_send(&client, F_DELIVER, data.to_vec());
                    }
                    None => self.handle_reply(&rid, &data[16..]),
                }
            }
            _ => {}
        }
    }

    fn handle_ask_frag(&self, data: &[u8]) {
        let mut rid = [0u8; 16];
        rid.copy_from_slice(&data[..16]);
        let mut gateway = [0u8; 32];
        gateway.copy_from_slice(&data[16..48]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[48..80]);
        let total = u16::from_le_bytes([data[80], data[81]]);
        let idx = u16::from_le_bytes([data[82], data[83]]);
        if total == 0 || total as usize > PUSH_FRAGS_MAX || idx >= total {
            return;
        }
        let large = total as usize > ASK_FRAGS_MAX;
        let done = {
            let mut a = lock(&self.assembling);
            if !a.contains_key(&rid) && a.len() >= ASSEMBLING_MAX {
                return;
            }
            // Only a transaction push is this large, and only a few assemble at once, so this node holds at most
            // PUSHES_ASSEMBLING_MAX × PUSH_FRAGS_MAX fragments for them however many arrive.
            if large && !a.contains_key(&rid) && a.values().filter(|e| e.total as usize > ASK_FRAGS_MAX).count() >= PUSHES_ASSEMBLING_MAX {
                return;
            }
            let e = a.entry(rid).or_insert_with(|| Assembling { gateway, key: Zeroizing::new(key), total, parts: HashMap::new(), last_ms: now_ms() });
            e.last_ms = now_ms();
            if e.total != total {
                return;
            }
            e.parts.insert(idx, data[ASK_HDR..].to_vec());
            if e.parts.len() == total as usize {
                a.remove(&rid)
            } else {
                None
            }
        };
        if let Some(mut e) = done {
            let mut req = Vec::new();
            for i in 0..e.total {
                match e.parts.remove(&i) {
                    Some(p) => req.extend_from_slice(&p),
                    None => return,
                }
            }
            self.serve_ask(rid, e.gateway, e.key.clone(), req);
        }
    }

    /// An ask past the serve limit is dropped on the spot, never queued as a task: the asker re-asks, and a flood of asks
    /// cannot grow this node's task count or starve anything else it does.
    fn serve_ask(&self, rid: [u8; 16], gateway: NodeId, key: Zeroizing<[u8; 32]>, req: Vec<u8>) {
        let Ok(permit) = self.serves.clone().try_acquire_owned() else {
            self.counters.dropped_queue.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let me = self.arc();
        self.handle.spawn(async move {
            let _permit = permit;
            let page = crate::arti_transport::bulk_answer(&req, &me.serve).await;
            me.counters.asks_served.fetch_add(1, Ordering::Relaxed);
            me.queue_page(&rid, gateway, &key, &page);
        });
    }

    fn queue_page(&self, rid: &[u8; 16], gateway: NodeId, key: &[u8; 32], page: &[u8]) {
        let frags = page.len().div_ceil(REPLY_DATA).max(1);
        let mut rng = lock(&self.rng);
        let mut q = lock(&self.out_bulk);
        // A page that cannot fit goes as an empty answer, so the asker is not left waiting on it.
        let (page, frags) = if q.len() + frags > BULK_OUT_MAX {
            self.counters.dropped_queue.fetch_add(1, Ordering::Relaxed);
            (&[][..], 1)
        } else {
            (page, frags)
        };
        for i in 0..frags {
            let chunk: &[u8] = if page.is_empty() { &[] } else { &page[i * REPLY_DATA..((i + 1) * REPLY_DATA).min(page.len())] };
            let mut plain = vec![0u8; REPLY_CIPHER];
            plain[..4].copy_from_slice(&(i as u32).to_le_bytes());
            plain[4..8].copy_from_slice(&(frags as u32).to_le_bytes());
            plain[8..10].copy_from_slice(&(chunk.len() as u16).to_le_bytes());
            plain[REPLY_HDR..REPLY_HDR + chunk.len()].copy_from_slice(chunk);
            let mut nonce = [0u8; 16];
            rng.fill(&mut nonce);
            reply_keystream(key, &nonce, &mut plain);
            let tag = reply_mac(key, rid, &nonce, &plain);
            let mut data = Vec::with_capacity(16 + 16 + plain.len() + 32);
            data.extend_from_slice(rid);
            data.extend_from_slice(&nonce);
            data.extend_from_slice(&plain);
            data.extend_from_slice(tag.as_bytes());
            q.push_back((gateway, frame_inner(K_REPLY, &data)));
        }
    }

    fn handle_reply(&self, rid: &[u8; 16], rest: &[u8]) {
        if rest.len() != 16 + REPLY_CIPHER + 32 {
            return;
        }
        let (nonce, tail) = rest.split_at(16);
        let (ct, tag) = tail.split_at(REPLY_CIPHER);
        let finished = {
            let mut asks = lock(&self.asks);
            let Some(a) = asks.get_mut(rid) else { return };
            if reply_mac(&a.key, rid, nonce, ct) != *tag {
                return;
            }
            let mut plain = ct.to_vec();
            reply_keystream(&a.key, nonce, &mut plain);
            let idx = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]);
            let total = u32::from_le_bytes([plain[4], plain[5], plain[6], plain[7]]);
            let len = u16::from_le_bytes([plain[8], plain[9]]) as usize;
            let max_frags = (crate::arti_transport::BULK_FRAME_MAX / REPLY_DATA + 1) as u32;
            if total == 0 || total > max_frags || idx >= total || len > REPLY_DATA {
                return;
            }
            if a.total != 0 && a.total != total {
                return;
            }
            a.total = total;
            a.last_ms = now_ms();
            a.parts.insert(idx, plain[REPLY_HDR..REPLY_HDR + len].to_vec());
            if a.parts.len() == total as usize {
                asks.remove(rid)
            } else {
                None
            }
        };
        if let Some(a) = finished {
            self.finish_ask(a);
        }
    }

    /// Sends one ask. False when nothing could carry it, so the caller's other paths still run. `follow_host` is held in the
    /// guard, and `host` is who answers; otherwise a random node does.
    pub fn ask(&self, req: &[u8], host: Option<NodeId>, follow_host: Option<String>, idle_ms: u64) -> bool {
        let now = now_ms();
        let epoch = epoch_now(now);
        let frags_max = if crate::arti_transport::is_tx_push_ask(req) { PUSH_FRAGS_MAX } else { ASK_FRAGS_MAX };
        if req.is_empty() || req.len() > ASK_FRAG * frags_max {
            return false;
        }
        let mut rng = lock(&self.rng);
        let host = match host {
            Some(h) => h,
            None => match lock(&self.view).random_other(epoch, &mut rng) {
                Some(h) => h,
                None => return false,
            },
        };
        // The neighbour that takes the reply. Not the host while another is linked: the host would know its asker.
        // Only a neighbour the view can route to: a peer that dialled in is linked under a throwaway id with no record, so a reply
        // sent to it has no route and was dropped without a word. MEASURED: 67 of 94 transaction fetches timed out with 0 fragments
        // on three real nodes, each holding one of the two data-page slots for 20 s, and the fold's by-id record ask starved behind
        // them for about 200 s after Tor went down. ROOT-LAYER: the one place a reply's carrier is chosen.
        // MUST-STAY-GREEN: `scripts/mix/mix_outage.py`. cons: none, a peer that only dialled in can never carry a reply anyway.
        let linked: Vec<NodeId> = lock(&self.links).keys().copied().collect();
        let neighbours: Vec<NodeId> = {
            let view = lock(&self.view);
            linked.into_iter().filter(|n| view.get(n).is_some()).collect()
        };
        if neighbours.is_empty() {
            return false;
        }
        let others: Vec<NodeId> = neighbours.iter().copied().filter(|n| *n != host).collect();
        let pick_from = if others.is_empty() { &neighbours } else { &others };
        let gateway = pick_from[rng.below(pick_from.len())];
        let mut rid = [0u8; 16];
        rng.fill(&mut rid);
        let key = rng.bytes32();
        drop(rng);
        if !self.link_send(&gateway, F_REGISTER, rid.to_vec()) {
            return false;
        }
        crate::arti_transport::bulk_inflight_acquire(req);
        let mut guard = InflightGuard::new(req);
        guard.follow_host = follow_host;
        lock(&self.asks).insert(rid, Ask { guard, key: Zeroizing::new(key), parts: HashMap::new(), total: 0, last_ms: now, idle_ms });
        let frags = req.len().div_ceil(ASK_FRAG);
        let mut q = lock(&self.out_bulk);
        for i in 0..frags {
            let chunk = &req[i * ASK_FRAG..((i + 1) * ASK_FRAG).min(req.len())];
            let mut data = Vec::with_capacity(ASK_HDR + chunk.len());
            data.extend_from_slice(&rid);
            data.extend_from_slice(&gateway);
            data.extend_from_slice(&key);
            data.extend_from_slice(&(frags as u16).to_le_bytes());
            data.extend_from_slice(&(i as u16).to_le_bytes());
            data.extend_from_slice(chunk);
            // An ask goes ahead of page fragments, so a large page in the queue cannot starve the next ask.
            q.push_front((host, frame_inner(K_ASK, &data)));
        }
        self.counters.asks_sent.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn follow_hosts(&self, n: usize) -> Vec<NodeId> {
        lock(&self.view).fanout(epoch_now(now_ms()), n)
    }

    fn sweep(&self) {
        let now = now_ms();
        let timed_out = {
            let mut asks = lock(&self.asks);
            let before = asks.len();
            // Dropping an ask drops its guard, which releases its in-flight slot.
            asks.retain(|_, a| now.saturating_sub(a.last_ms) < a.idle_ms);
            before - asks.len()
        };
        self.counters.asks_timed_out.fetch_add(timed_out as u64, Ordering::Relaxed);
        lock(&self.pseudonyms).retain(|_, v| v.1 > now);
        lock(&self.assembling).retain(|_, a| now.saturating_sub(a.last_ms) < ASSEMBLE_TTL_MS);
    }

    /// Which network carries this node's private traffic, decided once a second. Moving is safe at any moment because both networks can
    /// carry at once and every node refuses duplicates by id. So this node starts on its own network as soon as Tor goes quiet, and only
    /// leaves it after Tor has stayed up a while: a Tor that flickers costs extra copies, never a lost message.
    fn tick_mode(&self) {
        let now = now_ms();
        let choice = super::network_choice();
        let up = (self.primary_up)() && choice != super::NetworkChoice::OwnOnly;
        // A push can take this network when a reply can come back: a linked neighbour the view can route to (see `ask`).
        let (routable_link, crowd) = {
            let linked: Vec<NodeId> = lock(&self.links).keys().copied().collect();
            let view = lock(&self.view);
            let epoch = epoch_now(now);
            (linked.iter().any(|n| view.get(n).is_some()) && view.routable_count(epoch) > 0, view.crowd(epoch, now))
        };
        // O2: below the floor with Tor up a payment takes Tor (it hides the IP among millions); with Tor down, or at the floor, it
        // takes this network at once. A payment never waits on the floor (`super::our_network_carries_push`, `ANON_FLOOR`).
        let tor_down = self.primary_down.load(Ordering::Relaxed);
        super::note_push_route(choice != super::NetworkChoice::TorOnly && routable_link && super::our_network_carries_push(crowd, tor_down));
        if up {
            self.primary_down_since_ms.store(0, Ordering::Relaxed);
            let since = self.primary_up_since_ms.load(Ordering::Relaxed);
            if since == 0 {
                self.primary_up_since_ms.store(now, Ordering::Relaxed);
            } else if now.saturating_sub(since) >= PRIMARY_UP_AFTER_MS {
                self.primary_down.store(false, Ordering::Relaxed);
            }
        } else {
            self.primary_up_since_ms.store(0, Ordering::Relaxed);
            let since = self.primary_down_since_ms.load(Ordering::Relaxed);
            if since == 0 {
                self.primary_down_since_ms.store(now, Ordering::Relaxed);
            } else if now.saturating_sub(since) >= PRIMARY_DOWN_AFTER_MS {
                self.primary_down.store(true, Ordering::Relaxed);
            }
        }
        let need = self.peer_need_until_ms.load(Ordering::Relaxed) > now;
        // This network carries private traffic only once Tor is down Tor-wide (`arti_transport::tor_reachable`, then the debounce
        // above), or when the user chose it. It used to take over at Tor's first quiet second, which moved everyone on mere lag.
        // User 2026-11-07: "the automatic switch must only happen in a true tor-wide outage not just lag."
        let carrying = self.primary_down.load(Ordering::Relaxed) || choice == super::NetworkChoice::OwnOnly || need;
        super::note_network_state(choice != super::NetworkChoice::OwnOnly && !self.primary_down.load(Ordering::Relaxed), self.links_count());
        self.active.store(carrying && choice != super::NetworkChoice::TorOnly, Ordering::Relaxed);
        if choice == super::NetworkChoice::TorOnly {
            // A user who chose Tor alone keeps no links here, so no first hop of ours sees this machine.
            lock(&self.links).clear();
            lock(&self.parked).clear();
        }
    }

    fn status_json(&self) -> String {
        let c = &self.counters;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let (view, routable) = {
            let v = lock(&self.view);
            (v.len(), v.routable_count(epoch_now(now_ms())))
        };
        format!(
            "{{\"active\":{},\"primary_down\":{},\"links\":{},\"view\":{},\"routable\":{},\"sent_real\":{},\"sent_cover\":{},\"relayed\":{},\"delivered\":{},\"cells_in\":{},\"cells_out\":{},\"bad_mac\":{},\"replays\":{},\"tagged\":{},\"wrong_size\":{},\"records_new\":{},\"records_refused\":{},\"loops_sent\":{},\"loops_back\":{},\"loop_ms_sum\":{},\"asks_sent\":{},\"asks_answered\":{},\"asks_timed_out\":{},\"asks_served\":{},\"replies_relayed\":{},\"dropped_pool\":{},\"dropped_link\":{},\"dropped_queue\":{},\"links_up\":{},\"dials_failed\":{},\"handshakes_failed\":{},\"links_closed_bad\":{},\"frames_unknown\":{},\"out_cells\":{},\"out_bulk\":{},\"carrier_ready\":{},\"hop_ready\":{},\"hops_held\":{},\"hops_registered\":{},\"hops_refused\":{},\"hop_forwarded\":{}}}",
            self.active.load(Ordering::Relaxed),
            self.primary_down.load(Ordering::Relaxed),
            self.links_count(),
            view,
            routable,
            g(&c.sent_real),
            g(&c.sent_cover),
            g(&c.relayed),
            g(&c.delivered),
            g(&c.cells_in),
            g(&c.cells_out),
            g(&c.bad_mac),
            g(&c.replays),
            g(&c.tagged),
            g(&c.wrong_size),
            g(&c.records_new),
            g(&c.records_refused),
            g(&c.loops_sent),
            g(&c.loops_back),
            g(&c.loop_ms_sum),
            g(&c.asks_sent),
            g(&c.asks_answered),
            g(&c.asks_timed_out),
            g(&c.asks_served),
            g(&c.replies_relayed),
            g(&c.dropped_pool),
            g(&c.dropped_link),
            g(&c.dropped_queue),
            g(&c.links_up),
            g(&c.dials_failed),
            g(&c.handshakes_failed),
            g(&c.links_closed_bad),
            g(&c.frames_unknown),
            lock(&self.out_cells).len(),
            lock(&self.out_bulk).len(),
            !self.own_carriers().is_empty(),
            lock(&self.hop).as_ref().is_some_and(|h| h.registered.is_some()),
            lock(&self.hops).len(),
            g(&c.hops_registered),
            g(&c.hops_refused),
            g(&c.hop_forwarded),
        )
    }

    /// ⭐ THE RELAY FACES THIS NODE CAN HAND A STRANGER (lane af57, 2026-11-15; user: "finish pqmix to fully replace tor now").
    ///
    /// Up to `max` signed records, each naming a relay face (a reachable address that opens links into this network):
    /// - this node's own record first, when it opened a relay face;
    /// - then the longest-known routable entries that carry a relay address (addrman's preference for age).
    ///
    /// A record with no relay address is never served. A hidden node's record names no way to reach it and stays inside this
    /// network's own gossip, so nothing here can point at a hidden address.
    ///
    /// Read by the kind-30 ask (`arti_transport::BULK_REQ_KIND_RELAY_FACES`), which carries relay faces over Tor while Tor is
    /// up. So a node that never had a seed of this network links into it before Tor fails, and a Tor outage finds it already
    /// carried (no cliff, spec §6c).
    pub fn relay_face_records(&self, max: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if max == 0 {
            return out;
        }
        if matches!(self.relay_face, Some(CarrierAddr::Relay(_))) {
            if let Some(raw) = self.build_own_record() {
                out.push(raw);
            }
        }
        let epoch = epoch_now(now_ms());
        let v = lock(&self.view);
        let mut held: Vec<(u64, &Vec<u8>)> = v
            .entries()
            .filter(|e| e.record.epoch + 1 >= epoch && e.record.carriers.iter().any(|c| matches!(c, CarrierAddr::Relay(_))))
            .map(|e| (e.first_seen_ms, &e.raw))
            .collect();
        held.sort_by_key(|(seen, _)| *seen);
        for (_, raw) in held {
            if out.len() >= max {
                break;
            }
            out.push(raw.clone());
        }
        out
    }

    /// The relay faces this node knows, as `relay:<address>:<port>`: its own first, then the longest-known in the view, at most
    /// `max` (the view itself is bounded by `VIEW_MAX`). Read from the records the view already verified; nothing re-parsed.
    pub fn relay_face_addrs(&self, max: usize) -> Vec<String> {
        let epoch = epoch_now(now_ms());
        let own = self.relay_face.iter().cloned();
        let v = lock(&self.view);
        let mut held: Vec<(u64, CarrierAddr)> = v
            .entries()
            .filter(|e| e.record.epoch + 1 >= epoch)
            .flat_map(|e| e.record.carriers.iter().filter(|c| matches!(c, CarrierAddr::Relay(_))).map(move |c| (e.first_seen_ms, c.clone())))
            .collect();
        held.sort_by_key(|(seen, _)| *seen);
        let mut out: Vec<String> = Vec::with_capacity(max);
        own.chain(held.into_iter().map(|(_, c)| c)).filter_map(|c| match c {
            CarrierAddr::Relay(a) => Some(format!("relay:{a}")),
            CarrierAddr::Unix(_) | CarrierAddr::Via(_) => None,
        })
        .for_each(|line| {
            if out.len() < max && !out.contains(&line) {
                out.push(line);
            }
        });
        out
    }

    /// The kind-30 answer, whole: `RELAYFCE ‖ n u8 ‖ (len u16 LE ‖ record)ⁿ`, from [`Self::relay_face_records`] (at most
    /// [`RELAY_FACES_ANSWER_MAX`], never past `byte_budget`). One constant-bounded page.
    pub fn relay_faces_answer(&self, byte_budget: usize) -> Vec<u8> {
        let held = self.relay_face_records(RELAY_FACES_ANSWER_MAX);
        let mut out = Vec::with_capacity(9);
        out.extend_from_slice(crate::arti_transport::RELAY_FACES_TAG);
        out.push(0);
        let mut n = 0u8;
        for one in &held {
            let Ok(len) = u16::try_from(one.len()) else { continue };
            if out.len() + 2 + one.len() > byte_budget {
                break;
            }
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(one);
            n += 1;
        }
        out[8] = n;
        out
    }

    /// A kind-30 answer's body (after its tag), decoded within its own length, at most [`RELAY_FACES_ANSWER_MAX`] entries, and
    /// admitted by [`Self::admit_learned`]. A short or overlong page admits nothing past its first malformed entry. Returns
    /// `(offered, new)`.
    pub fn admit_relay_faces_page(&self, body: &[u8]) -> (usize, usize) {
        let Some((&n, mut rest)) = body.split_first() else { return (0, 0) };
        let want = usize::from(n).min(RELAY_FACES_ANSWER_MAX);
        let mut got: Vec<Vec<u8>> = Vec::with_capacity(want);
        while got.len() < want {
            let Some(len) = rest.get(..2).map(|l| usize::from(u16::from_le_bytes([l[0], l[1]]))) else { break };
            let Some(one) = rest.get(2..2 + len) else { break };
            got.push(one.to_vec());
            rest = &rest[2 + len..];
        }
        (got.len(), self.admit_learned(&got))
    }

    /// How many routable relay faces this node's view holds (its own not counted): what decides whether a kind-30 ask is due.
    pub fn relay_faces_known(&self) -> usize {
        let epoch = epoch_now(now_ms());
        lock(&self.view)
            .entries()
            .filter(|e| e.record.epoch + 1 >= epoch && e.record.carriers.iter().any(|c| matches!(c, CarrierAddr::Relay(_))))
            .count()
    }

    /// ⭐ ADMIT RELAY FACES LEARNED OUTSIDE THIS NETWORK (a kind-30 answer that came over Tor).
    ///
    /// Each record is held to every check a record arriving on a link is held to (`verify_record` at this epoch: the ML-DSA
    /// signature, the identity work, the epoch rent), and in addition it must carry a relay address. Every admitted record
    /// counts against ONE source, [`LEARNED_OUTSIDE`], so all the peers answering over Tor together fill at most
    /// `view::SOURCE_MAX` entries of the view, however many answers they send. A new record is flooded to this node's links
    /// like any other (it is public), and the maintainer dials it like any neighbour.
    ///
    /// Returns how many were new.
    pub fn admit_learned(&self, raws: &[Vec<u8>]) -> usize {
        let now = now_ms();
        let epoch = epoch_now(now);
        let mut new = 0usize;
        for raw in raws.iter().take(RELAY_FACES_ANSWER_MAX) {
            let Ok(r) = record::verify_record(raw, Some(epoch)) else {
                self.counters.records_refused.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            if lock(&self.view).is_self(&record::id_of(&r.dsa_pk)) {
                continue;
            }
            if !r.carriers.iter().any(|c| matches!(c, CarrierAddr::Relay(_))) {
                self.counters.records_refused.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if lock(&self.view).admit(r, raw.clone(), now, now, LEARNED_OUTSIDE) == Admit::New {
                new += 1;
                self.counters.records_new.fetch_add(1, Ordering::Relaxed);
                self.flood(F_RECORD, raw, None);
            }
        }
        new
    }

    fn save_records(&self) {
        let mut out = Vec::new();
        let v = lock(&self.view);
        // Not this node's own hop record: a new run picks its gateway afresh and re-registers.
        for e in v.entries().filter(|e| !v.is_self(&record::id_of(&e.record.dsa_pk))) {
            out.extend_from_slice(&e.first_seen_ms.to_le_bytes());
            out.extend_from_slice(&(e.raw.len() as u32).to_le_bytes());
            out.extend_from_slice(&e.raw);
        }
        drop(v);
        // LOCAL-STORAGE-REQUIRED: what a restart with Tor down needs to find anyone. O1-FOOTPRINT-REVIEWED: at most `VIEW_MAX`
        // records, rewritten whole.
        let tmp = self.state_dir.join("mix-records.tmp");
        if std::fs::write(&tmp, &out).is_ok() && std::fs::rename(&tmp, self.state_dir.join("mix-records.bin")).is_err() {
            eprintln!("[mix] the record file could not be replaced; a restart will start from the last good one");
        }
    }

    fn load_records(&self) {
        let Ok(b) = std::fs::read(self.state_dir.join("mix-records.bin")) else { return };
        let now = now_ms();
        let mut at = 0usize;
        while at + 12 <= b.len() {
            let mut t = [0u8; 8];
            t.copy_from_slice(&b[at..at + 8]);
            let len = u32::from_le_bytes([b[at + 8], b[at + 9], b[at + 10], b[at + 11]]) as usize;
            at += 12;
            let Some(raw) = b.get(at..at + len) else { return };
            at += len;
            if let Ok(r) = record::verify_record(raw, None) {
                let id = record::id_of(&r.dsa_pk);
                if id != self.id.id {
                    // Its own file: the age it earned stays, and each record counts as first-hand.
                    lock(&self.view).admit(r, raw.to_vec(), now, u64::from_le_bytes(t), id);
                }
            }
        }
    }
}

async fn pump(s: Arc<Shared>) {
    let mut turn = false;
    loop {
        let rate = s.rate();
        let wait = lock(&s.rng).exp_ms(1000.0 / rate);
        // A sub-millisecond draw at a high rate still paces on average, since each slot takes its own draw.
        tokio::time::sleep(std::time::Duration::from_millis(wait as u64)).await;
        turn = !turn;
        if super::network_choice() != super::NetworkChoice::TorOnly {
            s.emit_one(turn, mean_delay_ms(rate));
        }
    }
}

async fn pool_runner(s: Arc<Shared>) {
    let mut every = tokio::time::interval(std::time::Duration::from_millis(2));
    loop {
        every.tick().await;
        s.run_due();
    }
}

async fn unix_acceptor(s: Arc<Shared>, path: PathBuf) {
    // A stale socket from a previous run of this node. The path is this node's own, from its own configuration.
    if path.exists() && std::fs::remove_file(&path).is_err() {
        eprintln!("[mix] the old local socket could not be removed");
    }
    if let Some(dir) = path.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            eprintln!("[mix] the folder for the local socket could not be made");
        }
    }
    let Ok(l) = tokio::net::UnixListener::bind(&path) else {
        eprintln!("[mix] could not listen on the local path this node was given");
        return;
    };
    loop {
        match l.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(s.clone().respond_link(Box::new(stream)));
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
}

/// Answers inbound links on this node's relay face. Only a node whose operator opened one runs this.
async fn relay_acceptor(s: Arc<Shared>, addr: String) {
    carrier::relay_accept_loop(&addr, |stream| {
        tokio::spawn(s.clone().respond_link(stream));
    })
    .await;
}

async fn maintain(s: Arc<Shared>) {
    let mut last_gossip = std::time::Instant::now();
    let mut last_save = std::time::Instant::now();
    let mut last_log = std::time::Instant::now();
    let mut tick = 0u64;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        tick += 1;
        s.tick_mode();
        s.sweep();
        let (others, crowd) = {
            let v = lock(&s.view);
            let now = now_ms();
            (v.neighbours(), v.crowd(epoch_now(now), now))
        };
        super::note_band_ids(&s.id.id, &others);
        super::note_crowd(crowd);

        // The key turn: mine this epoch's rent off the runtime, then keep the old key one more epoch, and destroy the one
        // before that together with its replay set.
        let epoch = epoch_now(now_ms());
        if lock(&s.keys).cur.epoch != epoch {
            let pk = s.id.dsa_pk.clone();
            if let Ok(n) = tokio::task::spawn_blocking(move || record::mine_epoch_work(&pk, epoch)).await {
                *lock(&s.epoch_nonce) = (epoch, n);
                let mut k = lock(&s.keys);
                let old = std::mem::replace(&mut k.cur, fresh_key(epoch));
                k.prev = Some(old);
                drop(k);
                s.publish_own();
            }
        }

        if tick % 5 == 0 {
            // O5: a node with no address of its own is a hop through a relay face it is linked to (`tick_hop`).
            s.clone().tick_hop().await;
        }
        if tick % 5 == 0 && super::network_choice() != super::NetworkChoice::TorOnly {
            // First contact, and again whenever a seed's neighbour is gone.
            let linked: HashSet<NodeId> = lock(&s.links).keys().copied().collect();
            let own = s.own_carriers();
            for seed in &s.seeds {
                if own.contains(seed) {
                    continue;
                }
                if lock(&s.seeds_linked).get(seed).is_some_and(|id| linked.contains(id)) {
                    continue;
                }
                if !lock(&s.seeds_dialing).insert(seed.clone()) {
                    continue;
                }
                let (s2, seed2) = (s.clone(), seed.clone());
                tokio::spawn(async move {
                    if let Some(stream) = s2.dial(&seed2).await {
                        if let Some(peer) = s2.clone().initiate_link(stream, None).await {
                            lock(&s2.seeds_linked).insert(seed2.clone(), peer);
                        }
                    } else {
                        s2.counters.dials_failed.fetch_add(1, Ordering::Relaxed);
                    }
                    lock(&s2.seeds_dialing).remove(&seed2);
                });
            }
            // Keep a working set of links. A relay's packets for anyone else open a link on demand.
            let mut wanted: Vec<NodeId> = lock(&s.view).neighbours().into_iter().filter(|n| !linked.contains(n)).collect();
            let room = LINKS_TARGET.saturating_sub(linked.len());
            let mut rng = lock(&s.rng);
            for _ in 0..room.min(wanted.len()) {
                let i = rng.below(wanted.len());
                let n = wanted.swap_remove(i);
                s.dial_soon(n);
            }
            drop(rng);
            if std::fs::write(s.state_dir.join("mix-status.json"), s.status_json()).is_err() {
                eprintln!("[mix] the status file could not be written");
            }
        }
        if last_gossip.elapsed().as_secs() >= 60 {
            last_gossip = std::time::Instant::now();
            let txs: Vec<mpsc::Sender<(u8, Vec<u8>)>> = lock(&s.links).values().map(|l| l.tx.clone()).collect();
            for tx in &txs {
                s.share_sample(tx, 4);
            }
        }
        if last_save.elapsed().as_secs() >= 60 {
            last_save = std::time::Instant::now();
            s.save_records();
        }
        if last_log.elapsed().as_secs() >= 60 {
            last_log = std::time::Instant::now();
            // DIGITAL-CASH-PRIVACY-REVIEWED: counts of this node's own transport. Names no peer, address, note, amount, key or owner.
            eprintln!("[mix] {}", s.status_json());
        }
    }
}

/// Starts the mix on its own thread and runtime. It blocks only on the identity's first mint and this epoch's work.
pub fn spawn(cfg: Config) -> std::io::Result<Arc<Shared>> {
    if std::fs::create_dir_all(&cfg.state_dir).is_err() {
        eprintln!("[mix] the state folder could not be made");
    }
    let id = Identity::load_or_mint(&cfg.state_dir);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().thread_name("usdmd-mix").build()?;
    let epoch = epoch_now(now_ms());
    let epoch_nonce = record::mine_epoch_work(&id.dsa_pk, epoch);
    let own_id = id.id;
    let unix = cfg.unix_listen.clone();
    let relay_addr = match &cfg.relay_face {
        Some(CarrierAddr::Relay(a)) => Some(a.clone()),
        _ => None,
    };
    let handle = rt.handle().clone();
    let shared = Arc::new_cyclic(|me: &Weak<Shared>| Shared {
        me: me.clone(),
        id,
        view: Mutex::new(View::new(own_id, cfg.unix_listen.is_some())),
        keys: Mutex::new(Keys { cur: fresh_key(epoch), prev: None }),
        epoch_nonce: Mutex::new((epoch, epoch_nonce)),
        links: Mutex::new(HashMap::new()),
        link_generation: AtomicU64::new(0),
        hops: Mutex::new(HashMap::new()),
        hop: Mutex::new(None),
        parked: Mutex::new(HashMap::new()),
        dialing: Mutex::new(HashSet::new()),
        seeds_dialing: Mutex::new(HashSet::new()),
        seeds_linked: Mutex::new(HashMap::new()),
        cells_in: Mutex::new(VecDeque::new()),
        inbox: Arc::new(BulkInbox::default()),
        asks: Mutex::new(HashMap::new()),
        pseudonyms: Mutex::new(HashMap::new()),
        assembling: Mutex::new(HashMap::new()),
        out_cells: Mutex::new(VecDeque::new()),
        out_bulk: Mutex::new(VecDeque::new()),
        pool: Mutex::new(BinaryHeap::new()),
        pool_seq: AtomicU64::new(0),
        primary_up: cfg.primary_up,
        primary_down_since_ms: AtomicU64::new(0),
        primary_up_since_ms: AtomicU64::new(0),
        peer_need_until_ms: AtomicU64::new(0),
        primary_down: AtomicBool::new(false),
        active: AtomicBool::new(false),
        counters: Counters::default(),
        rng: Mutex::new(Rng::new()),
        relay_face: cfg.relay_face,
        own_unix: cfg.unix_listen,
        seeds: cfg.seeds,
        serve: cfg.serve,
        serves: Arc::new(tokio::sync::Semaphore::new(SERVES_MAX)),
        state_dir: cfg.state_dir,
        handshakes_pending: AtomicUsize::new(0),
        handle,
        active_pps: ACTIVE_PPS,
    });
    shared.load_records();
    shared.publish_own();
    let _ = RUNNING.set(Arc::downgrade(&shared));
    let s = shared.clone();
    std::thread::Builder::new().name("usdmd-mix".into()).spawn(move || {
        rt.block_on(async move {
            if let Some(path) = unix {
                tokio::spawn(unix_acceptor(s.clone(), path));
            }
            if let Some(addr) = relay_addr {
                tokio::spawn(relay_acceptor(s.clone(), addr));
            }
            tokio::spawn(pump(s.clone()));
            tokio::spawn(pool_runner(s.clone()));
            maintain(s).await;
        });
    })?;
    Ok(shared)
}

// TWO-PARTY-REVIEWED: what can be said without a second process is only the delay's derivation. The running layer crosses
// between real processes in `mix_cut.py` and `mix_attack`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_delay_holds_the_pool_target_at_every_rate_a_carrier_might_run() {
        for rate in [16.0, 32.0, 64.0, 128.0, 256.0] {
            let d = mean_delay_ms(rate);
            let pool = packet::HOPS as f64 * rate * d / 1000.0;
            assert!(pool >= POOL_TARGET - 1e-9, "at {rate} pkt/s a relay holds {pool} packets");
            assert!((DELAY_MIN_MS..=DELAY_MAX_MS).contains(&d));
        }
        assert_eq!(mean_delay_ms(128.0), DELAY_MIN_MS, "a fast carrier keeps the floor");
        assert_eq!(mean_delay_ms(STANDBY_PPS), DELAY_MAX_MS, "standby hits the ceiling, and carries no real traffic");
    }

    /// ⭐ THE RELAY FACES DOOR (kind 30), ACROSS TWO REAL MIX RUNTIMES (lane af57, 2026-11-15; user: "finish pqmix to fully
    /// replace tor now").
    ///
    /// **Setup.** A opened a relay face; B, a hidden node with no seed, starts knowing no relay face at all, which is the shape
    /// of every wallet's node before this door.
    ///
    /// **The honest path.** A's kind-30 page carries A's relay face to B. B then knows it, lists it as a seed it would ship,
    /// and serves it on.
    ///
    /// **Refused, each by name:**
    /// - a record whose signature does not verify;
    /// - a hidden node's record, which names no relay face, so no answer can point at a hidden address;
    /// - a truncated page, which admits nothing past its length;
    /// - a replay, which admits nothing new.
    ///
    /// ROOT-LAYER: the verified records live in the mix's own view, and only there, so the page is produced and admitted at
    /// this layer (`relay_faces_answer` / `admit_relay_faces_page`); the node runtime only routes the bytes of kind 30 and
    /// `RELAYFCE`.
    /// MUST-STAY-GREEN: every `pqmix` pin (record, view, link, packet, dpf); the node's exact-shape serve arms for kinds 21, 26,
    /// 22 and 28 ahead of this one; `mix_cut.py` / `mix_outage.py` on real processes.
    /// TWO-PARTY-REVIEWED: the parties are A's serve and B's admission, two separate runtimes with separate identities, state
    /// folders and views. Between real processes, over relay faces with Tor cut, this is the relay rig (`scratchpad/net/net.py`
    /// NET_OWN=relay; its rows are `<check>@af57-relay` in results.tsv). (Corrected 2026-11-16: this line named a
    /// `mix_relay_outage.py` that does not exist in the tree.)
    #[test]
    fn a_relay_face_crosses_by_the_kind_30_page_and_a_tampered_or_hidden_record_is_refused() {
        let tmp = |n: &str| {
            let d = std::env::temp_dir().join(format!("af57-relayfaces-{n}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            d
        };
        let port = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port").local_addr().expect("its address").port();
        let face = format!("relay:127.0.0.1:{port}");
        let start = |dir: PathBuf, relay_face: Option<CarrierAddr>| {
            spawn(Config { state_dir: dir, seeds: Vec::new(), unix_listen: None, relay_face, serve: BulkServeSlot::default(), primary_up: Box::new(|| true) })
                .expect("a mix runtime starts")
        };
        let a = start(tmp("a"), CarrierAddr::parse(&face));
        let b = start(tmp("b"), None);
        assert_eq!(b.relay_faces_known(), 0, "CALIBRATION: B starts knowing no relay face, as a wallet's node did");
        // A's own record, served first. (MEASURED: other runtimes this test process started earlier may already have linked to
        // A's freshly bound port and gossiped records of their own, so A's answer is asserted to LEAD with A, never to be
        // only A; every page below is built from A's one record so each refusal is measured against exactly one.)
        // The identities a page's records carry, in order (a record is re-signed at every build, so bytes are not compared).
        let ids_in = |page: &[u8]| -> Vec<NodeId> {
            let mut out = Vec::new();
            let mut rest = &page[9..];
            for _ in 0..page[8] {
                let len = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
                out.push(record::id_of(&record::verify_record(&rest[2..2 + len], None).expect("a served record verifies").dsa_pk));
                rest = &rest[2 + len..];
            }
            out
        };
        let own = a.build_own_record().expect("A has its own record");
        let page = a.relay_faces_answer(1 << 20);
        assert_eq!(&page[..8], crate::arti_transport::RELAY_FACES_TAG, "the answer carries its tag");
        assert!(page[8] >= 1, "A serves at least its own relay face");
        assert_eq!(ids_in(&page).first(), Some(&a.id.id), "and serves its own first");
        let single = |rec: &[u8]| {
            let mut p = vec![1u8];
            p.extend_from_slice(&(rec.len() as u16).to_le_bytes());
            p.extend_from_slice(rec);
            p
        };
        let honest = single(&own);

        let mut forged = own.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(b.admit_relay_faces_page(&single(&forged)), (1, 0), "⛔ a record whose signature does not verify was admitted");
        // A node with no address publishes no record of its own (O5); a record shaped like one (no carrier), and a hop's record
        // (a `Via` carrier, no address), are each refused as a relay face.
        assert!(b.build_own_record().is_none(), "⛔ a node with no address published a record of its own");
        let shaped = |carriers: Vec<CarrierAddr>| {
            let (epoch, kem_pk) = {
                let k = lock(&b.keys);
                (k.cur.epoch, k.cur.kem_pk.clone())
            };
            let r = Record {
                dsa_pk: b.id.dsa_pk.clone(),
                epoch,
                kem_pk,
                carriers,
                seq: now_ms() / 1000,
                pow_nonce: b.id.pow_nonce,
                epoch_nonce: lock(&b.epoch_nonce).1,
            };
            record::encode_signed(&r, &b.id.dsa_sk).expect("B signs")
        };
        let hidden = shaped(Vec::new());
        assert_eq!(a.admit_relay_faces_page(&single(&hidden)), (1, 0), "⛔ a hidden node's record (no relay face) was admitted");
        let hop = shaped(vec![CarrierAddr::Via(a.id.id)]);
        assert_eq!(a.admit_relay_faces_page(&single(&hop)), (1, 0), "⛔ a hop's record (Via only, no address) was admitted as a relay face");
        assert_eq!(b.admit_relay_faces_page(&honest[..honest.len() - 10]), (0, 0), "⛔ a truncated page admitted a record");
        assert_eq!(b.relay_faces_known(), 0, "nothing refused reached B's view");

        assert_eq!(b.admit_relay_faces_page(&honest), (1, 1), "the honest page admits A's relay face");
        assert!(b.relay_faces_known() >= 1, "B now knows A's relay face");
        assert!(b.relay_face_addrs(32).contains(&face), "and lists it as a seed a release would ship");
        assert_eq!(b.admit_relay_faces_page(&honest), (1, 0), "a replay admits nothing new");
        let onward = ids_in(&b.relay_faces_answer(1 << 20));
        assert!(onward.contains(&a.id.id), "B serves the relay face it learned");
        assert!(!onward.contains(&b.id.id), "⛔ B served its own hidden record");
        assert_eq!(a.relay_faces_answer(9)[8], 0, "an answer never exceeds the lane's byte budget");
    }

    // TWO-PARTY-REVIEWED: three independent mix runtimes (each its own state folder, identity, tokio runtime and sockets) cross
    // real TCP on this machine, and every assertion is what one OBSERVES of another (the gateway holds the hops' records; a hidden
    // node relays another's packets; its loops come back through its gateway). Between real node processes, with Tor cut, this
    // is the relay rig (`scratchpad/net/net.py` NET_OWN=relay: fresh, pay, change, restart).
    // ROOT-LAYER: `send_packet` is the one place a packet leaves for its next hop, and `tick_hop` / the F_HOP doors are where a
    // hop's reachability is PRODUCED (its record and its gateway's hold); no reader is patched.
    // MUST-STAY-GREEN: the relay-face pin above, the carrier census, and the relay rig's fresh/pay/change/restart (NET_OWN=relay).
    /// ⭐ O5 — EVERY NODE A RELAY, AND NO IP LEAVES ITS FIRST HOP (lane af57, 2026-11-16; user: "If we have 500 nodes on tor then
    /// we should have 500 relays automatically … Just make sure users ips arent exposed and able to be linked").
    ///
    /// G opens a relay face; H and S have no address and only dial G. Measured, RED before O5: a node with no address had no
    /// record anyone could route to, so it never relayed, never counted in the crowd, and its own loops were lost. Here:
    /// - H and S each register a hop identity with G (G holds 2), and that id is NOT the node's long-term id;
    /// - the hop records name G and no address, and reach the other hidden node through G's gossip (so it can route through it);
    /// - a hidden node RELAYS for others, and its own loops come back through its gateway;
    /// - a node with no address publishes no record of its own (its long-term id never reaches a relay);
    /// - G refuses a record naming another gateway, and a proof over another link's binding (a copied record cannot be
    ///   registered), and its hold on the hop does not move.
    #[test]
    fn every_node_is_a_relay_a_hidden_node_registers_through_its_gateway_relays_for_others_and_its_loops_come_back() {
        let tmp = |n: &str| {
            let d = std::env::temp_dir().join(format!("af57-o5-{n}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            d
        };
        let port = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port").local_addr().expect("its address").port();
        let face = CarrierAddr::parse(&format!("relay:127.0.0.1:{port}")).expect("a relay address");
        let start = |dir: PathBuf, relay_face: Option<CarrierAddr>, seeds: Vec<CarrierAddr>| {
            spawn(Config { state_dir: dir, seeds, unix_listen: None, relay_face, serve: BulkServeSlot::default(), primary_up: Box::new(|| true) })
                .expect("a mix runtime starts")
        };
        let g = start(tmp("g"), Some(face.clone()), Vec::new());
        let h = start(tmp("h"), None, vec![face.clone()]);
        let s = start(tmp("s"), None, vec![face]);
        assert!(h.build_own_record().is_none() && s.build_own_record().is_none(), "⛔ a node with no address published its long-term record");
        let hop_of = |x: &Shared| lock(&x.hop).as_ref().and_then(|p| p.registered.map(|_| p.ident.id));
        let t0 = std::time::Instant::now();
        loop {
            let held = lock(&g.hops).len();
            let (hx, sx) = (hop_of(&h), hop_of(&s));
            let knows = |x: &Shared, id: Option<NodeId>| id.is_some_and(|i| lock(&x.view).get(&i).is_some());
            let loops = (h.counters.loops_back.load(Ordering::Relaxed), s.counters.loops_back.load(Ordering::Relaxed));
            let relayed = (h.counters.relayed.load(Ordering::Relaxed), s.counters.relayed.load(Ordering::Relaxed));
            if held >= 2 && knows(&h, sx) && knows(&s, hx) && loops.0 > 0 && loops.1 > 0 && (relayed.0 > 0 || relayed.1 > 0) {
                break;
            }
            assert!(
                t0.elapsed().as_secs() < 400,
                "⛔ O5 did not come up in 400 s: gateway holds {held}, hops {hx:?}/{sx:?}, loops back {loops:?}, relayed {relayed:?}\n\
                 G {}\nH {}\nS {}",
                g.status_json(),
                h.status_json(),
                s.status_json()
            );
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        let (hx, sx) = (hop_of(&h).expect("H is a hop"), hop_of(&s).expect("S is a hop"));
        assert!(hx != h.id.id && sx != s.id.id, "⛔ a hop identity is the node's long-term id");
        for x in [hx, sx] {
            let carriers = lock(&g.view).get(&x).expect("G holds the hop's record").record.carriers.clone();
            assert_eq!(carriers, vec![CarrierAddr::Via(g.id.id)], "⛔ a hop's record names something other than its gateway");
        }
        assert!(lock(&g.view).get(&h.id.id).is_none() && lock(&g.view).get(&s.id.id).is_none(),
                "⛔ a hidden node's long-term id reached its gateway");
        assert!(g.counters.hop_forwarded.load(Ordering::Relaxed) > 0, "the gateway forwarded packets down its hops' links");

        // The gateway's doors, each refusal counted. H's record as gossip carries it, with a proof by another key over a binding
        // that is not the link it arrives on (an attacker's link) is refused, and G's hold on H does not move.
        let refused = || g.counters.hops_refused.load(Ordering::Relaxed);
        let raw = lock(&g.view).get(&hx).expect("H's record").raw.clone();
        let r = g.check_hop_record(&raw).expect("an honest hop record passes the record door");
        let before = (refused(), lock(&g.hops).get(&hx).copied());
        let attacker_link = [0x5au8; 32];
        let attacker_binding = [0xa5u8; 32];
        let wrong = crate::pqauth::ml_dsa_sign(&hop_statement(&attacker_binding, &hx, r.epoch), &s.id.dsa_sk).expect("signs");
        g.register_at_gateway(attacker_link, 0, &attacker_binding, r.clone(), raw.clone(), &wrong);
        assert_eq!(refused(), before.0 + 1, "⛔ a proof by another key over another link's binding was accepted");
        assert_eq!(lock(&g.hops).get(&hx).copied(), before.1, "⛔ a refused registration moved the gateway's hold on the hop");
        // A record that names some other gateway is refused at the record door.
        let mut other = r;
        other.carriers = vec![CarrierAddr::Via([7u8; 32])];
        let other_raw = {
            let hp = lock(&h.hop);
            record::encode_signed(&other, &hp.as_ref().expect("H's hop").ident.dsa_sk).expect("signs")
        };
        assert!(g.check_hop_record(&other_raw).is_none(), "⛔ a record naming another gateway passed G's door");
    }

    #[test]
    fn inner_framing_round_trips_and_refuses_a_length_past_its_end() {
        let v = frame_inner(K_CELL, b"abc");
        assert_eq!(read_inner(&v), Some((K_CELL, &b"abc"[..])));
        let mut bad = v.clone();
        bad[1] = 200;
        assert_eq!(read_inner(&bad), None);
        assert!(ASK_FRAG > 1024, "an ask fragment holds {ASK_FRAG} bytes");
        assert!(REPLY_DATA > 4096, "a reply fragment holds {REPLY_DATA} bytes");
        assert!(frame_inner(K_CELL, &vec![0u8; crate::net::CELL_SIZE + 1]).len() <= INNER, "a whole cell fits one packet");
    }
}

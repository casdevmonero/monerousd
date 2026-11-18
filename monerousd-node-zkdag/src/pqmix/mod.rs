// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD's own post-quantum mix layer: a separate anonymous transport that replaces Tor while Tor is down.
//! docs/PQ-MIX-LAYER-SPEC-20261106.md has the design, its costs, and every way it does not beat Tor.
//!
//! User 2026-11-06: *"our mix layer must not require ip. ip should also not be findable on our layer under any
//! circumstances"*; *"it cant rely on tor … this is a seperate layer from tor and the goal is to improve upon its failures
//! especially with anoniminity"*.
//!
//! It is one more leg of [`crate::transport::MultiTransport`], and the node above it does not know it is there.

pub mod carrier;
pub mod dpf;
pub mod link;
pub mod packet;
pub mod record;
pub mod replay;
pub mod rng;
pub mod runtime;
pub mod view;

use crate::arti_transport::{bulk_inflight_admits, follow_slot_claim, BULK_REQ_KIND_BLOCK_FOLLOW, FOLLOW_HOLD};
use crate::net::{is_cover, NetError, CELL_SIZE};
use crate::transport::{BulkServeSlot, CellTransport, PeerPeering, CELL_KIND_COVER};
use carrier::CarrierAddr;
use runtime::Shared;
use std::sync::atomic::Ordering;
use std::sync::Arc;

const STATE_TOR: u8 = 0;
const STATE_MIX: u8 = 1;
const STATE_NONE: u8 = 2;
static NETWORK_STATE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(STATE_NONE);

/// Which private network is carrying this node now, for the wallet to say in plain words: `tor`, `mix`, or `none` while it is
/// looking for one. One word about this node's own transport; it names no peer, address or route. A network the user just turned off
/// is never named, even before the next tick re-reads the links: right after "Our network only" the wallet said "on Tor".
pub fn network_state() -> &'static str {
    match NETWORK_STATE.load(Ordering::Relaxed) {
        STATE_TOR if tor_allowed() => "tor",
        STATE_MIX if own_allowed() => "mix",
        _ => "none",
    }
}

/// How many relays a sender's packets hide among before this network's privacy counts as large: a crowd of a thousand day-old relays.
/// Below it a payment is still hidden, but a watcher of the whole internet has fewer people to choose from, and the wallet says so.
pub const CROWD_LARGE: usize = 1_000;

static CROWD: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The crowd this node's view holds now (`View::crowd`). The count of public records every view already holds, so it reveals nothing.
pub fn crowd() -> usize {
    CROWD.load(Ordering::Relaxed)
}

pub(crate) fn note_crowd(n: usize) {
    CROWD.store(n, Ordering::Relaxed);
}

static BAND_IDS: std::sync::Mutex<Option<(String, Vec<String>)>> = std::sync::Mutex::new(None);

/// This node's id here and every id it sees, while this network is what carries it. `None` while Tor does, and the node ranks provers by
/// onion as it always has. An id here is a relay's public record id, already public in every view, and names no hidden address.
pub fn band_ids() -> Option<(String, Vec<String>)> {
    if NETWORK_STATE.load(Ordering::Relaxed) == STATE_TOR {
        return None;
    }
    match BAND_IDS.lock() {
        Ok(g) => g.clone(),
        Err(e) => e.into_inner().clone(),
    }
}

pub(crate) fn note_band_ids(me: &[u8; 32], others: &[[u8; 32]]) {
    let text = |id: &[u8; 32]| id.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let own = format!("mix:{}", text(me));
    let mut all: Vec<String> = others.iter().map(|o| format!("mix:{}", text(o))).collect();
    all.push(own.clone());
    all.sort();
    all.dedup();
    let value = Some((own, all));
    match BAND_IDS.lock() {
        Ok(mut g) => *g = value,
        Err(e) => *e.into_inner() = value,
    }
}

/// Which networks a node may use, a user's choice, changed at any time with nothing lost. Auto uses both and moves on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkChoice {
    Auto,
    TorOnly,
    OwnOnly,
}

impl NetworkChoice {
    pub fn name(self) -> &'static str {
        match self {
            NetworkChoice::Auto => "auto",
            NetworkChoice::TorOnly => "tor",
            NetworkChoice::OwnOnly => "own",
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "auto" => Some(NetworkChoice::Auto),
            "tor" => Some(NetworkChoice::TorOnly),
            "own" => Some(NetworkChoice::OwnOnly),
            _ => None,
        }
    }
}

static NETWORK_CHOICE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
static CHOICE_FILE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

pub fn network_choice() -> NetworkChoice {
    match NETWORK_CHOICE.load(Ordering::Relaxed) {
        1 => NetworkChoice::TorOnly,
        2 => NetworkChoice::OwnOnly,
        _ => NetworkChoice::Auto,
    }
}

/// Applies a choice at once and keeps it across restarts. A choice only decides how bytes travel, so it cannot touch a balance.
/// LOCAL-STORAGE-REQUIRED: a user's setting has no home on the chain or the wire, and must survive a restart.
/// bound: one file of a few bytes, overwritten in place.
pub fn set_network_choice(choice: NetworkChoice) {
    let v = match choice {
        NetworkChoice::Auto => 0,
        NetworkChoice::TorOnly => 1,
        NetworkChoice::OwnOnly => 2,
    };
    NETWORK_CHOICE.store(v, Ordering::Relaxed);
    if let Some(path) = CHOICE_FILE.get() {
        if std::fs::write(path, choice.name()).is_err() {
            eprintln!("[mix] the network choice could not be saved, and holds until the next restart");
        }
    }
}

/// Whether the user's choice lets Tor carry anything.
pub fn tor_allowed() -> bool {
    network_choice() != NetworkChoice::OwnOnly
}

static TOR_OUTAGE_FILE: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
static TOR_OUTAGE_READ_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static TOR_OUTAGE_NOW: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// How a real-node check takes Tor from a node that is already running: while the file named by `MONEROUSD_TEST_TOR_OUTAGE_FILE` exists, this
/// node's Tor links deliver nothing and carry nothing, the silence a real outage makes, and the node has to notice it by itself. No OS cut can
/// reach a live process without root. Unset, this is one cached read per call and is always false, so a node without the variable is unchanged.
/// Limit: a peer's in-flight bulk answer can still finish, and this node still answers a bulk ask a peer opened over Tor.
pub fn tor_outage() -> bool {
    let Some(path) = TOR_OUTAGE_FILE.get_or_init(|| std::env::var_os("MONEROUSD_TEST_TOR_OUTAGE_FILE").map(std::path::PathBuf::from)) else {
        return false;
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    if now.saturating_sub(TOR_OUTAGE_READ_MS.load(Ordering::Relaxed)) >= 1000 {
        TOR_OUTAGE_READ_MS.store(now, Ordering::Relaxed);
        TOR_OUTAGE_NOW.store(path.exists(), Ordering::Relaxed);
    }
    TOR_OUTAGE_NOW.load(Ordering::Relaxed)
}

/// Whether this network may carry anything right now.
pub fn own_allowed() -> bool {
    network_choice() != NetworkChoice::TorOnly
}

static PUSH_ROUTE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this network can carry a transaction push right now: allowed, and a routable neighbour to take the reply. Re-read
/// once a second. While it can, Tor never carries a push, even when this network is briefly busy: the push waits for it.
pub fn push_route() -> bool {
    PUSH_ROUTE.load(Ordering::Relaxed)
}

pub(crate) fn note_push_route(on: bool) {
    PUSH_ROUTE.store(on, Ordering::Relaxed);
}

/// What carries this node now, as the move rule decided it (`runtime::tick_mode`): Tor until Tor is down Tor-wide and the debounce has passed,
/// never Tor's reachability second by second, so a stall the rule rides out is never reported as a move.
pub(crate) fn note_network_state(tor_carries: bool, mix_links: usize) {
    let state = if tor_carries {
        STATE_TOR
    } else if mix_links > 0 {
        STATE_MIX
    } else {
        STATE_NONE
    };
    NETWORK_STATE.store(state, Ordering::Relaxed);
}

pub struct MixLeg {
    shared: Arc<Shared>,
    serve: BulkServeSlot,
}

impl MixLeg {
    /// Starts the layer with its configuration from the environment and from its state folder (the node's Tor state folder,
    /// `.usdmd-arti-<port>`, where `network-choice` lives too):
    /// - `MONEROUSD_MIX_SEEDS`: comma-separated relay faces or local paths. A bare address is refused.
    /// - `mix-seeds` (file): more seeds, one per line (`#` starts a comment). This is the first contact a release ships, read
    ///   through the same parser as the environment. A2 (lane af57, 2026-11-15): a wallet's node used to start with no seed of
    ///   this network at all (the wallet forwarded onion seeds only, `network_descriptor.rs`), so it never joined, and a Tor
    ///   outage stopped it.
    /// - `MONEROUSD_MIX_UNIX`: a local path to listen on, for nodes on one machine.
    /// - `MONEROUSD_MIX_RELAY`: this node's relay face, as `relay:<address>:<port>`. When unset, the `mix-relay-face` file
    ///   gives it, so an operator's choice survives every restart and every spawn path. Unset everywhere by default: a node
    ///   then only dials out, and no address of it is known beyond its first hops, which cannot tell which hidden address it
    ///   holds (spec §6a limit 2: a relay face is off by default on a wallet node).
    pub fn from_env(state_dir: std::path::PathBuf, serve: BulkServeSlot, primary_up: Box<dyn Fn() -> bool + Send + Sync>) -> std::io::Result<MixLeg> {
        let choice_path = state_dir.join("network-choice");
        if let Some(c) = std::fs::read_to_string(&choice_path).ok().and_then(|t| NetworkChoice::parse(t.trim())) {
            set_network_choice(c);
        }
        let _ = CHOICE_FILE.set(choice_path);
        let mut seed_text = std::env::var("MONEROUSD_MIX_SEEDS").unwrap_or_default();
        if let Ok(file) = std::fs::read_to_string(state_dir.join("mix-seeds")) {
            for line in file.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                if !line.is_empty() {
                    seed_text.push(',');
                    seed_text.push_str(line);
                }
            }
        }
        let mut seeds: Vec<CarrierAddr> = Vec::new();
        for t in seed_text.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            match CarrierAddr::parse(t) {
                Some(a) if !seeds.contains(&a) && seeds.len() < MIX_SEEDS_MAX => seeds.push(a),
                Some(_) => {}
                None => eprintln!("[mix] a seed that is not a carrier address was refused"),
            }
        }
        let unix_listen = std::env::var("MONEROUSD_MIX_UNIX").ok().map(std::path::PathBuf::from);
        let relay_text = std::env::var("MONEROUSD_MIX_RELAY")
            .ok()
            .or_else(|| std::fs::read_to_string(state_dir.join("mix-relay-face")).ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()));
        let relay_face = match relay_text {
            Some(text) => {
                let a = CarrierAddr::parse(&text).filter(|a| matches!(a, CarrierAddr::Relay(_)));
                if a.is_none() {
                    eprintln!("[mix] the relay face given is not a relay address, so none was opened");
                }
                a
            }
            None => None,
        };
        let shared = runtime::spawn(runtime::Config { state_dir, seeds, unix_listen, relay_face, serve: serve.clone(), primary_up })?;
        Ok(MixLeg { shared, serve })
    }

    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }
}

impl CellTransport for MixLeg {
    /// The same serve callback the Tor lane answers from. This leg sits first in the transport, so the runtime fills this
    /// slot, and the Tor lane reads the same one.
    fn bulk_serve_slot(&self) -> BulkServeSlot {
        self.serve.clone()
    }
    fn has_bulk_lane(&self) -> bool {
        true
    }
    /// A public ask goes one hop to a neighbour whenever one is linked: no switch and no wait on Tor. Anything else is mixed, and only
    /// while this node's Tor is down; otherwise it answers false, and the next leg takes it.
    fn bulk_raw_request(&self, req: &[u8]) -> bool {
        if !own_allowed() || !bulk_inflight_admits(req) {
            return false;
        }
        if is_public_ask(req) && self.shared.relay_ask(req, None, None, runtime_ask_idle_ms(req)) {
            return true;
        }
        // A transaction push takes this network whether Tor is up or not, but only while this network may carry it hidden (O2,
        // `push_route`: a routable link and a crowd at the floor, or the user's consent). Otherwise Tor carries it when Tor is
        // up (`ArtiOnionTransport::push_over_tor`), and it waits when Tor is down.
        if crate::arti_transport::is_tx_push_ask(req) && !push_route() {
            return false;
        }
        if !self.shared.primary_down.load(Ordering::Relaxed) && !crate::arti_transport::is_tx_push_ask(req) {
            return false;
        }
        self.shared.ask(req, None, None, runtime_ask_idle_ms(req))
    }
    /// One follow per neighbour, through the same shared bound as the Tor lane's. A followed block is public, so this is the relay plane.
    fn bulk_follow_request(&self, req: &[u8]) -> usize {
        if req.first() != Some(&BULK_REQ_KIND_BLOCK_FOLLOW) || !own_allowed() {
            return 0;
        }
        let mut issued = 0;
        for host in self.shared.linked_peers(crate::arti_transport::FOLLOW_HOSTS_MAX) {
            let name = format!("mix:{}", u64::from_le_bytes([host[0], host[1], host[2], host[3], host[4], host[5], host[6], host[7]]));
            if !follow_slot_claim(&name) {
                continue;
            }
            if self.shared.relay_ask(req, Some(host), Some(name.clone()), runtime_ask_idle_ms(req)) {
                issued += 1;
            } else {
                crate::arti_transport::follow_slot_release(&name);
            }
        }
        issued
    }
    fn drain_bulk_responses(&self) -> Vec<Vec<u8>> {
        self.shared.inbox.drain_all()
    }
    fn take_bulk_consensus_pages(&self, max: usize) -> Vec<Vec<u8>> {
        self.shared.inbox.take_consensus(max)
    }
    fn take_bulk_responses(&self, max: usize) -> Vec<Vec<u8>> {
        self.shared.inbox.take(max)
    }
    fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError> {
        self.send_cell_kind(cell, 15)
    }
    /// Cover from above is dropped: this layer's pump has its own. A public cell goes one hop to every neighbour. Anything else is
    /// mixed, and in standby it is dropped, since Tor carries it; a node goes active when its Tor is down or a peer says its own is.
    fn send_cell_kind(&self, cell: Vec<u8>, kind: u8) -> Result<(), NetError> {
        if cell.len() != CELL_SIZE {
            return Err(NetError::BadCell);
        }
        if kind == CELL_KIND_COVER || is_cover(&cell) || !own_allowed() {
            return Ok(());
        }
        if is_public_kind(kind) {
            self.shared.relay_cell(&cell);
            return Ok(());
        }
        if !self.shared.active.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.shared.send_cell(&cell);
        Ok(())
    }
    fn recv_cell(&self) -> Option<Vec<u8>> {
        match self.shared.cells_in.lock() {
            Ok(mut q) => q.pop_front(),
            Err(e) => e.into_inner().pop_front(),
        }
    }
    fn peering(&self) -> Box<dyn PeerPeering> {
        Box::new(MixPeering(self.shared.clone()))
    }
}

/// What the runtime sees of this leg. It has no onion, and takes none: nothing about Tor enters this layer.
struct MixPeering(Arc<Shared>);
impl PeerPeering for MixPeering {
    fn add(&self, _peer_id: &str, _addr: &str, _x_pk: &[u8], _ek: &[u8]) -> bool {
        false
    }
    fn own_identity(&self) -> Option<(String, Vec<u8>, Vec<u8>)> {
        None
    }
    fn own_address(&self) -> Option<String> {
        None
    }
    /// Counted only while this layer is what carries the node: while Tor is up, a node's Tor health checks must read Tor.
    fn live_writers(&self) -> usize {
        if self.0.primary_down.load(Ordering::Relaxed) {
            self.0.links_count()
        } else {
            0
        }
    }
}

/// The mix layer's parsers of outside bytes, one call each, for `decode_doors`. `None` names no parser here. Nothing here reads
/// or writes node state.
pub fn drive_door(name: &str, bytes: &[u8]) -> Option<bool> {
    use packet::{kem_keypair, peel, HopKey};
    use replay::ReplayBloom;
    match name {
        "mix-packet" => {
            thread_local! {
                static HOP: std::cell::RefCell<(packet::KemSecret, ReplayBloom)> =
                    std::cell::RefCell::new((kem_keypair().1, ReplayBloom::new()));
            }
            Some(HOP.with(|h| {
                let (sk, replay) = &mut *h.borrow_mut();
                peel(bytes, &mut [HopKey { sk, replay }]).is_ok()
            }))
        }
        "mix-record" => Some(record::verify_record(bytes, None).is_ok()),
        "mix-frame" => Some(link::hostile_frame(bytes)),
        "mix-inner" => Some(runtime::hostile_inner_parse(bytes)),
        "mix-carrier" => {
            let text = std::str::from_utf8(bytes).ok();
            let parsed = text.and_then(CarrierAddr::parse).is_some();
            let decoded = bytes.split_first().is_some_and(|(k, rest)| CarrierAddr::decode(*k, rest).is_some());
            Some(parsed || decoded)
        }
        _ => None,
    }
}

/// Cell classes that are public chain data, by index in `CELL_KIND_NAMES`: Block, TipBeacon, SyncResp, SyncReq, Ladder, BlockAck, Band.
/// A list of what may skip the mix, never of what must take it, so a class added later is mixed until someone decides otherwise.
fn is_public_kind(kind: u8) -> bool {
    matches!(kind, 0 | 3 | 4 | 5 | 11 | 14 | 22)
}

/// Asks for public chain data: a bundle, a block by any route, a block inventory or part, a follow, a band step, finality certificates,
/// and the descent lanes. A wallet's questions about records or notes, and a transaction fetch, are absent from this list and stay mixed.
fn is_public_ask(req: &[u8]) -> bool {
    // 30: the relay faces this network's relays publish anyway (`runtime::Shared::relay_face_records`), so it is public data
    // 31, 32 (§14): a bundle's head and its members' bodies, which the block that lays them carries (the bodies' carriers
    // are what every node pulled of a payment before the relay), so they are public chain data
    req.len() != 12 && matches!(req.first(), Some(&(4 | 9 | 11 | 12 | 13 | 15 | 16 | 18 | 19 | 20 | 22 | 25 | 30 | 31 | 32)))
}

/// ⭐ O2 — THE ANONYMITY FLOOR (spec §6c item 4, §6e O2; lane af57, 2026-11-15).
///
/// **A PAYMENT NEVER WAITS ON THE FLOOR** (user 2026-11-15: "be careful not to cause a chain halt by making payments wait … is
/// halting payments acceptable for a monero ethos project?"). No: a payment always goes. The floor only picks the carrier that
/// hides it best right now:
/// - at least `ANON_FLOOR` relays known for a day (`crowd`): our network carries it (constant cover, 3 mixed hops);
/// - below the floor with Tor up: Tor carries it on a fresh circuit, which hides its IP among Tor's millions;
/// - below the floor with Tor down: our network carries it at once. It still travels encrypted through 3 relays to one random
///   node that announces it as its own, and the wallet states the crowd while it is under `CROWD_LARGE`.
///
/// What the crowd decides is only which machine sent a payment. What it was, how much and to whom stay hidden on chain whatever
/// carries it.
///
/// An earlier draft of this rule held a payment below the floor with Tor down until "send now". It was never built into a
/// binary. MEASURED why it was wrong: on today's testnet the crowd is a few relays, so the hold would have lasted the whole Tor
/// outage, hours tonight. That is a halt of the user's money, against Monero's ethos and against the standing rule "never
/// limit, hold".
///
/// **DERIVED.** A route is `packet::HOPS` (3) relays. If an observer runs one relay of a crowd of N, all three hops are its with
/// probability (1/N)³; at N = 32 that is 2⁻¹⁵, about 1 in 33,000 per payment.
///
/// **Assumption stated:** each relay is an independent operator and route choice is uniform. A sybil holding a fraction f of
/// the crowd's identities breaks it as f³, which the day of age and the identity work price, and which bond weighting (§6c
/// item 5) will price in money.
pub const ANON_FLOOR: usize = 32;

/// Whether our network should carry a payment now rather than Tor: the crowd is at the floor, or Tor is not carrying (then ours
/// carries it at once: a payment never waits on the floor), or the user chose our network outright.
pub fn our_network_carries_push(crowd: usize, tor_down: bool) -> bool {
    crowd >= ANON_FLOOR || tor_down || network_choice() == NetworkChoice::OwnOnly
}

#[cfg(test)]
mod floor_tests {
    use super::*;

    /// ⭐ O2 — THE FLOOR PICKS THE CARRIER AND NEVER HOLDS A PAYMENT.
    /// - With Tor up, a crowd under the floor sends a payment by Tor; at the floor, by our network.
    /// - With Tor down, our network carries it at any crowd: no wait.
    /// - The floor is the smallest crowd where one observer relay holds all `HOPS` hops of a route with probability at most 2⁻¹⁵.
    ///
    /// ROOT-LAYER: the rule decides `push_route`, the one predicate both legs read before a payment leaves (`MixLeg::bulk_raw_request`
    /// and `push_over_tor`): exactly one carrier is chosen, and one always is while either network can reach anyone.
    /// MUST-STAY-GREEN: every `pqmix` pin; `NET_OWN=1` rigs (choice "own": our network carries, as before); `NET_OWN=relay` pay.
    /// TWO-PARTY-REVIEWED: one node's own choice of carrier, which has no second side; the crossing is `NET_OWN=relay` pay on real
    /// processes (Tor cut, crowd 0: the payment went at once).
    #[test]
    fn the_floor_picks_tor_for_a_small_crowd_and_never_holds_a_payment_when_tor_is_down() {
        if network_choice() == NetworkChoice::OwnOnly {
            return; // another pin of this process set our network outright; the rule is measured under Automatic
        }
        assert!(!our_network_carries_push(0, false) && !our_network_carries_push(ANON_FLOOR - 1, false), "a small crowd with Tor up sends by Tor");
        assert!(our_network_carries_push(ANON_FLOOR, false), "a crowd at the floor sends by our network");
        assert!(our_network_carries_push(0, true), "⛔ with Tor down a payment must go by our network at once, never wait");
        let p = |n: usize| (1.0f64 / n as f64).powi(packet::HOPS as i32);
        assert!(p(ANON_FLOOR) <= 2f64.powi(-15) + 1e-15, "the floor holds a full-route compromise to 2^-15");
        assert!(p(ANON_FLOOR - 1) > 2f64.powi(-15), "and is the smallest crowd that does (derived, not tuned)");
    }
}

/// The most seeds a node keeps (environment and `mix-seeds` together). A seed is untrusted (all it serves self-verifies), so
/// the bound is on work: one dial per seed every five seconds while it is unlinked.
pub const MIX_SEEDS_MAX: usize = 64;

/// The relay faces a node wants in its view before its kind-30 asks slow down to the refresh pace.
pub const RELAY_FACES_WANT: usize = 8;
/// How often a node asks while it holds fewer than [`RELAY_FACES_WANT`], and after that.
const RELAY_FACES_ASK_SOON_MS: u64 = 60_000;
const RELAY_FACES_ASK_REFRESH_MS: u64 = 600_000;
static RELAY_FACES_LAST_ASK_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Up to `max` signed relay-face records this node can hand a stranger (empty when no mix runs here). Answers kind 30.
pub fn relay_face_records(max: usize) -> Vec<Vec<u8>> {
    runtime::running().map(|s| s.relay_face_records(max)).unwrap_or_default()
}

/// Admit relay-face records a kind-30 answer carried; how many were new. Every check a linked record meets, plus a relay address.
pub fn admit_relay_faces(raws: &[Vec<u8>]) -> usize {
    runtime::running().map(|s| s.admit_learned(raws)).unwrap_or(0)
}

/// The kind-30 answer page this node serves (`RELAYFCE ‖ n ‖ entries`): the tag and `n = 0` when no mix runs here.
pub fn relay_faces_answer(byte_budget: usize) -> Vec<u8> {
    match runtime::running() {
        Some(s) => s.relay_faces_answer(byte_budget),
        None => {
            let mut out = crate::arti_transport::RELAY_FACES_TAG.to_vec();
            out.push(0);
            out
        }
    }
}

/// A kind-30 answer's body (after the tag), admitted: `(offered, new)`.
pub fn admit_relay_faces_page(body: &[u8]) -> (usize, usize) {
    runtime::running().map(|s| s.admit_relay_faces_page(body)).unwrap_or((0, 0))
}

/// The relay faces this node knows, as `relay:<address>:<port>` (its own first): what a release ships as first contact
/// (`/get_relay_faces`, `scratchpad/seed_list.py --relays`).
pub fn relay_face_addrs(max: usize) -> Vec<String> {
    runtime::running().map(|s| s.relay_face_addrs(max)).unwrap_or_default()
}

/// Whether the runtime should ask a peer for relay faces now (kind 30), and if so, the moment is taken. Due every
/// [`RELAY_FACES_ASK_SOON_MS`] while the view holds fewer than [`RELAY_FACES_WANT`] relay faces, every
/// [`RELAY_FACES_ASK_REFRESH_MS`] after; never when the user chose Tor alone, never with no mix running.
pub fn relay_faces_ask_due(now_ms: u64) -> bool {
    if network_choice() == NetworkChoice::TorOnly {
        return false;
    }
    let Some(s) = runtime::running() else { return false };
    let gap = if s.relay_faces_known() < RELAY_FACES_WANT { RELAY_FACES_ASK_SOON_MS } else { RELAY_FACES_ASK_REFRESH_MS };
    let last = RELAY_FACES_LAST_ASK_MS.load(Ordering::Relaxed);
    if last != 0 && now_ms.saturating_sub(last) < gap {
        return false;
    }
    RELAY_FACES_LAST_ASK_MS.store(now_ms, Ordering::Relaxed);
    true
}

/// How long an ask may go without a fragment arriving. A follow waits on the server's hold first.
fn runtime_ask_idle_ms(req: &[u8]) -> u64 {
    let hold = if req.first() == Some(&BULK_REQ_KIND_BLOCK_FOLLOW) { FOLLOW_HOLD.as_millis() as u64 } else { 0 };
    hold + 20_000
}

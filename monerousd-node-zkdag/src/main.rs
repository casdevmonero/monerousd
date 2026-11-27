// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `usdmd-node` entrypoint — a runnable bring-up of the assembled greenfield node.
//!
//! Boots genesis, then produces a short DAG ON THE TIPS THE NODE ALREADY HOLDS — every node is a
//! first-class producer (no parent-body refetch), so killing all-but-one node cannot stall the DAG.
//! It prints the adaptive per-block work + blue-score as the DAG advances, plus the live
//! governance-tunable params. The arti onion mesh, the usdm-decider WHIR ZK-verify (brick 6), and instant-sync
//! (brick 7) drive this SAME `Node`; the loopback RPC ([`usdmd_node::rpc`]) is its local control face.

use usdmd_node::block::{Block, BlockHeader};

// ⭐⭐⭐ §CR — THE GLOBAL ALLOCATOR. See the long note in `Cargo.toml` for the measurement that chose it.
//
// ⛔ THE NODE HAD NO `#[global_allocator]` AT ALL, so it ran on the platform default. On macOS that is
// libmalloc, whose large-allocation cache holds freed pages indefinitely: `vmmap -summary` on a node at
// height 428 reported `MALLOC_LARGE (empty)` at **227.7 MB resident** against a `/ram_census` total under
// 10 MB. The chain's own state was never the growth; the allocator's retention of the prover's per-block
// traces was.
//
// ⛔ THIS IS NOT A CAP, A WINDOW OR AN AGE-OUT. Nothing is refused, bounded or dropped — every allocation
// still succeeds, and no note, proof or carrier is affected. It changes only when pages the process has
// ALREADY FREED are handed back to the operating system.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// DB-92 (real-node run 92, `vmmap --summary` on a live node): jemalloc's arenas held 961 MB RESIDENT
// (one anonymous region class, 9,567 mappings) against a physical-footprint PEAK of 393 MB and a
// `/ram_census` of 7 MB. The chain's state is bounded; what grew was FREED pages jemalloc had not yet
// returned — its default decay keeps dirty pages ~10 s and, with one arena per core for the prover's
// rayon threads, every arena retains its own share. These options only change WHEN freed pages go back
// to the operating system (a background purger, a 1 s dirty decay, no muzzy stage, four arenas); no
// allocation is refused, capped or aged out, and no consensus rule, wire format or gate is touched.
// Bitcoin Core ships the same class of allocator tuning for the same reason.
#[cfg(not(target_env = "msvc"))]
#[allow(non_upper_case_globals)]
#[export_name = "_rjem_malloc_conf"]
pub static malloc_conf: &[u8] =
    b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0,narenas:4\0";
use usdmd_node::governance::{Chamber, EnactOutcome, ParamChange};
use usdmd_node::hash::Hash32;
use usdmd_node::node::Node;
use usdmd_node::pqauth::{
    finality_vote_msg, ml_dsa_keypair, ml_dsa_sign, pubkey_id, MlDsaVerifier,
};
use usdmd_node::validator::VoteCert;

/// The binary's ONE crash-free fatal path (Bitcoin Core's `InitError` shape): a bring-up step that cannot continue
/// prints its real state on stderr and exits non-zero — never a panic (no unwind through the node's locks, no
/// backtrace, one legible line). Every former `.expect(..)` of the entrypoint routes here.
fn fatal(what: &str, detail: &dyn std::fmt::Debug) -> ! {
    eprintln!("fatal: {what}: {detail:?}");
    std::process::exit(2)
}
trait OrFatal<T> {
    fn or_fatal(self, what: &str) -> T;
}
impl<T> OrFatal<T> for Option<T> {
    fn or_fatal(self, what: &str) -> T {
        match self {
            Some(v) => v,
            None => fatal(what, &"absent"),
        }
    }
}
impl<T, E: std::fmt::Debug> OrFatal<T> for Result<T, E> {
    fn or_fatal(self, what: &str) -> T {
        match self {
            Ok(v) => v,
            Err(e) => fatal(what, &e),
        }
    }
}

/// `usdmd-node serve-sites [<site-root>]` — load the node's chain-anchored dApp bundles and bind the
/// loopback sovereign HTTP server. The user's OWN node is the deploy location for every ecosystem
/// service (Pillar C); the wallet's dApp browser + Ion Swap launcher probe this loopback surface
/// node-first. Site-bundle store = the positional arg, else `MONEROUSD_SITE_ROOT`, else `./sites`.
fn run_sovereign(args: &[String]) {
    use std::path::PathBuf;
    use std::sync::Arc;
    use usdmd_node::sovereign::{SovereignServer, SOVEREIGN_DEFAULT_PORT, SOVEREIGN_LOOPBACK_HOST};

    let root = args
        .iter()
        .skip_while(|a| *a != "serve-sites")
        .nth(1)
        .filter(|s| !s.starts_with('-'))
        .cloned()
        .or_else(|| std::env::var("MONEROUSD_SITE_ROOT").ok())
        .unwrap_or_else(|| "sites".to_string());
    let root = PathBuf::from(root);
    let port: u16 = std::env::var("MONEROUSD_SOVEREIGN_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(SOVEREIGN_DEFAULT_PORT);

    println!(
        "usdmd-node sovereign server — node-first hosting (Pillar C), loopback {}:{} (onion mesh distributes bundles; this last hop is private loopback)",
        SOVEREIGN_LOOPBACK_HOST, port
    );
    let mut server = SovereignServer::new();
    // Node-local dApp backend: /api/*,/v1/*,/events,/ws reverse-proxy SAME-ORIGIN to this loopback
    // upstream (the node IS the backend — no VPS, no fallback). Loopback-guarded; default off.
    if let Ok(upstream) = std::env::var("MONEROUSD_SOVEREIGN_API_UPSTREAM") {
        server.set_api_upstream(Some(upstream.clone()));
        match server.api_upstream() {
            Some(u) => println!("dApp backend upstream (loopback, same-origin /api,/v1,/ws): {u}"),
            None => eprintln!("WARN: MONEROUSD_SOVEREIGN_API_UPSTREAM={upstream} is not loopback — ignored (no VPS/routable backend allowed)"),
        }
    }
    match server.load_all(&root) {
        Ok(loaded) => {
            for (dir, r) in &loaded {
                println!("  hosted {}  root={}…", dir, &r.to_hex()[..16]);
            }
            println!(
                "serving {} chain-anchored dApp bundle(s) from {}",
                loaded.len(),
                root.display()
            );
        }
        Err(e) => {
            eprintln!(
                "fatal: could not load site bundles from {}: {e}",
                root.display()
            );
            std::process::exit(1);
        }
    }
    // Live chain tip: MIRROR the REAL local node's height over loopback (Pillar C — the user's own
    // node computes the backend). The old shape booted a PRIVATE throwaway node that minted its own
    // chain just to answer /api/chain-tip — an island height no other node agreed on (join-mesh-or-
    // nothing forbids exactly that). Now /api/chain-tip reflects the canonical mesh chain the real
    // node serves on its loopback RPC; while that node is unreachable the tip honestly stays at the
    // last mirrored value (the server's proxy fallback covers cold start).
    // The mirror and the serve loop are the library's (`sovereign::serve_mirroring_tip`): a phone's in-process host
    // runs the same bring-up on a thread, since it cannot spawn this process.
    println!("chain-tip: mirroring the real local node's loopback /get_info — /api/chain-tip is the canonical mesh height (no private island chain, no VPS)");
    println!(
        "sovereign HTTP up on http://{}:{}/  (Ctrl-C to stop)",
        SOVEREIGN_LOOPBACK_HOST, port
    );
    if let Err(e) = usdmd_node::sovereign::serve_mirroring_tip(server, port) {
        eprintln!("fatal: sovereign server bind/serve failed: {e}");
        std::process::exit(1);
    }
}

/// `usdmd-node serve` — boot a PERSISTENT node + block producer and bind the loopback tx-RPC
/// ([`usdmd_node::rpc_http`]) on 127.0.0.1:27780. This is the LIVE backend the greenfield wallet's
/// broadcast buttons POST `/submit_pq_tx` to: a submitted PQ carrier is verified by the LIGHT decider
/// (an INVALID carrier that fails the verify is REJECTED, fail-closed), pooled, and mined into the DAG
/// by the producer. Blocks forever.
/// Auto-select a FREE RPC port for automated multi-node operation: start at `preferred` and probe upward until
/// one binds, so a second node on the same host never collides-and-dies — it self-assigns the next free port
/// with zero manual configuration. Falls back to `preferred` if the whole window is busy (the real bind then
/// surfaces the true error instead of masking it).
fn pick_free_rpc_port(preferred: u16) -> u16 {
    // ⛔ PORT-RACE-IDENTITY (lane livewedge, 2026-11-26) — A NODE WITH ITS OWN SAVED CHAIN ON A PORT KEEPS THAT PORT. Per-node files
    // follow the served port (DB-341), so a node that binds a port it has no chain on boots EMPTY under that port's name. MEASURED
    // (live, 2026-11-26 05:37–05:41): the origin (~/.usdmd-node, chain on 27780) was mid-boot when the wallet node (its own state dir,
    // chain on 27781, preferring 27780) restarted; the wallet node took the free 27780, the origin's relaunch took 27781, and both
    // served fresh chains from genesis (heights 0 and 27) while their real snapshots sat intact. Now: the first port in this node's
    // range that THIS state dir holds a snapshot for is its port, taken even when an earlier one is free, and waited for (a bounded
    // 120 s: a just-stopped instance or a booting neighbour) when busy; past the bound the process exits non-zero and its supervisor
    // restarts it, never as another node. A state dir with no snapshot in the range picks as before (a fresh node, a second node).
    // AI RESISTANT (b): local files of this node only. SCALE: ≤ 32 file checks at boot. NOTHING HALTS: the wait is bounded and its
    // expiry hands the restart to the supervisor; production never waits on it.
    let own = |p: u16| usdmd_node::persist::state_dir().join(format!("state-{p}.snap")).exists();
    let free = |p: u16| usdmd_node::rpc_http::reusable_tcp_listener("127.0.0.1", p).is_ok();
    let mine_all: Vec<u16> = (preferred..preferred.saturating_add(32)).filter(|p| own(*p)).collect();
    // a state dir that still hosts two nodes' chains: a FREE port of its own goes first, so neither takes the other's
    if let Some(p) = mine_all.iter().copied().find(|p| free(*p)) {
        return p;
    }
    if let Some(&mine) = mine_all.first() {
        let began = std::time::Instant::now();
        while usdmd_node::rpc_http::reusable_tcp_listener("127.0.0.1", mine).is_err() {
            if began.elapsed() >= std::time::Duration::from_secs(120) {
                eprintln!(
                    "[auto-port] ⛔ this node's own chain is on port {mine} and the port stayed busy for 120 s — exiting so the \
                     supervisor restarts it; it never serves another port's identity"
                );
                std::process::exit(75);
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        return mine;
    }
    for cand in preferred..preferred.saturating_add(32) {
        // SO_REUSEADDR probe (same as the real serve bind): a TIME_WAIT socket a JUST-KILLED prior instance left
        // on `preferred` is RECLAIMABLE, so a restart stays on ITS OWN port (and thus ITS snapshot + onion),
        // instead of drifting to the next port + a DIFFERENT chain — the self-inflicted restart-fork. A genuinely
        // LIVE listener still fails this bind, so a real second node still auto-selects the next free port.
        if usdmd_node::rpc_http::reusable_tcp_listener("127.0.0.1", cand).is_ok() {
            return cand; // bound + dropped -> free (or reclaimable-stale) for the real RPC bind moments later
        }
    }
    preferred
}

fn run_serve() {
    use usdmd_node::rpc::RPC_DEFAULT_PORT;

    // AUTOMATED MULTI-NODE: honor MONEROUSD_RPC_PORT as the PREFERRED port, but auto-select the next free one
    // if it is busy, so a second node on the same host never collides-and-dies — it self-assigns with zero
    // manual config. The tor supervisor + onion identity both derive from THIS port, so the node stays consistent.
    let preferred: u16 = std::env::var("MONEROUSD_RPC_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(RPC_DEFAULT_PORT);
    let port = pick_free_rpc_port(preferred);
    // ⛔ DB-341: this process serves `port` — fixed BEFORE any per-node file (the validator key first) is named, so an
    // auto-selected port never keys this node to the preferred port's files (another node's identity).
    usdmd_node::persist::set_serving_port(port);
    if port != preferred {
        println!("[auto-port] preferred RPC port {preferred} busy — auto-selected free {port} (automated multi-node)");
    }
    // GENESIS = DETERMINISTIC PER-NETWORK CONSTANT, NO COMMIT (user 2026-07-13). Genesis identity is PURELY
    // f(network) — this network's id prefix, with ZERO per-device / env input — so two FRESH devices on the same
    // network build a BYTE-IDENTICAL genesis and converge with no split BY CONSTRUCTION, and genesis records NO
    // state at all. testnet / mainnet / every re-genesis stay ISOLATED because the per-network id differs; both
    // mesh nodes sharing MONEROUSD_NET build the SAME genesis and converge. (The per-device
    // MONEROUSD_GENESIS_PARITY_COMMIT env — which made a device diverge from a fresh one — is REMOVED at the source.)
    let mut params = usdmd_node::params::ChainParams::default();
    {
        let net = std::env::var("MONEROUSD_NET").unwrap_or_default();
        // Before the public launch no node starts on the mainnet identity (`params::mainnet_launched`): said once, in
        // plain words, with the fix, before anything is built or written.
        if let Err(why) = usdmd_node::params::refuse_unlaunched_network(&net) {
            eprintln!("[network] ⛔ {why}");
            std::process::exit(2);
        }
        params.genesis_parity_commit = network_genesis_prefix(&net);
        // Fix this process's network identity BEFORE any tx is stamped or judged — per-tx work is bound to it.
        usdmd_node::params::set_process_network_id(&params.genesis_parity_commit);
        params.net_prefix_len = params.genesis_parity_commit.len();
    }
    let mut node = match Node::with_params(
        Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: usdmd_node::block::genesis_header_for_network(&params.genesis_parity_commit),
            tx_ids: vec![],
            pow_proof: Vec::new(),
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            note_transition: None,
            nullifier_proof: usdmd_node::block::NfBlockProof::default(),
            cover_transition: None,
            member_transition: None,
        },
        params,
    ) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("fatal: genesis add failed: {e}");
            std::process::exit(1);
        }
    };
    // #106 frontier-persist: RESUME this node's last committed checkpoint from local disk, so a restart resumes
    // its exact state (note set / reserve ledger / spent-nullifiers) instead of restarting from an empty chain —
    // a restart is no longer a wipe. Keyed by the RPC `port` so two same-host nodes keep separate checkpoints.
    // After this, every committed block auto-saves the O(1) resumable checkpoint (background write, off the
    // consensus/RPC critical path). A joining node with no checkpoint still instant-syncs via #29 DSYNC.
    // The persist door REFUSES (never wipes) an unreadable or foreign checkpoint; the DAEMON exits 97 on that
    // refusal so a deploy skew is noticed. The in-process node (`serve.rs`) hands the same refusal to the
    // wallet as an error instead — a wallet app must never die at launch on its node's cache.
    // THE BLOCK WINDOW (2026-09-21, owner-approved): every whole block above the DAG's horizon lives in
    // `~/.usdmd-node/pruning-window-{port}` — Kaspa's block store — and the restore below re-installs it.
    // ⭐⭐⭐ THE ONE BOOT (`Node::boot`, 2026-10-06): the block window (Kaspa's block store), the #106 checkpoint resume with
    // its verified caches, the boot retention sweep, the @username registry, the on-chain directory, the production
    // verifiers (ML-DSA site + finality, the WHIR whole-chain decider — without them every DSYNC adopt is `Unverified`), this
    // node's identity (DB-272/DB-341: the one vote key) and its custody opening (§CZ-b). The in-process node (`serve.rs`) and
    // the journey simulator boot through the SAME function, so a simulated restart is this restart.
    // The persist door REFUSES (never wipes) an unreadable or foreign checkpoint; the daemon exits 97 so a skew is noticed.
    let boot = {
        let (pk, _sk) = load_or_create_validator_key();
        match node.boot(&usdmd_node::persist::BootFiles::for_port(port), pubkey_id(&pk)) {
            Ok(b) => b,
            Err(why) => {
                eprintln!("[persist] ⛔⛔⛔ {why}");
                std::process::exit(97);
            }
        }
    };
    if boot.resumed {
        println!("[persist] resumed committed checkpoint from ~/.usdmd-node/state-{port}.snap (height continues, no wipe)");
        println!("[da-census] retention sweep at boot: {} cover-shaped record(s) dropped, {} referenced record(s) kept", boot.swept.0, boot.swept.1);
        println!("[block-window] {} whole block(s) held on disk ({} KB) — the span this node serves peers from", boot.window.0, boot.window.1 / 1024);
    }
    println!("[persist] on-chain directory loaded from ~/.usdmd-node/dir-{port}.bin ({} records)", boot.directory_records);
    if boot.custody_opening {
        println!("custody: this custodian's opening resumed from disk (it can attest and execute after the restart)");
    }
    // HF44 L2 settlement: the pqpool STARK-era settlement verify is RETIRED with the FFI. The default
    // `RefuseAllSettlement` stays installed — FAIL-CLOSED (no unverified value move is ever applied), and a
    // settlement is an OPTIONAL carrier so rejecting it never halts the chain (no-halts pillar). The WHIR-native
    // cross-sender settle verify (#144/#145 in `usdm-decider`) is the node-side conversion that re-enables the
    // carrier (#142) — sound-by-default until it lands, never admit-structurally.
    // ⭐⭐⭐ A VALIDATOR SEAT IS PUBLISHED TO THE CHAIN, NEVER TAKEN LOCALLY (§CW). Identical to the
    // in-process runtime in `serve.rs` — see the measurement there. MONEROUSD_VALIDATOR_BOND now means
    // "ask the chain for a seat": sign a `Class::MembershipBond` with this node's identity key and admit
    // it to the pool; it counts only once a block carries it, on every node, and is free exactly while
    // the reserve is zero. MONEROUSD_CHARTER_QUORUM is retired outright — a set each node read from its
    // own env was local state, §BA's fork with better manners; the chain records who bonded first.
    if std::env::var("MONEROUSD_VALIDATOR_BOND")
        .ok()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .map(|b| b > 0)
        .unwrap_or(false)
    {
        let (pk, sk) = load_or_create_validator_key();
        // DB-437: the one boot seat request (`Node::request_own_seat_at_boot`), shared with the in-process node and the
        // simulator's validator daemons. The log line prints only the request's STATUS (its outcome and the seat count —
        // no key bytes); the key never appears in a log line's arguments.
        let seat = node.request_own_seat_at_boot(&pk, &sk);
        println!("validator: {seat}");
    }

    // The transport that drives the LIVE NodeRuntime is the REAL Tor `.onion` mesh — ALWAYS. Onion is
    // NOT optional and there is NO non-onion node build (a featureless node would be a clearnet/IP-leak
    // privacy hole). submit_tx (RPC) pools + publishes the tx as constant-rate cells on `musdm/cells`,
    // seed peers are dialed over Tor and re-dialed forever, and the tick loop drains inbound peer cells
    // → verify + graft + re-gossip. So cross-node prove/verify/RELAY is automatic — the two nodes AGREE
    // over the onion wire. Onion-only by construction: if no Tor can come up the node FAILS CLOSED
    // (its IP never leaks — Pillar 1).
    #[cfg(feature = "libp2p-onion-ffi")]
    {
        // ALWAYS-UP onion: the node OWNS its Tor. `ensure_tor_socks` reuses an already-up SOCKS or SPAWNS +
        // SUPERVISES a node-owned tor (auto-respawn / KeepAlive) so onion connectivity is never a flaky
        // external dependency at a guessed port. Onion-only by construction: if no Tor can come up, FAIL
        // CLOSED — the node has deliberately NO non-onion egress path (Pillar 1: a node's IP never leaks).
        let tor_dir = usdmd_node::persist::state_dir().join(format!("tor-{port}"));
        match usdmd_node::tor_supervisor::ensure_tor_socks(port, &tor_dir) {
            Some(proxy) => match bring_up_onion_transport(&proxy, port) {
                Some(t) => {
                    run_node_runtime(node, t, port);
                    return;
                }
                None => {
                    eprintln!("fatal: onion transport bring-up FAILED over {proxy} — fail-closed (onion-only)");
                    std::process::exit(1);
                }
            },
            None => {
                eprintln!("fatal: no onion SOCKS available (no external Tor + no `tor` binary) — fail-closed (onion-only; the node never egresses off Tor). Install tor or set MONEROUSD_TOR_BIN.");
                std::process::exit(1);
            }
        }
    }
    // PURE-RUST arti onion mesh (no C libp2p FFI linked): serve THIS prepared node over the SAME arti Tor v3
    // `.onion` CellTransport the wallet's in-process node rides — ONE wire protocol for every node on every
    // device (daemon binary, desktop wallet, phone), so they all auto-join and converge on ONE mesh. The lib
    // serve loop spawns the relay + producer + auto-join (announce/dial/DSYNC-pull) + finality-voter threads
    // and blocks on the loopback RPC.
    #[cfg(all(not(feature = "libp2p-onion-ffi"), feature = "arti-onion"))]
    {
        if let Err(e) = usdmd_node::serve::serve_node_over_onion_mesh(node, port) {
            eprintln!("fatal: arti onion serve failed: {e} — fail-closed (onion-only)");
            std::process::exit(1);
        }
    }
    // NO onion transport linked at all ⇒ FAIL CLOSED. The former loopback-island fallback is REMOVED: a node
    // that can never converge with the network is a non-converging fake (islanded-node cheat), and a clearnet
    // fallback would leak the IP (Pillar 1). Build with `libp2p-onion-ffi` or `arti-onion`.
    #[cfg(all(not(feature = "libp2p-onion-ffi"), not(feature = "arti-onion")))]
    {
        drop(node);
        eprintln!("fatal: no onion transport feature linked (need `libp2p-onion-ffi` or `arti-onion`) — fail-closed (onion-only; a loopback island would never converge)");
        std::process::exit(1);
    }
}

/// This node's per-node validator ML-DSA keypair: load the persisted `(pk_len_le || pk || sk)`, or draw a
/// FRESH-RANDOM one from the CSPRNG on first run and persist it. The identity is this node's own and stable
/// across restarts, so the bonded id — and the reserve address derived from the bonded set — is stable.
fn load_or_create_validator_key() -> (Vec<u8>, Vec<u8>) {
    // DB-272: ONE definition, shared with the loopback RPC that signs this node's own unbond.
    usdmd_node::validator::load_or_create_node_vote_key()
}

/// Build the LIVE NodeRuntime over `transport`, spawn the produce/relay tick loop, and bind the
/// loopback tx-RPC on 127.0.0.1:`port`. submit_tx (RPC) pools + gossips a tx; the tick loop drains
/// inbound peer txs/blocks, consensus-verifies + grafts + re-gossips them, and produces on spacing —
/// so cross-node prove/verify/RELAY is automatic once the transport has a live peer. Generic over the
/// transport so the SAME runtime drives the in-process loopback OR the real Tor `.onion` mesh.
fn run_node_runtime<T>(mut node: Node, transport: T, port: u16)
where
    T: usdmd_node::transport::CellTransport + Send + 'static,
{
    use std::sync::{Arc, Mutex};
    use usdmd_node::node_runtime::NodeRuntime;
    // AUTO-PEER PERSISTENCE (no single point of failure): every peer this node has ever learned was loaded by the ONE
    // boot (`BootFiles::peers`, `~/.usdmd-node/known-peers-<port>.pd`), so it RE-DIALS survivors on restart — after one
    // successful join the pinned seed is never needed again. The runtime persists newly gossip-adopted peers back to it.
    // Grab the transport's AUTO-PEER dialer + own identity BEFORE the transport moves into the runtime. Every
    // node auto-peers UNCONDITIONALLY; the onion transport supplies a real onion dialer, the in-process test
    // loopback a no-op (peered by construction). There is no per-node opt-out.
    let peering = transport.peering();
    // BULK-lane serve slot: grab it BEFORE the transport moves into the runtime, install the answerer AFTER
    // the runtime exists. The callback is the runtime's ONE range-page encoder under the same lock every RPC
    // serve takes — a bulk ask can never serve a page shape the cell path would not.
    let bulk_slot = usdmd_node::transport::CellTransport::bulk_serve_slot(&transport);
    let rt = Arc::new(Mutex::new(NodeRuntime::new(node, transport)));
    // SPEED L7: the height this node had SEEN final before it stopped is re-installed (bound to the chain it resumed),
    // and kept current from here on — a restart never takes back a figure a wallet already showed as final.
    // cons: none on any growth axis — ONE record of 48 B (8 magic + 8 height + 32 block id), rewritten whole each time
    // the figure advances: 48 B at height 1 and 48 B at height 10^9, f(fixed constants), never f(history).
    rt.lock().unwrap_or_else(|e| e.into_inner()).node_mut().restore_seen_final_from(usdmd_node::node::Node::seen_final_record_path());
    let rt_for_term_watcher = rt.clone();
    // ⛔ SAVE ON TERM — a clean shutdown must not lose the last blocks' circulating records (the
    // five-times-measured roll-loss class; see Node::persist_blocking). A raw libc handler sets a flag; the
    // watcher thread below does the actual save under the rt lock, then exits the process.
    {
        // ⛔ THE RAW `signal()` EXTERN DID NOT TAKE — MEASURED 2026-08-13: a live TERM killed the process
        // with no handler print and no shutdown save, i.e. the default disposition still ruled. `sigaction`
        // installs reliably: `oscall::term_flag` registers it through signal-hook (a flag store, nothing else).
        let term_requested = usdmd_node::oscall::term_flag();
        let rt_term = rt_for_term_watcher.clone();
        let port_term = port;
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(200));
            // File-based shutdown request: `touch <HOME>/.usdmd-node/shutdown-<port>` asks for a clean
            // save+exit — signal-free, so it cannot suffer the measured silent non-delivery of the
            // sigaction path (two live TERMs, zero handler lines). The file is consumed (removed) on exit.
            // cons: one stat per 200ms poll tick; the deploy script must touch-then-wait (kill stays the
            // hard fallback); cons otherwise: none.
            let shutdown_file = usdmd_node::persist::state_dir().join(format!("shutdown-{port_term}"));
            if shutdown_file.exists() {
                let _ = std::fs::remove_file(&shutdown_file);
                term_requested.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            // A seed-derived identity was just provisioned (`/provision_validator`): the same clean save + exit, and
            // the supervisor (launchd KeepAlive, the wallet's watchdog) restarts the node onto the new identity.
            if usdmd_node::validator::identity_restart_requested() {
                term_requested.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if term_requested.load(std::sync::atomic::Ordering::SeqCst) {
                eprintln!("[term] signal received — writing the shutdown snapshot before exit");
                match rt_term.lock() {
                    Ok(g) => g.node().persist_blocking(),
                    Err(e) => eprintln!(
                        "[term] ⛔ rt lock failed at shutdown: {e} — exiting without save"
                    ),
                }
                std::process::exit(0);
            }
        });
    }

    {
        let rt_bulk = rt.clone();
        if let Ok(mut g) = bulk_slot.lock() {
            *g = Some(Arc::new(move |req: &[u8], turn: usdmd_node::transport::BulkServeTurn| -> Vec<u8> {
                // THE one NotesReq answerer — every request form, identical to the cell path.
                //
                // ⭐⭐⭐ THE BULK PAGE BUDGET IS THE REQUEST'S OWN FIXED SHAPE, NOT THE CELL PATH'S 1MB.
                //
                // ROOT-LAYER: this callback is where the bulk page budget is PRODUCED — the serve-side
                // `bounded_page_push` only honors what is passed here, and the dial side reads any frame
                // up to BULK_FRAME_MAX (16 MiB). The 1MB value was the PACED cell path's cover-discipline
                // budget copied onto the un-paced bulk lane, where it silently truncated every full-width
                // ask (32 records × ~330KB wire ≈ 10.6MB) down to ~3 records per Tor conversation.
                //
                // MEASURED (gate run 13, scratch musd-ecocheck-Ic1T36): a restarted node's backfill moved
                // ~110 records in 420s — n2 answered "3 of the named" ×24 and "1 of" ×19, ~1 conversation
                // per 8s over Tor — while the pair produced ~2.5 blocks/s, so the post-jump payload hole
                // (debt 114) NEVER closed and step 3 failed on unspent_root. At 32 records/conversation
                // the same cadence clears ~4 blocks/s > production: the race flips.
                //
                // NOT growth and NOT a reach bound: the budget is TX_REQ_FIXED_COUNT × the fixed record
                // wire shape — a protocol CONSTANT independent of chain length, and every named record the
                // page cannot fit is simply re-asked next tick (nothing is ever refused by age or reach).
                // The ≤1.8MB pillar bounds the DSYNC PROOF, which is untouched (it fits unchanged).
                // BULK_FRAME_MAX (16 MiB) still ceilings the frame at both ends against a lying header.
                //
                // MUST-STAY-GREEN: node lib suite (625/0), the #29 DSYNC suite, and the gate's step-3
                // rolling-restart reconvergence — this exists to make that step's heal beat production.
                match rt_bulk.lock() {
                    Ok(mut rt) => rt.serve_bulk_bytes(req, turn, 14 * 1024 * 1024),
                    Err(_) => Vec::new(),
                }
            }));
        }
    }

    // (0) AUTO-PEER + ANNOUNCE thread — the bidirectional PEER DIRECTORY loop that makes "any node on any
    //     device auto-joins the correct mesh" true with NO single point of failure. Every ~5s it:
    //       (a) ANNOUNCES this node's own signed peer record (once our tor `.onion` is up) so every peer learns
    //           + re-dials us — re-announcing with a bumped `seq` so onion rotations / restarts propagate; and
    //       (b) DIALS every peer in the converged directory (`known_peers` = persisted survivors + gossip-
    //           learned) it has not dialed yet, via the transport's own dialer.
    //     Because peer records gossip + persist, a restarted mesh re-forms among whoever is alive — the pinned
    //     seed is pure first-contact redundancy (pin many; any one up suffices), never a dependency.
    {
        let rt = Arc::clone(&rt);
        let (node_pk, node_sk) = load_or_create_validator_key();
        std::thread::Builder::new()
            .name("peer-directory".into())
            .spawn(move || {
                // DB-341: the seed line is read where `write_seed_line` wrote it — the one state directory.
                let node_dir = usdmd_node::persist::state_dir();
                // ⛔⛔⛔ THE ANNOUNCE WAS SILENTLY DEAD — IT READ THE ONION FROM A DIRECTORY THAT NO LONGER
                // EXISTS. This thread looked for `~/.usdmd-node/tor-<port>/` (the retired C-tor supervisor
                // layout), but the live arti transport keeps its state (and `own-onion.txt`) under
                // `~/.usdmd-arti-<slot>/` — so `onion_hostname()` returned `None` forever, with NO log line.
                // MEASURED 2026-08-13 on a live pair: node A drained 439 TipBeacons from B over a healthy
                // inbound link, `[peer-adopt]` fired ZERO times on either side, A held ZERO writers
                // ("written to NOBODY"), and B — the lighter chain — never heard A's beacon, so the fork
                // NEVER CONVERGED. Every mesh join since the arti migration has silently depended on the
                // hand-pinned seed line, which is exactly the manual link the design forbids.
                //
                // THE FIX IS ONE SOURCE OF TRUTH: the serve layer already derives this node's REAL dialable
                // record — right onion, right cell port, right PQ keys — and writes it whole to
                // `~/.usdmd-node/seed-line-<port>.txt`. Announce THAT (identity keys still from
                // `own_identity()`, the authoritative transport identity), and never recompute an address
                // from a second, driftable formula (the old `35000+port-27780` guess disagreed with the
                // real cell port too). Waiting is now LOUD — a silent `None` is how this hid.
                let mut dialed: std::collections::HashSet<String> = std::collections::HashSet::new();
                let mut last_announce_ms = 0u64;
                let mut last_wait_line_ms = 0u64;
                let mut ticks = 0u64;
                loop {
                    // (a) announce our own record once the .onion is up; re-announce every ~5 min with a fresh seq.
                    // ⛔ THE STRICT IDENTITY GATE KEPT THE WHOLE MESH SILENT — MEASURED 2026-08-13: zero
                    // `peer-directory ANNOUNCED` lines across ALL THREE nodes for hours, so the joiner C sat
                    // at peers=1 forever and every delivery to it crawled through one link (send #6's 14-min
                    // no-show). `own_identity()` flips only on HS-status Running or a completed inbound
                    // rendezvous; frequently-restarted nodes can satisfy neither for a long time. The
                    // announce's ADDRESS already comes from the seed-line file (the stable identity, the
                    // documented one-source-of-truth from the announce-regression fix) — so gate the KEYS the
                    // same way: `own_identity_early()` (same keys, available from service creation). Peers
                    // that dial before publication simply retry — the dialer already does. cons: a peer may
                    // burn dial attempts against a not-yet-published onion (bounded by the existing dial
                    // retry cadence, and exactly what the seed-line path already causes); cons otherwise: none.
                    if let Some((own_id, own_xpk, own_ek)) =
                        peering.own_identity().or_else(|| peering.own_identity_early())
                    {
                        let seed_path = node_dir.join(format!("seed-line-{port}.txt"));
                        let own_addr: Option<String> = std::fs::read_to_string(&seed_path)
                            .ok()
                            .and_then(|line| {
                                let f: Vec<&str> = line.trim().split('|').collect();
                                if f.len() == 4 && !f[1].is_empty() { Some(f[1].to_string()) } else { None }
                            });
                        let now = now_unix_ms();
                        match own_addr {
                            Some(addr) => {
                                if now.saturating_sub(last_announce_ms) >= 300_000 {
                                    // THE ONE OWN-RECORD ANNOUNCE (`NodeRuntime::announce_own_record`, 2026-10-06).
                                    let signed = {
                                        let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                                        r.announce_own_record(own_id, addr, own_xpk, own_ek, &node_pk, &node_sk, now)
                                    };
                                    if signed {
                                        last_announce_ms = now;
                                        println!(
                                            "onion: peer-directory ANNOUNCED this node's own record — \
                                             peers on any device can now learn + dial us without a \
                                             pinned seed."
                                        );
                                    }
                                }
                            }
                            None => {
                                if now.saturating_sub(last_wait_line_ms) >= 60_000 {
                                    last_wait_line_ms = now;
                                    println!(
                                        "onion: peer-directory WAITING for this node's own seed line at \
                                         {} — until it exists this node cannot announce itself and no \
                                         peer can auto-learn us.",
                                        seed_path.display()
                                    );
                                }
                            }
                        }
                    }
                    // (b) dial the converged directory with ECLIPSE RESISTANCE. Split known peers into ANCHORS
                    //     (signer is a BONDED validator in our live set — Sybil-resistant, each cost a real stake
                    //     bond) and ordinary free-onion peers. Anchors are RE-dialed every pass (idempotent), so a
                    //     set of free `.onion` Sybils can never displace the honest bonded peers from our
                    //     connection slots — eclipsing us requires posting real stake, which is costly. Ordinary
                    //     peers are dialed once (deduped).
                    let (anchors, others) = {
                        let r = rt.lock().unwrap_or_else(|e| e.into_inner());
                        r.node().peer_anchors()
                    };
                    for rec in &anchors {
                        // ALWAYS re-dial anchors (the stake-backed, eclipse-resistant slots) — never skip via dedup.
                        if peering.add(&rec.peer_id, &rec.addr, &rec.x_pk, &rec.ek)
                            && dialed.insert(rec.peer_id.clone())
                        {
                            println!(
                                "onion: peer-directory dialing BONDED anchor {} @ {}",
                                rec.peer_id, rec.addr
                            );
                        }
                    }
                    for rec in &others {
                        if dialed.contains(&rec.peer_id) {
                            continue;
                        }
                        if peering.add(&rec.peer_id, &rec.addr, &rec.x_pk, &rec.ek) {
                            dialed.insert(rec.peer_id.clone());
                            println!(
                                "onion: peer-directory dialing converged peer {} @ {}",
                                rec.peer_id, rec.addr
                            );
                        }
                    }
                    // (b2) ⭐ EPIDEMIC LETTER RE-FLOOD — every pass, the DAEMON lane.
                    // ROOT-LAYER: delivery is produced by the relay's outbound queue on a periodic sender —
                    // the admit path fires exactly once per blob, so retries can only live on this loop. The
                    // first landing of this call went into serve.rs's auto-join loop only, which the DAEMON
                    // never runs (this loop here is its counterpart) — so the deployed pair still one-shot.
                    // MEASURED: 2026-08-24 00:00 — with the re-flood binary live on both daemons, a wallet-app
                    // send STILL sat only in the origin's ring (recipient probe: 1 msg on 27780, 0 on 28901,
                    // >90s) because this lane was missing; the serve.rs lane alone never queued a retry.
                    // MUST-STAY-GREEN: letter suite; bounded traffic (≤64 frames/5s, countdown-drained).
                    {
                        let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                        r.reflood_letters();
                        // ⭐ The book gets the SAME epidemic retry as the letter ring: a resting
                        // order's post-time gossip is a single shot on the paced lane, and gate
                        // run 26 step 8 measured exactly that shot lost (n2's book empty for 150s
                        // while n1 held the order). Receivers dedup, so repeats change nothing.
                        r.reflood_orders();
                        r.request_letters();
                        r.request_dir_refill();
                    }
                    // (c) ANTI-ECLIPSE FRESHNESS PULL: every ~30s, actively pull the current tip via #29 DSYNC so a
                    //     node whose gossip inbound is being censored by a Sybil set still self-heals its VIEW from a
                    //     stake-backed anchor (any honest peer serves it) instead of silently going stale. Only when
                    //     we actually know of peers (a lone node has nothing to pull).
                    ticks = ticks.wrapping_add(1);
                    if ticks % 6 == 0 && !(anchors.is_empty() && others.is_empty()) {
                        let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                        r.request_dsync();
                    }
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            })
            .ok();
    }

    // TWO independent background threads share the runtime under a Mutex; the RPC (`rpc_http::serve`) is a
    // third lock-holder. Splitting relay from production is the FAST-pillar HALT FIX (#73 PoUW): the ~1s
    // PoUW grind + WHIR `pi` prove must NOT run under the lock (it would starve the RPC → get_info times
    // out → the mesh reads "0 blocks / Δ0 halt"). Each thread holds the lock only for microseconds.
    // BLOCK CLOCK = SHARED WALL-CLOCK (unix millis), NOT per-process elapsed. Every node MUST agree on "now" so a
    // node that RESTARTS (whose process-relative clock would reset to 0) does not reject a long-running peer's
    // blocks as future-dated — the mesh-halt bug where a restarted node rejects every gossiped block with
    // TimestampTooFarFuture and never catches up. `now_unix_ms()` is the single shared time source used for BOTH
    // block production and the timestamp validation, so the mesh converges regardless of when each node started.

    // ⭐ STARTUP HEALTH CHECK ON THE DECIDER — prove→verify a real AIR before this node accepts a
    // single carrier. `whir_decider::decider_selftest` was written as exactly this and had no caller, so a
    // node whose decider was broken found out by refusing every spend on the network instead of at boot.
    // One prove/verify of a fixed tiny statement; it does not grow with anything.
    if !usdmd_node::whir_decider::decider_selftest() {
        eprintln!(
            "[decider] ⛔ THE LIGHT DECIDER FAILED ITS OWN SELF-TEST at startup — this node cannot verify \
             a carrier, so every spend it sees would be refused. Refusing to serve rather than joining the \
             mesh as a node that says no to honest money."
        );
        std::process::exit(2);
    }
    // (1) RELAY + PUMP thread — drains inbound (verify + graft + re-gossip peer blocks/txs/sites/votes;
    //     serve DSYNC + emit/adopt tip-beacons) and emits EXACTLY ONE constant-rate onion cell every
    //     COVER_INTERVAL_MS. It runs at the CELL cadence (not the slower block spacing) so a real tx does
    //     not crawl to peers, and — critically — it is INDEPENDENT of the miner, so cover traffic + gossip
    //     never pause during a mine (the constant-rate metadata-privacy invariant holds) and its lock hold
    //     stays tiny. No production happens here (`tick_relay`, never `tick`).
    {
        let rt = Arc::clone(&rt);
        std::thread::spawn(move || {
            let cell_ms = usdmd_node::net::COVER_INTERVAL_MS.max(1);
            let mut last_info_ms = 0u64;
            loop {
                let now = now_unix_ms();
                {
                    let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                    r.tick_relay(now);
                }
                // DB-137: the PRODUCER publishes the `/get_info` string, on the thread that owns the tick
                // cadence, right after its own tick released the lock — twice a second at most. MEASURED
                // 2026-09-21: a separate refresher thread starved behind this thread on the unfair mutex (the
                // joiner's info trailed its live height by 150 blocks at rest); the request path's try-lock
                // never won on a busy node (h 788 served for ten minutes against a live 1,299).
                if now.saturating_sub(last_info_ms) >= 500 {
                    usdmd_node::rpc_http::refresh_get_info_cache(&rt);
                    last_info_ms = now;
                }
                std::thread::sleep(std::time::Duration::from_millis(cell_ms));
            }
        });
    }

    // (2) PRODUCER (miner) thread — on the 1s spacing boundary it takes the lock BRIEFLY to build the
    //     UNMINED template (`begin_produce`), RELEASES the lock, mines OFF-LOCK (grind PQ-PoUW to the DAA
    //     target + prove the non-outsourceable #73 `pi` — the heavy ~1s step), then re-takes the lock
    //     BRIEFLY to graft + gossip the mined block (`finish_produce`). Because the grind runs with the
    //     lock released, the RPC + the relay/pump thread stay fully responsive throughout (no halt).
    {
        let rt = Arc::clone(&rt);
        // This node's miner, built ONCE from its own seed. It grinds PQ-PoUW + proves `pi` purely from the
        // node's coinbase secrets (it never touches Node state), so it mines entirely off the lock; the
        // same seed ⇒ same secrets ⇒ the mined `pi` passes THIS node's own verify. Feature-gated: a
        // pure-Rust build has no miner and simply grafts the unmined template block.
        let miner = {
            let seed = rt
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .node()
                .miner_seed();
            usdmd_node::pow::PowMiner::new()
        };
        std::thread::spawn(move || loop {
            let now = now_unix_ms();
            // PRODUCE-CADENCE PROBE (see node_runtime statics): time the three phases so a slow live
            // cadence names its own bottleneck — lock WAIT at (a)/(c), the off-lock GRIND, and the
            // whole cycle — readable via /get_info. Stores are relaxed atomics, ~free.
            let cyc_t0 = std::time::Instant::now();
            // (a) BRIEF lock: build the unmined next-block template on the spacing boundary (else None).
            let wait_a_t0 = std::time::Instant::now();
            let job = {
                let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                let waited_a = wait_a_t0.elapsed().as_millis() as u64;
                usdmd_node::node_runtime::PRODUCE_LOCK_WAIT_MS
                    .store(waited_a, std::sync::atomic::Ordering::Relaxed);
                r.begin_produce(now, Hash32::ZERO, Hash32::ZERO)
            };
            // DB-105: the note transition proves HERE, off the lock; a refused one evicts its spends
            let job = job.and_then(|j| match usdmd_node::node_runtime::complete_produce_job(j) {
                Ok(j) => Some(j),
                Err(ids) => {
                    let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                    r.evict_refused_spends(&ids);
                    None
                }
            });
            let job = job.map(|mut j| {
                rt.lock().unwrap_or_else(|e| e.into_inner()).rebind_parents(&mut j);
                j
            });
            match job {
                Some(mut job) => {
                    // (b) OFF-LOCK: mine. Lock RELEASED for the whole grind — the FAST-pillar fix.
                    //     `miner` is Option (PowMiner::new can fail to derive secrets / init the kernel); a
                    //     None miner or a failed grind ⇒ None ⇒ no block this spacing (fail-closed).
                    // ⛔ A-F110 (lane af110, 2026-11-19): THE GRIND IS THE PRODUCTION. It runs at this node's duty
                    // (`NodeRuntime::grind_duty_milli`: its share, slow-started) until a digest meets the work; a new selected tip
                    // stops it, and the SAME proven job is rebound to the new tip (`rebind_parents` recomputes the work from the new
                    // selected parent) and ground again — the grind is memoryless, so the stop costs nothing and the prove is kept.
                    let grind_t0 = std::time::Instant::now();
                    let mined: Option<Block> = miner.as_ref().and_then(|m| usdmd_node::node_runtime::grind_job(&rt, m, &mut job, now_unix_ms));
                    usdmd_node::node_runtime::PRODUCE_GRIND_MS.store(
                        grind_t0.elapsed().as_millis() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    // (c) BRIEF lock: graft + gossip the mined block.
                    match mined {
                        Some(mb) => {
                            let wait_c_t0 = std::time::Instant::now();
                            let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                            let waited_c = wait_c_t0.elapsed().as_millis() as u64;
                            usdmd_node::node_runtime::PRODUCE_LOCK_WAIT_MS
                                .fetch_add(waited_c, std::sync::atomic::Ordering::Relaxed);
                            r.finish_produce(job, mb);
                            usdmd_node::node_runtime::PRODUCE_BLOCKS
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        None => {
                            usdmd_node::node_runtime::PRODUCE_MINE_FAILS
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            eprintln!(
                                "produce: mine failed (could not prove coinbase pi) — retry next spacing"
                            );
                        }
                    }
                    let cyc = cyc_t0.elapsed().as_millis() as u64;
                    usdmd_node::node_runtime::PRODUCE_CYCLE_MS
                        .store(cyc, std::sync::atomic::Ordering::Relaxed);
                    // Anomaly-gated (silent on a healthy cadence): one line when a cycle blows past 4x
                    // the 500ms target — names the guilty phase inline, no log growth per block.
                    if cyc > 2_000 {
                        eprintln!(
                            "[produce-probe] slow cycle {cyc}ms (lock-wait {}ms, grind {}ms) — the cadence                              bottleneck names itself here",
                            usdmd_node::node_runtime::PRODUCE_LOCK_WAIT_MS
                                .load(std::sync::atomic::Ordering::Relaxed),
                            usdmd_node::node_runtime::PRODUCE_GRIND_MS
                                .load(std::sync::atomic::Ordering::Relaxed)
                        );
                    }
                }
                // Not yet the spacing boundary — nap a small fraction of it so we neither spin the CPU nor
                // overshoot the 1s cadence (the mine itself, when due, dominates the interval anyway).
                None => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        });
    }

    // (3) FINALITY-VOTER thread — this bonded validator CASTS its finality vote so `finalized_height` actually
    //     CLIMBS. Without it the serve loop only INGESTS gossiped votes + never emits its own, so no vote is ever
    //     cast → finality stalls at 0 (violating the "finality NEVER halts — climbs by construction" pillar). Every
    //     second it signs (ML-DSA-65) a vote for the CHECKPOINT block — the selected-chain block at a stride-aligned
    //     height a couple below the tip — and submits it (counts locally + GOSSIPS to the bonded set). The stride
    //     makes every CONVERGED validator vote the SAME block, so ≥2/3 bonded weight lands on ONE block: a lone
    //     self-bonded node finalizes its own checkpoint (its 1 vote = 100% > 2/3); a multi-validator set converges
    //     the tally bidirectionally. Fail-closed by construction: an unbonded voter carries weight 0 (never counted,
    //     never a halt); onion-only — the vote rides the same gossip mesh as blocks.
    {
        let rt = Arc::clone(&rt);
        let (pk, sk) = load_or_create_validator_key();
        // ⛔ DB-437: this voter ran the superseded rule (stride 4, settle 2, the SELECTED-CHAIN block at a 1 s cadence) — the
        // shape runs 39/40 measured freezing finality at [1, 0], because under Tor latency each producer's selected chain is
        // its own blocks. It now runs the one tick every voter runs (`vote_guard::vote_tick`: the symmetric target, one DAG
        // width deep, levels caught up in order) at the in-process node's 200 ms cadence.
        std::thread::spawn(move || {
            // ⛔⛔⛔ DB-370 — what this key signed lives in the WRITE-AHEAD record beside the vote key (`vote_guard`), never in
            // a local that a restart resets to 0: a restarted voter that re-signs a level with a different block hands
            // every node the evidence that burns its bond.
            let mut guard = usdmd_node::vote_guard::VoteGuard::for_node_vote_key();
            // Payment locks (spec §11 stage 1): the same key signs them, under its own write-ahead table beside the vote
            // guard's record — what this key locked reaches the disk before the signature, and a restart reads it back.
            let mut lock_guard = usdmd_node::spend_lock::LockGuard::for_node_vote_key();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(200));
                let _ = usdmd_node::vote_guard::vote_tick(&rt, &mut guard, &pk, &sk);
                let _ = usdmd_node::spend_lock::lock_tick(&rt, &mut lock_guard, &pk, &sk);
            }
        });
    }
    // ⭐ A-F114 — under the network upgrade a seat request expires (`membership_bond_tx::SEAT_REQUEST_TTL_MS`), so a validator
    // that is not seated signs a fresh one whenever its kept request is stale; once a minute at most, and never before the
    // upgrade (`Node::own_seat_request_stale` answers false).
    if usdmd_node::params::canon_live()
        && std::env::var("MONEROUSD_VALIDATOR_BOND").ok().and_then(|s| s.trim().parse::<u128>().ok()).is_some_and(|b| b > 0)
    {
        let rt = Arc::clone(&rt);
        let (pk, sk) = load_or_create_validator_key();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            if g.node().own_seat_request_stale(&pk) {
                let seat = g.node_mut().request_own_seat_at_boot(&pk, &sk);
                println!("validator: the seat request expired; signed again: {seat}"); // status only, no key bytes
            }
        });
    }

    println!(
        "usdmd-node serve — loopback tx-RPC up on http://127.0.0.1:{port}/  (POST /submit_pq_tx · GET /get_info,/get_height) · NodeRuntime producing + gossiping (prove/verify/relay) · Ctrl-C to stop"
    );
    if let Err(e) = usdmd_node::rpc_http::serve(rt, port) {
        eprintln!("fatal: rpc bind/serve failed: {e}");
        std::process::exit(1);
    }
}

/// Bring up the REAL Tor `.onion` [`OnionTransport`] for the node runtime: seed a DETERMINISTIC identity
/// (MONEROUSD_ONION_SEED — so a peer can pre-configure this node's PeerId + PQ keys), listen behind the
/// tor HiddenService (MONEROUSD_ONION_LISTEN, e.g. `/ip4/127.0.0.1/tcp/<port>`), advertise our own
/// seed-peer identity to stdout, and add every configured persistent seed peer
/// (MONEROUSD_LIBP2P_SEED_PEERS = "peer_id|/dns/<onion>.onion/tcp/<port>|x_pk_hex|ek_hex", comma-sep).
#[cfg(feature = "libp2p-onion-ffi")]
fn bring_up_onion_transport(
    proxy: &str,
    port: u16,
) -> Option<usdmd_node::onion_transport::OnionTransport> {
    use usdmd_node::onion_transport::OnionTransport;
    // AUTO IDENTITY: a fresh-random 32B onion seed drawn ONCE from the OS CSPRNG and PERSISTED per node, so
    // the peer_id is STABLE across restarts (published peer files stay valid) yet never a guessable seed.
    let seed = std::env::var("MONEROUSD_ONION_SEED")
        .ok()
        .and_then(|h| hex_to_array32(&h))
        .unwrap_or_else(|| load_or_create_onion_seed(port));
    let t = OnionTransport::new_onion_seeded(proxy, &seed)?;
    println!("onion: node up over Tor SOCKS {proxy} (cells ride 'musdm/cells')");
    // AUTO LISTEN: bind a libp2p listen multiaddr so peers can DIAL us — default derived from the RPC port
    // (loopback for the same-host mesh); no manual MONEROUSD_ONION_LISTEN required.
    let listen = std::env::var("MONEROUSD_ONION_LISTEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            format!(
                "/ip4/127.0.0.1/tcp/{}",
                35000u16.wrapping_add(port.wrapping_sub(27780))
            )
        });
    println!("onion: listen {listen} -> {}", t.listen(&listen));
    // AUTO PEERING: publish our identity to the shared local peer directory + start a background discovery
    // loop that dials every OTHER node it finds there. GOSSIP IS THEREFORE AUTOMATIC ON RESTART — bidirectional,
    // self-healing, ZERO manual seed-peer wiring (the same-host analog of the chain-anchored onion directory).
    if let (Some(pid), Some(xpk), Some(ek)) = (t.own_peer_id(), t.own_x_pk(), t.own_ek()) {
        publish_peer_file(port, &pid, &listen, &xpk, &ek);
        start_peer_discovery(t.peer_adder(), port, &pid);
        println!("onion: auto-peer directory published + discovery running (peer_id={pid})");
        // CROSS-DEVICE REACHABILITY (precondition for "all nodes auto-join the correct mesh regardless of
        // device"): the loopback `listen` above only lets a SAME-HOST node dial us. Once tor generates THIS
        // node's own v3 .onion (its HiddenService descriptor — ~30-90s on first boot), re-advertise the REAL
        // .onion so a node on ANY device can dial us + converge, and emit the full canonical seed line to
        // ~/.usdmd-node/seed-line-<port>.txt so ANY always-up node can be pinned as a bootstrap seed with zero
        // manual wiring. NO fixed fallback: if the HS never generates, we FAIL LOUD (the node is honestly only
        // same-host-reachable), we never fabricate a fake/deterministic onion.
        let (pid_t, xpk_t, ek_t) = (pid.clone(), xpk, ek.clone());
        std::thread::Builder::new().name("onion-seed-line".into()).spawn(move || {
            let node_dir = usdmd_node::persist::state_dir();
            let tor_data = node_dir.join(format!("tor-{port}"));
            let hs_port = 35000u16.wrapping_add(port.wrapping_sub(27780));
            let mut waited = 0u32;
            loop {
                if let Some(onion) = usdmd_node::tor_supervisor::onion_hostname(&tor_data) {
                    let addr = format!("/dns/{onion}/tcp/{hs_port}");
                    // Re-publish our directory record with the REAL onion multiaddr (cross-device dialable).
                    publish_peer_file(port, &pid_t, &addr, &xpk_t, &ek_t);
                    let seed_line = format!("{pid_t}|{addr}|{}|{}", hex_encode(&xpk_t), hex_encode(&ek_t));
                    let out = node_dir.join(format!("seed-line-{port}.txt"));
                    let _ = std::fs::write(&out, &seed_line);
                    println!("onion: THIS NODE'S REACHABLE SEED LINE (pin to bootstrap a fresh node on ANY device):\n  {seed_line}");
                    println!("onion: seed line also written to {}", out.display());
                    return;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
                waited += 2;
                if waited >= 600 {
                    eprintln!("onion: tor HS .onion NOT generated after {waited}s — this node is only SAME-HOST reachable (cross-device peers cannot dial it yet). No fixed/fake onion is substituted; check tor.");
                    return;
                }
            }
        }).ok();
    }
    // Also honor an explicit MONEROUSD_LIBP2P_SEED_PEERS list (superset — e.g. a remote .onion peer).
    if let Ok(peers) = std::env::var("MONEROUSD_LIBP2P_SEED_PEERS") {
        for entry in peers.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let f: Vec<&str> = entry.split('|').collect();
            // DIGITAL-CASH-PRIVACY-REVIEWED (whole block): every value emitted below is a BOOTSTRAP SEED
            // ENTRYPOINT — a published .onion compiled byte-identically into every wallet build, the analogue
            // of Bitcoin's DNS seeds. No address, note, nullifier, amount, count or timing of THIS user's
            // activity appears, and no value is ever routed to a seed. Silence here is what islanded every
            // install, so refusing to speak is the harm this block exists to undo.
            if f.len() != 4 {
                eprintln!("onion: bad seed peer '{entry}'");
                continue;
            } // DIGITAL-CASH-PRIVACY-REVIEWED: published seed entrypoint, not user state
              // ⛔⛔⛔ A BOOTSTRAP SEED IS NEVER DISCARDED IN SILENCE. This `if let` used to have NO `else`, and
              // the ONE seed compiled into every wallet build (`canonical_seeds_testnet.txt`) carries EMPTY PQ
              // key fields — `n7zizldl….onion|/dns/…/tcp/27780||`. Four fields, so it cleared the length check
              // above; then `hex_to_array32("")` returned None and the entire bootstrap fell on the floor with
              // no log line at all. Every install therefore had ZERO peers, self-elected as a MESH_BOOTSTRAP
              // origin, and produced its OWN fork — an island showing a perfectly healthy block count. Funds
              // could not move between two devices because the two devices were never on the same chain.
              //
              // The PQ x_pk/ek are APP-LAYER cell keys, learned from the peer directory once connected — they
              // are NOT a precondition for the libp2p handshake. So a keyless seed line is still a usable
              // rendezvous: DIAL it, let the directory supply the keys, and say so out loud either way.
            match (hex_to_array32(f[2]), hex_to_vec(f[3])) {
                (Some(xpk), Some(ek)) => {
                    let verdict = if t.add_persistent_peer(f[0], f[1], &xpk, &ek) {
                        "dialing"
                    } else {
                        "REJECTED"
                    };
                    println!("onion: seed peer {} @ {} -> {verdict}", f[0], f[1]);
                    // DIGITAL-CASH-PRIVACY-REVIEWED: published seed entrypoint, not user state
                }
                _ => {
                    // Keys absent or malformed — the multiaddr alone still reaches the mesh.
                    let verdict = if t.dial(f[1]) {
                        "dialing"
                    } else {
                        "DIAL FAILED"
                    };
                    println!(
                        "onion: seed peer @ {} has no PQ keys (learned after connect) -> {verdict}",
                        f[1]
                    ); // DIGITAL-CASH-PRIVACY-REVIEWED: published seed entrypoint, not user state
                }
            }
        }
    }
    Some(t)
}

/// `~/.usdmd-node/peers/` — the shared local peer directory every same-host node publishes to + discovers from.
fn peer_dir() -> std::path::PathBuf {
    let d = usdmd_node::persist::state_dir().join("peers");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// Load this node's PERSISTED onion identity seed, or draw a FRESH 32-byte seed from the OS CSPRNG
/// (`/dev/urandom`) and persist it — fresh-random once, stable across restarts so the peer_id never changes.
/// NO FIXED-SEED FALLBACK: if the CSPRNG or persistence is unavailable, this FAILS LOUD (it never silently
/// falls back to a deterministic / all-zero identity). A shared/fixed identity would collide EVERY node onto
/// one peer_id and break mesh join — so each device MUST draw its OWN unique identity, the precondition for
/// "all nodes, on any device, automatically join the correct mesh".
fn load_or_create_onion_seed(port: u16) -> [u8; 32] {
    use std::io::Read;
    let dir = usdmd_node::persist::state_dir();
    std::fs::create_dir_all(&dir)
        .or_fatal("usdmd: cannot create the node's state directory for its onion identity — refusing to start");
    let path = dir.join(format!("onion-{port}.seed"));
    // Reuse a PERSISTED per-node identity (stable peer_id across restarts). Reject an all-zero seed: a real
    // node identity is never all-zero, so an all-zero file is the artifact of the retired fixed-seed cheat.
    // A TRANSPORT identity, not a value key (geth's `nodekey` shape): owner-only by the umask, never sealed, so no
    // keystore state can ever stop a node from joining (user 2026-09-28: key safety must never cost liveness).
    // O1-INFINITY-REVIEWED: the node's OWN onion identity, one 32-byte file; not chain state, read here as before.
    if let Ok(b) = std::fs::read(&path) {
        if b.len() == 32 {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            assert!(
                s.iter().any(|&x| x != 0),
                "usdmd: refusing an all-zero onion identity seed at {path:?} (retired fixed-seed cheat) — \
                 delete this file so a real per-node CSPRNG identity is drawn"
            );
            return s;
        }
    }
    // FRESH per-node identity from the OS CSPRNG — FAIL LOUD on any failure, never a fixed/deterministic fallback.
    let mut s = [0u8; 32];
    usdmd_node::oscall::os_random(&mut s)
        .or_fatal("usdmd: failed to read 32 CSPRNG bytes for the per-node identity — refusing to start with a fixed identity");
    assert!(
        s.iter().any(|&x| x != 0),
        "usdmd: the OS CSPRNG returned an all-zero identity seed — refusing to start"
    );
    usdmd_node::keystore::write_key_file_unsealed(&path, &s)
        .or_fatal("usdmd: failed to persist the per-node identity seed — refusing to start with an unstable identity");
    s
}

/// Publish this node's peer record (`peer_id|listen_multiaddr|x_pk_hex|ek_hex`) so peers auto-dial us.
fn publish_peer_file(port: u16, peer_id: &str, listen: &str, x_pk: &[u8], ek: &[u8]) {
    let line = format!("{peer_id}|{listen}|{}|{}", hex_encode(x_pk), hex_encode(ek));
    let _ = std::fs::write(peer_dir().join(format!("{port}.peer")), line);
}

/// Background AUTO-DISCOVERY: every few seconds, read every OTHER node's peer file in the shared directory and
/// dial it (dedup by peer_id). This makes the mesh peer + gossip AUTOMATICALLY on restart with zero manual
/// wiring — a node that comes up simply finds its neighbours and converges. No-gossip-halt cannot occur.
#[cfg(feature = "libp2p-onion-ffi")]
fn start_peer_discovery(
    adder: usdmd_node::onion_transport::PeerAdder,
    port: u16,
    own_peer_id: &str,
) {
    let own = own_peer_id.to_string();
    let self_file = format!("{port}.peer");
    std::thread::Builder::new()
        .name("onion-auto-peer".into())
        .spawn(move || {
            let mut dialed: std::collections::HashSet<String> = std::collections::HashSet::new();
            loop {
                if let Ok(rd) = std::fs::read_dir(peer_dir()) {
                    for e in rd.flatten() {
                        let name = e.file_name().to_string_lossy().to_string();
                        if !name.ends_with(".peer") || name == self_file {
                            continue;
                        }
                        let Ok(body) = std::fs::read_to_string(e.path()) else {
                            continue;
                        };
                        let f: Vec<&str> = body.trim().split('|').collect();
                        // f = [peer_id, listen_multiaddr, x_pk_hex, ek_hex]
                        if f.len() != 4 || f[0] == own || dialed.contains(f[0]) {
                            continue;
                        }
                        if let (Some(xpk), Some(ek)) = (hex_to_array32(f[2]), hex_to_vec(f[3])) {
                            if adder.add(f[0], f[1], &xpk, &ek) {
                                dialed.insert(f[0].to_string());
                                println!(
                                    "onion: auto-discovered + dialing peer {} @ {}",
                                    f[0], f[1]
                                );
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        })
        .ok();
}

/// hex → Vec<u8> (ignores non-hex separators; None on odd nibble count).
fn hex_to_vec(h: &str) -> Option<Vec<u8>> {
    let clean: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() % 2 != 0 {
        return None;
    }
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// hex → [u8;32] (exactly 32 bytes, else None).
fn hex_to_array32(h: &str) -> Option<[u8; 32]> {
    let v = hex_to_vec(h)?;
    if v.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Some(a)
}

/// bytes → lowercase hex (for advertising this node's seed-peer identity).
fn hex_encode(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{:02x}", x);
    }
    s
}

/// Genesis PoUW work — the starting accumulated-difficulty seed (a genesis parameter every chain
/// fixes); the live adaptive DAA takes over from block 1 onward.
/// A DISTINCT per-network id bound into the genesis so testnet and mainnet each own a SEPARATE chain by construction —
/// a note/tx/bond from one is structurally invalid on the other, and a re-genesis is never a deterministic replay of
/// another chain. Unknown/unset MONEROUSD_NET => mainnet (the value-bearing side, safe default; refused before launch).
/// (user 2026-07-11: "give our testnet and future mainnet their own network ids so something like that can never happen".)
/// See feedback_chains_nondeterministic_network_ids.
///
/// The domain-tagged, per-network genesis identity: `genesis_parity_commit` IS this value, so every node on the SAME
/// network derives the SAME genesis (mesh converges) while a DIFFERENT network derives a DIFFERENT genesis (isolated chains —
/// assets never cross), and the `chain_id` digest is scoped to this network by construction. ONE DEFINITION
/// (`params::network_genesis_prefix`, lane dcash 2026-11-12): this was a second copy of the transform; the mainnet genesis
/// now also commits to the launch anchor (`params::LaunchAnchor`), and a copy here would have built the un-anchored genesis
/// while the in-process node built the anchored one — the daemon disagreeing with itself about which chain it is on.
fn network_genesis_prefix(net: &str) -> Vec<u8> {
    usdmd_node::params::network_genesis_prefix(net)
}

/// ⭐⭐ `usdmd-node launch-anchor --tree <node crate dir> [--depth N] [--dry-run]` — WRITE THE MAINNET LAUNCH ANCHOR
/// (`params::LaunchAnchor`; user 2026-11-12: the mainnet genesis "has to be tied to something nobody can know before launch
/// (the files your launch command generates plus a recent Bitcoin block hash)"). The launch command runs this after it has
/// generated the launch files into the tree and before it builds the launch release:
///   1. a short-lived Tor of its own (SOCKS only — no hidden service, nothing published), so the node stays onion-only and
///      no paid or clearnet service is used;
///   2. the Bitcoin tip height from EVERY mempool onion explorer the price relays already read (`price_relay::RELAYS`,
///      mempool.space and emzy — at least two), and the hash of the block `depth` (default 6) below the lowest tip, from each:
///      every hash must be the same, or nothing is written (independent operators, a reorg-safe depth);
///   3. `params::launch_artifacts_digest` of `<tree>/src/sat_set_aside.bin` and `<tree>/src/defi_launch.bin`, both non-empty;
///   4. the three lines into `<tree>/src/mainnet_launch_anchor.txt` (or printed only, with `--dry-run`).
/// The release built from that tree opens mainnet with the anchored genesis; every build checks the anchor against its own
/// compiled launch files (`params::mainnet_launch_anchor`). Exit 0 on success, 1 on any refusal, with the reason.
/// DIGITAL-CASH-PRIVACY-REVIEWED: public Bitcoin block data from public explorers; no user, key, note or amount.
fn run_launch_anchor(args: &[String]) -> i32 {
    let after = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
    let Some(tree) = after("--tree") else {
        eprintln!("launch-anchor: --tree <the monerousd-node-zkdag folder> is required");
        return 1;
    };
    let depth: u64 = after("--depth").and_then(|d| d.parse().ok()).unwrap_or(6);
    let dry = args.iter().any(|a| a == "--dry-run");
    let src = std::path::Path::new(&tree).join("src");
    let read = |name: &str| std::fs::read(src.join(name)).map_err(|e| format!("cannot read src/{name}: {e}"));
    let (sat, defi) = match (read("sat_set_aside.bin"), read("defi_launch.bin")) {
        (Ok(s), Ok(d)) => (s, d),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("launch-anchor: {e}");
            return 1;
        }
    };
    if sat.is_empty() || defi.is_empty() {
        eprintln!(
            "launch-anchor: the launch files are empty (sat_set_aside.bin {} B, defi_launch.bin {} B): run the launch generator first",
            sat.len(),
            defi.len()
        );
        return 1;
    }
    let artifacts = usdmd_node::params::launch_artifacts_digest(&sat, &defi);
    let explorers: Vec<&usdmd_node::price_relay::Relay> = usdmd_node::price_relay::RELAYS
        .iter()
        .filter(|r| r.network == usdmd_node::price_relay::Network::Mempool)
        .collect();
    if explorers.len() < 2 {
        eprintln!("launch-anchor: this release lists {} Bitcoin explorer(s); two independent ones are required", explorers.len());
        return 1;
    }

    // 1. a Tor of our own, SOCKS only, stopped and removed on every exit below
    let Some(tor_bin) = usdmd_node::tor_supervisor::find_tor_binary() else {
        eprintln!("launch-anchor: no tor binary (set MONEROUSD_TOR_BIN or install tor)");
        return 1;
    };
    let tor_dir = std::env::temp_dir().join(format!("usdmd-launch-anchor-tor-{}", std::process::id()));
    let socks_port = match std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()) {
        Ok(a) => a.port(),
        Err(e) => {
            eprintln!("launch-anchor: no free local port for Tor: {e}");
            return 1;
        }
    };
    // NO config file at all: a path that does not exist, with `--ignore-missing-torrc`, so tor runs on its own defaults plus
    // the flags below. Measured 2026-11-12: with no `-f`, tor read the system torrc (/opt/homebrew/etc/tor/torrc), whose
    // ControlPort the machine's own tor already held, and exited at once; `-f /dev/null` is refused on macOS ("Unable to
    // open configuration file").
    let no_torrc = tor_dir.with_extension("no-torrc");
    // Tor's own progress lines, read back to wait for a full bootstrap before any explorer is asked.
    let tor_log = tor_dir.with_extension("log");
    let mut tor = match std::process::Command::new(&tor_bin)
        .arg("--ignore-missing-torrc")
        .arg("-f")
        .arg(&no_torrc)
        .arg("--defaults-torrc")
        .arg(&no_torrc)
        .args(["--SocksPort", &format!("127.0.0.1:{socks_port}"), "--DataDirectory"])
        .arg(&tor_dir)
        .args(["--Log", "warn stderr", "--Log"])
        .arg(format!("notice file {}", tor_log.display()))
        .stdout(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("launch-anchor: tor did not start: {e}");
            return 1;
        }
    };
    let code = launch_anchor_over_tor(&mut tor, &tor_log, socks_port, &explorers, depth, artifacts, &sat, &defi, &src, dry);
    let _ = tor.kill();
    let _ = tor.wait();
    let _ = std::fs::remove_dir_all(&tor_dir);
    let _ = std::fs::remove_file(&tor_log);
    code
}

/// The part of `launch-anchor` that runs while its Tor is up: SOCKS ready, every explorer's tip, the block `depth` below the
/// lowest tip from every explorer (all equal), then the anchor written (see [`run_launch_anchor`]).
#[allow(clippy::too_many_arguments)]
fn launch_anchor_over_tor(
    tor: &mut std::process::Child,
    tor_log: &std::path::Path,
    socks_port: u16,
    explorers: &[&usdmd_node::price_relay::Relay],
    depth: u64,
    artifacts: [u8; 32],
    sat: &[u8],
    defi: &[u8],
    src: &std::path::Path,
    dry: bool,
) -> i32 {
    use std::io::Write as _;
    let socks = format!("127.0.0.1:{socks_port}");
    let t0 = std::time::Instant::now();
    while std::net::TcpStream::connect(&socks).is_err() {
        if let Ok(Some(status)) = tor.try_wait() {
            eprintln!("launch-anchor: tor exited before its SOCKS port opened ({status}); its own lines are above");
            return 1;
        }
        if t0.elapsed() > std::time::Duration::from_secs(120) {
            eprintln!("launch-anchor: tor's SOCKS port did not open in 120 s");
            return 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    // A fresh Tor answers on SOCKS at once but reaches no onion until it has bootstrapped: wait for its own "Bootstrapped 100%"
    // line (measured 2026-11-12 under machine load: asking at SOCKS-open spent every retry before the circuits existed).
    let mut shown = String::new();
    loop {
        let log = std::fs::read_to_string(tor_log).unwrap_or_default();
        let last = log.lines().filter_map(|l| l.find("Bootstrapped ").map(|i| &l[i..])).last().unwrap_or("").to_string();
        if last != shown && !last.is_empty() {
            println!("launch-anchor: tor {last}");
            shown = last;
        }
        if shown.starts_with("Bootstrapped 100%") {
            break;
        }
        if let Ok(Some(status)) = tor.try_wait() {
            eprintln!("launch-anchor: tor exited while bootstrapping ({status})");
            return 1;
        }
        if t0.elapsed() > std::time::Duration::from_secs(600) {
            eprintln!("launch-anchor: tor did not finish bootstrapping in 600 s (last: {shown:?})");
            return 1;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let mut tips = Vec::new();
    for e in explorers {
        println!("launch-anchor: asking {} for the Bitcoin tip", e.operator);
        match usdmd_node::price_relay::explorer_tip_height(&socks, e.onion) {
            Some(h) => {
                println!("launch-anchor: {} says the tip is {h}", e.operator);
                tips.push(h)
            }
            None => {
                eprintln!("launch-anchor: {} did not answer its tip height", e.operator);
                return 1;
            }
        }
    }
    let low = tips.iter().copied().min().unwrap_or(0);
    let high = tips.iter().copied().max().unwrap_or(0);
    if low <= depth || high - low > 3 {
        eprintln!("launch-anchor: the explorers' tips disagree or are implausible: {tips:?}");
        return 1;
    }
    let anchor_height = low - depth;
    let mut hashes = Vec::new();
    for e in explorers {
        match usdmd_node::price_relay::explorer_block_hash(&socks, e.onion, anchor_height) {
            Some(h) => hashes.push(h),
            None => {
                eprintln!("launch-anchor: {} answered no block hash at height {anchor_height}", e.operator);
                return 1;
            }
        }
    }
    if hashes.windows(2).any(|w| w[0] != w[1]) {
        eprintln!("launch-anchor: the explorers disagree on block {anchor_height} — nothing written");
        return 1;
    }
    let anchor = usdmd_node::params::LaunchAnchor { bitcoin_height: anchor_height, bitcoin_block: hashes[0], artifacts };
    let text = anchor.render();
    if usdmd_node::params::LaunchAnchor::parse(&text) != Ok(Some(anchor)) {
        eprintln!("launch-anchor: the rendered anchor does not parse back to itself — nothing written");
        return 1;
    }
    let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("launch-anchor: Bitcoin block {anchor_height} = {} (tips {tips:?}, every explorer agrees)", hex(&hashes[0]));
    println!("launch-anchor: launch files digest {} (set-aside {} B, launch position {} B)", hex(&artifacts), sat.len(), defi.len());
    println!("launch-anchor: mainnet genesis anchor digest {}", hex(&anchor.digest()));
    if dry {
        print!("{text}");
        return 0;
    }
    // LOCAL-STORAGE-REQUIRED: the launch anchor is a BUILD INPUT written into the source tree once per network launch, compiled
    // into the launch release by include_str!; no node state, proof, DA record or wire field can supply what the release is
    // built from, and no node ever writes or reads it at run time.
    // bound: one fixed file of about 400 bytes per source tree, written once at launch.
    let path = src.join("mainnet_launch_anchor.txt");
    match std::fs::File::create(&path).and_then(|mut f| f.write_all(text.as_bytes())) {
        Ok(()) => {
            println!("launch-anchor: wrote {} — build the launch release from this tree", path.display());
            0
        }
        Err(e) => {
            eprintln!("launch-anchor: could not write {}: {e}", path.display());
            1
        }
    }
}

/// The canonical genesis header — a single source of truth on the lib so the daemon and the phone's in-process
/// node ([`usdmd_node::serve::run_in_process`]) build the SAME genesis.
///
/// It NAMES its network ([`usdmd_node::block::genesis_header_for_network`]). The bare all-constant header gave
/// every network one identical block id, so `chain_id` — which IS that id — could not tell testnet from mainnet
/// and the wallet's fork-detector reported agreement between nodes that shared no chain. Every genesis built
/// anywhere in this binary must therefore go through the SAME network binding as the params path above, or the
/// daemon would disagree with itself about what chain it is on.
fn genesis_header() -> BlockHeader {
    let net = std::env::var("MONEROUSD_NET").unwrap_or_default();
    usdmd_node::block::genesis_header_for_network(&network_genesis_prefix(&net))
}

/// The SHARED block clock: wall-clock milliseconds since the Unix epoch. Every node computes the same value for the
/// same instant (modulo tiny NTP drift, absorbed by `max_ts_drift_ms`), so block timestamps are comparable ACROSS
/// nodes and a restart never resets the clock. This is the fix for the mesh halt where a freshly-restarted node's
/// process-relative clock started at 0 and it rejected a long-running peer's blocks as `TimestampTooFarFuture`.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn main() {
    // ⛔⛔⛔ CUSTODY KEY SAFETY (user 2026-09-28): EVERY FILE THIS NODE CREATES IS OWNER-ONLY, FROM ITS FIRST BYTE.
    // MEASURED 2026-09-28 on the live home: the validator ML-DSA key (signs custody releases), the custody ML-KEM key
    // (opens sealed peg deltas), the custodian's sealed openings, the custody book and the onion identity seed were all
    // `-rw-r--r--`: six writers created them under the inherited umask 022, so any local account could read them.
    // ROOT-LAYER: the umask is where a created file's mode is PRODUCED, so setting it here, before anything is
    // created, covers every writer that exists and every one added later. A per-writer chmod would cover only the
    // writers somebody remembered, and would leave a window where the file is readable.
    // Files an older binary created were tightened by the operator (the live pair, 2026-09-28).
    // `harness::custody` pins that this stays the first statement of `main`.
    // cons: none. Nothing this node creates is meant for another local account; RPC and the onion transport are how
    // anything is shared.
    #[cfg(unix)]
    usdmd_node::oscall::umask_owner_only();
    // The one TLS crypto provider, before any Tor code runs (see `arti_transport::install_tls_provider`): without it the
    // onion thread panicked and no node could publish its onion (every real-process journey of 2026-11-01).
    usdmd_node::arti_transport::install_tls_provider();
    // Sovereign-hosting run mode: `usdmd-node serve-sites [<site-root>]` binds the LOOPBACK sovereign
    // HTTP server (127.0.0.1:27752) and serves the node's chain-anchored dApp bundles to the local UI
    // (the wallet's dApp browser + Ion Swap launcher). This is the node-first deploy route (Pillar C).
    // It BLOCKS; every other invocation runs the DAG bring-up demo below.
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "serve-sites") {
        run_sovereign(&args);
        return;
    }
    // Node lifecycle control (user-owned): `stop` PERMANENTLY stops the supervised node until a manual
    // `start`/`restart` — clearing the run-flag the LaunchAgent's keepalive is gated on, so nothing
    // self-resurrects (across exit AND reboot). This replaces the old unconditional `KeepAlive = true`.
    // lane speed5 2026-11-18: `--version` / `-V` print the version and exit. Before, any unknown argument fell through to the
    // in-process demo chain, so `usdmd-node --version` (the installers' smoke test) ran a whole demo before exiting.
    if args.iter().skip(1).any(|a| a == "--version" || a == "-V") {
        println!("usdmd-node v{}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|a| a == "stop") {
        std::process::exit(usdmd_node::lifecycle::stop());
    }
    if args.iter().any(|a| a == "restart") {
        std::process::exit(usdmd_node::lifecycle::restart());
    }
    if args.iter().any(|a| a == "start") {
        std::process::exit(usdmd_node::lifecycle::start());
    }
    // `usdmd-node serve` binds the LIVE loopback tx-RPC (127.0.0.1:27780) — the backend the greenfield
    // wallet's broadcast buttons POST `/submit_pq_tx` to. It BLOCKS (persistent node + producer).
    // `serve --supervised` (the LaunchAgent form) additionally honors the run-flag: if the node was
    // administratively `stop`ped, a keepalive/RunAtLoad relaunch exits CLEANLY instead of respawning.
    if args.iter().any(|a| a == "serve") {
        if args.iter().any(|a| a == "--supervised") && !usdmd_node::lifecycle::supervised_enabled()
        {
            println!(
                "usdmd-node: administratively STOPPED (disabled-sentinel {} present) — not starting. `usdmd-node start` to resume.",
                usdmd_node::lifecycle::disabled_flag_path().display()
            );
            return;
        }
        run_serve();
        return;
    }
    // `usdmd-node charter-export` prints THIS node's charter-member line ("mldsa_pk_hex:secp_compressed_hex",
    // PUBLIC parts only) so the launch operators assemble the shared MONEROUSD_CHARTER_QUORUM (each node holds
    // its own secrets; the aggregate is a real t-of-n threshold no single party can wield).
    // `usdmd-node launch-anchor --tree <node crate dir> [--depth N] [--dry-run]` (params::LaunchAnchor): the launch command's
    // last step before the launch release is built — writes the mainnet genesis anchor into that tree.
    if args.iter().any(|a| a == "launch-anchor") {
        std::process::exit(run_launch_anchor(&args));
    }
    // `usdmd-node verify-release --sums SHA256SUMS --attestations DIR` (docs/INSTALL.md §1): every artifact's digest and
    // ≥ 2 distinct compiled-in builders' ML-DSA-65 attestations over this exact sums file, or exit 1 with the refusal.
    if args.iter().any(|a| a == "verify-release") {
        let after = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
        let (Some(sums), Some(att)) = (after("--sums"), after("--attestations")) else {
            eprintln!("usage: usdmd-node verify-release --sums SHA256SUMS --attestations DIR");
            std::process::exit(2);
        };
        match usdmd_node::release_verify::verify_release(std::path::Path::new(&sums), std::path::Path::new(&att)) {
            Ok(builders) => {
                println!("release VERIFIED: every artifact in {sums} hashes to its line; {} distinct builder(s) attest it", builders.len());
                for b in builders {
                    println!("  builder {}", b.iter().map(|x| format!("{x:02x}")).collect::<String>());
                }
            }
            Err(why) => {
                eprintln!("release REFUSED: {why}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.iter().any(|a| a == "charter-export") {
        match usdmd_node::bridge::export_local_charter_member() {
            Some(line) => println!("{line}"),
            None => {
                eprintln!("charter-export: no validator key yet — run `serve` once to create it");
                std::process::exit(1);
            }
        }
        return;
    }

    println!(
        "usdmd-node v{} — ZK + PoUW + GHOSTDAG-DAG · PQ base layer · libp2p onion iron mesh",
        env!("CARGO_PKG_VERSION")
    );
    println!("greenfield node: pure-Rust usdm-decider WHIR verify + arti onion mesh; no Monero cryptonote_core.");

    let mut node = match Node::new(Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
        header: genesis_header(),
        tx_ids: vec![],
        pow_proof: Vec::new(),
        output_notes: Vec::new(),
        oli_tags: Vec::new(),
        account_targets: Vec::new(),
        bond_set: Vec::new(),
        // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
        credit_set: Vec::new(),
        dir_set: Vec::new(),
        letter_set: Vec::new(),
        tag_evidence: Vec::new(),
        note_transition: None,
        nullifier_proof: usdmd_node::block::NfBlockProof::default(),
        cover_transition: None,
        member_transition: None,
    }) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("fatal: genesis add failed: {e}");
            std::process::exit(1);
        }
    };
    // Pin the production PQ signature verifier: real ML-DSA-65 (FIPS 204) authenticates finality
    // votes + site publishes. The fail-closed UnpinnedVerifier default is only for an unconfigured node.
    node.set_site_verifier(Box::new(MlDsaVerifier));
    node.set_finality_verifier(Box::new(MlDsaVerifier));
    {
        let (pk, _sk) = load_or_create_validator_key();
        node.set_own_validator_id(pubkey_id(&pk));
    }
    let p = node.params();
    println!(
        "params: dag_width={} ghostdag_k={} target_spacing_ms={} (governance-tunable at runtime)",
        p.dag_width, p.ghostdag_k, p.target_spacing_ms
    );
    println!(
        "genesis tip = {}",
        node.selected_tip().or_fatal("genesis tip")
    );

    // Produce a short chain on the tips the node already holds — no parent-body refetch.
    let spacing = node.params().target_spacing_ms;
    let mut ts = spacing;
    for i in 0..6u64 {
        let fr = Hash32::hash(format!("frontier-{i}").as_bytes());
        let mc = Hash32::hash(format!("reward-{i}").as_bytes());
        match node.produce(ts, fr, mc) {
            Some(b) => {
                let _n = node.dag().get(&b.id()).or_fatal("produced block present");
            }
            None => println!("  (no block at ts={ts})"),
        }
        ts += spacing;
    }

    let tip = node.selected_tip().or_fatal("tip after production");
    let tip_node = node.dag().get(&tip).or_fatal("tip node");
    println!(
        "node advanced: blocks={} blue_score={} tips={} finalized_height={}",
        node.dag().len(),
        tip_node.blue_score,
        node.dag().tips().len(),
        node.finalized_height()
    );

    // Demonstrate BICAMERAL governance retuning a consensus parameter at RUNTIME (no restart). The
    // chamber totals come from chain state — bonded stake + recent block-production weight; here we
    // show a proposal clearing 2/3 of BOTH chambers so neither can move consensus alone.
    let before = node.params().dag_width;
    // SetDagWidth(48) is a throughput retune; DAG width is the community's free vote (not constitutionally
    // locked), so it clears the constitutional gate. The demo just shows the bicameral 2/3-of-both flow.
    let pid = node
        .propose_param(ParamChange::SetDagWidth(48))
        .or_fatal("a DAG-width retune clears the constitutional gate");
    for who in 1u8..=2 {
        let mut miner = [0u8; 32];
        miner[0] = who;
        let mut validator = [0u8; 32];
        validator[0] = 100 + who;
        node.vote_param(&pid, Chamber::Miners, miner, 3000);
        node.vote_param(&pid, Chamber::Validators, validator, 3000);
    }
    // ⛔ THE DEMO SHOWS THE TALLY, NOT A RETUNE — because a retune here would be a LOCAL rule change.
    // `evaluate_param_enactment` answers "would both chambers carry it" and touches nothing. Applying it
    // is a CHAIN OBJECT: the block must carry the enacted change so every node retunes at the same
    // height from the same evidence (see `docs/DB154-COMMITTED-NULLIFIER-ROOT.md`). A demo that printed
    // "retuned" while the params had not moved would be the dishonest kind of green.
    match node.evaluate_param_enactment(&pid, 9000, 9000) {
        Some(EnactOutcome::Enacted) => println!(
            "governance: bicameral 2/3 carried on this tally (dag_width {before} -> 48 once a block \
             CARRIES the enactment; live params deliberately unchanged here)"
        ),
        other => println!("governance: proposal would not carry ({other:?})"),
    }

    // Finalize the selected tip with REAL ML-DSA-signed validator votes — the full PQ finality path
    // end to end (keypair -> sign -> ML-DSA verify -> bonded-weight threshold -> finalized_height).
    // Every bonded validator signs + votes (full set, no cap); finality crosses once >=2/3 weight is in.
    let tip = node.selected_tip().or_fatal("tip");
    let tip_h = node.dag().get(&tip).or_fatal("tip node").blue_score;
    let validators: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| ml_dsa_keypair()).collect();
    // CHAIN-PUBLISH-REVIEWED: the BRING-UP DEMO's throwaway node, not a live chain. `main()` hands the
    // `serve` argument to `run_serve()` and returns; every other invocation builds its own scratch
    // `Node::new(Block { .. })` above, exercises the DAG end to end and exits. These three keypairs are
    // drawn here and exist nowhere else, so seating them mutates a node that no peer will ever meet and
    // that outlives this function by nothing. The LIVE seat was removed from `run_serve` (above) and from
    // `serve.rs` — on a real chain a validator is admitted ONLY by `Node::apply_bond_set` from a bond tx
    // the block carries.
    for (pk, _sk) in &validators {
        node.admit_validator(pubkey_id(pk), 2000, 0)
            .or_fatal("admit validator");
    }
    let vote_msg = finality_vote_msg(&tip, tip_h);
    for (pk, sk) in &validators {
        let sig = ml_dsa_sign(&vote_msg, sk).or_fatal("sign vote");
        let cert = VoteCert {
            pubkey: pk.clone(),
            block: tip,
            height: tip_h,
            sig,
        };
        node.submit_finality_vote(cert);
    }
    println!(
        "finality: tip finalized at height {} via real ML-DSA-65 votes (>=2/3 of {} bonded validators)",
        node.finalized_height(),
        node.validators().len()
    );

    // #29 DSYNC instant-sync over the constant-rate onion cell channel: node A serves its decider sync
    // bundle, which crosses to a FRESH node as a stream of fixed-size cells (cover-filled at a constant
    // rate, so timing/size leak nothing), where it is reassembled. The joiner's adopt gate is
    // FAIL-CLOSED by default; the pure-Rust usdm-decider WhirDecider (the default build) turns a
    // verified bundle into an O(1) jump to A's tip — no block-by-block replay.
    {
        use usdmd_node::protocol::WireMsg;
        use usdmd_node::sync::{FrontierSnapshot, SyncBundle};
        use usdmd_node::transport::{CellChannel, LoopbackTransport};

        let a_tip = node.selected_tip().or_fatal("tip to serve");
        let a_bs = node.dag().get(&a_tip).or_fatal("tip node").blue_score;
        let frontier = FrontierSnapshot {
            root: *node.note_frontier_root().as_bytes(),
            height: node.note_frontier_count(),
            peaks_hex: node.spend_frontier_peaks_hex(), // the serve's REAL spine (DB-376: a spine-less serve is a lie)
        };
        let _ = a_bs;
        let served = node
            .serve_sync_request(vec![0u8; 40_000], frontier)
            .or_fatal("A serves its DSYNC bundle");

        let (ta, tb) = LoopbackTransport::pair();
        let mut ca = CellChannel::new(ta);
        let mut cb = CellChannel::new(tb);
        ca.queue_message(&served)
            .or_fatal("queue the bundle as cells");

        let step = node.params().target_spacing_ms;
        let mut cells = 0u64;
        let mut received: Option<WireMsg> = None;
        for slot in 0..4000u64 {
            if ca.tick(slot * step).unwrap_or(false) {
                cells += 1;
            }
            if let Ok(Some(m)) = cb.poll() {
                received = Some(m);
                break;
            }
        }
        match received {
            Some(WireMsg::SyncResponse(bytes)) => {
                let bundle = SyncBundle::from_wire(&bytes);
                println!(
                    "instant-sync: #29 DSYNC bundle ({} B) crossed as {} constant-rate onion cells to a fresh node; decoded={}",
                    bytes.len(),
                    cells,
                    bundle.is_some()
                );
                if let Some(b) = bundle {
                    let mut joiner = Node::new(Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
                        header: genesis_header(),
                        tx_ids: vec![],
                        pow_proof: Vec::new(),
                        output_notes: Vec::new(),
                        oli_tags: Vec::new(),
                        account_targets: Vec::new(),
                        bond_set: Vec::new(),
                        // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
                        credit_set: Vec::new(),
                        dir_set: Vec::new(),
                        letter_set: Vec::new(),
                        tag_evidence: Vec::new(),
                        note_transition: None,
                        nullifier_proof: usdmd_node::block::NfBlockProof::default(),
                        cover_transition: None,
            member_transition: None,
                    })
                    .or_fatal("joiner genesis");
                    println!(
                        "instant-sync: fresh-node adopt = {:?} (fail-closed unless the WHIR decider verifies; then it jumps to tip {})",
                        joiner.instant_sync(b),
                        a_tip
                    );
                }
            }
            _ => println!("instant-sync: bundle did not reassemble within the slot budget"),
        }
    }

    // The two-node convergence coverage lives in `node_runtime.rs`: the join-mesh-or-nothing gate tests
    // (a fresh node NEVER produces until it adopts/grafts from a live peer) and the live-Tor 2-node
    // `two_separate_nodes_graft_each_others_blocks_over_onion` harness. A same-process pair in this
    // selftest could not demonstrate convergence (two same-genesis islands climb in lockstep), so no
    // in-binary demo runs here.

    #[cfg(feature = "libp2p-onion-ffi")]
    bring_up_onion();
}

/// Bring up the REAL Tor `.onion` transport (ALWAYS — onion is mandatory). Onion-only by
/// construction: the node is created over a Tor SOCKS proxy and reached only by `.onion` multiaddr.
/// Env-gated on `MONEROUSD_TOR_SOCKS` (e.g. "127.0.0.1:9050") so the pure bring-up does not require a
/// live Tor; when set, it opens the onion cell transport the [`usdmd_node::transport::CellChannel`]
/// drives. `MONEROUSD_ONION_LISTEN` optionally sets the `.onion` listen multiaddr.
#[cfg(feature = "libp2p-onion-ffi")]
fn bring_up_onion() {
    use usdmd_node::onion_transport::OnionTransport;
    match std::env::var("MONEROUSD_TOR_SOCKS") {
        Ok(proxy) if !proxy.is_empty() => match OnionTransport::new_onion(&proxy) {
            Some(t) => {
                println!("onion: node up over Tor SOCKS {proxy} (cells ride the 'musdm/cells' topic)");
                if let Ok(addr) = std::env::var("MONEROUSD_ONION_LISTEN") {
                    if !addr.is_empty() {
                        println!("onion: listen on {addr} -> {}", t.listen(&addr));
                    }
                }
            }
            None => eprintln!("onion: failed to bring up the onion node over {proxy}"),
        },
        _ => println!(
            "onion: real .onion CellTransport is linked; set MONEROUSD_TOR_SOCKS=<host:port> to bring up the live node"
        ),
    }
}

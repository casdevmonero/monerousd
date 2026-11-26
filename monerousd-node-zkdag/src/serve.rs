// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! In-process node serve entry — the LIBRARY orchestrator the wallet (Tauri / iOS) calls to spawn the node
//! ON A BACKGROUND THREAD binding loopback RPC, WITHOUT a subprocess or any C dylib (the phone runs its OWN
//! node in-process). Mirrors the daemon `run_serve` core in the shape a phone can link: build the genesis node
//! → the pure-Rust arti Tor v3 `.onion` mesh transport ([`crate::arti_transport::ArtiOnionTransport`], so the
//! phone node JOINS THE REAL MESH — hosts its own `.onion`, dials seed peers, converges; NOT a loopback island)
//! → [`crate::node_runtime::NodeRuntime`] → [`crate::rpc_http::serve`] (blocks, serving `get_info` /
//! `submit_pq_tx` / `get_my_pq_notes` / … on `127.0.0.1:port`). The wallet calls this on a dedicated background
//! thread so the UI thread never touches it; the loopback RPC binds instantly while Tor bootstraps in the
//! background, so the UI never freezes.

use crate::block::Block;
use crate::node::Node;
#[cfg(feature = "arti-onion")]
use crate::node_runtime::NodeRuntime;
use crate::params::ChainParams;
#[cfg(feature = "arti-onion")]
use std::sync::{Arc, Mutex};

/// Spawn the phone's OWN node in-process and serve the loopback JSON-RPC on `127.0.0.1:port`. BLOCKS (runs the
/// RPC accept loop), so the wallet calls this on a dedicated background thread — the UI thread never touches it.
/// `net` selects the network. Genesis is a DETERMINISTIC per-network CONSTANT (`genesis_parity_commit =
/// network_genesis_prefix(net)`, ZERO per-device input), so an in-process (phone) node and a daemon node on the
/// SAME network build BYTE-IDENTICAL genesis and converge by construction.
///
/// AUTO-JOIN BY CONSTRUCTION (the permanent shape for every device): a fresh install on any device starts on the
/// network's deterministic genesis, auto-dials the canonical seed `.onion`s (`MONEROUSD_LIBP2P_SEED_PEERS`), and
/// reaches the canonical chain BY ADOPTION: the first gossiped block whose ancestry it lacks triggers the throttled
/// #29 DSYNC request, the peer serves its ≤1.8MB decider bundle, and one verify-once adopt jumps this node to the
/// canonical tip (no env, no file, no hand-wiring on ANY joining device).

/// The shared LOCAL peer directory: one file per node on this host, each holding that node's dialable record.
/// This is the bootstrap gossip cannot provide — gossip needs a peer to gossip to, so two fresh nodes would
/// otherwise never find each other (measured: two processes, `mesh_joined: true`, 1 shared block of ~200).
fn local_peer_dir() -> std::path::PathBuf {
    // One state base for the whole node (see `persist::state_base`): a test or a second host node that sets
    // `MONEROUSD_STATE_DIR` must not leave peer records in the operator's live home either.
    let d = crate::persist::state_dir().join("peers");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// This node's CANONICAL SEED LINE — the one artifact another DEVICE needs to pin it as a bootstrap peer
/// (`MONEROUSD_LIBP2P_SEED_PEERS=<contents>`). The local peer directory cannot cross a machine boundary; this
/// can. Written whole then renamed so a reader never sees a partial line.
fn write_seed_line(port: u16, line: &str) {
    let dir = crate::persist::state_dir();
    let _ = std::fs::create_dir_all(&dir);
    let tmp = dir.join(format!("seed-line-{port}.txt.tmp"));
    let path = dir.join(format!("seed-line-{port}.txt"));
    let _ = std::fs::write(&tmp, line).and_then(|_| std::fs::rename(&tmp, &path));
}

/// Publish THIS node's record. Written whole then renamed, so a reader never sees a half-written file.
fn write_local_peer_record(port: u16, line: &str) {
    let dir = local_peer_dir();
    let tmp = dir.join(format!("{port}.peer.tmp"));
    let path = dir.join(format!("{port}.peer"));
    let _ = std::fs::write(&tmp, line).and_then(|_| std::fs::rename(&tmp, &path));
}

/// Every OTHER node's record on this host: `(peer_id, addr, x_pk, ek)`. Our own file is skipped by name AND
/// the caller re-checks by peer id — dialing yourself turns broadcast into an echo chamber that looks
/// perfectly healthy.
fn read_local_peer_records(own_port: u16) -> Vec<(String, String, Vec<u8>, Vec<u8>)> {
    let self_file = format!("{own_port}.peer");
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(local_peer_dir()) else {
        return out;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.ends_with(".peer") || name == self_file {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(e.path()) else {
            continue;
        };
        let f: Vec<&str> = body.trim().split('|').collect();
        if f.len() != 4 {
            continue; // malformed record — skipped, never guessed at
        }
        // x_pk is NOT a 32-byte classical key here. On the PQ onion transport `own_identity()` puts the
        // ML-KEM-768 public key (1184 B) in this slot — there is no classical static key to carry. Forcing it
        // into `[u8; 32]` silently dropped EVERY record and the discovery loop found nothing to dial, which
        // looked exactly like "no peers exist".
        let Some(xpk) = unhex(f[2]) else { continue };
        let Some(ek) = unhex(f[3]) else { continue };
        if xpk.is_empty() || ek.is_empty() {
            continue; // a record with no key material is not dialable — skipped, never guessed at
        }
        out.push((f[0].to_string(), f[1].to_string(), xpk, ek));
    }
    out
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(h: &str) -> Option<Vec<u8>> {
    let c: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if c.len() % 2 != 0 {
        return None;
    }
    (0..c.len() / 2)
        .map(|i| u8::from_str_radix(&c[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

#[cfg(all(test, feature = "pins-core"))]
mod peer_file_tests {
    use super::{read_local_peer_records, write_local_peer_record};

    /// ⭐ THE LOCAL PEER-FILE BOOTSTRAP, ROUND-TRIPPED AT REAL PQ KEY SIZES.
    ///
    /// This directory is what lets two same-host nodes find each other at all: the arti path announces its
    /// record only over gossip, and gossip needs a peer to gossip TO — so without a shared file two fresh
    /// nodes stay islanded forever (measured: 1 shared block root of ~430, both reporting `mesh_joined: true`).
    ///
    /// The size matters and is the whole point of this test. On the PQ transport the `x_pk` slot carries the
    /// ML-KEM-768 public key (1184 B), not a 32-byte classical key — there is no classical static key in a PQ
    /// base layer. Parsing it into `[u8; 32]` silently dropped EVERY record, and the discovery loop then
    /// looked identical to "there are no peers".
    #[test]
    fn a_published_peer_record_round_trips_with_pq_sized_keys_and_excludes_self() {
        let dir = std::env::temp_dir().join(format!("musd-peerfile-{}", std::process::id()));
        std::env::set_var("HOME", &dir);
        // DB-341: the node directory under this test's own HOME — removed only if it IS inside the temp dir.
        let nd = crate::persist::state_dir();
        if nd.starts_with(&dir) {
            let _ = std::fs::remove_dir_all(nd);
        }

        // Real PQ shapes: ML-KEM-768 encapsulation key is 1184 bytes, nowhere near 32.
        let (ek, _dk) = crate::pqkem::keypair();
        assert!(
            ek.len() > 32,
            "an ML-KEM public key is not 32 bytes — that is the assumption that broke this"
        );
        let hexed: String = ek.iter().map(|b| format!("{b:02x}")).collect();
        let onion = "h34wf6htca3sje4d6m52ujulyll4kujdbh2fjrxc7hpd4tobfzxtxaad.onion";
        let line = format!("{onion}|/dns/{onion}/tcp/9999|{hexed}|{hexed}");

        write_local_peer_record(27781, &line);
        write_local_peer_record(
            27782,
            &line.replace(
                onion,
                "ylz3yloafwm2vktoudc4hqk5akltbu6vzpjsfzfowms6fmr4ixzpsqyd.onion",
            ),
        );

        // A node reading as 27781 sees the OTHER record and not its own.
        let seen = read_local_peer_records(27781);
        assert_eq!(
            seen.len(),
            1,
            "exactly the sibling record is returned, never our own file"
        );
        let (pid, addr, xpk, ek_out) = &seen[0];
        assert!(
            pid.ends_with(".onion"),
            "the peer id is a Tor v3 onion: {pid}"
        );
        assert!(
            addr.contains(".onion"),
            "and its address carries the onion — onion-only by construction"
        );
        assert_eq!(
            xpk.len(),
            ek.len(),
            "the PQ key survives the round trip at FULL length, not truncated"
        );
        assert_eq!(ek_out.len(), ek.len());

        // The other direction excludes the other file — self-exclusion is by OWN port, both ways.
        let seen_b = read_local_peer_records(27782);
        assert_eq!(seen_b.len(), 1);
        assert_ne!(
            seen_b[0].0, seen[0].0,
            "each node sees its sibling, not itself"
        );

        // A malformed record is skipped, never half-parsed into a dialable peer.
        write_local_peer_record(27783, "not|enough");
        assert_eq!(
            read_local_peer_records(27781).len(),
            1,
            "still just the ONE valid sibling — a malformed record is skipped, not half-parsed into a peer"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

pub fn run_in_process(port: u16, net: &str) -> std::io::Result<()> {
    // Before the public launch no node starts on the mainnet identity (`params::mainnet_launched`), the daemon's own gate
    // (main.rs). Checked BEFORE the once-per-process latch below, so a refused call never blocks a later testnet start.
    if let Err(why) = crate::params::refuse_unlaunched_network(net) {
        eprintln!("[network] ⛔ {why}");
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, why));
    }
    // EXACTLY-ONCE PER PROCESS: the wallet's concurrent startup paths (UI probe + ensure_node) can both decide
    // "no node yet" before either has bound the RPC and call this twice ~1s apart (observed on iOS: two onion
    // transports racing on the same arti state dir + snapshot path + :27780 bind). The node is process-wide
    // state — the second caller must be a no-op join, never a second node.
    static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        eprintln!(
            "[node] run_in_process already active in this process — reusing the running node"
        );
        return Ok(());
    }
    // DB-341: this process serves `port`; every per-node file (the validator key first) is named by it.
    crate::persist::set_serving_port(port);
    let mut params = ChainParams::default();
    // GENESIS = DETERMINISTIC PER-NETWORK CONSTANT (user 2026-07-13): identical to the daemon (main.rs). Genesis
    // identity is PURELY this network's id prefix — ZERO per-device / env input — so an in-process (phone) node and
    // a daemon node on the SAME network build BYTE-IDENTICAL genesis and converge. Nothing device-specific enters
    // genesis (the old per-device commit input was removed at the source — it made a device diverge from a fresh one).
    params.genesis_parity_commit = crate::params::network_genesis_prefix(net);
    // Fix this process's network identity BEFORE any tx is stamped or judged — per-tx work is bound to it.
    crate::params::set_process_network_id(&params.genesis_parity_commit);
    params.net_prefix_len = params.genesis_parity_commit.len();
    let genesis = Block {
        cover_key: None,
        wide_objects: Vec::new(),
        tx_bodies: Vec::new(),
        agg_tables: Vec::new(),
        note_commitments: Vec::new(),
        // The genesis id NAMES this network (see `block::genesis_header_for_network`): the all-constant header
        // gave every network the same `chain_id`, so a testnet node and a mainnet node looked identical while
        // rejecting each other's DSYNC bundles forever.
        header: crate::block::genesis_header_for_network(&params.genesis_parity_commit),
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
        nullifier_proof: crate::block::NfBlockProof::default(),
        cover_transition: None,
        member_transition: None,
    };
    let mut node = Node::with_params(genesis, params).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("genesis add failed: {e:?}"),
        )
    })?;
    // UNIVERSAL FULL NODE — the in-process node carries the SAME prologue as the daemon (`main.rs run_serve`),
    // because there is exactly ONE node type on every device: it persists (#106 O(1) resume), it verifies
    // (site/finality/decider verifiers installed — without them every gossiped vote/site/DSYNC bundle is
    // dropped fail-closed and two peers could never reconcile), and it can carry the bonded-validator role.
    // An unreadable or foreign checkpoint is REFUSED by the door, never wiped; here that refusal becomes an
    // error the wallet can show ("node could not open its state") instead of the process exit the daemon
    // uses — an app must never die at launch on its node's cache (measured on the iPhone, 2026-09-17).
    // THE BLOCK WINDOW (2026-09-21): the in-process node keeps the same on-disk span a daemon keeps.
    // ⭐⭐⭐ THE ONE BOOT (`Node::boot`, 2026-10-06) — the daemon's exact sequence. MEASURED that day: this in-process node had
    // drifted from the daemon and never reloaded the @username registry or the on-chain directory, so the wallet's own node
    // forgot every registration at each restart. A refused checkpoint reaches the wallet as an error (an app never dies at
    // launch on its node's cache — measured on the iPhone, 2026-09-17).
    let (pk, _sk) = load_or_create_node_identity_key(port);
    let boot = node.boot(&crate::persist::BootFiles::for_port(port), crate::pqauth::pubkey_id(&pk)).map_err(|why| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("the node's persisted checkpoint was refused — {why}"))
    })?;
    if boot.resumed {
        eprintln!("[block-window] {} whole block(s) reopened from disk ({} KB)", boot.window.0, boot.window.1 / 1024);
        eprintln!("[node] resumed committed checkpoint (height continues, no wipe)");
        eprintln!("[da-census] retention sweep at boot: {} cover-shaped record(s) dropped, {} referenced record(s) kept", boot.swept.0, boot.swept.1);
    }
    eprintln!("[persist] on-chain directory: {} record(s)", boot.directory_records);
    if boot.custody_opening {
        eprintln!("[custody] this custodian's opening resumed from disk (it can attest and execute after the restart)");
    }
    // HF44 L2 settlement: the pqpool STARK-era settlement verify is RETIRED with the FFI. The node's default
    // `RefuseAllSettlement` stays installed — FAIL-CLOSED (no unverified value move is ever applied), and a
    // settlement is an OPTIONAL carrier so rejecting it never halts the chain (no-halts pillar). The WHIR-native
    // cross-sender settle verify (#144/#145 in `usdm-decider`) is the node-side conversion that re-enables the
    // carrier (#142) — sound-by-default until it lands, never admit-structurally.
    // ⭐⭐⭐ A VALIDATOR SEAT IS PUBLISHED TO THE CHAIN, NEVER TAKEN LOCALLY (§CW).
    //
    // This block used to call `Node::admit_validator` directly when MONEROUSD_VALIDATOR_BOND was set — a
    // local write that never travelled. MEASURED 2026-09-17 on two REAL peered `usdmd-node` processes,
    // each answering `{"validators":1}` (itself and nobody else): node0 minted a BTC deposit, refused its
    // own replay, and node1 MINTED THE SAME DEPOSIT AGAIN. One deposit, N nodes, N mints.
    //
    // Now the env var means "this node ASKS the chain for a seat": it signs a `Class::MembershipBond` with
    // its own identity key and admits it to the pool. The seat lands only when a block carries it and
    // `apply_bond_set` runs — on this node and every peer alike, from the same bytes. Whether the seat is
    // FREE is decided then, from chain state: the adaptive rule at its zero point (owner: "membership
    // bonding should be free whenever the required bond equals zero, i.e. reserve is zero"). No founding
    // keys, no charter constant: the chain records who bonded first.
    if std::env::var("MONEROUSD_VALIDATOR_BOND")
        .ok()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .map(|b| b > 0)
        .unwrap_or(false)
    {
        let (pk, sk) = load_or_create_node_identity_key(port);
        // DB-437: the one boot seat request (`Node::request_own_seat_at_boot`), shared with the daemon and the simulator's
        // validator daemons. The log line prints only the request's STATUS (its outcome and the seat count — no key
        // bytes); the key never appears in a log line's arguments.
        let seat = node.request_own_seat_at_boot(&pk, &sk);
        eprintln!("[node] {seat}");
    }
    serve_node_over_onion_mesh(node, port)
}

/// The node's dormant BLE transport LEG — a clone-shared [`crate::transport::BridgeCellTransport`] the node
/// peers over (inside its [`crate::transport::MultiTransport`]) ALONGSIDE arti Tor. The wallet's `node_ble`
/// CoreBluetooth radio grabs a clone (the SAME `Arc` queues) and pumps cell-fragments through it during a BLE
/// sync session, so a phone converges over Bluetooth when Tor is down. Idle it carries nothing (bounded
/// drop-oldest, ~1 MB cap) and never affects the arti path. One process-wide leg (init-once).
pub fn ble_bridge() -> crate::transport::BridgeCellTransport {
    static BLE_BRIDGE: std::sync::OnceLock<crate::transport::BridgeCellTransport> =
        std::sync::OnceLock::new();
    BLE_BRIDGE
        .get_or_init(|| crate::transport::BridgeCellTransport::new(256))
        .clone()
}

/// Bring up the pure-Rust arti onion mesh transport, join it to the node runtime, auto-dial seed peers, and
/// serve the loopback RPC (blocks). The node hosts its own `.onion` (dialable by peers) and dials the seed
/// peers' `.onion`, so blocks/txs flow BOTH ways and the DAGs converge — no loopback island. `pub` because it
/// is the ONE serve loop every arti node rides: the wallet's in-process node enters via [`run_in_process`]
/// (which prepares its node from `(commit, net)`), and the daemon binary (built without the C libp2p FFI)
/// enters directly with the node its own prologue prepared — one wire protocol on every device.
#[cfg(feature = "arti-onion")]
pub fn serve_node_over_onion_mesh(node: Node, port: u16) -> std::io::Result<()> {
    use crate::arti_transport::ArtiOnionTransport;
    use crate::hash::Hash32;
    use crate::transport::CellTransport;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    // ⭐ SPEED G1 (lane speed4, 2026-11-12, docs/SPEED-MAX-PROGRAM-20261112.md §8): the prover's proof-of-work grinds run
    // on the GPU where there is one. Prover-only: every witness is checked by the challenger's own CPU check before it is
    // used and the proofs are the bytes the CPU search makes, so peers see no difference. One status line at start.
    // CHAIN-OBJECT: none — this changes how fast this node proves, never what it proves or accepts.
    eprintln!("[gpu] {}", usdm_decider::gpu_grind::install());

    // ⛔ AUDIT 2026-11-10 (the bridge, read): A BINARY THAT CAN BE TOLD "THIS DEPOSIT IS CONFIRMED" NEVER SERVES BY
    // ACCIDENT. The `bridge-test-oracle` feature compiles in `/dev/inject_confirmed_deposit`; a custodian running such a
    // build attests deposits nobody made. The compile-time gate keeps it out of a default build, and nothing stopped a
    // build made WITH the feature (a test rig's binary copied to the wrong place) from serving like any other node. Such
    // a build now starts only when its operator says it is a test rig, and says so at every start.
    // SAFE-FALLBACK: none taken; a build with the oracle and without the word exits before it opens a port.
    #[cfg(feature = "bridge-test-oracle")]
    {
        if std::env::var("MONEROUSD_TEST_ORACLE_OK").as_deref() != Ok("1") {
            eprintln!(
                "[oracle] ⛔ this binary was built with the test deposit oracle (it can be told a foreign deposit was \
                 confirmed). It is not a node for real value and will not serve. A test rig sets MONEROUSD_TEST_ORACLE_OK=1."
            );
            std::process::exit(98);
        }
        eprintln!("[oracle] ⚠️ TEST RIG: this binary carries the test deposit oracle (MONEROUSD_TEST_ORACLE_OK=1). Never run it with real value.");
    }

    // SHARED WALL-CLOCK (unix millis) — every node agrees on "now" so a restarted node never rejects a peer's
    // blocks as future-dated (the mesh-halt bug). The same source drives production AND timestamp validation.
    fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    // ⭐ BOOT TIMELINE — name the term that eats the user's wait. MEASURED 2026-08-14 on BOTH
    // platforms: the RPC answered only minutes after spawn on several relaunches ("Starting your
    // node…" for the whole gap), and nothing said WHICH phase between transport spawn and the RPC
    // bind was eating it. One fixed line per phase with elapsed ms — no state, no growth, prints
    // once per boot. cons: none — four fixed log lines per process lifetime.
    let boot_t0 = std::time::Instant::now();
    let arti = ArtiOnionTransport::spawn(arti_state_dir(port))?;
    eprintln!(
        "[boot-timeline] transport spawned at {}ms",
        boot_t0.elapsed().as_millis()
    );
    // MULTI-RADIO: the node peers over arti Tor AND the dormant BLE leg at once ([`crate::transport::MultiTransport`]).
    // The BLE bridge carries no cells until the wallet's `node_ble` radio pumps it (a BLE sync session); idle it is
    // bounded + harmless, so the node is ALWAYS ready to converge over Bluetooth when Tor is down. `transport.peering()`
    // below is the COMPOSED peering — arti drives the `.onion` directory; the BLE leg is NoPeering (no-op).
    //
    // ⭐ THE MIX LAYER (docs/PQ-MIX-LAYER-SPEC-20261106.md): first, so it can take a bulk ask while Tor is down and hand
    // every one to arti while Tor is up. It reads one fact about Tor, whether it is carrying this node, and touches nothing else.
    let tor_writers = std::sync::Mutex::new(arti.peering());
    let mix = crate::pqmix::MixLeg::from_env(
        arti_state_dir(port),
        crate::transport::CellTransport::bulk_serve_slot(&arti),
        Box::new(move || {
            let writers = match tor_writers.lock() {
                Ok(p) => p.live_writers(),
                Err(e) => e.into_inner().live_writers(),
            };
            // Tor counts as down only when it is down Tor-wide: every peer silent for a minute and no probe circuit reaching two
            // known onions (`tor_reachable`). A node with no writer yet is still starting, not cut off.
            let _ = writers;
            crate::arti_transport::tor_reachable()
        }),
    )?;
    // Leg 1 is Tor. A user who chose our own network alone has it off; its links stay up, so choosing again costs nothing.
    let transport = crate::transport::MultiTransport::new(vec![Box::new(mix), Box::new(arti), Box::new(ble_bridge())])
        .with_gated_leg(1, crate::pqmix::tor_allowed);
    // ⭐⭐⭐ ZERO-CONFIG FIRST CONTACT — NODES MUST PEER WITHOUT A HUMAN.
    //
    // user 2026-08-10: *"if the wallets were working correctly then the two separate nodes should have
    // automatically peered. Nodes shouldnt require manual intervention. If you have to manually do it then the
    // wallet is still broken. That is the standard."* Correct, and the gap is stated in `peer_directory`'s own
    // header: the gossiped directory replaces the seed only *"after ONE successful join"* — FIRST contact still
    // needed a pinned `MONEROUSD_LIBP2P_SEED_PEERS`, and the old same-host discovery folder was retired as
    // "useless across devices". Two fresh nodes therefore had no way to find each other at all.
    //
    // MEASURED 2026-08-10: two independent nodes on one machine, both producing (heights 116 and 101), sat at
    // `peers: 0` indefinitely. They peered only after node A's 4,878-char seed line was pasted into node B by
    // hand — exactly the manual step that means the product is broken.
    //
    // Every node already writes its dialable seed line to `~/.usdmd-node/seed-line-<port>.txt`, so reading the
    // SIBLINGS of that file costs nothing and needs no new artifact. They are MERGED into the pinned-seed
    // string below so the existing, proven parse-and-dial path handles them — no second dial path to keep
    // correct, and `onion_host_of`'s rejection of any IP or non-`.onion` host still applies, so onion-only is
    // preserved by construction. Across devices nothing changes: the gossiped peer directory still converges.
    // DIGITAL-CASH-PRIVACY-REVIEWED: reads files this node's own process wrote, on this machine only, and
    // learns only what to DIAL. No note, amount, key, owner or commitment is involved.
    let sibling_seeds: String = {
        // DB-341: the port this node SERVES, not the launch env (an auto-selected port would skip the wrong line).
        let own_port = port.to_string();
        // ⛔ THE READER MUST USE THE WRITER'S BASE. `write_seed_line` and `local_peer_dir` write under
        // `persist::state_base()`; this reader read `$HOME` directly, so a node isolated by MONEROUSD_STATE_DIR still
        // found — and DIALLED — every seed line in the operator's live home (MEASURED by lane-wallet-cover 2026-09-27:
        // an in-process regtest node auto-joined 15 sibling seeds incl. the live testnet pair). One base, one reader.
        let dir = crate::persist::state_dir();
        let mut out: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if !name.starts_with("seed-line-") || !name.ends_with(".txt") {
                    continue;
                }
                // Never dial ourselves — the one entry here that is not a peer.
                if !own_port.is_empty() && name == format!("seed-line-{own_port}.txt") {
                    continue;
                }
                if let Ok(t) = std::fs::read_to_string(e.path()) {
                    let rec = t.trim().to_string();
                    if !rec.is_empty() {
                        out.push(rec);
                    }
                }
            }
        }
        if !out.is_empty() {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a COUNT of local files — never an address or key.
            crate::arti_transport::ilog(&format!(
                "[mesh] same-host auto-join: {} sibling seed line(s) found on this machine — merging into the \
                 dial set so a second node peers with NO manual seed and NO pinned bootstrap",
                out.len()
            ));
        }
        out.join(",")
    };
    // Auto-peer: dial every `.onion` seed record the deployment pins (mutual — each seed also dials us back).
    let all_seeds: String = {
        let pinned = std::env::var("MONEROUSD_LIBP2P_SEED_PEERS").unwrap_or_default();
        match (pinned.trim().is_empty(), sibling_seeds.is_empty()) {
            (true, true) => String::new(),
            (true, false) => sibling_seeds.clone(),
            (false, true) => pinned,
            (false, false) => format!("{},{}", pinned.trim(), sibling_seeds),
        }
    };
    if !all_seeds.is_empty() {
        let seeds = all_seeds;
        let peering = transport.peering();
        let mut n = 0usize;
        for rec in seeds.split(',').map(str::trim).filter(|r| !r.is_empty()) {
            // ⛔⛔⛔ THE SEED RECORD WAS HANDED OVER WHOLE, WITH ITS IDENTITY AND BOTH PQ KEYS DROPPED.
            //
            // A seed line is `pid|addr|xpk_hex|ek_hex` — exactly what the origin writes to
            // seed-line-<port>.txt. Passing the WHOLE string as the address with `""` for the peer id and
            // empty slices for both keys means the peer enters the dial list with NO identity and NO ML-KEM
            // key, so it never becomes a directory entry and nothing sealed can be addressed to it.
            //
            // MEASURED 2026-07-31: node B logged `[mesh] 1 onion seed peer(s) queued for the first hop` and
            // was actively dialing the origin, while `[link-state]` on the same node reported `0 known
            // peer(s)`. Seeded, dialing, and still not peered — which is why `peers` stayed 0 and every send
            // ran against a pair that could not settle.
            //
            // Parse the record into its four fields; fall back to treating the whole string as an address
            // only when it carries no separator, so a bare onion still works.
            let mut f = rec.split('|');
            let pid = f.next().unwrap_or("");
            let addr = f.next().unwrap_or("");
            fn hexb(h: &str) -> Vec<u8> {
                (0..h.len() / 2)
                    .filter_map(|i| u8::from_str_radix(h.get(i * 2..i * 2 + 2)?, 16).ok())
                    .collect()
            }
            let xpk = f.next().map(hexb).unwrap_or_default();
            let ek = f.next().map(hexb).unwrap_or_default();
            if addr.is_empty() {
                crate::arti_transport::ilog(&format!(
                    "[mesh] queued seed dial (bare address): {rec}"
                ));
                peering.add("", rec, &[], &[]);
            } else {
                crate::arti_transport::ilog(&format!(
                    "[mesh] queued seed dial: addr={addr} pid={} xpk={}B ek={}B — an empty xpk/ek here is \
                     why a seeded peer never became a KNOWN peer.",
                    &pid.chars().take(8).collect::<String>(),
                    xpk.len(),
                    ek.len()
                ));
                peering.add(pid, addr, &xpk, &ek);
            }
            n += 1;
        }
        crate::arti_transport::ilog(&format!(
            "[mesh] {n} onion seed peer(s) queued for the first hop"
        ));
        if n == 0 {
            crate::arti_transport::ilog(
                "[mesh] WARNING: MONEROUSD_LIBP2P_SEED_PEERS set but EMPTY — nothing to dial",
            );
        }
    }
    let dir_peering = transport.peering();
    // BULK-lane serve slot: grabbed BEFORE the transport moves into the runtime, installed AFTER the
    // runtime exists. ⛔ THIS WAS ONLY EVER WIRED IN main.rs's `run_node_runtime` — which is cfg'd to the
    // RETIRED libp2p-onion-ffi arm and is NEVER CALLED in the arti build (MEASURED 2026-08-13 the hard way:
    // strings absent from a provably fresh compile = zero monomorphizations; every bulk answer empty because
    // the serve slot was never installed; the TERM/shutdown watcher likewise never existed at runtime).
    // THIS file is the live driver, so the wiring lives HERE. cons: none beyond the pieces' own stated costs.
    let bulk_slot = crate::transport::CellTransport::bulk_serve_slot(&transport);
    let rt = Arc::new(Mutex::new(NodeRuntime::new(node, transport)));
    // SPEED L7: the height this node had SEEN final before it stopped is re-installed (bound to the chain it resumed),
    // and kept current from here on — a restart never takes back a figure a wallet already showed as final. Wired HERE,
    // in the live driver (see the note above: `main.rs`'s own serve arm is never called in this build).
    // cons: none on any growth axis — ONE record of 48 B (8 magic + 8 height + 32 block id), rewritten whole each time
    // the figure advances: 48 B at height 1 and 48 B at height 10^9, f(fixed constants), never f(history).
    rt.lock().unwrap_or_else(|e| e.into_inner()).node_mut().restore_seen_final_from(crate::node::Node::seen_final_record_path());
    // SPEED: this node's measured relay rounds are read back, so its voter and its producer resume at the pace they had
    // measured instead of the constants (MEASURED: 110 to 190 s without a measure after every restart, finality standing
    // still meanwhile). Wired HERE, in the driver a real node runs. cons: one fixed record of 136 B, f(fixed constants).
    rt.lock().unwrap_or_else(|e| e.into_inner()).restore_relay_rounds_from(crate::node_runtime::relay_round_record_path());
    eprintln!(
        "[boot-timeline] node runtime built at {}ms",
        boot_t0.elapsed().as_millis()
    );
    {
        let rt_bulk = rt.clone();
        if let Ok(mut g) = bulk_slot.lock() {
            *g = Some(std::sync::Arc::new(move |req: &[u8], turn: crate::transport::BulkServeTurn| -> Vec<u8> {
                // ⛔ DB-234 — EVERY INBOUND BULK ASK IS ANSWERED UNDER THE RUNTIME LOCK, AND NOTHING TIMED IT.
                // `[tick-slow]` times the DRAIN's holds only, so a node serving its peer's pages (block
                // batches, record pages, bundles) paid lock time no breakdown could see.
                // ROOT-LAYER: this closure is where the serve's lock hold is produced — the one door every bulk
                // ask passes; a per-handler stamp would miss the lock wait and any handler added later.
                // MEASURED: gate K (/tmp/musd-ecocheck-tgdoCV) — the follower served 94 batch pages to the
                // leader carrying 954 bodies the leader already held, and its drain's own slow ticks summed to
                // 43.2 s; the serve's share of the lock was unmeasurable. This is instrumentation only.
                // MUST-STAY-GREEN: every bulk answer byte-identical (the closure returns the same `out`), the
                // poisoned-lock arm unchanged (an empty answer; the asker re-asks another peer).
                // DIGITAL-CASH-PRIVACY-REVIEWED: the ask's kind byte, two durations and a reply byte count — the
                // asker already sees all of them; no id, record, note, amount, key or owner.
                // cons: two `Instant::now()` per bulk ask; a line only for a hold past half a block time.
                let wait_t0 = std::time::Instant::now();
                match rt_bulk.lock() {
                    Ok(mut r) => {
                        let hold_t0 = std::time::Instant::now();
                        let out = r.serve_bulk_bytes(req, turn, crate::protocol::RECORD_ANSWER_BUDGET_BYTES);
                        drop(r);
                        let hold_ms = hold_t0.elapsed().as_millis();
                        // The AGGREGATE too: many short holds can cost the drain more than one long one.
                        static SERVES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                        static HELD_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                        let n = SERVES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        let total =
                            HELD_MS.fetch_add(hold_ms as u64, std::sync::atomic::Ordering::Relaxed) + hold_ms as u64;
                        if n % 128 == 0 {
                            eprintln!(
                                "[bulk-serve] {n} bulk ask(s) served so far, {total} ms of rt lock held serving them"
                            );
                        }
                        if hold_ms > 250 {
                            eprintln!(
                                "[bulk-serve-slow] a kind-{} ask held the rt lock {hold_ms}ms (waited {}ms for it), \
                                 {} byte(s) answered — the drain and every RPC waited this long",
                                req.first().copied().unwrap_or(0),
                                hold_t0.duration_since(wait_t0).as_millis(),
                                out.len()
                            );
                        }
                        out
                    }
                    Err(_) => Vec::new(),
                }
            }));
        }
    }
    // Shutdown watcher (file-based, signal-free): `touch <HOME>/.usdmd-node/shutdown-<port>` → blocking
    // snapshot save → exit(0). Closes the measured roll-loss window for clean shutdowns; `kill` remains the
    // hard fallback (last autosave + mesh replication cover it). cons: one stat per 200ms.
    {
        // ⛔⛔⛔ SIGTERM / SIGINT MUST TAKE THE SAME PATH AS THE SHUTDOWN FILE. The `sigaction` handler
        // that sets a TERM flag lived only in `main.rs::run_node_runtime` — a function the default
        // `serve` command never reaches, because main.rs:358 hands straight to THIS function. So on the
        // onion path every TERM kept its DEFAULT disposition: the process died instantly with no
        // "[term]" line and no snapshot, and the node resumed from its last AUTOSAVE, losing every
        // record written since. That is the "measured silent non-delivery" the comment in main.rs
        // recorded, seen from the path that actually runs.
        //
        // ROOT-LAYER: the disposition is decided where the signal is received — in the process that
        // serves — and the blocking snapshot is produced here, under the rt lock, by the watcher that
        // already exists. Teaching every caller to `touch` a file first (the gate's `kill`, launchd
        // stop, a user's ^C) would be the read-layer patch; installing the handler in the dead path
        // was the same mistake once already.
        // MEASURED: before → scratch node killed with `kill -TERM`: exited in 1 s, 0 "[term]" lines,
        // 0 "shutdown snapshot WRITTEN", state file = the last autosave (43,307 B); gate 29's restarted
        // node had itself written 9 of the 12 seed-only records it then "truly did not hold".
        // After → the same TERM prints "[term] signal received", writes the blocking snapshot, exits 0.
        // MUST-STAY-GREEN: the shutdown-file restart (the deploy runbook's primitive — unchanged; the
        // flag and the file are OR-ed into one exit path), every RPC while serving (the handler only
        // stores a flag; the save still runs on the watcher thread under the same lock), and the
        // persist door tests (a snapshot written here is the same `persist_blocking` bytes).
        // cons: none — two libc syscalls at startup and one atomic load per 200 ms poll tick.
        let term_requested = crate::oscall::term_flag();
        let rt_term = rt.clone();
        std::thread::spawn(move || {
            let mut ticks: u64 = 0;
            loop {
            std::thread::sleep(std::time::Duration::from_millis(200));
            ticks += 1;
            // ⛔⛔⛔ THE NODE BOUNDS ITS OWN LOG DISK. Under launchd, fd 2 is a plain file that grows forever
            // (MEASURED 2026-09-03: node.err.log 52 MB, joiner 70 MB, +~300 KB/min, no rotation anywhere —
            // a per-tick growth axis on the operator's disk, the class NO-GROWTH bans). Every ~2 s the
            // watcher checks the file behind fd 2 and, past the cap, rotates it in-process: the current
            // file becomes `.1` (replacing an older `.1`), a fresh file takes fd 2. Worst case on disk is
            // 2 × cap per node, forever, whatever the supervisor does. Roots and tags in the log are
            // public consensus values; nothing here changes what is logged, only how much is kept.
            if ticks % 10 == 0 {
                if let Some(n) = crate::log_cap::rotate_stderr_if_over(crate::log_cap::STDERR_CAP_BYTES) {
                    eprintln!("[log] stderr rotated at {n} bytes — previous log kept as .1, cap {} bytes", crate::log_cap::STDERR_CAP_BYTES);
                }
            }
            let f = crate::persist::state_dir().join(format!("shutdown-{port}"));
            // A provisioned seed-derived identity restarts the node exactly as a shutdown file does.
            let by_file = f.exists() || crate::validator::identity_restart_requested();
            if by_file {
                let _ = std::fs::remove_file(&f);
            }
            if by_file || term_requested.load(std::sync::atomic::Ordering::SeqCst) {
                if by_file {
                    eprintln!("[term] shutdown file seen — writing the blocking snapshot before exit");
                } else {
                    eprintln!("[term] signal received — writing the blocking snapshot before exit");
                }
                match rt_term.lock() {
                    Ok(g) => g.node().persist_blocking(),
                    Err(e) => eprintln!("[term] ⛔ rt lock failed at shutdown: {e}"),
                }
                std::process::exit(0);
            }
            }
        });
    }

    // Register this node's ML-DSA identity as the bridge SIGNER, so /peg_in_execute and /peg_out_execute
    // can offer an attestation for an orchestrated confidential mint/redeem. The secret stays in-process —
    // set here, NEVER on the wire, never in a request. A node that sets nothing leaves it unset and
    // /peg_in_execute REQUESTS over the lane (DB-77: any node can ask; the custodians complete).
    //
    // ⛔ THE COMMENT HERE USED TO SAY "if THIS node self-bonded as a validator", and that is no longer
    // what this tests — nor what it should. Seating a signer is a LOCAL choice about which key this
    // process will sign with; it grants NO WEIGHT. Weight comes only from the chain-derived bonded set
    // (`Node::apply_bond_set`, fed by `Block::bond_set`). So this signature is inert until a real bond tx
    // has ridden a block naming this identity: `threshold_ok` weighs it against the bonded set and a key
    // with no chain-carried bond contributes ZERO. That is exactly the property whose absence let one BTC
    // deposit mint USDm once per node — the seat must come from the chain, never from this process.
    //
    // The env var is read only as the operator's INTENT to attest with this node's identity. It no longer
    // bonds anything (see the retired self-bond block above).
    {
        let wants_to_attest = std::env::var("MONEROUSD_VALIDATOR_BOND")
            .ok()
            .and_then(|s| s.trim().parse::<u128>().ok())
            .map(|b| b > 0)
            .unwrap_or(false)
            && crate::bridge::charter_members_from_env().first().is_none();
        if wants_to_attest {
            let (pk, sk) = load_or_create_node_identity_key(port);
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            g.set_bridge_signer(pk, sk);
            // …and the custody decapsulation key, so this custodian can OPEN the sealed peg-in deltas
            // addressed to the ek its seat published and attest other executors' mints.
            if let Some((ek, dk)) = crate::bridge::node_own_custody_kem() {
                g.set_custody_kem(ek, dk);
            }
        }
    }

    // (0) AUTO-JOIN / PEER-DIRECTORY thread — the SAME loop the daemon runs, so an in-process node on ANY
    //     device joins the wider mesh with zero hand-wiring (the permanent standard): (a) ANNOUNCE this node's
    //     own ML-DSA-signed dialable `.onion` record into the chain-anchored directory (so future peers dial
    //     US back — the bidirectional law); (b) DIAL the converged directory with eclipse resistance (bonded
    //     ANCHORS re-dialed every pass so free-onion Sybils can never displace the stake-backed slots; ordinary
    //     peers dialed once); (c) ANTI-ECLIPSE FRESHNESS PULL every ~30s: gossip a #29 DSYNC request so any
    //     honest peer serves its ≤1.8MB decider bundle. (c) is ALSO what carries a fresh no-env device onto the
    //     canonical chain: the verified bundle installs the canonical tip + frontier (genesis parity BY
    //     ADOPTION), and a node already at tip idempotently re-adopts the same state. Unlike the daemon this
    //     pulses even before directory records converge — a seeds-only fresh node must still pull.
    {
        let rt = Arc::clone(&rt);
        std::thread::spawn(move || {
            let (node_pk, node_sk) = load_or_create_node_identity_key(port);
            let mut dialed: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut last_announce_ms: u64 = 0;
            // When this node first noticed it had no onion identity yet, and when it last said so. See the
            // `[seed-line] still waiting` probe below: the wait for an identity was previously SILENT, which
            // is the single longest unexplained gap in a fresh node's life.
            let mut identity_wait_since_ms: u64 = 0;
            let mut last_identity_say_ms: u64 = 0;
            let mut ticks: u64 = 0;
            loop {
                // (a) announce our own dialable record once the `.onion` has published, refresh every ~5min.
                if let Some((own_id, own_xpk, own_ek)) = dir_peering.own_identity() {
                    let now = now_unix_ms();
                    // ⛔⛔⛔ ANNOUNCING ONCE AND HOPING IS WHY ONE SEND WORKS AND THE NEXT DOES NOT.
                    //
                    // user 2026-08-09: *"if 1 send works then all sends should work. If thats not the case
                    // then sends and receives arent unilateral."*
                    //
                    // This was a flat 300_000 ms. A node therefore announced its own peer record ONCE at
                    // startup and then stayed silent for five minutes — and `announce_peer` already records
                    // that the onion comes up "MINUTES before any link exists", so that single announce is
                    // routinely written to nobody. Whether a counterparty ever learns this node is then a
                    // RACE between one broadcast and the link coming up.
                    //
                    // MEASURED 2026-08-09 on a failing cross-device run, node B:
                    //   `[link-state] 25 inbound message(s) since the last probe (121 since boot) from 0
                    //    known peer(s)`
                    // 121 messages received from zero known peers: the node can hear, but knows nobody to
                    // ask — so it can never request a backfill, and a note that did not arrive by push is
                    // simply never obtained. Passing runs show a healthy peer; failing ones show this.
                    //
                    // So keep announcing until somebody can actually hear it. `live_writers() == 0` means
                    // this node cannot currently write to any peer, which is exactly the state in which its
                    // last announce cannot have landed. CONDITION-DRIVEN, not a timer: it stops the moment a
                    // writer exists, and the 5-minute steady-state cadence is unchanged. Nothing is refused,
                    // bounded, or aged out — this only removes a silence that had no reason to exist.
                    let announce_due_ms: u64 = if dir_peering.live_writers() == 0 {
                        10_000
                    } else {
                        300_000
                    };
                    if now.saturating_sub(last_announce_ms) >= announce_due_ms {
                        let addr = format!(
                            "/dns/{own_id}/tcp/{}",
                            crate::arti_transport::ONION_CELL_PORT
                        );
                        let rec_line = format!("{}|{}|{}|{}", own_id, addr, hex_lower(&own_xpk), hex_lower(&own_ek));
                        // ⭐ PUBLISH TO THE SHARED LOCAL PEER DIRECTORY TOO — the BOOTSTRAP that gossip
                        // cannot provide.
                        //
                        // `announce_peer` gossips this record over the mesh, which requires a peer to gossip
                        // it TO. Two fresh nodes therefore never find each other: discovery needs a
                        // connection and a connection needs discovery. MEASURED: two node processes on one
                        // host, both reporting `mesh_joined: true` and the same chain_id, shared 1 block root
                        // of ~200 — each had produced its whole chain alone. (Identical chain_id is what
                        // ISLANDED nodes look like, since genesis is f(network).)
                        //
                        // A file per node in one directory breaks the cycle with no pre-existing link. It is
                        // strictly additive: gossip still carries records across devices, and the onion
                        // address published here is the REAL one, so nothing is same-host-only by design.
                        write_local_peer_record(port, &rec_line);
                        // THE ONE OWN-RECORD ANNOUNCE (`NodeRuntime::announce_own_record`, 2026-10-06).
                        let signed = {
                            let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                            r.announce_own_record(own_id, addr, own_xpk, own_ek, &node_pk, &node_sk, now)
                        };
                        if signed {
                            last_announce_ms = now;
                        }
                    }
                }
                // (a1) EMIT THIS NODE'S CANONICAL SEED LINE once its `.onion` exists, so a node on ANOTHER
                // DEVICE can pin it via `MONEROUSD_LIBP2P_SEED_PEERS` with no log-scraping. The same-host peer
                // directory below cannot cross a machine boundary; this file is the artifact that does.
                //
                // Written every pass (cheap, idempotent) because the onion appears ~30-90s AFTER boot — a
                // one-shot write at startup would always run too early and emit nothing.
                // ⭐⭐⭐ THE SEED LINE USES THE KNOWN ADDRESS, NOT THE PUBLISHED ONE.
                //
                // This read `own_identity()`, which answers only once the hidden service is REACHABLE. The
                // mesh announcement still waits for that — announcing an unpublished address is what
                // islanded fresh nodes, and that gate is untouched. But a seed line is a local file another
                // device reads to learn what to DIAL, and the address is known the instant the service
                // exists.
                //
                // MEASURED 2026-08-09 on the cross-device pair: node A logged `state Bootstrapping, problem
                // none reported` for the FULL 180s run — not wedged, just slow, so no heal path applied —
                // the seed line never appeared, and the run failed at "node A never published a dialable
                // seed line" with node B holding no peers. Node A's address had been known since second one.
                //
                // A dialer retries until the descriptor lands, which it already does. Withholding the
                // address does not make the pair connect sooner; it only guarantees they cannot.
                if let Some((own_id, own_xpk, own_ek)) = dir_peering.own_identity_early() {
                    let line = format!(
                        "{}|/dns/{}/tcp/{}|{}|{}",
                        own_id,
                        own_id,
                        crate::arti_transport::ONION_CELL_PORT,
                        hex_lower(&own_xpk),
                        hex_lower(&own_ek)
                    );
                    if identity_wait_since_ms != 0 {
                        eprintln!(
                            "[seed-line] ✅ onion identity established after {}s of waiting — seed line \
                             written; a second node can now be started against it.",
                            now_unix_ms().saturating_sub(identity_wait_since_ms) / 1000
                        );
                        identity_wait_since_ms = 0;
                    }
                    write_seed_line(port, &line);
                    // ⛔ AND PUBLISH IT FOR SAME-HOST PEERS. `write_local_peer_record` existed, was tested,
                    // and was NEVER CALLED outside those tests — so two nodes on one machine could only ever
                    // find each other through Tor. Every pair run therefore hinged on an onion descriptor
                    // publishing, which this session measured at 6s, 44s, 230s and never; when it never
                    // published, no seed line was written, the second node was started with an EMPTY seed and
                    // dialled nobody, and the whole run was void while looking busy. A node that already knows
                    // its own record has no reason to withhold it from a peer sharing its filesystem.
                    write_local_peer_record(port, &line);
                } else {
                    // ⛔⛔⛔ THE LONGEST UNEXPLAINED SILENCE IN A FRESH NODE'S LIFE — AND IT PRINTED NOTHING.
                    //
                    // user 2026-08-09: "add more observability ... our sends between devices should be
                    // instant like bnb, we have 500ms block time."
                    //
                    // Until `own_identity()` answers there is no seed line, so a second node cannot be
                    // pointed at this one and the pair CANNOT peer. That whole period was mute: the node
                    // printed chain progress and looked perfectly healthy while the one artifact another
                    // device needs did not exist.
                    //
                    // MEASURED 2026-08-09, `cross_device_send` (4 processes), one captured FAILING run:
                    //   `node A never published a dialable seed line at .../seed-line-27841.txt — node B
                    //    would start with no peers and island, which no send can cross`
                    // The harness had waited 180s and the node had said NOTHING about why. The neighbouring
                    // comment records the same wait measured at "6s, 44s, 230s and never". How often this
                    // cause accounts for a failure across runs is NOT established — one failing run was
                    // captured and read, and this branch is what makes the next one legible.
                    //
                    // NO-WINDOW-REVIEWED: the 15s is a PRINT CADENCE and decides no verdict. Crossing it
                    // REFUSES NOTHING — it does not stop waiting, give up, retry differently, reject a peer,
                    // or bound how far back anything may reach. The surrounding loop keeps polling
                    // `own_identity()` to exhaustion exactly as before; the only effect is whether a line is
                    // emitted this pass instead of every pass. Delete this branch and node behaviour is
                    // byte-identical. Same shape as `[link-state]`'s existing emit cadence.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: an elapsed duration only. No address, note, amount, key,
                    // owner or peer is named — this branch runs precisely because no identity exists yet.
                    let now_ms = now_unix_ms();
                    if identity_wait_since_ms == 0 {
                        identity_wait_since_ms = now_ms;
                        last_identity_say_ms = now_ms;
                        eprintln!(
                            "[seed-line] no onion identity yet — this node has NO seed line, so no other \
                             device can be pointed at it and no cross-device send can cross. Waiting."
                        );
                    } else if now_ms.saturating_sub(last_identity_say_ms) >= 15_000 {
                        last_identity_say_ms = now_ms;
                        eprintln!(
                            "[seed-line] still waiting for an onion identity after {}s — the chain is \
                             producing but this node is UN-DIALABLE and its seed line does not exist, so \
                             another device has nothing to dial.",
                            now_ms.saturating_sub(identity_wait_since_ms) / 1000
                        );
                    }
                }
                // (a1b) RE-DIAL the pinned cross-device seeds every pass, not only at boot. The startup dial
                // runs BEFORE this node's onion is established, so a seed that was unreachable then would
                // never be retried and the node would sit permanently islanded from the deployment it was
                // configured to join.
                if let Ok(seeds) = std::env::var("MONEROUSD_LIBP2P_SEED_PEERS") {
                    // ⛔ NEVER DIAL OURSELVES. The canonical seed list is compiled into every build, so the node
                    // that PUBLISHED a seed reads its OWN onion back out of it and adds itself as a peer —
                    // measured live: `/get_peers` listed this node's own `.onion` alongside its real peer.
                    // Self-peering turns broadcast into an echo chamber that looks perfectly healthy: the peer
                    // count rises, gossip flows, and none of it is another party. It also burns a dial slot
                    // that eclipse resistance is counting on.
                    // ⛔⛔⛔ `dialed` IS PERMANENT, SO A NODE WHOSE LINK DIES NEVER RE-DIALS ANYONE.
                    //
                    // Ordinary peers are "dialed once" and their key stays in `dialed` forever, even after the
                    // link is gone. An ACCEPTOR is hit hardest: its only way to write back is the write half of
                    // the stream a peer opened, so when that stream dies it holds NO writer and can never
                    // re-establish one on its own initiative.
                    //
                    // MEASURED 2026-08-01 on the live pair: node 27840 `peers=2 writers_held=0 inbound=20576`
                    // against node 27841 `peers=2 writers_held=6`. Node A had drained 20,576 cells and could
                    // not write a single one back — a one-way link that every peer counter still reported as
                    // healthy, and the send-precondition guard correctly refused to run a payment over it.
                    //
                    // Holding ZERO writers is proof the previous dials are dead, so clear the record of them
                    // and let this pass dial again. This is CONDITION-driven, not a timer and not a retry
                    // budget: it fires exactly while the node cannot write to anybody, and stops the moment a
                    // writer exists. It EXTENDS reachability and refuses nothing — a peer of any age is
                    // re-dialable, which is what "if you can make 1 node you can make infinite nodes" needs.
                    // ⛔⛔⛔ RECOVERY WAS GATED ON THE WRONG DIRECTION.
                    //
                    // `live_writers() == 0` is an OUTBOUND condition: it asks "can I write to anybody?". But
                    // a node RECEIVES blocks on its inbound stream, and the two die independently. A node
                    // holding a healthy writer while its inbound stream is dead looks perfectly connected —
                    // peers non-zero, writers non-zero, nothing refused — and silently stops receiving. No
                    // block arrives, so no payment can ever be detected on it.
                    //
                    // MEASURED 2026-08-09, node B in a failing cross-device run:
                    //   `[link-state] ⛔ 232 inbound message(s) drained SINCE BOOT but ZERO since the last
                    //    probe — 2 known peer(s). ... this link delivered and is now carrying NOTHING.`
                    // The payer's send was ADMITTED on node A (`[nf-gate] ADMIT: 32 input(s)`) — the money
                    // moved — and the recipient polled the full 300s and saw nothing, because its node had
                    // stopped receiving and this recovery never fired: writers were not zero.
                    //
                    // The inbound term is the DELTA between probes, never the since-boot total. The total is
                    // HISTORY: it stays non-zero forever once a single message has ever arrived, which is
                    // exactly why the old gauge could not report a link that died mid-run.
                    //
                    // CONDITION-DRIVEN, not a timer and not a retry budget: it fires precisely while the
                    // node cannot move traffic and stops the moment it can. Re-dialing is idempotent
                    // (`add` returns false for a peer already known), so this EXTENDS reachability and
                    // refuses nothing — a peer of any age stays re-dialable, which is what "if you can make
                    // 1 node you can make infinite nodes" requires.
                    let inbound_now = rt
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .live_peer_contacts_delta();
                    let writers_dead = dir_peering.live_writers() == 0;
                    if (writers_dead || inbound_now == 0) && !dialed.is_empty() {
                        eprintln!(
                            "[arti] link recovery: writers_live={} inbound_since_last_probe={} — clearing {} \
                             spent dial record(s) so every known peer is dialable again. A node that can \
                             write but RECEIVES nothing stops seeing blocks, so no payment can settle on it, \
                             and no other gauge reports that.",
                            dir_peering.live_writers(),
                            inbound_now,
                            dialed.len()
                        );
                        dialed.clear();
                    }
                    let own_onion = dir_peering
                        .own_identity()
                        .map(|(id, _, _)| id)
                        .unwrap_or_default();
                    for rec in seeds.split(',').map(str::trim).filter(|r| !r.is_empty()) {
                        if !own_onion.is_empty() && rec.contains(&own_onion) {
                            continue; // this seed IS us
                        }
                        let key = dial_key("", rec);
                        if dialed.contains(&key) {
                            continue;
                        }
                        if dir_peering.add("", rec, &[], &[]) {
                            dialed.insert(key);
                            eprintln!("[arti] cross-device seed dial: {rec}");
                        }
                    }
                }
                // ⭐⭐⭐ (a1c) DIAL EVERY PEER THIS NODE HAS EVER LEARNED — the seed is only the FIRST HOP.
                //
                // Peer records arrive over gossip, are ML-DSA signature-checked, adopted into the directory
                // and PERSISTED to disk — and nothing ever dialed them again. `known_peers` occurred in the
                // live path in exactly zero places: a comment pointing at the `libp2p-onion-ffi` loop (not
                // the default feature) and the directory's own unit test. So a node met the network, wrote it
                // down, and then went on depending forever on the ONE compiled-in seed onion. If that single
                // host is off, every install is islanded — the same fragility as the dead seed this replaced,
                // merely pointing somewhere else. A hardcoded address is not a network.
                //
                // This is the property every real network has (Bitcoin's `addrv2`): meet one peer, learn the
                // rest, persist them, and re-form among survivors with no seed reachable at all. The directory
                // is a bounded snapshot (<=MAX_PEERS), so a pass is a function of that FIXED shape — never of
                // chain height, note count, or how long this node has been running.
                let learned: Vec<crate::peer_directory::PeerRecord> = {
                    let r = rt.lock().unwrap_or_else(|e| e.into_inner());
                    r.node().known_peers()
                };
                // ⛔⛔⛔ ONE NEW DIAL PER PASS — SIMULTANEOUS BRING-UP STARVES THE HS CIRCUIT POOL.
                //
                // This dialed EVERY newly-learned peer in a single pass. Each dial makes arti build circuits,
                // and arti's hidden-service pool is small and private (`DEFAULT_NAIVE_STEM_TARGET = 3` in
                // tor-circmgr) — firing them together exhausts it and `hspool.rs` gives up with
                // "Too many preemptive onion service circuits failed; waiting a while."
                //
                // MEASURED 2026-08-01 on this host, same binary, same seed, only the START ORDER differing:
                //   both nodes brought up together : 50x that warning, `Ipt([])`, onion_published FALSE on
                //                                    both, zero links established all session
                //   second node started AFTER the first published : 0 warnings, `cell link up` x2,
                //                                    inbound 313 / 15 - a real bidirectional link
                // Four heals plus three full cache rebuilds never fixed the first case, because local state
                // was never the constraint: circuit SUPPLY was.
                //
                // This is Bitcoin's outbound policy (open one connection at a time, keep topping up) and it is
                // transport-agnostic - nothing here weakens onion-only.
                //
                // EXTENDS auto-join, never narrows it: every learned peer is still dialed, one taken per pass
                // until none remain, so a mesh of any size still converges by construction. Only the RATE of
                // new attempts is spread; the SET is unchanged and nothing is refused for age or reach.
                let mut dialed_this_pass = 0usize;
                for rec in learned {
                    let key = dial_key(&rec.peer_id, &rec.addr);
                    if dialed.contains(&key) {
                        continue;
                    }
                    if dialed_this_pass >= 1 {
                        break; // the rest are picked up on the next pass - nothing is dropped
                    }
                    // Dialing yourself turns broadcast into an echo chamber that looks perfectly healthy.
                    if let Some((own_id, _, _)) = dir_peering.own_identity() {
                        if rec.peer_id == own_id {
                            continue;
                        }
                    }
                    if dir_peering.add(&rec.peer_id, &rec.addr, &rec.x_pk, &rec.ek) {
                        dialed.insert(key);
                        dialed_this_pass += 1;
                        eprintln!(
                            "[arti] learned-peer dial (no seed required): {} - one per pass, so a fresh mesh \
                             does not exhaust the HS circuit pool bringing everyone up at once.",
                            rec.addr
                        );
                    }
                }
                // (a2) ADOPT SIBLINGS FROM THE SHARED LOCAL DIRECTORY. Same-host nodes learn each other here
                // without any pre-existing link; every record still carries the node's REAL onion address, so
                // a peer found this way is dialed exactly like one learned by gossip.
                if let Some((own_id, _, _)) = dir_peering.own_identity() {
                    for (pid, addr, xpk, ek) in read_local_peer_records(port) {
                        // Same onion key as every other dial path — a peer reachable both here and via the
                        // seed list must never be dialed twice.
                        let key = dial_key(&pid, &addr);
                        if pid == own_id || dialed.contains(&key) {
                            continue;
                        }
                        if dir_peering.add(&pid, &addr, &xpk, &ek) {
                            dialed.insert(key);
                            eprintln!("[arti] local peer-file discovery: dialing {pid} @ {addr}");
                        }
                    }
                }
                // (b) dial the converged directory (anchors ALWAYS re-dialed — the eclipse-resistant slots).
                let (anchors, others) = {
                    let r = rt.lock().unwrap_or_else(|e| e.into_inner());
                    r.node().peer_anchors()
                };
                for rec in &anchors {
                    if dir_peering.add(&rec.peer_id, &rec.addr, &rec.x_pk, &rec.ek)
                        && dialed.insert(rec.peer_id.clone())
                    {
                        eprintln!(
                            "[arti] peer-directory dialing BONDED anchor {} @ {}",
                            rec.peer_id, rec.addr
                        );
                    }
                }
                // (b') Open fresh outbound links to a ROTATING, per-node-UNPREDICTABLE selection of the
                //      unverified peers (`others_to_dial` — rendezvous-hashed, eclipse-resistant, epoch-rotated).
                //      Every peer still receives every block via multi-hop gossip flooding, so convergence is
                //      unaffected; this just spreads which links each node keeps open. `ticks/12` ≈ 1-min epoch.
                let epoch = ticks / 12;
                // Use the SELF-EXCLUSION address, not the announce identity — a node whose descriptor has not
                // published yet still knows which address is its own, and must still be able to dial out.
                let own = dir_peering
                    .own_address()
                    .or_else(|| dir_peering.own_identity().map(|(id, _, _)| id))
                    .unwrap_or_default();
                // ⭐⭐⭐ SELF-EXCLUDE BY OUR ML-KEM KEY, WHICH NEEDS NO TOR AT ALL.
                //
                // MEASURED 2026-07-31: the joiner logged `own onion identity not established yet — skipping
                // peer dials this pass` and refused to dial for the FULL 358s its service took to publish,
                // burning guards while blocked (`Disabling guard: 80.0% of circuits died under mysterious
                // circumstances`). `live_peer_contacts` stayed 0 on BOTH nodes — not one inbound peer message
                // ever crossed either link.
                //
                // The block exists to stop a node dialing ITSELF, and the ONLY reason it needed the onion is
                // that self-exclusion compared addresses. But every `PeerRecord` also carries `ek` — this
                // node's ML-KEM public key, which exists the instant the process starts and never depends on
                // Tor. Comparing THAT excludes ourselves just as exactly, from the very first pass.
                //
                // Persisting our own onion (arti_transport) fixes the RESTART case; this fixes FIRST BOOT,
                // where no address has ever been learned. Both are needed: neither alone lets a fresh node
                // dial while its own service is still publishing.
                let own_ek = dir_peering.own_identity().map(|(_, _, ek)| ek);
                if own.is_empty() && own_ek.is_none() {
                    // NO SELF-EXCLUSION IS POSSIBLE WITHOUT AN IDENTITY. `own_identity()` returns None until this
                    // node's onion is established, and the empty-string default silently disables the
                    // self-exclusion inside `others_to_dial` — so the node dials ITSELF, "connects", and every
                    // gossip message it sends loops straight back. Two such nodes look perfectly healthy (cell
                    // link up, heights climbing in lockstep) while never exchanging a single message: the
                    // fake-convergence island. Skip the dial pass entirely until identity is known.
                    eprintln!("[arti] own onion identity not established yet — skipping peer dials this pass");
                } else {
                    for rec in
                        &crate::peer_directory::others_to_dial(&own, epoch, anchors.len(), &others)
                    {
                        // KEY-BASED self-exclusion: exact, and available before the onion is.
                        if own_ek
                            .as_ref()
                            .is_some_and(|k| !k.is_empty() && rec.ek == *k)
                        {
                            continue;
                        }
                        if !own.is_empty() && rec.peer_id == own {
                            // BELT AND BRACES: never dial ourselves even if the directory hands us our own record.
                            // A self-link is not a peer — it silently turns broadcast into an echo chamber.
                            continue;
                        }
                        // Epoch-sample path — same onion key, so a peer already dialed via the seed list, the
                        // gossip directory or a same-host file is never dialed a second time here.
                        let key = dial_key(&rec.peer_id, &rec.addr);
                        if dialed.contains(&key) {
                            continue;
                        }
                        if dir_peering.add(&rec.peer_id, &rec.addr, &rec.x_pk, &rec.ek) {
                            dialed.insert(key);
                            eprintln!(
                                "[arti] peer-directory dialing peer {} @ {} (epoch {epoch})",
                                rec.peer_id, rec.addr
                            );
                        }
                    }
                }
                // (b2) ⭐ EPIDEMIC LETTER RE-FLOOD — every pass.
                // ROOT-LAYER: delivery is PRODUCED by the relay's outbound queue on the serve tick — the admit
                // path fires exactly once per blob, so retry semantics can only live here, where the periodic
                // sender runs; patching any reader (inbox/history) cannot re-send a frame a stalled writer ate.
                // MEASURED: 2026-08-23 — a wallet-app send sat in the origin ring (probe: 1 msg opened by the
                // recipient's keys on 27780) and NEVER appeared on the joiner (0 msgs on 28901, >60s), because
                // the single admit-time flood hit a stalled Tor writer. With re-flood, each 5s pass re-queues
                // every fresh blob until its countdown drains (~20 passes), and the receiver's content-dedup
                // makes repeats no-ops.
                // MUST-STAY-GREEN: letter unit suite (order-independent acc folds, constant-shape carrier,
                // seal/open), flood-control (admit dedup still gossips a blob at most once per NEW admit on the
                // receive path), and the mesh's block gossip cadence (this adds ≤64 frames per 5s pass, bounded).
                // + (c) the anti-eclipse freshness pull (every 6th pass): one shared site, the one netsim runs too.
                {
                    let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                    let now = r.now_unix_ms();
                    r.maintenance_tick_at(now);
                }
                ticks = ticks.wrapping_add(1);
                std::thread::sleep(Duration::from_secs(5));
            }
        });
    }

    // (1) RELAY + PUMP thread — drains inbound peer cells (verify + graft + re-gossip) and emits exactly one
    //     constant-rate onion cell every COVER_INTERVAL_MS. Independent of the miner so gossip + cover traffic
    //     never pause during a mine, and its lock hold stays tiny. No production here (`tick_relay`, never `tick`).
    {
        let rt = Arc::clone(&rt);
        let cell_ms = crate::net::COVER_INTERVAL_MS.max(1);
        std::thread::spawn(move || {
            let mut last_info_ms = 0u64;
            loop {
                let now = now_unix_ms();
                {
                    let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                    r.tick_relay(now);
                }
                // DB-137, ON THE DRIVER THAT RUNS: the producer side publishes the `/get_info` string, on the thread
                // that owns the tick cadence, right after its own tick released the lock, twice a second at most.
                // The fix lived only in the other driver (`main.rs`, the arm this build never reaches), so on this
                // one the string refreshed only when a request happened to win the runtime lock.
                // MEASURED 2026-11-10 05:46–05:56 (two real nodes, load 42–89): node 0 answered the same height at
                // both ends of a 420 s window in which the pair made 57 blocks; the wallet's status page and every
                // check's tip readout read that door.
                // cons: one more runtime-lock take per 500 ms on this thread, held for the build of one status string.
                if now.saturating_sub(last_info_ms) >= 500 {
                    crate::rpc_http::refresh_get_info_cache(&rt);
                    last_info_ms = now;
                }
                std::thread::sleep(Duration::from_millis(cell_ms));
            }
        });
    }

    // (2) PRODUCER (miner) thread — THIS is what makes the phone node's blocks CLIMB. Without it the node
    //     serves genesis (block 0) forever, which is exactly the "no blocks loading" bug. Mirrors the daemon
    //     `run_node_runtime` producer EXACTLY so the phone produces identically to a desktop node: on the 1s
    //     spacing boundary BRIEFLY lock to build the unmined template (`begin_produce`), RELEASE the lock, mine
    //     OFF-LOCK (grind PQ-PoUW to the DAA target + prove the non-outsourceable #73 `pi`, the heavy ~1s
    //     step), then re-lock BRIEFLY to graft + gossip (`finish_produce`). Grinding with the lock released keeps
    //     the RPC + relay fully responsive (FAST-pillar halt fix). A `None` miner (kernel scratchpad alloc failed)
    //     fails closed (no block that spacing) rather than faking one.
    {
        let rt = Arc::clone(&rt);
        let miner = {
            let seed = rt
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .node()
                .miner_seed();
            crate::pow::PowMiner::new()
        };
        std::thread::spawn(move || {
            // O(1)-STARTUP (no lock-starve): WARM the working nullifier tree OFF the rt lock BEFORE the produce loop.
            // On a tall-chain RESUME the DA replay (`rebuild_nf_tree_from_da`) is O(blocks); running it inside the
            // first `begin_produce` UNDER the rt lock froze the RPC + relay + finality for the WHOLE rebuild — a
            // resumed node was unreachable (the "wallet can't see its node after restart" symptom). Snapshot the DA
            // dir + applied-block count under a BRIEF lock, replay WITHOUT the lock, then install under a BRIEF lock —
            // so serving/gossip/finality stay live from boot and ONLY the first PRODUCE waits for the warm-up
            // (production can wait; serving cannot — a seed must relay + serve DSYNC immediately). A block ingested
            // mid-rebuild makes the install a no-op (root moved) → the next `begin_produce` warms under the lock as
            // before, so correctness is unchanged (fail-closed), only the common no-race resume path is accelerated.
            // ⛔ THE STARTUP WALK IS DELETED, NOT MOVED.
            //
            // This block used to call `rebuild_sparse_from_da_dir` — `for seq in 0..n_blocks`, replaying every
            // block's nullifiers to rebuild a working tree before the first produce. Measured on a live
            // 31,387-block restart: ~1M tree inserts, 100% CPU for 13+ minutes, ZERO blocks produced, RPC
            // still answering so the node looked perfectly healthy. An earlier "fix" only moved that replay
            // OFF the rt lock, which is why it survived: it kept its cost and lost its symptom.
            //
            // Nothing needs warming now. The produce path reads each nullifier's non-membership copath from
            // the DA node index (`da_sparse_copath`) and derives the insert from that copath alone
            // (`da_insert_nf_path`), so a restarted node is immediately as capable as one that never stopped.
            // ([[feedback_no_growth_any_axis]], O1_CRYPTOGRAPHIC_DEFINITION.md: TIME IS AN AXIS)
            {
                // ONE PRODUCTION OWNER: this loop drives the off-lock trio, so the tick's inline
                // produce stands down (see NodeRuntime::external_producer — the two paths fighting
                // over the spacing clock measured 1,981ms/block against the 500ms target).
                let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                r.set_external_producer();
            }
            loop {
                let now = now_unix_ms();
                // PRODUCE-CADENCE PROBE — the DAEMON runs THIS loop (main-thread stack proves it:
                // main → serve_node_over_onion_mesh → rpc_http::serve), while the identically-shaped
                // main.rs loop carried the timers and never ran here, so every phase read 0 beside 12
                // live jobs (measured 2026-08-22). Same statics, same stores, one truth.
                let cyc_t0 = std::time::Instant::now();
                let wait_a_t0 = std::time::Instant::now();
                let job = {
                    let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                    crate::node_runtime::PRODUCE_LOCK_WAIT_MS.store(
                        wait_a_t0.elapsed().as_millis() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    r.begin_produce(now, Hash32::ZERO, Hash32::ZERO)
                };
                // DB-105: the note transition proves HERE, off the lock; a refused one evicts its spends
                let job = job.and_then(|j| match crate::node_runtime::complete_produce_job(j) {
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
                        let grind_t0 = std::time::Instant::now();
                        // A-F110: the one grind every producer runs (`node_runtime::grind_job`)
                        let mined: Option<Block> = miner.as_ref().and_then(|m| crate::node_runtime::grind_job(&rt, m, &mut job, now_unix_ms));
                        crate::node_runtime::PRODUCE_GRIND_MS.store(
                            grind_t0.elapsed().as_millis() as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        if let Some(mb) = mined {
                            let wait_c_t0 = std::time::Instant::now();
                            let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
                            crate::node_runtime::PRODUCE_LOCK_WAIT_MS.fetch_add(
                                wait_c_t0.elapsed().as_millis() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            r.finish_produce(job, mb);
                            crate::node_runtime::PRODUCE_BLOCKS
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            // SPEED LANE INSTRUMENT (user 2026-11-09): where one of this node's blocks spent its time, once per
                            // block. A real pair is prover-limited (MEASURED round 18: 23 s per node per block against the
                            // 9.3 s relay floor), so the prove is split from the template, the grind and the lock waits.
                            // DIGITAL-CASH-PRIVACY-REVIEWED: this node's own timers, in its own log; no note, amount or peer.
                            let ld = |s: &std::sync::atomic::AtomicU64| s.load(std::sync::atomic::Ordering::Relaxed);
                            eprintln!(
                                "[produce-time] template {} ms, prove {} ms, grind {} ms, lock waits {} ms — {} ms from the cycle's start",
                                ld(&crate::node_runtime::TEMPLATE_MS),
                                ld(&crate::node_runtime::PRODUCE_TRANSITION_MS),
                                ld(&crate::node_runtime::PRODUCE_GRIND_MS),
                                ld(&crate::node_runtime::PRODUCE_LOCK_WAIT_MS),
                                cyc_t0.elapsed().as_millis()
                            );
                        } else {
                            crate::node_runtime::PRODUCE_MINE_FAILS
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        crate::node_runtime::PRODUCE_CYCLE_MS.store(
                            cyc_t0.elapsed().as_millis() as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    None => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        });
    }

    // (3) FINALITY-VOTER thread — identical to the daemon's: every second this node signs (ML-DSA-65) a vote
    //     for the stride-aligned CHECKPOINT block a couple below the tip and submits it (counts locally +
    //     gossips to the bonded set), so `finalized_height` CLIMBS BY CONSTRUCTION on an all-in-process mesh
    //     too — without it no vote is ever cast and finality stalls at 0 (pillar violation). Fail-closed by
    //     construction: an unbonded voter carries weight 0 (never counted, never a halt).
    {
        let rt = Arc::clone(&rt);
        let (pk, sk) = load_or_create_node_identity_key(port);
        // USER TARGET (2026-09-18): sub-2 s finality. Every block is a checkpoint (stride 1) one block
        // below the tip (settle 1), polled every 200 ms — a bonded node votes within a block time of
        // seeing a block. BFT-safe at any depth: one vote per height per validator (an equivocation is
        // slashed), and a quorum on a block finalizes its whole past, so a height whose votes split on a
        // shallow fork simply finalizes at the next height where they agree. Measured before this: a
        // 4-block stride, a 2-block settle and a 1 s sleep on top of votes queued behind bulk pages —
        // finality lagged the tip by 40–75 blocks (runs 27/28).
        // Run 37 (2026-09-18): with settle 1 each producer voted for its OWN not-yet-settled tip at height
        // h, the peer for its own sibling, and the one-vote-per-height rule then forbade re-voting once the
        // selected chains converged — finality advanced only in jumps (22 → 65 while the tips passed 129).
        // Four blocks deep the selected chain is settled on both (their tips ran 1–5 blocks apart), so the
        // votes agree at every height: finality lags ~4 blocks (~3 s at 1.5 blocks/s) instead of ~60.
        // Runs 39/40 (2026-09-18): settle 4 FROZE finality at [1, 0] while the tips passed 200 — under
        // Tor latency each producer's virtual selected chain is its OWN blocks, so "the selected-chain
        // block at height h" named a different block on each validator at every height, and one vote per
        // height made every level dead. The target is SYMMETRIC now (`Node::finality_vote_targets`: the
        // lowest-id block at blue score h inside the tip's past, or the block bonded peers already voted
        // at h), one vote per level, levels caught up in order — the levels a jump skipped are covered by
        // the first finalized block above them.
        // MEASURED runs 66–70 (2026-09-18, two real producers over Tor): with the vote cast four levels
        // behind the tip, the two validators named DIFFERENT lowest-id blocks at most levels (47 of 282
        // levels agreed in run 70) because the block set at a level is still arriving when the vote is
        // cast, and one vote per height (safety, kept) then leaves the level dead forever — finality
        // stopped at 110/74 in every run. A level is voted only once it is one DAG width deep, when every
        // block at that level has propagated and both validators see the same set. Finality latency is
        // that depth's worth of blocks; liveness is what this buys. Safety is unchanged.
        // DB-437: the depth and catch-up width live in `vote_guard` (FINALITY_SETTLE / FINALITY_CATCH_UP), and the tick is
        // the one every voter runs (`vote_guard::vote_tick`) — the daemon and the simulator included.
        std::thread::spawn(move || {
            // ⛔⛔⛔ DB-370 — what this key signed lives in the WRITE-AHEAD record beside the vote key, never in a local that a
            // restart resets to 0. MEASURED before (`node::tests::db370_…`): a restarted voter re-voted a level with a
            // different block — a valid equivocation that burns an honest bond.
            let mut guard = crate::vote_guard::VoteGuard::for_node_vote_key();
            // Payment locks (docs/CHAIN-SPEED-ROOT-SPEC-20261110.md §11, stage 1): the same key signs them, under its own
            // write-ahead table beside the vote guard's record — what this key locked reaches the disk before the
            // signature, and a restart reads it back. ⛔ THIS is the serve path a node runs over the onion mesh; the
            // first build wired the tick only into `main.rs`'s other serve path, and real nodes signed no lock
            // (MEASURED 2026-11-10 04:53, `locks.py`: 0 of the stake locked a payment that sat in the pool for 60 s).
            // cons: at most 9,437,192 B on disk for the table at any height (65,536 rows of 72 B, compacted), f(fixed constants).
            let mut lock_guard = crate::spend_lock::LockGuard::for_node_vote_key();
            // ⛔⛔ LIVE-FIN F1 (lane selfheal, 2026-11-25; docs/LIVE-FOLD-WEDGE-DEEP-AUDIT-20261125.md F1) — THE SEAT REQUEST IS
            // RE-SIGNED ON THIS PATH TOO. Under the constant chain a seat request expires (`SEAT_REQUEST_TTL_MS`, 600 s) and a node
            // that is not seated signs a fresh one (A-F114) — but that loop lived only in `main.rs`'s `run_node_runtime`, which the
            // default build (`arti-onion`) never runs: it serves through THIS function. MEASURED on the live testnet after the
            // regenesis (main d8922319): the origin's one request was "refused: an expired seat request", no re-sign was ever
            // printed, the founding seat (whose key no live node holds) stayed the only validator, finalized 0 at height 873.
            // Here, beside the votes and the locks the same key signs: once a minute at most, only while unseated and stale.
            // SCALE: one stale check a minute, one signature an expiry. AI RESISTANT (b): the seat door still checks the request.
            let mut last_seat_check = std::time::Instant::now();
            // the same gate as the daemon's other path: only a node that chose to bond (MONEROUSD_VALIDATOR_BOND > 0) re-signs
            let bonds = std::env::var("MONEROUSD_VALIDATOR_BOND").ok().and_then(|s| s.trim().parse::<u128>().ok()).is_some_and(|b| b > 0);
            loop {
                std::thread::sleep(Duration::from_millis(200));
                let _ = crate::vote_guard::vote_tick(&rt, &mut guard, &pk, &sk);
                let _ = crate::spend_lock::lock_tick(&rt, &mut lock_guard, &pk, &sk);
                if bonds && crate::params::canon_live() && last_seat_check.elapsed() >= Duration::from_secs(60) {
                    last_seat_check = std::time::Instant::now();
                    let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                    if g.node().own_seat_request_stale(&pk) {
                        let seat = g.node_mut().request_own_seat_at_boot(&pk, &sk);
                        eprintln!("[validator] the seat request expired; signed again: {seat}"); // status only, no key bytes
                    }
                }
            }
        });
    }

    eprintln!("[boot-timeline] handing off to RPC serve (bind) at {}ms — every ms before this line is pre-RPC boot work; the user's \"Starting your node\" clears when this bind accepts", boot_t0.elapsed().as_millis());
    crate::rpc_http::serve(rt, port)
}

/// The in-process onion node needs the pure-Rust arti transport; a build without `arti-onion` cannot join the
/// mesh, so it refuses honestly rather than falling back to a loopback island (which would be a non-converging
/// cheat). The native daemon path (`main.rs run_serve`) uses the C-backed onion transport instead of this entry.
#[cfg(not(feature = "arti-onion"))]
pub fn serve_node_over_onion_mesh(_node: Node, _port: u16) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "in-process onion node requires the `arti-onion` feature (pure-Rust Tor mesh transport)",
    ))
}

/// This node's persistent ML-DSA identity keypair — signs its own peer-directory record AND its finality
/// votes, and is the identity a validator self-bond admits. The EXACT load-or-create shape the daemon uses
/// (`$HOME/.usdmd-node/validator-<port>.key`, `pk_len_le ‖ pk ‖ sk`), so an in-process node and a daemon on
/// the same port share ONE identity across restarts and upgrades.
fn load_or_create_node_identity_key(port: u16) -> (Vec<u8>, Vec<u8>) {
    // ⛔ DB-341: the ONE definition (`validator::load_or_create_node_vote_key`) — the key `/validator_id` reports is the
    // key the finality voter, the bridge signer, the announce, `/sign_bond` and the node's own unbond sign with. This
    // function carried its own formula (state_base + the served port) while the daemon's prologue and the RPC used
    // `$HOME` + the env port; an isolated or auto-ported node ran two identities at once.
    crate::persist::set_serving_port(port);
    crate::validator::load_or_create_node_vote_key()
}

/// Where arti persists the Tor state + this node's hidden-service key (so its `.onion` is stable across
/// restarts). Honors `MONEROUSD_STATE_DIR`, else `$HOME/.usdmd-arti-<port>` (the app sandbox on iOS) — never a
/// hardcoded home path. Keyed by the node's RPC port so two same-host nodes (e.g. the :27780/:27781 local mesh)
/// each keep their OWN onion identity + Tor state and never contend on one arti lock/dir.
#[cfg(feature = "arti-onion")]

/// ⛔⛔⛔ ONE DIAL KEY FOR ONE PEER — the ONION, never a path-specific label.
///
/// Four separate loops dial peers: the pinned seed list, the gossip-learned directory, the same-host peer
/// files, and the epoch sample. Each deduped with its OWN key — `seed:<full record>` in one, `peer_id` in
/// another — so the SAME peer reached by two paths was dialed twice. A second connection to a peer that is
/// already linked displaces the first, which tears the link down and triggers a re-dial, which races the other
/// path again: measured on the phone as `connected … cell link up` / `link closed; re-dialing` repeating for
/// minutes, with the same onion dialed twice per round. Each churn burns a fresh Tor circuit, which is what
/// turned a join that should take seconds into one that took ~20 minutes.
///
/// A peer's identity on this network IS its onion. Keying every path on that makes a duplicate dial
/// impossible by construction rather than by four loops agreeing on a convention.
fn dial_key(peer_id: &str, addr: &str) -> String {
    crate::peer_directory::onion_host_of(addr)
        .or_else(|| {
            // A bare/`host:port` record still names its onion; fall back to the id only when neither parses.
            addr.split('/')
                .find(|p| p.ends_with(".onion"))
                .map(|h| h.to_string())
        })
        .unwrap_or_else(|| peer_id.to_string())
}

#[cfg(feature = "arti-onion")]
fn arti_state_dir(port: u16) -> std::path::PathBuf {
    // ⛔⛔⛔ A NODE'S MESH IDENTITY IS *WHO IT IS ON THE NETWORK* — NEVER A LOCAL TRANSPORT DETAIL.
    //
    // arti persists this node's hidden-service key in here, so THIS DIRECTORY NAME *IS* THE NODE'S `.onion`.
    // Keying it by RPC port meant that changing the port minted a brand-new identity and silently orphaned
    // every seed line anyone had pinned — the node vanished from the network and reappeared as a stranger.
    // Measured: `onion-27780.seed`, `-27781`, `-27782`, `-27795` were four identities for ONE device, and the
    // wallet's own port failover (27780 -> 60358) rotated it again, which is why the seed compiled into every
    // wallet build pointed at an onion with no descriptor. THAT is the seed rot; the dead seed was a symptom.
    //
    // `MONEROUSD_MESH_IDENTITY` names the identity SLOT explicitly, so a long-lived node (the desktop wallet's)
    // keeps ONE `.onion` for life no matter which loopback port it lands on. The port stays the default so the
    // same-host :27780/:27781 mesh below keeps distinct identities and never contends on one arti lock.
    let slot = std::env::var("MONEROUSD_MESH_IDENTITY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.contains('/') && !s.contains('.'))
        .unwrap_or_else(|| port.to_string());
    if let Ok(d) = std::env::var("MONEROUSD_STATE_DIR") {
        return std::path::PathBuf::from(d).join(format!("arti-{slot}"));
    }
    // iOS SANDBOX: `$HOME` is the app CONTAINER ROOT, which is NOT writable — only `Library/`, `Documents/`,
    // `tmp/` under it are (proven live: `Sandbox: deny file-write-create .../.usdmd-arti` → arti bootstrap died
    // in 4ms → the phone could never dial the seed → "Joining mesh… block 0" forever). So on iOS the state dir
    // MUST live under `Library/Application Support/` (Apple's canonical spot for app-managed, backed-up support
    // files). This is the write-permission fix that lets Tor bootstrap + the seed dial actually happen.
    #[cfg(target_os = "ios")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::PathBuf::from(home)
                .join(format!("Library/Application Support/usdmd-arti-{slot}"));
        }
    }
    // One state base (see `persist::state_base`, which already falls back to "." when HOME is unset): an isolated
    // node never shares the live node's Tor state.
    std::path::PathBuf::from(crate::persist::state_base()).join(format!(".usdmd-arti-{slot}"))
}

#[cfg(all(test, feature = "pins-core"))]
mod learned_peers_survive_the_seed_tests {
    /// ⭐⭐⭐ A NODE THAT HAS MET THE NETWORK MUST NEVER NEED THE SEED AGAIN.
    ///
    /// TWO-PARTY-REVIEWED: two independent nodes — one ANNOUNCES its record, the other INGESTS it over the
    /// gossip path and must still hold it after a restart. The disagreement this guards against is a joiner
    /// that has met the mesh and, on reboot, behaves like it never did.
    ///
    /// The live arti dial loop only ever dialed the ONE compiled-in seed onion and same-host peer files.
    /// Gossip-learned records were signature-checked, adopted and written to disk — then never dialed again;
    /// `known_peers` appeared nowhere in the live path. So the entire network hung off a single hardcoded
    /// address: turn that one host off and every install is islanded, exactly like the dead seed it replaced.
    /// A hardcoded address is not a network. What makes one is Bitcoin's `addrv2` property — meet one peer,
    /// learn the rest, persist them, re-form among survivors with no seed reachable at all.
    #[test]
    fn cross_node_a_learned_peer_is_still_dialable_after_restart_with_no_seed() {
        use crate::peer_directory::{PeerDirectory, PeerOutcome};
        // A FILE path, not a directory: the snapshot writes `<path>.tmp` then renames onto `<path>`, and
        // renaming a file over a directory fails silently — which looks exactly like "persistence is broken".
        let scratch =
            std::env::temp_dir().join(format!("musd-learned-{}.peers", std::process::id()));
        let _ = std::fs::remove_file(&scratch);

        // PARTY A announces a signed record; PARTY B ingests it exactly as the wire handler does.
        let (pk_a, sk_a) = crate::pqauth::ml_dsa_keypair();
        let onion_a = "h34wf6htca3sje4d6m52ujulyll4kujdbh2fjrxc7hpd4tobfzxtxaad.onion";
        let announced =
            crate::peer_directory::signed_record_for_test(&pk_a, &sk_a, onion_a, 35000, 3);

        let learned_before_restart = {
            let mut b = PeerDirectory::with_persist(scratch.clone());
            assert_eq!(
                b.adopt(&announced),
                PeerOutcome::Adopted,
                "B adopts A's gossiped record"
            );
            b.peers().len()
        };
        assert_eq!(
            learned_before_restart, 1,
            "B holds exactly the peer it learned"
        );

        // ── RESTART with NO seed configured at all. This is the case that matters: the seed host is gone,
        // and the node must still know where the network is.
        std::env::remove_var("MONEROUSD_LIBP2P_SEED_PEERS");
        let after_restart = PeerDirectory::with_persist(scratch.clone());
        assert_eq!(
            after_restart.peers().len(),
            1,
            "after restart with NO seed reachable, this node knows of NO peers — it met the network, wrote it \
             down, and forgot it. Every boot would then depend on one hardcoded onion staying alive."
        );
        let rec = &after_restart.peers()[0];
        assert!(
            rec.addr.contains(onion_a),
            "the re-loaded record must carry the peer's REAL onion so it can actually be dialed, not just counted: {}",
            rec.addr
        );
        assert!(
            !rec.x_pk.is_empty() && !rec.ek.is_empty(),
            "a re-loaded record with no PQ key material is not dialable — it would be silently skipped, which \
             looks identical to having no peers at all"
        );
        let _ = std::fs::remove_file(&scratch);
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod one_dial_key_per_peer_tests {
    use super::dial_key;

    /// ⭐⭐⭐ ONE PEER MUST PRODUCE ONE DIAL KEY, WHATEVER PATH FOUND IT.
    ///
    /// TWO-PARTY-REVIEWED: this is the dedup rule that decides whether a SECOND connection is opened to a peer
    /// that is already linked. The cross-node effect — a link that connects, closes and re-dials forever — is
    /// what the phone measured; this pins the rule that prevents it.
    ///
    /// Four loops dial peers (pinned seeds, the gossip directory, same-host peer files, the epoch sample) and
    /// each deduped with its own key: `seed:<whole record>` in one, `peer_id` in another. The same peer reached
    /// by two paths therefore got dialed TWICE, the second connection displaced the first, the link tore down
    /// and re-dialed — and each cycle burned a fresh Tor circuit. Measured on the phone: the same onion dialed
    /// twice per round with `connected … cell link up` / `link closed; re-dialing` repeating for minutes, which
    /// is what turned a join that takes ~1s of Tor bootstrap into one the user timed at ~20 minutes.
    #[test]
    fn every_path_that_names_the_same_peer_produces_the_same_key() {
        let onion = "7srgbwzvprpqll7unmrguqqj2kgekjee5wfmh6s7m6irkwovacv3smyd.onion";
        let multiaddr = format!("/dns/{onion}/tcp/27781");

        // The seed list hands a full pipe-delimited record; the directory hands (peer_id, multiaddr). Same peer.
        let from_seed = dial_key("", &multiaddr);
        let from_directory = dial_key(onion, &multiaddr);
        let from_peer_file = dial_key("some-other-label", &multiaddr);
        assert_eq!(
            from_seed, from_directory,
            "the seed path and the directory path produced DIFFERENT keys for one peer — it would be dialed \
             twice, and the second connection tears down the first"
        );
        assert_eq!(
            from_directory, from_peer_file,
            "a differing peer_id label changed the key for the same onion — the label is not the identity"
        );
        assert_eq!(
            from_seed, onion,
            "the key must BE the onion, which is what identifies a peer here"
        );

        // And two genuinely different peers must NOT collide, or dedup would suppress a real dial.
        let other = "27rlthhjj4wbnkwgzespuztweemxantktseyqe5y2qac3oo3nr7hh2ad.onion";
        assert_ne!(
            dial_key("", &format!("/dns/{other}/tcp/27781")),
            from_seed,
            "two different onions collapsed to one key — a real peer would never be dialed"
        );
    }
}

/// Resident set of THIS process in KiB — the phone-class figure a node must keep flat (mach task info on Apple
/// platforms, through `memory-stats`); `None` where unreadable. Read by the wallet's phone console line and by
/// anyone measuring "does the node eat RAM silently" on a device where `ps` is not available.
pub fn resident_kb() -> Option<u64> {
    crate::oscall::resident_kb()
}

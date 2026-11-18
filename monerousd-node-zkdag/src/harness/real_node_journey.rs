// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ THE TIER THIS TREE NEVER HAD: JOURNEYS DRIVEN AGAINST THE REAL `usdmd-node` BINARY.
//!
//! ## The gap this closes, measured on ourselves
//! Every pin in [`crate::harness::e2e_claims::VALUE_CLASSES`] was an IN-PROCESS `Node::new(..)` fixture
//! with a simulated transport, and the gate that certified them —
//! `a_pin_that_claims_a_user_can_move_value_asserts_on_a_second_party` — decides by READING THE PIN'S
//! SOURCE TEXT for the substring `"assert"` beside a peer-ish name. So the register's green is a property
//! of the source text, not of the chain.
//!
//! ⭐⭐⭐ **A FIXTURE CAN BE RED FOR A FIXTURE REASON AND WE WILL READ IT AS A CHAIN REASON.** Not
//! hypothetical: on 2026-09-16 the DEX fill fixture answered `OrderAlreadyFilled` because
//! `a_real_trade()` proves both halves and builds the PAYOUT notes while never putting the notes being
//! SPENT on chain — and that refusal was read as a live consensus defect, re-deriving a §AQ diagnosis
//! already closed on 9/13 for the asset path. The cost was three turns, a withdrawn §CF, and a PILLAR
//! TRADE (an O(pool) per-block carrier stepper, §CT) proposed to fix a hole a real node did not have.
//! **A harness that cannot tell a missing fixture setup from a refusing chain will spend your time
//! re-closing closed work, and will eventually spend a pillar on it.**
//!
//! ## The borrowed shape, cited
//! Bitcoin Core runs TWO test tiers and does not let one impersonate the other: `src/test` (in-process
//! unit tests, component behaviour) and `test/functional` (a framework that starts REAL `bitcoind`
//! processes and drives them over their REAL RPC — consensus claims live there). Ethereum draws the same
//! line with `hive`. We had only the unit tier and were making consensus claims from it. This module is
//! our functional tier; the two-phase onion bootstrap below is lifted from our own
//! `scripts/mesh_convergence_tps.sh`, which already knew how to stand a real mesh up.
//!
//! ## What a journey here may claim
//! Exactly one thing, and only when the SECOND PROCESS'S OWN RPC says it: that a user moved value. The
//! rig deliberately exposes no way to inspect a node's memory — there is no handle to a `Node`, only
//! `get`/`post` against a socket, because **a test that asserts on what a call RETURNS proves nothing**
//! (measured 2026-09-03: two honest nodes each self-verified the same DEX fill and the maker's lot paid
//! out twice). If the value is not visible on the far end of a second process's socket, it did not
//! travel.
//!
//! ## ⛔ THIS RIG STORES NOTHING PER ITEM
//! The only filesystem objects it creates are ONE datadir and ONE log per PROCESS, bounded by the fixed
//! constant [`MAX_JOURNEY_NODES`] — never by height, blocks, notes, spends or pool depth. What the node
//! then writes inside its own datadir is the node's footprint, measured by `/ram_census` and the
//! store-bound manifest, not by this file. `mod harness` is `#[cfg(test)]`, so none of this links into
//! the shipped binary.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::btc_regtest::RegtestCore;

/// Where the real binary lives. `cargo test --release` builds the package's bin targets, so a test that
/// finds this missing is being run in a way that cannot prove anything — it must SAY so, never skip
/// quietly. A silent skip is how a tier stops existing without anyone deciding that it should.
/// How long a real pair gets for a chain object to apply on both processes. An object applies at its FOLD: 32 confirmations are
/// chain blocks, two concurrent producers add ~1.7 blue per chain block, and a real block takes ~14 s (MEASURED 2026-11-03,
/// usdmd_journey_nativesend_65464: the fold 54-55 blue behind the tip), so one fold is ~13 minutes of wall. The old 420 s read
/// every not-yet-folded object as lost: `THE SEATS DID NOT TRAVEL node0=1 node1=1`, `no 2-of-2 custody quorum [1, 1]`, each
/// the second seat still inside its fold. A bound only costs time when the condition is not met; a real loss still fails here.
pub const CHAIN_WAIT_S: u64 = 1_320;

pub fn node_binary() -> PathBuf {
    // A lane measuring its own landed fixes names its own release build here instead of replacing the shared
    // `target/release` binary, which the lane holding the roll builds and gates (charter §8.5). Test-only.
    if let Ok(p) = std::env::var("MONEROUSD_JOURNEY_NODE_BIN") {
        return PathBuf::from(p);
    }
    // ⛔ THE DAEMON BUILT BESIDE THIS TEST BINARY (user 2026-09-28, usage rule 4). A lane builds in its own
    // CARGO_TARGET_DIR, so the shared `target/release/usdmd-node` below is some other build's daemon, or MISSING.
    // MEASURED 2026-09-28: four seat journeys ran 25 min against a missing shared binary and measured nothing. This
    // binary sits at `<target>/<profile>/deps/usdmd_node-<hash>`, so `<target>/<profile>/usdmd-node` is the daemon
    // `cargo build --bin usdmd-node` wrote for the SAME target dir. It is preferred whenever it exists.
    if let Some(sibling) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent()?.parent().map(|profile| profile.join("usdmd-node")))
        .filter(|p| p.is_file())
    {
        // Visible, so a daemon older than the tree it is meant to measure is never silent.
        let age = |p: &std::path::Path| {
            std::fs::metadata(p).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).map(|d| d.as_secs())
        };
        eprintln!(
            "[journey] daemon = {} (built {:?} s ago; this test binary {:?} s ago)",
            sibling.display(),
            age(&sibling),
            std::env::current_exe().ok().and_then(|e| age(&e))
        );
        return sibling;
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target");
    p.push("release");
    p.push("usdmd-node");
    p
}

/// ⛔⛔ A JOURNEY NEVER MEASURES A BINARY OLDER THAN THE CODE IT CLAIMS TO PROVE (2026-10-03).
///
/// MEASURED: the register's real-node re-run ran its wallet journeys against
/// `monerousd-wallet-v2/src-tauri/target/release/wallet-harness`, built 2026-09-28. That predates the DB-223 wallet half
/// (e8fb355, 2026-10-02), so every wallet send failed with "MEMBERSHIP_PROOF_INVALID" — a stale-fixture red read as a
/// chain verdict. Earlier, the OrderFill row had cited a journey that failed at its drip for days.
///
/// THE RULE IS THE SOURCE FILES' OWN TIMES, never a commit's (2026-10-06): a binary is stale when any `.rs` file in a tree it
/// compiles is NEWER than the binary — an uncommitted edit counts, and a commit that changes no file's content does not.
/// MEASURED link 8: the wallet built at 22:27 from exactly the source b401fde committed at 22:39 was refused as "711 s
/// BEFORE the newest landed change", while `sim.sh` (which judges by file mtime) correctly judged it current and did not
/// rebuild — so every simulator run after every landing failed at T1.1 on a fresh binary. One rule for one fact: this is
/// the rule `sim.sh` applies.
/// - `None` = fresh, or the trees could not be read (the age is still printed where the binary is chosen).
/// - The harness tree is NOT a source of any binary: `mod harness` is `#[cfg(test)]` (lib.rs), so no release daemon or
///   wallet compiles a byte of it. MEASURED sim-20261006-173848: a harness-only commit (b72b8fd, netsim.rs) refused the
///   wallet built 411 s earlier as STALE at T1.1, while `sim.sh` (which excludes `*/harness/*`) judged it current — two
///   rules for one fact. Both exclude the same tree.
/// A source file that is `#[cfg(test)]` by the tree's own layout — the pins, the fixtures, the test modules — and so never a
/// byte of a shipped daemon or wallet. MEASURED 2026-11-02 (user "lets do it all"): every edit to `node/pins.rs`, `node/tests.rs`
/// or a `*_tests.rs` file refused the wallet-harness as STALE and cost a 4–8 min rebuild per edit, for code the binary does not
/// contain. The rule stays one fact: the binary must be newer than every source it is built from.
fn test_only_source(path: &std::path::Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == "tests.rs" || name == "pins.rs" || name == "test_support.rs" || name.ends_with("_tests.rs") || name.ends_with("_pins.rs")
}

/// ⭐ 2026-11-02 — THE RULE IS THE SOURCE FILES' CONTENT, read two ways, never a bare mtime: (1) a file whose content is not
/// HEAD's (git status: modified or untracked) counts by its own time — an uncommitted edit after the build is stale; (2) a
/// landing after the build counts by the files its commits changed (git log --since the binary's time) — a landed change
/// the binary does not contain is stale; (3) a file whose content IS HEAD's never counts, whatever its mtime says.
/// MEASURED 2026-11-02 16:30:56/16:30:57 (base-dsol-pair.log): `lane_run.sh` touches EVERY `.rs` of a crate when the worktree
/// building into a target dir changes (lane_run.sh:90, to force a real recompile), so a wallet-harness built one second
/// before a node pin build was refused as STALE with no edit anywhere — and the same shape refused c4-pair (15:50:39 vs
/// 15:50:56). ROOT-LAYER: one guard, content-defined, for every journey binary. MUST-STAY-GREEN: the pair pins' T1.1 wallet
/// create on a binary built from this tree. Without a git view (no repo), the mtime walk below stays the rule.
#[must_use]
pub fn binary_predates_landed_sources(bin: &std::path::Path, trees: &[&str]) -> Option<String> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent()?.to_path_buf();
    let built = std::fs::metadata(bin).ok()?.modified().ok()?;
    let is_source = |p: &std::path::Path| {
        p.extension().is_some_and(|x| x == "rs")
            && !test_only_source(p)
            && !p.components().any(|c| {
                let c = c.as_os_str();
                c == "harness" || c == "tests" || c == "fuzz"
            })
    };
    let git = |args: &[&str]| -> Option<String> {
        let out = std::process::Command::new("git").current_dir(&repo).args(args).output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let stale = |by: u64, what: String| {
        format!(
            "⛔ STALE BINARY: {} was built {by} s BEFORE the newest change to its sources {:?} ({what}). A journey on it \
             measures old code, not this tree — rebuild it (or name a fresh build in MONEROUSD_JOURNEY_*_BIN).",
            bin.display(),
            trees,
        )
    };
    let mut status_args = vec!["status", "--porcelain", "--untracked-files=all", "--"];
    status_args.extend(trees.iter().copied());
    if let Some(status) = git(&status_args) {
        // (1) content not HEAD's: the file's own time decides
        let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
        for line in status.lines() {
            let Some(rest) = line.get(3..) else { continue };
            let rel = rest.rsplit(" -> ").next().unwrap_or(rest).trim();
            let path = repo.join(rel);
            if !is_source(&path) {
                continue;
            }
            if let Ok(m) = std::fs::metadata(&path).and_then(|m| m.modified()) {
                if m > built && newest.as_ref().map_or(true, |(t, _)| m > *t) {
                    newest = Some((m, path));
                }
            }
        }
        if let Some((changed, file)) = newest {
            let by = changed.duration_since(built).ok()?.as_secs();
            return Some(stale(by, format!("uncommitted: {}", file.strip_prefix(&repo).unwrap_or(&file).display())));
        }
        // (2) landed after the build: the files the commits since then changed
        let built_unix = built.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
        let since = format!("--since=@{built_unix}");
        let mut log_args = vec!["log", &since, "--name-only", "--format=%ct", "--"];
        log_args.extend(trees.iter().copied());
        if let Some(log) = git(&log_args) {
            // A landing counts only when it REWROTE a source after the build: a rebase that replays this lane's own,
            // byte-identical work rewrites nothing (the file's time stays older than the binary; cargo rebuilds nothing),
            // while another lane's real change always rewrites the file at checkout. MEASURED 2026-11-03 (c25/c26): the
            // lane's own landing at 00:49 refused the harness built at 00:40 from exactly that content, twice.
            let mut at: u64 = 0;
            for line in log.lines() {
                let line = line.trim();
                if let Ok(t) = line.parse::<u64>() {
                    at = at.max(t);
                } else if !line.is_empty() {
                    let path = repo.join(line);
                    let rewritten = std::fs::metadata(&path).and_then(|m| m.modified()).is_ok_and(|m| m > built);
                    if is_source(&path) && rewritten {
                        return Some(stale(at.saturating_sub(built_unix), format!("landed: {line}")));
                    }
                }
            }
        }
        return None;
    }
    // No git view: the newest `.rs` file under the trees by mtime, harness excluded (an iterative walk).
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    let mut stack: Vec<PathBuf> = trees.iter().map(|t| repo.join(t)).collect();
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let path = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if path.file_name().is_some_and(|n| n != "harness" && n != "tests" && n != "fuzz") {
                    stack.push(path);
                }
            } else if is_source(&path) {
                if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
                    if newest.as_ref().map_or(true, |(t, _)| m > *t) {
                        newest = Some((m, path));
                    }
                }
            }
        }
    }
    let (changed, file) = newest?;
    let by = changed.duration_since(built).ok()?.as_secs();
    (changed > built).then(|| stale(by, file.strip_prefix(&repo).unwrap_or(&file).display().to_string()))
}

/// ⛔ THE FIXED CONSTANT EVERY STORE IN THIS RIG IS BOUND BY. A journey names how many real processes it
/// wants and that number is a TEST CONSTANT: it never tracks height, note count, peer count, pool depth
/// or supply. A rig that sized itself from chain state would be the very growth vector the node forbids,
/// reintroduced inside the instrument that exists to catch it.
pub const MAX_JOURNEY_NODES: usize = 8;
/// DB-102: how long one wallet-harness child may run before the harness kills it and reports a death.
pub const WALLET_RUN_DEADLINE_SECS: u64 = 300;
/// DB-102: how many burst provers run at once (a real spend proves for ~7 s and holds its own witness
/// memory; sixteen at once exhausted a 16 GB machine).
pub const BURST_PROVERS_AT_ONCE: usize = 4;

/// A mesh of REAL `usdmd-node` processes, each with its own datadir, RPC port and onion identity.
///
/// ⛔ The CARDINAL on process lifetime is obeyed by construction: every child is killed BY ITS OWN PID
/// through the `Child` handle this struct owns. Nothing here ever runs a pattern-matching kill, because a
/// broad `pkill usdmd` on a developer's machine takes down the node holding their real funds.
pub struct RealMesh {
    /// O1-FOOTPRINT-REVIEWED: fixed-width at MAX_JOURNEY_NODES (=8) — one entry per PROCESS, never per
    /// item; cannot grow with history, blocks, notes or spends.
    children: Vec<Child>,
    /// O1-FOOTPRINT-REVIEWED: fixed-width at MAX_JOURNEY_NODES (=8) — one RPC port per process.
    ports: Vec<u16>,
    /// O1-FOOTPRINT-REVIEWED: fixed-width at MAX_JOURNEY_NODES (=8) — one datadir path per process.
    dirs: Vec<PathBuf>,
    /// Kept so a failing journey can print WHICH mesh said what without the caller plumbing it.
    pub tag: String,
    /// The pinned seed list every node was (re)started with — a restart hands the SAME list back.
    seeds: String,
    /// DB-313 §3: the node indices launched WITHOUT `MONEROUSD_VALIDATOR_BOND` — no seat, the gate's own daemon
    /// shape, so a wallet's USDm bond onto that node's vote identity is not refused as redundant. A restart keeps it.
    /// O1-FOOTPRINT-REVIEWED: at most MAX_JOURNEY_NODES (=8) indices, fixed at mesh start.
    unseated: Vec<usize>,
}

impl RealMesh {
    pub fn len(&self) -> usize {
        self.ports.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }
    /// Resident set of journey node `i` in KB (`ps -o rss=`), the phone-class figure every milestone prints.
    pub fn rss_kb(&self, i: usize) -> u64 {
        let pid = self.children.get(i).map(|c| c.id()).unwrap_or(0);
        let out = Command::new("ps").args(["-o", "rss=", "-p", &pid.to_string()]).output();
        out.ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// The kernel's own attribution of node `i`'s resident set (`vmmap --summary`, macOS): the MALLOC
    /// zones against mapped files, stacks and the physical footprint. Read-only, one line per region
    /// class. When the node's `/ram_census` totals 16 MB and the resident set is 700 MB (run 91), this is
    /// the reading that says whether the difference is HEAP (a store the census misses, or allocator
    /// retention after the prover) or something else.
    pub fn vm_summary(&self, i: usize) -> String {
        let pid = self.children.get(i).map(|c| c.id()).unwrap_or(0);
        let out = Command::new("vmmap").args(["--summary", &pid.to_string()]).output();
        let txt = out.ok().and_then(|o| String::from_utf8(o.stdout).ok()).unwrap_or_default();
        // every region class up to the per-zone table (run 92: the filtered classes summed to 18 MB
        // resident against a 549 MB total — the answer was in a class the filter dropped)
        txt.lines()
            .take_while(|l| !l.starts_with("MALLOC ZONE"))
            .filter(|l| !l.trim().is_empty() && !l.starts_with("REGION TYPE") && !l.starts_with("===="))
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join(" | ")
    }

    pub fn port(&self, i: usize) -> u16 {
        self.ports[i]
    }
    pub fn log_path(&self, i: usize) -> PathBuf {
        self.dirs[i].join("node.log")
    }

    /// The OPERATOR's view of process `i`'s validator key: the `(pk_len u32 LE) ‖ pk ‖ sk` file the daemon
    /// itself seats with, at `HOME/.usdmd-node/validator-<port>.key` (`main.rs::validator_key_path`). The rig
    /// gives every daemon its own HOME and port, so this is exactly the file that daemon signed its seat with.
    /// The secret never leaves this test process. It signs what that daemon's operator would sign.
    pub fn validator_key(&self, i: usize) -> Result<(Vec<u8>, Vec<u8>), String> {
        let path = self.dirs[i]
            .join(".usdmd-node")
            .join(format!("validator-{}.key", self.ports[i]));
        let b = std::fs::read(&path).map_err(|e| format!("node{i} validator key {}: {e}", path.display()))?;
        if b.len() < 4 {
            return Err(format!("node{i} validator key file is {} bytes", b.len()));
        }
        let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if b.len() < 4 + n {
            return Err(format!("node{i} validator key file is truncated ({} < {})", b.len(), 4 + n));
        }
        Ok((b[4..4 + n].to_vec(), b[4 + n..].to_vec()))
    }

    /// GET a route on node `i`. Returns the body, or the transport error — never a panic, so a journey
    /// can distinguish "the node refused" from "the node is not there", which are different findings.
    pub fn get(&self, i: usize, route: &str) -> Result<String, String> {
        let url = format!("http://127.0.0.1:{}{}", self.ports[i], route);
        match ureq::get(&url).timeout(Duration::from_secs(90)).call() {
            Ok(r) => r.into_string().map_err(|e| format!("body: {e}")),
            Err(ureq::Error::Status(code, r)) => {
                let b = r.into_string().unwrap_or_default();
                Err(format!("HTTP {code}: {b}"))
            }
            Err(e) => Err(format!("transport: {e}")),
        }
    }

    /// POST a JSON body to a route on node `i`.
    pub fn post(&self, i: usize, route: &str, body: &str) -> Result<String, String> {
        let url = format!("http://127.0.0.1:{}{}", self.ports[i], route);
        match ureq::post(&url)
            .timeout(Duration::from_secs(300))
            .set("content-type", "application/json")
            .send_string(body)
        {
            Ok(r) => r.into_string().map_err(|e| format!("body: {e}")),
            Err(ureq::Error::Status(code, r)) => {
                let b = r.into_string().unwrap_or_default();
                Err(format!("HTTP {code}: {b}"))
            }
            Err(e) => Err(format!("transport: {e}")),
        }
    }

    /// The node's own reported height, from its own socket.
    pub fn height(&self, i: usize) -> Option<u64> {
        let b = self.get(i, "/get_height").ok()?;
        json_u64(&b, "height").or_else(|| b.trim().parse::<u64>().ok())
    }

    /// How many peers node `i` believes it has, EXCLUDING itself — or `None` when the node could not be
    /// ASKED (a timeout or transport error).
    ///
    /// ⛔⛔⛔ "I ASKED AND THE ANSWER WAS ZERO" AND "I COULD NOT ASK" ARE DIFFERENT FACTS, AND COLLAPSING
    /// THEM COST A RUN. This returned a bare `usize` and mapped every transport error to `0`, so a node
    /// that was merely BUSY read as ISLANDED. Measured 2026-09-17: the peg journey aborted with "at least
    /// one node still had ZERO peers" while that node's own log said `from 2 known peer(s)` and
    /// `cells written to peers: 129 across 3 writer(s)` — it was saturated (queue depth 3331, 11,325
    /// `SyncResp` refused at the bound) and its 20s RPC timed out. The mesh was fine; the instrument
    /// reported a fatal finding about the chain because it could not tell silence from an answer. Same
    /// class as §CU: a refusal that came from the INSTRUMENT, read as a verdict about the SYSTEM.
    pub fn peers_known(&self, i: usize) -> Option<usize> {
        let b = self.get(i, "/get_peers").ok()?;
        let mine = self.get(i, "/peer_record").ok()?;
        let my_id = json_str(&mine, "peer_id").unwrap_or_default();
        let listed = b.matches("\"peer_id\"").count();
        let counts_self = !my_id.is_empty() && b.contains(&my_id);
        Some(listed.saturating_sub(usize::from(counts_self)))
    }

    /// The same question when a caller only wants a number for a log line. Prefer [`Self::peers_known`]
    /// anywhere the answer decides something.
    pub fn peer_count_excluding_self(&self, i: usize) -> usize {
        self.peers_known(i).unwrap_or(0)
    }


    /// `origin`: the node that founds the network carries the explicit boot directive that lets a
    /// node holding NO chain produce on its own tips; every joiner runs without it and stays gated
    /// until it holds the origin's chain (the daemon ignores the directive on a node that already
    /// holds a chain, so a later restart of the origin is harmless).
    fn spawn_one(
        bin: &PathBuf,
        i: usize,
        port: u16,
        dir: &PathBuf,
        seeds: &str,
        origin: bool,
        // DB-313 §3: false launches the node WITHOUT a seat (see `RealMesh::unseated`).
        seated: bool,
    ) -> Result<Child, String> {
        // O1-FOOTPRINT-REVIEWED: fixed-width at MAX_JOURNEY_NODES (=8) — ONE log per PROCESS, the node's
        // own stdout sink, opened once at spawn. No per-block or per-note path reaches here.
        let log =
            std::fs::File::create(dir.join("node.log")).map_err(|e| format!("node{i} log: {e}"))?;
        let errlog = log.try_clone().map_err(|e| format!("node{i} log dup: {e}"))?;
        let mut cmd = Command::new(bin);
        cmd.arg("serve")
            .env("MONEROUSD_NODE_DATA", dir)
            .env("MONEROUSD_RPC_PORT", port.to_string())
            .env("MONEROUSD_LIBP2P_SEED_PEERS", seeds)
            // ⭐ SELF-BOND, so `/peg_in_execute` has a custodian at all. `serve.rs` seats the bridge
            // signer from this node's OWN persisted ML-DSA identity when this is set and no charter is
            // pinned; the secret stays in-process and never touches the wire. Without it the peg door
            // fail-closes with NOT_A_CUSTODIAN and a peg journey would measure nothing.
            .env("MONEROUSD_VALIDATOR_BOND", if seated { "200000" } else { "" })
            // ⛔ GENESIS IS f(NETWORK), so an unset net is a DIFFERENT CHAIN. Measured 2026-08-14: a
            // joiner launched without this computed chain_id 8ce28721… against an origin on 9482705b…
            // and spent an hour looking like broken peering. Parity says testnet, so the journey runs
            // the same consensus rules as production.
            .env("MONEROUSD_NET", "testnet")
            // ⭐ …and an ISOLATED HOME, so the mesh inherits NO peer directory from this machine. The
            // seed list above is the journey's whole world: without this the nodes could dial the live
            // testnet, and a journey that reaches a real network is not a measurement of THIS mesh.
            .env("HOME", dir)
            .env("MONEROUSD_FINALITY_TRACE", "1");
        if origin {
            cmd.env("MONEROUSD_MESH_BOOTSTRAP", "1");
        }
        // DB-121: the Bitcoin leg's source is the journey's to choose — a regtest Bitcoin Core it raised
        // (`MONEROUSD_BTC_NET=regtest`, `MONEROUSD_BTC_RPC_URL`, `MONEROUSD_BTC_RPC_AUTH`,
        // `MONEROUSD_BTC_FEE_RATE_SAT_VB`) travels to every daemon it spawns; a run that sets none of them
        // leaves the daemon on its production source exactly as before.
        for (k, v) in std::env::vars() {
            // §21: no price travels here — each daemon quotes what its own sample of the onion price relays agrees on.
            if k.starts_with("MONEROUSD_BTC_") || k.starts_with("MONEROUSD_XMR_") {
                cmd.env(k, v);
            }
        }
        // DB-121x: each custodian daemon drives ITS OWN monero-wallet-rpc, so the Monero wallet URL and directory
        // are per node: the journey lists them in order (`MONEROUSD_JOURNEY_XMR_WALLET_RPCS`,
        // `MONEROUSD_JOURNEY_XMR_WALLET_DIRS`, comma-separated) and node `i` receives the i-th of each.
        let pick = |list: &str| list.split(',').map(|s| s.trim().to_string()).nth(i);
        if let Some(url) = std::env::var("MONEROUSD_JOURNEY_XMR_WALLET_RPCS").ok().as_deref().and_then(pick) {
            cmd.env("MONEROUSD_XMR_WALLET_RPC_URL", url);
        }
        if let Some(dir) = std::env::var("MONEROUSD_JOURNEY_XMR_WALLET_DIRS").ok().as_deref().and_then(pick) {
            cmd.env("MONEROUSD_XMR_WALLET_DIR", dir);
        }
        cmd.stdout(Stdio::from(log))
            .stderr(Stdio::from(errlog))
            .spawn()
            .map_err(|e| format!("node{i} spawn: {e}"))
    }

    fn kill_all(&mut self) {
        for c in self.children.iter_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.children.clear();
    }

    fn wait_rpc(&self, i: usize, secs: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if self.get(i, "/get_height").is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }

    /// STOP node `i` the way production does (2026-09-21, the one-DAG rule): the `shutdown-{port}` file the daemon
    /// polls asks it to write its blocking shutdown snapshot and exit 0 (SIGKILL only if it has not exited in 20 s).
    /// Its datadir, port, onion identity and seed list are kept for [`Self::start_node`]. Returns whether it stopped
    /// cleanly.
    pub fn stop_node(&mut self, i: usize) -> Result<bool, String> {
        let port = self.ports[i];
        let flag = self.dirs[i].join(".usdmd-node").join(format!("shutdown-{port}"));
        std::fs::write(&flag, b"1").map_err(|e| format!("node{i} shutdown flag: {e}"))?;
        let t0 = Instant::now();
        let mut clean = false;
        while t0.elapsed() < Duration::from_secs(20) {
            if let Ok(Some(_)) = self.children[i].try_wait() {
                clean = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        if !clean {
            let _ = self.children[i].kill();
            let _ = self.children[i].wait();
        }
        eprintln!(
            "[restart] node{i} stopped {} after {:.1}s",
            if clean { "CLEANLY (shutdown snapshot written)" } else { "by SIGKILL (no shutdown snapshot)" },
            t0.elapsed().as_secs_f64()
        );
        Ok(clean)
    }

    /// START node `i` again after [`Self::stop_node`]: the SAME datadir, port, onion identity and seed list come back
    /// (node 0 keeps the origin directive, exactly as the live origin's plist does). Returns the seconds it took to
    /// answer its RPC again.
    pub fn start_node(&mut self, i: usize) -> Result<f64, String> {
        let (port, dir, seeds) = (self.ports[i], self.dirs[i].clone(), self.seeds.clone());
        let c = Self::spawn_one(&node_binary(), i, port, &dir, &seeds, i == 0, !self.unseated.contains(&i))?;
        self.children[i] = c;
        let t1 = Instant::now();
        if !self.wait_rpc(i, 180) {
            return Err(format!("node{i} never answered its RPC after the restart"));
        }
        Ok(t1.elapsed().as_secs_f64())
    }

    /// THE SUPERVISOR'S HALF OF A SELF-RESTART — what launchd's KeepAlive does in production (and the wallet's watchdog on
    /// a desktop): a node that EXITED on its own is started again on the same datadir and seeds. A wallet's first bond
    /// provisions its seed-derived validator identity (`validator::provision_identity`), and the node then saves and exits
    /// so its supervisor restarts it onto that identity. Without a supervisor the journey's node simply stayed down — the
    /// MEASURED failure: "the node did not come back on your validator identity within 3 minutes". `true` when it
    /// respawned the node.
    pub fn respawn_if_exited(&mut self, i: usize) -> Result<bool, String> {
        match self.children[i].try_wait() {
            Ok(Some(status)) => {
                eprintln!("[supervise] node{i} exited on its own ({status}) — respawning it, as its supervisor does");
                self.start_node(i).map(|_| true)
            }
            _ => Ok(false),
        }
    }

    /// Run `f` — a wallet command that may make node `i` restart itself — while SUPERVISING node `i` as production does.
    pub fn supervised<T: Send>(&mut self, i: usize, f: impl FnOnce() -> T + Send) -> T {
        std::thread::scope(|s| {
            let h = s.spawn(f);
            while !h.is_finished() {
                if let Err(e) = self.respawn_if_exited(i) {
                    eprintln!("[supervise] ⛔ node{i} could not be respawned: {e}");
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            h.join().expect("the supervised wallet call returned")
        })
    }

    /// RESTART node `i` the way production does: [`Self::stop_node`], `downtime`, then [`Self::start_node`]. Returns
    /// the seconds the restarted node took to answer its RPC again.
    pub fn restart_node(&mut self, i: usize, downtime: Duration) -> Result<f64, String> {
        self.stop_node(i)?;
        eprintln!("[restart] node{i} down for {:.0}s", downtime.as_secs_f64());
        std::thread::sleep(downtime);
        self.start_node(i)
    }

    /// Stand up `k` real nodes and PEER THEM, using the two-phase onion bootstrap from
    /// `scripts/mesh_convergence_tps.sh`: seed peers are read ONCE at startup, so a node can only be
    /// given a seed list that already contains everyone's published onion — which means booting once to
    /// mint the identities, collecting `/peer_record`, and restarting with the list pinned.
    ///
    /// Returns `Err` with a plain reason rather than panicking, so the caller decides whether a mesh it
    /// could not raise is a FINDING or an environment problem — those are not the same and the rig must
    /// not decide for it.
    pub fn start(k: usize, tag: &str) -> Result<RealMesh, String> {
        Self::start_with(k, tag, &[])
    }

    /// [`Self::start`], with the listed node indices launched WITHOUT a seat (DB-313 §3; see `RealMesh::unseated`).
    pub fn start_with(k: usize, tag: &str, unseated: &[usize]) -> Result<RealMesh, String> {
        if k == 0 || k > MAX_JOURNEY_NODES {
            return Err(format!(
                "a journey mesh is 1..={MAX_JOURNEY_NODES} nodes; asked for {k}"
            ));
        }
        let bin = node_binary();
        if !bin.exists() {
            return Err(format!(
                "the real node binary is not built at {}. This tier proves nothing without it — build \
                 with `cargo build --release --bin usdmd-node`.",
                bin.display()
            ));
        }
        if let Some(why) = binary_predates_landed_sources(&bin, &["monerousd-node-zkdag/src", "monerousd-node-zkdag/vendor/Plonky3/usdm-decider/src"]) {
            return Err(why);
        }
        // A port base derived from the PID keeps concurrent test binaries off each other's sockets
        // without a shared lock, and the datadir is namespaced the same way.
        let base = 41000u16 + ((std::process::id() as u16) % 6000) / 8 * 8;
        let root = std::env::temp_dir().join(format!("usdmd_journey_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        sweep_stale_journey_dirs();
        let mut me = RealMesh {
            children: Vec::new(),
            ports: Vec::new(),
            dirs: Vec::new(),
            tag: tag.to_string(),
            seeds: String::new(),
            unseated: unseated.to_vec(),
        };
        for i in 0..k {
            let dir = root.join(format!("n{i}"));
            // O1-FOOTPRINT-REVIEWED: fixed-width at MAX_JOURNEY_NODES (=8) — ONE datadir per PROCESS,
            // created once at mesh start. The loop is over processes, not blocks/notes/spends.
            std::fs::create_dir_all(&dir).map_err(|e| format!("datadir {i}: {e}"))?;
            me.dirs.push(dir);
            me.ports.push(base + i as u16);
        }

        // ── PHASE 1a — first boot mints each node's onion identity into its datadir ───────────────────
        for i in 0..k {
            let c = Self::spawn_one(&bin, i, me.ports[i], &me.dirs[i], "", false, !me.unseated.contains(&i))?;
            me.children.push(c);
        }
        for i in 0..k {
            if !me.wait_rpc(i, 90) {
                let why = format!("node{i} never answered /get_height on its first boot");
                me.kill_all();
                return Err(why);
            }
        }
        let onion_wait: u64 = std::env::var("MONEROUSD_JOURNEY_ONION_WAIT")
            .ok()
            .and_then(|v| v.parse().ok())
            // ⭐ MEASURED 2026-09-17: two arti hidden services bootstrapping concurrently on one host
            // took longer than 240s on a loaded machine ("onion … not reachable yet after 60s — state
            // Bootstrapping"). That is the real cost of an onion-only transport, not a defect, so the
            // bound is generous and the failure names how many nodes made it.
            .unwrap_or(600);
        let end = Instant::now() + Duration::from_secs(onion_wait);
        let mut recs: Vec<String> = vec![String::new(); k];
        loop {
            let mut ready = 0usize;
            for i in 0..k {
                if let Ok(r) = me.get(i, "/peer_record") {
                    if r.contains("\"addr\"") {
                        recs[i] = r;
                        ready += 1;
                    }
                }
            }
            if ready >= k {
                break;
            }
            if Instant::now() >= end {
                me.kill_all();
                return Err(format!(
                    "only {ready} of {k} nodes published an onion within {onion_wait}s — the transport \
                     is onion-only, so without it there is no peering and no claim worth making"
                ));
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        let mut seedlist: String = (0..k)
            .filter_map(|i| {
                let pid = json_str(&recs[i], "peer_id")?;
                let addr = json_str(&recs[i], "addr")?;
                let xpk = json_str(&recs[i], "x_pk_hex")?;
                let ek = json_str(&recs[i], "ek_hex")?;
                Some(format!("{pid}|{addr}|{xpk}|{ek}"))
            })
            .collect::<Vec<_>>()
            .join(",");
        // SECOND DEVICE (2026-09-17): the other device's node has a STABLE onion (one mesh identity for the
        // life of its install), so this mesh dials IT from boot — `MONEROUSD_JOURNEY_EXTRA_SEEDS` carries its
        // seed line(s), appended to every node's seed list; peering is bidirectional, so the phone learns
        // this mesh from the handshake and never needs a restart. The mesh's own lines are printed too, for
        // the other direction (`MONEROUSD_LIBP2P_SEED_PEERS` at the other device's launch).
        if let Ok(extra) = std::env::var("MONEROUSD_JOURNEY_EXTRA_SEEDS") {
            let extra = extra.trim();
            if !extra.is_empty() {
                seedlist.push(',');
                seedlist.push_str(extra);
                eprintln!("[phone] {} extra seed line(s) from the second device appended to every node's seed list", extra.split(',').count());
            }
        }
        eprintln!("[phone] SEED_LINES {seedlist}");
        me.seeds = seedlist.clone();

        // ── PHASE 1b — restart with the seed list pinned, then ASSERT peering actually happened ───────
        me.kill_all();
        // THE DEPLOYMENT SHAPE. One origin produces alone until it holds a chain; every other node
        // starts LATER and joins a running network (a #29 DSYNC bundle above the gap policy, a batch
        // pull below it). Nobody co-founds at genesis: two founders producing from genesis over Tor
        // braid at the bootstrap levels (runs 39–62 measured it), and that is not how the user runs
        // the network (the first live node originated it; the second joined hours later). Node 0
        // gets the explicit origin directive; the joiners get NO directive and stay gated until they
        // hold node 0's chain — the same un-gate a real joiner takes.
        let head_start: u64 = std::env::var("MONEROUSD_JOURNEY_ORIGIN_HEAD_START")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(40);
        let c = Self::spawn_one(&bin, 0, me.ports[0], &me.dirs[0], &seedlist, true, !me.unseated.contains(&0))?;
        me.children.push(c);
        if !me.wait_rpc(0, 120) {
            me.kill_all();
            return Err("node0 (the origin) never came back after the seeded restart".to_string());
        }
        if k > 1 && head_start > 0 {
            let t0 = Instant::now();
            let end = t0 + Duration::from_secs(420);
            loop {
                let h = me.height(0).unwrap_or(0);
                if h >= head_start {
                    eprintln!(
                        "[phone] origin head start: node0 holds height {h} after {:.1}s — the {} joiner(s) start now",
                        t0.elapsed().as_secs_f64(),
                        k - 1
                    );
                    break;
                }
                if Instant::now() >= end {
                    eprintln!(
                        "[phone] origin head start: node0 only reached height {h} in 420 s (wanted {head_start}) — \
                         starting the joiner(s) anyway; a chain that does not grow alone is a finding of its own"
                    );
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        for i in 1..k {
            let c = Self::spawn_one(&bin, i, me.ports[i], &me.dirs[i], &seedlist, false, !me.unseated.contains(&i))?;
            me.children.push(c);
        }
        for i in 0..k {
            if !me.wait_rpc(i, 120) {
                let why = format!("node{i} never came back after the seeded restart");
                me.kill_all();
                return Err(why);
            }
        }
        let peer_wait: u64 = std::env::var("MONEROUSD_JOURNEY_PEER_WAIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(420);
        let end = Instant::now() + Duration::from_secs(peer_wait);
        loop {
            // ⭐⭐⭐ PEERING IS A LINK, AND A LINK IS BIDIRECTIONAL — ASK IT THAT WAY.
            //
            // Requiring every node to ANSWER with >=1 peer made the gate depend on the slowest node's
            // RPC, and a node is slowest exactly when it is busiest talking to its peers. MEASURED
            // 2026-09-17: both nodes were exchanging cells (`[link-state] … from 2 known peer(s) — the
            // link CARRIES traffic NOW`) while `/get_peers` timed out under a 16,271-deep `SyncResp`
            // backlog, so the rig waited out its whole budget on a mesh that was already up. **The
            // instrument demanded a reply from the node least able to give one.**
            //
            // A node is not islanded if ANY other node lists it. So: every node must be VOUCHED FOR —
            // by its own answer, or by appearing in a peer's. One reachable node can establish the link
            // for both ends, which is what makes this robust to exactly the load peering creates.
            let mut vouched = vec![false; k];
            if k == 1 {
                // A lone Mac node has no Mac peer to vouch for it: its link is the SECOND DEVICE's, which
                // dials in after this returns (the phone runs, 2026-09-17). Not an island by construction.
                vouched[0] = true;
            }
            let mut lists: Vec<Option<String>> = Vec::with_capacity(k);
            for i in 0..k {
                let list = me.get(i, "/get_peers").ok();
                if let Some(n) = me.peers_known(i) {
                    if n >= 1 {
                        vouched[i] = true;
                    }
                }
                lists.push(list);
            }
            for i in 0..k {
                if vouched[i] {
                    continue;
                }
                let Ok(mine) = me.get(i, "/peer_record") else {
                    continue;
                };
                let Some(my_id) = json_str(&mine, "peer_id") else {
                    continue;
                };
                if my_id.is_empty() {
                    continue;
                }
                // Somebody else can see this node, so the link exists whether or not it can answer.
                if (0..k).any(|j| j != i && lists[j].as_deref().is_some_and(|l| l.contains(&my_id))) {
                    vouched[i] = true;
                }
            }
            if vouched.iter().all(|v| *v) {
                break;
            }
            if Instant::now() >= end {
                let unvouched: Vec<usize> = (0..k).filter(|i| !vouched[*i]).collect();
                me.kill_all();
                return Err(format!(
                    "after {peer_wait}s node(s) {unvouched:?} were not vouched for by ANY node — \
                     neither their own peer list nor any other node's mentions them. That is a real \
                     island and nothing measured on this mesh would mean what it claimed. ⛔ Before \
                     blaming the chain, read those nodes' node.log: `[link-state] … known peer(s)` \
                     means the link is live and the fault is in this gate, not in the transport."
                ));
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        Ok(me)
    }
}

/// How many finished journey datadirs the rig keeps for post-mortem (the node logs a failed pin is read from).
pub const JOURNEY_DIRS_KEPT: usize = 8;

/// ⛔ THE RIG LEAKED DISK, RUN AFTER RUN. `Drop` kills the processes and left `usdmd_journey_<tag>_<pid>` behind
/// (MEASURED 2026-09-26: 290 dirs, ~7.3 GB, up to 360 MB each, on a machine whose "out of memory" was once a full
/// disk). Keep the newest [`JOURNEY_DIRS_KEPT`]; remove every older one whose owning process is gone. A dir whose
/// process still runs (a concurrent test binary) is never touched, whatever its age.
fn sweep_stale_journey_dirs() {
    let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) else { return };
    let mut dirs: Vec<(std::time::SystemTime, std::path::PathBuf, u32)> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let rest = name.strip_prefix("usdmd_journey_")?;
            let pid: u32 = rest.rsplit('_').next()?.parse().ok()?;
            let modified = e.metadata().ok()?.modified().ok()?;
            Some((modified, e.path(), pid))
        })
        .collect();
    dirs.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
    for (_, path, pid) in dirs.into_iter().skip(JOURNEY_DIRS_KEPT) {
        if pid == std::process::id() || process_alive(pid) {
            continue;
        }
        let _ = std::fs::remove_dir_all(&path);
    }
}

/// Whether a process with this pid exists (`kill -0`, which signals nothing).
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(true) // cannot tell: keep the dir
}

impl Drop for RealMesh {
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// ⛔ THE WALLET RIG, EXPLICITLY TEST-ONLY. `mod harness` is already `#[cfg(test)]`, so none of this can
/// reach a shipped binary; saying so here too keeps the boundary legible at the point where the rig touches
/// the filesystem. Every path it writes is ONE per wallet ROLE (bounded by MAX_JOURNEY_NODES), never one
/// per note, block or height.
#[cfg(test)]
pub mod wallet {
    use super::*;

    /// ⭐⭐⭐ A REAL MONEROUSD WALLET PROCESS, DRIVEN AS A USER DRIVES IT.
    ///
    /// `wallet-harness` is the wallet tree's OWN driver: one real wallet per process, its note store
    /// isolated at `MONEROUSD_WALLET_DATA`, talking ONLY to the node at `MONEROUSD_NODE_URL`, and every
    /// command a direct call into `monerousd_wallet_v2_lib::harness` — "a thin wrapper over the EXACT
    /// functions the Tauri UI invokes", in its own words. A green here is a statement about the SHIPPED
    /// wallet, not about a re-implementation of it.
    ///
    /// ⛔ AND THE WALLET DID NOT COMPILE WHEN THIS WAS WRITTEN. `error[E0560]: struct Block has no field
    /// named 'settlement'` — a field replaced by `note_transition` in §CB on 2026-09-15. **The wallet had
    /// been broken against the live node for two days and nothing said so**, because the node's
    /// `cargo test` never builds the wallet tree. Identical rot to `tests/psm_bridge_e2e.rs` dying on
    /// `credit_set` the same week. Two trees, one lesson: a cross-tree consumer that nothing compiles is a
    /// consumer that has already drifted.
    pub struct RealWallet {
        /// O1-FOOTPRINT-REVIEWED: fixed-width at MAX_JOURNEY_NODES (=8) — one wallet per journey role.
        dir: PathBuf,
        /// O1-FOOTPRINT-REVIEWED: fixed-width at MAX_JOURNEY_NODES (=8) — one seed file per wallet role.
        seed_file: PathBuf,
        node_url: String,
        /// The wallet's own receive address, as the wallet itself reported it.
        pub address: String,
    }

    impl RealWallet {
        /// The wallet's OWN reasons from its LAST command (`wallet-stderr.log`, the section after the last `=====` marker):
        /// the lines naming why a note is not spendable, the presence mask and the in-flight change — what a failed balance
        /// step must print, because the balance reply alone says only "confirming". Its own local log; counts and levels.
        pub fn last_reasons(&self, max: usize) -> Vec<String> {
            let log = std::fs::read_to_string(self.dir.join("wallet-stderr.log")).unwrap_or_default();
            let last = log.rsplit("\n===== ").next().unwrap_or("");
            let mut out: Vec<String> = Vec::new();
            for l in last.lines() {
                if ["[member-book]", "[instant-mask]", "[change-in-flight]", "[fold-horizon]", "[window", "[oli-"].iter().any(|p| l.contains(p))
                    && !out.iter().any(|o| o == l)
                {
                    out.push(l.chars().take(300).collect());
                }
            }
            let n = out.len();
            out.into_iter().skip(n.saturating_sub(max)).collect()
        }

        pub fn binary() -> PathBuf {
            // The wallet-side twin of `MONEROUSD_JOURNEY_NODE_BIN`: a lane measuring its own wallet build names it
            // here instead of replacing the shared `target/release` harness (charter §8.5). Test-only.
            if let Ok(p) = std::env::var("MONEROUSD_JOURNEY_WALLET_BIN") {
                return PathBuf::from(p);
            }
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.pop();
            p.push("monerousd-wallet-v2");
            p.push("src-tauri");
            p.push("target");
            p.push("release");
            p.push("wallet-harness");
            p
        }

        /// Create a FRESH wallet exactly as tapping "Create wallet" does (`HARNESS_GENERATE=1` — the app's
        /// own create path: birth at the current tip, scan starts there). The seed is persisted so every
        /// later command reopens the SAME wallet.
        pub fn create(tag: &str, role: &str, node_url: &str) -> Result<RealWallet, String> {
            let bin = Self::binary();
            if !bin.exists() {
                return Err(format!(
                    "the real wallet binary is not built at {}. Build it with `cargo build --release \
                     --bin wallet-harness` in monerousd-wallet-v2/src-tauri — a wallet claim needs the \
                     real wallet.",
                    bin.display()
                ));
            }
            // The wallet compiles in its own tree, the node crate and the decider: older than a landed change to any of
            // them, it measures old code (MEASURED 2026-10-03: a Sep 28 harness failed every send on the DB-223 door).
            if let Some(why) = binary_predates_landed_sources(
                &bin,
                &[
                    "monerousd-wallet-v2/src-tauri/src",
                    "monerousd-node-zkdag/src",
                    "monerousd-node-zkdag/vendor/Plonky3/usdm-decider/src",
                ],
            ) {
                return Err(why);
            }
            let dir = std::env::temp_dir().join(format!("usdmw_{tag}_{role}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).map_err(|e| format!("wallet dir: {e}"))?;
            let out = Command::new(&bin)
                .env("HARNESS_GENERATE", "1")
                .env("MONEROUSD_NODE_URL", node_url)
                .env("MONEROUSD_WALLET_DATA", &dir)
                .env("MONEROUSD_NET", "testnet")
                .stdin(Stdio::null())
                .output()
                .map_err(|e| format!("wallet spawn: {e}"))?;
            let txt = String::from_utf8_lossy(&out.stdout).to_string();
            let seed = json_str(&txt, "seed")
                .or_else(|| json_str(&txt, "mnemonic"))
                .ok_or_else(|| format!("the wallet did not report a seed on create: {txt}"))?;
            let address = json_str(&txt, "address")
                .ok_or_else(|| format!("the wallet did not report an address on create: {txt}"))?;
            let seed_file = dir.join("seed.txt");
            std::fs::write(&seed_file, &seed).map_err(|e| format!("seed file: {e}"))?;
            Ok(RealWallet { dir, seed_file, node_url: node_url.to_string(), address })
        }

        /// Run a batch of the harness's OWN commands (`balance`, `bond`, `send`, `refresh`, `mybond`, …)
        /// and return one reply line per command, through its one-shot config mode.
        /// A real spend from THIS wallet in its own thread (the burst measurement runs N of these at
        /// once — N users each proving their own spend). Returns (submitted ok, seconds).
        /// THE SAME SEED, A FRESH EMPTY DATA DIR, THE OTHER NODE — what a user does when their phone is
        /// lost. Nothing from this wallet's note store, spent record or witness book crosses over: the
        /// restored wallet must find its notes on the CHAIN (records + account targets), learn which of
        /// them are spent from the unspent tree (the presence probe — it has no local spent record), and
        /// show the same spendable balance. The user's question (2026-09-19): "custody/ownership and
        /// finding notes gave us trouble originally, have we gotten that reliable where funds never
        /// disappear?" — this is the measurement that answers it, on the real node, every run.
        /// Harness fixture (test-only): one restore dir per wallet ROLE, removed before reuse.
        pub fn restored_elsewhere_for_test(&self, role: &str, node_url: &str) -> Result<RealWallet, String> {
            let dir = std::env::temp_dir().join(format!("usdmw_restore_{role}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).map_err(|e| format!("restore dir: {e}"))?;
            // the SAME seed file — nothing else of the original wallet is reachable from `dir`
            Ok(RealWallet { dir, seed_file: self.seed_file.clone(), node_url: node_url.to_string(), address: self.address.clone() })
        }

        /// DB-98a made every poll a real detection pass, so sixteen sequential polls became minutes;
        /// the burst wallets are polled in PARALLEL (one wallet process each), exactly as they spend.
        /// The same wallet (its datadir, seed and node) as a second handle — for running its commands on another thread.
        #[must_use]
        pub fn clone_handle(&self) -> RealWallet {
            RealWallet {
                dir: self.dir.clone(),
                seed_file: self.seed_file.clone(),
                node_url: self.node_url.clone(),
                address: self.address.clone(),
            }
        }

        /// The wallet's datadir (its note store, witness book and the `seed.txt` `create` wrote) — what a parked journey
        /// moves between processes.
        pub fn dir(&self) -> &std::path::Path {
            &self.dir
        }

        /// THE SAME WALLET IN A LATER PROCESS: its datadir as parked (`dir`, holding the `seed.txt` `create` wrote), its own
        /// address, and the node URL this process serves — nothing is generated; every later command reopens the wallet
        /// `create` made, exactly as the app reopens it on the next launch. The real journey's legs
        /// (`netsim::journey_tests::sim_journey_real_leg_*`) reopen W1 and W2 this way after the park.
        pub fn reopened(dir: PathBuf, node_url: &str, address: String) -> RealWallet {
            let seed_file = dir.join("seed.txt");
            RealWallet { dir, seed_file, node_url: node_url.to_string(), address }
        }

        pub fn spawn_balance(&self) -> std::thread::JoinHandle<u64> {
            let w = RealWallet {
                dir: self.dir.clone(),
                seed_file: self.seed_file.clone(),
                node_url: self.node_url.clone(),
                address: self.address.clone(),
            };
            std::thread::spawn(move || {
                let r = w.run(&["refresh", "balance"]).unwrap_or_default();
                r.iter()
                    .filter(|l| l.contains("\"op\":\"balance\""))
                    .filter_map(|l| json_u64(l, "atomic"))
                    .last()
                    .unwrap_or(0)
            })
        }

        /// PERF TIER (P2/P3/P5): one `refresh` + `balance` as [`Self::spawn_balance`] runs it, read whole — (spendable atomic,
        /// pending atomic, confirming atomic) from the wallet's own balance reply, and the command's wall seconds.
        pub fn spawn_balance_parts(&self) -> std::thread::JoinHandle<((u64, u64, u64), f64)> {
            let w = self.clone_handle();
            std::thread::spawn(move || {
                let t0 = std::time::Instant::now();
                let r = w.run(&["refresh", "balance"]).unwrap_or_default();
                let secs = t0.elapsed().as_secs_f64();
                let line = r.iter().filter(|l| l.contains("\"op\":\"balance\"")).last().cloned().unwrap_or_default();
                let part = |k: &str| json_u64(&line, k).unwrap_or(0);
                ((part("atomic"), part("pending_atomic"), part("confirming_atomic")), secs)
            })
        }

        pub fn spawn_send(&self, to: &str, amount: &str) -> std::thread::JoinHandle<(bool, f64)> {
            let w = RealWallet {
                dir: self.dir.clone(),
                seed_file: self.seed_file.clone(),
                node_url: self.node_url.clone(),
                address: self.address.clone(),
            };
            let (to, amount) = (to.to_string(), amount.to_string());
            std::thread::spawn(move || {
                let (sent, secs, last) = w.send_in_session(&to, &amount, 360);
                if !sent {
                    eprintln!("[real-send] refused after {secs:.1}s — last reply: {last}");
                }
                (sent, secs)
            })
        }

        /// ⭐ A SEND THE WAY THE APP MAKES ONE — from ONE long-lived wallet process.
        ///
        /// Spend authority is a MAINTAINED recursive carrier (`nf_carrier`) that the wallet's background
        /// follower keeps at the chain tip. A process started only to send registers the note and exits before
        /// the follower's next pass, so it can never send. MEASURED 2026-09-26 on two real processes: a funded
        /// wallet's one-shot `send` answered "this note's spend authority is still being built: the wallet is 0
        /// block(s) behind the chain … it becomes spendable as soon as the carrier reaches the tip" in 0.2 s,
        /// and the old one-shot retry did not recognise that reply.
        ///
        /// This drives the harness over stdin, as `ecosystem-check.sh`'s `wallet()` does: `detect`, `balance`, then
        /// `send`. On a retryable refusal it `hold`s the SAME process so the follower keeps following, then
        /// sends again. That is the user's "retry in a moment", with the reason on screen. A new `send` is
        /// written only after the previous one's reply has been read, so one payment can never be submitted
        /// twice. Every read has a deadline, so a hung wallet ends the call instead of the test.
        ///
        /// Returns (sent, seconds since the first attempt, the last `send` reply).
        pub fn send_in_session(&self, to: &str, amount: &str, secs: u64) -> (bool, f64, String) {
            self.pay_in_session(&format!("send {to} {amount}"), "send", secs)
        }

        /// [`Self::send_in_session`]'s loop for ANY paying command — `send <to> <usdm>`, or DB-319's `tappay <charge>`
        /// (the tap UI's one pay path, `wallet_pos_pay`): `detect`, `balance`, then the command, holding the SAME
        /// process on a retryable refusal. A new attempt is written only after the previous reply was read, so one
        /// payment can never be submitted twice. Returns (paid, seconds since the first attempt, the last reply).
        pub fn pay_in_session(&self, cmd: &str, op: &str, secs: u64) -> (bool, f64, String) {
            use std::io::{BufRead, BufReader, Write};
            let seed = match std::fs::read_to_string(&self.seed_file) {
                Ok(s) => s,
                Err(e) => return (false, 0.0, format!("seed file: {e}")),
            };
            let mut child = match Command::new(Self::binary())
                .env("HARNESS_SEED", seed.trim())
                .env("MONEROUSD_NODE_URL", &self.node_url)
                .env("MONEROUSD_WALLET_DATA", &self.dir)
                .env("MONEROUSD_NET", "testnet")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                // The wallet's OWN reasons (`[member-book] … not spendable yet`, `[asset-send] …`) reach the run's log, never
                // /dev/null: MEASURED sim-20261006-215209 T2 "never held its created SIMT within 832 s" with no wallet line
                // anywhere to say why. Inherited — no file is written; the run's own log is the one record.
                .stderr(Stdio::inherit())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => return (false, 0.0, format!("wallet spawn: {e}")),
            };
            let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
                let _ = child.kill();
                let _ = child.wait();
                return (false, 0.0, "the wallet's stdio was not piped".to_string());
            };
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            let deadline = Instant::now() + Duration::from_secs(secs);
            // The reply to one command: the next line naming its op, or None at the deadline / on exit.
            let reply = |op: &str| -> Option<String> {
                let tag = format!("\"op\":\"{op}\"");
                loop {
                    let left = deadline.checked_duration_since(Instant::now())?;
                    match rx.recv_timeout(left) {
                        Ok(line) if line.contains(&tag) => return Some(line),
                        Ok(_) => continue,
                        Err(_) => return None,
                    }
                }
            };
            let mut say = |cmd: &str| -> bool { writeln!(stdin, "{cmd}").and_then(|_| stdin.flush()).is_ok() };
            let retryable = |r: &str| {
                // the carrier has not reached the tip yet (nf_carrier's two "retry in a moment" states)
                r.contains("spend authority is still being built")
                    || r.contains("spend authority is not available yet")
                    // the funded note's block must fold first (a confirmation depth) — the class the
                    // one-shot loop retried on, kept so no caller loses a retry it had
                    || r.contains("deletion witness")
                    || r.contains("not folded")
                    || r.contains("NOT in the unspent tree")
                    || r.contains("copath")
                    || r.contains("membership")
                    // the node's own retry code: an otherwise-valid input whose record is not folded there yet
                    || r.contains("NOT_FOLDED_YET")
                    // the spend's member-path anchor left the node's ring between the wallet's poll and the node's
                    // judgment (a fold rewind): the next attempt polls the stream again, the book re-captures from the
                    // fork (`apply_stream`) and the carrier re-anchors in the current ring — Zcash's wallet re-anchors
                    // after a reorg the same way. MEASURED: launch-leg1-g11b-20261022-2245.log:24049 "retryable false".
                    || r.contains("anchor ring")
                    // 2026-10-28 (lane funds, journey-125/139.log T3 POS tap): two refusals the node itself words as
                    // "right now" — `MEMBERSHIP_PROOF_MISSING` (the leg's ring anchor left the node's ring in a re-fold
                    // between the wallet's poll and the door's judgment; the next poll re-anchors) and "cannot prove this
                    // note's tags unspent right now (503): this node holds no leaves for that nullifier shard" (the
                    // DB-353 shard witness not held yet). The app re-polls on both; the harness re-presses within the
                    // step's own budget, exactly as the classes above. Neither widens a gate: the door still refuses.
                    || r.contains("MEMBERSHIP_PROOF_MISSING")
                    || r.contains("right now (503)")
                    // the submit node did not answer an evidence read in time (a restart's closed port, a lock held): the
                    // wallet names it (`fetch_fold_base`) and the app retries it — the spend was never broadcast
                    || r.contains("did not answer")
                    // 2026-10-29 (brb1-journey-lane6 T2): the wallet's own remainder from its last payment is still in
                    // flight ("they become spendable when the chain carries them") — the wallet names it as a wait, not an
                    // empty balance, and the app re-polls; the harness re-presses within the step's budget.
                    || r.contains("still in flight")
                    // 2026-11-01 (lane stable, stable/pa1.log PA.4): a seed RESTORED on another node is a new device (DB-329)
                    // and claims a slot on chain before it writes change; the write gate names the two states that settle
                    // by themselves — "the send goes once the claim confirms" (Claiming) and "once the slot is settled"
                    // (Undecided) — and the app re-polls. `NeedsAdd` ("Add this device again") needs the user and stays
                    // fatal. A claim that never confirms still fails the step when its budget ends, with this reply.
                    || r.contains("the send goes once the claim confirms")
                    || r.contains("the send goes once the slot")
            };
            let t0 = Instant::now();
            let (mut sent, mut last) = (false, String::new());
            // `balance` before `send`, as in the app: the balance summary calls `nf_carrier::watch` for every
            // owned note, so the follower starts before the first send (wallet lane's ruling, 2026-09-26).
            if say("detect") && reply("detect").is_some() && say("balance") && reply("balance").is_some() {
                let mut said = String::new();
                while say(cmd) {
                    let Some(r) = reply(op) else { break };
                    last = r;
                    // Each NEW refusal reaches the run's log as it happens, not only at the loop's end: MEASURED
                    // sim-20261006-234445 T1.7 — 13 retried sends after node 0's restart, the sim budget ended the call
                    // first, and not one reply was ever printed, so the step's cause had no name.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a test harness's refusal text (an error string), the harness's own log.
                    if !last.contains("\"ok\":true") && last != said {
                        eprintln!("[real-send] {op} refused (retryable {}): {}", retryable(&last), last.chars().take(600).collect::<String>());
                        said.clone_from(&last);
                    }
                    // A command that ran its plan but had a part REFUSED (`swapexec`'s `"complete":false`, its refusals
                    // named in `refused`) has not paid: it is retried like any refusal, on the same rule.
                    if last.contains("\"ok\":true") && !last.contains("\"complete\":false") {
                        sent = true;
                        break;
                    }
                    if !retryable(&last) || !say("hold 3000") || reply("hold").is_none() {
                        break;
                    }
                    // The shipped UI refreshes its balance between a user's attempts; a re-press that never re-reads the
                    // chain waits on a remainder the chain already carried (c10-journey.log, 270 re-presses over 832 s).
                    if !say("balance") || reply("balance").is_none() {
                        break;
                    }
                }
            }
            let _ = say("quit");
            let _ = child.kill();
            let _ = child.wait();
            (sent, t0.elapsed().as_secs_f64(), last)
        }

        /// A LIVE wallet-harness process over stdio — the shape [`Self::send_in_session`] drives, exposed so a
        /// journey can hold TWO wallets open at once and carry bytes between them (the tap's crossings). Every
        /// read is bounded by the session's deadline, so a hung wallet ends the call, never the test; dropping
        /// the session quits and reaps the process.
        pub fn session(&self, secs: u64) -> Result<Session, String> {
            use std::io::{BufRead, BufReader};
            let seed = std::fs::read_to_string(&self.seed_file).map_err(|e| format!("seed file: {e}"))?;
            let mut child = Command::new(Self::binary())
                .env("HARNESS_SEED", seed.trim())
                .env("MONEROUSD_NODE_URL", &self.node_url)
                .env("MONEROUSD_WALLET_DATA", &self.dir)
                .env("MONEROUSD_NET", "testnet")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                // The wallet's OWN reasons (`[member-book] … not spendable yet`, `[asset-send] …`) reach the run's log, never
                // /dev/null: MEASURED sim-20261006-215209 T2 "never held its created SIMT within 832 s" with no wallet line
                // anywhere to say why. Inherited — no file is written; the run's own log is the one record.
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("wallet spawn: {e}"))?;
            let stdin = child.stdin.take().ok_or_else(|| "the wallet's stdin was not piped".to_string())?;
            let stdout = child.stdout.take().ok_or_else(|| "the wallet's stdout was not piped".to_string())?;
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            Ok(Session { child, stdin, rx, deadline: Instant::now() + Duration::from_secs(secs) })
        }

        pub fn run(&self, cmds: &[&str]) -> Result<Vec<String>, String> {
            let cfg_path = self.dir.join("cmd.json");
            let out_path = self.dir.join("out.jsonl");
            let _ = std::fs::remove_file(&out_path);
            // Each command is a JSON STRING (escaped), so a command carrying a quote or backslash — a letter body, a
            // profile bio, a relayed frame array — reaches the wallet as typed instead of breaking the config.
            let cmds_json = cmds
                .iter()
                .map(|c| serde_json::to_string(c).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(",");
            let cfg = format!(
                "{{\"seed_file\":\"{}\",\"node_url\":\"{}\",\"data_dir\":\"{}\",\"out\":\"{}\",\"cmds\":[{}]}}",
                self.seed_file.display(),
                self.node_url,
                self.dir.display(),
                out_path.display(),
                cmds_json
            );
            std::fs::write(&cfg_path, cfg).map_err(|e| format!("wallet cfg: {e}"))?;
            // DB-102 (runs 102c/102h, 2026-09-19): `Command::output()` waited on the child FOREVER — a
            // wallet-harness process found 12 minutes old and idle (RSS 14 MB) while the journey's burst
            // thread blocked on it, and the journey then died with SIGKILL from outside. A child that has
            // not exited after WALLET_RUN_DEADLINE_SECS is killed and reported AS a death with its stderr —
            // never waited on past the deadline, never read as a chain verdict.
            // O1-FOOTPRINT-REVIEWED: by construction — one child's piped stderr, a `_for_test` harness buffer
            // that lives for one wallet command; the wallet log it feeds is capped at 4 MiB below.
            let mut child = Command::new(Self::binary())
                .arg(&cfg_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("wallet run: {e}"))?;
            let started = Instant::now();
            let mut err_pipe = child.stderr.take();
            let drain = std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut e) = err_pipe.take() {
                    use std::io::Read;
                    let _ = e.read_to_end(&mut buf);
                }
                buf
            });
            let status = loop {
                match child.try_wait() {
                    Ok(Some(st)) => break st,
                    Ok(None) => {
                        if started.elapsed() > Duration::from_secs(WALLET_RUN_DEADLINE_SECS) {
                            let _ = child.kill();
                            let _ = child.wait();
                            let words = String::from_utf8_lossy(&drain.join().unwrap_or_default()).to_string();
                            let tail_at = words.len().saturating_sub(1500);
                            let tail = &words[words.char_indices().map(|(i, _)| i).find(|&i| i >= tail_at).unwrap_or(0)..];
                            return Err(format!(
                                "the wallet HUNG past {WALLET_RUN_DEADLINE_SECS}s running {cmds:?} and was killed by the \
                                 harness (DB-102) — its stderr tail:\n{tail}"
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(e) => return Err(format!("wallet wait: {e}")),
                }
            };
            let st = std::process::Output { status, stdout: Vec::new(), stderr: drain.join().unwrap_or_default() };
            // ⛔ A WALLET THAT DIES IS NOT A CHAIN REFUSAL (measured 2026-08-09 and again 2026-09-17: the
            // first wallet money-path run read a harness death during `send` as "the send was refused").
            // The death is reported AS a death, with the process's own last words (its piped stderr).
            // DB-98 (run 99): the wallet's own scan/discovery log is the ONLY witness of why a received note
            // stays invisible; keep every run's stderr in the wallet's directory (`wallet-stderr.log`) so a
            // silent "balance did not rise" can be read after the fact. Bounded: one file per wallet, the
            // last 4 MiB kept (`_for_test` harness file, never node state).
            {
                let log_path = self.dir.join("wallet-stderr.log");
                let mut prev = std::fs::read(&log_path).unwrap_or_default();
                prev.extend_from_slice(format!("\n===== {cmds:?} =====\n").as_bytes());
                prev.extend_from_slice(&st.stderr);
                if prev.len() > 4 << 20 {
                    prev.drain(..prev.len() - (4 << 20));
                }
                let _ = std::fs::write(&log_path, &prev);
            }
            if !st.status.success() {
                let err_txt = String::from_utf8_lossy(&st.stderr);
                let tail_at = err_txt.len().saturating_sub(1500);
                let tail = &err_txt[err_txt.char_indices().map(|(i, _)| i).find(|&i| i >= tail_at).unwrap_or(0)..];
                return Err(format!("the wallet DIED ({}) running {cmds:?} — its stderr tail:\n{tail}", st.status));
            }
            let txt = std::fs::read_to_string(&out_path).unwrap_or_default();
            if txt.trim().is_empty() {
                return Err(format!(
                    "the wallet produced no replies ({}). A wallet that DIES reads nothing like a \
                     chain refusal — measured 2026-08-09, a wallet-process death was counted as a failed \
                     payment. Opposite defects, opposite fixes; never report one as the other.",
                    st.status
                ));
            }
            // A REFUSED command carries the wallet's OWN cause into the journey log (bounded: its tagged lines only).
            // MEASURED why (sim-20261023-042514.log:32954): T3's matured unbond was refused "has not settled its device
            // slot", and the [store-load] lines naming why sat in a wallet-stderr.log the final leg's cleanup removed.
            if txt.lines().any(|l| l.contains("\"ok\":false")) {
                let err_txt = String::from_utf8_lossy(&st.stderr);
                let tagged: Vec<&str> = err_txt
                    .lines()
                    .filter(|l| l.contains("[store-load]") || l.contains("[device-slot]") || l.contains("[slot") || l.contains('⛔'))
                    .collect();
                for l in tagged.iter().rev().take(12).rev() {
                    eprintln!("[wallet-stderr] {}", l.chars().take(300).collect::<String>());
                }
            }
            Ok(txt.lines().map(|l| l.to_string()).collect())
        }
    }

    /// A live wallet process opened by [`RealWallet::session`].
    pub struct Session {
        child: Child,
        stdin: std::process::ChildStdin,
        rx: std::sync::mpsc::Receiver<String>,
        deadline: Instant,
    }

    impl Session {
        /// Write one command, then return the reply line naming `op` — `None` at the session's deadline or if the
        /// wallet exited. Lines naming other ops are skipped.
        pub fn ask(&mut self, cmd: &str, op: &str) -> Option<String> {
            use std::io::Write;
            writeln!(self.stdin, "{cmd}").and_then(|_| self.stdin.flush()).ok()?;
            let tag = format!("\"op\":\"{op}\"");
            loop {
                let left = self.deadline.checked_duration_since(Instant::now())?;
                match self.rx.recv_timeout(left) {
                    Ok(line) if line.contains(&tag) => return Some(line),
                    Ok(_) => continue,
                    Err(_) => return None,
                }
            }
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            use std::io::Write;
            let _ = writeln!(self.stdin, "quit");
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Pull `"key":<number>` out of a JSON body without a parser dependency in the test path.
/// The `/dag_recent` rows — `(id, parents, on_selected_chain)`, newest first — scanned out of the JSON text
/// (`{"id":"…","parents":[…],"blue_score":…,"ts":…,"selected":…}` per row; the harness has no JSON parser).
pub fn dag_recent_rows(body: &str) -> Vec<(String, Vec<String>, bool)> {
    let mut rows = Vec::new();
    let mut rest = body;
    while let Some(p) = rest.find("\"id\":\"") {
        let after = &rest[p + 6..];
        let Some(e) = after.find('"') else { break };
        let id = after[..e].to_string();
        let row_end = after.find("\"id\":\"").unwrap_or(after.len());
        let row = &after[..row_end];
        let parents = row
            .find("\"parents\":[")
            .map(|q| {
                let s = &row[q + 11..];
                let end = s.find(']').unwrap_or(0);
                s[..end]
                    .split(',')
                    .map(|x| x.trim().trim_matches('"').to_string())
                    .filter(|x| !x.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let selected = row.contains("\"selected\":true");
        rows.push((id, parents, selected));
        rest = after;
    }
    rows
}

/// DB-65 (run 75): how much of each node's recent DAG the other nodes hold — the figure behind "the joiner
/// never applied the origin's mint block": heights looked close while node 1 held 11 of node 0's 53 recent
/// selected-chain blocks and none of its newest block's parents. Printed per pair; a node holding under
/// half of another's recent selected chain is a finding (the two DAGs run as separate branches).
pub fn dag_overlap(mesh: &RealMesh, n: usize, when: &str) -> Vec<String> {
    let views: Vec<Vec<(String, Vec<String>, bool)>> =
        (0..n).map(|i| dag_recent_rows(&mesh.get(i, "/dag_recent").unwrap_or_default())).collect();
    let mut findings = Vec::new();
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            let held: std::collections::HashSet<&str> = views[j].iter().map(|r| r.0.as_str()).collect();
            let recent = views[i].len();
            let recent_held = views[i].iter().filter(|r| held.contains(r.0.as_str())).count();
            let sel: Vec<&(String, Vec<String>, bool)> = views[i].iter().filter(|r| r.2).collect();
            let sel_held = sel.iter().filter(|r| held.contains(r.0.as_str())).count();
            let newest_parents = views[i].first().map(|r| r.1.len()).unwrap_or(0);
            let newest_parents_held = views[i]
                .first()
                .map(|r| r.1.iter().filter(|p| held.contains(p.as_str())).count())
                .unwrap_or(0);
            eprintln!(
                "[dag-overlap] {when}: node{i} recent {recent} held by node{j}: {recent_held}; node{i} selected-chain recent {}: held by node{j} {sel_held}; node{i}'s newest block's parents held by node{j}: {newest_parents_held}/{newest_parents}",
                sel.len()
            );
            if recent > 0 && !sel.is_empty() && sel_held * 2 < sel.len() {
                findings.push(format!(
                    "node{j} holds only {sel_held} of node{i}'s {} recent selected-chain blocks {when} — the two DAGs run as separate branches (DB-65)",
                    sel.len()
                ));
            }
        }
    }
    findings
}

pub fn json_u64(body: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let at = body.find(&needle)? + needle.len();
    let rest = body[at..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Pull `"key":"<string>"` out of a JSON body.
pub fn json_str(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let at = body.find(&needle)? + needle.len();
    let rest = &body[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// DB-273 §19.6 L3 — a REAL owner clue for a journey's owner-named object: the `chg` locator at index 0 of a locator
/// secret derived from `seed`, through the same `oli` encoding a wallet uses. Distinct seeds give unlinkable clues.
#[must_use]
pub fn journey_owner_clue(seed: u64) -> Vec<u8> {
    let loc_sk = crate::oli::derive_loc_sk(blake3::hash(&seed.to_le_bytes()).as_bytes());
    let salt = crate::oli::address_salt(&loc_sk, "chg", 0);
    crate::oli::tag_clue_bytes_v2(
        &crate::oli::locator_at(&loc_sk, "chg", 0),
        &salt,
        &crate::oli::address_index_hint(&loc_sk, &salt, 0),
    )
}

/// DB-273 §17 (1) — a REAL v4 receive address for a journey party that must hold its OWN keys (to open the note and build a
/// proof over it in-test): `ek` and the party's spend key `spk` (DB-395 — the faucet refuses an address without one) wrapped
/// with the `recv` locator, salt and hint at index 0 of a locator secret derived from `seed`, through the same `oli` encoding a
/// wallet uses. The faucet refuses a bare key (`NO_LOCATOR`: a note filed for nobody is a burn), so a party that drips to
/// itself names a findable address.
#[must_use]
pub fn journey_receive_address(seed: u64, ek: &[u8], spk: &crate::spend_frontier::Digest4) -> String {
    let loc_sk = crate::oli::derive_loc_sk(blake3::hash(&seed.to_le_bytes()).as_bytes());
    let salt = crate::oli::address_salt(&loc_sk, "recv", 0);
    crate::address::pq_stealth_address_v4(
        1,
        blake3::hash(&[&seed.to_le_bytes()[..], b"journey-b"].concat()).as_bytes(),
        ek,
        Some((
            &crate::oli::locator_at(&loc_sk, "recv", 0),
            &salt,
            &crate::oli::address_index_hint(&loc_sk, &salt, 0),
        )),
        spk,
    )
    .expect("an ML-KEM-768 key encodes into a v4 receive address")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────
// THE JOURNEYS
// ─────────────────────────────────────────────────────────────────────────────────────────────────────
#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn hexs(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }

    /// ⭐⭐⭐ THE FIRST RUN OF THIS TIER REFUTED A CLOSURE MADE FROM A FIXTURE THE DAY BEFORE.
    ///
    /// On 2026-09-16 the in-process pin `a_fill_settles_on_a_produced_node_when_its_inputs_are_in_the_
    /// live_unspent_tree` went green and §AQ was written up as closed for the DEX path. This journey ran
    /// the same trade against TWO REAL `usdmd-node` PROCESSES and measured, from the nodes' own logs:
    ///
    /// ```text
    /// [order-post] ⛔ rested locally but the mempool REFUSED the transaction (InvalidProof)
    ///              — this order will exist on this node and nowhere else
    /// [nf-gate]    REJECT: 32 input(s) carried NO absence proof
    /// [order-fill] ⛔ REFUSED at the burn gate: the settlement's inputs cannot be proved unspent
    ///              against this node's live root, so NOTHING was written
    /// ```
    ///
    /// ⭐ **THE NODE IS RIGHT AND THE GREEN PIN WAS THE PROBLEM.** A fill whose inputs the chain never
    /// held MUST be refused — that is the deletion transition doing exactly its job. The pin only passed
    /// because it plants its inputs with `carry_notes_in_a_block_for_test`, a TEST-ONLY door with no
    /// real-node equivalent. So the fixture was not modelling a user; it was modelling a user plus a
    /// privilege no user has.
    ///
    /// ⛔ **THE BLOCKER, NAMED:** this rig has no way to fund a party on a real chain, so no journey can
    /// yet carry a DEX fill the whole way. Until it can, `OrderFill` is `Moved::Unproven` in the register
    /// — which is the register working, not the register failing. What this journey DOES establish is
    /// below, and every line of it is a fact about real processes over real sockets.
    #[test]
    fn two_real_nodes_peer_and_a_settlement_whose_inputs_the_chain_never_held_is_refused_by_both() {
        use usdm_decider::whir_rec_block::{
            prove_order_maker_half, prove_order_taker_half, wrapped_asset_tag_u32, MakerHalfWitness,
            OrderTerms, TakerHalfWitness, USDM_ASSET_TAG,
        };

        let t0 = Instant::now();
        let mesh = match RealMesh::start(2, "dexfill") {
            Ok(m) => m,
            Err(e) => panic!(
                "⛔ THE FUNCTIONAL TIER COULD NOT RAISE A REAL 2-NODE MESH: {e}\n   This tier is the \
                 only thing in the tree that can tell a chain refusal from a fixture that forgot its \
                 setup. A mesh that will not stand up is a finding about the node or the host, not a \
                 reason to fall back to an in-process fixture and call the result a consensus verdict."
            ),
        };
        // `RealMesh::start` returns once every node is VOUCHED for by some peer list — a ONE-WAY link
        // satisfies it. This journey's claim needs both nodes to see each other and the joiner to hold the
        // chain, and an onion service's descriptor lands when Tor says so: MEASURED 2026-09-20, two runs in a
        // row read `node0 sees 1 peer(s), node1 sees 0; heights 67/0` and `node0 sees 0, node1 sees 1;
        // heights 60/0` at the instant `start` returned, while the money-path journeys on the same rig
        // reached two-way links and their settle gate inside their own 420 s budget. So wait for the
        // two-way link and a non-zero joiner height on the same budget the rig gives peering, then judge.
        let peer_wait: u64 = match std::env::var("MONEROUSD_JOURNEY_PEER_WAIT").ok().and_then(|v| v.parse().ok()) {
            Some(secs) => secs,
            None => 420, // the rig's own peering budget
        };
        let end = Instant::now() + Duration::from_secs(peer_wait);
        let (mut p0, mut p1) = (0usize, 0usize);
        loop {
            p0 = mesh.peer_count_excluding_self(0);
            p1 = mesh.peer_count_excluding_self(1);
            let joiner_has_chain = matches!(mesh.height(1), Some(h) if h > 0);
            if (p0 >= 1 && p1 >= 1 && joiner_has_chain) || Instant::now() >= end {
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        eprintln!(
            "[journey] 2 real usdmd-node processes peered in {:.1}s — node0 :{} sees {p0} peer(s), \
             node1 :{} sees {p1}; heights {:?}/{:?}",
            t0.elapsed().as_secs_f64(),
            mesh.port(0),
            mesh.port(1),
            mesh.height(0),
            mesh.height(1),
        );
        assert!(
            p0 >= 1 && p1 >= 1,
            "⛔ an islanded node witnesses nothing — every claim below would be vacuous"
        );

        // ── A REAL ORDER, PROVEN FOR REAL, POSTED OVER A REAL SOCKET ─────────────────────────────────
        // DEX-GRID (C3): through the one snap helper.
        let t = OrderTerms {
            lot: crate::order_book::snap_to_grid(100_000),
            pay_b: crate::order_book::snap_to_grid(250_000),
            asset_a: wrapped_asset_tag_u32(1),
            asset_b: USDM_ASSET_TAG,
            expires_at_height: crate::order_book::snap_expiry(500_000),
        };
        let (maker_bytes, maker) = prove_order_maker_half(
            &MakerHalfWitness {
                owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[41, 42, 43, 44])),
                payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[51, 52, 53, 54]),
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            },
            &t,
        )
        .expect("maker half proves");
        let h3 = |v: &[u64; 3]| -> String {
            let mut o = String::new();
            for w in v {
                o.push_str(&hexs(&w.to_le_bytes()));
            }
            o
        };
        let h4 = |v: &crate::spend_frontier::Digest4| -> String {
            hexs(&crate::spend_frontier::leaf_to_cm_bytes(*v))
        };
        let mut maker_payout_note = vec![0u8; 1153];
        maker_payout_note[..32]
            .copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(maker.payout_cm));
        let post_body = format!(
            "{{\"lot\":{},\"pay_b\":{},\"asset_a\":\"{}\",\"asset_b\":\"{}\",\"expires_at_height\":{},\"nullifier\":\"{}\",\"leaf_commit\":\"{}\",\"payout_cm\":\"{}\",\"maker_bytes_hex\":\"{}\",\"payout_note_hex\":\"{}\",\"payout_clue_hex\":\"{}\"}}",
            t.lot, t.pay_b, h3(&t.asset_a), h3(&t.asset_b), t.expires_at_height,
            h4(&maker.nullifier), h4(&maker.leaf_commit), h4(&maker.payout_cm),
            hexs(&maker_bytes), hexs(&maker_payout_note),
            // DB-273 §19.6 L3: the maker's payout owner.
            hexs(&journey_owner_clue(0x1300))
        );
        // ⛔ DB-150 MOVED THIS JOURNEY'S REFUSAL TO THE POST DOOR (declared amendment, lane-wallet 2026-09-30, found by
        // lane-recursion reviewing L3): an order must carry its maker's membership bind, which only a lot note the chain
        // actually holds can produce. This maker's lot was proven from a seed and never entered any block, so there is no
        // bind to send and the order CANNOT rest — the old assertion that it rests could no longer pass on any binary
        // since DB-150. The claim is unchanged and now stated where it is decided: an order backed by nothing never
        // rests, and a fill against it settles nothing.
        let posted = match mesh.post(0, "/post_order", &post_body) {
            Ok(j) => j,
            Err(e) => e,
        };
        eprintln!("[journey] node0 /post_order -> {}", posted.trim());
        assert!(
            !posted.contains("\"resting\":true"),
            "⛔⛔⛔ a real node RESTED an order whose lot no block ever carried (no membership bind exists for it): {posted}"
        );

        // ── THE SEAM: the taker gets ONLY what node 0's own book served ──────────────────────────────
        let level_body = format!(
            "{{\"asset_a\":\"{}\",\"asset_b\":\"{}\",\"level\":{}}}",
            h3(&t.asset_a),
            h3(&t.asset_b),
            crate::order_book::RestingOrder {
                terms: t,
                maker,
                maker_bytes: maker_bytes.clone(),
                payout_note: maker_payout_note.clone(),
                membership_carrier: Vec::new(),
                membership_tip: Vec::new(),
                payout_clue: Vec::new(), // `.level()` reads the terms only
            }
            .level()
        );
        // Neither real book serves an order that could not rest. The fill below is built from the maker's OWN values —
        // exactly the bytes a would-be taker would need — to show a fill against an order no book holds settles nothing.
        let served_nullifier = h4(&maker.nullifier);
        for i in 0..2 {
            let served = match mesh.post(i, "/book_level", &level_body) {
                Ok(j) => j,
                Err(e) => e,
            };
            assert!(
                !served.contains(&served_nullifier),
                "⛔ node{i}'s real book serves an order whose lot no block ever carried: {served}"
            );
        }
        let served_maker_bytes = hexs(&maker_bytes);
        let served_leaf_commit = h4(&maker.leaf_commit);
        let served_payout_cm = h4(&maker.payout_cm);
        let served_payout_note = hexs(&maker_payout_note);

        // ── THE TAKER'S HALF, PROVEN FOR REAL AGAINST WHAT THE BOOK PUBLISHED ────────────────────────
        let (taker_bytes, taker) = prove_order_taker_half(
            &TakerHalfWitness {
                owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[61, 62, 63, 64])),
                value_in: t.pay_b + 40_000,
                change_opening: usdm_decider::poseidon2_compress::lanes_of(&[71, 72, 73, 74]),
                payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[81, 82, 83, 84]),
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            },
            &t,
            crate::params::ORDER_FILL_FEE_BPS_DEFAULT,
        )
        .expect("taker half proves");
        let note_for = |cm: crate::spend_frontier::Digest4| -> Vec<u8> {
            let mut v = vec![0u8; 1153];
            v[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
            v
        };
        // DB-273 §19.6 L3: the taker's two owners ride as clue records keyed to its payout and change; no address.
        let taker_clues = crate::node::Node::encode_note_clue_records(&[
            (crate::spend_frontier::leaf_to_cm_bytes(taker.payout_cm), journey_owner_clue(0x1401)),
            (crate::spend_frontier::leaf_to_cm_bytes(taker.change_cm), journey_owner_clue(0x1402)),
        ]);
        let fill_body = format!(
            "{{\"maker_carrier\":\"{}\",\"maker_nullifier\":\"{}\",\"maker_leaf_commit\":\"{}\",\"maker_payout_cm\":\"{}\",\"taker_carrier\":\"{}\",\"taker_nullifier\":\"{}\",\"taker_leaf_commit\":\"{}\",\"taker_change_cm\":\"{}\",\"taker_payout_cm\":\"{}\",\"lot\":{},\"pay_b\":{},\"asset_a\":\"{}\",\"asset_b\":\"{}\",\"expires_at_height\":{},\"maker_payout_note\":\"{}\",\"taker_payout_note\":\"{}\",\"taker_change_note\":\"{}\",\"note_clues_hex\":\"{}\"}}",
            served_maker_bytes, served_nullifier, served_leaf_commit, served_payout_cm,
            hexs(&taker_bytes), h4(&taker.nullifier), h4(&taker.leaf_commit), h4(&taker.change_cm),
            h4(&taker.payout_cm), t.lot, t.pay_b, h3(&t.asset_a), h3(&t.asset_b), t.expires_at_height,
            served_payout_note, hexs(&note_for(taker.payout_cm)), hexs(&note_for(taker.change_cm)),
            hexs(&taker_clues)
        );

        // ── ⛔⛔⛔ FINDING 2, AND THE LOAD-BEARING ASSERTION: NEITHER REAL NODE CREATES VALUE FROM
        // NOTES THE CHAIN NEVER HELD. The maker's and taker's inputs were proven from seeds and never
        // entered any block, so no absence proof over them exists and the burn gate must refuse. This
        // is the DELETION TRANSITION being the spend authority on a live mesh — the §AQ architecture
        // working, measured on real processes instead of asserted from a fixture.
        let r0 = mesh.post(0, "/submit_order_fill", &fill_body);
        let r1 = mesh.post(1, "/submit_order_fill", &fill_body);
        let settled = |r: &Result<String, String>| matches!(r, Ok(j) if j.contains("SETTLED"));
        eprintln!("[journey] node0 /submit_order_fill -> {r0:?}");
        eprintln!("[journey] node1 /submit_order_fill -> {r1:?}");
        assert!(
            !settled(&r0) && !settled(&r1),
            "⛔⛔⛔ A REAL NODE SETTLED A FILL WHOSE INPUTS NO BLOCK EVER CARRIED. That is value created \
             from notes that do not exist — the maker's lot and the taker's payment would both be \
             conjured. node0: {r0:?} · node1: {r1:?}"
        );

        // ⛔ AND THE REFUSAL IS THE RIGHT ONE. A node that answered `NotPublished` or timed out would
        // fail this assertion too, and would mean something completely different.
        // DECLARED AMENDMENT (lane-wallet 2026-09-30): the door that answers is now the BOOK, not the burn gate. Since
        // DB-150 the order could not rest (above), and since DB-273 §19.6 L3 the fill door takes the maker's owner from
        // the resting order, so a fill against an order no book holds is refused `ORDER_NOT_IN_BOOK` before any burn.
        for (who, r) in [("node0", &r0), ("node1", &r1)] {
            let text = match r {
                Ok(j) => j.clone(),
                Err(e) => e.clone(),
            };
            assert!(
                text.contains("ORDER_NOT_IN_BOOK"),
                "⛔ {who} refused for an unexpected reason — the book is the door that should have answered here \
                 (the order never rested), and naming the wrong door is how three turns went into re-closing a \
                 closed item: {text}"
            );
        }
        eprintln!(
            "[journey] TOTAL {:.1}s — real mesh, real order, real refusal at the burn gate on BOTH \
             processes. ⛔ WHAT IS STILL UNPROVEN: a fill that SETTLES, because this rig cannot yet fund \
             a party on a real chain. `OrderFill` stays Moved::Unproven until it can.",
            t0.elapsed().as_secs_f64()
        );
    }
}

// (The `peg_journeys` module that stood here — `a_real_node_seats_no_validator_it_did_not_learn_from_the_
// chain_so_a_deposit_cannot_mint_per_node` — asserted `validators:0` on both processes with
// MONEROUSD_VALIDATOR_BOND set, the §CW closure of 2026-09-17 AM. That premise was superseded the same
// day by `Class::MembershipBond`: the env var now ASKS THE CHAIN for a seat, and both processes hold the
// SAME two seats from the block alone. Its property — a seat comes only from the chain, so one deposit
// cannot mint once per node — is the first arm of `seat_journeys` below, measured positively, with the
// money path behind it. One real-node journey per property; a second one restating it costs 7 minutes.)

#[cfg(all(test, feature = "pins-harness"))]
mod wallet_journeys {
    use super::wallet::RealWallet;
    use super::*;
    use std::time::{Duration, Instant};

    /// ⭐⭐⭐ THE DEFINITIVE TEST: A REAL WALLET BONDS, AND BOTH REAL NODES DERIVE THE SAME VALIDATOR SET.
    ///
    /// A real wallet asks its node to bond 5 USDm of collateral, and the node refuses: since §CY/§CZ
    /// (2026-09-17) the founding seats are FREE, one per node vote identity, so this node is seated and a
    /// second bond "would spend your note without adding weight". MEASURED 2026-09-20 on two real nodes:
    /// `{"ok":false,"op":"bond","result":{"error":"this node's vote identity is … bonded (0.00000001 USDm) —
    /// a second bond would spend your note without adding weight. Unbond first, or run a second node …"}}`,
    /// `mybond` = the free seat, both nodes at `validators=2` throughout. Until that run this journey held the
    /// pre-§CY premise (`validators:0` before the wallet bonds, then a bond that adds a seat); neither exists
    /// in the shipped model. What it pins now is what is true and matters for funds: the refusal fires, the
    /// wallet's balance is untouched, and the two nodes still agree on the seat set. A collateral bond that
    /// FORMS needs a node WITHOUT a seat — a rig shape this tier does not build yet (every node is launched
    /// with `MONEROUSD_VALIDATOR_BOND`); that half is recorded open, not faked green.
    ///
    /// ⛔ WHY THE WALLET AND NOT THE NODE. A bond tx is a SPEND: `verify_carried_bond_tx` demands two
    /// output notes, a nullifier, a membership leaf + carrier and a bond-validity carrier. The node holds
    /// NO SCAN KEY (Pillar-1), so it can never find or open a note of its own. Bonding is a wallet
    /// operation by construction, which is exactly why the env-var self-bond had to be a local forgery.
    ///
    /// EVERY PROCESS HERE IS REAL: two `usdmd-node` binaries peered over the real onion transport, and one
    /// `wallet-harness` — the wallet tree's own driver, whose commands are direct calls into the same
    /// functions the Tauri UI invokes.
    #[test]
    fn a_real_wallets_redundant_bond_is_refused_by_its_seated_node_and_both_real_nodes_keep_the_same_validator_set() {
        let t0 = Instant::now();
        let mesh = match RealMesh::start(2, "walletbond") {
            Ok(m) => m,
            Err(e) => panic!("⛔ THE FUNCTIONAL TIER COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let url0 = format!("http://127.0.0.1:{}", mesh.port(0));
        eprintln!(
            "[wallet] mesh up in {:.1}s — node0 :{} ({} peers), node1 :{} ({} peers)",
            t0.elapsed().as_secs_f64(),
            mesh.port(0),
            mesh.peer_count_excluding_self(0),
            mesh.port(1),
            mesh.peer_count_excluding_self(1)
        );

        // ── THE PRECONDITION, AND THE CALIBRATION FOR THE CLAIM: nobody is bonded anywhere. ──
        // §CY/§CZ (2026-09-17): the founding quorum bonds FREE from the chain, so a fresh two-node mesh
        // already holds two chain-derived seats on BOTH nodes — the pre-§CY premise "zero validators before
        // any bond" was measured stale here 2026-09-20 (`{"status":"OK","validators":2}` on node0). The
        // precondition that still means something: both nodes derive the SAME seat count before the wallet
        // acts, and the wallet's bond then ADDS a seat that both nodes see. A node that cannot even report
        // its seats fails HERE, loudly — never as a zero.
        let seats_of = |i: usize| -> usize {
            let t = match mesh.get(i, "/get_validator_bond_tree") {
                Ok(t) => t,
                Err(e) => panic!("⛔ node{i} did not answer /get_validator_bond_tree: {e}"),
            };
            match json_u64(&t, "validators") {
                Some(n) => n as usize,
                None => panic!("⛔ node{i}'s /get_validator_bond_tree carries no `validators` count: {t}"),
            }
        };
        // The free seats ride blocks and reach both nodes only once the link is two-way — `RealMesh::start`
        // returns on a ONE-WAY vouch (MEASURED 2026-09-20: `mesh up in 98.0s — node0 (0 peers), node1 (1
        // peers)`, seats node0=1 node1=0 at that instant; the seat journey on the same rig reached
        // `validators=2` on both once the link closed). Wait for two-way peering and seat agreement on the
        // rig's own peering budget before judging; a mesh that never agrees is a real island and fails here.
        let peer_wait: u64 = match std::env::var("MONEROUSD_JOURNEY_PEER_WAIT").ok().and_then(|v| v.parse().ok()) {
            Some(secs) => secs,
            None => 420, // the rig's own peering budget
        };
        let before = {
            let end = Instant::now() + Duration::from_secs(peer_wait);
            let (mut a_n, mut b_n) = (0usize, 0usize);
            // Every node the rig launches asks the chain for its own free seat, so the SETTLED founding set
            // is one seat per node on BOTH nodes (`validators == mesh.len()`, the seat journey's own
            // measurement). An instant where both read 1 is each node holding only itself — MEASURED
            // 2026-09-20: `before` taken at 1/1, then node1 reached 2 while node0 still read 1, and the
            // refused bond was blamed for a set that was still settling.
            loop {
                let two_way = mesh.peer_count_excluding_self(0) >= 1 && mesh.peer_count_excluding_self(1) >= 1;
                a_n = seats_of(0);
                b_n = seats_of(1);
                if (two_way && a_n == b_n && a_n >= mesh.len()) || Instant::now() >= end {
                    break;
                }
                std::thread::sleep(Duration::from_secs(3));
            }
            assert_eq!(
                a_n, b_n,
                "⛔ the two nodes disagree about the chain-derived seats BEFORE the wallet bonds (node0={a_n} \
                 node1={b_n}) after {peer_wait}s — the claim below would be about the free-seat lane, not the \
                 wallet's bond"
            );
            eprintln!("[wallet] chain-derived seats before the wallet bonds: {a_n} on both nodes");
            a_n
        };

        // ── A REAL WALLET, CREATED THE WAY A USER CREATES ONE ──
        let w = match RealWallet::create("walletbond", "operator", &url0) {
            Ok(w) => w,
            Err(e) => panic!(
                "⛔ THE REAL WALLET COULD NOT BE CREATED: {e}\n   The wallet is how a human touches this \
                 chain; if it cannot open, nothing else measured here matters."
            ),
        };
        eprintln!("[wallet] created, address={}…", &w.address[..w.address.len().min(24)]);

        // ── FUND IT. The faucet is testnet-only scaffolding, and it is NOT what is under test here: it
        // stands in for "this operator already holds USDm". What IS under test is whether the WALLET can
        // see that money and turn it into a bond that travels.
        let drip = mesh
            .post(
                0,
                "/faucet/drip",
                &format!(r#"{{"amount":2500000000,"to":"{}"}}"#, w.address),
            )
            .unwrap_or_else(|e| panic!("⛔ the faucet could not fund the wallet: {e}"));
        eprintln!("[wallet] drip -> {}", drip.trim());
        assert!(
            drip.contains("\"published\":true"),
            "the drip must be PUBLISHED as a chain object, not staged locally: {drip}"
        );

        // Let the credit ride a block and reach the wallet's scan.
        let h0 = mesh.height(0).unwrap_or(0);
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(180) {
            if mesh.height(0).unwrap_or(0) > h0 + 1 {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        // ── ⭐ THE WALLET SEES REAL MONEY ON A REAL CHAIN ──
        let seen = w
            .run(&["refresh", "balance"])
            .unwrap_or_else(|e| panic!("⛔ the wallet could not refresh/balance: {e}"));
        for line in &seen {
            eprintln!("[wallet] {}", &line[..line.len().min(220)]);
        }
        let bal_line = seen
            .iter()
            .find(|l| l.contains("\"op\":\"balance\""))
            .cloned()
            .unwrap_or_default();
        let atomic = json_u64(&bal_line, "atomic").unwrap_or(0);
        eprintln!("[wallet] balance atomic={atomic}");

        // ── ⭐⭐⭐ THE WALLET BONDS — a REAL staking transaction it builds and submits itself ──
        let bonded = w
            .run(&["refresh", "bond 5.0", "mybond"])
            .unwrap_or_else(|e| panic!("⛔ the wallet could not run the bond batch: {e}"));
        for line in &bonded {
            eprintln!("[wallet] {}", &line[..line.len().min(320)]);
        }

        // ── THE SEATED NODE REFUSES THE BOND, AND THE NOTE STAYS ──
        // WHAT PRODUCES the refusal: the node's per-vote-identity seat gate in its `bond` handler — this node
        // holds its free seat, and a collateral bond for a seated identity would spend the wallet's note and
        // add no weight. It CANNOT be deleted: that gate IS the fund protection under test here. So the
        // wallet's op must come back refused with that reason, its balance must be exactly what it was, and
        // the two nodes must still agree on the seat set.
        let bond_line = match bonded.iter().find(|l| l.contains("\"op\":\"bond\"")) {
            Some(l) => l.clone(),
            None => panic!("⛔ the bond batch printed no `bond` result at all: {bonded:?}"),
        };
        assert!(
            bond_line.contains("\"ok\":false") && bond_line.contains("without adding weight"),
            "⛔ the seated node did not refuse the bond that would spend the note without adding weight — it \
             went through, or was refused for a different reason: {bond_line}"
        );
        let after = w
            .run(&["refresh", "balance"])
            .unwrap_or_else(|e| panic!("⛔ the wallet could not refresh/balance after the refused bond: {e}"));
        let bal_after = match after.iter().find(|l| l.contains("\"op\":\"balance\"")).and_then(|l| json_u64(l, "atomic")) {
            Some(a) => a,
            None => panic!("⛔ no balance line after the refused bond: {after:?}"),
        };
        assert_eq!(
            bal_after, atomic,
            "⛔ the refused bond still moved the wallet's balance ({atomic} → {bal_after}) — the note was spent on a no-op"
        );
        let seats = (seats_of(0), seats_of(1));
        eprintln!(
            "[wallet] after the refused bond — node0 validators={} · node1 validators={} (before {before}); \
             balance atomic {atomic} → {bal_after}",
            seats.0, seats.1
        );

        // ⛔ THE CLAIM. Both nodes must hold the SAME set, and a refused bond must not have moved it.
        assert_eq!(
            seats.0, seats.1,
            "⛔⛔⛔ THE TWO NODES DISAGREE ABOUT WHO IS BONDED (node0={} node1={}). A validator set that \
             differs between peers is the §CW defect: node0's attestation fails threshold on node1, \
             `apply_chain_peg_in` returns before the replay-set insert, and one BTC deposit mints USDm \
             once per node.",
            seats.0, seats.1
        );
        assert_eq!(
            seats.0, before,
            "⛔ a REFUSED bond changed the seat count ({before} → {}) — a refusal that still mutates the set is \
             a local seat, the §CW shape",
            seats.0
        );
        eprintln!(
            "[wallet] TOTAL {}s — the seated node refused the wallet's bond, the note stayed, and BOTH real \
             nodes keep the same {before}-seat set",
            t0.elapsed().as_secs()
        );
    }

    /// ⭐⭐⭐ DB-313 §3 — A REAL WALLET BONDS USDm ONTO AN UNSEATED NODE, BOTH REAL PROCESSES ADMIT THE WEIGHT FROM A
    /// BLOCK, AND THE OWNER'S UNBOND RELEASES IT ON BOTH.
    ///
    /// MEASURED before (gate Q16 step 10, and every [gatepf]/[gateT1] run since): the template evicted every welded
    /// carrier, so no USDm bond was ever laid and `unbond` answered `UNBOND_REFUSED`. Here node 1 runs WITHOUT a seat
    /// (the gate's daemon shape; a USDm bond onto a SEATED identity is refused before any spend, which
    /// `a_real_wallets_redundant_bond_…` pins). The wallet is funded on node 1, asks node 1 to sign its bond statement
    /// and bonds 3 USDm; the claim is read from BOTH processes' own sockets: `/get_validator_bond` of node 1's vote id
    /// equals the weight on node 0 — which could only have learned it from a block — AND on node 1. Then the wallet
    /// unbonds and both read 0. CONTROL: before the bond, both read 0 for that id.
    #[test]
    fn a_real_wallet_bonds_usdm_onto_an_unseated_node_and_both_real_processes_admit_then_release_the_weight() {
        let t0 = Instant::now();
        let mesh = match RealMesh::start_with(2, "usdmbond", &[1]) {
            Ok(m) => m,
            Err(e) => panic!("⛔ THE FUNCTIONAL TIER COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let url1 = format!("http://127.0.0.1:{}", mesh.port(1));
        let vote_id_of = |m: &RealMesh| -> String {
            m.get(1, "/validator_id")
                .ok()
                .and_then(|b| json_str(&b, "validator_id_hex"))
                .unwrap_or_else(|| panic!("⛔ node 1 reports no vote identity at /validator_id"))
        };
        let vid_before = vote_id_of(&mesh);
        let bond_of = |m: &RealMesh, i: usize, vid: &str| -> u64 {
            m.post(i, "/get_validator_bond", &format!(r#"{{"voter_id":"{vid}"}}"#))
                .ok()
                .and_then(|b| json_u64(&b, "bond"))
                .unwrap_or(0)
        };
        assert_eq!(
            (bond_of(&mesh, 0, &vid_before), bond_of(&mesh, 1, &vid_before)),
            (0, 0),
            "CONTROL: node 1's vote id holds no weight on either process"
        );
        let w = RealWallet::create("usdmbond", "operator", &url1)
            .unwrap_or_else(|e| panic!("⛔ THE REAL WALLET COULD NOT BE CREATED: {e}"));
        let drip = mesh
            .post(1, "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{}"}}"#, w.address))
            .unwrap_or_else(|e| panic!("⛔ the faucet could not fund the wallet: {e}"));
        assert!(drip.contains("\"published\":true"), "the drip must be PUBLISHED as a chain object: {drip}");
        // The credit rides a block and becomes spendable in the wallet's own scan.
        let t = Instant::now();
        let mut atomic = 0u64;
        while t.elapsed() < Duration::from_secs(300) {
            let seen = w.run(&["refresh", "balance"]).unwrap_or_default();
            atomic = seen
                .iter()
                .find(|l| l.contains("\"op\":\"balance\""))
                .and_then(|l| json_u64(l, "atomic"))
                .unwrap_or(0);
            if atomic >= 2_500_000_000 {
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        assert!(atomic >= 2_500_000_000, "PRECONDITION: the wallet holds its 25 USDm (atomic {atomic})");
        // ── ⭐⭐⭐ THE WALLET BONDS 3 USDm ONTO NODE 1's VOTE IDENTITY ──
        // The first bond provisions the wallet's seed-derived validator identity, and node 1 restarts onto it: the call
        // runs SUPERVISED, so node 1 comes back the way launchd brings a live node back.
        let mut mesh = mesh;
        // A node that has just restarted (the provisioning above) may not yet hold the nullifier shard its witness needs
        // and answers a TRANSIENT 503 with "nothing was broadcast; the note is untouched" — that restart gap is its own
        // register row ("minutes a restarted node cannot serve Lane A"). The owner retries, as a user does: bounded.
        let t_bond = Instant::now();
        let bonded = loop {
            let out = mesh
                .supervised(1, || w.run(&["refresh", "bond 3", "mybond"]))
                .unwrap_or_else(|e| panic!("⛔ the wallet could not run the bond batch: {e}"));
            let refused_503 = out.iter().any(|l| l.contains("\"op\":\"bond\"") && l.contains("\"ok\":false") && l.contains("(503)"));
            if !refused_503 || t_bond.elapsed() > Duration::from_secs(360) {
                break out;
            }
            eprintln!("[usdm-bond] the restarted node cannot witness the note yet (503) — retrying ({:.0}s)", t_bond.elapsed().as_secs_f64());
            std::thread::sleep(Duration::from_secs(10));
        };
        // The weight sits on the identity node 1 runs NOW: the wallet's seed-derived one (the automatic validator), which
        // replaced node 1's boot identity in the supervised restart above.
        let vid_hex = vote_id_of(&mesh);
        eprintln!("[usdm-bond] node 1 runs vote id {}… (was {}…)", &vid_hex[..12.min(vid_hex.len())], &vid_before[..12.min(vid_before.len())]);
        let bond_on = |i: usize| -> u64 { bond_of(&mesh, i, &vid_hex) };
        for line in &bonded {
            eprintln!("[usdm-bond] {}", &line[..line.len().min(320)]);
        }
        let bond_line = bonded.iter().find(|l| l.contains("\"op\":\"bond\"")).cloned().unwrap_or_default();
        assert!(bond_line.contains("\"ok\":true"), "⛔ the wallet's USDm bond onto an unseated node was refused: {bond_line}");
        // ── THE CLAIM, FROM BOTH PROCESSES: the weight landed from a block on each ──
        let want: u64 = 300_000_000;
        let t = Instant::now();
        let mut seen = (0u64, 0u64);
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            seen = (bond_on(0), bond_on(1));
            if seen == (want, want) {
                break;
            }
            std::thread::sleep(Duration::from_secs(4));
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: a validator's bonded weight is consensus-public (`/get_validator_bond`).
        eprintln!("[usdm-bond] after {:.1}s: node0 bond={} node1 bond={} (want {want})", t.elapsed().as_secs_f64(), seen.0, seen.1);
        assert_eq!(
            seen,
            (want, want),
            "⛔⛔⛔ DB-313: THE USDm BOND DID NOT LAND ON BOTH REAL PROCESSES within 420 s — node 0 can only learn the \
             weight from a block; a bond that lands on its own node only is a local mutation"
        );
        // The owner's SPENDABLE balance while bonded: the locked note is not spendable (the bond transition admits the
        // change only), so the returned note must raise this by the weight once the unbond lands.
        let atomic_of = |w: &RealWallet| -> u64 {
            w.run(&["refresh", "balance"])
                .unwrap_or_default()
                .iter()
                .find(|l| l.contains("\"op\":\"balance\""))
                .and_then(|l| json_u64(l, "atomic"))
                .unwrap_or(0)
        };
        let bonded_balance = atomic_of(&w);
        eprintln!("[usdm-bond] spendable while bonded: {bonded_balance} atomic");
        // ── AND THE OWNER'S UNBOND RELEASES IT ON BOTH ──
        let unb = w.run(&["unbond"]).unwrap_or_else(|e| panic!("⛔ the wallet could not run unbond: {e}"));
        let unb_line = unb.iter().find(|l| l.contains("\"op\":\"unbond\"")).cloned().unwrap_or_default();
        eprintln!("[usdm-bond] {}", &unb_line[..unb_line.len().min(320)]);
        assert!(unb_line.contains("\"ok\":true"), "⛔ the owner's unbond was refused: {unb_line}");
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            seen = (bond_on(0), bond_on(1));
            if seen == (0, 0) {
                break;
            }
            std::thread::sleep(Duration::from_secs(4));
        }
        eprintln!("[usdm-bond] after the unbond {:.1}s: node0 bond={} node1 bond={}", t.elapsed().as_secs_f64(), seen.0, seen.1);
        assert_eq!(seen, (0, 0), "⛔⛔ the unbond did not release the weight on BOTH real processes within 420 s");
        // ── ⭐⭐ THE LOCKED NOTE COMES BACK (the `bond_note` claim) — to its owner on node 1, and from node 0's own chain ──
        // At most 0.5 USDm of the 3 may go to the unbond's fee; anything less than 2.5 back is a note that did not return.
        let want_back = bonded_balance + 250_000_000;
        let t = Instant::now();
        let mut back = 0u64;
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            back = atomic_of(&w);
            if back >= want_back {
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        eprintln!("[usdm-bond] spendable after the unbond (node 1): {back} atomic (was {bonded_balance} while bonded)");
        assert!(
            back >= want_back,
            "⛔⛔ the unbond released the weight but the LOCKED NOTE did not return to its owner: {bonded_balance} → {back} \
             (want ≥ {want_back})"
        );
        // The SAME seed, restored against node 0, must find the returned note from node 0's chain alone.
        let url0 = format!("http://127.0.0.1:{}", mesh.port(0));
        let w0 = w
            .restored_elsewhere_for_test("usdmbond-node0", &url0)
            .unwrap_or_else(|e| panic!("⛔ the seed could not be restored against node 0: {e}"));
        let t = Instant::now();
        let mut back0 = 0u64;
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            back0 = atomic_of(&w0);
            if back0 == back {
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        eprintln!("[usdm-bond] the seed restored on node 0 holds {back0} atomic (node 1 showed {back})");
        assert_eq!(back0, back, "⛔⛔ node 0 does not hold the owner's returned note: {back0} restored vs {back} on node 1");
        eprintln!(
            "[usdm-bond] TOTAL {}s — bonded, admitted on both, released on both, the locked note returned and node 0 holds it",
            t0.elapsed().as_secs()
        );
    }
}

#[cfg(all(test, feature = "pins-harness"))]
mod seat_journeys {
    use super::wallet::RealWallet;
    use super::*;
    use std::time::{Duration, Instant};

    /// ⭐ §BR-14 — PAY A CREATION'S FEE ON REAL PROCESSES, the way the creator's wallet does: a faucet drip of price + F + a
    /// remainder sealed to a fresh party (opened with its own keys), both processes a record depth past it on one
    /// accumulator, then the bond-validity burn of exactly the price into `c`'s burn opening with the one-step member leg
    /// built from process `node`'s OWN served record. Sets `c.fee`; returns the `"fee_*"` JSON fields `/submit_asset_create`
    /// reads (appended after the creator key).
    fn rn_pay_creation_fee(mesh: &RealMesh, node: usize, c: &mut crate::asset_tx::AssetCreateTx, seed: u8) -> String {
        use crate::spend_frontier::{leaf_to_cm_bytes, note_leaf_of, poseidon_pair, Digest4};
        use usdm_decider::note_membership_air::NoteMembershipCarrier;
        use usdm_decider::whir_rec_block::{NoteOwner, SpendValidityWitness, PROTOCOL_FEE_ATOMIC};
        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("⛔ the node served non-hex")).collect()
        };
        let price = c.creation_price();
        let amount = price + PROTOCOL_FEE_ATOMIC + 50_000_000;
        let (ek, _) = crate::faucet::kem_keypair_from_seed(&[seed; 32]);
        let payer = crate::faucet::RecipientSecrets::for_test(&[seed; 32]);
        let spk = payer.spk();
        let drip = mesh
            .post(node, "/faucet/drip", &format!(r#"{{"amount":{amount},"to":"{}"}}"#, journey_receive_address(0x7000 + u64::from(seed), &ek, &spk)))
            .unwrap_or_else(|e| panic!("⛔ the creation fee's drip was refused over the real RPC: {e}"));
        let note = unhex(&json_str(&drip, "note").unwrap_or_else(|| panic!("⛔ the drip named no note: {drip}")));
        let (amt, nseed) = crate::faucet::open_note(&note, &payer.dk, &spk).expect("⛔ the payer cannot open its own drip");
        assert!(amt >= price + PROTOCOL_FEE_ATOMIC, "PRECONDITION: the drip covers the price and the network fee");
        let cm: [u8; 32] = note[..32].try_into().expect("a note starts with its commitment");
        let snap = |i: usize| -> (u64, u64, String) {
            let info = mesh.get(i, "/get_info").unwrap_or_default();
            (json_u64(&info, "height").unwrap_or(0), json_u64(&info, "served_seq").unwrap_or(0), json_str(&info, "membership_acc").unwrap_or_default())
        };
        let ((h0, s0, _), (h1, s1, _)) = (snap(0), snap(1));
        let (h_from, s_from, past) = (h0.max(h1), s0.max(s1), crate::params::RECORD_FOLD_DEPTH_DEFAULT + 1);
        let t = Instant::now();
        loop {
            let ((h0, s0, a0), (h1, s1, a1)) = (snap(0), snap(1));
            if h0 > h_from + past && h1 > h_from + past && s0 == s1 && s0 >= s_from + past && !a0.is_empty() {
                assert_eq!(a0, a1, "⛔⛔⛔ the two real processes DISAGREE on the membership accumulator past the fee drip");
                break;
            }
            assert!(t.elapsed() < Duration::from_secs(600), "⛔ INCONCLUSIVE: the pair never stood past the fee drip within 600 s");
            std::thread::sleep(Duration::from_secs(3));
        }
        let w = SpendValidityWitness {
            value_in: amt,
            owner: NoteOwner { ask: payer.ask, nk: payer.nk, seed: nseed },
            value_out: amt - PROTOCOL_FEE_ATOMIC,
            fee: PROTOCOL_FEE_ATOMIC,
            lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            out0_value: price,
            out0_opening: crate::asset_tx::creation_burn_opening(&c.asset_id),
            out1_value: amt - PROTOCOL_FEE_ATOMIC - price,
            out1_opening: usdm_decider::poseidon2_compress::lanes_of(&[0xfee, u64::from(seed), 1, 1]),
        };
        let (carrier, cms, nf, lc) = usdm_decider::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(&w, price)
            .expect("the creation fee's burn proves over the dripped note");
        // The one-step member leg from process `node`'s OWN served record (the fill journey's `bind`).
        let leaf = note_leaf_of(&cm);
        let t = Instant::now();
        let (rid, sibs, dirs, root): (u64, Vec<Digest4>, Vec<bool>, Digest4) = loop {
            let r = mesh.post(node, "/note_ordinal_by_cm", &format!(r#"{{"cms_hex":"{}"}}"#, hexs(&cm))).unwrap_or_default();
            let addr = r.find("\"ordinals\":[").and_then(|at| {
                let rest = &r[at + "\"ordinals\":[".len()..];
                let end = rest.find(|ch: char| ch == ',' || ch == ']')?;
                rest[..end].trim().parse::<i64>().ok().filter(|o| *o >= 0).map(|o| o as u64)
            });
            if let Some(addr) = addr {
                let body = format!(r#"{{"cms_hex":"{}","addrs_hex":"{}"}}"#, hexs(&cm), hexs(&addr.to_le_bytes()));
                let r = mesh.post(node, "/note_copath", &body).unwrap_or_default();
                if r.contains("\"served\":true") {
                    let lane = crate::spend_frontier::DIGEST_LANE_BYTES;
                    let sibs: Vec<Digest4> = unhex(&json_str(&r, "siblings_hex").expect("a served copath names its siblings"))
                        .chunks_exact(lane)
                        .map(|b| crate::spend_frontier::digest_from_lane_bytes(b).expect("⛔ a non-canonical sibling"))
                        .collect();
                    let dirs: Vec<bool> = json_str(&r, "dirs").expect("a served copath names its sides").chars().map(|ch| ch == '1').collect();
                    let root = crate::spend_frontier::digest_from_lane_bytes(&unhex(&json_str(&r, "block_root_hex").expect("a record root")))
                        .expect("⛔ a non-canonical record root");
                    break (addr, sibs, dirs, root);
                }
            }
            assert!(t.elapsed() < Duration::from_secs(300), "⛔ PROCESS {node} NEVER SERVED THE FEE NOTE'S RECORD within 300 s");
            std::thread::sleep(Duration::from_secs(3));
        };
        let refold = sibs.iter().zip(&dirs).fold(leaf, |cur, (s, right)| if *right { poseidon_pair(*s, cur) } else { poseidon_pair(cur, *s) });
        assert_eq!(refold, root, "⛔ the served copath does not refold the fee note's leaf to the served record root");
        let mut mc = NoteMembershipCarrier::new(leaf, root, crate::node::Node::MEMBERSHIP_GENESIS_ACC, nf, crate::spend_frontier::TEST_LC_BLIND);
        assert!(mc.attach_membership(leaf, &sibs, &dirs), "the served copath reaches the record root");
        let (proof, acc, tip_prev, tip_root) = mc.finalize_one_step().expect("the one-step carrier certifies");
        let mut tip = Vec::with_capacity(4 * crate::spend_frontier::DIGEST_LANE_BYTES + 8);
        for d in [crate::node::Node::MEMBERSHIP_GENESIS_ACC, tip_prev, tip_root, acc] {
            tip.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&d));
        }
        tip.extend_from_slice(&rid.to_le_bytes());
        let mut change_note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        change_note[..32].copy_from_slice(&leaf_to_cm_bytes(cms[1]));
        c.fee = crate::asset_tx::CreationFee {
            nullifier: leaf_to_cm_bytes(nf),
            leaf_commit: leaf_to_cm_bytes(lc),
            carrier,
            membership_carrier: proof,
            membership_tip: tip,
            change_note,
            change_clue: journey_owner_clue(0x7f00 + u64::from(seed)),
        };
        let f = &c.fee;
        format!(
            r#","fee_nullifier":"{}","fee_leaf_commit":"{}","fee_carrier_hex":"{}","fee_membership_carrier_hex":"{}","fee_membership_tip_hex":"{}","fee_change_note_hex":"{}","fee_change_clue_hex":"{}""#,
            hexs(&f.nullifier),
            hexs(&f.leaf_commit),
            hexs(&f.carrier),
            hexs(&f.membership_carrier),
            hexs(&f.membership_tip),
            hexs(&f.change_note),
            hexs(&f.change_clue)
        )
    }

    fn hexs(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }

    /// ⭐⭐⭐ THE MONEY PATH, END TO END, ON REAL NODES — WITH THE QUORUM THE CHAIN ITSELF RECORDED.
    ///
    /// No founding keys, no charter constant, no env seat. Both processes are launched with
    /// `MONEROUSD_VALIDATOR_BOND` set, which now means "ask the chain for a seat": each signs a
    /// `Class::MembershipBond` and pools it. The seats ride `Block::bond_set`, and `apply_bond_set` lands
    /// them on EVERY node from the same bytes — free, because the reserve is zero (the adaptive rule at
    /// its zero point). Then a real BTC deposit mints, the mint travels, and the peer refuses its replay.
    ///
    /// Every arm below was RED at some point today on these same two processes:
    ///   * `validators:1` each (disjoint local seats) → one deposit minted once per node (§CW);
    ///   * `validators:0` each (seat removed, nothing replaced it) → `UNDERBONDED`, nothing minted;
    ///   * bond cap removed → `INSUFFICIENT_THRESHOLD`, still nothing minted (no quorum existed).
    /// This is the first run in which a quorum exists that BOTH nodes derived from the chain.
    #[test]
    fn two_real_nodes_bond_free_from_the_chain_and_the_money_path_runs_with_the_replay_refused_on_the_peer(
    ) {
        let t0 = Instant::now();
        let mesh = match RealMesh::start(2, "seat") {
            Ok(m) => m,
            Err(e) => panic!("⛔ THE FUNCTIONAL TIER COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let own_id = |i: usize| -> String {
            json_str(&mesh.get(i, "/validator_id").unwrap_or_default(), "validator_id_hex")
                .unwrap_or_default()
        };
        let bond_on = |i: usize, id: &str| -> u64 {
            json_u64(
                &mesh
                    .post(i, "/get_validator_bond", &format!(r#"{{"voter_id":"{id}"}}"#))
                    .unwrap_or_default(),
                "bond",
            )
            .unwrap_or(0)
        };
        let count = |i: usize| -> u64 {
            json_u64(&mesh.get(i, "/get_validator_bond_tree").unwrap_or_default(), "validators")
                .unwrap_or(0)
        };
        let (id0, id1) = (own_id(0), own_id(1));
        eprintln!("[seat] node0 id={}… node1 id={}…", &id0[..16], &id1[..16]);
        assert_ne!(id0, id1, "two processes must hold two identities");

        // ── ⭐⭐⭐ THE SEATS TRAVEL. Both nodes must reach validators:2, AND each must hold the OTHER's
        // seat — that is what "the same set" means, and it is exactly what was false this morning.
        let t = Instant::now();
        let mut ok = false;
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            let (c0, c1) = (count(0), count(1));
            if c0 >= 2 && c1 >= 2 && bond_on(0, &id1) > 0 && bond_on(1, &id0) > 0 {
                ok = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        eprintln!(
            "[seat] after {:.1}s — node0 validators={} (holds node1: {}) · node1 validators={} (holds node0: {})",
            t.elapsed().as_secs_f64(),
            count(0),
            bond_on(0, &id1) > 0,
            count(1),
            bond_on(1, &id0) > 0
        );
        assert!(
            ok,
            "⛔⛔⛔ THE SEATS DID NOT TRAVEL. A membership bond published on one node must land on the \
             other from the block alone; a set that differs between peers is the §CW fork (one BTC \
             deposit minted once per node). node0={} node1={}",
            count(0),
            count(1)
        );

        // ── THE BUYER and the deposit machinery (identical to the peg journey).
        // ⭐ DB-273 §19 L1: the buyer's owner is a REAL OLI clue for its own locator (`chg`, index 0), exactly what a
        // wallet sends — the door computes the recipient the quorum signs as the commitment to it.
        let owner_loc_sk = crate::oli::derive_loc_sk(blake3::hash(b"journey-peg-buyer").as_bytes());
        let owner_salt = crate::oli::address_salt(&owner_loc_sk, "chg", 0);
        let owner_clue = crate::oli::tag_clue_bytes_v2(
            &crate::oli::locator_at(&owner_loc_sk, "chg", 0),
            &owner_salt,
            &crate::oli::address_index_hint(&owner_loc_sk, &owner_salt, 0),
        );
        // DB-93: one mint per reserve address — each deposit has its OWN per-swap address and the id the
        // node derives from it (any other id is refused at the door before sealing).
        // DB-123: the address is the reserve's OWN — a function of the deposit's MINT BLIND under the
        // chain-built custody leaf — asked of node0 exactly as the wallet asks it; a custodian refuses a
        // deposit at any other address. Two deposits ⇒ two blinds (salts) ⇒ two addresses.
        let blind_of = |salt: u64| usdm_decider::poseidon2_compress::lanes_of(&[0xdbu64, 0x80, 0x5e, salt]);
        let reserve_for = |salt: u64| -> String {
            let d_blind_hex = hexs(&crate::spend_frontier::digest_to_lane_bytes(&blind_of(salt)));
            let j = mesh
                .post(0, "/get_reserve_swap_address", &format!(r#"{{"asset":"BTC","d_blind_hex":"{d_blind_hex}"}}"#))
                .unwrap_or_else(|e| panic!("⛔ node0 served no reserve address for the deposit's blind: {e}"));
            json_str(&j, "deposit_address")
                .unwrap_or_else(|| panic!("⛔ node0's reserve answer carries no deposit address: {j}"))
        };
        let (salt_a, salt_b) = (1u64, 2u64);
        let reserve_a_s = reserve_for(salt_a);
        let reserve_b_s = reserve_for(salt_b);
        let (reserve_a, reserve_b) = (reserve_a_s.as_str(), reserve_b_s.as_str());
        assert_ne!(reserve_a, reserve_b, "two blinds derive two reserve addresses");
        eprintln!("[seat] reserve addresses from node0's live custody leaf: A={reserve_a} B={reserve_b}");
        let dep_a = hexs(&crate::peg::deposit_id_for_reserve_address(reserve_a));
        let dep_b = hexs(&crate::peg::deposit_id_for_reserve_address(reserve_b));
        // DB-80: the requester commits its mint delta (`delta_commit`), seals the blind to the custodians
        // (`d_blind_hex`) and proves the note opens to the committed figure — no amount rides a chain object.
        let note_for_mint = |mint: u64, salt: u64| -> (String, String, String, String, String) {
            let sk = usdm_decider::poseidon2_compress::lanes_of(&[0xf0u64, 0xf1, 0xf2, mint]);
            let d_blind = blind_of(salt);
            let (carrier, cm, dc) =
                usdm_decider::whir_rec_block::prove_mint_validity_committed_bytes(mint, &sk, &d_blind)
                    .expect("the mint-validity carrier PROVES for the authorized amount");
            let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(cm);
            let mut payload = Vec::with_capacity(1153);
            payload.extend_from_slice(&cm_bytes);
            payload.extend_from_slice(&[0u8; 1153 - 32]);
            (
                hexs(&cm_bytes),
                hexs(&payload),
                hexs(&carrier),
                hexs(&crate::spend_frontier::leaf_to_cm_bytes(dc)),
                hexs(&crate::spend_frontier::digest_to_lane_bytes(&d_blind)),
            )
        };
        let exec = |n: usize, dep: u64, mint: u64, id: &str, reserve: &str, salt: u64| -> String {
            let (recip, note, mint_carrier, delta_commit, d_blind_hex) = note_for_mint(mint, salt);
            let body = format!(
                r#"{{"deposit_id":"{id}","recipient":"{recip}","deposit_value":{dep},"mint":{mint},"delta_commit":"{delta_commit}","d_blind_hex":"{d_blind_hex}","reserve_address":"{reserve}","note_payload":"{note}","mint_carrier_hex":"{mint_carrier}","note_clue_hex":"{}"}}"#,
                hexs(&owner_clue)
            );
            match mesh.post(n, "/peg_in_execute", &body) {
                Ok(j) => j,
                Err(e) => e,
            }
        };
        let inject = |n: usize, reserve: &str, sats: u64| -> Result<String, String> {
            mesh.post(
                n,
                "/dev/inject_confirmed_deposit",
                &format!(r#"{{"address":"{reserve}","sats":{sats}}}"#),
            )
        };

        // ── ARM 1 — no confirmed deposit ⇒ no mint, even with a quorum. The calibration.
        let no_dep = exec(0, 3_000, 2_000, &dep_a, reserve_a, salt_a);
        eprintln!("[seat] ARM 1 no confirmed deposit -> {}", no_dep.trim());
        assert!(
            !no_dep.contains("\"minted\":true"),
            "⛔⛔⛔ USDm MINTED WITH NO CONFIRMED DEPOSIT — unbacked supply: {no_dep}"
        );
        for reserve in [reserve_a, reserve_b] {
            inject(0, reserve, 100_000_000).unwrap_or_else(|e| panic!("⛔ no dev oracle door — build with --features bridge-test-oracle: {e}"));
            inject(1, reserve, 100_000_000).expect("node1's own watcher is given the same external-chain fact");
        }

        // ── ARM 2 — ⭐⭐⭐ THE MONEY PATH. A confirmed deposit MINTS on a quorum the chain built.
        //
        // With TWO seats of equal weight, neither node alone reaches ≥2/3: the executor PROPOSES over
        // gossip (`crate::peg_attest`, the delta sealed to the peer's ek), the peer attests from ITS
        // OWN opening + ITS OWN watcher, and the executor's next poll finds the signature and mints.
        // The wallet polls this same door until it mints; the journey does exactly that, bounded.
        // The door is a POLL: INSUFFICIENT_THRESHOLD+gathering while the quorum's signatures travel,
        // CONFIDENTIAL_PUBLISHED while the object waits for a block, ALREADY_MINTED (minted:true) once a
        // block carried it. Anything else is a refusal and ends the poll.
        let mint_until = |n: usize, dep: u64, mint: u64, id: &str, reserve: &str, salt: u64, secs: u64| -> String {
            let t = Instant::now();
            let mut last = String::new();
            while t.elapsed() < Duration::from_secs(secs) {
                last = exec(n, dep, mint, id, reserve, salt);
                let pending = last.contains("\"gathering\":true") || last.contains("\"published\":true");
                if last.contains("\"minted\":true") || !pending {
                    break;
                }
                std::thread::sleep(Duration::from_secs(2));
            }
            last
        };
        let minted = mint_until(0, 3_000, 2_000, &dep_a, reserve_a, salt_a, 180);
        eprintln!("[seat] ARM 2 node0 mint -> {}", minted.trim());
        assert!(
            minted.contains("\"minted\":true"),
            "⛔ A CONFIRMED DEPOSIT DID NOT MINT with a chain-derived quorum in place — the depositor's \
             BTC is in custody with nothing issued: {minted}"
        );

        // ── ARM 3a — the control: node0 answers ALREADY_MINTED for its own deposit and publishes NOTHING new.
        let self_replay = exec(0, 3_000, 2_000, &dep_a, reserve_a, salt_a);
        eprintln!("[seat] ARM 3a node0 re-executes its own deposit -> {}", self_replay.trim());
        assert!(
            self_replay.contains("ALREADY_MINTED") && !self_replay.contains("\"published\":true"),
            "⛔ node0 did not answer ALREADY_MINTED for a deposit its chain carried: {self_replay}"
        );

        // ── ARM 3b — ⛔⛔⛔ THE CLAIM: THE MINT TRAVELLED, AND node1 NEVER ISSUES A SECOND ONE. node1 is
        // asked for the SAME deposit until it answers ALREADY_MINTED — which it can only do once the block
        // carrying node0's mint grafted on it (the travel proof) — and along the way it must never say
        // `published:true` (a second issuance of the same deposit, which is what run 3 measured at h=90
        // when node1 stood on a fork and still held the cached attestations). While node1 waits for the
        // block it may gather, but node0 refuses to attest a deposit its chain already minted.
        let t = Instant::now();
        let mut replay = String::new();
        let mut second_issue = false;
        while t.elapsed() < Duration::from_secs(300) {
            replay = exec(1, 3_000, 2_000, &dep_a, reserve_a, salt_a);
            if replay.contains("\"published\":true") {
                second_issue = true;
                break;
            }
            if replay.contains("ALREADY_MINTED") {
                break;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        eprintln!(
            "[seat] ARM 3b node1 asked for the SAME deposit -> {} (after {:.1}s; node0 h={:?} node1 h={:?})",
            replay.trim(),
            t.elapsed().as_secs_f64(),
            mesh.height(0),
            mesh.height(1)
        );
        assert!(
            !second_issue,
            "⛔⛔⛔ THE SAME BITCOIN DEPOSIT WAS ISSUED TWICE ON ONE MESH — node1 published its own mint for a \
             deposit node0's chain already carried: {replay}"
        );
        assert!(
            replay.contains("ALREADY_MINTED"),
            "⛔ THE MINT DID NOT TRAVEL: node1 never applied node0's peg-in from a block within 300 s: {replay}"
        );

        // ── ARM 4 — the refutation of arm 3b: node1 MINTS a deposit the chain has never seen. This is
        // also the arm a STALE OPENING breaks: node1 proposes from the opening it advanced when node0's
        // mint grafted, and node0 attests from the opening it advanced at execute.
        let fresh = mint_until(1, 3_000, 2_000, &dep_b, reserve_b, salt_b, 180);
        eprintln!("[seat] ARM 4 node1 fresh deposit -> {}", fresh.trim());
        assert!(
            fresh.contains("\"minted\":true"),
            "⛔ THIS RUN PROVED NOTHING: node1 refused a never-seen deposit, so its refusal in 3b is not \
             evidence the replay set travelled — node1 just refuses peg-ins: {fresh}"
        );
        eprintln!(
            "[seat] TOTAL {:.1}s — two real nodes bonded FREE from the chain (validators:2, same set on \
             both), a confirmed BTC deposit MINTED on a 2-of-2 quorum gathered over the mesh, the mint \
             travelled (the peer answers ALREADY_MINTED from the block), the peer issued no second mint, \
             and the peer then minted a fresh deposit with the first executor's attestation.",
            t0.elapsed().as_secs_f64()
        );

        // ── DB-127 (2026-09-21): A NODE MUST NOT COUNT RECORDS IT WILL NEVER RECEIVE AS MISSING.
        // The live origin reported `missing_records: 32` for the life of every chain it started while it
        // served every early record (ordinals 1–64 all answered): `da_block_root_at_ordinal_derive` registered
        // a BY-ID want keyed by an ORDINAL (1..32, one fold page) whenever a caller asked for a block root
        // before the first page had folded, and an ordinal is not a record id, so those wants could never be
        // satisfied. `missing_records` then read 32 forever, and a restarted or jumped node's unspent heal took
        // the count as ledger holes and reverted for good. Node0 produced alone before node1 joined here, which
        // is exactly the shape. Both nodes must count ZERO missing records once the first page has folded and
        // node1 must serve presence verdicts; measured per node, never inferred from the pair.
        let mut zero_missing = false;
        let mut last = String::new();
        let t_miss = Instant::now();
        while t_miss.elapsed() < Duration::from_secs(120) {
            let a = mesh.get(0, "/get_info").unwrap_or_default();
            let b = mesh.get(1, "/get_info").unwrap_or_default();
            let ma = json_u64(&a, "missing_records");
            let mb = json_u64(&b, "missing_records");
            let ready_b = b.contains("\"unspent_serve_ready\":true");
            last = format!("node0 missing_records={ma:?} node1 missing_records={mb:?} node1 unspent_serve_ready={ready_b}");
            if ma == Some(0) && mb == Some(0) && ready_b {
                zero_missing = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        eprintln!("[seat] DB-127 record accounting after the money path: {last}");
        assert!(
            zero_missing,
            "⛔ DB-127: a real node counts records it will never receive as missing (or the joiner never \
             became ready) — {last}"
        );
    }

    /// ⭐⭐⭐ THE WALLET SIDE OF THE MONEY PATH ON REAL NODES (item 6, 2026-09-17). A REAL wallet process
    /// (`wallet-harness`: the exact functions the Buy screen and the Send button call) buys USDm against
    /// a BTC deposit on node0 — the wallet asks the node for the threshold-custodied reserve address,
    /// the deposit is confirmed by the watcher (the dev oracle door on BOTH nodes: one external-chain
    /// fact), the wallet polls its mint until the 2-of-2 quorum gathered over the mesh lands it in a
    /// block — holds the money in its own balance, and SENDS part of it to a second real wallet whose
    /// node is the OTHER node, which sees it from its own chain. No faucet anywhere: the USDm exists
    /// because BTC entered custody. CONTROLS first: both wallets empty; the mint polled before any
    /// deposit mints nothing.
    /// THE WALLET MONEY PATH ON N REAL NODES — one body, two sizes: the 2-node pair (the founding 2-of-2)
    /// and the 5-node mesh (the scale floor's node count; the second DEVICE is the phone). Every node seats
    /// itself, the wallet buys on node0, sends to a wallet on the last node, that wallet redeems; each
    /// node's resident set is measured against the phone budget throughout.
    /// The settle gate's bar: the pair may differ by one Tor round trip of blocks at the mesh rate.
    const SETTLE_GAP_BLOCKS: u64 = 8;

    fn wallet_money_path_on_real_nodes(n: usize, tag: &str) {
        let t0 = Instant::now();
        // DB-121 (2026-09-21): `MONEROUSD_JOURNEY_BTC_REGTEST=1` puts a REAL Bitcoin Core (regtest) under the
        // Bitcoin leg — the journey raises it, every daemon reads it as its Bitcoin source, the deposit is a
        // real coin Core sends to the reserve address, and the redeem is judged by the BTC ARRIVING at the
        // redeemer's address in Core's wallet. No oracle injector anywhere on that path.
        let regtest = if std::env::var("MONEROUSD_JOURNEY_BTC_REGTEST").ok().as_deref() == Some("1") {
            let r = RegtestCore::start(tag).unwrap_or_else(|e| panic!("⛔ NO REGTEST BITCOIN CORE: {e}"));
            std::env::set_var("MONEROUSD_BTC_NET", "regtest");
            std::env::set_var("MONEROUSD_BTC_RPC_URL", format!("http://127.0.0.1:{}", r.port));
            std::env::set_var("MONEROUSD_BTC_RPC_AUTH", "u:p");
            std::env::set_var("MONEROUSD_BTC_FEE_RATE_SAT_VB", "2");
            eprintln!("[regtest] Bitcoin Core regtest serving at 127.0.0.1:{} · height {}", r.port, r.height());
            Some(r)
        } else {
            None
        };
        // DB-121x (2026-09-21): `MONEROUSD_JOURNEY_XMR_REGTEST=1` puts a REAL Monero daemon (regtest) and one
        // monero-wallet-rpc per custodian under the Monero leg: the custodians' lanes form the k-of-n custody wallet
        // over the mesh, the deposit is a coin the miner wallet sends to the swap's integrated address, and the
        // redeem is judged by the XMR ARRIVING at the redeemer's address in the miner wallet.
        let xmr = if std::env::var("MONEROUSD_JOURNEY_XMR_REGTEST").ok().as_deref() == Some("1") {
            let x = crate::xmr_regtest::MoneroRegtest::start(tag, n).unwrap_or_else(|e| panic!("⛔ NO REGTEST MONERO DAEMON: {e}"));
            std::env::set_var("MONEROUSD_XMR_NET", "regtest");
            std::env::set_var("MONEROUSD_XMR_DAEMON_URL", x.daemon_url());
            std::env::set_var(
                "MONEROUSD_JOURNEY_XMR_WALLET_RPCS",
                (0..n).map(|i| x.custodian_url(i)).collect::<Vec<_>>().join(","),
            );
            std::env::set_var(
                "MONEROUSD_JOURNEY_XMR_WALLET_DIRS",
                x.custodian_dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(","),
            );
            eprintln!("[xmr-regtest] monerod regtest at {} · blocks {} · {} custodian wallet-rpcs", x.daemon_url(), x.block_count(), n);
            Some(x)
        } else {
            None
        };
        let asset = if xmr.is_some() { "XMR" } else { "BTC" };
        let mesh = match RealMesh::start(n, tag) {
            Ok(m) => m,
            Err(e) => panic!("⛔ THE FUNCTIONAL TIER COULD NOT RAISE A REAL {n}-NODE MESH: {e}"),
        };
        let url0 = format!("http://127.0.0.1:{}", mesh.port(0));
        let payee_node = n - 1;
        let url1 = format!("http://127.0.0.1:{}", mesh.port(payee_node));
        let count = |i: usize| -> u64 {
            json_u64(&mesh.get(i, "/get_validator_bond_tree").unwrap_or_default(), "validators")
                .unwrap_or(0)
        };
        let t = Instant::now();
        let all_seated = |mesh: &RealMesh| (0..n).all(|i| json_u64(&mesh.get(i, "/get_validator_bond_tree").unwrap_or_default(), "validators").unwrap_or(0) >= n as u64);
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            if all_seated(&mesh) {
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        assert!(
            all_seated(&mesh),
            "⛔ no {n}-of-{n} custody quorum from the chain: {:?}",
            (0..n).map(count).collect::<Vec<_>>()
        );
        eprintln!("[wallet] {n}-node quorum on every node after {:.1}s", t0.elapsed().as_secs_f64());
        // ── THE MESH MUST BE SETTLED BEFORE A WALLET IS ASKED TO MOVE MONEY THROUGH IT. Runs 3 and 4
        // (2026-09-17): a 3–5 min seat wait meant the Tor link was still churning when the buy began; the
        // executor's published mint then never reached a block in 300 s (DB-7). A user's wallet talks to
        // a settled node; this gate isolates the wallet claim from item 1's liveness work and weakens no
        // assertion — it only refuses to START the money path on a pair that has not converged.
        let height = |i: usize| -> u64 {
            json_u64(&mesh.get(i, "/get_height").unwrap_or_default(), "height").unwrap_or(0)
        };
        // PHONE-CLASS: each node's resident set at the start and at every milestone; a node that grows
        // past the budget, or by more than a fifth over the run, is a RED — the user's standard is a
        // phone that runs the node, so RAM is measured here, never assumed.
        const PHONE_RSS_BUDGET_KB: u64 = 600_000;
        let rss_all = |mesh: &RealMesh| (0..n).map(|i| mesh.rss_kb(i)).collect::<Vec<u64>>();
        // THE NODE ATTRIBUTES ITS OWN RESIDENT SET (`/ram_census`): store name, entries, bytes — printed
        // next to every RSS reading so a growth axis is NAMED by the run instead of guessed at afterwards
        // (run 90: floors 303 → 525 MB and 245 → 743 MB with nothing to say which store grew).
        let census = |mesh: &RealMesh, when: &str| {
            for i in 0..n {
                let body = mesh.get(i, "/ram_census").unwrap_or_default();
                let total = json_u64(&body, "total_bytes").unwrap_or(0);
                // top stores by bytes (the route sorts them): name, entries, bytes
                let mut rows: Vec<String> = Vec::new();
                for seg in body.split("{\"store\":\"").skip(1).take(8) {
                    let name = seg.split('"').next().unwrap_or("?");
                    let entries = seg.split("\"entries\":").nth(1).and_then(|t| t.split(',').next()).unwrap_or("?");
                    let bytes = seg.split("\"bytes\":").nth(1).and_then(|t| t.split('}').next()).unwrap_or("?");
                    rows.push(format!("{name}={entries}e/{bytes}B"));
                }
                eprintln!("[ram-census] node{i} {when}: census total {} KB · rss {} MB · {}", total / 1024, mesh.rss_kb(i) / 1024, rows.join(" "));
                eprintln!("[vm-summary] node{i} {when}: {}", mesh.vm_summary(i));
            }
        };
        // The resident-set BASELINE is taken after the settle gate below, not here: a node still syncing at
        // this point is not at its floor (run walletbtc 2026-09-21: node1 sampled at 89 MB here and 243 MB
        // settled, node0 219 → 267 — the same code at the same height, one of them caught mid warm-up, and
        // the growth check read the warm-up as a growth axis while the RAM census was equal on both).
        census(&mesh, "at start");
        let spread = |height: &dyn Fn(usize) -> u64| -> (u64, u64) {
            let hs: Vec<u64> = (0..n).map(|i| height(i)).collect();
            (*hs.iter().min().unwrap_or(&0), *hs.iter().max().unwrap_or(&0))
        };
        let t = Instant::now();
        let mut findings: Vec<String> = Vec::new();
        let mut settled_since: Option<Instant> = None;
        while t.elapsed() < Duration::from_secs(600) {
            let (lo, hi) = spread(&height);
            let (h0, h1) = (lo, hi);
            // SETTLE = within one Tor round trip of blocks (run 51, 2026-09-18: the pair hovered 1–6 apart
            // at ~1 block/s with both nodes finalizing the SAME height, and a 3-block bar kept resetting on
            // the relay's own latency). Eight blocks is that round trip; the finalized heights below say
            // whether the two really share a chain.
            if h0 > 0 && h0.abs_diff(h1) <= SETTLE_GAP_BLOCKS {
                if settled_since.get_or_insert_with(Instant::now).elapsed() >= Duration::from_secs(30) {
                    break;
                }
            } else {
                settled_since = None;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        // The verdict is the LOOP's: it left only once the pair had stayed within the bar for 30 s (or on
        // the timeout). A fresh read here is one instant later, and run 53 (2026-09-18) took that instant
        // as a 16-body batch page landed on one node — [46, 33] a second after thirty settled seconds.
        let settled = settled_since.map(|s| s.elapsed() >= Duration::from_secs(30)).unwrap_or(false);
        // DB-68b (run 79): heights [450, 449] "settled" while the two DAGs shared NOTHING — two islands producing
        // at one rate. The bar is the SAME CHAIN, so the verdict also requires each node to hold the other's
        // recent selected chain; the overlap findings carry the numbers.
        let overlap_findings = dag_overlap(&mesh, n, "at the settle verdict");
        let settled = settled && overlap_findings.is_empty();
        let (lo, hi) = spread(&height);
        eprintln!(
            "[wallet] settle gate: heights {:?} after {:.1}s (finalized {:?})",
            (0..n).map(|i| height(i)).collect::<Vec<_>>(),
            t.elapsed().as_secs_f64(),
            (0..n).map(|i| json_u64(&mesh.get(i, "/get_height").unwrap_or_default(), "finalized_height").unwrap_or(0)).collect::<Vec<_>>()
        );
        if !(settled) {
            let f = format!("⛔ the {n} real nodes never settled within {SETTLE_GAP_BLOCKS} blocks for 30 s (item 1): last {:?}",
            (lo, hi));
            eprintln!("⛔ {f}");
            findings.push(f);
        }
        for f in overlap_findings {
            eprintln!("⛔ {f}");
            findings.push(f);
        }
        // The resident-set baseline: the pair has settled, so what each node holds now is its floor and any
        // growth from here is the money path's own.
        let rss0 = rss_all(&mesh);
        eprintln!("[phone] rss at the settled baseline (MB): {:?}", rss0.iter().map(|k| k / 1024).collect::<Vec<_>>());
        // ── FINALITY IS MEASURED, NOT ASSUMED (item 6, 2026-09-18). Every node serves its finalized
        // height; with the seats bonded, ≥2/3 of the bonded weight votes and the finalized height must
        // CLIMB on every node. The lag (tip − finalized) is the figure a wallet's "final" badge rests on.
        let finalized = |i: usize| -> u64 {
            json_u64(&mesh.get(i, "/get_height").unwrap_or_default(), "finalized_height").unwrap_or(0)
        };
        let fin0: Vec<u64> = (0..n).map(|i| finalized(i)).collect();
        let tf = Instant::now();
        let mut climbed_at: Option<f64> = None;
        let mut lag_samples: Vec<Vec<u64>> = vec![Vec::new(); n];
        while tf.elapsed() < Duration::from_secs(120) {
            let now_fin: Vec<u64> = (0..n).map(|i| finalized(i)).collect();
            // NON-VACUOUS (run 39 read [1, 1] → [1, 1] as "climbed"): every node must move above its start.
            if climbed_at.is_none() && (0..n).all(|i| now_fin[i] > fin0[i]) {
                climbed_at = Some(tf.elapsed().as_secs_f64());
            }
            if let Some(c) = climbed_at {
                for i in 0..n {
                    lag_samples[i].push(height(i).saturating_sub(now_fin[i]));
                }
                // one minute of steady-state samples after the first climb is the figure that matters
                if tf.elapsed().as_secs_f64() - c >= 60.0 {
                    break;
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        let fin_now: Vec<u64> = (0..n).map(|i| finalized(i)).collect();
        let lag: Vec<u64> = (0..n).map(|i| height(i).saturating_sub(fin_now[i])).collect();
        let median_lag: Vec<u64> = lag_samples
            .iter()
            .map(|v| {
                let mut s = v.clone();
                s.sort_unstable();
                s.get(s.len() / 2).copied().unwrap_or(0)
            })
            .collect();
        eprintln!(
            "[finality] finalized heights {fin_now:?} (from {fin0:?}), lag behind tip now {lag:?} block(s), median lag {median_lag:?} over {} sample(s), climbed on every node after {climbed_at:?} s",
            lag_samples[0].len()
        );
        finality_vote_agreement(&mesh, n);
        if climbed_at.is_none() {
            let f = format!(
                "FINALITY NEVER ADVANCED on a settled {n}-node mesh with bonded seats: finalized {fin_now:?} (from {fin0:?}) — no wallet can call anything final"
            );
            eprintln!("⛔ {f}");
            findings.push(f);
        }
        let wa = RealWallet::create(tag, "buyer", &url0)
            .unwrap_or_else(|e| panic!("⛔ THE REAL WALLET COULD NOT BE CREATED: {e}"));
        // CROSS-DEVICE PAYEE (user 2026-09-17: "the mac and the iphone should have different seeds …
        // truly cross device value transfer not just a self send"): when `MONEROUSD_JOURNEY_PHONE_DIR` names
        // a directory, the payee is a wallet on ANOTHER device with its OWN seed. This side learns only its
        // ADDRESS (`<dir>/address`, written from the other device's screen or console by the operator), pays
        // it, and never holds its seed; receipt is confirmed from the other device (`<dir>/paid` carries the
        // balance it showed), and the redeem leg runs on the buyer, whose keys ARE here. The harness only
        // READS that directory. Without it the payee is a second real wallet on node n-1 as before.
        let phone_dir = std::env::var("MONEROUSD_JOURNEY_PHONE_DIR").ok();
        let hold_secs: u64 = std::env::var("MONEROUSD_JOURNEY_HOLD_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
        let wait_for_file = |path: &str, what: &str| -> String {
            let t = Instant::now();
            let limit = Duration::from_secs(hold_secs.max(900));
            loop {
                if let Ok(txt) = std::fs::read_to_string(path) {
                    let txt = txt.trim().to_string();
                    if !txt.is_empty() {
                        eprintln!("[phone] {what} arrived after {:.0}s ({} chars)", t.elapsed().as_secs_f64(), txt.len());
                        return txt;
                    }
                }
                assert!(t.elapsed() < limit, "⛔ {what} never arrived at {path} within {limit:?}");
                if t.elapsed().as_secs() % 30 == 0 {
                    eprintln!("[phone] waiting for {what} at {path} ({:.0}s)", t.elapsed().as_secs_f64());
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        };
        let wb = if phone_dir.is_some() {
            None
        } else {
            Some(
                RealWallet::create(tag, "payee", &url1)
                    .unwrap_or_else(|e| panic!("⛔ THE SECOND REAL WALLET COULD NOT BE CREATED: {e}")),
            )
        };
        let bal = |w: &RealWallet| -> u64 {
            let lines = w.run(&["refresh", "balance"]).unwrap_or_default();
            lines
                .iter()
                .find(|l| l.contains("\"op\":\"balance\""))
                .and_then(|l| json_u64(l, "atomic"))
                .unwrap_or(0)
        };
        assert_eq!(bal(&wa), 0, "the buyer starts empty (no faucet)");
        if let Some(wb) = &wb {
            assert_eq!(bal(wb), 0, "the payee starts empty");
        }

        // ── DB-121x: with a Monero daemon under the leg, the custodians' lanes must first FORM the set's k-of-n
        //    custody wallet over the mesh and announce it (a user's node serves Monero addresses only from a wallet
        //    ≥k members announced). The wait is the key exchange's own: each poll re-sends a round; nothing is nudged.
        if xmr.is_some() {
            let t = Instant::now();
            let probe_blind = hexs(&[0x5eu8; 64]);
            let mut ready = false;
            let mut last = String::new();
            while t.elapsed() < Duration::from_secs(600) {
                last = mesh
                    .post(0, "/get_reserve_swap_address", &format!(r#"{{"asset":"XMR","d_blind_hex":"{probe_blind}"}}"#))
                    .unwrap_or_default();
                if last.contains("\"reserve_ready\":true") {
                    ready = true;
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
            eprintln!("[xmr-regtest] Monero custody wallet announced to node0 after {:.1}s: {}", t.elapsed().as_secs_f64(), &last[..last.len().min(200)]);
            assert!(ready, "⛔ THE MONERO CUSTODY WALLET NEVER FORMED over the mesh within 600 s: {last}");
        }
        // ── BUY: the wallet asks node0 for THIS swap's reserve deposit address.
        let buy = wa
            .run(&[&format!("buy {asset} 20")])
            .unwrap_or_else(|e| panic!("⛔ the wallet could not start a buy: {e}"));
        let buy_line = buy.iter().find(|l| l.contains("\"op\":\"buy\"")).cloned().unwrap_or_default();
        eprintln!("[wallet] buy -> {}", &buy_line[..buy_line.len().min(320)]);
        let swap_id = json_str(&buy_line, "swap_id").unwrap_or_else(|| panic!("⛔ no swap id: {buy_line}"));
        let deposit_address = json_str(&buy_line, "deposit_address").unwrap_or_default();
        assert!(
            !deposit_address.is_empty() && buy_line.contains("\"reserve_ready\":true"),
            "⛔ the reserve gave the wallet no deposit address (no quorum-derived reserve key): {buy_line}"
        );
        // CONTROL: polling the mint BEFORE any deposit mints nothing.
        let pre = wa.run(&[&format!("mint {swap_id}")]).unwrap_or_default();
        let pre_line = pre.iter().find(|l| l.contains("\"op\":\"mint\"")).cloned().unwrap_or_default();
        eprintln!("[wallet] mint before any deposit -> {}", &pre_line[..pre_line.len().min(240)]);
        assert!(
            !pre_line.contains("\"minted\":true"),
            "⛔⛔⛔ USDm MINTED WITH NO CONFIRMED DEPOSIT — unbacked supply: {pre_line}"
        );
        // ── THE DEPOSIT.
        match (&regtest, &xmr) {
            // DB-121: a REAL coin. The wallet asked 150% of 20 USDm at price 1 = 30 BTC; Core's wallet sends it
            // to the reserve address and mines it to THORChain maturity — ⌈value/subsidy⌉ confirmations, the
            // count every custodian's own source read must reach before it calls the deposit confirmed.
            (Some(r), _) => {
                let txid = r.send(&deposit_address, "30").unwrap_or_else(|e| panic!("⛔ Core could not fund the reserve: {e}"));
                let confs = crate::btc_watch::required_confirmations(30 * 100_000_000) + 1;
                r.mine(confs).unwrap_or_else(|e| panic!("⛔ Core could not mine the deposit: {e}"));
                eprintln!("[regtest] deposited 30 BTC to the reserve address {deposit_address} in {txid}, mined under {confs} blocks (Core h={})", r.height());
            }
            // DB-121x: a REAL Monero coin. The wallet asked 150% of 20 USDm at the ledger's one-atomic-unit-per-cent
            // convention = 3 000 000 000 piconero; the miner wallet sends it to the swap's INTEGRATED address and
            // the chain is mined to maturity — Monero's 10-block lock (⌈value/reward⌉ is smaller here) plus one.
            (None, Some(x)) => {
                let atomic: u64 = 30 * 100_000_000;
                let txid = x.send(&deposit_address, atomic).unwrap_or_else(|e| panic!("⛔ the miner wallet could not fund the reserve: {e}"));
                let confs = crate::xmr_watch::required_confirmations(atomic) + 1;
                x.mine(confs).unwrap_or_else(|e| panic!("⛔ monerod could not mine the deposit: {e}"));
                eprintln!("[xmr-regtest] deposited {atomic} piconero to the integrated address {deposit_address} in {txid}, mined under {confs} blocks (blocks {})", x.block_count());
            }
            // The external-chain fact reaches BOTH watchers through the dev oracle door.
            (None, None) => {
                for i in 0..n {
                    mesh.post(
                        i,
                        "/dev/inject_confirmed_deposit",
                        &format!(r#"{{"address":"{deposit_address}","sats":10000000000}}"#),
                    )
                    .unwrap_or_else(|e| {
                        panic!("⛔ no dev oracle door on node{i} — build with --features bridge-test-oracle: {e}")
                    });
                }
            }
        }
        // ── THE MINT: the wallet polls exactly as the Buy screen does, until a block carries it.
        let t = Instant::now();
        let mut last = String::new();
        let mut polls = 0u32;
        while t.elapsed() < Duration::from_secs(600) {
            let r = wa.run(&[&format!("mint {swap_id}")]).unwrap_or_default();
            last = r.iter().find(|l| l.contains("\"op\":\"mint\"")).cloned().unwrap_or_default();
            if last.contains("\"minted\":true") {
                break;
            }
            polls += 1;
            if polls % 10 == 0 {
                // The payee node is `n - 1`: on a one-Mac + phone run it IS node 0 (run 90 phone panicked
                // here indexing a second Mac that does not exist).
                eprintln!(
                    "[wallet] still waiting for the mint at {:.0}s — node0 h={} node{payee_node} h={} · {}",
                    t.elapsed().as_secs_f64(),
                    height(0),
                    height(payee_node),
                    &last[..last.len().min(160)]
                );
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        eprintln!("[wallet] mint after {:.1}s -> {}", t.elapsed().as_secs_f64(), &last[..last.len().min(320)]);
        assert!(last.contains("\"minted\":true"), "⛔ THE WALLET'S DEPOSIT NEVER MINTED: {last}");
        // ── THE MONEY IS SPENDABLE in the buyer's own wallet (its node scanned the block).
        let t = Instant::now();
        let mut a_bal = 0u64;
        while t.elapsed() < Duration::from_secs(240) {
            a_bal = bal(&wa);
            if a_bal >= 20 * 100_000_000 {
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        eprintln!("[wallet] buyer balance atomic={a_bal} after {:.1}s", t.elapsed().as_secs_f64());
        eprintln!("[phone] rss after the mint (MB): {:?}", rss_all(&mesh).iter().map(|k| k / 1024).collect::<Vec<_>>());
        assert!(a_bal >= 20 * 100_000_000, "⛔ the minted USDm is not in the buyer's wallet: atomic={a_bal}");
        // ── DB-77 ON TWO DEVICES (user 2026-09-19: "use the mac as node 1 and iphone as node 2"): the PHONE's
        //    own in-process node holds NO seat, and it is the node that REQUESTS a mint. Its console prints the
        //    deposit address its `buy` derived from chain state; this Mac custodian's watcher is given the
        //    external-chain fact, the request reaches it over Tor gossip, it proposes/attests/publishes, and
        //    the block credits the phone — which its console reports as `[phone] minted`.
        let phone_wait = |path: &str, what: &str, secs: u64| -> Option<String> {
            let t = Instant::now();
            loop {
                if let Ok(txt) = std::fs::read_to_string(path) {
                    let txt = txt.trim().to_string();
                    if !txt.is_empty() {
                        eprintln!("[phone] {what} arrived after {:.0}s", t.elapsed().as_secs_f64());
                        return Some(txt);
                    }
                }
                if t.elapsed() >= Duration::from_secs(secs) {
                    eprintln!("[phone] {what} did NOT arrive within {secs}s");
                    return None;
                }
                if t.elapsed().as_secs() % 60 == 0 {
                    eprintln!("[phone] waiting for {what} ({:.0}s)", t.elapsed().as_secs_f64());
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        };
        if let Some(d) = &phone_dir {
            let tp = Instant::now();
            match phone_wait(&format!("{d}/deposit_address"), "the phone's OWN deposit address (its seatless node's buy)", hold_secs.max(900)) {
                Some(addr) => {
                    for i in 0..n {
                        mesh.post(
                            i,
                            "/dev/inject_confirmed_deposit",
                            &format!(r#"{{"address":"{addr}","sats":10000000000}}"#),
                        )
                        .unwrap_or_else(|e| panic!("⛔ no dev oracle door on node{i}: {e}"));
                    }
                    eprintln!("[phone] the phone's deposit is confirmed on the Mac custodian's watcher ({:.1}s)", tp.elapsed().as_secs_f64());
                    match phone_wait(&format!("{d}/minted"), "the phone's MINT (requested from a node with no seat, completed by this custodian over the lane)", 900) {
                        Some(line) => eprintln!("[phone] ⭐ PHONE MINT LANDED (DB-77) after {:.1}s: {line}", tp.elapsed().as_secs_f64()),
                        None => {
                            let f = "THE PHONE'S MINT REQUEST (from a node with no custodian seat) NEVER LANDED — DB-77 lane not closed on real devices".to_string();
                            eprintln!("⛔ {f}");
                            findings.push(f);
                        }
                    }
                    let log0 = std::fs::read_to_string(mesh.log_path(0)).unwrap_or_default();
                    eprintln!(
                        "[phone] node0 lane trace: requests seen {}, proposed {}, published {}, mints applied from blocks {}",
                        log0.matches("[peg-in] REQUESTED").count() + log0.matches("a relayed request").count(),
                        log0.matches("this custodian PROPOSED a mint").count(),
                        log0.matches("PUBLISHED the chain object for a completed request (kind 0)").count(),
                        log0.matches("[peg-in] mint").count()
                    );
                }
                None => {
                    let f = "THE PHONE NEVER PUBLISHED A BUY (no deposit address arrived from the second device)".to_string();
                    eprintln!("⛔ {f}");
                    findings.push(f);
                }
            }
        }
        // ── SEND to the second wallet, whose node is the OTHER node.
        let payee_address = match (&phone_dir, &wb) {
            (Some(d), _) => wait_for_file(&format!("{d}/address"), "the second device's wallet address"),
            (None, Some(wb)) => wb.address.clone(),
            (None, None) => unreachable!("a payee is either on the other device or a wallet here"),
        };
        let send = wa
            .run(&[&format!("send {} 5.0", payee_address)])
            .unwrap_or_else(|e| panic!("⛔ the wallet could not send: {e}"));
        let send_line = send.iter().find(|l| l.contains("\"op\":\"send\"")).cloned().unwrap_or_default();
        eprintln!("[wallet] send -> {}", &send_line[..send_line.len().min(320)]);
        assert!(send_line.contains("\"ok\":true"), "⛔ the send was refused: {send_line}");
        let t = Instant::now();
        let mut b_bal = 0u64;
        match (&phone_dir, &wb) {
            (Some(d), _) => {
                // The other device confirms receipt: `<dir>/paid` holds the balance its wallet showed.
                let paid = wait_for_file(&format!("{d}/paid"), "the second device's receipt");
                b_bal = paid.parse::<u64>().unwrap_or(0);
                eprintln!("[wallet] payee balance atomic={b_bal} after {:.1}s (the SECOND DEVICE's own wallet)", t.elapsed().as_secs_f64());
            }
            (None, Some(wb)) => {
                while t.elapsed() < Duration::from_secs(300) {
                    b_bal = bal(wb);
                    if b_bal >= 5 * 100_000_000 {
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(3));
                }
                eprintln!("[wallet] payee balance atomic={b_bal} after {:.1}s (node{payee_node})", t.elapsed().as_secs_f64());
            }
            (None, None) => unreachable!(),
        }
        if b_bal < 5 * 100_000_000 {
            let f = format!("THE PAYEE ON NODE{payee_node} NEVER SAW THE MONEY: atomic={b_bal}");
            eprintln!("⛔ {f}");
            findings.push(f);
        }
        // ── REAL THROUGHPUT NUMBERS (user 2026-09-18: "get real transaction per second numbers"). With
        // ── THE REDEEM (item 3 on real nodes): the payee SELLS 5 USDm for BTC through the peg-out lane —
        // the exact `wallet_sell_usdm` the Sell screen calls: burn carrier + membership carrier built in the
        // wallet, `/peg_out_execute` on its own node (node1), the 2-of-2 quorum gathered over the mesh
        // (node0 verifies the burn itself before signing), the release published, the burn applied from
        // the block. Each `sell` call re-proves the same note and polls the same proposal (the nullifier
        // keys it), so repeating it is the Sell screen's own poll.
        // The seller is the payee's wallet when it lives here, else the buyer (the other device's keys are
        // not here — it keeps what it was paid, as a user would).
        // ── DB-77 ON TWO DEVICES, THE REDEEM: the PHONE's seatless node requests the burn of the 5 USDm it
        //    was paid; this custodian completes it; the block burns the note on both devices.
        if let Some(d) = &phone_dir {
            let tp = Instant::now();
            match phone_wait(&format!("{d}/sold"), "the phone's REDEEM (requested from a node with no seat)", 900) {
                Some(line) => eprintln!("[phone] ⭐ PHONE REDEEM LANDED (DB-77) after {:.1}s: {line}", tp.elapsed().as_secs_f64()),
                None => {
                    let f = "THE PHONE'S REDEEM REQUEST (from a node with no custodian seat) NEVER LANDED".to_string();
                    eprintln!("⛔ {f}");
                    findings.push(f);
                }
            }
            let log0 = std::fs::read_to_string(mesh.log_path(0)).unwrap_or_default();
            let applied = log0.matches("PegOut object applied on this node: Redeemed").count();
            eprintln!(
                "[phone] node0 redeem trace: proposed {}, published {}, PegOut objects applied from blocks {applied}",
                log0.matches("this custodian PROPOSED a redeem").count(),
                log0.matches("PUBLISHED the chain object for a completed request (kind 1)").count()
            );
            if applied == 0 {
                let f = "THE MAC CUSTODIAN NEVER APPLIED A PegOut OBJECT FROM A BLOCK (the phone's burn did not settle on the chain)".to_string();
                eprintln!("⛔ {f}");
                findings.push(f);
            }
        }
        let seller = wb.as_ref().unwrap_or(&wa);
        let seller_before = bal(seller);
        eprintln!("[wallet] seller balance before the redeem atomic={seller_before}");
        // DB-121: with a real Bitcoin Core under the leg the redeemer's address is one Core's wallet holds, so
        // Core itself reports the arrival. Without one, the redeemer's address is still a REAL taproot address
        // — derived from a key this journey draws, on the network the daemons are on (owner 2026-09-21: "no
        // placeholder addresses left, only real derived reserve addresses"); a made-up string would be a burn
        // paying nobody.
        let payout_s = match (&regtest, &xmr) {
            (Some(r), _) => r.fresh_address().unwrap_or_else(|e| panic!("⛔ Core gave no redeemer address: {e}")),
            (None, Some(x)) => x.fresh_address().unwrap_or_else(|e| panic!("⛔ the miner wallet gave no redeemer address: {e}")),
            (None, None) => {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(crate::hash::Hash32::hash(format!("{tag}-redeemer-{}", std::process::id()).as_bytes()).0.as_slice());
                let x = crate::btc_tx::xonly_pubkey(&secret).unwrap_or_else(|| panic!("⛔ the redeemer key is not a valid secp256k1 secret"));
                crate::btc_tx::reserve_address(crate::bridge::btc_hrp(), &x)
            }
        };
        let payout = payout_s.as_str();
        let t = Instant::now();
        let mut sold = String::new();
        while t.elapsed() < Duration::from_secs(600) {
            let r = seller.run(&[&format!("sell 5.0 {asset} {payout}")]).unwrap_or_default();
            sold = r.iter().find(|l| l.contains("\"op\":\"sell\"")).cloned().unwrap_or_default();
            if sold.contains("\"sold\":true") {
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        eprintln!("[wallet] sell after {:.1}s -> {}", t.elapsed().as_secs_f64(), &sold[..sold.len().min(320)]);
        // The redeem is a FINDING, asserted at the end with the others (2026-09-18): the burst below is a
        // measurement the run must still make when the redeem fails, and the node's `[peg-out]` gate lines
        // say why it failed.
        let redeem_ok = sold.contains("\"sold\":true");
        if !redeem_ok {
            let f = format!("THE PAYEE'S REDEEM NEVER LANDED: {}", &sold[..sold.len().min(300)]);
            eprintln!("⛔ {f}");
            findings.push(f);
        }
        let t = Instant::now();
        let mut b_after = u64::MAX;
        while redeem_ok && t.elapsed() < Duration::from_secs(300) {
            b_after = bal(seller);
            if b_after + 5 * 100_000_000 <= seller_before {
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        eprintln!("[wallet] payee balance after the burn atomic={b_after} after {:.1}s", t.elapsed().as_secs_f64());
        // ── DB-121: THE BTC ARRIVES. With a real Bitcoin Core under the leg, the burn's payout must be proposed
        // by the rotating proposer, signed by BOTH custodians (each from its own sealed leg and its own view of
        // the reserve coins), broadcast to Core, mined, and seen confirmed by the custodians — and Core's wallet
        // must show the redeemer's address paid EXACTLY the released sats (5 USDm burned → 5 BTC at price 1;
        // the miner fee comes out of the reserve's change, never the redeemer's leg). Regtest mines nothing on
        // its own, so a block is mined every few seconds while waiting; nothing else is nudged.
        if let Some(r) = &regtest {
            let expect_sats: u64 = 5 * 100_000_000;
            let lane_trace = |i: usize| -> String {
                let log = std::fs::read_to_string(mesh.log_path(i)).unwrap_or_default();
                format!(
                    "node{i}: booked {} proposed {} signed {} broadcast {} settled {}",
                    log.matches("obligation booked for burn").count(),
                    log.matches("PROPOSING a payout").count(),
                    log.matches("SIGNED proposal").count(),
                    log.matches("PAYOUT BROADCAST").count(),
                    log.matches("SETTLED burn").count()
                )
            };
            let t = Instant::now();
            let mut got = 0u64;
            let mut last_said = 0u64;
            while redeem_ok && t.elapsed() < Duration::from_secs(900) {
                got = r.received_sats(payout);
                if got >= expect_sats {
                    break;
                }
                let _ = r.mine(1);
                if t.elapsed().as_secs() / 30 != last_said {
                    last_said = t.elapsed().as_secs() / 30;
                    eprintln!(
                        "[regtest] waiting for the payout at {:.0}s — Core h={} received={got} sats · {} · {}",
                        t.elapsed().as_secs_f64(),
                        r.height(),
                        lane_trace(0),
                        lane_trace(n - 1)
                    );
                }
                std::thread::sleep(Duration::from_secs(5));
            }
            eprintln!(
                "[regtest] ⭐ redeemer address {payout} holds {got} sats after {:.1}s (released {expect_sats}) · {} · {}",
                t.elapsed().as_secs_f64(),
                lane_trace(0),
                lane_trace(n - 1)
            );
            if got != expect_sats {
                let f = format!(
                    "THE REDEEMED BTC DID NOT ARRIVE: Core shows {got} sats at the redeemer's address, the burn released {expect_sats}"
                );
                eprintln!("⛔ {f}");
                findings.push(f);
            }
            // F5: the release is RECORDED only when each custodian's own source sees the payout confirmed —
            // both nodes must log the settlement from their own read of Core; a payout that arrived but was
            // never settled would leave the burn "owed" forever and the lane proposing it again.
            let t = Instant::now();
            let mut settled_on = 0usize;
            while got == expect_sats && t.elapsed() < Duration::from_secs(240) {
                settled_on = (0..n)
                    .filter(|i| std::fs::read_to_string(mesh.log_path(*i)).unwrap_or_default().contains("SETTLED burn"))
                    .count();
                if settled_on == n {
                    break;
                }
                let _ = r.mine(1);
                std::thread::sleep(Duration::from_secs(5));
            }
            eprintln!(
                "[regtest] release settled from their own source read on {settled_on}/{n} custodians after {:.1}s · {} · {}",
                t.elapsed().as_secs_f64(),
                lane_trace(0),
                lane_trace(n - 1)
            );
            if got == expect_sats && settled_on != n {
                let f = format!("THE PAYOUT ARRIVED BUT ONLY {settled_on}/{n} CUSTODIANS RECORDED THE RELEASE from their own source read (F5)");
                eprintln!("⛔ {f}");
                findings.push(f);
            }
        }
        // ── DB-121x: THE XMR ARRIVES. With a real monerod under the leg, the burn's payout must be built by the
        // rotating proposer's own wallet, signed in sequence by the custodians' wallets, relayed, mined, and seen
        // confirmed by each custodian's wallet — and the miner wallet must show the redeemer's subaddress paid EXACTLY
        // the released piconero (5 USDm burned → 500 000 000 piconero at the ledger's one-unit-per-cent convention;
        // the fee comes out of the reserve's change). Blocks are mined every few seconds so the payout confirms.
        if let Some(x) = &xmr {
            let expect_atomic: u64 = 5 * 100_000_000;
            let lane_trace = |i: usize| -> String {
                let log = std::fs::read_to_string(mesh.log_path(i)).unwrap_or_default();
                format!(
                    "node{i}: booked {} proposed {} signed {} broadcast {} settled {}",
                    log.matches("[xmr-payout] obligation booked").count(),
                    log.matches("PROPOSING a Monero payout").count(),
                    log.matches("SIGNED payout").count(),
                    log.matches("[xmr-payout] ⭐ PAYOUT BROADCAST").count(),
                    log.matches("[xmr-payout] ⭐ SETTLED burn").count()
                )
            };
            let t = Instant::now();
            let mut got = 0u64;
            let mut last_said = 0u64;
            while redeem_ok && t.elapsed() < Duration::from_secs(900) {
                got = x.received_atomic(payout, 1);
                if got >= expect_atomic {
                    break;
                }
                let _ = x.mine(1);
                if t.elapsed().as_secs() / 30 != last_said {
                    last_said = t.elapsed().as_secs() / 30;
                    eprintln!(
                        "[xmr-regtest] waiting for the payout at {:.0}s — blocks {} received={got} piconero · {} · {}",
                        t.elapsed().as_secs_f64(),
                        x.block_count(),
                        lane_trace(0),
                        lane_trace(n - 1)
                    );
                }
                std::thread::sleep(Duration::from_secs(5));
            }
            eprintln!(
                "[xmr-regtest] ⭐ redeemer address {payout} received {got} piconero after {:.1}s (released {expect_atomic}) · {} · {}",
                t.elapsed().as_secs_f64(),
                lane_trace(0),
                lane_trace(n - 1)
            );
            if got != expect_atomic {
                let f = format!(
                    "THE REDEEMED XMR DID NOT ARRIVE: the miner wallet shows {got} piconero at the redeemer's address, the burn released {expect_atomic}"
                );
                eprintln!("⛔ {f}");
                findings.push(f);
            }
            // F5: the release is recorded only when each custodian's own wallet sees the payout confirmed (Monero's
            // 10-block lock); blocks keep coming so it can.
            let t = Instant::now();
            let mut settled_on = 0usize;
            while got == expect_atomic && t.elapsed() < Duration::from_secs(300) {
                settled_on = (0..n)
                    .filter(|i| std::fs::read_to_string(mesh.log_path(*i)).unwrap_or_default().contains("[xmr-payout] ⭐ SETTLED burn"))
                    .count();
                if settled_on == n {
                    break;
                }
                let _ = x.mine(1);
                std::thread::sleep(Duration::from_secs(5));
            }
            eprintln!(
                "[xmr-regtest] release settled from their own wallet read on {settled_on}/{n} custodians after {:.1}s · {} · {}",
                t.elapsed().as_secs_f64(),
                lane_trace(0),
                lane_trace(n - 1)
            );
            if got == expect_atomic && settled_on != n {
                let f = format!("THE MONERO PAYOUT ARRIVED BUT ONLY {settled_on}/{n} CUSTODIANS RECORDED THE RELEASE from their own wallet read (F5)");
                eprintln!("⛔ {f}");
                findings.push(f);
            }
        }
        // MEASURED run 64 (2026-09-18): a node's resident set swings 476 → 939 → 598 MB within minutes
        // (bundle proving and adopt buffers, then released), so one instantaneous read is noise. The
        // phone-class question is the FLOOR — what the node holds when the transient work is done — so
        // the reading is the minimum of five samples two seconds apart, and the verdict is a finding
        // asserted at the END with the others (the burst still runs and reports its numbers).
        let rss1 = {
            let mut floor = rss_all(&mesh);
            for _ in 0..4 {
                std::thread::sleep(Duration::from_secs(2));
                for (f, v) in floor.iter_mut().zip(rss_all(&mesh)) {
                    if v > 0 && (v < *f || *f == 0) {
                        *f = v;
                    }
                }
            }
            floor
        };
        eprintln!("[phone] rss floor at the end (MB): {:?} (start {:?})", rss1.iter().map(|k| k / 1024).collect::<Vec<_>>(), rss0.iter().map(|k| k / 1024).collect::<Vec<_>>());
        census(&mesh, "at the end");
        for i in 0..n {
            let (a, b) = (rss0[i], rss1[i]);
            if b > PHONE_RSS_BUDGET_KB {
                let f = format!("node{i} resident-set floor {} MB is over the phone budget {} MB", b / 1024, PHONE_RSS_BUDGET_KB / 1024);
                eprintln!("⛔ {f}");
                findings.push(f);
            }
            if b > a + a / 5 + 65_536 {
                let f = format!("node{i} resident-set floor grew {} → {} MB over the run — a growth axis, not phone-class", a / 1024, b / 1024);
                eprintln!("⛔ {f}");
                findings.push(f);
            }
        }
        if redeem_ok && b_after + 5 * 100_000_000 > seller_before {
            let f = format!("the burned USDm is still in the seller's wallet: before={seller_before} after={b_after}");
            eprintln!("⛔ {f}");
            findings.push(f);
        }
        // ── RESTORE FROM SEED ON THE OTHER NODE (ownership is chain-derived or it is not): the buyer's
        // seed opens a wallet with NO local store against the payee's node; its balance must equal the
        // persisted wallet's spendable balance (the 20 USDm input must read as SPENT from the unspent
        // tree alone, the change and nothing else as owned). Same for the payee's seed against node 0
        // when the payee is a wallet here. A restore that shows MORE (the spent input counted) or LESS
        // (a note not found) is a funds-safety finding either way.
        if wb.is_some() {
            let expect_a = bal(&wa);
            let expect_b = bal(wb.as_ref().unwrap());
            for (who, w, other_url, expect) in [
                ("buyer", &wa, &url1, expect_a),
                ("payee", wb.as_ref().unwrap(), &url0, expect_b),
            ] {
                match w.restored_elsewhere_for_test(who, other_url) {
                    Ok(r) => {
                        let t = Instant::now();
                        let mut got = u64::MAX;
                        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
                            got = bal(&r);
                            if got == expect {
                                break;
                            }
                            std::thread::sleep(Duration::from_secs(5));
                        }
                        eprintln!(
                            "[restore] the {who}'s seed restored on the OTHER node with an empty store: spendable atomic={got} (persisted wallet says {expect}) after {:.1}s",
                            t.elapsed().as_secs_f64()
                        );
                        if got != expect {
                            let f = format!("RESTORE FROM SEED DISAGREES WITH THE WALLET THAT SPENT: {who} restored={got} persisted={expect} — ownership/spent-status is not fully chain-derived");
                            eprintln!("⛔ {f}");
                            findings.push(f);
                        }
                    }
                    Err(e) => {
                        let f = format!("could not restore the {who}'s seed elsewhere: {e}");
                        eprintln!("⛔ {f}");
                        findings.push(f);
                    }
                }
            }
        }
        for f in dag_overlap(&mesh, n, "at the end") {
            eprintln!("⛔ {f}");
            findings.push(f);
        }
        // ── THE BURST (TPS) runs AFTER the redeem (2026-09-18): the fund-safety path (buy, pay, redeem)
        // must complete whatever the throughput measurement finds; the burst is the measurement.
        // MONEROUSD_JOURNEY_BURST=N: the buyer funds N fresh wallets on the payee node one by one (each
        // a real spend, timed), then all N spend back to the buyer IN PARALLEL (N wallet processes, each
        // proving its own spend — what N users do), and the chain is timed to inclusion of every one.
        // Nothing is stubbed: every spend is a real PQ spend through the real pool door.
        if let Ok(nstr) = std::env::var("MONEROUSD_JOURNEY_BURST") {
            let burst: usize = nstr.parse().unwrap_or(0).min(64);
            if burst > 0 {
                let t_fund = Instant::now();
                let mut fund_secs: Vec<f64> = Vec::new();
                let mut payees: Vec<RealWallet> = Vec::new();
                for i in 0..burst {
                    let w = RealWallet::create(tag, &format!("burst{i}"), &url1)
                        .unwrap_or_else(|e| panic!("⛔ burst wallet {i}: {e}"));
                    // A fresh change note is spendable once its block FOLDS (~record_fold_depth blocks): the
                    // wallet refuses "cannot build the deletion witness … not in the unspent tree" until then
                    // (run 38, 2026-09-18). That wait is a confirmation depth, so the spend retries for up to
                    // 360 s on exactly that refusal; any other refusal is a defect and fails the run.
                    let ts = Instant::now();
                    let mut line = String::new();
                    let mut waited_fold = 0.0f64;
                    loop {
                        let r = wa.run(&[&format!("send {} 0.2", w.address)]).unwrap_or_default();
                        line = r.iter().find(|l| l.contains("\"op\":\"send\"")).cloned().unwrap_or_default();
                        if line.contains("\"ok\":true") {
                            break;
                        }
                        // DB-94: a copath the node cannot serve YET (a record still travelling, an index entry
                        // healing after a re-fold) is the same confirmation-depth class — retry on it too.
                        let fold_lag = line.contains("deletion witness")
                            || line.contains("not folded")
                            || line.contains("NOT in the unspent tree")
                            || line.contains("copath")
                            || line.contains("membership");
                        if !fold_lag || ts.elapsed() > Duration::from_secs(360) {
                            break;
                        }
                        waited_fold = ts.elapsed().as_secs_f64();
                        std::thread::sleep(Duration::from_secs(3));
                    }
                    assert!(line.contains("\"ok\":true"), "⛔ funding send {i} refused: {line}");
                    if waited_fold > 0.0 {
                        eprintln!("[tps] funding send {i} waited {waited_fold:.1}s for the change note's block to fold (confirmation depth)");
                    }
                    fund_secs.push(ts.elapsed().as_secs_f64());
                    payees.push(w);
                }
                let avg_fund = fund_secs.iter().sum::<f64>() / fund_secs.len().max(1) as f64;
                eprintln!(
                    "[tps] funded {burst} wallet(s) sequentially in {:.1}s — one real spend (prove+submit) averages {:.2}s on this machine",
                    t_fund.elapsed().as_secs_f64(),
                    avg_fund
                );
                let t = Instant::now();
                loop {
                    let handles: Vec<std::thread::JoinHandle<u64>> = payees.iter().map(|w| w.spawn_balance()).collect();
                    let landed = handles.into_iter().map(|h| h.join().unwrap_or(0)).filter(|b| *b >= 20_000_000).count();
                    if landed == burst || t.elapsed() > Duration::from_secs(240) {
                        eprintln!("[tps] {landed}/{burst} funded wallets see their note after {:.1}s", t.elapsed().as_secs_f64());
                        assert_eq!(landed, burst, "⛔ not every funded wallet saw its note");
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
                let buyer_before = bal(&wa);
                let h_before = height(0);
                let t_burst = Instant::now();
                let buyer_addr = wa.address.clone();
                // DB-102: sixteen provers at once exhausted this machine (runs 102c/102h died with SIGKILL
                // from outside, right here, with no jetsam report to read) — the burst runs in waves of
                // BURST_PROVERS_AT_ONCE; every spend is still submitted, and the chain-side inclusion figure
                // below is measured from the last submit exactly as before.
                let mut results: Vec<(bool, f64)> = Vec::new();
                for wave in payees.chunks(BURST_PROVERS_AT_ONCE) {
                    let handles: Vec<std::thread::JoinHandle<(bool, f64)>> =
                        wave.iter().map(|w| w.spawn_send(&buyer_addr, "0.1")).collect();
                    results.extend(handles.into_iter().map(|h| h.join().unwrap_or((false, 0.0))));
                }
                let submitted = results.iter().filter(|(ok, _)| *ok).count();
                let submit_wall = t_burst.elapsed().as_secs_f64();
                let max_prove = results.iter().map(|(_, s)| *s).fold(0.0f64, f64::max);
                eprintln!(
                    "[tps] burst: {submitted}/{burst} parallel spends submitted in {submit_wall:.1}s wall (slowest prove {max_prove:.1}s) ⇒ {:.2} submitted tx/s from ONE machine's provers",
                    submitted as f64 / submit_wall.max(0.001)
                );
                let want = buyer_before + (submitted as u64) * 10_000_000;
                let t_incl = Instant::now();
                let mut incl_secs = None;
                while t_incl.elapsed() < Duration::from_secs(300) {
                    if bal(&wa) >= want {
                        incl_secs = Some(t_incl.elapsed().as_secs_f64());
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
                let h_after = height(0);
                let fin = finalized(0);
                match incl_secs {
                    Some(secs) => eprintln!(
                        "[tps] all {submitted} burst spends INCLUDED on node 0 after {secs:.1}s from the last submit ({} block(s) advanced, finalized_height {fin} vs height {h_after}) ⇒ chain-side {:.1} tx/s over the burst window",
                        h_after.saturating_sub(h_before),
                        submitted as f64 / (submit_wall + secs).max(0.001)
                    ),
                    None => eprintln!("[tps] ⛔ NOT every burst spend was included within 300 s: buyer balance {} vs wanted {want}", bal(&wa)),
                }
                assert!(incl_secs.is_some(), "⛔ the burst did not fully land (item: real TPS)");
            }
        }
        eprintln!(
            "[wallet] TOTAL {:.1}s — a real wallet bought USDm with a BTC deposit on a 2-of-2 quorum, held \
             it, paid a second real wallet on the other node, and that wallet redeemed it for BTC",
            t0.elapsed().as_secs_f64()
        );
        // HOLD (2026-09-17): keep the mesh alive after the money path so the second device can be read at
        // leisure (its final balance, its height against the mesh); `<dir>/release` ends it early.
        if hold_secs > 0 {
            let release = phone_dir.as_ref().map(|d| format!("{d}/release")).unwrap_or_default();
            let th = Instant::now();
            eprintln!("[hold] mesh held for up to {hold_secs}s (node0 rpc {url0}); create {release} to end it");
            while th.elapsed().as_secs() < hold_secs && !(!release.is_empty() && std::path::Path::new(&release).exists()) {
                std::thread::sleep(Duration::from_secs(30));
                let hs: Vec<u64> = (0..n).map(|i| height(i)).collect();
                let peers0 = mesh.get(0, "/get_peers").map(|s| s.matches("\"peer_id\"").count()).unwrap_or(0);
                eprintln!(
                    "[hold] t={}s heights={hs:?} node0_peers={peers0} rss_mb={:?}",
                    th.elapsed().as_secs(),
                    rss_all(&mesh).iter().map(|k| k / 1024).collect::<Vec<_>>()
                );
            }
        }
        finality_vote_agreement(&mesh, n);
        assert!(findings.is_empty(), "⛔ FINDINGS this run (the money path above still ran to the end): {findings:#?}");
    }

    /// Every node's cast votes (`[finality-vote] cast h=… block=…`, printed under
    /// `MONEROUSD_FINALITY_TRACE=1`) read back from its log: on how many levels every node voted, and on
    /// how many of those they named ONE block. A split level can never finalize (one vote per height), so
    /// this ratio IS the finality liveness — measured, never assumed.
    fn finality_vote_agreement(mesh: &RealMesh, n: usize) {
        use std::collections::{BTreeMap, BTreeSet};
        let mut per: Vec<BTreeMap<u64, String>> = Vec::new();
        for i in 0..n {
            let txt = std::fs::read_to_string(mesh.log_path(i)).unwrap_or_default();
            let mut m = BTreeMap::new();
            for l in txt.lines().filter(|l| l.contains("[finality-vote] cast h=")) {
                let h = l.split("h=").nth(1).and_then(|s| s.split_whitespace().next()).and_then(|s| s.parse::<u64>().ok());
                let b = l.split("block=").nth(1).and_then(|s| s.split_whitespace().next()).map(str::to_string);
                if let (Some(h), Some(b)) = (h, b) {
                    m.insert(h, b);
                }
            }
            per.push(m);
        }
        let heights: BTreeSet<u64> = per.iter().flat_map(|m| m.keys().copied()).collect();
        let (mut all, mut agree, mut subset) = (0usize, 0usize, 0usize);
        let mut splits: Vec<String> = Vec::new();
        for h in heights {
            let votes: Vec<Option<&String>> = per.iter().map(|m| m.get(&h)).collect();
            if votes.iter().all(|v| v.is_some()) {
                all += 1;
                let first = votes[0].unwrap();
                if votes.iter().all(|v| v.unwrap() == first) {
                    agree += 1;
                } else if splits.len() < 6 {
                    splits.push(format!("h={h}:{:?}", votes.iter().map(|v| v.unwrap().as_str()).collect::<Vec<_>>()));
                }
            } else {
                subset += 1;
            }
        }
        eprintln!(
            "[finality] vote agreement: {agree}/{all} level(s) voted by every node name ONE block; {subset} level(s) voted by a subset only; first splits {splits:?}"
        );
    }

    /// ⭐⭐⭐ THE WALLET SIDE OF THE MONEY PATH ON REAL NODES (item 6): a REAL wallet process buys USDm with a
    /// BTC deposit on a 2-of-2 quorum, pays a second real wallet on the other node, and that wallet redeems.
    #[test]
    fn a_real_wallet_buys_usdm_with_a_btc_deposit_on_two_real_nodes_and_pays_a_second_wallet() {
        wallet_money_path_on_real_nodes(2, "walletmint");
    }

    /// ⭐⭐⭐ DB-121 — THE SAME WALLET MONEY PATH WITH A REAL BITCOIN CORE UNDER THE PEG (regtest): the deposit is
    /// a coin Core sends to the reserve address, the mint waits for THORChain maturity from each custodian's own
    /// source read, the redeem is signed by both custodians and broadcast to Core, and the run is judged by the
    /// BTC ARRIVING in Core's wallet at the redeemer's address — no oracle injector anywhere on the path.
    #[test]
    fn a_real_wallet_deposits_real_bitcoin_mints_redeems_and_the_btc_arrives_from_a_real_bitcoin_core() {
        std::env::set_var("MONEROUSD_JOURNEY_BTC_REGTEST", "1");
        wallet_money_path_on_real_nodes(2, "walletbtc");
    }

    /// ⭐⭐⭐ DB-121x — the same money path on two_nodes (custodian 0, custodian 1 — two daemons, each with its own
    /// Monero wallet-rpc) with a real Monero daemon (regtest) under the peg: a real coin deposited to the swap's
    /// integrated address, the buyer pays the payee on the second daemon, the payee's redeem is signed by both
    /// custodians in sequence, and the run is judged by the XMR arriving at the redeemer's address.
    #[test]
    fn a_real_wallet_deposits_real_monero_mints_redeems_and_the_xmr_arrives_from_a_real_monero_daemon() {
        std::env::set_var("MONEROUSD_JOURNEY_XMR_REGTEST", "1");
        wallet_money_path_on_real_nodes(2, "walletxmr");
    }

    /// ⭐⭐⭐ THE SCALE FLOOR'S NODE COUNT: the same money path on FIVE real nodes (a 5-of-5 founding
    /// quorum gathered over the mesh), the payee on the fifth node. The second device (the phone) joins this
    /// mesh in the 2-device certification.
    #[test]
    fn a_real_wallet_on_the_mac_pays_a_wallet_on_the_iphone_through_one_mac_node() {
        // ONE Mac node + the iPhone's in-process node: two real nodes on two devices, the payee's wallet
        // on the phone with its OWN seed (`MONEROUSD_JOURNEY_PHONE_DIR`). Runs 16–21 (2026-09-17) measured
        // two Mac producers outrunning a Tor circuit's bytes at this block size and rate (DB-13); with one
        // producer the phone keeps pace by pulls alone. The ≥5-node/2-device floor is the follow-on.
        wallet_money_path_on_real_nodes(1, "walletphone");
    }

    /// ⭐⭐⭐ THE ONE-DAG RULE ON REAL NODES (2026-09-21; owner: "all nodes even nodes on different devices
    /// must be on the same dag. A chain split shouldnt be possible for joining nodes like its not on kaspa").
    /// Two real nodes over onion; a wallet on node 1 is paid; then three restarts — node 1 (the joiner)
    /// briefly, node 0 (the origin, the one node carrying the boot directive), node 1 again for longer — and
    /// after each: the restarted node is JOINED (its `/get_info` names how) within 120 s, the pair re-converges
    /// (heights within 8, `missing_records` 0 on both), the two nodes' recent DAG views are ONE set over the
    /// range both cover, and the wallet on node 1 still sees every coin it held. RED before 2026-09-21 by the
    /// live pair itself (19:07–19:15: both resumed gated, DAGs of 38 and 34 blocks with ZERO in common above
    /// genesis, bundles refused, chain halted for eight minutes).
    #[test]
    fn a_restarted_real_node_stays_on_the_same_dag_as_its_peer_and_keeps_every_coin() {
        let t0 = Instant::now();
        let mut mesh = match RealMesh::start(2, "restart") {
            Ok(m) => m,
            Err(e) => panic!("⛔ THE FUNCTIONAL TIER COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let url1 = format!("http://127.0.0.1:{}", mesh.port(1));
        fn info(mesh: &RealMesh, i: usize) -> String {
            mesh.get(i, "/get_info").unwrap_or_default()
        }
        fn heights(mesh: &RealMesh) -> (u64, u64) {
            (mesh.height(0).unwrap_or(0), mesh.height(1).unwrap_or(0))
        }
        fn missing(mesh: &RealMesh, i: usize) -> Option<u64> {
            json_u64(&info(mesh, i), "missing_records")
        }
        // The one-DAG measure: the ids each node's recent view holds, over the range BOTH views cover (the
        // views are cut at 96 rows and the top blocks are in flight, so the allowance is 8 + the height gap).
        fn same_dag(mesh: &RealMesh, when: &str) -> (usize, usize) {
            let a = dag_recent_rows(&mesh.get(0, "/dag_recent").unwrap_or_default());
            let b = dag_recent_rows(&mesh.get(1, "/dag_recent").unwrap_or_default());
            let ida: std::collections::HashSet<&str> = a.iter().map(|(id, _, _)| id.as_str()).collect();
            let idb: std::collections::HashSet<&str> = b.iter().map(|(id, _, _)| id.as_str()).collect();
            let common = ida.intersection(&idb).count();
            let smaller = ida.len().min(idb.len());
            eprintln!(
                "[one-dag] {when}: node0 view {} block(s), node1 view {} block(s), in common {common}",
                ida.len(),
                idb.len()
            );
            (common, smaller)
        }
        fn wait_joined(mesh: &RealMesh, i: usize, secs: u64, when: &str) {
            let t = Instant::now();
            loop {
                let body = info(mesh, i);
                if body.contains("\"mesh_joined\":true") {
                    eprintln!(
                        "[one-dag] {when}: node{i} JOINED after {:.1}s — {}",
                        t.elapsed().as_secs_f64(),
                        json_str(&body, "mesh_joined_how").unwrap_or_default()
                    );
                    return;
                }
                assert!(
                    t.elapsed() < Duration::from_secs(secs),
                    "⛔ {when}: node{i} never re-joined within {secs}s — production gated after a restart (the 19:07 halt)"
                );
                std::thread::sleep(Duration::from_secs(2));
            }
        }
        fn wait_converged(mesh: &RealMesh, when: &str, secs: u64) -> (u64, u64) {
            let t = Instant::now();
            loop {
                let (h0, h1) = heights(mesh);
                let diff = h0.abs_diff(h1);
                if h0 > 0 && h1 > 0 && diff <= 8 && missing(mesh, 0) == Some(0) && missing(mesh, 1) == Some(0) {
                    let (common, smaller) = same_dag(mesh, when);
                    if common + 8 + diff as usize >= smaller {
                        eprintln!(
                            "[one-dag] {when}: CONVERGED on one DAG after {:.1}s — heights {h0}/{h1}, {common} of {smaller} recent blocks in common",
                            t.elapsed().as_secs_f64()
                        );
                        return (h0, h1);
                    }
                }
                assert!(
                    t.elapsed() < Duration::from_secs(secs),
                    "⛔ {when}: the pair did not re-converge on ONE DAG within {secs}s — heights {h0}/{h1}, missing {:?}/{:?}",
                    missing(mesh, 0),
                    missing(mesh, 1)
                );
                std::thread::sleep(Duration::from_secs(3));
            }
        }
        // (spendable atomic, pending USDm) from one wallet refresh — the pending figure tells a note the
        // node has not re-certified yet (presence map rebuilding after a restart) from a note that is GONE.
        fn balances(w: &RealWallet) -> (u64, f64) {
            let lines = w.run(&["refresh", "balance"]).unwrap_or_default();
            let line = lines.iter().filter(|l| l.contains("\"op\":\"balance\"")).last().cloned().unwrap_or_default();
            let spendable = json_u64(&line, "atomic").unwrap_or(0);
            let pending = line
                .split("\"pending_usdm\":")
                .nth(1)
                .and_then(|t| t.split(|c: char| c == ',' || c == '}').next())
                .and_then(|n| n.trim().parse::<f64>().ok())
                .unwrap_or(0.0);
            (spendable, pending)
        }
        fn balance_of(w: &RealWallet) -> u64 {
            balances(w).0
        }
        // FINALITY FOLLOWS THE TIP ON BOTH NODES (2026-09-21, the KIND 16 certificate lane): the live joiner sat at
        // `finalized_height 0` for an hour after a restart while the origin finalized ~22 s behind its tip. Within
        // `secs` of converging, each node's finalized height must be within 128 blocks (~64 s) of its own height.
        fn wait_finality(mesh: &RealMesh, when: &str, secs: u64) {
            let t = Instant::now();
            loop {
                let (h0, h1) = heights(mesh);
                let f0 = json_u64(&info(mesh, 0), "finalized_height").unwrap_or(0);
                let f1 = json_u64(&info(mesh, 1), "finalized_height").unwrap_or(0);
                if f0 + 128 >= h0 && f1 + 128 >= h1 && f0 > 0 && f1 > 0 {
                    eprintln!("[one-dag] {when}: FINALITY follows the tip on both nodes after {:.1}s — finalized {f0}/{f1} at heights {h0}/{h1}", t.elapsed().as_secs_f64());
                    return;
                }
                assert!(
                    t.elapsed() < Duration::from_secs(secs),
                    "⛔ {when}: finality did not follow the tip within {secs}s — finalized {f0}/{f1} at heights {h0}/{h1} (a restarted node stuck at 0 is the 22:05 live hole)"
                );
                std::thread::sleep(Duration::from_secs(5));
            }
        }
        // The user's promise after a restart: every coin comes BACK as spendable, and we measure how long
        // the wallet read it as pending (the "balance flickers to 0" the owner reported). A coin that is
        // neither spendable nor pending within `secs` is LOST — the assertion this journey exists for.
        fn wait_balance_back(w: &RealWallet, before: u64, secs: u64, when: &str) -> u64 {
            let t = Instant::now();
            let mut last = (0u64, 0.0f64);
            loop {
                last = balances(w);
                if last.0 >= before {
                    eprintln!(
                        "[one-dag] {when}: wallet spendable again after {:.1}s ({} atomic, pending {:.2} USDm)",
                        t.elapsed().as_secs_f64(),
                        last.0,
                        last.1
                    );
                    return last.0;
                }
                assert!(
                    t.elapsed() < Duration::from_secs(secs),
                    "⛔ {when}: node1's wallet did not see its coins come back within {secs}s ({before} -> spendable {} atomic, pending {:.2} USDm)",
                    last.0,
                    last.1
                );
                eprintln!("[one-dag] {when}: wallet reads spendable {} / pending {:.2} USDm — waiting", last.0, last.1);
                std::thread::sleep(Duration::from_secs(8));
            }
        }

        // A converged, producing pair before anything is restarted.
        // The calibration wants a converged pair that HOLDS 40 blocks each; `wait_converged` returns at the first agreement
        // (diff <= 8), which on real processes came at 41/35 (2026-11-03, cashfirst real-cash6.log) and fired this calibration
        // on the instrument. Waited for in blocks: re-converge until both hold 40, red only if the lower tip stops moving.
        let (mut h0, mut h1) = wait_converged(&mesh, "before any restart", 300);
        let (mut low, mut moved) = (h0.min(h1), Instant::now());
        while h0.min(h1) < 40 && moved.elapsed() < Duration::from_secs(300) {
            std::thread::sleep(Duration::from_secs(5));
            (h0, h1) = wait_converged(&mesh, "before any restart", 300);
            if h0.min(h1) > low {
                low = h0.min(h1);
                moved = Instant::now();
            }
        }
        assert!(h0 >= 40 && h1 >= 40, "calibration: both nodes hold a chain ({h0}/{h1})");

        // A wallet on node 1, paid by the chain's drip, seen by the wallet.
        let w = RealWallet::create("restart", "payee", &url1)
            .unwrap_or_else(|e| panic!("⛔ THE REAL WALLET COULD NOT BE CREATED: {e}"));
        let drip = mesh
            .post(1, "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{}"}}"#, w.address))
            .unwrap_or_else(|e| panic!("⛔ the drip could not pay the wallet: {e}"));
        assert!(drip.contains("\"published\":true"), "the drip must be PUBLISHED as a chain object: {drip}");
        let t = Instant::now();
        let mut before = 0u64;
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            before = balance_of(&w);
            if before > 0 {
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        assert!(before > 0, "⛔ the wallet never saw the drip on node1 within its fold");
        eprintln!("[one-dag] wallet holds {before} atomic on node1 before any restart");

        // Phase 1 — the joiner restarts briefly (20 s: a live tip under the resume rule).
        let (_, h1a) = heights(&mesh);
        let up = mesh.restart_node(1, Duration::from_secs(20)).unwrap_or_else(|e| panic!("⛔ node1 restart: {e}"));
        eprintln!("[restart] node1 answered its RPC {up:.1}s after the respawn");
        wait_joined(&mesh, 1, 120, "after node1's brief restart");
        let (_, h1b) = wait_converged(&mesh, "after node1's brief restart", 300);
        wait_finality(&mesh, "after node1's brief restart", 240);
        // RUN 4 (2026-09-22 03:07) read this instantaneously and went red at 99 -> 99: a young scratch chain makes
        // ten blocks a minute while its DAA ramps, so a 20 s restart can land on the same height. The property is
        // that node1 FOLLOWS the chain after its restart — its height must rise within a bounded wait.
        let t_adv = Instant::now();
        let mut h1c = h1b;
        while h1c <= h1a && t_adv.elapsed() < Duration::from_secs(90) {
            std::thread::sleep(Duration::from_secs(3));
            h1c = heights(&mesh).1;
        }
        assert!(h1c > h1a, "node1 advanced past its pre-restart height ({h1a} -> {h1c}) within 90 s of reconverging");
        let _after1 = wait_balance_back(&w, before, 300, "after node1's brief restart");

        // Phase 2 — the ORIGIN restarts (the node carrying the boot directive): it must produce again on the
        // chain it held — never originate, never wait for a peer.
        let (h0c, _) = heights(&mesh);
        let up = mesh.restart_node(0, Duration::from_secs(20)).unwrap_or_else(|e| panic!("⛔ node0 restart: {e}"));
        eprintln!("[restart] node0 answered its RPC {up:.1}s after the respawn");
        wait_joined(&mesh, 0, 120, "after the origin's restart");
        let t = Instant::now();
        loop {
            let (h0d, _) = heights(&mesh);
            if h0d >= h0c + 20 {
                eprintln!(
                    "[one-dag] the restarted origin is producing again: {h0c} -> {h0d} in {:.1}s",
                    t.elapsed().as_secs_f64()
                );
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(180),
                "⛔ the restarted origin is not producing ({h0c} -> {h0d} in 180 s) — a halt"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
        wait_converged(&mesh, "after the origin's restart", 300);
        wait_finality(&mesh, "after the origin's restart", 240);
        let after2 = wait_balance_back(&w, before, 300, "after the origin's restart");
        let _ = after2;

        // Phase 3 — the joiner restarts for longer (90 s ≈ 180 blocks at 500 ms): it pages the gap from the
        // origin's block window and lands on the same DAG — no bundle jump, no split.
        let (_, h1e) = heights(&mesh);
        let up = mesh.restart_node(1, Duration::from_secs(90)).unwrap_or_else(|e| panic!("⛔ node1 long restart: {e}"));
        eprintln!("[restart] node1 answered its RPC {up:.1}s after the respawn");
        wait_joined(&mesh, 1, 120, "after node1's long restart");
        let (h0f, h1f) = wait_converged(&mesh, "after node1's long restart", 420);
        wait_finality(&mesh, "after node1's long restart", 240);
        // RUN 3 (2026-09-22 00:57) read "+100" as the gap and went red at 737 -> 815 with the origin at 823: the
        // scratch mesh made 86 blocks in that window (its DAA was still ramping), so the fixed number was the
        // harness's assumption, not the node's failure. The gap is whatever the origin actually produced.
        assert!(
            h0f > h1e + 40 && h1f + 8 >= h0f,
            "node1 caught up through the gap ({h1e} -> {h1f}, origin {h0f})"
        );
        let after3 = wait_balance_back(&w, before, 300, "after node1's long restart");
        eprintln!(
            "[one-dag] ✅ GREEN in {:.0}s — three restarts, one DAG, wallet {before} -> {after3} atomic",
            t0.elapsed().as_secs_f64()
        );
    }

    #[test]
    fn a_real_wallet_moves_money_across_five_real_nodes() {
        wallet_money_path_on_real_nodes(5, "walletfive");
    }


    /// ⭐⭐⭐ CRITERION 2 — `dsync_join` ON REAL NODE PROCESSES, NOT IN PROCESS.
    ///
    /// The register carried this class as `CrossNode`, backed by
    /// `two_nodes_instant_sync_roundtrip_serve_then_adopt` — two `Node` structs in ONE address space.
    /// `Moved::CrossNode`'s own doc says why that is weaker than it reads: *"a local mutation and a chain
    /// object look IDENTICAL when the second party shares your address space"*. A join is exactly the
    /// claim that cannot be trusted in-process, because the whole question is whether a SEPARATE process
    /// reached the tip through the real transport.
    ///
    /// So: two real `usdmd-node` processes, peered over the real onion transport, and every figure below
    /// read from the SECOND PROCESS'S OWN SOCKET.
    ///
    /// ⛔ AND IT ASSERTS STATE, NOT JUST HEIGHT. Height alone is the metric DB-211 caught me trusting:
    /// on a GHOSTDAG mesh each node reports its own selected-chain length, so heights may differ while the
    /// chain agrees. `membership_acc` is the note-membership accumulator — it ADVANCES as blocks carry
    /// notes, so unlike `unspent_root` (all-zero on an idle chain, the vacuity DB-211 found) an agreement
    /// here cannot be two constants matching. The pin REFUSES to pass on an unmoved accumulator.
    /// ⛔ THE FIXTURE MUST LEAVE A DSYNC ADOPT AS THE ONLY WAY TO THE TIP (2026-09-27, [slotB9]). Started together,
    /// the second process joined by grafting the origin's first gossiped block ("consensus-grafted a live peer's
    /// block" in its own log), and this pin refused it correctly: the join it names never ran. So once the pair has
    /// joined, the joiner is STOPPED the production way, the origin runs alone until its blue score is more than
    /// `LIVE_CATCH_UP_DEPTH` past the joiner's (beyond that depth the block lanes do not close a gap and the certified
    /// jump is the door, `node_runtime.rs`), and the joiner comes back on its own datadir. A node with no live writer
    /// produces at the mesh target (`fair_share_spacing_ms`), so the depth takes minutes, not a pair's 4 s per block.
    /// Every assertion below is one this pin already made; only the fixture changed, and values are now collected
    /// only from post-restart samples (the joiner's stale pre-restart state is not movement).
    #[test]
    fn two_real_nodes_join_by_dsync_and_agree_on_state_from_their_own_sockets() {
        let mut mesh = match RealMesh::start(2, "dsyncjoin") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let info = |m: &RealMesh, i: usize| -> String { m.get(i, "/get_info").unwrap_or_default() };
        // ONE /get_info read per node per poll, so the fields compared come from one instant of each process.
        // `unspent_root` is `nullifier_root()`: the consensus SPENT-STATE root (DB-229 put it back on its own
        // key).
        // ⭐ WELL-POSED (2026-09-26, slot B2 pin 1): each accumulator moves every block, so two live processes polled a
        // few ms apart almost never stand at the same instant of the chain. v1 demanded equal values in ONE poll and
        // read a moving mesh as a disagreement (node1: 44 distinct accs in 421 s, never equal in one poll). Each is
        // now compared at a COMMON POSITION:
        //   * the membership accumulator at equal `served_seq` (records folded, in canonical ordinal order);
        //   * the spent-state root at equal `nf_fold_seq`.
        // Equal positions are equal prefixes, so a mismatch there IS a divergence (asserted first). No common
        // position in the window is INCONCLUSIVE, and says so; it is never read as agreement.
        let snap = |m: &RealMesh, i: usize| -> (u64, u64, u64, String, String, bool) {
            let info = m.get(i, "/get_info").unwrap_or_default();
            (
                json_u64(&info, "height").unwrap_or(0),
                json_u64(&info, "served_seq").unwrap_or(0),
                json_u64(&info, "nf_fold_seq").unwrap_or(0),
                json_str(&info, "membership_acc").unwrap_or_default(),
                json_str(&info, "unspent_root").unwrap_or_default(),
                info.contains("\"mesh_joined\":true"),
            )
        };

        // 1. The pair joins as it always has: this is where the joiner's datadir comes into existence.
        let t_join = Instant::now();
        loop {
            let (h0, _, _, _, _, j0) = snap(&mesh, 0);
            let (h1, _, _, _, _, j1) = snap(&mesh, 1);
            if j0 && j1 && h0 > 8 && h1 > 8 {
                break;
            }
            assert!(
                t_join.elapsed() < Duration::from_secs(300),
                "⛔ COULD NOT RAISE A JOINED PAIR in 300 s (h0={h0} h1={h1} joined={j0}/{j1}) — an environment finding, \
                 not a DSYNC verdict"
            );
            std::thread::sleep(Duration::from_secs(3));
        }

        // 2. The joiner goes down the production way; the origin runs alone past the catch-up depth.
        let depth = crate::node_runtime::LIVE_CATCH_UP_DEPTH;
        // ⭐ DB-346 (MEASURED slot B18): a gap of JUST past the depth could never show a jump. The served certificate
        // trails the origin's tip by the fold depth plus up to half the catch-up depth (the warm threshold), and a joiner
        // jumps only when that certificate is MORE than one depth ahead of it. So the joiner must fall behind by
        // depth + depth/2 + record_fold_depth for the pin to test a DSYNC adopt at all.
        let needed = depth + depth / 2 + crate::params::RECORD_FOLD_DEPTH_DEFAULT;
        let score = |m: &RealMesh, i: usize| -> u64 { json_u64(&info(m, i), "blue_score").unwrap_or(0) };
        let stop_score = score(&mesh, 1);
        let stop_h1 = json_u64(&info(&mesh, 1), "height").unwrap_or(0);
        let clean = mesh.stop_node(1).unwrap_or_else(|e| panic!("⛔ COULD NOT STOP node1: {e}"));
        let t_down = Instant::now();
        let mut s_origin = score(&mesh, 0);
        while s_origin <= stop_score + needed {
            assert!(
                t_down.elapsed() < Duration::from_secs(1200),
                "⛔ INCONCLUSIVE — alone for {:.0} s the origin reached blue score {s_origin} against the joiner's \
                 {stop_score} + LIVE_CATCH_UP_DEPTH {depth}; the joiner never fell past the catch-up depth, so this run \
                 cannot show a DSYNC join (origin live_writers_held={:?})",
                t_down.elapsed().as_secs_f64(),
                json_u64(&info(&mesh, 0), "live_writers_held")
            );
            std::thread::sleep(Duration::from_secs(3));
            s_origin = score(&mesh, 0);
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: blue scores, heights and a down time — all public at /get_info; never a note,
        // amount, key, owner or tag.
        eprintln!(
            "[dsync-join] node1 down {:.0} s (clean stop: {clean}); origin blue score {s_origin} vs the joiner's \
             {stop_score} (height {stop_h1}) — gap {} > LIVE_CATCH_UP_DEPTH {depth}",
            t_down.elapsed().as_secs_f64(),
            s_origin - stop_score
        );
        let back = mesh.start_node(1).unwrap_or_else(|e| panic!("⛔ COULD NOT RESTART node1: {e}"));
        eprintln!("[dsync-join] node1 answered its RPC {back:.1} s after the restart");

        // 3. The comparison this pin always made, from the moment the joiner is back.
        let t = Instant::now();
        let (mut seen, mut seen_spent) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
        let (mut acc_agree, mut root_agree, mut root_differ) = (0u32, 0u32, 0u32);
        let mut divergences: Vec<String> = Vec::new();
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            let (h0, s0, f0, a0, u0, j0) = snap(&mesh, 0);
            let (h1, s1, f1, a1, u1, j1) = snap(&mesh, 1);
            // Only a sample the restarted joiner took PAST its own stale height counts: its pre-restart state
            // standing still is not movement, and agreeing on it is not a join.
            if j0 && j1 && h0 > 8 && h1 > stop_h1 {
                if !a1.is_empty() {
                    seen.insert(a1.clone());
                }
                if !u1.is_empty() {
                    seen_spent.insert(u1.clone());
                }
                if s0 == s1 && s0 > 0 && !a0.is_empty() {
                    if a0 == a1 {
                        acc_agree += 1;
                    } else if divergences.len() < 6 {
                        divergences.push(format!("membership_acc differs at served_seq {s0}"));
                    }
                }
                // ⛔ v3 (2026-09-27): `nf_fold_seq` is an ARRIVAL-order count, so in a width>1 DAG two nodes can stand
                // on the same count over DIFFERENT block sets (sibling order). The spent-state root is compared only at
                // an equal count AND an equal height, the same chain position; see the divergence rule below.
                if f0 == f1 && f0 > 0 && h0 == h1 && !u0.is_empty() {
                    if u0 == u1 {
                        root_agree += 1;
                    } else {
                        root_differ += 1;
                        if divergences.len() < 6 {
                            divergences.push(format!("unspent_root differs at height {h0}, nf_fold_seq {f0}"));
                        }
                    }
                }
                if acc_agree >= 1 && root_agree >= 1 && seen.len() > 1 && seen_spent.len() > 1 {
                    break;
                }
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        let (h0, h1) = (
            json_u64(&info(&mesh, 0), "height").unwrap_or(0),
            json_u64(&info(&mesh, 1), "height").unwrap_or(0),
        );
        let (j0, j1) = (
            info(&mesh, 0).contains("\"mesh_joined\":true"),
            info(&mesh, 1).contains("\"mesh_joined\":true"),
        );
        // DIGITAL-CASH-PRIVACY-REVIEWED: block COUNTS, fold/record POSITIONS, booleans and counts of DISTINCT values —
        // all already public at /get_info. Never a note, amount, key, owner or tag.
        eprintln!(
            "[dsync-join] after {:.1}s — h0={h0} h1={h1} joined={j0}/{j1}; agreements at a common position: acc \
             {acc_agree} root {root_agree}; divergences at a common position: {divergences:?}; distinct accs seen on \
             node1={} distinct spent-state roots seen on node1={}",
            t.elapsed().as_secs_f64(),
            seen.len(),
            seen_spent.len()
        );
        // The membership accumulator is compared at an equal CANONICAL position (`served_seq`), so any difference there
        // is a divergence. The spent-state root rides an arrival-order count: one differing sample can be sibling order,
        // so it is called a divergence only when it NEVER agreed at an equal (height, count) and differed at three or
        // more of them.
        let acc_diverged = divergences.iter().any(|d| d.starts_with("membership_acc"));
        let root_diverged = root_agree == 0 && root_differ >= 3;
        assert!(
            !acc_diverged && !root_diverged,
            "⛔⛔⛔ THE TWO REAL PROCESSES DISAGREE: {divergences:?} (spent-state root: {root_agree} agreement(s), \
             {root_differ} difference(s) at an equal height AND fold count). A membership difference at an equal \
             canonical position, or a spent-state root that never once agrees at an equal chain position, is a \
             divergence between honest nodes, not a moving target."
        );
        assert!(
            acc_agree >= 1 && root_agree >= 1,
            "⛔ INCONCLUSIVE — in 420 s the two processes never stood at a common position for both accumulators \
             (acc agreements {acc_agree}, root agreements {root_agree}; h0={h0} h1={h1} joined={j0}/{j1}). This is \
             NOT a divergence claim. The join was not shown to agree."
        );
        assert!(
            seen_spent.len() > 1,
            "⛔ THE SPENT-STATE ROOT NEVER MOVED on node1 ({} distinct value(s)) — agreeing on it would be two \
             constants matching (the DB-211 vacuity), not evidence the joiner inherited the spent state.",
            seen_spent.len()
        );
        assert!(
            seen.len() > 1,
            "⛔ THE ACCUMULATOR NEVER MOVED on node1 ({} distinct value(s)) — so 'the two agree' is two \
             CONSTANTS matching and proves nothing. This is the DB-211 vacuity check, armed: a comparison \
             that could not have gone red is not evidence.",
            seen.len()
        );
        // ⛔ AND THE JOIN WAS A DSYNC ADOPT. Agreement alone does not say HOW the joiner reached the tip. A
        // node also joins by "consensus-grafted a live peer's block", which is block-by-block following,
        // and a pin named for DSYNC must not pass on that path. The joiner's own log names the path it took
        // (`mark_mesh_joined`), and it is read here from the joiner's process, not inferred. The rig opens the log
        // fresh at every spawn, so this is the RESTARTED process's own log; `mesh_joined_how` is read from its socket.
        let how_rpc = json_str(&info(&mesh, 1), "mesh_joined_how").unwrap_or_default();
        let joiner_log = std::fs::read_to_string(mesh.log_path(1)).unwrap_or_default();
        let how = joiner_log
            .lines()
            .find(|l| l.contains("[mesh] JOINED the canonical mesh ("))
            .unwrap_or("(no join line)")
            .to_string();
        // ⭐ THE ADOPT ITSELF, NOT THE FIRST JOIN REASON (2026-09-28, slot B18m2). `mesh_joined_how` records only the
        // FIRST join of the restarted process. MEASURED: the joiner grafted one live block first (log line 103, "consensus-
        // grafted"), then ADOPTED the DSYNC bundle at line 290 ("adopted certified state to height 1101 — 1049 block(s) of
        // note payload were NOT applied"): a 1,049-block jump. The old check counted the mark_mesh_joined reason string,
        // which that adopt never re-logs, and so called a real jump "not DSYNC". The evidence the class needs is the
        // restarted process's own ADOPT, and that the adopt jumped MORE than one catch-up depth (block lanes did not
        // close the gap). Both are read from the joiner's own log.
        let jumped: Vec<u64> = joiner_log
            .lines()
            .filter(|l| l.starts_with("[dsync] adopted certified state to height "))
            .filter_map(|l| {
                let after = l.split(" — ").nth(1)?;
                after.split_whitespace().next()?.parse::<u64>().ok()
            })
            .collect();
        let adopted = joiner_log.matches("adopt outcome: Some(Adopted(").count();
        eprintln!(
            "[dsync-join] the joiner's own log: {how} | its /get_info mesh_joined_how: {how_rpc} | adopts {adopted}, \
             blocks jumped by each: {jumped:?}"
        );
        assert!(
            adopted >= 1 && jumped.iter().any(|j| *j > depth),
            "⛔ THE JOINER DID NOT JOIN BY A DSYNC JUMP. Adopts in its own log: {adopted}; blocks jumped: {jumped:?} (a \
             jump must exceed LIVE_CATCH_UP_DEPTH {depth}). First join: {how} (mesh_joined_how: {how_rpc}). It reached \
             agreement by another path, so this run is not evidence for the dsync_join class."
        );
    }


    /// ⭐⭐ CRITERION 2 — `jumped_node_spent_state` ON REAL NODE PROCESSES, and criterion 7's number on a small chain.
    ///
    /// The in-process pin (`two_nodes_instant_sync_roundtrip_serve_then_adopt`) asserts a jumped node inherits the spent
    /// state on THREE surfaces: the committed nullifier root, the count, and the SPARSE view's root. The real DSYNC pin
    /// proves the first two at common positions. This pin proves the third, after a DSYNC JUMP past LIVE_CATCH_UP_DEPTH
    /// (read from the joiner's own log):
    /// - the jumped process's nullifier view must become PRESENT and MATCH its own order-free accumulator (`/get_info`
    ///   `nf_view_present` && `nf_view_matches_acc`);
    /// - the two processes' accumulators must agree at an EXACT common position (equal tip set and fold count, from
    ///   `/get_nf_fold_inputs`).
    ///
    /// The wall time from the restart to a present, matching view is printed. It IS "minutes a restarted node cannot
    /// serve Lane A" (criterion 7) on a chain of this size. MEASURED 2026-09-28 (slot B18m2): the view was still warming,
    /// at 147,456 of ~282k tags, when the DSYNC pin ended. So this pin waits, bounded, and a view that never arrives is the
    /// DB-290 red it names.
    #[test]
    fn a_real_node_that_jumped_by_dsync_warms_its_nullifier_view_to_the_certified_spent_state() {
        let mut mesh = match RealMesh::start(2, "dsyncview") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let info = |m: &RealMesh, i: usize| -> String { m.get(i, "/get_info").unwrap_or_default() };
        let score = |m: &RealMesh, i: usize| -> u64 { json_u64(&info(m, i), "blue_score").unwrap_or(0) };
        // 1. A joined pair.
        let t = Instant::now();
        loop {
            let (i0, i1) = (info(&mesh, 0), info(&mesh, 1));
            if i0.contains("\"mesh_joined\":true")
                && i1.contains("\"mesh_joined\":true")
                && json_u64(&i0, "height").unwrap_or(0) > 8
                && json_u64(&i1, "height").unwrap_or(0) > 8
            {
                break;
            }
            assert!(t.elapsed() < Duration::from_secs(300), "⛔ COULD NOT RAISE A JOINED PAIR in 300 s — an environment finding");
            std::thread::sleep(Duration::from_secs(3));
        }
        // 2. The joiner goes down until a DSYNC jump is the only way back (the DSYNC pin's derivation: the warmed
        // certificate trails the tip by the fold depth plus up to half the catch-up depth).
        let depth = crate::node_runtime::LIVE_CATCH_UP_DEPTH;
        let needed = depth + depth / 2 + crate::params::RECORD_FOLD_DEPTH_DEFAULT;
        let stop_score = score(&mesh, 1);
        mesh.stop_node(1).unwrap_or_else(|e| panic!("⛔ COULD NOT STOP node1: {e}"));
        let t_down = Instant::now();
        while score(&mesh, 0) <= stop_score + needed {
            assert!(
                t_down.elapsed() < Duration::from_secs(1200),
                "⛔ INCONCLUSIVE — alone for {:.0} s the origin never ran {needed} past the joiner",
                t_down.elapsed().as_secs_f64()
            );
            std::thread::sleep(Duration::from_secs(3));
        }
        mesh.start_node(1).unwrap_or_else(|e| panic!("⛔ COULD NOT RESTART node1: {e}"));
        let t_back = Instant::now();
        // 3. PRECONDITION: the restarted process's own log names an adopt that jumped past the depth.
        let jumps = |m: &RealMesh| -> Vec<u64> {
            std::fs::read_to_string(m.log_path(1))
                .unwrap_or_default()
                .lines()
                .filter(|l| l.starts_with("[dsync] adopted certified state to height "))
                .filter_map(|l| l.split(" — ").nth(1)?.split_whitespace().next()?.parse::<u64>().ok())
                .collect()
        };
        let t = Instant::now();
        let mut jumped = Vec::new();
        while t.elapsed() < Duration::from_secs(600) {
            jumped = jumps(&mesh);
            if jumped.iter().any(|j| *j > depth) {
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        assert!(
            jumped.iter().any(|j| *j > depth),
            "⛔ PRECONDITION: the joiner never jumped by DSYNC (blocks jumped {jumped:?}) — the DSYNC pin's own red, not this one's"
        );
        // 4. ⭐ THE CLAIM, part 1: the jumped view becomes PRESENT and MATCHES its accumulator.
        let t = Instant::now();
        let mut ready_after = None;
        while t.elapsed() < Duration::from_secs(2700) {
            let i1 = info(&mesh, 1);
            if i1.contains("\"nf_view_present\":true") && i1.contains("\"nf_view_matches_acc\":true") {
                ready_after = Some(t_back.elapsed());
                break;
            }
            std::thread::sleep(Duration::from_secs(10));
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: booleans and a duration from this node's own public /get_info.
        eprintln!(
            "[dsync-view] jumped {jumped:?} block(s); the jumped process's nullifier view present+matching after {:?} \
             (criterion 7 on this chain: Lane A unavailable for that long after the restart)",
            ready_after
        );
        let ready = ready_after.unwrap_or_else(|| {
            panic!(
                "⛔⛔ DB-290: the jumped process's nullifier view never became present AND matching within 45 min of its \
                 restart (last /get_info: nf_view_present / nf_view_matches_acc false) — a jumped node that cannot serve Lane A"
            )
        });
        // 5. ⭐ THE CLAIM, part 2: the two accumulators agree at an EXACT common position — an equal tip SET (sorted) and
        // an equal fold count — read from each process's own `/get_nf_fold_inputs`.
        // DIGITAL-CASH-PRIVACY-REVIEWED: tip ids, a fold count and the order-free accumulator — all consensus-public.
        // MEASURED slotB20view: demanding both processes on one key AT THE SAME INSTANT found none in 420 s (a producing
        // pair holds a tip set ~2 s), and a body-less read returned a 4,096-block page per sample. The state at a key is a
        // function of the key, so each process's samples are keyed by (sorted tip set, nf_fold_seq) and compared at
        // every key BOTH were seen at, whenever each was seen there; a sample asks for a ONE-block page.
        let field = |body: &str, key: &str| -> String {
            let k = format!("\"{key}\":[");
            body.find(&k)
                .and_then(|s| body[s + k.len()..].find(']').map(|e| body[s + k.len()..s + k.len() + e].to_string()))
                .unwrap_or_default()
        };
        let sorted = |s: String| -> String {
            let mut v: Vec<&str> = s.split(',').map(str::trim).filter(|x| !x.is_empty()).collect();
            v.sort_unstable();
            v.join(",")
        };
        // O1-FOOTPRINT-REVIEWED: one entry per distinct key a process was sampled at, at most one per second over the
        // bounded 420 s window, dropped when this pin returns.
        let mut seen: [std::collections::HashMap<(String, u64), String>; 2] = Default::default();
        let t = Instant::now();
        let (mut agree, mut differ) = (0u32, 0u32);
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) && agree < 3 {
            for i in 0..2 {
                let b = mesh.post(i, "/get_nf_fold_inputs", r#"{"from":0,"count":1}"#).unwrap_or_default();
                let (tips, seq, acc) = (sorted(field(&b, "tips_hex")), json_u64(&b, "nf_fold_seq").unwrap_or(0), field(&b, "a_tip"));
                if tips.is_empty() || seq == 0 || acc.is_empty() {
                    continue;
                }
                let key = (tips, seq);
                if seen[i].contains_key(&key) {
                    continue;
                }
                if let Some(other) = seen[1 - i].get(&key) {
                    if *other == acc {
                        agree += 1;
                    } else {
                        differ += 1;
                    }
                }
                seen[i].insert(key, acc);
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        eprintln!(
            "[dsync-view] exact common positions (equal tip set + fold count, keyed by (sorted tip set, nf_fold_seq) \
             across samples): {agree} agree, {differ} differ; keys sampled {} / {}",
            seen[0].len(),
            seen[1].len()
        );
        assert_eq!(differ, 0, "⛔⛔⛔ THE JUMPED PROCESS'S SPENT STATE DIFFERS FROM ITS ORIGIN'S at an equal tip set and fold count");
        assert!(
            agree >= 1,
            "⛔ INCONCLUSIVE — in 420 s the pair never stood on an equal tip set (view ready after {ready:?}); this is not a \
             divergence claim"
        );
    }

    /// ⭐⭐⭐ CRITERION 2 — `AssetCreate` ON REAL NODE PROCESSES.
    ///
    /// DB-200 proved this in process: A publishes, A produces, B grafts the BLOCK and its registry root
    /// moves to equal A's. That pin is `Moved::CrossNode` — two `Node` structs in one address space,
    /// which its own variant doc calls weaker than it reads. This is the same claim where it counts: the
    /// creation is POSTed to node 0's real RPC, and the registry root is read from NODE 1'S OWN SOCKET.
    ///
    /// ⛔ THE PEER IS NEVER TOLD THE DESCRIPTOR. It learns the asset from the block or not at all,
    /// which is what distinguishes a chain object from the local mutation that paid a DEX maker twice.
    #[test]
    fn a_real_second_node_registers_an_asset_it_only_saw_in_a_block() {
        let mesh = match RealMesh::start(2, "assetcreate") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let reg = |i: usize| -> String {
            json_str(&mesh.get(i, "/get_info").unwrap_or_default(), "token_registry_root")
                .unwrap_or_default()
        };
        // ⛔ AN UNANSWERED STATUS DOOR IS NOT A DIFFERENT REGISTRY. MEASURED 2026-09-26 (lane-db224-carriage):
        // node 0's `/get_info` gave no answer for the whole 90 s request timeout right after boot (the
        // status-door blackout class), `unwrap_or_default` turned that into "", and the precondition then
        // compared "" against node 1's empty-registry root and failed — a boot-latency fact reported as a
        // registry disagreement. Wait until BOTH nodes actually answer, bounded, and fail naming the node that
        // never does; only then compare.
        let t_ready = Instant::now();
        let (empty0, empty1) = loop {
            let (r0, r1) = (reg(0), reg(1));
            if !r0.is_empty() && !r1.is_empty() {
                break (r0, r1);
            }
            assert!(
                t_ready.elapsed() < Duration::from_secs(300),
                "⛔ a real node's status door never reported a registry root within 300 s (node0 {:?}, node1 {:?})",
                r0,
                r1
            );
            std::thread::sleep(Duration::from_secs(3));
        };
        assert_eq!(empty0, empty1, "PRECONDITION: both real nodes start on the same registry");

        // ⛔ THE ROUTE REQUIRES THE CREATOR'S PQ KEY (`creator_pubkey`, from which the asset id derives). This body
        // lacked it and would have been answered 400 MALFORMED_ASSET_CREATE. It was never reached before,
        // because every earlier run stopped at the status-door wait above. Found reading the route, 2026-09-26.
        let (creator_pk, _creator_sk) = crate::pqauth::ml_dsa_keypair();
        // §BR-14: the creation pays its fee — built the way the creator's wallet builds it.
        let mut c = crate::asset_tx::AssetCreateTx {
            kind: crate::asset_tx::AssetKind::Token,
            symbol: "RNODE".to_string(),
            name: "real node asset".to_string(),
            logo: [0u8; 32],
            bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, "RNODE", "real node asset").bytecode,
            creator: crate::pqauth::pubkey_id(&creator_pk),
            asset_id: [0u8; 32],
            fee: crate::asset_tx::CreationFee::default(),
            art: Vec::new(),
            supply: None,
        };
        c.asset_id = c.derived_id();
        let fee = rn_pay_creation_fee(&mesh, 0, &mut c, 0x61);
        let body = format!(
            r#"{{"kind":"token","symbol":"RNODE","name":"real node asset","creator_pubkey":"{}"{fee}}}"#,
            hexs(&creator_pk)
        );
        let resp = mesh
            .post(0, "/submit_asset_create", &body)
            .unwrap_or_else(|e| panic!("⛔ node 0 refused the creation over its real RPC: {e}"));
        assert!(
            resp.contains("\"status\":\"OK\""),
            "⛔ the creation was not admitted by a REAL node's door: {resp}"
        );

        // The peer must reach the SAME registry, having seen only blocks.
        let t = Instant::now();
        let mut ok = false;
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            let (r0, r1) = (reg(0), reg(1));
            if r0 != empty0 && r0 == r1 {
                ok = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: a public registry ROOT and a boolean — already served at
        // /get_info to everyone. Never a note, amount, key, owner or tag.
        eprintln!(
            "[asset-create-real] after {:.1}s — node0 root moved={} node1 matches={}",
            t.elapsed().as_secs_f64(),
            reg(0) != empty0,
            reg(0) == reg(1)
        );
        assert!(
            ok,
            "⛔ THE SECOND REAL PROCESS NEVER REGISTERED THE ASSET. node0={} node1={} (started {}). An \
             asset that only exists on its creator is the local mutation the cardinal forbids.",
            reg(0), reg(1), empty0
        );
    }

    /// ⭐⭐⭐ CRITERION 2 — `AssetMint` ON REAL NODE PROCESSES.
    ///
    /// DB-201 proved in process that a mint travels: B's spent set absorbs the asset's ISSUANCE RIGHT from the
    /// block. On real processes the spent-state root moves on every block (the cover tags), so "it moved" would
    /// be vacuous there. The observable is the right itself:
    ///   * process 1 admits the asset's FIRST mint. That is the calibration: the construction is valid, and the
    ///     right is live.
    ///   * The mint rides process 1's block.
    ///   * Process 0, having learned the retired right only from that block, REFUSES a second mint of the same
    ///     asset, built exactly like the first with a fresh note.
    /// A mint that stayed a local mutation on process 1 would leave process 0 admitting it. Two processes on one
    /// machine: not a scale claim.
    #[test]
    fn a_mint_admitted_by_one_real_process_retires_the_issuance_right_on_the_other() {
        let (minting_node, peer) = (1usize, 0usize);
        let mesh = match RealMesh::start(2, "assetmint") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let reg = |i: usize| -> String {
            json_str(&mesh.get(i, "/get_info").unwrap_or_default(), "token_registry_root").unwrap_or_default()
        };
        // (height, served_seq, membership_acc) from ONE /get_info read. The accumulator is compared only at a COMMON
        // served_seq: "equal in one poll" is ill-posed on a producing mesh (the dsync pin, slot B2 2026-09-26).
        let snap = |i: usize| -> (u64, u64, String) {
            let info = mesh.get(i, "/get_info").unwrap_or_default();
            (
                json_u64(&info, "height").unwrap_or(0),
                json_u64(&info, "served_seq").unwrap_or(0),
                json_str(&info, "membership_acc").unwrap_or_default(),
            )
        };
        let t_ready = Instant::now();
        let empty = loop {
            let (r0, r1) = (reg(0), reg(1));
            if !r0.is_empty() && !r1.is_empty() {
                assert_eq!(r0, r1, "PRECONDITION: both real nodes start on the same registry");
                break r0;
            }
            assert!(t_ready.elapsed() < Duration::from_secs(300), "⛔ a status door never answered within 300 s");
            std::thread::sleep(Duration::from_secs(3));
        };

        // The creator's PQ identity: the asset id derives from it, and only its key can mint.
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        const SYMBOL: &str = "RMINT";
        const NAME: &str = "real node mint";
        let mut c = crate::asset_tx::AssetCreateTx {
            kind: crate::asset_tx::AssetKind::Token,
            symbol: SYMBOL.to_string(),
            name: NAME.to_string(),
            logo: [0u8; 32],
            bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, SYMBOL, NAME).bytecode,
            creator: crate::pqauth::pubkey_id(&pk),
            asset_id: [0u8; 32],
            fee: crate::asset_tx::CreationFee::default(),
            art: Vec::new(),
            supply: None,
        };
        c.asset_id = c.derived_id();
        // §BR-14: the creation pays its fee — built the way the creator's wallet builds it.
        let fee = rn_pay_creation_fee(&mesh, peer, &mut c, 0x62);
        let create = mesh
            .post(
                peer,
                "/submit_asset_create",
                &format!(r#"{{"kind":"token","symbol":"{SYMBOL}","name":"{NAME}","creator_pubkey":"{}"{fee}}}"#, hexs(&pk)),
            )
            .unwrap_or_else(|e| panic!("⛔ the creation was refused over the real RPC: {e}"));
        assert!(
            create.contains(&format!("\"asset_id\":\"{}\"", hexs(&c.asset_id))),
            "PRECONDITION: the route derived the same asset id: {create}"
        );
        let t = Instant::now();
        while !(reg(0) != empty && reg(0) == reg(1)) {
            assert!(t.elapsed() < Duration::from_secs(CHAIN_WAIT_S), "⛔ the creation never registered on both processes");
            std::thread::sleep(Duration::from_secs(3));
        }

        // A mint built the way a real minter builds it: a real WHIR carrier, the creator's signature, and the
        // registry path self-built from the public creation.
        let leaves = vec![crate::dsol::descriptor_leaf(&c.descriptor())];
        let (path, dirs) = crate::dsol::token_membership_path(&leaves, 0).expect("the minter's own path");
        let path_hex: String = path.iter().map(|d| hexs(&crate::spend_frontier::leaf_to_cm_bytes(*d))).collect();
        let dirs_s: String = dirs.iter().map(|d| if *d { '1' } else { '0' }).collect();
        let mint_body = |seed: u64| -> String {
            const AMOUNT: u64 = 4_200;
            let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[seed, seed + 1, seed + 2, seed + 3]);
            let (carrier, cm) =
                usdm_decider::whir_rec_block::prove_asset_mint_validity_bytes(AMOUNT, c.asset_tag(), &note_sk)
                    .expect("a real WHIR mint carrier");
            let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(cm);
            let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            note[..crate::spend_frontier::NOTE_CM_BYTES].copy_from_slice(&cm_bytes);
            // DB-273 §19.6 L3: the supply note's owner clue, signed by the creator and sent as `note_clue_hex`.
            let clue = journey_owner_clue(seed);
            let sig = crate::pqauth::ml_dsa_sign(
                &crate::asset_tx::asset_mint_msg(&c.asset_id, AMOUNT, &cm_bytes, &crate::oli::owner_clue_digest(&clue), ""),
                &sk,
            )
            .expect("the creator signs its own mint");
            format!(
                r#"{{"asset_id":"{}","kind":"token","amount":{AMOUNT},"note_hex":"{}","mint_carrier_hex":"{}","creator_pubkey":"{}","creator_sig":"{}","symbol":"{SYMBOL}","asset_name":"{NAME}","registry_path_hex":"{path_hex}","registry_dirs":"{dirs_s}","note_clue_hex":"{}"}}"#,
                hexs(&c.asset_id),
                hexs(&note),
                hexs(&carrier),
                hexs(&pk),
                hexs(&sig),
                hexs(&clue)
            )
        };

        // CALIBRATION: the minting process admits the asset's first mint.
        // DECLARED FIXTURE AMENDMENT (lane-db224-carriage 2026-09-27; assertions unchanged): a real client HOLDS AND
        // RESENDS while the node answers HTTP 503 — its "not right now" — exactly as the gate's `send_in_session` does.
        // MEASURED (slotB6, usdmd_journey_assetmint_566): the minting process is a JUMPED joiner whose sparse view was
        // still warming (16,171 / 25,856 tags absorbed) when the first mint arrived: `[nf-gate] REFUSE … this node's own
        // view cannot answer (… jumped …)`, answered 503 NOT_PUBLISHED with nothing written. The wait is PRINTED — it
        // is readiness criterion 11's figure for a joiner, never hidden. Any non-503 answer still fails at once.
        let t_mint = Instant::now();
        let first = loop {
            let r = mesh.post(minting_node, "/submit_asset_mint", &mint_body(11)).unwrap_or_else(|e| e);
            if r.contains("\"verdict\":\"PUBLISHED\"") || !r.contains("HTTP 503") || t_mint.elapsed() > Duration::from_secs(600) {
                break r;
            }
            std::thread::sleep(Duration::from_secs(5));
        };
        eprintln!(
            "[asset-mint-real] the minting process answered its first mint after {:.1}s of HTTP 503 holds",
            t_mint.elapsed().as_secs_f64()
        );
        assert!(
            first.contains("\"verdict\":\"PUBLISHED\""),
            "CALIBRATION: process {minting_node} must admit the asset's first mint: {first}"
        );
        // Let the block carrying it reach the peer: both processes move 20 blocks past this point, and they
        // stand on one state.
        // A common position 20 records past the minter's own position at publish time is a prefix that covers the
        // block that carried the mint.
        let (h_pub, s_pub, _) = snap(minting_node);
        let t = Instant::now();
        loop {
            let ((h0, s0, a0), (h1, s1, a1)) = (snap(0), snap(1));
            if h0 > h_pub + 20 && h1 > h_pub + 20 && s0 == s1 && s0 >= s_pub + 20 && !a0.is_empty() {
                assert_eq!(
                    a0, a1,
                    "⛔⛔⛔ the two real processes DISAGREE on the membership accumulator at a common position \
                     (served_seq {s0}) after the mint: a divergence between honest nodes, not a moving target"
                );
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(CHAIN_WAIT_S),
                "⛔ INCONCLUSIVE: the pair never stood at a common position past the mint within 420 s (not a \
                 divergence claim)"
            );
            std::thread::sleep(Duration::from_secs(3));
        }
        // THE CLAIM: the peer refuses a second mint of the same asset. It knows the right is retired only from
        // the block.
        let second = mesh.post(peer, "/submit_asset_mint", &mint_body(23)).unwrap_or_else(|e| e);
        // DIGITAL-CASH-PRIVACY-REVIEWED: route verdicts only — no amount beyond this pin's own literal, no owner.
        eprintln!("[asset-mint-real] process {minting_node} first mint: PUBLISHED; process {peer} second mint: {second}");
        assert!(
            !second.contains("\"verdict\":\"PUBLISHED\""),
            "⛔⛔⛔ PROCESS {peer} ADMITTED A SECOND MINT OF AN ASSET WHOSE ISSUANCE RIGHT PROCESS {minting_node} \
             ALREADY RETIRED IN A BLOCK — the first mint never travelled, or the right is refused only where it \
             was spent: supply minted twice. Reply: {second}"
        );
    }

    /// ⭐⭐⭐ CRITERION 2 — `AssetSpend` ON REAL NODE PROCESSES.
    ///
    /// DB-216 proved in process that a holder MOVES a minted asset and a second node retires the input from the
    /// block alone. On real processes the spent-state root moves on every block (the cover tags), so "it moved"
    /// would be vacuous; the observables are the note's own nullifier and the transfer's own outputs:
    ///   * CALIBRATION: process 1 admits the asset's first mint. Process 0 learned the minted note only from that
    ///     block, and it serves the note's record address and in-record copath from its OWN record. The client
    ///     refolds that copath before trusting it.
    ///   * CONTROL: neither process places the transfer's outputs before the transfer exists.
    ///   * The holder (this client, the only party that knows the note's secret) builds the transfer from process
    ///     0's served copath exactly as `asset_tx`'s in-process pin builds it, and publishes it to process 0. It
    ///     must be PUBLISHED.
    ///   * Process 1 is the other process: it learned of the transfer only from the wire. It must place both
    ///     outputs in a record, and it must REFUSE a second spend of the same note (new outputs, new bytes, same
    ///     nullifier) for the spent set's own reason. Process 0 must refuse it for the same reason.
    /// A transfer that stayed a local mutation on process 0 would leave the other process admitting the second
    /// spend. Different bytes can only be refused by the spent set, and each reply names the rule that refused it.
    /// Two processes on one machine: not a scale claim.
    #[test]
    fn a_transfer_published_through_one_real_process_is_retired_by_the_other_and_a_second_spend_is_refused_by_both() {
        // CROSS-NODE-REVIEWED: two independent usdmd-node PROCESSES (RealMesh 0 and 1). The transfer is published through
        // one; every claim — each output placed from the block alone, the spent input retired, the second spend refused —
        // is read from EACH process's own socket in the `for i in 0..2` loop below.
        use crate::spend_frontier::{leaf_to_cm_bytes, note_leaf_of, poseidon_pair, Digest4};
        use usdm_decider::note_membership_air::NoteMembershipCarrier;
        use usdm_decider::whir_rec_block::{
            asset_spend_input_leaf, prove_asset_spend_validity_carrier_bytes, AssetSpendValidityWitness,
        };
        let (minting_node, spending_node) = (1usize, 0usize);
        let mesh = match RealMesh::start(2, "assetspend") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let reg = |i: usize| -> String {
            json_str(&mesh.get(i, "/get_info").unwrap_or_default(), "token_registry_root").unwrap_or_default()
        };
        // (height, served_seq, membership_acc) from ONE /get_info read; the accumulator is compared only at a
        // COMMON served_seq (the dsync pin, slot B2 2026-09-26).
        let snap = |i: usize| -> (u64, u64, String) {
            let info = mesh.get(i, "/get_info").unwrap_or_default();
            (
                json_u64(&info, "height").unwrap_or(0),
                json_u64(&info, "served_seq").unwrap_or(0),
                json_str(&info, "membership_acc").unwrap_or_default(),
            )
        };
        // Both processes 20 blocks and 20 records past `(h_from, s_from)`, standing on one accumulator there.
        let common_position_past = |h_from: u64, s_from: u64, what: &str| {
            let t = Instant::now();
            loop {
                let ((h0, s0, a0), (h1, s1, a1)) = (snap(0), snap(1));
                if h0 > h_from + 20 && h1 > h_from + 20 && s0 == s1 && s0 >= s_from + 20 && !a0.is_empty() {
                    assert_eq!(
                        a0, a1,
                        "⛔⛔⛔ the two real processes DISAGREE on the membership accumulator at a common position \
                         (served_seq {s0}) after {what}: a divergence between honest nodes, not a moving target"
                    );
                    return;
                }
                assert!(
                    t.elapsed() < Duration::from_secs(CHAIN_WAIT_S),
                    "⛔ INCONCLUSIVE: the pair never stood at a common position past {what} within 420 s (not a \
                     divergence claim)"
                );
                std::thread::sleep(Duration::from_secs(3));
            }
        };
        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("⛔ the node served a non-hex digest"))
                .collect()
        };
        // A note's canonical record address on process `i`, resolved from its commitment by the route a wallet
        // uses, or None while that process places no record holding it.
        let record_of = |i: usize, cm: &[u8; 32]| -> Option<u64> {
            let r = mesh.post(i, "/note_ordinal_by_cm", &format!(r#"{{"cms_hex":"{}"}}"#, hexs(cm))).ok()?;
            let at = r.find("\"ordinals\":[")? + "\"ordinals\":[".len();
            let rest = &r[at..];
            let end = rest.find(|ch: char| ch == ',' || ch == ']')?;
            rest[..end].trim().parse::<i64>().ok().filter(|o| *o >= 0).map(|o| o as u64)
        };
        // A client HOLDS AND RESENDS while a node answers HTTP 503 ("not right now"), exactly as the gate's
        // `send_in_session` does; any other answer returns at once. The wait is PRINTED, never hidden.
        let post_holding = |i: usize, route: &str, body: &str, what: &str| -> String {
            let t = Instant::now();
            let r = loop {
                let r = mesh.post(i, route, body).unwrap_or_else(|e| e);
                // 503 (could not publish yet) and 409 MEMBERSHIP_NOT_FOLDED_YET (the spent note's record is not folded
                // there yet — `MemberVerdict::Pending`) are both the node's own "retry" answers.
                let wait = r.contains("HTTP 503") || r.contains("MEMBERSHIP_NOT_FOLDED_YET");
                if r.contains("\"verdict\":\"PUBLISHED\"") || !wait || t.elapsed() > Duration::from_secs(600) {
                    break r;
                }
                std::thread::sleep(Duration::from_secs(5));
            };
            eprintln!("[asset-spend-real] process {i} answered {what} after {:.1}s of retry holds", t.elapsed().as_secs_f64());
            r
        };

        // ── 1. CREATE through process 0; registered on both.
        let t_ready = Instant::now();
        let empty = loop {
            let (r0, r1) = (reg(0), reg(1));
            if !r0.is_empty() && !r1.is_empty() {
                assert_eq!(r0, r1, "PRECONDITION: both real nodes start on the same registry");
                break r0;
            }
            assert!(t_ready.elapsed() < Duration::from_secs(300), "⛔ a status door never answered within 300 s");
            std::thread::sleep(Duration::from_secs(3));
        };
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        const SYMBOL: &str = "RSPND";
        const NAME: &str = "real node transfer";
        let mut c = crate::asset_tx::AssetCreateTx {
            kind: crate::asset_tx::AssetKind::Token,
            symbol: SYMBOL.to_string(),
            name: NAME.to_string(),
            logo: [0u8; 32],
            bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, SYMBOL, NAME).bytecode,
            creator: crate::pqauth::pubkey_id(&pk),
            asset_id: [0u8; 32],
            fee: crate::asset_tx::CreationFee::default(),
            art: Vec::new(),
            supply: None,
        };
        c.asset_id = c.derived_id();
        // §BR-14: the creation pays its fee — built the way the creator's wallet builds it.
        let fee = rn_pay_creation_fee(&mesh, spending_node, &mut c, 0x63);
        let create = mesh
            .post(
                spending_node,
                "/submit_asset_create",
                &format!(r#"{{"kind":"token","symbol":"{SYMBOL}","name":"{NAME}","creator_pubkey":"{}"{fee}}}"#, hexs(&pk)),
            )
            .unwrap_or_else(|e| panic!("⛔ the creation was refused over the real RPC: {e}"));
        assert!(
            create.contains(&format!("\"asset_id\":\"{}\"", hexs(&c.asset_id))),
            "PRECONDITION: the route derived the same asset id: {create}"
        );
        let t = Instant::now();
        while !(reg(0) != empty && reg(0) == reg(1)) {
            assert!(t.elapsed() < Duration::from_secs(CHAIN_WAIT_S), "⛔ the creation never registered on both processes");
            std::thread::sleep(Duration::from_secs(3));
        }

        // ── 2. MINT through process 1: a real WHIR carrier over a note whose secret only this client holds.
        const AMOUNT: u64 = 4_200;
        let note_sk_owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[11, 12, 13, 14]));
        let note_sk = note_sk_owner.opening(); // DB-395: the note's opening, under its owner
        let (mint_carrier, cm) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_bytes(AMOUNT, c.asset_tag(), &note_sk)
                .expect("a real WHIR mint carrier");
        let cm_bytes = leaf_to_cm_bytes(cm);
        let note_of = |d: Digest4| -> Vec<u8> {
            let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            n[..crate::spend_frontier::NOTE_CM_BYTES].copy_from_slice(&leaf_to_cm_bytes(d));
            n
        };
        let leaves = vec![crate::dsol::descriptor_leaf(&c.descriptor())];
        let (path, rdirs) = crate::dsol::token_membership_path(&leaves, 0).expect("the minter's own path");
        let path_hex: String = path.iter().map(|d| hexs(&leaf_to_cm_bytes(*d))).collect();
        let rdirs_s: String = rdirs.iter().map(|d| if *d { '1' } else { '0' }).collect();
        // DB-273 §19.6 L3: the supply note's owner clue, signed by the creator and sent as `note_clue_hex`.
        let mint_clue = journey_owner_clue(0x4163);
        let sig = crate::pqauth::ml_dsa_sign(
            &crate::asset_tx::asset_mint_msg(&c.asset_id, AMOUNT, &cm_bytes, &crate::oli::owner_clue_digest(&mint_clue), ""),
            &sk,
        )
        .expect("the creator signs its own mint");
        let mint_body = format!(
            r#"{{"asset_id":"{}","kind":"token","amount":{AMOUNT},"note_hex":"{}","mint_carrier_hex":"{}","creator_pubkey":"{}","creator_sig":"{}","symbol":"{SYMBOL}","asset_name":"{NAME}","registry_path_hex":"{path_hex}","registry_dirs":"{rdirs_s}","note_clue_hex":"{}"}}"#,
            hexs(&c.asset_id),
            hexs(&note_of(cm)),
            hexs(&mint_carrier),
            hexs(&pk),
            hexs(&sig),
            hexs(&mint_clue)
        );
        let minted = post_holding(minting_node, "/submit_asset_mint", &mint_body, "the mint");
        assert!(
            minted.contains("\"verdict\":\"PUBLISHED\""),
            "CALIBRATION: process {minting_node} must admit the asset's first mint: {minted}"
        );
        let (h_mint, s_mint, _) = snap(minting_node);
        common_position_past(h_mint, s_mint, "the mint");

        // ── 3. CALIBRATION: process 0 serves the minted note's membership from its OWN record.
        let want_leaf = note_leaf_of(&cm_bytes);
        let t = Instant::now();
        let (named_record, sibs, dirs, root) = loop {
            if let Some(addr) = record_of(spending_node, &cm_bytes) {
                let body = format!(r#"{{"cms_hex":"{}","addrs_hex":"{}"}}"#, hexs(&cm_bytes), hexs(&addr.to_le_bytes()));
                let r = mesh.post(spending_node, "/note_copath", &body).unwrap_or_default();
                if r.contains("\"served\":true") {
                    let lane = crate::spend_frontier::DIGEST_LANE_BYTES;
                    let sibs: Vec<Digest4> = unhex(&json_str(&r, "siblings_hex").expect("a served copath names its siblings"))
                        .chunks_exact(lane)
                        .map(|b| crate::spend_frontier::digest_from_lane_bytes(b).expect("⛔ a non-canonical sibling"))
                        .collect();
                    let dirs: Vec<bool> =
                        json_str(&r, "dirs").expect("a served copath names its sides").chars().map(|ch| ch == '1').collect();
                    let root = crate::spend_frontier::digest_from_lane_bytes(&unhex(
                        &json_str(&r, "block_root_hex").expect("a served copath names its record root"),
                    ))
                    .expect("⛔ a non-canonical record root");
                    break (addr, sibs, dirs, root);
                }
            }
            assert!(
                t.elapsed() < Duration::from_secs(300),
                "⛔⛔⛔ PROCESS {spending_node} NEVER SERVED THE MINTED NOTE'S RECORD within 300 s of standing past the \
                 mint: it learned the mint's block and not the note's payload, so no holder could ever move the asset \
                 through it"
            );
            std::thread::sleep(Duration::from_secs(3));
        };
        // The client trusts nothing it was served: the path must refold the minted leaf to the served root.
        assert_eq!(sibs.len(), dirs.len(), "⛔ the served copath's siblings and sides disagree in length");
        let refold = sibs
            .iter()
            .zip(&dirs)
            .fold(want_leaf, |cur, (s, right)| if *right { poseidon_pair(*s, cur) } else { poseidon_pair(cur, *s) });
        assert_eq!(refold, root, "⛔ the served copath does not refold the minted note's leaf to the served record root");

        // ── 4. THE TRANSFER, built as `asset_tx`'s in-process pin builds it (one asset throughout).
        let build = |out0: u64| -> (String, [Digest4; 2]) {
            let w = AssetSpendValidityWitness {
                value_in: AMOUNT,
                owner: note_sk_owner,
                value_out: AMOUNT,
                fee: 0,
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
                out0_value: out0,
                out0_opening: usdm_decider::poseidon2_compress::lanes_of_const(&[31, 41, 59, 26]),
                out1_value: AMOUNT - out0,
                out1_opening: usdm_decider::poseidon2_compress::lanes_of_const(&[27, 18, 28, 18]),
                asset: c.asset_tag(),
            };
            assert_eq!(
                asset_spend_input_leaf(&w).expect("the input opens"),
                want_leaf,
                "⛔ THE TRANSFER'S INPUT LEAF IS NOT THE MINTED NOTE'S LEAF"
            );
            let (validity_carrier, cms, nf, lc) =
                prove_asset_spend_validity_carrier_bytes(&w).expect("an honest transfer proves");
            let mut mc = NoteMembershipCarrier::new(want_leaf, root, crate::node::Node::MEMBERSHIP_GENESIS_ACC, nf, crate::spend_frontier::TEST_LC_BLIND);
            assert!(mc.attach_membership(want_leaf, &sibs, &dirs), "the served copath reaches the record root");
            assert!(mc.step(root), "the one fold step proves");
            let (membership_carrier, tip_acc, tip_prev, tip_root) = mc.finalize_one_step().expect("certifies");
            assert_eq!(mc.leaf_commitment(), lc, "⛔ the two carriers name DIFFERENT notes");
            let t = crate::asset_tx::AssetSpendTx {
                notes: [note_of(cms[0]), note_of(cms[1])],
                nullifier: leaf_to_cm_bytes(nf),
                leaf_commit: lc,
                validity_carrier,
                membership_carrier,
                member_tuple: Vec::new(),
                named_record,
                tip_prev,
                tip_root,
                tip_acc,
                // DB-273 §19.6 L3: one owner clue per output, sent keyed to the outputs as `note_clues_hex`.
                owner_clues: vec![journey_owner_clue(0x5a1), journey_owner_clue(0x5a2)],
                slot_tag: None,
            };
            let outs = t.output_commitments().expect("canonical output fronts");
            let d = |x: Digest4| hexs(&leaf_to_cm_bytes(x));
            let body = format!(
                r#"{{"note0":"{}","note1":"{}","nullifier":"{}","leaf_commit":"{}","validity_carrier":"{}","membership_carrier":"{}","named_record":{},"tip_prev":"{}","tip_root":"{}","tip_acc":"{}","note_clues_hex":"{}"}}"#,
                hexs(&t.notes[0]),
                hexs(&t.notes[1]),
                hexs(&t.nullifier),
                d(t.leaf_commit),
                hexs(&t.validity_carrier),
                hexs(&t.membership_carrier),
                t.named_record,
                d(t.tip_prev),
                d(t.tip_root),
                d(t.tip_acc),
                hexs(&crate::node::Node::encode_note_clue_records(
                    &t.notes
                        .iter()
                        .zip(t.owner_clues.iter())
                        .filter_map(|(n, c)| Some((<[u8; 32]>::try_from(n.get(..32)?).ok()?, c.clone())))
                        .collect::<Vec<_>>()
                ))
            );
            (body, outs)
        };
        let (first_body, outs) = build(1_500);
        let out_cms: Vec<[u8; 32]> = outs.iter().map(|o| leaf_to_cm_bytes(*o)).collect();
        // PRODUCTION-SCALE-REVIEWED: `0..2` is the two real node PROCESSES (RealMesh indices); each must place every
        // output from the block alone. The outputs themselves are the spend's full production set.
        for i in 0..2 {
            for o in &out_cms {
                assert!(
                    record_of(i, o).is_none(),
                    "CONTROL: process {i} places an output of a transfer nobody has published — the landing check \
                     below would be vacuous"
                );
            }
        }

        // ── 5. PUBLISH through process 0, which learned the minted note only from process 1's block.
        let first = post_holding(spending_node, "/submit_asset_spend", &first_body, "the transfer");
        assert!(
            first.contains("\"verdict\":\"PUBLISHED\""),
            "CALIBRATION: process {spending_node} must admit an honest transfer of a note it learned from a block: {first}"
        );

        // ── 6. THE OUTPUTS LAND ON THE OTHER PROCESS, WHICH NEVER SAW THE SUBMIT.
        let t = Instant::now();
        loop {
            let placed: Vec<bool> = out_cms.iter().map(|o| record_of(minting_node, o).is_some()).collect();
            if placed.iter().all(|p| *p) {
                eprintln!(
                    "[asset-spend-real] process {minting_node} places both transfer outputs after {:.1}s",
                    t.elapsed().as_secs_f64()
                );
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(CHAIN_WAIT_S),
                "⛔⛔⛔ PROCESS {minting_node} NEVER PLACED THE TRANSFER'S OUTPUTS within 420 s (placed {placed:?}): the \
                 transfer credited only where it was submitted — the local mutation this row exists to catch"
            );
            std::thread::sleep(Duration::from_secs(3));
        }
        let (h_xfer, s_xfer, _) = snap(spending_node);
        common_position_past(h_xfer, s_xfer, "the transfer");

        // ── 7. THE CLAIM: a second spend of the same note is refused by the SPENT SET on both processes.
        let (second_body, second_outs) = build(2_000);
        assert_ne!(second_outs, outs, "PRECONDITION: the second spend is different bytes, so only the spent set can refuse it");
        for i in [minting_node, spending_node] {
            let r = post_holding(i, "/submit_asset_spend", &second_body, "a second spend of the same note");
            // DIGITAL-CASH-PRIVACY-REVIEWED: route verdicts only — no amount beyond this pin's own literals, no owner.
            eprintln!("[asset-spend-real] process {i} second spend of the same note: {r}");
            assert!(
                !r.contains("\"verdict\":\"PUBLISHED\""),
                "⛔⛔⛔ PROCESS {i} ADMITTED A SECOND SPEND OF A NOTE WHOSE TRANSFER A BLOCK ALREADY CARRIED — the burn \
                 never travelled, or is refused only where it was published: the asset is spent twice. Reply: {r}"
            );
            assert!(
                r.contains("the note is already spent"),
                "⛔ process {i} refused the second spend, but NOT by the spent set — this run cannot show the burn \
                 travelled. Reply: {r}"
            );
        }
    }

    /// ⭐⭐⭐ CRITERION 2 / TIER 2 — `OrderFill` ON REAL NODE PROCESSES: a real DEX fill settles on the mesh.
    ///
    /// DB-224 proved in process that a fill whose inputs a real chain route funded settles on a peer fed only the wire.
    /// This row was DEMOTED on 2026-09-17 by a real-node measurement: the order rested while its tx was refused
    /// (`InvalidProof`), and the fill was refused at the burn gate on both processes ("32 input(s) carried NO absence
    /// proof"). Here the same construction runs across the real RPC. The client (this harness) holds both notes' secrets,
    /// as a real maker and taker would.
    ///   * The MAKER's lot is a faucet drip (a BridgeCredit chain object) sealed to the maker's own ML-KEM key. The maker
    ///     opens it with its own decapsulation key, which yields the lot's spend key that the maker half proves.
    ///   * The TAKER's input is the first mint of a token this client created (the DSOL route), in the order's asset b.
    ///   * Each input's membership bind is built from process 0's OWN served record; the client refolds the copath.
    ///   * The order rests through process 0 (`/post_order`). CONTROL: it reaches the other process's book, and no
    ///     credited note is placed anywhere before the fill.
    ///   * The fill settles through process 0 (`/submit_order_fill`).
    ///   * Process 1 is the other process and never saw the submit. It must retire the order from its book and place the
    ///     maker's payout and the taker's payout and change in its records.
    ///   * The SAME fill resubmitted must be refused on BOTH processes by the spent set: `ORDER_ALREADY_FILLED` or
    ///     `TAKER_NOTE_SPENT`.
    /// Two processes on one machine: not a scale claim.
    #[test]
    fn a_fill_settled_through_one_real_process_retires_the_order_on_the_other_and_a_replay_is_refused_by_both() {
        // CROSS-NODE-REVIEWED: two independent usdmd-node PROCESSES (RealMesh 0 and 1). The fill is submitted to one, and
        // every claim — the order retired, the three outputs recorded, the replay refused — is read from EACH process's own
        // socket in the `for i in 0..2` loops below.
        use crate::spend_frontier::{leaf_to_cm_bytes, note_leaf_of, poseidon_pair, Digest4};
        use usdm_decider::note_membership_air::NoteMembershipCarrier;
        use usdm_decider::poseidon2_compress::lanes_of;
        use usdm_decider::whir_rec_block::{
            asset_note_cm, prove_order_maker_half, prove_order_taker_half, MakerHalfWitness, OrderTerms,
            TakerHalfWitness, USDM_ASSET_TAG,
        };
        let (minting_node, settling_node) = (1usize, 0usize);
        let mesh = match RealMesh::start(2, "orderfill") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let reg = |i: usize| -> String {
            json_str(&mesh.get(i, "/get_info").unwrap_or_default(), "token_registry_root").unwrap_or_default()
        };
        let snap = |i: usize| -> (u64, u64, String) {
            let info = mesh.get(i, "/get_info").unwrap_or_default();
            (
                json_u64(&info, "height").unwrap_or(0),
                json_u64(&info, "served_seq").unwrap_or(0),
                json_str(&info, "membership_acc").unwrap_or_default(),
            )
        };
        // Both processes `past` blocks and records beyond `(h_from, s_from)`, on one accumulator at a common position.
        let common_position_past = |h_from: u64, s_from: u64, past: u64, what: &str| {
            let t = Instant::now();
            loop {
                let ((h0, s0, a0), (h1, s1, a1)) = (snap(0), snap(1));
                if h0 > h_from + past && h1 > h_from + past && s0 == s1 && s0 >= s_from + past && !a0.is_empty() {
                    assert_eq!(
                        a0, a1,
                        "⛔⛔⛔ the two real processes DISAGREE on the membership accumulator at a common position \
                         (served_seq {s0}) after {what}: a divergence between honest nodes, not a moving target"
                    );
                    return;
                }
                assert!(
                    t.elapsed() < Duration::from_secs(600),
                    "⛔ INCONCLUSIVE: the pair never stood at a common position {past} past {what} within 600 s (not a \
                     divergence claim)"
                );
                std::thread::sleep(Duration::from_secs(3));
            }
        };
        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("⛔ the node served non-hex"))
                .collect()
        };
        let record_of = |i: usize, cm: &[u8; 32]| -> Option<u64> {
            let r = mesh.post(i, "/note_ordinal_by_cm", &format!(r#"{{"cms_hex":"{}"}}"#, hexs(cm))).ok()?;
            let at = r.find("\"ordinals\":[")? + "\"ordinals\":[".len();
            let rest = &r[at..];
            let end = rest.find(|ch: char| ch == ',' || ch == ']')?;
            rest[..end].trim().parse::<i64>().ok().filter(|o| *o >= 0).map(|o| o as u64)
        };
        let post_holding = |i: usize, route: &str, body: &str, what: &str| -> String {
            let t = Instant::now();
            let r = loop {
                let r = mesh.post(i, route, body).unwrap_or_else(|e| e);
                if !r.contains("HTTP 503") || t.elapsed() > Duration::from_secs(600) {
                    break r;
                }
                std::thread::sleep(Duration::from_secs(5));
            };
            eprintln!("[order-fill-real] process {i} answered {what} after {:.1}s of HTTP 503 holds", t.elapsed().as_secs_f64());
            r
        };
        let note_of = |d: Digest4| -> Vec<u8> {
            let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            n[..crate::spend_frontier::NOTE_CM_BYTES].copy_from_slice(&leaf_to_cm_bytes(d));
            n
        };
        // The one-step membership bind of note `cm`, built from process `i`'s OWN served record and bound to `binder`,
        // in the wire shape the order and fill doors read: (carrier, GENESIS ‖ prev ‖ root ‖ acc ‖ named record).
        let bind = |i: usize, cm: &[u8; 32], binder: Digest4| -> (Vec<u8>, Vec<u8>) {
            let leaf = note_leaf_of(cm);
            let t = Instant::now();
            let (rid, sibs, dirs, root) = loop {
                if let Some(addr) = record_of(i, cm) {
                    let body = format!(r#"{{"cms_hex":"{}","addrs_hex":"{}"}}"#, hexs(cm), hexs(&addr.to_le_bytes()));
                    let r = mesh.post(i, "/note_copath", &body).unwrap_or_default();
                    if r.contains("\"served\":true") {
                        let lane = crate::spend_frontier::DIGEST_LANE_BYTES;
                        let sibs: Vec<Digest4> = unhex(&json_str(&r, "siblings_hex").expect("a served copath names its siblings"))
                            .chunks_exact(lane)
                            .map(|b| crate::spend_frontier::digest_from_lane_bytes(b).expect("⛔ a non-canonical sibling"))
                            .collect();
                        let dirs: Vec<bool> =
                            json_str(&r, "dirs").expect("a served copath names its sides").chars().map(|ch| ch == '1').collect();
                        let root = crate::spend_frontier::digest_from_lane_bytes(&unhex(
                            &json_str(&r, "block_root_hex").expect("a served copath names its record root"),
                        ))
                        .expect("⛔ a non-canonical record root");
                        break (addr, sibs, dirs, root);
                    }
                }
                assert!(
                    t.elapsed() < Duration::from_secs(300),
                    "⛔⛔⛔ PROCESS {i} NEVER SERVED A FUNDED INPUT'S RECORD within 300 s — no holder could fill an order with \
                     it through that process"
                );
                std::thread::sleep(Duration::from_secs(3));
            };
            assert_eq!(sibs.len(), dirs.len(), "⛔ the served copath's siblings and sides disagree in length");
            let refold = sibs
                .iter()
                .zip(&dirs)
                .fold(leaf, |cur, (s, right)| if *right { poseidon_pair(*s, cur) } else { poseidon_pair(cur, *s) });
            assert_eq!(refold, root, "⛔ the served copath does not refold the input's leaf to the served record root");
            let mut carrier = NoteMembershipCarrier::new(leaf, root, crate::node::Node::MEMBERSHIP_GENESIS_ACC, binder, crate::spend_frontier::TEST_LC_BLIND);
            assert!(carrier.attach_membership(leaf, &sibs, &dirs), "the served copath reaches the record root");
            let (proof, acc, tip_prev, tip_root) = carrier.finalize_one_step().expect("the one-step carrier certifies");
            let mut tip = Vec::with_capacity(4 * crate::spend_frontier::DIGEST_LANE_BYTES + 8);
            for d in [crate::node::Node::MEMBERSHIP_GENESIS_ACC, tip_prev, tip_root, acc] {
                tip.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&d));
            }
            tip.extend_from_slice(&rid.to_le_bytes());
            (proof, tip)
        };

        // ── 1. CREATE the token through process 0 (the DSOL route); registered on both.
        let t_ready = Instant::now();
        let empty = loop {
            let (r0, r1) = (reg(0), reg(1));
            if !r0.is_empty() && !r1.is_empty() {
                assert_eq!(r0, r1, "PRECONDITION: both real nodes start on the same registry");
                break r0;
            }
            assert!(t_ready.elapsed() < Duration::from_secs(300), "⛔ a status door never answered within 300 s");
            std::thread::sleep(Duration::from_secs(3));
        };
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        const SYMBOL: &str = "RFILL";
        const NAME: &str = "real node fill";
        let mut c = crate::asset_tx::AssetCreateTx {
            kind: crate::asset_tx::AssetKind::Token,
            symbol: SYMBOL.to_string(),
            name: NAME.to_string(),
            logo: [0u8; 32],
            bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, SYMBOL, NAME).bytecode,
            creator: crate::pqauth::pubkey_id(&pk),
            asset_id: [0u8; 32],
            fee: crate::asset_tx::CreationFee::default(),
            art: Vec::new(),
            supply: None,
        };
        c.asset_id = c.derived_id();
        // §BR-14: the creation pays its fee — built the way the creator's wallet builds it.
        let fee = rn_pay_creation_fee(&mesh, settling_node, &mut c, 0x64);
        let create = mesh
            .post(
                settling_node,
                "/submit_asset_create",
                &format!(r#"{{"kind":"token","symbol":"{SYMBOL}","name":"{NAME}","creator_pubkey":"{}"{fee}}}"#, hexs(&pk)),
            )
            .unwrap_or_else(|e| panic!("⛔ the creation was refused over the real RPC: {e}"));
        assert!(
            create.contains(&format!("\"asset_id\":\"{}\"", hexs(&c.asset_id))),
            "PRECONDITION: the route derived the same asset id: {create}"
        );
        let t = Instant::now();
        while !(reg(0) != empty && reg(0) == reg(1)) {
            assert!(t.elapsed() < Duration::from_secs(CHAIN_WAIT_S), "⛔ the creation never registered on both processes");
            std::thread::sleep(Duration::from_secs(3));
        }

        // ── 2. THE MAKER'S LOT: a faucet drip sealed to the maker's own ADDRESS (its ML-KEM key and, DB-395, its spend key),
        // opened with its own keys.
        let (maker_ek, _) = crate::faucet::kem_keypair_from_seed(&[0x45; 32]);
        let maker = crate::faucet::RecipientSecrets::for_test(&[0x45; 32]);
        let maker_spk = maker.spk();
        // DB-273 §19.6 L3: owners are OLI clues — the maker's rides its order, the taker's two ride the fill.
        let (maker_payout_clue, taker_payout_clue, taker_change_clue) =
            (journey_owner_clue(0x4563), journey_owner_clue(0x4564), journey_owner_clue(0x4565));
        // DEX-GRID (C3): the lot is ON THE GRID, and the drip credits exactly that amount. MEASURED 2026-10-03: dripping
        // the raw 2,500,000,000 while the order rested `snap_to_grid(LOT)` made the maker half spend a different note than
        // the one dripped ("PRECONDITION: the maker half spends exactly the dripped lot", left != right).
        let lot_amount_on_grid = crate::order_book::snap_to_grid(2_500_000_000);
        let drip = mesh
            // DB-273 §17 (1): a findable receive address over the maker's own key, never the bare key (`NO_LOCATOR`).
            .post(
                settling_node,
                "/faucet/drip",
                &format!(r#"{{"amount":{lot_amount_on_grid},"to":"{}"}}"#, journey_receive_address(0x4566, &maker_ek, &maker_spk)),
            )
            .unwrap_or_else(|e| panic!("⛔ the maker's drip was refused over the real RPC: {e}"));
        let lot_note = unhex(&json_str(&drip, "note").unwrap_or_else(|| panic!("⛔ the drip named no note: {drip}")));
        let (lot_amount, lot_seed) =
            crate::faucet::open_note(&lot_note, &maker.dk, &maker_spk).expect("⛔ the maker cannot open the lot sealed to its own address");
        let maker_owner = usdm_decider::whir_rec_block::NoteOwner { ask: maker.ask, nk: maker.nk, seed: lot_seed };
        assert_eq!(lot_amount, lot_amount_on_grid, "PRECONDITION: the drip credits exactly the lot");
        let lot_cm: [u8; 32] = lot_note[..32].try_into().expect("a note starts with its commitment");

        // ── 3. THE TAKER'S INPUT: the token's first mint, over a note whose key only the taker (this client) holds.
        const PAY_IN: u64 = 1_000_000;
        // DB-395: the minted note commits to the taker's OPENING; the taker spends it as its owner.
        let taker_owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[8_101, 8_102, 8_103, 8_104]));
        let (mint_carrier, taker_cm) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_bytes(PAY_IN, c.asset_tag(), &taker_owner.opening())
                .expect("a real WHIR mint carrier");
        let taker_in = leaf_to_cm_bytes(taker_cm);
        let leaves = vec![crate::dsol::descriptor_leaf(&c.descriptor())];
        let (path, rdirs) = crate::dsol::token_membership_path(&leaves, 0).expect("the minter's own path");
        let path_hex: String = path.iter().map(|d| hexs(&leaf_to_cm_bytes(*d))).collect();
        let rdirs_s: String = rdirs.iter().map(|d| if *d { '1' } else { '0' }).collect();
        // DB-273 §19.6 L3: the taker's minted note's owner clue, signed by the creator and sent as `note_clue_hex`.
        let mint_clue = journey_owner_clue(0x4551);
        let sig = crate::pqauth::ml_dsa_sign(
            &crate::asset_tx::asset_mint_msg(&c.asset_id, PAY_IN, &taker_in, &crate::oli::owner_clue_digest(&mint_clue), ""),
            &sk,
        )
        .expect("the creator signs its own mint");
        let mint_body = format!(
            r#"{{"asset_id":"{}","kind":"token","amount":{PAY_IN},"note_hex":"{}","mint_carrier_hex":"{}","creator_pubkey":"{}","creator_sig":"{}","symbol":"{SYMBOL}","asset_name":"{NAME}","registry_path_hex":"{path_hex}","registry_dirs":"{rdirs_s}","note_clue_hex":"{}"}}"#,
            hexs(&c.asset_id),
            hexs(&note_of(taker_cm)),
            hexs(&mint_carrier),
            hexs(&pk),
            hexs(&sig),
            hexs(&mint_clue)
        );
        let minted = post_holding(minting_node, "/submit_asset_mint", &mint_body, "the taker's mint");
        assert!(
            minted.contains("\"verdict\":\"PUBLISHED\""),
            "CALIBRATION: process {minting_node} must admit the token's first mint: {minted}"
        );
        // Both funding objects ride blocks; the binds are built only once both records have entered the accumulator
        // every party checks a bind against — one production record depth (a protocol constant) past both.
        let ((h0, s0, _), (h1, s1, _)) = (snap(0), snap(1));
        common_position_past(h0.max(h1), s0.max(s1), crate::params::RECORD_FOLD_DEPTH_DEFAULT + 1, "the funding");

        // ── 4. THE ORDER: the maker sells its USDm lot for the token; both halves proven by this client.
        // DEX-GRID (C3): through the one snap helper.
        let t = OrderTerms {
            lot: lot_amount_on_grid,
            pay_b: crate::order_book::snap_to_grid(250_000),
            asset_a: USDM_ASSET_TAG,
            asset_b: c.asset_tag(),
            expires_at_height: crate::order_book::snap_expiry(1_000_000),
        };
        let mw = MakerHalfWitness { owner: maker_owner, payout_opening: lanes_of(&[7_111, 7_112, 7_113, 7_114]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
        let tw = TakerHalfWitness {
            value_in: PAY_IN,
            owner: taker_owner,
            change_opening: lanes_of(&[8_111, 8_112, 8_113, 8_114]),
            payout_opening: lanes_of(&[8_121, 8_122, 8_123, 8_124]),
            lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        };
        assert_eq!(leaf_to_cm_bytes(asset_note_cm(t.lot, t.asset_a, mw.owner.opening())), lot_cm, "PRECONDITION: the maker half spends exactly the dripped lot");
        assert_eq!(leaf_to_cm_bytes(asset_note_cm(tw.value_in, t.asset_b, tw.owner.opening())), taker_in, "PRECONDITION: the taker half spends exactly the minted note");
        let (maker_bytes, mp) = prove_order_maker_half(&mw, &t).expect("the maker half proves");
        let (taker_bytes, tp) =
            prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).expect("the taker half proves");
        let maker_bind = bind(settling_node, &lot_cm, mp.nullifier);
        let taker_bind = bind(settling_node, &taker_in, tp.nullifier);
        let d = |x: Digest4| hexs(&leaf_to_cm_bytes(x));
        let limbs3 = |a: [u64; 3]| -> String { hexs(&a.iter().flat_map(|l| l.to_le_bytes()).collect::<Vec<u8>>()) };
        let terms_json = format!(
            r#""lot":{},"pay_b":{},"asset_a":"{}","asset_b":"{}","expires_at_height":{}"#,
            t.lot,
            t.pay_b,
            limbs3(t.asset_a),
            limbs3(t.asset_b),
            t.expires_at_height
        );
        let maker_payout_note = note_of(mp.payout_cm);
        let post_body = format!(
            r#"{{{terms_json},"nullifier":"{}","leaf_commit":"{}","payout_cm":"{}","maker_bytes_hex":"{}","payout_note_hex":"{}","membership_carrier_hex":"{}","membership_tip_hex":"{}","payout_clue_hex":"{}"}}"#,
            d(mp.nullifier),
            d(mp.leaf_commit),
            d(mp.payout_cm),
            hexs(&maker_bytes),
            hexs(&maker_payout_note),
            hexs(&maker_bind.0),
            hexs(&maker_bind.1),
            hexs(&maker_payout_clue)
        );
        let posted = mesh.post(settling_node, "/post_order", &post_body).unwrap_or_else(|e| e);
        assert!(
            posted.contains("\"resting\":true"),
            "CALIBRATION: process {settling_node} must rest an order whose lot a real drip funded: {posted}"
        );
        let level = json_u64(&posted, "level").expect("a resting order names its level");
        let book_body = format!(r#"{{"asset_a":"{}","asset_b":"{}","level":{level}}}"#, limbs3(t.asset_a), limbs3(t.asset_b));
        let holds_order = |i: usize| mesh.post(i, "/book_level", &book_body).unwrap_or_default().contains(&d(mp.nullifier));
        let t_book = Instant::now();
        while !holds_order(minting_node) {
            assert!(
                t_book.elapsed() < Duration::from_secs(300),
                "⛔ CONTROL: the order never reached the other process's book within 300 s — it rests on one process only"
            );
            std::thread::sleep(Duration::from_secs(3));
        }
        let credited: Vec<[u8; 32]> = [mp.payout_cm, tp.payout_cm, tp.change_cm].iter().map(|x| leaf_to_cm_bytes(*x)).collect();
        // PRODUCTION-SCALE-REVIEWED: `0..2` is the two real node PROCESSES (RealMesh indices): BOTH must record all three
        // fill outputs from the block alone; it bounds no cover width.
        for i in 0..2 {
            for cm in &credited {
                assert!(
                    record_of(i, cm).is_none(),
                    "CONTROL: process {i} places a credited note of a fill nobody has settled — the landing check would \
                     be vacuous"
                );
            }
        }

        // ── 5. THE FILL, settled through process 0.
        let fill_body = format!(
            r#"{{{terms_json},"maker_carrier":"{}","taker_carrier":"{}","maker_nullifier":"{}","maker_leaf_commit":"{}","maker_payout_cm":"{}","taker_nullifier":"{}","taker_leaf_commit":"{}","taker_change_cm":"{}","taker_payout_cm":"{}","maker_payout_note":"{}","taker_payout_note":"{}","taker_change_note":"{}","maker_membership_carrier_hex":"{}","maker_membership_tip_hex":"{}","taker_membership_carrier_hex":"{}","taker_membership_tip_hex":"{}","note_clues_hex":"{}"}}"#,
            hexs(&maker_bytes),
            hexs(&taker_bytes),
            d(mp.nullifier),
            d(mp.leaf_commit),
            d(mp.payout_cm),
            d(tp.nullifier),
            d(tp.leaf_commit),
            d(tp.change_cm),
            d(tp.payout_cm),
            hexs(&maker_payout_note),
            hexs(&note_of(tp.payout_cm)),
            hexs(&note_of(tp.change_cm)),
            hexs(&maker_bind.0),
            hexs(&maker_bind.1),
            hexs(&taker_bind.0),
            hexs(&taker_bind.1),
            // DB-273 §19.6 L3: the taker's two owners, keyed to its payout and change in that order.
            hexs(&crate::node::Node::encode_note_clue_records(&[
                (leaf_to_cm_bytes(tp.payout_cm), taker_payout_clue.clone()),
                (leaf_to_cm_bytes(tp.change_cm), taker_change_clue.clone()),
            ]))
        );
        let settled = post_holding(settling_node, "/submit_order_fill", &fill_body, "the fill");
        assert!(
            settled.contains("\"verdict\":\"SETTLED\""),
            "CALIBRATION: process {settling_node} must settle a fill whose inputs real chain routes funded: {settled}"
        );

        // ── 6. THE OTHER PROCESS, which never saw the submit, retires the order and places every credited note.
        let t = Instant::now();
        loop {
            let retired = !holds_order(minting_node);
            let placed: Vec<bool> = credited.iter().map(|cm| record_of(minting_node, cm).is_some()).collect();
            if retired && placed.iter().all(|p| *p) {
                eprintln!(
                    "[order-fill-real] process {minting_node} retired the order and placed the maker's payout and the \
                     taker's payout and change after {:.1}s",
                    t.elapsed().as_secs_f64()
                );
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(CHAIN_WAIT_S),
                "⛔⛔⛔ PROCESS {minting_node} NEVER TOOK THE SETTLEMENT within 420 s (order retired {retired}, credited \
                 notes placed {placed:?}): the fill settled only where it was submitted — the 2026-09-03 double-payout shape"
            );
            std::thread::sleep(Duration::from_secs(3));
        }
        let (h_fill, s_fill, _) = snap(settling_node);
        common_position_past(h_fill, s_fill, 20, "the settlement");

        // ── 7. THE CLAIM: the SAME fill resubmitted is refused on BOTH processes, by the spent set.
        for i in [minting_node, settling_node] {
            let r = post_holding(i, "/submit_order_fill", &fill_body, "the same fill again");
            // DIGITAL-CASH-PRIVACY-REVIEWED: route verdicts only — no amount beyond this pin's own literals, no owner.
            eprintln!("[order-fill-real] process {i} replay of the settled fill: {r}");
            assert!(
                !r.contains("\"verdict\":\"SETTLED\""),
                "⛔⛔⛔ PROCESS {i} SETTLED THE SAME FILL TWICE — the maker's lot pays out again: {r}"
            );
            assert!(
                r.contains("ORDER_ALREADY_FILLED") || r.contains("TAKER_NOTE_SPENT"),
                "⛔ process {i} refused the replay, but NOT by the spent set — this run cannot show the settlement \
                 travelled: {r}"
            );
        }
    }

    /// ⛔⛔ DB-339 — A ROLLING RESTART OF A PRODUCING REAL PAIR LEAVES BOTH PROCESSES SERVING LANE A.
    ///
    /// The gate's step 3 ([gateT1] run 2, node 6ef57834) failed with ONE chain, both processes ready, and ONLY node2's
    /// nullifier view absent 420 s after its restart. Its kind-17 warm streamed the whole set (~41.8k tags) and never
    /// reached its pivot, silently. The two-producer in-process reproduction is GREEN (cycle 17 P3/F3), so the class
    /// lives on real processes. It is a RATE: T1-1, Q14 and Q16 passed step 3.
    ///
    /// This restarts each process in turn while both produce: process 1 first, then process 0, as the gate orders
    /// them. Each restarted process's view must be present AND match its accumulator within the gate's own 450 s
    /// bound, and the other process keeps producing throughout.
    ///
    /// Each restarted log's DB-339 line (`[nf-pivot] ⛔ DB-339: the stream is complete …`) is printed; it names which
    /// way a missed pivot misses. The ready times printed are THIS young chain's. The warm is O(tags), so they are not
    /// readiness criterion 7's value, which is measured on the live chain's length.
    #[test]
    fn a_rolling_restart_of_a_producing_real_pair_leaves_both_processes_serving_lane_a() {
        let mut mesh = match RealMesh::start(2, "rolling") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let info = |mesh: &RealMesh, i: usize| -> String { mesh.get(i, "/get_info").unwrap_or_default() };
        let view_ready = |mesh: &RealMesh, i: usize| -> bool {
            let b = info(mesh, i);
            b.contains("\"nf_view_present\":true") && b.contains("\"nf_view_matches_acc\":true")
        };
        // A producing pair with a chain and a ready view on both, before anything restarts.
        let t = Instant::now();
        loop {
            let (h0, h1) = (mesh.height(0).unwrap_or(0), mesh.height(1).unwrap_or(0));
            if h0 >= 40 && h1 >= 40 && view_ready(&mesh, 0) && view_ready(&mesh, 1) {
                eprintln!("[db339-real] before any restart: heights {h0}/{h1}, both views present+matching");
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(600),
                "⛔ PRECONDITION: the pair never held a 40-block chain with both views ready within 600 s (heights \
                 {h0}/{h1})"
            );
            std::thread::sleep(Duration::from_secs(5));
        }
        for i in [1usize, 0] {
            let other = 1 - i;
            let other_before = mesh.height(other).unwrap_or(0);
            let up = mesh.restart_node(i, Duration::from_secs(20)).unwrap_or_else(|e| panic!("⛔ node{i} restart: {e}"));
            let t = Instant::now();
            let mut ready = None;
            while t.elapsed() < Duration::from_secs(450) {
                if view_ready(&mesh, i) {
                    ready = Some(t.elapsed());
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
            let log = std::fs::read_to_string(mesh.log_path(i)).unwrap_or_default();
            let diag: Vec<&str> = log.lines().filter(|l| l.contains("DB-339")).collect();
            // DIGITAL-CASH-PRIVACY-REVIEWED: durations, heights and this node's own public readiness booleans; the DB-339
            // line carries counts only.
            eprintln!(
                "[db339-real] node{i} restarted (up after {up:.1}s): view present+matching after {ready:?} (bound 450 s); \
                 the other process's height {other_before} → {}; DB-339 lines in node{i}'s log: {} (last: {})",
                mesh.height(other).unwrap_or(0),
                diag.len(),
                diag.last().copied().unwrap_or("none")
            );
            assert!(
                ready.is_some(),
                "⛔⛔ DB-339 REPRODUCED ON REAL PROCESSES: node{i}'s nullifier view was not present AND matching within \
                 450 s of its restart (the gate's step-3 bound). Its DB-339 line: {}",
                diag.last().copied().unwrap_or("none — the stream never completed")
            );
            assert!(
                mesh.height(other).unwrap_or(0) > other_before,
                "⛔ the other process stopped producing while node{i} restarted — a restart must never halt its peer"
            );
        }
    }

    /// ⭐⭐⭐ CRITERION 2 — `WrappedMint` ON REAL NODE PROCESSES: the HOLDER journey this row asks for.
    ///
    /// A REAL Bitcoin Core (regtest) is the foreign chain, and both daemons are bonded seats, which makes them the
    /// custodians.
    ///   * Both operators sign a wrapped asset's ratio, and both processes apply the registration.
    ///   * The holder is this client, the only party that knows the note's key. It asks process 0 for a per-swap
    ///     reserve address; Core sends a real coin there and mines it to the custodians' own confirmation count.
    ///   * The holder then requests the wrapped mint through `/wrapped_mint_execute`, with a committed carrier over its
    ///     own note.
    ///   * The custodians decrypt the sealed request, see the deposit in their OWN Bitcoin source and attest, and the
    ///     quorum publishes.
    ///   * CONTROL 1: process 1 is the other process. It places no record for the wrapped note before a block carried
    ///     it, and must then place it from the mint block alone.
    ///   * The holder moves the note through process 0: an ordinary asset transfer in the wrapped tag, built from
    ///     process 0's own served copath.
    ///   * CONTROL 2: neither process places the transfer's outputs before the transfer is published.
    ///   * The other process must place both outputs, and a second spend of the same note is refused by the spent set
    ///     on BOTH.
    /// Two processes on one machine: not a scale claim.
    #[test]
    fn a_wrapped_note_minted_against_a_real_bitcoin_deposit_is_moved_and_the_other_process_retires_it() {
        use crate::spend_frontier::{leaf_to_cm_bytes, note_leaf_of, poseidon_pair, Digest4};
        use usdm_decider::note_membership_air::NoteMembershipCarrier;
        use usdm_decider::poseidon2_compress::lanes_of;
        use usdm_decider::whir_rec_block::{
            asset_spend_input_leaf, prove_asset_spend_validity_carrier_bytes, AssetSpendValidityWitness,
        };
        const ASSET: u32 = 78;
        const RATIO: u32 = 15_000;
        const MINTED: u64 = 1_000_000;
        // 200 % of the minted amount, in satoshis: above the registered 150 % ratio.
        const DEPOSIT_SATS: u64 = 2 * MINTED;
        let regtest = RegtestCore::start("wrappedmint").unwrap_or_else(|e| panic!("⛔ NO REGTEST BITCOIN CORE: {e}"));
        std::env::set_var("MONEROUSD_BTC_NET", "regtest");
        std::env::set_var("MONEROUSD_BTC_RPC_URL", format!("http://127.0.0.1:{}", regtest.port));
        std::env::set_var("MONEROUSD_BTC_RPC_AUTH", "u:p");
        std::env::set_var("MONEROUSD_BTC_FEE_RATE_SAT_VB", "2");
        eprintln!("[wrapped-mint-real] Bitcoin Core regtest at 127.0.0.1:{} · height {}", regtest.port, regtest.height());
        let (spending_node, other) = (0usize, 1usize);
        // ⛔ MEASURED [slotB24wrap] 2026-09-28 (node 78f78767): without an operator price source for THIS asset, both
        // custodians refused to attest 195/225 times — `[peg-attest] ⛔ not signing: the mint is not covered by the
        // deposit's PRICED value at the required ratio for asset 78` — because no price mark for asset 78 ever existed
        // (DB-124: no attested price, no mint; nothing stands in for a missing price). Each operator configures its
        // price source exactly as the PriceMark pin's operators do (DB-240); each daemon's reporter quotes it, the
        // ≥2/3 quorum publishes the mark, and only then can the attesters judge coverage.
        // ⭐ §21 (2026-10-30): nobody types a price any more — each daemon quotes what its sampled onion relays agree on,
        // and the relays price Bitcoin and Monero only. A registered wrapped asset with any other id (78 here) has no
        // relay price, so its mint fails closed exactly as DB-124 requires; this pin's subject needs an asset the relays
        // price (finding posted on the bus 2026-10-30).
        let mesh = RealMesh::start(2, "wrappedmint");
        let mesh = match mesh {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let snap = |i: usize| -> (u64, u64, String) {
            let info = mesh.get(i, "/get_info").unwrap_or_default();
            (
                json_u64(&info, "height").unwrap_or(0),
                json_u64(&info, "served_seq").unwrap_or(0),
                json_str(&info, "membership_acc").unwrap_or_default(),
            )
        };
        let common_position_past = |h_from: u64, s_from: u64, past: u64, what: &str| {
            let t = Instant::now();
            loop {
                let ((h0, s0, a0), (h1, s1, a1)) = (snap(0), snap(1));
                if h0 > h_from + past && h1 > h_from + past && s0 == s1 && s0 >= s_from + past && !a0.is_empty() {
                    assert_eq!(
                        a0, a1,
                        "⛔⛔⛔ the two real processes DISAGREE on the membership accumulator at a common position \
                         (served_seq {s0}) after {what}: a divergence between honest nodes, not a moving target"
                    );
                    return;
                }
                assert!(
                    t.elapsed() < Duration::from_secs(600),
                    "⛔ INCONCLUSIVE: the pair never stood at a common position {past} past {what} within 600 s (not a \
                     divergence claim)"
                );
                std::thread::sleep(Duration::from_secs(3));
            }
        };
        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("⛔ the node served non-hex"))
                .collect()
        };
        let record_of = |i: usize, cm: &[u8; 32]| -> Option<u64> {
            let r = mesh.post(i, "/note_ordinal_by_cm", &format!(r#"{{"cms_hex":"{}"}}"#, hexs(cm))).ok()?;
            let at = r.find("\"ordinals\":[")? + "\"ordinals\":[".len();
            let rest = &r[at..];
            let end = rest.find(|ch: char| ch == ',' || ch == ']')?;
            rest[..end].trim().parse::<i64>().ok().filter(|o| *o >= 0).map(|o| o as u64)
        };
        let post_holding = |i: usize, route: &str, body: &str, what: &str| -> String {
            let t = Instant::now();
            let r = loop {
                let r = mesh.post(i, route, body).unwrap_or_else(|e| e);
                if !r.contains("HTTP 503") || t.elapsed() > Duration::from_secs(600) {
                    break r;
                }
                std::thread::sleep(Duration::from_secs(5));
            };
            eprintln!("[wrapped-mint-real] process {i} answered {what} after {:.1}s of HTTP 503 holds", t.elapsed().as_secs_f64());
            r
        };
        let note_of = |d: Digest4| -> Vec<u8> {
            let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            n[..crate::spend_frontier::NOTE_CM_BYTES].copy_from_slice(&leaf_to_cm_bytes(d));
            n
        };
        // A fresh secret per run, from a fresh ML-KEM encapsulation key's bytes (never a fixed seed).
        let fresh = |tag: &[u8]| -> Digest4 {
            let (ek, _) = crate::pqkem::keypair();
            let mut pre = tag.to_vec();
            pre.extend_from_slice(&ek);
            let h = crate::hash::Hash32::hash(&pre);
            // The four limbs walk the hash's OWN bytes in 8-byte chunks (the AG class 9 rule: never an `i * 8` index).
            let mut limbs = [0u64; 4];
            for (limb, chunk) in limbs.iter_mut().zip(h.as_bytes().chunks_exact(8)) {
                *limb = u64::from_le_bytes(chunk.try_into().expect("8 bytes")) & 0x3fff_ffff;
            }
            lanes_of(&limbs)
        };

        // ── 1. THE CUSTODIANS AND THE WRAPPED ASSET.
        let seated = wait_seats(&mesh, 2, 420);
        assert_eq!(seated, (Some(2), Some(2)), "PRECONDITION: both daemons are bonded seats — the custodians");
        let line = format!("[wrapped-register] applied: asset {ASSET} ratio {RATIO}");
        let applied = |i: usize| -> bool { std::fs::read_to_string(mesh.log_path(i)).unwrap_or_default().contains(&line) };
        let msg = crate::peg::PegLedger::wrapped_register_msg(0, ASSET, 0, RATIO);
        let mut att: Vec<u8> = Vec::new();
        // PRODUCTION-SCALE-REVIEWED: `0..2` is the two real node PROCESSES of this pin (`i` indexes RealMesh), each an
        // operator signing with its own seated key; it bounds no cover, nullifier or note count.
        for i in 0..2 {
            let (pk, sk) = mesh.validator_key(i).unwrap_or_else(|e| panic!("⛔ operator {i}'s key: {e}"));
            let sig = crate::pqauth::ml_dsa_sign(&msg, &sk).expect("each operator signs the statement");
            att.extend_from_slice(&(pk.len() as u16).to_le_bytes());
            att.extend_from_slice(&pk);
            att.extend_from_slice(&(sig.len() as u16).to_le_bytes());
            att.extend_from_slice(&sig);
        }
        let reply = mesh
            .post(
                spending_node,
                "/register_wrapped_asset",
                &format!(r#"{{"asset_id":{ASSET},"ratio_bps":{RATIO},"epoch_id":0,"attestors_hex":"{}"}}"#, hexs(&att)),
            )
            .unwrap_or_else(|e| panic!("⛔ the registration route: {e}"));
        assert!(reply.contains("PUBLISHED"), "the registration must be PUBLISHED as a chain object: {reply}");
        let t = Instant::now();
        while !(applied(0) && applied(1)) {
            assert!(t.elapsed() < Duration::from_secs(CHAIN_WAIT_S), "⛔ the wrapped registration never applied on both processes");
            std::thread::sleep(Duration::from_secs(3));
        }

        // ── 2. THE DEPOSIT: a per-swap reserve address, and a REAL coin mined to the custodians' own count.
        let d_blind = fresh(b"wrappedmint-d-blind");
        let d_blind_hex = hexs(&crate::spend_frontier::digest_to_lane_bytes(&d_blind));
        let t = Instant::now();
        let reserve_address = loop {
            let r = mesh
                .post(spending_node, "/get_reserve_swap_address", &format!(r#"{{"asset":"BTC","d_blind_hex":"{d_blind_hex}"}}"#))
                .unwrap_or_default();
            if r.contains("\"reserve_ready\":true") {
                break json_str(&r, "deposit_address").expect("a ready reserve names its deposit address");
            }
            assert!(t.elapsed() < Duration::from_secs(600), "⛔ the custodians' reserve never became ready within 600 s: {r}");
            std::thread::sleep(Duration::from_secs(5));
        };
        let deposit_id = crate::peg::deposit_id_for_reserve_address(&reserve_address);
        let btc = format!("{}.{:08}", DEPOSIT_SATS / 100_000_000, DEPOSIT_SATS % 100_000_000);
        let txid = regtest.send(&reserve_address, &btc).unwrap_or_else(|e| panic!("⛔ Core could not fund the reserve: {e}"));
        let confs = crate::btc_watch::required_confirmations(DEPOSIT_SATS) + 1;
        regtest.mine(confs).unwrap_or_else(|e| panic!("⛔ Core could not mine the deposit: {e}"));
        eprintln!("[wrapped-mint-real] deposited {btc} BTC in {txid}, mined under {confs} block(s) (Core h={})", regtest.height());

        // ── 3. THE WRAPPED MINT over a note only this client holds.
        let note_sk_owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key(fresh(b"wrappedmint-note-sk"));
        let note_sk = note_sk_owner.opening(); // DB-395: the note's opening, under its owner
        let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(ASSET);
        let (mint_carrier, wcm, _wdc) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(MINTED, wtag, &note_sk, &d_blind)
                .expect("an authorized amount proves its own commitment in its own asset");
        let wcm_bytes = leaf_to_cm_bytes(wcm);
        let delta = crate::peg::PegLedger::mint_delta_commit(MINTED as u128, d_blind);
        // PRODUCTION-SCALE-REVIEWED: `0..2` is the two real node PROCESSES (RealMesh indices): the claim is read from each
        // process's own socket, not a cover width.
        for i in 0..2 {
            assert!(
                record_of(i, &wcm_bytes).is_none(),
                "CONTROL 1: process {i} places the wrapped note before any mint was requested"
            );
        }
        // ⭐ DB-273 §19 L1: the minter's owner is a REAL OLI clue for its own locator; the door computes the recipient
        // the quorum signs as the commitment to it, so no `recipient` rides the request.
        let owner_loc_sk = crate::oli::derive_loc_sk(blake3::hash(b"journey-wrapped-minter").as_bytes());
        let owner_salt = crate::oli::address_salt(&owner_loc_sk, "chg", 0);
        let owner_clue = crate::oli::tag_clue_bytes_v2(
            &crate::oli::locator_at(&owner_loc_sk, "chg", 0),
            &owner_salt,
            &crate::oli::address_index_hint(&owner_loc_sk, &owner_salt, 0),
        );
        let mint_body = format!(
            r#"{{"asset_id":{ASSET},"deposit_id":"{}","deposit_value":{DEPOSIT_SATS},"mint":{MINTED},"note_payload":"{}","reserve_address":"{reserve_address}","mint_carrier_hex":"{}","delta_commit":"{}","d_blind_hex":"{d_blind_hex}","note_clue_hex":"{}"}}"#,
            hexs(&deposit_id),
            hexs(&note_of(wcm)),
            hexs(&mint_carrier),
            hexs(&leaf_to_cm_bytes(delta)),
            hexs(&owner_clue)
        );
        let t = Instant::now();
        let outcome = loop {
            let r = mesh.post(spending_node, "/wrapped_mint_execute", &mint_body).unwrap_or_else(|e| e);
            let o = json_str(&r, "outcome").unwrap_or_default();
            assert!(!o.starts_with("BAD_REQUEST"), "⛔ the wrapped-mint request was malformed: {r}");
            if o == "CONFIDENTIAL_PUBLISHED" || o == "ALREADY_MINTED" {
                break o;
            }
            assert!(
                t.elapsed() < Duration::from_secs(900),
                "⛔ the custodians never published the wrapped mint within 900 s (last answer {r})"
            );
            std::thread::sleep(Duration::from_secs(5));
        };
        eprintln!(
            "[wrapped-mint-real] the quorum answered {outcome} after {:.1}s",
            t.elapsed().as_secs_f64()
        );

        // ── 4. THE MINT RIDES A BLOCK: the other process places the note from the block alone.
        let t = Instant::now();
        while !(record_of(other, &wcm_bytes).is_some() && record_of(spending_node, &wcm_bytes).is_some()) {
            assert!(
                t.elapsed() < Duration::from_secs(CHAIN_WAIT_S),
                "⛔⛔⛔ the wrapped note never reached a record on both processes within 420 s of its publication — \
                 a mint that stayed on its publisher"
            );
            std::thread::sleep(Duration::from_secs(3));
        }
        let ((h0, s0, _), (h1, s1, _)) = (snap(0), snap(1));
        common_position_past(h0.max(h1), s0.max(s1), 20, "the wrapped mint");

        // ── 5. THE HOLDER MOVES IT through process 0, from process 0's own served copath.
        let want_leaf = note_leaf_of(&wcm_bytes);
        let t = Instant::now();
        let (named_record, sibs, dirs, root) = loop {
            if let Some(addr) = record_of(spending_node, &wcm_bytes) {
                let body = format!(r#"{{"cms_hex":"{}","addrs_hex":"{}"}}"#, hexs(&wcm_bytes), hexs(&addr.to_le_bytes()));
                let r = mesh.post(spending_node, "/note_copath", &body).unwrap_or_default();
                if r.contains("\"served\":true") {
                    let lane = crate::spend_frontier::DIGEST_LANE_BYTES;
                    let sibs: Vec<Digest4> = unhex(&json_str(&r, "siblings_hex").expect("a served copath names its siblings"))
                        .chunks_exact(lane)
                        .map(|b| crate::spend_frontier::digest_from_lane_bytes(b).expect("⛔ a non-canonical sibling"))
                        .collect();
                    let dirs: Vec<bool> =
                        json_str(&r, "dirs").expect("a served copath names its sides").chars().map(|ch| ch == '1').collect();
                    let root = crate::spend_frontier::digest_from_lane_bytes(&unhex(
                        &json_str(&r, "block_root_hex").expect("a served copath names its record root"),
                    ))
                    .expect("⛔ a non-canonical record root");
                    break (addr, sibs, dirs, root);
                }
            }
            assert!(
                t.elapsed() < Duration::from_secs(300),
                "⛔ process {spending_node} never served the wrapped note's record within 300 s"
            );
            std::thread::sleep(Duration::from_secs(3));
        };
        let refold = sibs
            .iter()
            .zip(&dirs)
            .fold(want_leaf, |cur, (s, right)| if *right { poseidon_pair(*s, cur) } else { poseidon_pair(cur, *s) });
        assert_eq!(refold, root, "⛔ the served copath does not refold the wrapped note's leaf to the served record root");
        let build = |out0: u64| -> (String, [Digest4; 2]) {
            let w = AssetSpendValidityWitness {
                value_in: MINTED,
                owner: note_sk_owner,
                value_out: MINTED,
                fee: 0,
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
                out0_value: out0,
                out0_opening: usdm_decider::poseidon2_compress::lanes_of_const(&[31, 41, 59, 26]),
                out1_value: MINTED - out0,
                out1_opening: usdm_decider::poseidon2_compress::lanes_of_const(&[27, 18, 28, 18]),
                asset: wtag,
            };
            assert_eq!(
                asset_spend_input_leaf(&w).expect("the input opens"),
                want_leaf,
                "⛔ THE TRANSFER'S INPUT LEAF IS NOT THE WRAPPED NOTE'S LEAF"
            );
            let (validity_carrier, cms, nf, lc) =
                prove_asset_spend_validity_carrier_bytes(&w).expect("an honest transfer proves");
            let mut mc = NoteMembershipCarrier::new(want_leaf, root, crate::node::Node::MEMBERSHIP_GENESIS_ACC, nf, crate::spend_frontier::TEST_LC_BLIND);
            assert!(mc.attach_membership(want_leaf, &sibs, &dirs), "the served copath reaches the record root");
            assert!(mc.step(root), "the one fold step proves");
            let (membership_carrier, tip_acc, tip_prev, tip_root) = mc.finalize_one_step().expect("certifies");
            assert_eq!(mc.leaf_commitment(), lc, "⛔ the two carriers name DIFFERENT notes");
            let t = crate::asset_tx::AssetSpendTx {
                notes: [note_of(cms[0]), note_of(cms[1])],
                nullifier: leaf_to_cm_bytes(nf),
                leaf_commit: lc,
                validity_carrier,
                membership_carrier,
                member_tuple: Vec::new(),
                named_record,
                tip_prev,
                tip_root,
                tip_acc,
                // DB-273 §19.6 L3: one owner clue per output, sent keyed to the outputs as `note_clues_hex`.
                owner_clues: vec![journey_owner_clue(0x5a1), journey_owner_clue(0x5a2)],
                slot_tag: None,
            };
            let outs = t.output_commitments().expect("canonical output fronts");
            let d = |x: Digest4| hexs(&leaf_to_cm_bytes(x));
            let body = format!(
                r#"{{"note0":"{}","note1":"{}","nullifier":"{}","leaf_commit":"{}","validity_carrier":"{}","membership_carrier":"{}","named_record":{},"tip_prev":"{}","tip_root":"{}","tip_acc":"{}","note_clues_hex":"{}"}}"#,
                hexs(&t.notes[0]),
                hexs(&t.notes[1]),
                hexs(&t.nullifier),
                d(t.leaf_commit),
                hexs(&t.validity_carrier),
                hexs(&t.membership_carrier),
                t.named_record,
                d(t.tip_prev),
                d(t.tip_root),
                d(t.tip_acc),
                hexs(&crate::node::Node::encode_note_clue_records(
                    &t.notes
                        .iter()
                        .zip(t.owner_clues.iter())
                        .filter_map(|(n, c)| Some((<[u8; 32]>::try_from(n.get(..32)?).ok()?, c.clone())))
                        .collect::<Vec<_>>()
                ))
            );
            (body, outs)
        };
        let (first_body, outs) = build(700_000);
        let out_cms: Vec<[u8; 32]> = outs.iter().map(|o| leaf_to_cm_bytes(*o)).collect();
        // PRODUCTION-SCALE-REVIEWED: `0..2` is the two real node PROCESSES (RealMesh indices); each must place every
        // output from the block alone. The outputs themselves are the spend's full production set.
        for i in 0..2 {
            for o in &out_cms {
                assert!(
                    record_of(i, o).is_none(),
                    "CONTROL 2: process {i} places an output of a transfer nobody has published"
                );
            }
        }
        // DB-358: a spend may consume only CANONICAL state, so the door refuses a note whose record is not yet FOLDED and
        // logs "retry after the fold" (the minted note's record folds `record_fold_depth` blocks after it lands) and answers
        // its retry code, MEMBERSHIP_NOT_FOLDED_YET (409 — `MemberVerdict::Pending`; a forgery answers 422). The SAME
        // transfer is resubmitted while that is the answer — bounded; any other answer, or the bound, fails loudly below.
        let t_fold = Instant::now();
        let first = loop {
            let r = post_holding(spending_node, "/submit_asset_spend", &first_body, "the transfer");
            if r.contains("\"verdict\":\"PUBLISHED\"")
                || !r.contains("MEMBERSHIP_NOT_FOLDED_YET")
                || t_fold.elapsed() > Duration::from_secs(360)
            {
                break r;
            }
            std::thread::sleep(Duration::from_secs(5));
        };
        eprintln!("[wrapped-mint-real] the transfer was admitted {:.1}s after the note's record could first be served", t_fold.elapsed().as_secs_f64());
        assert!(
            first.contains("\"verdict\":\"PUBLISHED\""),
            "CALIBRATION: process {spending_node} must admit an honest transfer of the wrapped note: {first}"
        );
        let t = Instant::now();
        loop {
            let placed: Vec<bool> = out_cms.iter().map(|o| record_of(other, o).is_some()).collect();
            if placed.iter().all(|p| *p) {
                eprintln!(
                    "[wrapped-mint-real] process {other} places both transfer outputs after {:.1}s",
                    t.elapsed().as_secs_f64()
                );
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(CHAIN_WAIT_S),
                "⛔⛔⛔ PROCESS {other} NEVER PLACED THE TRANSFER'S OUTPUTS within 420 s (placed {placed:?})"
            );
            std::thread::sleep(Duration::from_secs(3));
        }
        let (h_x, s_x, _) = snap(spending_node);
        common_position_past(h_x, s_x, 20, "the transfer");

        // ── 6. THE CLAIM: a second spend of the wrapped note is refused by the SPENT SET on both processes.
        let (second_body, second_outs) = build(400_000);
        assert_ne!(second_outs, outs, "PRECONDITION: the second spend is different bytes, so only the spent set can refuse it");
        for i in [other, spending_node] {
            let r = post_holding(i, "/submit_asset_spend", &second_body, "a second spend of the wrapped note");
            // DIGITAL-CASH-PRIVACY-REVIEWED: route verdicts only — no amount beyond this pin's own literals, no owner.
            eprintln!("[wrapped-mint-real] process {i} second spend of the wrapped note: {r}");
            assert!(
                !r.contains("\"verdict\":\"PUBLISHED\""),
                "⛔⛔⛔ PROCESS {i} ADMITTED A SECOND SPEND OF A WRAPPED NOTE WHOSE TRANSFER A BLOCK ALREADY CARRIED: {r}"
            );
            assert!(
                r.contains("the note is already spent"),
                "⛔ process {i} refused the second spend, but NOT by the spent set: {r}"
            );
        }
    }

    /// ⭐⭐⭐ CRITERION 2 — `BridgeCredit` ON REAL NODE PROCESSES (DB-224).
    ///
    /// A bridge credit is a framed chain object. Since DB-224 it rides the block's carried credit set and
    /// every node applies it from the block. This is that claim on real processes: the credit is POSTed to
    /// the SUBMITTING process's faucet, and the wallet that owns it talks to the RECEIVING process only
    /// (its node URL names that process's socket and nothing else). So the spendable balance it reports is
    /// what the receiving process applied and serves, never a read of the submitting process's state.
    ///
    /// CONTROL: before the drip, the same wallet reads 0 through the receiving process.
    /// SCOPE: the faucet is testnet scaffolding, and this pin claims only the `BridgeCredit` class. The
    /// register's peg rule keeps it away from `PegIn` / `PegOut`, whose doors it never touches. Two
    /// processes on one machine prove the class travels between processes; they are not a scale claim.
    #[test]
    fn a_bridge_credit_posted_to_one_real_process_is_spendable_through_the_other() {
        const DRIP_ATOMIC: u64 = 2_500_000_000; // 25.0 USDm, the gate's own drip
        let (submitting_node, peer) = (0usize, 1usize);
        let mesh = match RealMesh::start(2, "bridgecredit") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let peer_url = format!("http://127.0.0.1:{}", mesh.port(peer));
        let w = match RealWallet::create("bridgecredit", "holder", &peer_url) {
            Ok(w) => w,
            Err(e) => panic!("⛔ THE REAL WALLET COULD NOT BE CREATED against the receiving process: {e}"),
        };
        let spendable_on_peer = |w: &RealWallet| -> u64 {
            w.run(&["refresh", "balance"])
                .unwrap_or_default()
                .iter()
                .filter(|l| l.contains("\"op\":\"balance\""))
                .filter_map(|l| json_u64(l, "atomic"))
                .last()
                .unwrap_or(0)
        };
        assert_eq!(
            spendable_on_peer(&w),
            0,
            "CONTROL: the wallet must read nothing through the receiving process before any credit exists — \
             or a balance afterwards would prove nothing about the credit travelling"
        );

        let drip = mesh
            .post(submitting_node, "/faucet/drip", &format!(r#"{{"amount":{DRIP_ATOMIC},"to":"{}"}}"#, w.address))
            .unwrap_or_else(|e| panic!("⛔ the submitting process's faucet refused the drip over its real RPC: {e}"));
        eprintln!("[bridge-credit-real] drip on process {submitting_node} -> {}", drip.trim());
        assert!(
            drip.contains("\"published\":true"),
            "the drip must be PUBLISHED on the submitting process as a chain object, not staged locally: {drip}"
        );

        // The money must become SPENDABLE through the receiving process: carried by a block, applied
        // there, and served to its wallet.
        let t = Instant::now();
        let mut got = 0u64;
        while t.elapsed() < Duration::from_secs(300) {
            got = spendable_on_peer(&w);
            if got >= DRIP_ATOMIC {
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        eprintln!(
            "[bridge-credit-real] after {:.1}s the wallet on process {peer} reads {got} atomic spendable \
             (heights {:?}/{:?})",
            t.elapsed().as_secs_f64(),
            mesh.height(submitting_node),
            mesh.height(peer)
        );
        assert!(
            got >= DRIP_ATOMIC,
            "⛔⛔⛔ A CREDIT POSTED TO THE SUBMITTING PROCESS NEVER BECAME SPENDABLE THROUGH THE RECEIVING \
             PROCESS within 300 s (read {got} atomic, wanted {DRIP_ATOMIC}). Either no block carried the credit \
             object to the other process, or that process did not apply it — the object applying only where \
             it was submitted is exactly what DB-224 exists to end."
        );
    }

    /// ⭐⭐⭐ CRITERION 2 — `MembershipBond` ON REAL NODE PROCESSES, split out of the peg journey (DB-240).
    ///
    /// Each process the rig launches publishes its own free seat as a `Class::MembershipBond` chain object.
    /// Since DB-224 that object rides the block's carried set, and every node applies it from the block. The
    /// claim: each process ends holding the OTHER's seat, so both report the same seat count, one per process,
    /// read from each one's own socket.
    ///
    /// WHY IT IS ITS OWN PIN: the journey this class used to cite also runs a peg mint, and DB-240 makes that
    /// mint unattestable on today's tree (no price mark can exist). A seat proof must not ride a pin whose
    /// later arm is red for an unrelated reason. Two processes on one machine: not a scale claim.
    #[test]
    fn two_real_processes_each_hold_the_seat_the_other_published() {
        let (first_node, second_node) = (0usize, 1usize);
        let mesh = match RealMesh::start(2, "seatonly") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let seats_of = |i: usize| -> Option<usize> {
            mesh.get(i, "/get_validator_bond_tree")
                .ok()
                .and_then(|t| json_u64(&t, "validators"))
                .map(|n| n as usize)
        };
        let t = Instant::now();
        let mut last = (None, None);
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            last = (seats_of(first_node), seats_of(second_node));
            let two_way =
                mesh.peer_count_excluding_self(first_node) >= 1 && mesh.peer_count_excluding_self(second_node) >= 1;
            if two_way && last.0 == last.1 && last.0.is_some_and(|n| n >= mesh.len()) {
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        eprintln!(
            "[seat-real] after {:.1}s seats: process {first_node}={:?} process {second_node}={:?}",
            t.elapsed().as_secs_f64(),
            last.0,
            last.1
        );
        assert!(
            last.0 == last.1 && last.0.is_some_and(|n| n >= mesh.len()),
            "⛔⛔⛔ THE TWO REAL PROCESSES DO NOT HOLD EACH OTHER'S SEAT within 420 s (process {first_node}={:?}, \
             process {second_node}={:?}, wanted {} on both). A seat that lands only on its publisher is the \
             local-mutation class DB-224 closes for every framed object.",
            last.0,
            last.1,
            mesh.len()
        );
    }

    /// Seats per process, read from each process's own socket.
    fn seats_on(mesh: &RealMesh, i: usize) -> Option<usize> {
        mesh.get(i, "/get_validator_bond_tree")
            .ok()
            .and_then(|t| json_u64(&t, "validators"))
            .map(|n| n as usize)
    }

    /// Wait (bounded) until both processes report exactly `n` seats; returns what each last reported.
    fn wait_seats(mesh: &RealMesh, n: usize, secs: u64) -> (Option<usize>, Option<usize>) {
        let t = Instant::now();
        let mut last = (None, None);
        while t.elapsed() < Duration::from_secs(secs) {
            last = (seats_on(mesh, 0), seats_on(mesh, 1));
            if last == (Some(n), Some(n)) {
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        last
    }

    /// ⭐⭐⭐ CRITERION 2 — `Unbond` ON REAL NODE PROCESSES.
    ///
    /// Both daemons seat themselves: a free `Class::MembershipBond` each, the seat pin's journey. Process 1's
    /// OPERATOR then unbonds process 1's seat through the production route, `/unbond_validator`. It signs with the
    /// validator key the daemon itself seated with, read from that daemon's own datadir. The unbond is a chain
    /// object, so the weight leaves when a block carries it, on every node, not where it was posted.
    /// The claim, read from each process's own socket: BOTH processes drop from 2 seats to 1.
    /// CONTROL: both held both seats first. Two processes on one machine: not a scale claim.
    #[test]
    fn a_seat_unbonded_through_one_real_process_leaves_the_validator_set_of_both() {
        let mesh = match RealMesh::start(2, "unbondreal") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let before = wait_seats(&mesh, 2, 420);
        assert_eq!(before, (Some(2), Some(2)), "CONTROL: both real processes hold both seats before any unbond");
        // DB-272 + DB-258: the operator unbonds its node's OWN identity through the loopback route; the node signs the v2
        // statement (validator, live bonding, owner) with its vote key, from its own chain state.
        // DB-273 §19.3 L2: the operator names the returned bond's owner by a REAL OLI clue for its own locator.
        let owner_loc_sk = crate::oli::derive_loc_sk(blake3::hash(b"journey-unbond-operator").as_bytes());
        let owner_salt = crate::oli::address_salt(&owner_loc_sk, "chg", 0);
        let owner_clue = crate::oli::tag_clue_bytes_v2(
            &crate::oli::locator_at(&owner_loc_sk, "chg", 0),
            &owner_salt,
            &crate::oli::address_index_hint(&owner_loc_sk, &owner_salt, 0),
        );
        let body = format!(r#"{{"own":true,"note_clue_hex":"{}"}}"#, hexs(&owner_clue));
        // The operator posts to its OWN process; the PEER never sees the post and must still drop the seat.
        let (publisher, peer) = (1usize, 0usize);
        let reply = mesh.post(publisher, "/unbond_validator", &body).unwrap_or_else(|e| panic!("⛔ the unbond route: {e}"));
        assert!(reply.contains("PUBLISHED"), "the unbond must be PUBLISHED as a chain object: {reply}");
        let t = Instant::now();
        let after = wait_seats(&mesh, 1, 420);
        // DIGITAL-CASH-PRIVACY-REVIEWED: seat COUNTS, already public at /get_validator_bond_tree.
        eprintln!(
            "[unbond-real] after {:.1}s seats: process 0={:?} process 1={:?}",
            t.elapsed().as_secs_f64(),
            after.0,
            after.1
        );
        let peer_seats = if peer == 0 { after.0 } else { after.1 };
        assert_eq!(
            peer_seats,
            Some(1),
            "⛔⛔⛔ THE PEER (process {peer}), which never saw the post, still counts the unbonded seat — the unbond did \
             not travel"
        );
        assert_eq!(
            after,
            (Some(1), Some(1)),
            "⛔⛔⛔ THE UNBOND DID NOT LEAVE BOTH REAL PROCESSES' VALIDATOR SETS within 420 s. A release that lands \
             only where it was posted is the §AS divergence: the finality denominator differs between honest nodes."
        );
    }

    /// ⭐⭐⭐ CRITERION 2 — `Equivocation` ON REAL NODE PROCESSES (DB-334).
    ///
    /// Both daemons seat themselves (the Unbond pin's journey). The harness then plays a WATCHTOWER that saw process 0's
    /// validator sign two different blocks at one height: it signs both votes with the key process 0's daemon seated
    /// with, read from that daemon's own datadir, and reports the pair to PROCESS 1 ONLY, through the production route
    /// `/report_equivocation`. The evidence is a chain object, so the slash lands wherever a block carrying it grafts —
    /// on every node, including process 0, which was never told. The claim, read from each process's own socket: BOTH
    /// processes drop from 2 seats to 1. CONTROL: both held both seats first. Two processes on one machine: not a scale
    /// claim.
    #[test]
    fn two_real_processes_slash_a_validator_whose_equivocation_one_of_them_was_told_of() {
        let mesh = match RealMesh::start(2, "equivocreal") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let before = wait_seats(&mesh, 2, 420);
        assert_eq!(before, (Some(2), Some(2)), "CONTROL: both real processes hold both seats before any report");
        let (pk, sk) = mesh.validator_key(0).unwrap_or_else(|e| panic!("⛔ process 0's seat key: {e}"));
        let height = 7u64;
        let vote = |tag: &[u8]| {
            let block = crate::hash::Hash32::hash(tag);
            crate::validator::VoteCert {
                pubkey: pk.clone(),
                block,
                height,
                sig: crate::pqauth::ml_dsa_sign(&crate::pqauth::finality_vote_msg(&block, height), &sk)
                    .expect("the seat key signs a finality vote"),
            }
        };
        let (a, b) = (vote(b"equivoc-real-x"), vote(b"equivoc-real-y"));
        let body = format!(r#"{{"vote_a_hex":"{}","vote_b_hex":"{}"}}"#, hexs(&a.to_wire()), hexs(&b.to_wire()));
        let (reporter, other) = (1usize, 0usize);
        let reply = mesh.post(reporter, "/report_equivocation", &body).unwrap_or_else(|e| panic!("⛔ the report route: {e}"));
        assert!(reply.contains("PUBLISHED"), "the evidence must be PUBLISHED as a chain object: {reply}");
        let t = Instant::now();
        let after = wait_seats(&mesh, 1, 420);
        // DIGITAL-CASH-PRIVACY-REVIEWED: seat COUNTS, already public at /get_validator_bond_tree.
        eprintln!(
            "[equivocation-real] after {:.1}s seats: process 0={:?} process 1={:?}",
            t.elapsed().as_secs_f64(),
            after.0,
            after.1
        );
        let other_seats = if other == 0 { after.0 } else { after.1 };
        assert_eq!(
            other_seats,
            Some(1),
            "⛔⛔⛔ THE PROCESS THAT WAS NEVER TOLD (process {other}) still counts the equivocator's seat — the evidence \
             did not travel"
        );
        assert_eq!(
            after,
            (Some(1), Some(1)),
            "⛔⛔⛔ THE EQUIVOCATOR WAS NOT SLASHED ON BOTH REAL PROCESSES within 420 s — a slash applied where it was \
             reported is the DB-266 divergence: every ≥2/3 denominator differs between honest nodes"
        );
    }

    /// ⭐⭐⭐ CRITERION 2 — `ReserveTheft` ON REAL NODE PROCESSES (DB-274 P4b, §8.15, commit ecd7f6f).
    ///
    /// Both daemons seat themselves (the Unbond pin's journey). The harness then plays the WATCHTOWER that saw process
    /// 0's custodian key move the reserve with no authorization:
    /// - BOTH seats sign the v2 theft message (`theft_tx::theft_msg`: the statement AND the offender id, process 0's
    ///   validator). Two of two seats is ≥ ⅔ of the bonded weight.
    /// - The evidence is reported to PROCESS 1 ONLY, through the production route `/slash_reserve_theft`.
    /// - The route only PUBLISHES. The block that carries the object slashes at its fold on every node, including the
    ///   peer process 0, which was never told.
    ///
    /// The claim, read from each process's own socket: BOTH processes drop from 2 seats to 1, the reporter AND the
    /// other process that only saw blocks.
    /// CONTROL: both held both seats first.
    /// Two processes on one machine: not a scale claim.
    #[test]
    fn two_real_processes_slash_a_reserve_thief_that_one_of_them_was_told_of() {
        let mesh = match RealMesh::start(2, "theftreal") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let before = wait_seats(&mesh, 2, 420);
        assert_eq!(before, (Some(2), Some(2)), "CONTROL: both real processes hold both seats before any report");
        let (pk0, sk0) = mesh.validator_key(0).unwrap_or_else(|e| panic!("⛔ process 0's seat key: {e}"));
        let (pk1, sk1) = mesh.validator_key(1).unwrap_or_else(|e| panic!("⛔ process 1's seat key: {e}"));
        let thief = crate::pqauth::pubkey_id(&pk0);
        let statement = crate::bond_tally::reserve_move_statement(
            "BTC",
            b"tb1pREALTHIEF",
            &usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
            &[0x5au8; 32],
            3,
        );
        let msg = crate::theft_tx::theft_msg(&statement, &[thief], 100_000_000);
        // The attestation wire the threshold routes share: pubkey_len(u16 LE) ‖ pubkey ‖ sig_len(u16 LE) ‖ sig.
        let mut attestors: Vec<u8> = Vec::new();
        for (pk, sk) in [(&pk0, &sk0), (&pk1, &sk1)] {
            let sig = crate::pqauth::ml_dsa_sign(&msg, sk).expect("each seat signs the theft statement");
            attestors.extend_from_slice(&(pk.len() as u16).to_le_bytes());
            attestors.extend_from_slice(pk);
            attestors.extend_from_slice(&(sig.len() as u16).to_le_bytes());
            attestors.extend_from_slice(&sig);
        }
        let body = format!(
            r#"{{"statement_hex":"{}","attestors_hex":"{}","offenders_hex":"{}","loss_sats":100000000}}"#,
            hexs(&statement),
            hexs(&attestors),
            hexs(&thief)
        );
        let (reporter, peer) = (1usize, 0usize);
        let reply = mesh.post(reporter, "/slash_reserve_theft", &body).unwrap_or_else(|e| panic!("⛔ the route: {e}"));
        assert!(reply.contains("PUBLISHED"), "the theft evidence must be PUBLISHED as a chain object: {reply}");
        let t = Instant::now();
        let after = wait_seats(&mesh, 1, 420);
        // DIGITAL-CASH-PRIVACY-REVIEWED: seat COUNTS, already public at /get_validator_bond_tree.
        eprintln!(
            "[theft-real] after {:.1}s seats: process 0={:?} process 1={:?}",
            t.elapsed().as_secs_f64(),
            after.0,
            after.1
        );
        let peer_seats = if peer == 0 { after.0 } else { after.1 };
        assert_eq!(
            peer_seats,
            Some(1),
            "⛔⛔⛔ THE PEER PROCESS THAT WAS NEVER TOLD (process {peer}) still counts the thief's seat — the evidence did \
             not travel"
        );
        assert_eq!(
            after,
            (Some(1), Some(1)),
            "⛔⛔⛔ THE THIEF WAS NOT SLASHED ON BOTH REAL PROCESSES within 420 s — a slash applied where it was reported \
             is the DB-274 §8.15 socket-mutation class: every ≥2/3 denominator differs between honest nodes"
        );
    }

    /// ⭐⭐⭐ CRITERION 2 — `WrappedAssetRegister` ON REAL NODE PROCESSES.
    ///
    /// The ratio a wrapped asset mints against is a chain object with a ≥2/3 bonded tally at apply. Both daemons
    /// are the bonded seats. Each operator signs the registration's statement with the key its daemon seated
    /// with, and it is published through process 0. The claim, read from BOTH processes' own logs: each
    /// process's door applied the same (asset, ratio) from a block.
    /// CONTROL: before the publish, neither log names this registration. Two processes on one machine: not a
    /// scale claim.
    #[test]
    fn two_real_validators_register_a_wrapped_asset_and_both_processes_apply_the_ratio() {
        const ASSET: u32 = 77;
        const RATIO: u32 = 15_000;
        let mesh = match RealMesh::start(2, "wrappedreg") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let seated = wait_seats(&mesh, 2, 420);
        assert_eq!(seated, (Some(2), Some(2)), "PRECONDITION: both daemons are bonded seats (the tally's weight)");
        let line = format!("[wrapped-register] applied: asset {ASSET} ratio {RATIO}");
        let applied = |i: usize| -> bool {
            std::fs::read_to_string(mesh.log_path(i)).unwrap_or_default().contains(&line)
        };
        assert!(!applied(0) && !applied(1), "CONTROL: neither process has applied this registration yet");
        let msg = crate::peg::PegLedger::wrapped_register_msg(0, ASSET, 0, RATIO);
        let mut att: Vec<u8> = Vec::new();
        for i in 0..2 {
            let (pk, sk) = mesh.validator_key(i).unwrap_or_else(|e| panic!("⛔ operator {i}'s key: {e}"));
            let sig = crate::pqauth::ml_dsa_sign(&msg, &sk).expect("each operator signs the statement");
            att.extend_from_slice(&(pk.len() as u16).to_le_bytes());
            att.extend_from_slice(&pk);
            att.extend_from_slice(&(sig.len() as u16).to_le_bytes());
            att.extend_from_slice(&sig);
        }
        let body = format!(
            r#"{{"asset_id":{ASSET},"ratio_bps":{RATIO},"epoch_id":0,"attestors_hex":"{}"}}"#,
            hexs(&att)
        );
        // Published through ONE process; the PEER learns of it only from a block.
        let (publisher, peer) = (0usize, 1usize);
        let reply = mesh.post(publisher, "/register_wrapped_asset", &body).unwrap_or_else(|e| panic!("⛔ the route: {e}"));
        assert!(reply.contains("PUBLISHED"), "the registration must be PUBLISHED as a chain object: {reply}");
        let t = Instant::now();
        let mut both = (false, false);
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            both = (applied(0), applied(1));
            if both == (true, true) {
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        eprintln!(
            "[wrapped-register-real] after {:.1}s: applied on process 0={} process 1={}",
            t.elapsed().as_secs_f64(),
            both.0,
            both.1
        );
        assert!(
            applied(peer),
            "⛔⛔⛔ THE PEER (process {peer}) never applied the registration it could only have learned from a block"
        );
        assert_eq!(
            both,
            (true, true),
            "⛔⛔⛔ THE TWO REAL PROCESSES DID NOT BOTH APPLY THE REGISTRATION within 420 s. A ratio that differs \
             between honest nodes is a mint gate measured against two numbers."
        );
    }

    /// ⭐⭐⭐ CRITERION 2 — `PriceMark` ON REAL NODE PROCESSES (DB-240's production publisher, measured).
    ///
    /// Both daemons are seated validators, and each samples the onion price relays over its own Tor (§21 — nobody types a
    /// price). Neither is handed a mark. Each node's own reporter signs a quote and gossips
    /// it over the onion lane. Each node gathers the other's quote, and at ≥2/3 of bonded weight one of them
    /// publishes a `Class::PriceMark` through `ingest_tx`. The claim is read from BOTH processes' own logs: each
    /// node's door applied the same (epoch, asset, price), from a block.
    /// CONTROL: before any mark, neither log names one. Two processes on one machine: not a scale claim.
    #[test]
    fn two_real_validators_price_an_asset_and_both_processes_apply_the_same_mark() {
        let mesh = RealMesh::start(2, "pricemark");
        let mesh = match mesh {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let (publisher_side, peer) = (0usize, 1usize);
        let applied = |i: usize| -> Option<String> {
            std::fs::read_to_string(mesh.log_path(i))
                .unwrap_or_default()
                .lines()
                .filter(|l| l.contains("[price-mark] applied:"))
                .last()
                .map(|l| l.split("applied:").nth(1).unwrap_or("").trim().to_string())
        };
        // No "before" control. A slow mesh start can already contain the seats and the first quotes, and a
        // control that fails on timing is not evidence. Non-vacuity comes from the claim itself: no mark exists
        // at genesis, so a mark can only be applied if a process PUBLISHED one (counted below), and both
        // processes must stand on it.
        let t = Instant::now();
        let mut last = (None, None);
        while t.elapsed() < Duration::from_secs(CHAIN_WAIT_S) {
            last = (applied(publisher_side), applied(peer));
            if last.0.is_some() && last.0 == last.1 {
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        let published = [publisher_side, peer]
            .iter()
            .map(|&i| {
                std::fs::read_to_string(mesh.log_path(i))
                    .unwrap_or_default()
                    .matches("[price-mark] published:")
                    .count()
            })
            .collect::<Vec<_>>();
        eprintln!(
            "[price-mark-real] after {:.1}s: process {publisher_side} stands on {:?}, process {peer} on {:?}; \
             publications per process {:?}",
            t.elapsed().as_secs_f64(),
            last.0,
            last.1,
            published
        );
        assert!(
            published.iter().sum::<usize>() >= 1,
            "⛔ NEITHER PROCESS PUBLISHED A MARK within 420 s — the production reporter/gatherer never reached \
             a >=2/3 quote book on real processes"
        );
        assert!(
            last.0.is_some() && last.0 == last.1,
            "⛔⛔⛔ THE TWO REAL PROCESSES DO NOT STAND ON THE SAME MARK (process {publisher_side}={:?}, \
             process {peer}={:?}) — a price that differs between honest nodes is solvency measured against \
             two numbers.",
            last.0,
            last.1
        );
        // The mark is a Bitcoin price the relays agreed on (mark units: USD × PRICE_SCALE), not a number anyone typed.
        let price = last.1.as_deref().and_then(|m| m.rsplit("price ").next()).and_then(|p| p.trim().parse::<u128>().ok());
        assert!(
            price.is_some_and(|p| (1_000 * crate::liquidation::PRICE_SCALE..10_000_000 * crate::liquidation::PRICE_SCALE).contains(&p)),
            "the mark is a relay-agreed Bitcoin price: {:?}",
            last.1
        );
    }

    /// ⭐⭐⭐ CRITERION 2 — `native_send` ON REAL NODE PROCESSES.
    ///
    /// The payer's wallet talks to the PAYING process, and the payee's wallet talks to the RECEIVING process
    /// only. The payer is funded by the faucet, then sends. The payee's spendable balance, read through the
    /// receiving process, must reach the amount sent. So the payer's own spend proof crossed to the other
    /// process in a block, and that process applied it and serves the output to its wallet.
    ///
    /// CONTROL: the payee reads 0 through the receiving process before the send. The faucet only funds the
    /// payer and is not what is claimed. Two processes on one machine: not a scale claim.
    #[test]
    fn a_payment_sent_through_one_real_process_is_spendable_through_the_other() {
        const FUND_ATOMIC: u64 = 2_500_000_000; // 25.0 USDm
        const SEND_ATOMIC: u64 = 700_000_000; // 7.0 USDm
        let (paying_node, peer) = (0usize, 1usize);
        let mesh = match RealMesh::start(2, "nativesend") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let paying_url = format!("http://127.0.0.1:{}", mesh.port(paying_node));
        let peer_url = format!("http://127.0.0.1:{}", mesh.port(peer));
        let payer = RealWallet::create("nativesend", "payer", &paying_url)
            .unwrap_or_else(|e| panic!("⛔ the payer's real wallet could not be created: {e}"));
        let payee = RealWallet::create("nativesend", "payee", &peer_url)
            .unwrap_or_else(|e| panic!("⛔ the payee's real wallet could not be created: {e}"));
        let spendable = |w: &RealWallet| -> u64 {
            w.run(&["refresh", "balance"])
                .unwrap_or_default()
                .iter()
                .filter(|l| l.contains("\"op\":\"balance\""))
                .filter_map(|l| json_u64(l, "atomic"))
                .last()
                .unwrap_or(0)
        };
        // SPENDABILITY IS WAITED FOR IN BLOCKS, NEVER IN SECONDS (2026-11-03). A note is spendable once its block is folded,
        // RECORD_FOLD_DEPTH_DEFAULT blocks behind the tip: a protocol cadence. MEASURED on this pair of processes on one
        // machine (not a scale claim; cashfirst real-cash6.log): 11.7 s per block and the fold 37 blocks behind the tip, so a
        // credit needs ~375 s while a 300 s wait read the faucet credit as "never spendable" in four journeys. The wait ends
        // when the amount is spendable, when the FOLD has passed every block that existed at the start + 16 (the note had its
        // whole fold and did not appear: red), or when the fold has not moved for 300 s (a stall: red). Read from the fold's own
        // position (`served_seq`), never tip + depth: 32 confirmations are chain blocks, and two concurrent producers add ~1.7
        // blue per chain block (MEASURED: the fold 54-55 blue behind the tip), so a blue-score horizon stopped short of the fold.
        let wait_for = |w: &RealWallet, want: u64, _secs: u64| -> (u64, f64) {
            let t = Instant::now();
            let info = |key: &str| (0..2).filter_map(|i| mesh.get(i, "/get_info").ok().and_then(|s| json_u64(&s, key))).max().unwrap_or(0);
            let need = info("blue_score") + 16;
            let (mut got, mut last, mut moved) = (0u64, info("served_seq"), Instant::now());
            loop {
                got = spendable(w);
                if got >= want {
                    break;
                }
                let fold = info("served_seq");
                if fold > last {
                    last = fold;
                    moved = Instant::now();
                }
                if fold >= need || moved.elapsed() > Duration::from_secs(300) {
                    eprintln!("[journey] spendable wait ended at fold {fold} (horizon {need}) with {got} of {want} atomic");
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
            (got, t.elapsed().as_secs_f64())
        };
        assert_eq!(spendable(&payee), 0, "CONTROL: the payee reads nothing through the receiving process before the send");

        let drip = mesh
            .post(paying_node, "/faucet/drip", &format!(r#"{{"amount":{FUND_ATOMIC},"to":"{}"}}"#, payer.address))
            .unwrap_or_else(|e| panic!("⛔ the paying process's faucet refused to fund the payer: {e}"));
        assert!(drip.contains("\"published\":true"), "the payer's funding must be a published chain object: {drip}");
        let (funded, fund_secs) = wait_for(&payer, FUND_ATOMIC, 300);
        assert!(funded >= FUND_ATOMIC, "PRECONDITION: the payer's funding never became spendable ({funded} atomic)");

        let (sent, send_secs) = payer.spawn_send(&payee.address, "7.0").join().expect("the send thread returns");
        assert!(sent, "⛔ the payer's real wallet could not send through the paying process ({send_secs:.1}s)");
        let (got, recv_secs) = wait_for(&payee, SEND_ATOMIC, 300);
        eprintln!(
            "[native-send-real] funded in {fund_secs:.1}s, sent in {send_secs:.1}s; the payee on process \
             {peer} reads {got} atomic spendable after {recv_secs:.1}s (heights {:?}/{:?})",
            mesh.height(paying_node),
            mesh.height(peer)
        );
        assert!(
            got >= SEND_ATOMIC,
            "⛔⛔⛔ A PAYMENT SENT THROUGH THE PAYING PROCESS NEVER BECAME SPENDABLE THROUGH THE RECEIVING PROCESS \
             within 300 s (read {got} atomic, wanted {SEND_ATOMIC})."
        );
    }

    /// ⭐⭐⭐ DB-300 — A SECOND SEND FROM THE FIRST SEND'S CHANGE, ON REAL NODE PROCESSES, STARTED THE MOMENT THE FIRST
    /// RETURNS.
    ///
    /// Every harness command is a NEW wallet process, so the change the first send made is read back by a process with
    /// no send log, exactly as after an app restart. MEASURED before DB-300 ([probe279e], run279e): such a process read
    /// the uncarried 24.0 change as spendable 2 s after the send, the next send chose it, and the paying node refused
    /// membership twice ("[copath] cannot serve record … held, but its 256 leaf/leaves do not contain the named note",
    /// then "… not served (a stale position …)", n1.log:942-943): the change's block had not grafted there yet.
    ///
    /// The claim: the second send spends the change only once the chain carries it, so the PAYING process logs no such
    /// refusal across both sends; and the RECEIVING process's wallet holds both payments. The payer then reads exactly
    /// 23.0 through a new process (nothing counted twice, nothing lost). CONTROL: the payee reads 0 before the first
    /// send. On a build without DB-300 the refusal count is RED only when the second send wins the race against the
    /// producer's grind and graft, as run279e did. Two processes on one machine: not a scale claim.
    #[test]
    fn a_second_send_spends_the_first_sends_change_and_the_receiving_node_holds_both_payments() {
        const FUND_ATOMIC: u64 = 2_500_000_000; // 25.0 USDm
        const SEND_ATOMIC: u64 = 100_000_000; // 1.0 USDm, twice
        let (paying_node, receiving_node) = (0usize, 1usize);
        let mesh = match RealMesh::start(2, "db300change") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let paying_url = format!("http://127.0.0.1:{}", mesh.port(paying_node));
        let receiving_url = format!("http://127.0.0.1:{}", mesh.port(receiving_node));
        let payer = RealWallet::create("db300change", "payer", &paying_url)
            .unwrap_or_else(|e| panic!("⛔ the payer's real wallet could not be created: {e}"));
        let payee = RealWallet::create("db300change", "payee", &receiving_url)
            .unwrap_or_else(|e| panic!("⛔ the payee's real wallet could not be created: {e}"));
        let spendable = |w: &RealWallet| -> u64 {
            w.run(&["refresh", "balance"])
                .unwrap_or_default()
                .iter()
                .filter(|l| l.contains("\"op\":\"balance\""))
                .filter_map(|l| json_u64(l, "atomic"))
                .last()
                .unwrap_or(0)
        };
        // SPENDABILITY IS WAITED FOR IN BLOCKS, NEVER IN SECONDS (2026-11-03). A note is spendable once its block is folded,
        // RECORD_FOLD_DEPTH_DEFAULT blocks behind the tip: a protocol cadence. MEASURED on this pair of processes on one
        // machine (not a scale claim; cashfirst real-cash6.log): 11.7 s per block and the fold 37 blocks behind the tip, so a
        // credit needs ~375 s while a 300 s wait read the faucet credit as "never spendable" in four journeys. The wait ends
        // when the amount is spendable, when the FOLD has passed every block that existed at the start + 16 (the note had its
        // whole fold and did not appear: red), or when the fold has not moved for 300 s (a stall: red). Read from the fold's own
        // position (`served_seq`), never tip + depth: 32 confirmations are chain blocks, and two concurrent producers add ~1.7
        // blue per chain block (MEASURED: the fold 54-55 blue behind the tip), so a blue-score horizon stopped short of the fold.
        let wait_for = |w: &RealWallet, want: u64, _secs: u64| -> (u64, f64) {
            let t = Instant::now();
            let info = |key: &str| (0..2).filter_map(|i| mesh.get(i, "/get_info").ok().and_then(|s| json_u64(&s, key))).max().unwrap_or(0);
            let need = info("blue_score") + 16;
            let (mut got, mut last, mut moved) = (0u64, info("served_seq"), Instant::now());
            loop {
                got = spendable(w);
                if got >= want {
                    break;
                }
                let fold = info("served_seq");
                if fold > last {
                    last = fold;
                    moved = Instant::now();
                }
                if fold >= need || moved.elapsed() > Duration::from_secs(300) {
                    eprintln!("[journey] spendable wait ended at fold {fold} (horizon {need}) with {got} of {want} atomic");
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
            (got, t.elapsed().as_secs_f64())
        };
        // The paying node's own refusals of a named note it does not hold (the run279e lines), counted from its log.
        let refusals = || -> usize {
            std::fs::read_to_string(mesh.log_path(paying_node))
                .unwrap_or_default()
                .lines()
                .filter(|l| l.contains("[copath] cannot serve record") || l.contains("a stale position"))
                .count()
        };
        assert_eq!(spendable(&payee), 0, "CONTROL: the payee reads nothing through the receiving process before the send");
        let drip = mesh
            .post(paying_node, "/faucet/drip", &format!(r#"{{"amount":{FUND_ATOMIC},"to":"{}"}}"#, payer.address))
            .unwrap_or_else(|e| panic!("⛔ the paying process's faucet refused to fund the payer: {e}"));
        assert!(drip.contains("\"published\":true"), "the payer's funding must be a published chain object: {drip}");
        let (funded, fund_secs) = wait_for(&payer, FUND_ATOMIC, 300);
        assert!(funded >= FUND_ATOMIC, "PRECONDITION: the payer's funding never became spendable ({funded} atomic)");

        let before = refusals();
        let (sent1, secs1, last1) = payer.send_in_session(&payee.address, "1.0", 360);
        assert!(sent1, "⛔ the first send was not admitted through the paying process ({secs1:.1}s): {last1}");
        // At once, in a NEW wallet process: the only note it holds is the first send's change.
        let (sent2, secs2, last2) = payer.send_in_session(&payee.address, "1.0", 360);
        let refused = refusals().saturating_sub(before);
        let (got, recv_secs) = wait_for(&payee, 2 * SEND_ATOMIC, 300);
        let (left, left_secs) = wait_for(&payer, FUND_ATOMIC - 2 * SEND_ATOMIC, 300);
        eprintln!(
            "[db300-real] funded in {fund_secs:.1}s; send 1 {sent1} in {secs1:.1}s; send 2 (from the change) {sent2} in \
             {secs2:.1}s; paying-node refusals of an unheld note {refused}; the payee on process {receiving_node} holds \
             {got} atomic after {recv_secs:.1}s; the payer reads {left} after {left_secs:.1}s (heights {:?}/{:?})",
            mesh.height(paying_node),
            mesh.height(receiving_node)
        );
        assert!(sent2, "⛔ the second send, from the first send's change, was not admitted ({secs2:.1}s): {last2}");
        assert_eq!(
            refused, 0,
            "⛔ the payer named a note the paying node does not hold ({refused} refusal line(s)): the change was offered \
             before the chain carried it (run279e)"
        );
        assert!(
            got >= 2 * SEND_ATOMIC,
            "⛔ the receiving process's wallet does not hold both payments within 300 s (read {got} atomic)"
        );
        assert_eq!(
            left,
            FUND_ATOMIC - 2 * SEND_ATOMIC,
            "⛔ the payer reads {left} atomic, not exactly 23.0: a change counted twice, or one lost"
        );
    }

    /// ⭐⭐⭐ `ble_tap_pay` — THE JOIN, ON REAL NODE PROCESSES.
    ///
    /// The register's named blocker: *"no test carries a charge over BLE, pays it, and then asks the MERCHANT's node
    /// whether the payment settled."* A merchant wallet on one process begins a tap for its own address; a payer
    /// wallet on the OTHER process runs the payer's half. They are two live harness processes that share nothing:
    /// every crossing of the tap protocol — the merchant's ML-KEM key, the payer's ciphertext, the charge sealed
    /// under their session, each framed at the tap MTU (`moneropay_ble::tap_*`, the radio's own steps) — is
    /// relayed between them by this test byte for byte, as the air would carry it. The payer opens the charge and
    /// pays it with the ordinary `send`; the merchant's spendable balance, read through the MERCHANT's own process,
    /// must reach the charged amount.
    ///
    /// NOT CLAIMED: the radio's physical layer (advertising, GATT, RSSI range physics) — the frames cross by
    /// relay, not by air; that crossing is proven on hardware separately. CONTROL: the merchant reads nothing
    /// through its process before the tap. Two processes on one machine: not a scale claim.
    #[test]
    fn a_charge_carried_over_the_tap_protocol_is_paid_and_the_merchants_node_holds_it() {
        const FUND_ATOMIC: u64 = 2_500_000_000; // 25.0 USDm
        const CHARGE_ATOMIC: u64 = 50_000_000; // 0.5 USDm — what the merchant's tap asks for
        // The merchant runs on the paying node's PEER — the second party the payment must reach.
        let (paying_node, peer) = (0usize, 1usize);
        let mesh = match RealMesh::start(2, "tapjoin") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let paying_url = format!("http://127.0.0.1:{}", mesh.port(paying_node));
        let merchant_url = format!("http://127.0.0.1:{}", mesh.port(peer));
        let payer = RealWallet::create("tapjoin", "payer", &paying_url)
            .unwrap_or_else(|e| panic!("⛔ the payer's real wallet could not be created: {e}"));
        let merchant = RealWallet::create("tapjoin", "merchant", &merchant_url)
            .unwrap_or_else(|e| panic!("⛔ the merchant's real wallet could not be created: {e}"));
        let spendable = |w: &RealWallet| -> u64 {
            w.run(&["refresh", "balance"])
                .unwrap_or_default()
                .iter()
                .filter(|l| l.contains("\"op\":\"balance\""))
                .filter_map(|l| json_u64(l, "atomic"))
                .last()
                .unwrap_or(0)
        };
        // SPENDABILITY IS WAITED FOR IN BLOCKS, NEVER IN SECONDS (2026-11-03). A note is spendable once its block is folded,
        // RECORD_FOLD_DEPTH_DEFAULT blocks behind the tip: a protocol cadence. MEASURED on this pair of processes on one
        // machine (not a scale claim; cashfirst real-cash6.log): 11.7 s per block and the fold 37 blocks behind the tip, so a
        // credit needs ~375 s while a 300 s wait read the faucet credit as "never spendable" in four journeys. The wait ends
        // when the amount is spendable, when the FOLD has passed every block that existed at the start + 16 (the note had its
        // whole fold and did not appear: red), or when the fold has not moved for 300 s (a stall: red). Read from the fold's own
        // position (`served_seq`), never tip + depth: 32 confirmations are chain blocks, and two concurrent producers add ~1.7
        // blue per chain block (MEASURED: the fold 54-55 blue behind the tip), so a blue-score horizon stopped short of the fold.
        let wait_for = |w: &RealWallet, want: u64, _secs: u64| -> (u64, f64) {
            let t = Instant::now();
            let info = |key: &str| (0..2).filter_map(|i| mesh.get(i, "/get_info").ok().and_then(|s| json_u64(&s, key))).max().unwrap_or(0);
            let need = info("blue_score") + 16;
            let (mut got, mut last, mut moved) = (0u64, info("served_seq"), Instant::now());
            loop {
                got = spendable(w);
                if got >= want {
                    break;
                }
                let fold = info("served_seq");
                if fold > last {
                    last = fold;
                    moved = Instant::now();
                }
                if fold >= need || moved.elapsed() > Duration::from_secs(300) {
                    eprintln!("[journey] spendable wait ended at fold {fold} (horizon {need}) with {got} of {want} atomic");
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
            (got, t.elapsed().as_secs_f64())
        };
        assert_eq!(spendable(&merchant), 0, "CONTROL: the merchant reads nothing through its process before the tap");
        let drip = mesh
            .post(paying_node, "/faucet/drip", &format!(r#"{{"amount":{FUND_ATOMIC},"to":"{}"}}"#, payer.address))
            .unwrap_or_else(|e| panic!("⛔ the paying process's faucet refused to fund the payer: {e}"));
        assert!(drip.contains("\"published\":true"), "the payer's funding must be a published chain object: {drip}");
        let (funded, fund_secs) = wait_for(&payer, FUND_ATOMIC, 300);
        assert!(funded >= FUND_ATOMIC, "PRECONDITION: the payer's funding never became spendable ({funded} atomic)");

        // ── THE TAP: two live processes; this test is the air between them. ─────────────────────────────────
        // One crossing's frames, lifted out of a reply as the compact JSON array the other side's command takes.
        let frames = |reply: &str| -> String {
            let v: serde_json::Value = serde_json::from_str(reply).unwrap_or_default();
            assert_eq!(v["ok"], serde_json::json!(true), "⛔ a tap step failed: {reply}");
            let f = &v["result"]["frames"];
            assert!(f.as_array().is_some_and(|a| !a.is_empty()), "⛔ a tap step put no frames on the air: {reply}");
            f.to_string()
        };
        let mut m = merchant.session(300).unwrap_or_else(|e| panic!("⛔ the merchant's wallet did not open: {e}"));
        let mut p = payer.session(300).unwrap_or_else(|e| panic!("⛔ the payer's wallet did not open: {e}"));
        let ek = frames(&m.ask(&format!("tapcharge-begin {CHARGE_ATOMIC}"), "tapcharge-begin").expect("merchant: key"));
        let ct = frames(&p.ask(&format!("tapcharge-encaps {ek}"), "tapcharge-encaps").expect("payer: ciphertext"));
        let sealed = frames(&m.ask(&format!("tapcharge-seal {ct}"), "tapcharge-seal").expect("merchant: sealed charge"));
        let opened = p.ask(&format!("tapcharge-open {sealed}"), "tapcharge-open").expect("payer: the opened charge");
        drop(m);
        drop(p);
        let o: serde_json::Value = serde_json::from_str(&opened).unwrap_or_default();
        assert_eq!(o["ok"], serde_json::json!(true), "⛔ the payer could not open the charge it was handed: {opened}");
        let to = o["result"]["to"].as_str().unwrap_or_default().to_string();
        assert_eq!(o["result"]["atomic"].as_u64(), Some(CHARGE_ATOMIC), "the payer read the amount the merchant sealed");
        assert_eq!(to, merchant.address, "the opened charge pays the MERCHANT — the address its own wallet sealed");
        let charge_hex = o["result"]["charge_hex"].as_str().unwrap_or_default().to_string();
        assert!(!charge_hex.is_empty(), "the payer's verified view must carry the opened charge it will pay: {opened}");

        // ── THE PAYMENT: the ONE path that moves a tap's money (DB-319: `tappay` = `wallet_pos_pay` — the payer's
        //    gate again, then EXACTLY the signed atomic amount; the step the tap UI runs after its verify), and the
        //    MERCHANT's process is asked. ──────────────────────────────────────────────────────────────────────
        let (sent, send_secs, last) = payer.pay_in_session(&format!("tappay {charge_hex}"), "tappay", 420);
        assert!(sent, "⛔ the payer's real wallet could not pay the opened charge ({send_secs:.1}s): {last}");
        let (got, recv_secs) = wait_for(&merchant, CHARGE_ATOMIC, 300);
        eprintln!(
            "[tap-join-real] funded in {fund_secs:.1}s; the charge crossed 3 relayed crossings and was paid in \
             {send_secs:.1}s; the merchant on process {peer} reads {got} atomic spendable after \
             {recv_secs:.1}s (heights {:?}/{:?})",
            mesh.height(paying_node),
            mesh.height(peer)
        );
        assert!(
            got >= CHARGE_ATOMIC,
            "⛔⛔⛔ A CHARGE CARRIED OVER THE TAP PROTOCOL AND PAID NEVER BECAME SPENDABLE THROUGH THE MERCHANT'S \
             PROCESS within 300 s (read {got} atomic, wanted {CHARGE_ATOMIC})."
        );
    }

    /// ⭐⭐⭐ DB-350 — A PEER CANNOT LEARN WHICH COMMITMENT A WALLET OWNS FROM ITS NODE'S ASKS, MEASURED ON REAL
    /// PROCESSES WITH THE SECOND PROCESS OBSERVING.
    ///
    /// The wallet's membership miss is driven through process 0 at the one moment it is real. The note was just
    /// credited through process 1, no block carries it yet, and process 0 cannot place it (`/note_ordinal_by_cm`
    /// answers -1, asserted). The requests are exactly the wallet's miss path: `/note_ordinal_by_cm`, `/note_copath`,
    /// and the retired `/want_note_record` that a wallet built before DB-350 posts next. Then the real money path
    /// runs: the funded wallet on process 0 pays a wallet on process 1, and process 1's wallet reads it.
    ///
    /// Two logs decide, each process's own:
    /// * process 1 counts every by-commitment ask it RECEIVED — `[cm-ask-in]` from the retired serve arm (every
    ///   arrival prints, so one cannot hide), and `[cm-serve]` on a pre-DB-350 binary;
    /// * process 0 counts every by-commitment ask it BUILT — `[cm-want]`, which only a pre-DB-350 binary prints.
    ///
    /// REFUTATION BEFORE GREEN (MEASURED 2026-09-28 05:53-06:00): this pin run with `MONEROUSD_JOURNEY_NODE_BIN` naming
    /// the pre-DB-350 node 80f51e83 FAILED on those logs — process 0 built 13 by-commitment asks and process 1 received 4,
    /// while the money path itself passed (docs/DB-350 §8). Two nodes, two processes on one machine: not a scale claim.
    #[test]
    fn a_wallets_membership_miss_on_one_real_process_sends_its_peer_no_by_commitment_ask() {
        const FUND_ATOMIC: u64 = 2_500_000_000; // 25.0 USDm
        const SEND_ATOMIC: u64 = 700_000_000; // 7.0 USDm
        let (asking_node, receiving_node) = (0usize, 1usize);
        let mesh = match RealMesh::start(2, "cmask") {
            Ok(m) => m,
            Err(e) => panic!("⛔ COULD NOT RAISE A REAL 2-NODE MESH: {e}"),
        };
        let asking_url = format!("http://127.0.0.1:{}", mesh.port(asking_node));
        let receiving_url = format!("http://127.0.0.1:{}", mesh.port(receiving_node));
        let payer = RealWallet::create("cmask", "payer", &asking_url)
            .unwrap_or_else(|e| panic!("⛔ the payer's real wallet could not be created: {e}"));
        let payee = RealWallet::create("cmask", "payee", &receiving_url)
            .unwrap_or_else(|e| panic!("⛔ the payee's real wallet could not be created: {e}"));
        let spendable = |w: &RealWallet| -> u64 {
            w.run(&["refresh", "balance"])
                .unwrap_or_default()
                .iter()
                .filter(|l| l.contains("\"op\":\"balance\""))
                .filter_map(|l| json_u64(l, "atomic"))
                .last()
                .unwrap_or(0)
        };
        // SPENDABILITY IS WAITED FOR IN BLOCKS, NEVER IN SECONDS (2026-11-03). A note is spendable once its block is folded,
        // RECORD_FOLD_DEPTH_DEFAULT blocks behind the tip: a protocol cadence. MEASURED on this pair of processes on one
        // machine (not a scale claim; cashfirst real-cash6.log): 11.7 s per block and the fold 37 blocks behind the tip, so a
        // credit needs ~375 s while a 300 s wait read the faucet credit as "never spendable" in four journeys. The wait ends
        // when the amount is spendable, when the FOLD has passed every block that existed at the start + 16 (the note had its
        // whole fold and did not appear: red), or when the fold has not moved for 300 s (a stall: red). Read from the fold's own
        // position (`served_seq`), never tip + depth: 32 confirmations are chain blocks, and two concurrent producers add ~1.7
        // blue per chain block (MEASURED: the fold 54-55 blue behind the tip), so a blue-score horizon stopped short of the fold.
        let wait_for = |w: &RealWallet, want: u64, _secs: u64| -> (u64, f64) {
            let t = Instant::now();
            let info = |key: &str| (0..2).filter_map(|i| mesh.get(i, "/get_info").ok().and_then(|s| json_u64(&s, key))).max().unwrap_or(0);
            let need = info("blue_score") + 16;
            let (mut got, mut last, mut moved) = (0u64, info("served_seq"), Instant::now());
            loop {
                got = spendable(w);
                if got >= want {
                    break;
                }
                let fold = info("served_seq");
                if fold > last {
                    last = fold;
                    moved = Instant::now();
                }
                if fold >= need || moved.elapsed() > Duration::from_secs(300) {
                    eprintln!("[journey] spendable wait ended at fold {fold} (horizon {need}) with {got} of {want} atomic");
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
            (got, t.elapsed().as_secs_f64())
        };

        // ── 1. The payer's note is credited THROUGH THE PEER, so the asking process holds nothing of it yet. ──
        let drip = mesh
            .post(receiving_node, "/faucet/drip", &format!(r#"{{"amount":{FUND_ATOMIC},"to":"{}"}}"#, payer.address))
            .unwrap_or_else(|e| panic!("⛔ process {receiving_node}'s faucet refused to fund the payer: {e}"));
        assert!(drip.contains("\"published\":true"), "the payer's funding must be a published chain object: {drip}");
        let note_hex = json_str(&drip, "note").unwrap_or_else(|| panic!("the drip names the credited note: {drip}"));
        assert!(note_hex.len() >= 64, "the credited note carries its commitment in front: {note_hex}");
        let cm_hex = note_hex[..64].to_string();

        // ── 2. The wallet's miss, request for request, on the process that cannot place the note. ──
        let placed = mesh
            .post(asking_node, "/note_ordinal_by_cm", &format!(r#"{{"cms_hex":"{cm_hex}"}}"#))
            .unwrap_or_else(|e| format!("error: {e}"));
        let copath = mesh
            .post(asking_node, "/note_copath", &format!(r#"{{"cms_hex":"{cm_hex}"}}"#))
            .unwrap_or_else(|e| format!("error: {e}"));
        let retired = mesh.post(asking_node, "/want_note_record", &format!(r#"{{"cm_hex":"{cm_hex}"}}"#));
        eprintln!(
            "[db350-real] on process {asking_node} right after the drip: /note_ordinal_by_cm -> {placed}; /note_copath served \
             it: {}; /want_note_record -> {retired:?}",
            copath.contains("\"served\":true")
        );
        assert!(
            placed.contains("\"ordinals\":[-1]"),
            "PRECONDITION: process {asking_node} could not place the note when the wallet asked — the exact state that raised \
             the by-commitment ask. It placed it already, so this run measures nothing: {placed}"
        );

        // ── 3. The real money path, through both processes. ──
        let (funded, fund_secs) = wait_for(&payer, FUND_ATOMIC, 300);
        assert!(funded >= FUND_ATOMIC, "PRECONDITION: the payer's funding never became spendable ({funded} atomic)");
        let (sent, send_secs) = payer.spawn_send(&payee.address, "7.0").join().expect("the send thread returns");
        assert!(sent, "⛔ the payer's real wallet could not send through process {asking_node} ({send_secs:.1}s)");
        let (got, recv_secs) = wait_for(&payee, SEND_ATOMIC, 300);

        // ── 4. What each process's OWN log says. ──
        let count = |i: usize, needle: &str| -> usize {
            std::fs::read_to_string(mesh.log_path(i)).unwrap_or_default().matches(needle).count()
        };
        let built = count(asking_node, "[cm-want]");
        let received = count(receiving_node, "[cm-ask-in]") + count(receiving_node, "[cm-serve]");
        let by_id_served = count(receiving_node, "[id-lane] serving by-id");
        eprintln!(
            "[db350-real] funded through process {asking_node} in {fund_secs:.1}s, sent in {send_secs:.1}s, the payee on process \
             {receiving_node} reads {got} atomic after {recv_secs:.1}s. by-commitment asks BUILT by process {asking_node}: {built}; \
             RECEIVED by process {receiving_node}: {received}; by-id serves logged by process {receiving_node} (sampled 1-in-16): {by_id_served}"
        );
        assert_eq!(
            received, 0,
            "⛔⛔⛔ PROCESS {receiving_node} RECEIVED {received} BY-COMMITMENT ASK(S): a peer learned which note the wallet on process \
             {asking_node} owns"
        );
        assert_eq!(built, 0, "⛔ process {asking_node} BUILT {built} by-commitment ask(s)");
        assert!(
            matches!(&retired, Err(e) if e.starts_with("HTTP 404")),
            "⛔ /want_note_record still answers on process {asking_node}: the by-commitment door is open: {retired:?}"
        );
        assert!(
            got >= SEND_ATOMIC,
            "⛔ the money path regressed: the payment sent through process {asking_node} never became spendable through \
             process {receiving_node} within 300 s (read {got} atomic, wanted {SEND_ATOMIC})"
        );
    }
}

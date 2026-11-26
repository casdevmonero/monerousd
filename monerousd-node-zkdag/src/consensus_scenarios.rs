// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **MONEROUSD CONSENSUS SCENARIOS — cases as DATA, one engine, two backends.**
//!
//! Ethereum's clients do not find consensus bugs by running the whole system and reading the logs. They
//! run `consensus-spec-tests`: cases written as DATA (a pre-state, a script, an expected post-state) that
//! any client executes, plus `hive`, which starts several clients under a scripted network. The value is
//! not the containers — it is that a case is a FILE, so a class found once is executable forever, by
//! anyone, in seconds.
//!
//! This is that shape for MonerousD. A case names the parties, a script over the four events that have
//! ever broken our fold — produce, deliver out of order, restart through the checkpoint, jump by a
//! certified bundle — and the property that must hold at the end. Cases live in
//! `consensus_scenarios.txt`, beside this file, and every one of them is a class a GATE RUN found the
//! expensive way (runs 30-45, roughly fifteen minutes and a freeze apiece).
//!
//! ⛔ SCOPE, stated so it is never overclaimed: the runner here is IN-PROCESS. It is an island. It proves
//! nothing about the onion transport, about per-node cost, or about scale, and no result from it may be
//! cited as evidence that the network works. It exists so that the live pair gate and the multi-device
//! run at the scale floor — which remain the only network proofs, and are a follow-on to every run here —
//! stop being used as debuggers for a class this can answer in a second.
//!
//! The second backend (the same case text driving real processes over the real transport) is the next
//! step and is why the engine, the case format and the property live in a normal module rather than
//! inside a test.

use crate::block::Block;
use crate::decider::{ConsensusVerifier, DeciderBundle};
use crate::hash::Hash32;
use crate::node::Node;
use crate::params::{network_genesis_prefix, ChainParams};
use crate::relay::RelayOutcome;
use crate::sync::{AdoptOutcome, FrontierSnapshot};

/// The case library. Data, not code: adding a class is adding lines to a text file.
pub(crate) const CASES: &str = include_str!("consensus_scenarios.txt");

/// One scheduled event. The alphabet is exactly the four things that have broken the record fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Act {
    /// Party `i` produces `n` blocks back to back; every other party owes each of them.
    Produce(usize, usize),
    /// Hand the `k`th owed block to its recipient NOW — out of order by construction.
    Deliver(usize),
    /// Hand every owed block over until nothing is owed.
    Drain,
    /// Party `i` goes through its checkpoint: export, fresh process, restore.
    Restart(usize),
    /// Party `i` adopts party `j`'s certified bundle, the way a joiner does.
    Jump(usize, usize),
    /// Hand over the next `k` owed blocks at once — a cascade, the shape the onion transport delivers.
    Burst(usize),
    /// Lose one owed delivery to party `i` for good: gossip never brings it; only a parent ask can.
    Drop(usize),
    /// Party `i` produces a block carrying a REAL note (a receive): its record is not regenerable cover.
    Receive(usize),
    /// Party `i` forgets the bytes of every idle record it holds — they must regenerate from coordinates.
    Forget(usize),
    /// Party `i` is offered a TAMPERED bundle from `j` (spine that does not reproduce the certified root):
    /// it must refuse it and keep its own state byte for byte.
    Tamper(usize, usize),
    /// Party `i` is paged forged rows (random record ids at real ordinals): none may displace a claim.
    ForgeRows(usize),
    /// Party `i` gossips an INVALID block (wrong work): every party must reject it, DAGs unchanged.
    Invalid(usize),
    /// Party `i` is re-sent the last bundle it adopted from `j` (a replay): no state may move.
    Replay(usize, usize),
    /// Party `i` SPENDS one of the real notes it holds unspent — a deletion carried by its next block —
    /// so every party's unspent set must move identically and answer "spent" for that note.
    Spend(usize),
}

/// A case: a name, how many parties, the script, and the property asserted at the end.
#[derive(Clone, Debug)]
pub(crate) struct Scenario {
    pub name: String,
    pub parties: usize,
    /// O1-FOOTPRINT-REVIEWED: bounded by the case file — a fixed list of actions parsed once at build
    /// time from `consensus_scenarios.txt`; nothing appends at run time.
    pub script: Vec<Act>,
}

/// Parse the case library. A malformed line is an ERROR, never a skipped case: a scenario that silently
/// does not run is worse than no scenario, because it reads as coverage.
pub(crate) fn parse(text: &str) -> Result<Vec<Scenario>, String> {
    let mut out: Vec<Scenario> = Vec::new();
    let mut cur: Option<Scenario> = None;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let t: Vec<&str> = line.split_whitespace().collect();
        let num = |s: &str| -> Result<usize, String> {
            s.parse::<usize>().map_err(|_| format!("line {}: '{s}' is not a number", n + 1))
        };
        match t[0] {
            "name" => {
                if let Some(c) = cur.take() {
                    out.push(c);
                }
                let name = t.get(1).ok_or_else(|| format!("line {}: name needs a value", n + 1))?;
                cur = Some(Scenario { name: (*name).to_string(), parties: 2, script: Vec::new() });
            }
            other => {
                let c = cur
                    .as_mut()
                    .ok_or_else(|| format!("line {}: '{other}' before any 'name'", n + 1))?;
                match other {
                    "parties" => c.parties = num(t.get(1).copied().unwrap_or(""))?,
                    "produce" => {
                        let who = num(t.get(1).copied().unwrap_or(""))?;
                        let count = match t.get(2) {
                            Some(v) => num(v)?,
                            None => 1,
                        };
                        c.script.push(Act::Produce(who, count));
                    }
                    "deliver" => c.script.push(Act::Deliver(num(t.get(1).copied().unwrap_or("0"))?)),
                    "drain" => c.script.push(Act::Drain),
                    "restart" => c.script.push(Act::Restart(num(t.get(1).copied().unwrap_or(""))?)),
                    "jump" => c.script.push(Act::Jump(
                        num(t.get(1).copied().unwrap_or(""))?,
                        num(t.get(2).copied().unwrap_or(""))?,
                    )),
                    "burst" => c.script.push(Act::Burst(num(t.get(1).copied().unwrap_or("1"))?)),
                    "drop" => c.script.push(Act::Drop(num(t.get(1).copied().unwrap_or(""))?)),
                    "receive" => c.script.push(Act::Receive(num(t.get(1).copied().unwrap_or(""))?)),
                    "forget" => c.script.push(Act::Forget(num(t.get(1).copied().unwrap_or(""))?)),
                    "tamper" => c.script.push(Act::Tamper(
                        num(t.get(1).copied().unwrap_or(""))?,
                        num(t.get(2).copied().unwrap_or(""))?,
                    )),
                    "forge-rows" => c.script.push(Act::ForgeRows(num(t.get(1).copied().unwrap_or(""))?)),
                    "invalid" => c.script.push(Act::Invalid(num(t.get(1).copied().unwrap_or(""))?)),
                    "replay" => c.script.push(Act::Replay(
                        num(t.get(1).copied().unwrap_or(""))?,
                        num(t.get(2).copied().unwrap_or(""))?,
                    )),
                    "spend" => c.script.push(Act::Spend(num(t.get(1).copied().unwrap_or(""))?)),
                    _ => return Err(format!("line {}: unknown action '{other}'", n + 1)),
                }
            }
        }
    }
    if let Some(c) = cur.take() {
        out.push(c);
    }
    if out.is_empty() {
        return Err("the case library parsed to zero scenarios".into());
    }
    Ok(out)
}

struct AcceptAll;
impl ConsensusVerifier for AcceptAll {
    fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
        true
    }
}

/// A scenario party is built through the PRODUCTION genesis path — the same `Block` literal and the same
/// `genesis_header_for_network` call `main.rs` uses to start a real node — so a case cannot pass against a
/// genesis no real node would ever hold. It also keeps this module free of anything `#[cfg(test)]`, which
/// is what lets the same engine drive real processes later.
///
/// ⛔ THE DATADIR IS A PARAMETER, NOT A SECRET THIS FUNCTION KEEPS. A persisting party is a directory on a
/// real disk, and the version of this function that allocated its own — and told nobody — is what leaked
/// 11,161 of them (see [`ScenarioDataDir`]). Taking the [`ScenarioDataDir`] by reference means the caller
/// already holds the owner, so there is no path by which a party outlives, or outlasts, its disk.
///
/// It is also the restart door: `Sim::restart` mints a fresh `Node` into the SAME directory the party has
/// used since `Sim::new`, which is both what a real operator restart does (one datadir, many processes)
/// and what keeps the harness's disk bounded by the PARTY count instead of the CANDIDATE count.
pub(crate) fn scenario_node_in(dir: &ScenarioDataDir) -> Node {
    scenario_node_in_at_depth(dir, crate::params::RECORD_FOLD_DEPTH_DEFAULT)
}

/// The same party, built to fold its records `depth` selected-chain steps below the tip.
///
/// ⭐ WHY THIS IS A PARAMETER AND NOT A CONSTANT. A record is invisible to everything that reads what a
/// node HOLDS until it FOLDS — `live_leaves` counts real note commitments in FOLDED records only. At the
/// production depth (32) a fixture whose subject is custody must produce 32 blocks past its receive
/// before the node holds anything a detector can watch leave, and a fixture that runs short asserts
/// against an EMPTY set: the classic green that tests nothing (measured 2026-09-24 — `i8_custody` held
/// `1 ordinal row, spend-frontier count 0` after 12 receive+produce rounds and said so rather than
/// passing).
///
/// ⛔ NOT A RELAXATION OF A CONSENSUS RULE. The fold DELAY is its own subject with its own coverage; a
/// depth of 0 is a legal `ChainParams` value that the rpc-test helper already uses for the same stated
/// reason — *these tests' subject is not the fold delay: fold at the tip*. Every party in a given `Sim`
/// shares one depth (including across a `Restart`), so no party can disagree with its peers about when a
/// record becomes canonical, which is the only thing a mixed depth could break.
pub(crate) fn scenario_node_in_at_depth(dir: &ScenarioDataDir, depth: u64) -> Node {
    scenario_node_built_at_depth(dir, depth).0
}

/// ⭐ G1h (lane b 2026-10-23) — THE RESTART DOOR OF BOTH SCENARIO BACKENDS: the party rebuilt in the SAME datadir after
/// its previous process wrote its shutdown checkpoint (`Node::persist_blocking`), resumed through the ONE resume a
/// daemon's boot runs (`enable_persist` → `restore_from_disk` → `resume_from_checkpoint`: the snapshot AND its fold
/// record — the band door, the respend carry, the window span). `None` when the directory held no checkpoint that
/// resumed. MEASURED before (scratchpad/verify/g1h-crawler-restart-red-20261022.log, cases 05 and 12): the harness
/// restarted a party through `clear_checkpoint` + `restore_snapshot` — a SNAPSHOT-ONLY path `resume_from_checkpoint`'s
/// own doc names as "a path no node takes" — so the restarted party's band door stayed at genesis, its restored
/// accumulator root was not placeable in that door's journal, `sparse_pivot()` was `None`, the runtime's warm never
/// started (0 `[nf-pivot]` lines in 13,289) and the fold waited on its first spend-carrying block for 2,671 passes
/// ("the fold-point spent set is blind"): party 1 fold 30 vs party 0 98. The pins measured the harness, not the node.
pub(crate) fn scenario_node_resumed_in_at_depth(dir: &ScenarioDataDir, depth: u64) -> Option<Node> {
    let (node, resumed) = scenario_node_built_at_depth(dir, depth);
    resumed.then_some(node)
}

fn scenario_node_built_at_depth(dir: &ScenarioDataDir, depth: u64) -> (Node, bool) {
    let mut p = ChainParams::default();
    p.genesis_parity_commit = network_genesis_prefix("testnet");
    p.net_prefix_len = p.genesis_parity_commit.len();
    p.record_fold_depth = depth;
    let g = Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
        header: crate::block::genesis_header_for_network(&p.genesis_parity_commit),
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
    let mut n = Node::with_params(g, p).expect("a testnet node builds");
    n.set_decider_verifier(Box::new(AcceptAll));
    // A real node PERSISTS: `enable_persist` is what files the genesis record at ordinal 0 (the one row no
    // page re-supplies) and what a restart resumes from. An in-memory party without it is a node no
    // operator runs — and the case suite showed exactly that gap: a resumed in-memory party had no row 0.
    // ⭐ G1h — the production boot (`Node::boot`) opens the block window BEFORE the checkpoint resumes, so the resumed span
    // is read from the window's bodies exactly as the daemon reads it (2026-10-27: a party with no window carried its
    // span in the unfolded set alone, a shape no production node has).
    n.enable_block_window(dir.window_path());
    let resumed = n.enable_persist(dir.snapshot_path()).unwrap_or(false);
    (n, resumed)
}

/// A scenario party's DATADIR, with a lifetime: the directory exists exactly as long as this guard.
///
/// ⛔⛔ WHY THIS TYPE EXISTS — A MEASURED DISK-EXHAUSTION VECTOR IN THE INSTRUMENT ITSELF.
/// `scenario_node_in` mints a PERSISTING node, and persistence means a real directory holding a real
/// `state.snap` (1.5–2.4 MB measured). Until 2026-09-08 nothing ever removed one, so the harness leaked a
/// directory per party per `Sim`:
///
/// * MEASURED 2026-09-08, after ONE Lane F campaign plus ONE shrink: **11,161 `musd-scenario-*` dirs from
///   373 test PIDs, every one of them dead**. 6,658 held a `state.snap`; 6 held a `state.snap.tmp` a save
///   was killed in the middle of (which is why `clear_checkpoint` removes that name too).
/// * ⛔ SIZE, STATED AS MEASURED RATHER THAN AS EXTRAPOLATED — the first write-up of this defect sampled
///   three dirs at 1.5–2.4 MB and reported "≈ 20 GB". **Removing all 11,161 actually reclaimed ~3 GB**
///   (temp dir 18 GB → 15 GB), i.e. ~450 KB per snapshot: the sample was the tail, not the average, and
///   4,503 dirs held no snapshot at all. The correction does not retire the defect — the volume was 98%
///   full with ~20 GiB free, and the number that matters is the CEILING, below.
/// * The shrinker turns the leak into a MULTIPLIER: `SHRINK_MAX_CANDIDATES` (2,304) × `MAX_PARTIES` (4)
///   = **9,216 datadirs for a SINGLE find**, plus one more per `Restart` op in every candidate — ≈ 4 GB
///   at the measured average and **≈ 22 GB at the largest snapshot actually observed (2.4 MB)**, none of
///   it ever released. Unbounded on an axis, which is the class, whatever the constant is that week.
///
/// This project has already taken an ENOSPC outage. A test scaffold that can fill the disk is a defect in
/// the scaffold, so the directory now has an OWNER and dies with it — and the two things that bound the
/// disk are stated where they are enforced rather than left to a convention someone has to remember:
///
/// 1. **One dir per PARTY, for the party's whole life.** `Sim` holds these guards index-aligned with
///    `Sim::parties`; a `Restart` reuses the party's directory instead of minting another. A run's
///    directory count is therefore its PARTY count — 2 to 4 — no matter how many candidates a shrink
///    executes.
/// 2. **The dir dies with the run.** `Drop` removes the subtree, so it survives a panicking case (drop
///    runs while unwinding) and a failing assertion, not just the happy path.
///
/// ⛔ FIELD ORDER IS LOAD-BEARING wherever these are held beside their nodes: Rust drops struct fields in
/// declaration order, so the `Vec<Node>` must be declared BEFORE the `Vec<ScenarioDataDir>` — a node that
/// outlived its directory would auto-save into a path that no longer exists.
#[must_use = "the datadir is deleted the moment this guard drops — hold it as long as the node persists"]
pub(crate) struct ScenarioDataDir {
    dir: std::path::PathBuf,
}

impl ScenarioDataDir {
    /// Allocate a fresh, empty datadir under this process's own parent directory.
    pub(crate) fn new() -> ScenarioDataDir {
        sweep_dead_scenario_dirs_once();
        let stamp = SCENARIO_NODE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = scenario_root().join(format!("p{stamp}"));
        let _ = std::fs::create_dir_all(&dir);
        ScenarioDataDir { dir }
    }

    /// The directory itself — what the lifecycle pin asserts is created once and given back.
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.dir
    }

    /// Where this party's checkpoint file lives — what `enable_persist` is pointed at.
    /// The party's block window, named as the daemon names its own (`persist::BootFiles::window`, port 0 here).
    pub(crate) fn window_path(&self) -> std::path::PathBuf {
        self.dir.join(format!("{}0", crate::block_window::WINDOW_DIR_PREFIX))
    }

    pub(crate) fn snapshot_path(&self) -> std::path::PathBuf {
        self.dir.join("state.snap")
    }

    /// Erase the checkpoint so the NEXT node built here boots at genesis, exactly as a node built in a
    /// brand-new directory does.
    ///
    /// ⛔ THIS IS WHAT KEEPS A `Restart` A REAL RESTORE. `Node::enable_persist` RESTORES FROM DISK the
    /// moment it is called, so a fresh node pointed at a directory still holding the previous
    /// incarnation's auto-saved `state.snap` would boot ALREADY CARRYING the state — and the
    /// `restore_snapshot` that follows would then be asserted against a node that no longer needed it.
    /// The oracle's byte-identical unspent-set-and-root pin would go green without the checkpoint ever
    /// being exercised: a passing test proving nothing. The DIRECTORY is reused; the CHECKPOINT never is.
    pub(crate) fn clear_checkpoint(&self) {
        let path = self.snapshot_path();
        // `persist::save` writes `state.snap.tmp` and renames it into place, so a crash mid-save can
        // leave the temp file behind. Both names go.
        let _ = std::fs::remove_file(path.with_extension("snap.tmp"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(self.window_path()); // a genesis boot holds no window either
    }
}

impl Drop for ScenarioDataDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Distinct datadirs for distinct parties within one process.
static SCENARIO_NODE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// ONE parent per PROCESS: every party datadir a test binary makes is a child of it, so a run is a single
/// subtree to measure, to watch, and — if the process is killed before any guard can run — to remove.
fn scenario_root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("musd-scenario-{}", std::process::id()))
}

static SCENARIO_SWEEP: std::sync::Once = std::sync::Once::new();

/// Remove the datadirs of test processes that are NO LONGER RUNNING — once per process, off the hot path.
///
/// The RAII guard above stops the leak from here on, but it cannot help a process that never got to run a
/// destructor: a killed gate run, a ^C during a campaign, an OOM, a `process::exit`. Those leave their
/// subtree behind, and that is how 11,161 orphaned dirs from 373 dead PIDs accumulated. So the harness
/// buries its own dead: on the first datadir any run allocates, a detached thread walks the temp directory
/// and deletes every `musd-scenario-*` subtree whose owning PID is gone.
///
/// ⛔ THE SAFETY CONDITION IS "THE OWNER IS DEAD", NEVER AN AGE HEURISTIC. `kill(pid, 0)` answers exactly
/// that question, and anything still alive is left ALONE — so a concurrent test binary (cargo runs
/// several, and a campaign runs for hours) can never have its `state.snap` deleted out from under it. A
/// recycled PID can only make this MORE conservative: a dead run's dirs linger for one more sweep. It can
/// never make it delete a live one. Detached rather than joined because a first sweep can have thousands
/// of subtrees to unlink and no test should wait for it; every step is idempotent, so a process that exits
/// mid-sweep simply leaves the remainder for the next run.
fn sweep_dead_scenario_dirs_once() {
    SCENARIO_SWEEP.call_once(|| {
        std::thread::spawn(|| {
            let me = std::process::id();
            let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else { return };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let Some(tail) = name.strip_prefix("musd-scenario-") else { continue };
                // Both layouts are swept: the per-process parent `musd-scenario-<pid>` this file makes
                // now, and the flat `musd-scenario-<pid>-<stamp>` dirs every run before 2026-09-08 left
                // behind — the 11,161 the measurement found.
                let Some(pid) = tail.split('-').next().and_then(|p| p.parse::<u32>().ok()) else { continue };
                if pid == 0 || pid == me || pid_is_alive(pid) {
                    continue;
                }
                let _ = std::fs::remove_dir_all(entry.path());
            }
        });
    });
}

/// Is `pid` a process this machine is still running? `EPERM` counts as ALIVE: the PID resolves, it just is
/// not ours to signal — and "someone else's live process" is precisely the case that must not be swept.
fn pid_is_alive(pid: u32) -> bool {
    crate::oscall::pid_is_alive(pid)
}

/// The in-process engine. Real `Node` values, real checkpoints, real bundles; only the SCHEDULE is ours.
pub(crate) struct Sim {
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — the party count the case fixes before it runs.
    /// A test scaffold, never a node store.
    pub parties: Vec<Node>,
    /// Owed deliveries, with no ordering guarantee — which is the interesting part.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — parties times the case's fixed action count;
    /// `drain` empties it before every assertion.
    pub(crate) owed: Vec<(usize, Block)>,
    /// Every block produced, for the ordinal comparison at the end.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — at most one per Produce, and the case's
    /// action count is fixed.
    blocks: Vec<Block>,
    now: u64,
    rng: u64,
    /// ⭐ §CE — the case's own seed, kept so a RESTART can re-pin the party's node secret with the same
    /// derivation `new` used. `rng` is `seed | 1` and mutates as the schedule runs, so it is NOT the value
    /// to derive from — reading it here would have made the restart seed depend on how far the schedule
    /// had got, which is the drift this field exists to prevent.
    /// O1-FOOTPRINT-REVIEWED: one u64, fixed for the life of the case.
    seed: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one entry per executed action.
    pub trace: Vec<Act>,
    /// The bundle each party last adopted, by party — what a replay re-sends.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one slot per party.
    last_adopted: Vec<Option<crate::sync::SyncBundle>>,
    /// Record ids of every REAL-note block (receives): bytes every party must hold, never regenerable.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one per Receive action.
    pub(crate) real_records: Vec<u64>,
    /// An honest block a party REFUSED (`Invalid`): a consensus split among honest nodes, kept as evidence.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — at most one per delivery attempt of the case.
    honest_refusals: Vec<(usize, crate::block::BlockId, String)>,
    /// Produce cycles the runtime rule deferred (a party with orphans buffered never extends its chain).
    pub deferred_produces: usize,
    /// ⭐⭐⭐ DID A SEND ACTUALLY HAPPEN? `spend` has FOUR exits that change nothing and return `Ok(())`:
    /// no eligible note, the carrier refuses, production yields no block, and the relay-buffered defer.
    /// Every one of them is legitimate — a spend a party cannot carry right now is not a defect — but
    /// they are indistinguishable from a landed spend to everything downstream, because nothing counted
    /// them. A schedule could roll `Op::Spend` a dozen times, land ZERO, and the run would report clean.
    ///
    /// ⛔ THAT IS THE HARNESS-≠-REALITY SHAPE, ON THE SEND PATH. "No double-spend was found" is worth
    /// nothing if no spend ever occurred; the run proves the absence of an event it never staged. These
    /// counters make the difference assertable, so a clean send verdict has to be EARNED by a send.
    pub spends_landed: usize,
    /// Spends that found no note this party certifies present and unspent on its own view.
    pub spends_no_note: usize,
    /// Spends whose carrier the party could not build (`spend_tx_for_test` errored).
    pub spends_carrier_failed: usize,
    /// Spends that built a carrier but produced no block.
    pub spends_no_block: usize,
    /// Spends whose note this party holds but which had not CONFIRMED on the publishing party — its record still
    /// inside the fold lag after the owner waited `fold_depth + 1` of its own blocks. Counted apart from
    /// `spends_carrier_failed`, which is now only a CONFIRMED note whose carrier could not be built: a real defect.
    pub spends_unconfirmed: usize,
    /// Every real note's commitment and whether the schedule spent it — the digital-cash verdict each
    /// party must give. O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one per Receive action.
    pub(crate) real_notes: Vec<([u8; 32], bool)>,
    /// ⭐ Z1 — THE NULLIFIERS THIS SCHEDULE ACTUALLY PUBLISHED. Under the Zcash shape a spent note's
    /// record does NOT vanish: the commitment stays in the append-only frontier forever and the spend
    /// publishes a nullifier instead. So "did the chain spend it" is a question about THIS set, and it is
    /// the only coordinate on which every party can be held to the same answer.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one per landed Spend action, and a schedule
    /// carries a fixed number of actions.
    pub(crate) spent_nullifiers: Vec<[u8; 32]>,
    /// ⛔ THE DISK THIS RUN OWNS — one datadir per party, index-aligned with `parties`, for the whole life
    /// of the `Sim`. A `Restart` reuses `dirs[i]` rather than minting another, so a run's directory count
    /// is its PARTY count however many candidates a shrink executes, and dropping the `Sim` — on the happy
    /// path, on a failed assertion, or while unwinding from a panic — removes every one of them.
    /// See [`ScenarioDataDir`] for the 11,161-orphaned-directory measurement that made this a field.
    ///
    /// The record fold depth every party in this run was built with — see [`scenario_node_in_at_depth`].
    /// O1-FOOTPRINT-REVIEWED: one u64, fixed for the life of the case.
    fold_depth: u64,
    /// ⛔ THIS FIELD MUST STAY LAST. Rust drops fields in declaration order, so `parties` (first) dies
    /// before the directories it persists into; reordering these two would leave a node auto-saving to a
    /// path that no longer exists.
    /// O1-FOOTPRINT-REVIEWED: bounded by `harness::fuzz::engine::MAX_PARTIES` — one slot per party, fixed
    /// by the case before it runs; a `Restart` REUSES its slot rather than adding one.
    dirs: Vec<ScenarioDataDir>,
}

impl Sim {
    /// How many REAL notes this schedule actually planted — `Sim::receive` has an early exit that plants
    /// nothing, and a build that cannot tell the two apart asserts against whatever it happened to get.
    pub(crate) fn real_notes_len_for_test(&self) -> usize {
        self.real_notes.len()
    }

    /// The record ids of every REAL-note block this schedule planted.
    pub(crate) fn real_record_ids_for_test(&self) -> Vec<u64> {
        self.real_records.clone()
    }

    /// The record fold depth EVERY party in this run was built with.
    ///
    /// ⛔ A `Restart` must mint its fresh node at THIS depth, not at the default. A party that came back
    /// disagreeing with its peers about when a record becomes canonical would fold a different set and
    /// diverge — and the divergence would be the harness's, reported as the node's.
    pub(crate) fn fold_depth(&self) -> u64 {
        self.fold_depth
    }
}

impl Sim {
    /// Z1: what the sim knows the chain did to each real note (`spent`), beside what party `i` can
    /// still SEE of it — its record. A node can no longer answer "is this commitment spent": under the
    /// Zcash shape spent-ness is a fact about a NULLIFIER and is unlinkable to a commitment by anyone
    /// but the owner. The findability half is what a node still owes: a note whose record vanished is
    /// unspendable, which is the fund-loss class this diagnostic exists for.
    pub fn note_verdicts(&self, i: usize) -> Vec<(bool, Option<bool>)> {
        self.real_notes
            .iter()
            .map(|(cm, spent)| {
                (*spent, Some(!self.parties[i].records_containing_cm(cm).is_empty()))
            })
            .collect()
    }
    pub fn repair_round(&mut self) {
        for p in self.parties.iter_mut() {
            p.retire_held_record_ids();
            // The runtime runs this on EVERY tick (`drain_inbound`); an engine that skipped it kept
            // wants the production node would have retired, and read them as permanent holes.
            p.clear_satisfied_wants();
        }
        self.exchange_tips();
        self.exchange_pages();
        self.serve_roots_runs();
        self.serve_record_fetches();
        self.serve_notes_backfill();
        // The relay tick runs the payload-hole heal EVERY tick, converged or not — so does this engine.
        self.serve_payload_holes_by_id();
        // ⭐ DB-290 (A''): and it drives the copath-source warm every tick (`NodeRuntime::drive_nf_pivot`), so this engine
        // warms every viewless party too. Without it a jumped or restarted party stays viewless for the rest of the
        // schedule and refuses every spend (DB-217's stated con), and every send oracle here runs over zero sends.
        self.warm_viewless_parties();
        self.exchange_pages();
        self.re_anchor_stale_parties();
        for p in self.parties.iter_mut() {
            p.retire_held_record_ids();
            // The runtime runs this on EVERY tick (`drain_inbound`); an engine that skipped it kept
            // wants the production node would have retired, and read them as permanent holes.
            p.clear_satisfied_wants();
            let _ = p.fold_canonical_records();
        }
    }
    /// ⭐ DB-290 (A''): the warm the relay tick drives, run synchronously. Each party that stands on a pivot with no view
    /// pulls key-cursor pages from the first party whose view is CURRENT, exactly as the kind-17 lane serves them
    /// (`sparse_stream_page_after`, `NF_WARM_PAGE_TAGS` a page), syncs its own tail out, and installs only through
    /// `PivotWarm::into_healed` (root == its pivot) and `install_healed_pivot` (three re-checks). The donor choice is
    /// deterministic (lowest index), so a schedule replays identically. Bounded: each page advances the key cursor over
    /// a finite set, and a refused page ends the attempt. ⛔ DB-428: a donor that cannot place the pivot serves nothing for
    /// it, and the next current donor (in index order) is asked; a pivot no donor places waits for the scenario's next step.
    fn warm_viewless_parties(&mut self) {
        for i in 0..self.parties.len() {
            let Some(pivot) = self.parties[i].sparse_pivot() else {
                continue;
            };
            let donors: Vec<usize> = (0..self.parties.len())
                .filter(|&j| j != i && self.parties[j].nf_copath_source_state() == (true, true))
                .collect();
            for j in donors {
                let mut pw = crate::nf_sparse::PivotWarm::new(pivot);
                loop {
                    // DB-353 landing 2: the tail since THIS warm's target, from the band journal; a target that left the
                    // journal's reach ends the warm (the scenario's next step starts one toward the live band root).
                    let Some(tail) = self.parties[i].sparse_pivot_tail_since(pw.pivot(), pw.tail_synced()) else {
                        break;
                    };
                    pw.sync_tail(&tail);
                    if pw.stream_done() {
                        break;
                    }
                    // DB-426/428: the ONE serve — `set(pivot)` exactly, or nothing from a donor that cannot place it
                    let Ok(page) = self.parties[j].sparse_stream_page_for(&pw.pivot(), pw.cursor().as_ref(), 16_384) else {
                        break;
                    };
                    if !pw.absorb_page(&page, true) || pw.restart_if_exact_missed() {
                        break;
                    }
                }
                if let Ok(h) = pw.into_healed() {
                    let _ = self.parties[i].install_healed_pivot(h);
                    break;
                }
            }
        }
    }
    /// Hand everything over until nothing is owed. Bounded: a block that still cannot graft after this
    /// many passes is a real failure to agree, not a slow one.
    pub fn drain(&mut self) {
        // Blocks (with parent asks), then one mesh repair round — pages, roots runs, by-id fetches,
        // re-anchors — then the folds those unblock; repeated until a full round moves nothing.
        // Bounded: a queue that never empties is a failure to agree.
        let observe = |s: &Sim| -> Vec<String> {
            s.parties
                .iter()
                .map(|p| {
                    format!(
                        "{}|{}|{}|{}|{}|{:?}|{:?}|{}|{}",
                        p.served_seq(),
                        p.sidecar_gap_count(),
                        p.missing_record_count(),
                        p.serve_ready(),
                        p.spine_stale_for_test(),
                        p.spend_frontier_root(),
                        p.nullifier_root(),
                        p.relay_buffered_len(),
                        p.ordinal_rows_for_test().len()
                    )
                })
                .collect()
        };
        for _ in 0..8 {
            let mut passes = 0;
            while !self.owed.is_empty() && passes < 8_000 {
                self.deliver(0);
                passes += 1;
            }
            let before = observe(self);
            self.repair_round();
            let after = observe(self);
            if self.owed.is_empty() && before == after {
                break;
            }
        }
    }
    /// Party `i` spends one real note it still holds unspent: a deletion carried by its next block.
    fn spend(&mut self, i: usize) -> Result<(), String> {
        if i >= self.parties.len() {
            return Ok(());
        }
        if self.parties[i].relay_buffered_len() > 0 {
            self.deferred_produces += 1;
            return Ok(());
        }
        // a note this party certifies PRESENT right now (READY and unspent on its own view)
        let pick = self
            .real_notes
            .iter()
            .position(|(cm, spent)| !*spent && !self.parties[i].records_containing_cm(cm).is_empty());
        let Some(k) = pick else {
            // Nothing this party can spend right now. Legitimate, and COUNTED — an uncounted no-op here
            // is a send that silently never happened.
            self.spends_no_note += 1;
            return Ok(());
        };
        let cm = self.real_notes[k].0;
        // ⭐⭐⭐ A SPEND IS MADE BY WHOEVER OWNS THE NOTE, AND `i` IS AN ARBITRARY SCHEDULE INDEX.
        //
        // ⛔ AND THE CORPUS ONLY LEARNED THIS ONCE THE FIXTURE BUILT A REAL CARRIER. A node that took a
        // DSYNC JUMP cannot publish a spend at all: `self_build_publish_absence_witness` returns `None`
        // for any node whose fold base is not genesis — "it cannot vouch for the span it leapt", and
        // publishing a witness it could not itself admit would settle on one device and die on the next.
        // That is a REAL production property, documented at that function and enforced identically on the
        // order-fill path. While this fixture's spend carried no nullifier the gate ran VACUOUSLY and the
        // corpus never saw it; with a real nullifier it refused every spend the schedule happened to aim
        // at the jumped party, and the campaign pin read `8 scheduled, 0 landed`.
        //
        // So the sim asks the parties that ACTUALLY HOLD the note, in order, exactly as a real owner would
        // use whichever of their own nodes can publish. ⛔ This does NOT relax the pin: if no holder can
        // publish, every attempt is still counted and the pin still fails — which is the correct verdict,
        // because a note nobody can spend is a note nobody can spend.
        let holders: Vec<usize> = (0..self.parties.len())
            .filter(|&p| !self.parties[p].records_containing_cm(&cm).is_empty())
            .collect();
        let i = holders
            .iter()
            .copied()
            .find(|&p| self.parties[p].can_publish_a_spend())
            .unwrap_or(i);
        // ⭐ A NOTE IS SPENT ONCE IT HAS CONFIRMED — its record FOLDED on the publishing party, so the owner's member
        // leg exists (DB-223 Q7; the wallet's "confirming" state, DB-372). At the production fold depth (32) a note
        // received a few blocks ago has not, and the old pick spent it anyway: MEASURED `0 landed / 8 scheduled …
        // carrier_failed=4`, every one `[member-leg-miss] … holds no witness for the note` — the note still pending its
        // record's fold, so every send verdict of the campaign was vacuous. A real owner WAITS: the publisher lays its
        // own blocks until the note confirms, bounded by the protocol's own depth (`fold_depth + 1` blocks puts the
        // note's block below the fold on a chain this party extends). A note that never confirms inside that bound is
        // counted (`spends_unconfirmed`), never spent and never silently dropped.
        let mut waited = 0u64;
        while !self.parties[i].member_path_ready_for_test(&cm) && waited <= self.fold_depth {
            self.produce_one(i);
            waited += 1;
        }
        if !self.parties[i].member_path_ready_for_test(&cm) {
            self.spends_unconfirmed += 1;
            return Ok(());
        }
        let salt = self.blocks.len() as u64;
        let spent_nf = match self.parties[i].spend_tx_for_test(&cm, salt) {
            Ok((_id, nf)) => nf,
            Err(why) => {
            // A spend this party cannot carry right now is not necessarily a defect — the note stays
            // live. But the REASON must not be swallowed: this party picked a note it certifies present
            // and unspent on its own view, and then could not build a carrier for it. That is one step
            // away from "a holder cannot spend their own money", so the reason is printed rather than
            // counted silently.
                eprintln!("[spend-miss] party {i} holds a note it certifies unspent but built no carrier: {why}");
                self.spends_carrier_failed += 1;
                return Ok(());
            }
        };
        self.now += self.parties[0].params().target_spacing_ms;
        let tag = format!("spend-{}-{}", i, self.blocks.len());
        let now = self.now;
        let Some(blk) = self.parties[i].produce(now, Hash32::hash(tag.as_bytes()), Hash32::hash(b"miner")) else {
            self.spends_no_block += 1;
            return Ok(());
        };
        if blk.nullifier_proof.padded_tags.is_empty() {
            return Err(format!("party {i}: the block after a spend carried no nullifier"));
        }
        self.real_notes[k].1 = true;
        self.spent_nullifiers.push(spent_nf);
        // A SEND REALLY HAPPENED: a note this party certified present is now spent, and the block
        // carrying its deletion exists. This is the only path that may be counted as coverage.
        self.spends_landed += 1;
        for j in 0..self.parties.len() {
            if j != i {
                self.owed.push((j, blk.clone()));
            }
        }
        self.blocks.push(blk);
        Ok(())
    }
    /// A snapshot of everything a refused adopt must leave untouched.
    fn state_digest(&self, i: usize) -> (Option<crate::block::BlockId>, u64, crate::spend_frontier::Digest4, Vec<(u64, u64)>) {
        let n = &self.parties[i];
        (n.selected_tip(), n.served_seq(), n.spend_frontier_root(), n.ordinal_rows_for_test())
    }
    /// THE PROPERTY every gate failure from run 30 on violated: once everyone holds every block, everyone
    /// derives the same record space — the same ordinal for every record, the same dense fold counter, the
    /// same spine root, the same unspent root.
    pub fn agreement(&self) -> Result<(), String> {
        let ords = |n: &Node| -> Vec<Option<u64>> {
            self.blocks
                .iter()
                .map(|b| n.da_record_ordinal(Node::da_record_id_for_block(&b.id(), 0)))
                .collect()
        };
        let tip0 = self.parties[0].selected_tip();
        for (i, n) in self.parties.iter().enumerate().skip(1) {
            if n.selected_tip() != tip0 {
                return Err(format!(
                    "party {i} stands on a different selected tip than party 0 once the queue is empty \
                     ({:?} vs {:?})",
                    n.selected_tip(),
                    tip0
                ));
            }
        }
        let (o0, r0, s0) = (
            ords(&self.parties[0]),
            self.parties[0].spend_frontier_root(),
            self.parties[0].served_seq(),
        );
        for (i, n) in self.parties.iter().enumerate().skip(1) {
            let oi = ords(n);
            let differ: Vec<(usize, Option<u64>, Option<u64>)> = o0
                .iter()
                .zip(oi.iter())
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .map(|(k, (a, b))| (k, *a, *b))
                .collect();
            if !differ.is_empty() {
                // name the ordinals by the BLOCK INDEX they hold on each side — legible without a rid
                let by_index: Vec<String> = differ
                    .iter()
                    .take(6)
                    .map(|(k, a, b)| {
                        let at = |o: &Option<u64>, n: &Node| -> String {
                            match o {
                                Some(ord) => format!("{ord}"),
                                None => n
                                    .da_addr_at_ordinal(0)
                                    .and_then(|_| None::<u64>)
                                    .map(|x| x.to_string())
                                    .unwrap_or_else(|| "-".into()),
                            }
                        };
                        format!("block {k}: p0@{} p{i}@{}", at(a, &self.parties[0]), at(b, n))
                    })
                    .collect();
                let holders: Vec<String> = differ
                    .iter()
                    .take(6)
                    .filter_map(|(k, _, _)| self.blocks.get(*k))
                    .map(|b| {
                        let rid = Node::da_record_id_for_block(&b.id(), 0);
                        format!("{}", self.block_index_of_rid(rid).map(|x| x.to_string()).unwrap_or("?".into()))
                    })
                    .collect();
                return Err(format!(
                    "party {i} folds {} block(s) at different ordinals than party 0: [{}] (blocks {})",
                    differ.len(),
                    by_index.join(", "),
                    holders.join(",")
                ));
            }
            // ⛔ `served_seq` IS NOT A CONSENSUS VALUE, AND ASSERTING IT AS ONE REPORTED FALSE BUGS.
            //
            // It is a monotone LOCAL watermark. `restore_snapshot` raises it with
            // `served_seq.max(snap.served_seq)` and never shrinks it; a DSYNC jump raises it to a certified
            // position the jumper never folded through. MEASURED 2026-09-04 while chasing what looked like
            // a fold divergence: seed 2 reported "party 2 counter 2 vs party 0 1" with NOTHING filed at
            // ordinal 1 on either party — the counter had been raised by a jump, and both nodes were in
            // perfect agreement about every record that exists.
            //
            // The value that IS consensus is the one below: two nodes that folded the same records in the
            // same order hold the same spine root, and a node one record short cannot. Asserting the root
            // (plus the per-block ordinals above it) says everything the counter was standing in for and
            // nothing it was inventing. This is not a relaxation — it is the difference between checking a
            // node's private bookkeeping and checking the ledger.
            if n.spend_frontier_root() != r0 {
                return Err(format!("party {i} spine root differs from party 0"));
            }
            // ⭐ AUTHORITY BATCH 4 (2026-09-22) — two fields declared `ChainDerived` in
            // `AUTHORITY_MANIFEST` and, until now, compared by nothing. The manifest's own rule is that
            // a `ChainDerived` claim nothing compares reads as coverage while protecting nothing, which
            // is worse than an honest `Unclassified`; these two are added WITH their comparison rather
            // than parked against the ceiling.
            //
            //   certified_anchor_score — the blue score of the anchor this node certified. Two parties
            //   holding different ones disagree about which position the chain certified, which is the
            //   DB-140/141 class (a fold stopped when the horizon pruned the anchor).
            //   ⛔ RETIRED 2026-10-27 (lane funds; seed 2 of `every_layer_of_node_operation_…`): party 1 jumped to
            //   party 0's bundle and held anchor score 7, party 0 — the origin that folded the same chain from genesis —
            //   held 0, while both held one spine root and every ordinal above it. The score is where THIS node's
            //   certification begins (its own certificate: `AUTHORITY_MANIFEST` rules it LocalCache beside
            //   `certified_anchor`); the DB-140/141 class it stood for — a fold stopped at a pruned anchor — is what the
            //   spine-root equality above and the ordinal comparison below measure directly.
            //   dsol_registry — the token registry carried in the certified bundle and bound into
            //   `sync_binding`. A party holding a different root would admit token mints the chain never
            //   registered, or refuse ones it did.
            if n.dsol_registry_root() != self.parties[0].dsol_registry_root() {
                return Err(format!(
                    "party {i} holds a DIFFERENT DSOL registry root than party 0 — one of them would \
                     admit a token mint the chain never registered"
                ));
            }
        }
        // ⭐ Stage-3 cross-party pin (a) — REVERSE-map equality: the (ordinal -> record) map, not
        // just the per-block (record -> ordinal) zip above. Catches a PHANTOM row — an ordinal
        // occupied by a rid outside the recorded block list — which the forward zip can never see.
        // A pin (verdict tightening), not a fix: every mismatch is a returned failure.
        let horizon = self.blocks.len() as u64 + 2;
        for o in 0..horizon {
            let a0 = self.parties[0].da_addr_at_ordinal(o);
            for (i, n) in self.parties.iter().enumerate().skip(1) {
                let ai = n.da_addr_at_ordinal(o);
                if ai != a0 {
                    return Err(format!(
                        "party {i} holds a different record at ordinal {o} than party 0 \
                         (reverse map: {a0:?} vs {ai:?})"
                    ));
                }
            }
        }
        // ⭐ Stage-3 cross-party pin (c) — the leaf law asserted from OUTSIDE, per party: the spine
        // holds exactly cursor_row * width leaves (genesis holds position 0 and contributes none; a
        // party that never folded holds an empty spine) — the same law the C5 pass gate checks from
        // inside, measured here at quiescence where mid-batch excess must be gone.
        for (i, n) in self.parties.iter().enumerate() {
            let width = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
            let want = match n.fold_cursor_row_for_test() {
                Some(row) => row.saturating_mul(width),
                None => 0, // no cursor row = nothing folded: the law requires an empty spine
            };
            if n.spend_frontier_count() != want {
                return Err(format!(
                    "party {i} violates the leaf law: {} leaves vs cursor row {:?} * {width}",
                    n.spend_frontier_count(),
                    n.fold_cursor_row_for_test()
                ));
            }
        }
        Ok(())
    }
    /// Every party is READY the way the roll gate measures it: serving, no sidecar gap, no missing record,
    /// no stale spine, no gossiped block still waiting on a parent — and the queue is empty.
    pub fn all_ready(&self) -> Result<(), String> {
        if self.owed_len() > 0 {
            return Err(format!(
                "{} block(s) could never be delivered (first: block {:?} to party {:?})",
                self.owed_len(),
                self.owed_head().and_then(|(_, k)| k),
                self.owed_head().map(|(to, _)| to)
            ));
        }
        for (i, n) in self.parties.iter().enumerate() {
            if n.relay_buffered_len() > 0 {
                return Err(format!("party {i} still holds {} gossiped block(s) waiting on a parent", n.relay_buffered_len()));
            }
            if n.spine_stale_for_test() {
                return Err(format!("party {i} is STALE once everything is delivered — no certified bundle re-anchored it"));
            }
            if n.sidecar_gap_count() != 0 {
                // NAME THE COMPONENT. "a gap of 2" is four different defects wearing one number — a named
                // hole, a payload hole, the paging backlog, or the seed walk — and the fix for each is in
                // a different lane. Counts only; no coordinate, note, amount or owner.
                let (wo, wr, wi, dw, pg) = n.missing_record_breakdown();
                return Err(format!(
                    "party {i} has a sidecar gap of {} once everything is delivered \
                     (named holes {}, backlog {}, wanted_ordinals {wo}, wanted_ids {wr}+{wi}, da_wanted {dw}, payload holes {pg})",
                    n.sidecar_gap_count(),
                    n.sidecar_named_hole_count_for_test(),
                    n.sidecar_backlog(),
                ) + &format!(", of which stale (bytes already held) {}", n.payload_gap_stale_count_for_test()));
            }
            if n.missing_record_count() != 0 {
                return Err(format!("party {i} still misses {} record(s) once everything is delivered", n.missing_record_count()));
            }
            if !n.serve_ready() {
                return Err(format!("party {i} is NOT READY once everything is delivered"));
            }
        }
        Ok(())
    }
    /// ⭐ ONE DERIVATION for a party's node secret, used at construction AND across every restart — a
    /// second spelling is exactly how a replay lane drifts from itself.
    fn party_miner_seed(seed: u64, i: usize) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD-sim-party-miner-seed-v1");
        h.update(&seed.to_le_bytes());
        h.update(&(i as u64).to_le_bytes());
        *h.finalize().as_bytes()
    }

    pub fn new(n: usize, seed: u64) -> Sim {
        Sim::new_at_depth(n, seed, crate::params::RECORD_FOLD_DEPTH_DEFAULT)
    }

    /// A run whose parties fold their records AT THE TIP.
    ///
    /// For a fixture whose subject is what a node HOLDS — custody, retention, the leaf count a detector
    /// watches leave — rather than WHEN it becomes canonical. See [`scenario_node_in_at_depth`] for why
    /// the production depth makes such a fixture assert against an empty set.
    pub fn new_folding_at_tip(n: usize, seed: u64) -> Sim {
        Sim::new_at_depth(n, seed, 0)
    }

    fn new_at_depth(n: usize, seed: u64, fold_depth: u64) -> Sim {
        // H-3 (2026-10-27): the parties' fresh seed notes draw from `seed` on this thread, so a replay of one
        // (parties, seed, ops) reproduces the unspent roots and padded tags the catalogue judges (`cover::SEEDED_FRESH_NOTES`).
        #[cfg(test)]
        crate::cover::seed_fresh_notes_for_test(Some(seed ^ 0x5EED_0000_0000_0001));
        let dirs: Vec<ScenarioDataDir> = (0..n.max(2)).map(|_| ScenarioDataDir::new()).collect();
        let mut parties: Vec<Node> = dirs
            .iter()
            .map(|d| scenario_node_in_at_depth(d, fold_depth))
            .collect();
        // ⭐ DETERMINISTIC PER-PARTY SECRETS — a reproducer must control the node's secrets, not just its
        // ops. §CE derives the nullifier decoy secret from `miner_seed`, which production draws fresh per
        // node (correct: each node's decoys are its own). A replay lane cannot live with that, and said so:
        // `D-37 HAS ESCALATED` with every field identical except `nf_acc`/`nf_root`. Seeded from the sim's
        // own seed and the party index, so the same `(parties, seed, ops)` replays to the same state.
        for (i, p) in parties.iter_mut().enumerate() {
            p.set_miner_seed_for_test(Self::party_miner_seed(seed, i));
        }
        let parties = parties;
        let now = parties[0]
            .dag()
            .get(&parties[0].selected_tip().expect("tip"))
            .expect("header")
            .header
            .timestamp;
        let n = parties.len();
        Sim {
            parties,
            owed: Vec::new(),
            blocks: Vec::new(),
            now,
            rng: seed | 1,
            seed,
            trace: Vec::new(),
            last_adopted: (0..n).map(|_| None).collect(),
            real_records: Vec::new(),
            honest_refusals: Vec::new(),
            deferred_produces: 0,
            spends_landed: 0,
            spends_no_note: 0,
            spends_carrier_failed: 0,
            spends_no_block: 0,
            spends_unconfirmed: 0,
            real_notes: Vec::new(),
            spent_nullifiers: Vec::new(),
            fold_depth,
            dirs,
        }
    }

    /// Per real note: `(block_index, merged_later)` — the schedule index of the block that carried it, and
    /// whether ANY later block in the schedule names that block as a parent. Diagnostics only. A dropped
    /// delivery of a block no later block merges is a tip only the parties that received it can hold; the
    /// mesh's parent-ask cannot pull it (nothing references it) and this harness has no tip-exchange lane,
    /// so a party missing it is a harness-completeness fact, not a node fault — this is what tells the two
    /// apart. Bounded by the schedule's block list; a replay reads it once per dump.
    pub fn note_block_merged(&self) -> Vec<(usize, bool)> {
        self.real_records
            .iter()
            .map(|seq| {
                let pos = self
                    .blocks
                    .iter()
                    .position(|b| Node::da_record_id_for_block(&b.id(), 0) == *seq);
                match pos {
                    Some(k) => {
                        let id = self.blocks[k].id();
                        let merged = self.blocks[k + 1..].iter().any(|b| b.header.parents.contains(&id));
                        (k, merged)
                    }
                    None => (usize::MAX, false),
                }
            })
            .collect()
    }

    /// How many deliveries are still owed (diagnostics).
    pub fn owed_len(&self) -> usize {
        self.owed.len()
    }

    /// The recipient and schedule index of the next owed delivery (diagnostics).
    pub fn owed_head(&self) -> Option<(usize, Option<usize>)> {
        self.owed.first().map(|(to, b)| (*to, self.blocks.iter().position(|x| x.id() == b.id())))
    }

    /// One mesh repair round without block delivery: pages, roots runs, by-id fetches, re-anchors
    /// (diagnostics: lets a replay interleave markers between deliveries).
    /// Every block this schedule has produced (any party, any op), by id — the ground truth a party's DAG
    /// is compared against for "did it recover everything it missed".
    pub fn produced_block_ids(&self) -> Vec<crate::block::BlockId> {
        self.blocks.iter().map(|b| b.id()).collect()
    }

    /// THE DAS NOTES BACKFILL, as the mesh serves it (`[bulk]` pages): a party whose applied-note
    /// cursor sits below its note-body target asks for the records from that cursor up; any party that
    /// holds them answers a budgeted page; the asker verifies each record, applies the notes and moves
    /// its cursor to what the page covered (`Node::notes_page_budgeted`, `apply_backfilled_notes`).
    fn serve_notes_backfill(&mut self) {
        let n = self.parties.len();
        for i in 0..n {
            // ⭐ DB-302 (review, lane-wallet-cover): an empty askable list can now also mean "deferred behind an open
            // headers-first span", which is OWED. The builder still runs exactly as before (it carries the rolling
            // reseed); a deferred want keeps this round, and the range below stops at the door on its own.
            if self.parties[i].note_payload_debt() == 0
                && self.parties[i].wanted_record_ordinals().is_empty()
                && !self.parties[i].headers_first_defers_a_record_want()
            {
                continue;
            }
            let from = self.parties[i].note_backfill_cursor();
            // ⭐ DB-302: the range stops below an open headers-first span, as production's kind-8 ask does
            // (`range_ask_bound` → `Node::record_row_top`): bytes the open span cannot judge are not asked. The debt
            // stays; the same range goes out on the first round after the span closes.
            let mut count = 256u64;
            while count > 0 && self.parties[i].headers_first_door_open_at(from + count - 1) {
                count -= 1;
            }
            if count == 0 {
                continue;
            }
            for j in 0..n {
                if i == j {
                    continue;
                }
                let (page, covered) = self.parties[j].notes_page_budgeted(from, count, 8 << 20);
                if page.is_empty() {
                    continue;
                }
                // The mesh's OWN record encoding — never a fourth hand-written copy (see
                // `Node::ledger_record_for_rid`).
                let entries: Vec<crate::protocol::LedgerRecord> = page
                    .iter()
                    .filter_map(|(rid, _notes, _targets)| self.parties[j].ledger_record_for_rid(*rid))
                    .collect();
                for e in &entries {
                    let _ = self.parties[i].accept_fetched_record(e.rid, &e.notes, e.key());
                }
                let _ = self.parties[i].apply_backfilled_notes(&entries);
                self.parties[i].advance_note_backfill_cursor(covered);
                break;
            }
        }
    }

    /// ⭐⭐⭐ THE PAYLOAD-HOLE BY-ID REFILL, as the relay tick runs it (`node_runtime.rs`: the
    /// `payload_gap_ids()` → kind-1 `NotesReq` → `apply_backfilled_notes` heal).
    ///
    /// WHY A SECOND LANE. The cursor lane above asks from a CURSOR and only when a party's note-payload
    /// DEBT is non-zero. Both halves of that gate are blind to a hole: the debt is a COUNT
    /// (`note_body_target - blocks_note_applied`) that any later block pays down without naming the
    /// block that was skipped, and a cursor that has already walked PAST the hole never asks for it
    /// again. That is the I-CC lesson the node itself acted on — it stopped counting and started naming
    /// the blocks it holds without their record payload — and a schedule that models only the count
    /// lane asserts a convergence the real mesh reaches through a lane this Sim refused to run.
    /// MEASURED (this is why it exists): db119 left party 1 and db120 left party 0 at quiescence with
    /// `debt == 0`, no wanted ordinals, and 1 and 2 named payload holes that nothing would ever ask for.
    ///
    /// Bounded exactly as the wire is: at most `TX_REQ_FIXED_COUNT` ids per round, one peer per asker.
    fn serve_payload_holes_by_id(&mut self) {
        let n = self.parties.len();
        for i in 0..n {
            let mut ids = self.parties[i].payload_gap_ids();
            if ids.is_empty() {
                continue;
            }
            ids.truncate(crate::protocol::TX_REQ_FIXED_COUNT);
            for j in 0..n {
                if i == j {
                    continue;
                }
                let entries: Vec<crate::protocol::LedgerRecord> = ids
                    .iter()
                    .map(|id| self.parties[j].record_addr_for_block_or_canonical(id))
                    .filter_map(|rid| self.parties[j].ledger_record_for_rid(rid))
                    .collect();
                if entries.is_empty() {
                    continue;
                }
                for e in &entries {
                    let _ = self.parties[i].accept_fetched_record(e.rid, &e.notes, e.key());
                }
                let _ = self.parties[i].apply_backfilled_notes(&entries);
                break;
            }
        }
    }

    /// Every block's record id, in schedule order (diagnostics).
    pub fn block_rids(&self) -> Vec<u64> {
        self.blocks.iter().map(|b| Node::da_record_id_for_block(&b.id(), 0)).collect()
    }

    /// The schedule index of the block whose record id is `rid` (diagnostics).
    pub fn block_index_of_rid(&self, rid: u64) -> Option<usize> {
        self.blocks.iter().position(|b| Node::da_record_id_for_block(&b.id(), 0) == rid)
    }

    /// xorshift64 — deterministic, so a seed reproduces a schedule exactly.
    pub fn rand(&mut self, m: usize) -> usize {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        if m == 0 {
            0
        } else {
            (self.rng >> 3) as usize % m
        }
    }

    fn produce_one(&mut self, i: usize) {
        if i >= self.parties.len() {
            return;
        }
        // RUNTIME PARITY: `NodeRuntime::begin_produce` never extends a chain while a gossiped block waits
        // on a parent this node lacks (gate 45: a restarted node mined ~190 blocks alone on a stale tip).
        if self.parties[i].relay_buffered_len() > 0 {
            self.deferred_produces += 1;
            return;
        }
        self.now += self.parties[0].params().target_spacing_ms;
        let tag = format!("scen-{}-{}", i, self.blocks.len());
        let now = self.now;
        let blk = match self.parties[i].produce(now, Hash32::hash(tag.as_bytes()), Hash32::hash(b"miner")) {
            Some(b) => b,
            None => return, // a party that cannot produce right now simply does not — not a defect
        };
        for j in 0..self.parties.len() {
            if j != i {
                self.owed.push((j, blk.clone()));
            }
        }
        self.blocks.push(blk);
    }

    pub(crate) fn deliver(&mut self, k: usize) {
        if self.owed.is_empty() {
            return;
        }
        let k = k % self.owed.len();
        let (to, blk) = self.owed.remove(k);
        self.now += 1;
        let now = self.now;
        self.deliver_to(to, blk);
    }

    /// One delivery, with the mesh's answer to each outcome: a graft is done; a duplicate is done; a
    /// block waiting on a parent this party lacks pulls that parent FIRST (`[block-id-serve]`, the parent
    /// ask — a restarted node holds its anchor's past only as shells); a refusal of an HONEST block is
    /// recorded as evidence, never retried into silence.
    fn deliver_to(&mut self, to: usize, blk: Block) {
        self.now += 1;
        let now = self.now;
        match self.parties[to].ingest_block(blk.clone(), now) {
            RelayOutcome::Added(_) | RelayOutcome::Duplicate(_) => {}
            RelayOutcome::Buffered { missing, .. } => {
                // The parent ask walks DOWN: the missing parent may itself wait on a parent this party
                // lacks (a restarted node's anchor past is shells; a lost delivery's whole lineage). Ask
                // for the deepest missing ancestor first, then each one above it, then the block.
                let mut lineage: Vec<Block> = Vec::new();
                let mut want = missing;
                for _ in 0..4_096 {
                    if self.parties[to].dag().get(&want).is_some() {
                        break;
                    }
                    let Some(b) = self.blocks.iter().find(|b| b.id() == want).cloned() else { break };
                    let next = b
                        .header
                        .parents
                        .iter()
                        .copied()
                        .find(|p| self.parties[to].dag().get(p).is_none());
                    lineage.push(b);
                    match next {
                        Some(p) => want = p,
                        None => break,
                    }
                }
                if lineage.is_empty() {
                    self.owed.push((to, blk));
                } else {
                    self.owed.insert(0, (to, blk));
                    for b in lineage {
                        self.owed.insert(0, (to, b));
                    }
                }
            }
            RelayOutcome::Invalid(why) => {
                if self.blocks.iter().any(|b| b.id() == blk.id()) {
                    self.honest_refusals.push((to, blk.id(), format!("{why:?}")));
                }
            }
            other => {
                let _ = other;
                self.owed.push((to, blk));
            }
        }
    }

    /// THE SIDECAR PAGES, as the mesh serves them: every party hands every other party the
    /// (ordinal, record) rows it holds. A node that adopted a certified spine holds its prefix as
    /// coordinates only until pages arrive; a row is a hint above the counter and never displaces a
    /// local claim (`Node::adopt_sidecar_row`).
    /// THE TIP RELAY, as the mesh runs it: every party's DAG tips reach every other party (the runtime's `TipBeacon` cells and
    /// the block lane's getdata, BORROWED from Bitcoin's `inv`/`getdata` and Kaspa's tip relay), and a party that lacks one
    /// pulls it through the ordinary delivery door — parent asks included. MEASURED why (lane stable 2026-11-01, the
    /// three-party search seed 5, stable/c3.log): party 0 lost a block in flight (`drop 0`), nothing was ever built on it,
    /// and the drain — which repaired only parent asks — left party 0 without block 44d9ffc1 and its real record for good,
    /// where a daemon's next beacon would have named the tip. Only blocks the schedule produced honestly are handed over;
    /// a forged or tampered block is never re-sent by this repair.
    fn exchange_tips(&mut self) {
        let n = self.parties.len();
        for j in 0..n {
            for tip in self.parties[j].dag().tips() {
                for i in 0..n {
                    if i == j || self.parties[i].dag().get(&tip).is_some() {
                        continue;
                    }
                    if let Some(b) = self.blocks.iter().find(|b| b.id() == tip).cloned() {
                        self.deliver_to(i, b);
                    }
                }
            }
        }
        let mut passes = 0;
        while !self.owed.is_empty() && passes < 8_000 {
            self.deliver(0);
            passes += 1;
        }
    }

    fn exchange_pages(&mut self) {
        let n = self.parties.len();
        let rows: Vec<Vec<(u64, u64)>> = self.parties.iter().map(|p| p.ordinal_rows_for_test()).collect();
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    self.parties[i].adopt_rows_for_test(&rows[j]);
                }
            }
        }
    }

    /// THE BY-ID FETCH (`[da-fetch]`, the id lane): a party that wants a record's bytes by id asks, and any
    /// party that holds them answers; the asker verifies against the roots it holds and refuses otherwise
    /// (`Node::accept_fetched_record`).
    fn serve_record_fetches(&mut self) {
        let n = self.parties.len();
        for i in 0..n {
            let wanted: Vec<u64> = self.parties[i].wanted_record_ids();
            for rid in wanted {
                for j in 0..n {
                    if i == j {
                        continue;
                    }
                    if let Some(bytes) = self.parties[j].da_record_notes(rid) {
                        let key = self.parties[j].cover_key_of(rid);
                        if self.parties[i].accept_fetched_record(rid, &bytes, Some(key)) {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// THE BEACON PATH, as the mesh walks it: a party whose spine is stale (its chain moved below the
    /// certified anchor it holds shells under) asks for a certified bundle and adopts the heaviest one
    /// a peer serves — the verify-once fork choice, measured against its anchor.
    fn re_anchor_stale_parties(&mut self) {
        let n = self.parties.len();
        for i in 0..n {
            if !self.parties[i].spine_stale_for_test() {
                continue;
            }
            let mut peers: Vec<(u128, usize)> = (0..n)
                .filter(|j| *j != i && !self.parties[*j].spine_stale_for_test())
                .map(|j| {
                    let w = self.parties[j]
                        .selected_tip()
                        .and_then(|t| self.parties[j].dag().get(&t).map(|b| b.blue_work))
                        .unwrap_or(0);
                    (w, j)
                })
                .collect();
            peers.sort_by(|a, b| b.cmp(a));
            for (_, j) in peers {
                self.jump(i, j);
                if !self.parties[i].spine_stale_for_test() {
                    break;
                }
            }
        }
    }

    /// THE ROOTS RUN (kind 6), as the mesh serves it: a party with an open span asks, and any party that
    /// can derive the roots for that range answers; the asker verifies the run against its certified
    /// target and refuses it whole on a mismatch (`Node::accept_fetched_root_run`).
    fn serve_roots_runs(&mut self) {
        let n = self.parties.len();
        for i in 0..n {
            let Some((from, count)) = self.parties[i].roots_run_ask_range() else { continue };
            for j in 0..n {
                if i == j {
                    continue;
                }
                let mut roots: Vec<crate::spend_frontier::Digest4> = Vec::with_capacity(count as usize);
                for ord in from..from.saturating_add(count as u64) {
                    match self.parties[j].block_root_at_ordinal(ord) {
                        Some(r) => roots.push(r),
                        None => break,
                    }
                }
                if !roots.is_empty() && self.parties[i].accept_fetched_root_run(from, &roots) {
                    break;
                }
            }
        }
    }

    /// Hand over the next `k` owed blocks at once, in queue order — a cascade.
    fn burst(&mut self, k: usize) {
        for _ in 0..k.max(1) {
            if self.owed.is_empty() {
                break;
            }
            self.deliver(0);
        }
    }

    /// Lose one owed delivery to `i` for good. The block is still in the schedule's record, so a later
    /// parent ask can pull it — gossip alone never will.
    fn drop_one(&mut self, i: usize) {
        if let Some(pos) = self.owed.iter().position(|(to, _)| *to == i) {
            self.owed.remove(pos);
        }
    }

    /// A block carrying a REAL note on party `i`: its record is bytes every party must come to hold.
    fn receive(&mut self, i: usize) {
        if i >= self.parties.len() {
            return;
        }
        if self.parties[i].relay_buffered_len() > 0 {
            self.deferred_produces += 1;
            return;
        }
        self.now += self.parties[0].params().target_spacing_ms;
        // ⭐⭐⭐ THE NOTE IS PLANTED AT A WITNESS-DERIVED COMMITMENT, AND THAT IS NOT A DETAIL.
        //
        // A note's commitment is SPENDABLE only if it is the leaf the prover writes: the spend cross-bind
        // is `Poseidon(note_leaf(cm), nf)` and the carrier proves it over its own row's leaf. Planting at
        // `hash("real-note-i-n")` gave the corpus notes no carrier could ever spend, so `Op::Spend` built
        // a transaction with no nullifier and no carrier — which no note transition can state, so every
        // peer refused its deletion (§BB). One spelling, both ends: plant where the prover will prove.
        //
        // The index is the receive ORDINAL, so a reproducer replays identically and a note planted at `k`
        // in one case is the note spent at `k` in another.
        let (note, cm) = Node::test_spendable_note(self.real_notes.len() as u64);
        let now = self.now;
        let (blk, seq) = self.parties[i].carry_notes_in_a_block_for_test(now, &note);
        self.real_records.push(seq);
        self.real_notes.push((cm, false));
        for j in 0..self.parties.len() {
            if j != i {
                self.owed.push((j, blk.clone()));
            }
        }
        self.blocks.push(blk);
    }

    /// Party `i` forgets every idle record's bytes: what a node does with cover it never keeps.
    fn forget(&mut self, i: usize) {
        if i >= self.parties.len() {
            return;
        }
        let ids: Vec<u64> = self
            .blocks
            .iter()
            .filter(|b| b.header.output_notes_root == Hash32::hash(&[]))
            .map(|b| Node::da_record_id_for_block(&b.id(), 0))
            .collect();
        for seq in ids {
            let _ = self.parties[i].test_drop_record_bytes(seq);
        }
    }

    fn bundle_of(&mut self, j: usize) -> Option<crate::sync::SyncBundle> {
        let src = &mut self.parties[j];
        src.build_sync_bundle(
            vec![1u8; 4096],
            FrontierSnapshot {
                root: *src.note_frontier_root().as_bytes(),
                height: src.note_frontier_count(),
                peaks_hex: src.spend_frontier_peaks_hex(),
            },
        )
    }

    /// `i` is offered `j`'s bundle with a spine that does not reproduce the certified root.
    fn tamper(&mut self, i: usize, j: usize) -> Result<(), String> {
        if i == j || i >= self.parties.len() || j >= self.parties.len() {
            return Ok(());
        }
        let Some(mut bundle) = self.bundle_of(j) else { return Ok(()) };
        // a spine for a different tree: one leaf flipped, the certified root untouched
        let mut forged = crate::spend_frontier::PoseidonSpendFrontier::new();
        for k in 0..bundle.frontier.height.max(1) {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&k.to_le_bytes());
            b[9] = 0x5a;
            forged.append(crate::spend_frontier::cm_bytes_to_leaf(&b));
        }
        bundle.frontier.peaks_hex = forged.peaks_hex();
        let before = self.state_digest(i);
        let _ = self.parties[i].instant_sync(bundle);
        let after = self.state_digest(i);
        if before.2 != after.2 || before.3 != after.3 {
            return Err(format!("party {i} took a TAMPERED spine from party {j}: its spine or unspent root moved"));
        }
        Ok(())
    }

    /// `i` is paged forged rows: random record ids at every real ordinal it holds a claim for.
    /// ⛔⛔⛔ THE CARRIAGE VERDICT (calibration row E-4) — NO REAL NOTE MAY BE CARRIED TWICE.
    ///
    /// This is a DISTINCT invariant from conservation and the design says so explicitly, because the
    /// 2026-09-03 DEX double-payout is the counter-example: both carried copies were individually
    /// legitimate, every amount balanced, and the maker's lot paid out twice. A sum cannot see a
    /// duplicate. Nothing in the harness counted carriages before this
    /// (`grep -rni carriage src/harness` → 0), so the whole class was unreachable.
    ///
    /// Asked of EVERY party, not just the producer: a note carried once on the node that minted it and
    /// twice on the node that ingested it is exactly the shape that pays out twice, and a check on the
    /// producer alone would report clean.
    ///
    /// cons: bounded by (real notes this case created) x (records a party holds), evaluated ONCE at
    /// quiescence. The case's Receive count is fixed before it runs, so there is no term in chain
    /// height or history; nothing is stored and nothing is retained.
    /// ⛔⛔⛔ THE COLD-PEER VERDICT (calibration row E-7) — STATE MUST BE A FUNCTION OF THE CHAIN.
    ///
    /// Row E-7 is the 2026-09-03 double payout, and its one-line cause was *"the burn was LOCAL and
    /// never travelled"*. Every live party self-verified correctly; the money still went out twice,
    /// because a value transition lived in one node's own memory instead of in a block. No amount of
    /// comparing live parties finds that — they can all be wrong together, and in that incident they
    /// were all individually right.
    ///
    /// So this builds a party that CANNOT be in on it: a brand-new node with its own empty datadir,
    /// no mempool, no staging, no adopted bundle — handed nothing but the BLOCKS, in production order.
    /// Whatever it derives is what the chain actually says. If a live party's unspent root disagrees
    /// with the cold peer's, that party is holding value the chain does not carry, which is the
    /// TRUSTLESS cardinal violated: *self-verification is not consensus, and only inclusion in a block
    /// decides that a transition happened.*
    ///
    /// Genesis is the same deterministic genesis every party uses (`scenario_node_in`), so the cold
    /// peer starts from the identical chain start and differs only in having seen no local state.
    ///
    /// cons: one extra node built and fed this case's blocks ONCE at quiescence. The case's block
    /// count is fixed before it runs, so there is no term in chain height or history; the node and its
    /// datadir are dropped at the end of the call.
    /// ⛔⛔⛔ THE PROVENANCE VERDICT (calibration rows C-H4, E-5) — A REFUSAL MUST NOT BE PURCHASABLE
    /// BY ASKING TWICE.
    ///
    /// CIRCULAR AUTHORITY is the class: a node refuses an item, stores something DERIVED FROM that
    /// item anyway, and then accepts the same item on its second offer because the authority it now
    /// judges against came from the item itself. D-32 was exactly this, live, at the verified-fetch
    /// door — *"the door ACCEPTED on the second offer a record it refused on the first, because
    /// `apply_backfilled_notes` had meanwhile stored the attacker's own bytes and the root is DERIVED
    /// from them."* It is invisible to every single-offer test BY CONSTRUCTION: the first offer is
    /// refused, which looks correct, and nothing ever asks again. The harness had no re-offer op at
    /// all (`Op::Replay` replays a BUNDLE, not a record offer), so the row could not be driven.
    ///
    /// The check is the simplest statement of the property: offer the identical hostile rows TWICE and
    /// require the identical answer. A door whose verdict depends on what it stored while refusing is
    /// a door an attacker turns by repeating itself.
    ///
    /// The payload is the same real one `forge_rows` carries — a `del` naming a commitment the victim
    /// holds, a `recv` naming one nobody sent — so the offer is something the door must genuinely
    /// refuse rather than a shape it dismisses for free.
    ///
    /// cons: bounded by (parties) x (rows a party holds), evaluated ONCE at quiescence. Parties are
    /// bounded by `harness::fuzz::engine::MAX_PARTIES` = 4, fixed before the case runs; no state is
    /// added and every offer goes through the same production door a real page uses.
    pub fn provenance_verdict(&mut self) -> Result<(), String> {
        let del: Vec<u8> = self
            .real_notes
            .iter()
            .find(|(_, spent)| !*spent)
            .map(|(cm, _)| cm.to_vec())
            .unwrap_or_default();
        let recv: Vec<u8> = Hash32::hash(b"provenance-recv-never-sent").as_bytes().to_vec();
        // Over PARTIES, a fixed protocol constant (<= MAX_PARTIES = 4) chosen before the case runs.
        // No term in chain height, block count or history.
        for (idx, party) in self.parties.iter_mut().enumerate() {
            let rows: Vec<(u64, u64)> = party
                .ordinal_rows_for_test()
                .iter()
                .map(|(o, _)| {
                    (
                        *o,
                        u64::from_le_bytes(
                            Hash32::hash(format!("provenance-forged-{o}").as_bytes()).as_bytes()
                                [..8]
                                .try_into()
                                .expect("8 bytes"),
                        ),
                    )
                })
                .collect();
            if rows.is_empty() {
                continue;
            }
            let first = party.adopt_rows_with_sidecars_verdicts_for_test(&rows);
            let second = party.adopt_rows_with_sidecars_verdicts_for_test(&rows);
            if let Some(detail) = Self::provenance_flip_detail(idx, &first, &second, rows.len()) {
                return Err(detail);
            }
        }
        Ok(())
    }

    /// The `I-PA` comparison, an associated fn so it can be REFUTED on its own.
    ///
    /// ⛔ WHAT THIS DOES AND DOES NOT PROVE, said plainly rather than implied. `I-PA` has two halves:
    ///   (a) it ASKS THE DOOR TWICE with a byte-identical offer — structural, visible in
    ///       `provenance_verdict` above, and not something a unit test can falsify;
    ///   (b) it REPORTS when the two answers differ — this function, refuted in both directions by
    ///       `harness::fuzz::selfproof`.
    /// Refuting (b) proves the alarm is wired and will not stay silent on a flip. It does NOT prove a
    /// real door can be made to flip: constructing that state IS the defect, and the only honest way
    /// to produce one is to find a live circular-authority door. D-32 was exactly one and is fixed. So
    /// this is the single detector here whose positive case rests on a real defect rather than a
    /// constructed one — registered, not hidden.
    pub(crate) fn provenance_flip_detail(
        idx: usize,
        first: &[bool],
        second: &[bool],
        rows: usize,
    ) -> Option<String> {
        if first == second {
            return None;
        }
        let flipped = first
            .iter()
            .zip(second.iter())
            .filter(|(a, b)| a != b)
            .count();
        Some(format!(
                    "party {idx}: CIRCULAR AUTHORITY — {flipped} of {rows} identical re-offers got a \
                     DIFFERENT verdict the second time (first {first:?}, second {second:?}). Nothing \
                     about the offer changed, so what changed is what the door judges AGAINST: it \
                     stored something derived from the very bytes it was refusing, and now those \
                     bytes authorise themselves. A refusal an attacker can buy by repeating the \
             request is not a refusal."
        ))
    }

    /// How many blocks this case has produced — the non-vacuity handle for the cold replay.
    pub fn produced_block_count_for_test(&self) -> usize {
        self.blocks.len()
    }

    /// ⛔ SELF-PROOF ONLY — a block that enters party `i`'s DAG and NEVER ENTERS THE CHAIN.
    ///
    /// The violating state for the `relay` comparison, built through the REAL producer rather than by
    /// poking a field: party `i` mines a block exactly as `produce_one` does, and the result is
    /// deliberately not pushed into `self.blocks` and not owed to anybody. The cold peer replays
    /// `self.blocks`, so it never sees it — which is precisely what a private fork looks like from
    /// outside: one node holding weight and notes that exist for nobody else.
    ///
    /// Returns whether a block was mined. BY CONSTRUCTION `Node::produce` returns `None` rather than
    /// a block on a party that cannot extend right now (`produce_one` takes the same branch), so the
    /// caller must read this and assert its own DAG moved — a refutation run against a party that
    /// never produced would be green while testing nothing.
    #[cfg(test)]
    pub(crate) fn selfproof_mine_a_block_the_chain_never_carries(&mut self, i: usize) -> bool {
        if i >= self.parties.len() {
            return false;
        }
        self.now += self.parties[0].params().target_spacing_ms;
        let now = self.now;
        let tag = format!("selfproof-offchain-{i}-{}", self.blocks.len());
        self.parties[i]
            .produce(now, Hash32::hash(tag.as_bytes()), Hash32::hash(b"miner"))
            .is_some()
    }

    /// ⭐⭐⭐ I-CP, Z1 SHAPE — EVERY PARTY DERIVES THE SAME RECORD SPACE FROM THE SAME BLOCKS.
    ///
    /// The deletion model's per-store comparisons (`da_recv_mem` / `da_del_mem`, by CONTENT — the D-21
    /// lesson that a row COUNT over a store that prunes is not a verdict) retired with the tree they
    /// described. What is left is the claim that actually decides whether a payment is findable on a
    /// cold peer: for every record party 0 holds REAL note bytes for, every other party either holds the
    /// same bytes at the same coordinate or holds nothing there — never different bytes, and never a
    /// commitment no block carried. Plus the account targets, which are what make a note discoverable at
    /// all. Bounded by the blocks the case itself produced, never by history.
    fn cold_peer_verdict_inner(&self, behind: &[usize], _closure_is_asserted: bool) -> Result<(), String> {
        if behind.contains(&0) {
            return Ok(()); // party 0 is the reference; a short reference can decide nothing
        }
        for rid in self.block_rids() {
            let Some(mine) = self.parties[0].da_record_notes(rid) else { continue };
            let my_targets = self.parties[0].da_load_account_targets(rid);
            for (i, n) in self.parties.iter().enumerate().skip(1) {
                if behind.contains(&i) {
                    continue;
                }
                if let Some(theirs) = n.da_record_notes(rid) {
                    if theirs != mine {
                        // Name WHERE they differ: the first differing note slot, both commitments, and whether party
                        // 0's slot appears anywhere in party i's record (moved) or nowhere (replaced / absent).
                        let w = crate::cover::PQ_NOTE_BYTES;
                        let cms = |r: &[u8]| -> Vec<[u8; 32]> {
                            r.chunks(w).filter(|c| c.len() >= 32).map(|c| c[..32].try_into().expect("32")).collect()
                        };
                        let (a, b) = (cms(&mine), cms(&theirs));
                        // Which REAL notes does each side hold, and where does party 0's extra one come from: the
                        // block's credit set (carried whole: the reward), its body, or neither.
                        let (ra, rb) = (self.parties[0].da_record_reals(rid), n.da_record_reals(rid));
                        let blk = self.block_index_of_rid(rid).map(|k| &self.blocks[k]);
                        let carried: Vec<Vec<u8>> = blk
                            .and_then(|bk| crate::block::credit_set_iter(&bk.credit_set, crate::block::credit_seal_key(&bk.header, bk.cover_key.as_ref()).as_ref(), &bk.wide_objects))
                            .map(|objs| objs.iter().flat_map(|o| crate::chain_object::carried_note_payloads(o).unwrap_or_default()).collect())
                            .unwrap_or_default();
                        let origin = |note: &Vec<u8>| -> &'static str {
                            if carried.iter().any(|c| c == note) {
                                "credit-carried"
                            } else if blk.is_some_and(|bk| bk.output_notes.chunks(w).any(|c| c == &note[..])) {
                                "body"
                            } else {
                                "neither"
                            }
                        };
                        let extra: Vec<&'static str> = match (&ra, &rb) {
                            (Some(x), Some(y)) => x.iter().filter(|r| !y.contains(r)).map(|r| origin(r)).collect(),
                            _ => Vec::new(),
                        };
                        let missing: Vec<&'static str> = match (&ra, &rb) {
                            (Some(x), Some(y)) => y.iter().filter(|r| !x.contains(r)).map(|r| origin(r)).collect(),
                            _ => Vec::new(),
                        };
                        // Each credit-set object: its class, its own nullifiers' presence in THIS block's header-bound lane, and
                        // whether its notes sit in party i's record.
                        let objs: Vec<String> = blk
                            .and_then(|bk| crate::block::credit_set_iter(&bk.credit_set, crate::block::credit_seal_key(&bk.header, bk.cover_key.as_ref()).as_ref(), &bk.wide_objects).map(|v| (bk, v)))
                            .map(|(bk, v)| {
                                v.iter()
                                    .map(|o| {
                                        let class = crate::chain_object::unframe(o).map(|(c, _)| format!("{c:?}")).unwrap_or_else(|| "unframed".into());
                                        let own = crate::chain_object::object_own_nullifiers(o);
                                        let in_lane = own.as_ref().map(|v| v.iter().filter(|nf| bk.nullifier_proof.padded_tags.contains(nf)).count());
                                        let notes = crate::chain_object::carried_note_payloads(o).unwrap_or_default();
                                        let held_i = notes.iter().filter(|p| rb.as_ref().is_some_and(|y| y.contains(p))).count();
                                        format!(
                                            "{class}: own {:?} in-lane {:?} notes {} held-by-party{i} {held_i}",
                                            own.as_ref().map(|v| v.len()),
                                            in_lane,
                                            notes.len()
                                        )
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        let shape = format!(
                            "reals party0 {:?} party{i} {:?}; block #{:?} body notes {} credit-carried {} header-root-empty {}; \
                             party0-only reals {:?}; party{i}-only reals {:?}; objects {:?}; party0 node {:p} party{i} node {:p}",
                            ra.as_ref().map(|r| r.len()),
                            rb.as_ref().map(|r| r.len()),
                            self.block_index_of_rid(rid),
                            blk.map_or(0, |bk| bk.output_notes.len() / w),
                            carried.len(),
                            blk.map_or(false, |bk| bk.header.output_notes_root == crate::hash::Hash32::hash(&[])),
                            extra,
                            missing,
                            objs,
                            &self.parties[0] as *const Node,
                            n as *const Node,
                        );
                        let at = a.iter().zip(b.iter()).position(|(x, y)| x != y).unwrap_or(a.len().min(b.len()));
                        let hex = |x: Option<&[u8; 32]>| {
                            x.map(|c| c[..6].iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap_or_else(|| "none".into())
                        };
                        return Err(format!(
                            "party {i} holds DIFFERENT bytes for record {rid} than party 0 — a cold peer \
                             that reads this record sees a different payment than the chain carried \
                             [slots {}/{} bytes {}/{}; first differing slot {at}: party0 {} party{i} {}; party0's slot \
                             {} in party{i}'s record; {shape}]",
                            a.len(),
                            b.len(),
                            mine.len(),
                            theirs.len(),
                            hex(a.get(at)),
                            hex(b.get(at)),
                            if a.get(at).is_some_and(|c| b.contains(c)) { "is ELSEWHERE" } else { "is ABSENT" },
                        ));
                    }
                    let their_targets = n.da_load_account_targets(rid);
                    if !their_targets.is_empty() && their_targets != my_targets {
                        return Err(format!(
                            "party {i} files record {rid} under DIFFERENT account targets than party 0 — \
                             the credit lands in a different bucket, i.e. nowhere its owner looks"
                        ));
                    }
                }
            }
        }
        // ⭐⭐⭐ THE ORDER BOOK — the half of I-CP that could never fire, and why it can now.
        //
        // ⛔ A RESTING ORDER IS A MAKER'S STANDING COMMITMENT TO TRADE A LOCKED LOT. If party 0 holds
        // one and party i does not — or i retired one that 0 still rests — the SAME lot can be filled
        // on both while each node self-verifies correctly. That is the shape MEASURED on 2026-09-03,
        // when a maker's lot paid out TWICE because the burn was local and never travelled.
        //
        // ⛔⛔⛔ THIS COMPARISON WAS ABSENT, AND IT COULD NOT HAVE BEEN ADDED BEFORE TODAY. The book was
        // replicated by epidemic re-flood alone: `/post_order` published a RAW `postcard(OrderWire)`,
        // which `chain_object::unframe` reads as None, so the `Class::OrderPost` apply seam never ran on
        // any node and a party fed only the blocks derived NO BOOK AT ALL. A comparison against nothing
        // would have fired for every honest party — vacuous in the other direction. Now the route frames
        // the offer as its class and the seam applies it on every node that grafts the block, so two
        // parties holding the same chain must hold the same book, and a difference is a real divergence.
        // ⭐⭐⭐ AND THE COLLATERAL-RATIO CENSUS — kill-list item 5, blind for the identical reason.
        //
        // ⛔ THE RATIO DECIDES HOW MUCH USDm MAY EXIST against a given deposit. `POST
        // /register_wrapped_asset` set it with no threshold, no vote and no block for months, and this
        // verdict could not object because it never COMPARED the number — a census that reads no field
        // is silent in exactly the way a clean chain is. The route now publishes a
        // `Class::WrappedAssetRegister` and the apply seam advances every node, so two parties on the
        // same chain must hold the same census and a difference is a node that wrote it locally.
        let my_ratios = self.parties[0].peg().collateral_ratio_census();
        for (i, n) in self.parties.iter().enumerate().skip(1) {
            if behind.contains(&i) {
                continue;
            }
            let theirs = n.peg().collateral_ratio_census();
            if theirs != my_ratios {
                return Err(format!(
                    "party {i} holds a DIFFERENT collateral ratio census than party 0 on the SAME \
                     chain — the ratio census decides how much USDm may be minted against a deposit, \
                     so a node standing on a locally-written number is measuring solvency against a \
                     figure the chain never set"
                ));
            }
        }
        // ⭐⭐⭐ THE SURFACES THE CENSUS COULD NOT SEE (closed 2026-09-24).
        //
        // ⛔⛔⛔ MEASURED, refutation suite: five arms panicked with *"THE … COMPARISON CANNOT FIRE …
        // Verdict: Ok(())"* — a party forced a divergence NO BLOCK PRODUCED and this verdict said the
        // mesh was clean. Blind on: the account commitment (where a recipient's money is INDEXED), the
        // nullifier set (what refuses a SECOND spend), the serve position, the letter accumulator and
        // the @username directory (which misdirects PAYMENTS, not just names).
        //
        // ROOT-LAYER: this verdict is the one place a chain-only replay is compared against what a node
        // HOLDS, so a surface it does not read is a surface nothing checks anywhere. The fix is not a
        // better assertion in the tests — it is reading the field.
        //
        // MEASURED: before → 6 of 14 refutation tests RED, each naming a comparison that cannot fire.
        // After → each forced divergence produces a verdict that names its surface.
        //
        // MUST-STAY-GREEN: the negative control every one of those tests opens with — an HONEST mesh
        // must still verdict `Ok(())`. A phantom here ends every campaign and buries the real finding,
        // which is why each comparison skips parties known to be `behind`.
        //
        // Each is one fixed-width read and one comparison per party: no walk, no growth.
        macro_rules! census_cmp {
            ($get:expr, $what:expr) => {{
                let mine = $get(&self.parties[0]);
                for (i, n) in self.parties.iter().enumerate().skip(1) {
                    if behind.contains(&i) {
                        continue;
                    }
                    if $get(n) != mine {
                        return Err(format!(
                            "party {i} holds a DIFFERENT {} than party 0 on the SAME chain — {}",
                            $what.0, $what.1
                        ));
                    }
                }
            }};
        }
        // ⛔⛔⛔ THE DAG COMES FIRST, BECAUSE IT IS THE CAUSE AND THE REST ARE ITS SYMPTOMS.
        //
        // MEASURED: with the accumulator comparisons added but no DAG comparison, a forced PRIVATE FORK
        // was reported as *"party 1 holds a DIFFERENT cover-conf accumulator"* — true, and useless. The
        // cover-conf accumulator is advanced FROM the blocks, so a party holding a block nobody else has
        // differs there as a CONSEQUENCE. Naming the consequence sends the reader to the wrong
        // subsystem; that misdirection is the single most expensive failure mode a detector has.
        //
        // `relay` is declared ChainDerived and the DAG IS the chain: a party holding a block a node fed
        // ONLY the blocks does not have can credit notes, admit spends and serve roots out of a block no
        // peer holds. That is the finding; everything downstream is how it shows up.
        {
            let (mine_len, mine_tip) = (self.parties[0].dag_len(), self.parties[0].selected_tip());
            for (i, n) in self.parties.iter().enumerate().skip(1) {
                if behind.contains(&i) {
                    continue;
                }
                if n.dag_len() != mine_len || n.selected_tip() != mine_tip {
                    return Err(format!(
                        "PRIVATE FORK — party {i} holds {} DAG block(s) against party 0's {mine_len} on \
                         the SAME chain (tips {:?} vs {mine_tip:?}). A block one party holds and a node \
                         fed ONLY the blocks does not is a chain nobody else replays: that party can \
                         credit notes, admit spends and serve roots out of it, and every accumulator \
                         difference below is a SYMPTOM of this, not a separate finding",
                        n.dag_len(),
                        n.selected_tip()
                    ));
                }
            }
        }
        census_cmp!(
            |n: &Node| n.account_acc_for_audit(),
            (
                "account commitment",
                "a recipient's notes are INDEXED against it, and a note nobody can locate is a note \
                 nobody can spend"
            )
        );
        census_cmp!(
            |n: &Node| n.nf_cover_conf_acc(),
            (
                "cover-conf accumulator",
                "it is advanced per block from the block's OWN blobs, so a difference means the two \
                 folded different spend sets"
            )
        );
        census_cmp!(
            |n: &Node| n.note_frontier_root(),
            (
                "note frontier",
                "every membership proof is built against this tree, so a holder proving against it is \
                 proving against a tree its peers do not have"
            )
        );
        census_cmp!(
            |n: &Node| n.da_records_held(),
            (
                "record space",
                "record COORDINATES decide where a payload is filed, and a payload filed off the \
                 chain's coordinates is one no peer can serve"
            )
        );
        // ⭐ THE PER-ORDINAL MEMBERSHIP COORDINATES — unblocked 2026-09-24 and added the same day.
        //
        // These sat in the authority manifest's held-back list for a stated MECHANICAL reason: *"they are
        // empty on every harness schedule, so the only way to build a violating state is to write a row
        // into the map directly — which O(1) guard class K denies. They need a driver that makes the CHAIN
        // populate them."* The driver turned out to be the FOLD DEPTH: they fill in
        // `da_store_membership_acc`, which runs when a record takes an ordinal, and every `Sim` party used
        // the production `record_fold_depth` (32), so a short schedule folded nothing. `new_folding_at_tip`
        // builds parties at depth 0 and they fill — MEASURED by
        // `a_tip_folding_schedule_populates_the_per_ordinal_maps_the_verdict_cannot_yet_compare`:
        // `da_macc_fwd_mem=12 da_macc_rev_mem=12 da_leafstart_mem=12`. The same blindness `live_leaves`
        // had, from the same cause.
        census_cmp!(
            |n: &Node| n.per_ordinal_coordinates_for_audit(),
            (
                "per-ordinal membership coordinate set",
                "a note's copath is built at its LEAF OFFSET, so a node filing a record at a different                  offset than its peers serves a copath that folds to a root nobody else has — the                  owner's spend then verifies NOWHERE and the payment settles on chain unspendable"
            )
        );
        census_cmp!(
            |n: &Node| n.nf_leaves_for_audit(),
            (
                "nullifier root",
                "this is what refuses a SECOND spend; two nodes disagreeing here disagree about what \
                 has ALREADY been spent, and one will admit a double spend the other refuses"
            )
        );
        census_cmp!(
            |n: &Node| n.mint_ratio_bps_for_audit(),
            (
                "chain parameters",
                "this is not a disagreement about STATE but about the RULES — every gate such a node \
                 runs is measured against the wrong yardstick and agrees with itself perfectly"
            )
        );
        census_cmp!(
            |n: &Node| n.membership_tip_root_for_audit(),
            (
                "membership tip",
                "it is what a holder's proof is ROOTED at, so a spend proven against it is refused by \
                 every peer standing on the chain's"
            )
        );
        census_cmp!(
            |n: &Node| (n.root_history_root(), n.root_history_count()),
            (
                "root-history anchor set",
                "a spend proves membership under an ANCHOR, so a party holding one the chain never \
                 committed accepts a spend no block justifies — and refuses the anchors its peers accept"
            )
        );
        census_cmp!(
            |n: &Node| n.served_membership_acc_for_audit(),
            (
                "membership tip (the SERVED prefix accumulator)",
                "a wallet folds what `/membership_roots` served and proves against the RESULT, so a \
                 party holding an accumulator the chain does not derive refuses the very proof its own \
                 stream taught the wallet to build — measured on a real cross-device send as \
                 MEMBERSHIP_PROOF_INVALID with nothing wrong on either side"
            )
        );
        census_cmp!(
            |n: &Node| n.l2_state_root(),
            (
                "L2 settlement root",
                "value SETTLES against it, so two nodes holding different roots have settled \
                 different amounts to different owners"
            )
        );
        census_cmp!(
            |n: &Node| n.served_seq(),
            (
                "served record position",
                "a wallet folds this stream, so a position the chain does not support names a spend \
                 endpoint no peer will honour — the measured shape of sends that stop working as a \
                 chain ages"
            )
        );
        census_cmp!(
            |n: &Node| n.finalized_height(),
            (
                "finalized height",
                "it is what this node treats as IRREVERSIBLE, so a node standing past the chain's \
                 will refuse to reorg onto the chain everyone else is on"
            )
        );
        // `da_top` / `da_base` LEFT this comparison 2026-10-04: record addresses are `Dag::record_key(block_id)` — a
        // 56-bit fold of the block ID, not a chain position — so the max and min this node WROTE are a function of WHICH
        // records it holds. A DSYNC joiner holds no pre-anchor record by design (the O(1) jump), so its extremes differ
        // from the origin's whenever the extreme key sits in a pre-anchor record, with nothing outstanding to heal.
        // MEASURED: d47 / d49 / d50 (`Produce · Jump`) failed I-CP on exactly this surface and no other. They are
        // this node's own cursors (`Authority::LocalCache`), not the chain's.
        census_cmp!(
            |n: &Node| n.nf_fold_seq(),
            (
                "absence-fold position (`nf_fold_seq`)",
                "it advances EXACTLY with `nf_unspent_acc` and KEYS the fold sidecar, so a party off \
                 by even one files every served fold row under a different block than the one it \
                 describes — a spender folding that stream can never reproduce A_tip and its money \
                 will not move"
            )
        );
        census_cmp!(
            |n: &Node| n.letter_acc(),
            (
                "letter accumulator",
                "message history that is not a function of the chain means two nodes serve different \
                 content under the SAME anchor"
            )
        );
        census_cmp!(
            |n: &Node| n.dir_acc(),
            (
                "directory accumulator",
                "`#64 Pay @username` sends to whoever the directory resolves, so a directory the chain \
                 did not set sends a user's money to the wrong owner — with every node individually \
                 correct"
            )
        );
        census_cmp!(
            |n: &Node| n.unbonding_census(),
            (
                "unbonding collateral set",
                "the fold releases each entry's locked note when its window ends, so an entry one node holds \
                 and another does not returns a note on one node only — spendable there, locked everywhere else"
            )
        );
        // ⭐ DB-402 R1: the book by CONTENT, not by count. A COUNT passed DB-401 — every peer held the same number of offers,
        // each one HOLLOW (the maker's membership bind dropped by the wire), so every fill through a peer was refused. The
        // digest covers every byte an offer's `Debug` prints (terms, maker half, bind, payout), order-insensitive.
        let (mine, mine_len) = (self.parties[0].order_book_digest_for_audit(), self.parties[0].order_book_len_for_audit());
        for (i, n) in self.parties.iter().enumerate().skip(1) {
            if behind.contains(&i) {
                continue;
            }
            let (theirs, theirs_len) = (n.order_book_digest_for_audit(), n.order_book_len_for_audit());
            if theirs.0 != mine.0 {
                return Err(format!(
                    "party {i} holds a DIFFERENT order book than party 0 on the SAME chain ({theirs_len} vs {mine_len} \
                     resting order(s); content {} B vs {} B) — a resting order alive on one node and absent on another \
                     lets the same maker's lot be filled twice while both nodes self-verify correctly (the 2026-09-03 \
                     shape), and an offer held HOLLOW on a peer can never settle there (DB-401). The ORDER BOOK is where \
                     to look, not the unspent set.",
                    theirs.1, mine.1
                ));
            }
        }
        Ok(())
    }

    pub fn cold_peer_verdict(&self) -> Result<(), String> {
        self.cold_peer_verdict_excluding(&[])
    }

    /// The cold-peer verdict with the per-party comparisons skipped for `behind` — parties the engine
    /// knows are still short of blocks they lost to a drop (D-48): every derived field of a behind node
    /// legitimately trails the chain's, and the schedule that ends there is reported
    /// `convergence_unassertable`, never as a derivation finding it cannot be. Party 0 is the replay's
    /// reference for every chain-wide comparison, so a short party 0 skips the whole verdict.
    pub fn cold_peer_verdict_excluding(&self, behind: &[usize]) -> Result<(), String> {
        self.cold_peer_verdict_excluding_gated(behind, false)
    }

    /// [`Self::cold_peer_verdict_excluding`], told whether the END-OF-RUN closure assertions will run.
    ///
    /// `closure_is_asserted` must be the engine's own `!unrepaired(&dropped)` — the exact condition that
    /// decides whether `Sim::verdict` (and with it *"still misses N record(s) once everything is
    /// delivered"*) is reached. Passing `true` when it is not would grant the backfill exemption with no
    /// check behind it.
    pub fn cold_peer_verdict_excluding_gated(
        &self,
        behind: &[usize],
        closure_is_asserted: bool,
    ) -> Result<(), String> {
        // ⭐ EVERY I-CP FINDING SAYS WHICH OF ITS TWO CAUSES IT IS. Without this the finding text is the
        // same whether the party was mid-backfill (expected, self-healing) or holding every record and
        // still unable to derive the chain's state (the real defect) — and §CG ranked the whole class
        // as live fund loss on exactly that ambiguity.
        let gap = self.parties[0].missing_record_count();
        let sidecar_gap = self.parties[0].sidecar_gap_count();
        match self.cold_peer_verdict_inner(behind, closure_is_asserted) {
            Ok(()) => Ok(()),
            // ⛔ THE CONTEXT GOES FIRST. The engine TRUNCATES a finding's detail at ~200 chars, so an
            // appended diagnosis is cut off exactly when it is needed — measured: the context was added,
            // the run reproduced the three findings, and not one character of it survived into the
            // assertion. Lead with the discriminator; the prose that was already there can be the part
            // that gets clipped.
            Err(why) => Err(format!(
                "[party0 missing_records={gap} sidecar_gap={sidecar_gap} \
                 closure_asserted={closure_is_asserted} ⇒ {}] {why}",
                if gap == 0 && sidecar_gap == 0 {
                    "⛔ THIS IS THE REAL SHAPE: the party holds every record and every sidecar and STILL                      does not derive what the chain does. Nothing is outstanding, so nothing will heal it."
                } else if !closure_is_asserted {
                    "the party is mid-backfill AND the end-of-run closure assertions do not run on this                      schedule (an unrepaired drop), so this weaker check is deliberately still applied"
                } else {
                    "⛔ the party is mid-backfill and the exemption should have applied — if this fires,                      the exemption's condition and this context disagree and one of them is wrong"
                }
            )),
        }
    }

    /// The real note commitments this schedule created — the set the carriage counter is asked about.
    /// A pin needs this to prove the counter is not blind; nothing else reads it.
    pub fn real_note_cms_for_test(&self) -> Vec<[u8; 32]> {
        self.real_notes.iter().map(|(cm, _)| *cm).collect()
    }

    pub fn carriage_verdict(&self) -> Result<(), String> {
        for (idx, party) in self.parties.iter().enumerate() {
            for (cm, spent) in self.real_notes.iter() {
                let carried = party.da_carriage_count(cm);
                if carried > 1 {
                    return Err(format!(
                        "party {idx}: a real note is carried by {carried} DISTINCT records (spent={spent}).                          One note, two records, two independent membership proofs — money received once                          that can be proven twice. This is NOT a conservation failure: each carriage can                          be individually legitimate and every amount can balance, which is exactly how                          the 2026-09-03 DEX fill paid a maker's lot out twice. Find the second WRITER                          and make the record path idempotent on the commitment."
                    ));
                }
            }
        }
        Ok(())
    }

    /// How much hostile payload `forge_rows` would actually carry right now: `(unspent_cms,
    /// spent_cms)` available from `real_notes`.
    ///
    /// ⛔ A NON-VACUITY HANDLE, not a convenience. `forge_rows` draws its `del` from an UNSPENT real
    /// note and its `recv` from a SPENT one; if either set is empty the corresponding payload is empty
    /// and that half of the attack was never armed — a pin asserting "the door held" would then be
    /// asserting nothing at all, which is precisely the shape of a cheating test. Any pin driving this
    /// op must check here that the attack it claims to make was actually loaded.
    pub(crate) fn hostile_payload_available_for_test(&self) -> (usize, usize) {
        let unspent = self.real_notes.iter().filter(|(_, spent)| !*spent).count();
        let spent = self.real_notes.iter().filter(|(_, spent)| *spent).count();
        (unspent, spent)
    }

    fn forge_rows(&mut self, i: usize) -> Result<(), String> {
        if i >= self.parties.len() {
            return Ok(());
        }
        let before = self.parties[i].ordinal_rows_for_test();
        let forged: Vec<(u64, u64)> = before
            .iter()
            .map(|(o, _)| (*o, u64::from_le_bytes(Hash32::hash(format!("forged-{o}").as_bytes()).as_bytes()[..8].try_into().unwrap())))
            .collect();
        // ⛔⛔⛔ THE PAYLOAD THAT WAS ALWAYS EMPTY (calibration rows C-H2 / C-H3 / E-3).
        //
        // This op forged only `(ordinal, record_id)` pairs and handed `adopt_sidecar_row` two EMPTY
        // slices — aiming the hostile action at the one relation that door actually checks, while the
        // two arguments carrying the whole attack surface were hard-coded away. Three calibration rows
        // were unreachable for that single reason, each with a CORRECT oracle already written and
        // waiting. The payloads below are what a real hostile peer page carries:
        //
        //   `del`  — a commitment the victim GENUINELY HOLDS and has not spent. If the fold absorbs a
        //            deletion nobody proved, the note leaves the unspent set with no chain-recorded
        //            spend, which is `I-8 CUSTODY-NOTE-DESTROYED` (row C-H3) — a peer deleting another
        //            party's money on its say-so.
        //   `recv` — a commitment already SPENT. If the fold absorbs it, a spent note is back in the
        //            unspent set, which is `I-1/I-2 SPENT-NOTE-RESURRECTED` (row E-3), and the recv
        //            bytes reaching the fold sink at all is row C-H2.
        //
        // Both are drawn from `real_notes`, the schedule's own record of what was really received and
        // really spent — so the attack names REAL value this mesh holds, never an invented commitment
        // the door could dismiss for free. If `real_notes` is empty the op degrades to exactly its old
        // behaviour (empty payloads), so a schedule with no real notes yet is unchanged.
        let del: Vec<u8> = self
            .real_notes
            .iter()
            .find(|(_, spent)| !*spent)
            .map(|(cm, _)| cm.to_vec())
            .unwrap_or_default();
        // `recv` carries TWO commitments, because the two rows riding it are different attacks:
        //   * an INVENTED commitment nobody ever sent — if the fold absorbs it the victim's unspent set
        //     gains a note out of nothing, which is inflation, and it is row C-H2's "recv bytes reach
        //     the fold sink". Always available, so this half is armed on every schedule.
        //   * a SPENT commitment, when one exists — if the fold absorbs THAT, a spent note is back in
        //     the unspent set (row E-3, `I-1/I-2 SPENT-NOTE-RESURRECTED`).
        // Concatenated because the sidecar payload is a run of 32-byte commitments; the door parses
        // both or neither.
        let stale_before = self.parties[i].spine_stale_for_test();
        self.parties[i].adopt_rows_with_sidecars_for_test(&forged);
        let after = self.parties[i].ordinal_rows_for_test();
        if after != before {
            return Err(format!("party {i}: forged page rows displaced {} of its claims", before.iter().zip(after.iter()).filter(|(a, b)| a != b).count()));
        }
        if self.parties[i].spine_stale_for_test() && !stale_before {
            return Err(format!("party {i}: forged page rows made it stale — a page is never certified evidence"));
        }
        Ok(())
    }

    /// `i` gossips a block with the wrong work: every party must reject it and keep its DAG unchanged.
    fn invalid(&mut self, i: usize) -> Result<(), String> {
        if i >= self.parties.len() {
            return Ok(());
        }
        self.now += self.parties[0].params().target_spacing_ms;
        let now = self.now;
        let Some(mut blk) = self.parties[i].produce(now, Hash32::hash(b"invalid-frontier"), Hash32::hash(b"miner")) else {
            return Ok(());
        };
        // the block the honest party just grafted is real; the one we forge from it is not
        for j in 0..self.parties.len() {
            if j != i {
                self.owed.push((j, blk.clone()));
            }
        }
        self.blocks.push(blk.clone());
        blk.header.work = blk.header.work.saturating_mul(8).saturating_add(1);
        for j in 0..self.parties.len() {
            let tips_before = self.parties[j].dag().tips();
            let out = self.parties[j].ingest_block(blk.clone(), now + 1);
            if matches!(out, RelayOutcome::Added(_)) || self.parties[j].dag().tips() != tips_before {
                return Err(format!("party {j} ACCEPTED a block with forged work from party {i}: {out:?}"));
            }
        }
        Ok(())
    }

    /// `i` is re-sent the bundle it last adopted from `j`: nothing may move.
    fn replay(&mut self, i: usize, j: usize) -> Result<(), String> {
        if i == j || i >= self.parties.len() || j >= self.parties.len() {
            return Ok(());
        }
        let Some(bundle) = self.last_adopted[i].clone() else { return Ok(()) };
        let before = self.state_digest(i);
        let out = self.parties[i].instant_sync(bundle);
        let after = self.state_digest(i);
        if matches!(out, AdoptOutcome::Adopted(_)) && before != after {
            return Err(format!("party {i}: a REPLAYED bundle moved its state ({out:?})"));
        }
        Ok(())
    }

    fn restart(&mut self, i: usize) {
        if i >= self.parties.len() {
            return;
        }
        // ⭐ G1h — A RESTART IS THE PRODUCTION RESTART: the process writes its shutdown checkpoint (snapshot + fold
        // record) into the party's own datadir, the process is GONE (its `Node` dropped before any file is re-opened),
        // and the next process boots in the same directory through the ONE resume (`scenario_node_resumed_in_at_depth`).
        // Before, this was `clear_checkpoint` + `restore_snapshot`: a snapshot-only restore that never restored the band
        // door, so the restarted party could never warm its view nor decide a spend (cases 05 and 12 RED). The
        // checkpoint IS exercised here — the fresh node holds nothing it did not read from the file.
        self.parties[i].persist_blocking();
        drop(self.parties.remove(i));
        let Some(mut fresh) = scenario_node_resumed_in_at_depth(&self.dirs[i], self.fold_depth) else {
            // A checkpoint that does not resume is a refused boot (the daemon exits 97): said, never papered over.
            eprintln!("[scenario] ⛔ party {i}: its shutdown checkpoint did not resume — the party is GONE for the run");
            self.parties.insert(i, scenario_node_in_at_depth(&self.dirs[i], self.fold_depth));
            return;
        };
        // ⭐ §CE — RE-PIN THE PARTY'S SECRET ACROSS THE RESTART, or the reproducer stops reproducing.
        //
        // `miner_seed` is NOT persisted (it appears nowhere in `persist.rs`), so a restarted node draws a
        // fresh one and therefore fresh nullifier decoys. On chain that is harmless — every block carries
        // its own tags and no path re-derives a past block's. In a REPLAY lane it is fatal: MEASURED as
        // `D-37 HAS ESCALATED` with every field identical except `nf_acc`/`nf_root`, and the per-fold trace
        // put the first divergence at exactly the schedule's first Restart.
        //
        // A reproducer must control the node's secrets as well as its ops, so the same derivation
        // `Sim::new` used is re-applied here. Production is untouched: there is no production caller.
        fresh.set_miner_seed_for_test(Self::party_miner_seed(self.seed, i));
        self.parties.insert(i, fresh);
    }

    fn jump(&mut self, i: usize, j: usize) {
        if i == j || i >= self.parties.len() || j >= self.parties.len() {
            return;
        }
        // ⛔ A FIXTURE NEVER FALLS BEHIND THE DOOR (census S-DRAFT-ADOPT, 2026-11-26): a scheduled jump takes the bundle the source
        // node SERVES (`serve_join_bundle`: its frozen bundles, each checked by the joiner's own door before it is served), never a
        // draft beside the serve path. From 11/10 the door refused every draft `AnchorArray`, so every scheduled jump was a silent
        // no-op and the two schedule fuzzers reported parties on different tips. A source that cannot serve yet (no frozen bundle
        // with its 32 vouchers) offers no jump, exactly as a real joiner finds no bundle to take.
        let bundle = match self.parties[j].serve_join_bundle().and_then(|w| crate::sync::SyncBundle::from_wire(&w)) {
            Some(b) => b,
            None => return,
        };
        let keep = bundle.clone();
        if matches!(self.parties[i].instant_sync(bundle), AdoptOutcome::Adopted(_)) {
            self.last_adopted[i] = Some(keep);
        }
    }

    pub fn step(&mut self, a: Act) {
        let _ = self.step_checked(a);
    }

    /// Run one action; the adversarial ones carry their own verdict (a refusal that did not happen).
    pub fn step_checked(&mut self, a: Act) -> Result<(), String> {
        self.trace.push(a.clone());
        match a {
            Act::Produce(i, n) => {
                for _ in 0..n {
                    self.produce_one(i);
                }
                Ok(())
            }
            Act::Deliver(k) => {
                self.deliver(k);
                Ok(())
            }
            Act::Drain => {
                self.drain();
                Ok(())
            }
            Act::Restart(i) => {
                self.restart(i);
                Ok(())
            }
            Act::Jump(i, j) => {
                self.jump(i, j);
                Ok(())
            }
            Act::Burst(k) => {
                self.burst(k);
                Ok(())
            }
            Act::Drop(i) => {
                self.drop_one(i);
                Ok(())
            }
            Act::Receive(i) => {
                self.receive(i);
                Ok(())
            }
            Act::Forget(i) => {
                self.forget(i);
                Ok(())
            }
            Act::Tamper(i, j) => self.tamper(i, j),
            Act::ForgeRows(i) => self.forge_rows(i),
            Act::Invalid(i) => self.invalid(i),
            Act::Replay(i, j) => self.replay(i, j),
            Act::Spend(i) => self.spend(i),
        }
    }

    /// No honest block was ever refused by an honest party: a refusal is a consensus split (the restart
    /// search found `WrongWork` after a checkpoint resume this way).
    pub fn no_honest_refusal(&self) -> Result<(), String> {
        if let Some((to, id, why)) = self.honest_refusals.first() {
            return Err(format!(
                "party {to} REFUSED honest block {} ({why}) — {} refusal(s) in all",
                &id.to_hex()[..8],
                self.honest_refusals.len()
            ));
        }
        Ok(())
    }

    /// Every REAL-note record is held, byte for byte, by every party, at the same ordinal — the
    /// sole-holder hazard the roll gate names ("killing node2 now would strand sole-holder records").
    pub fn real_records_everywhere(&self) -> Result<(), String> {
        for seq in &self.real_records {
            let bytes0 = self.parties[0].da_record_notes(*seq);
            let ord0 = self.parties[0].da_record_ordinal(*seq);
            if bytes0.is_none() {
                // every party's view of the record, so the red names which side lost it and how far each one got
                let views: Vec<String> = self
                    .parties
                    .iter()
                    .enumerate()
                    .map(|(i, n)| {
                        format!(
                            "p{i}: block {:?} held {} ord {:?} wanted {} tip-ord {} missing {}",
                            n.block_for_record_addr(*seq).map(|b| b.to_hex()[..8].to_string()),
                            n.da_record_notes(*seq).is_some(),
                            n.da_record_ordinal(*seq),
                            n.record_is_wanted(*seq),
                            n.da_record_ordinal_top(),
                            n.missing_record_count()
                        )
                    })
                    .collect();
                return Err(format!("party 0 does not hold real record {seq} [{}]", views.join(" · ")));
            }
            for (i, n) in self.parties.iter().enumerate().skip(1) {
                if n.da_record_notes(*seq) != bytes0 {
                    return Err(format!("party {i} holds different bytes (or none) for real record {seq}"));
                }
                if n.da_record_ordinal(*seq) != ord0 {
                    return Err(format!("party {i} files real record {seq} at a different ordinal"));
                }
            }
        }
        Ok(())
    }

    /// ⭐⭐⭐ DIGITAL CASH AT THE NODE LAYER, IN THE ZCASH SHAPE (Z1).
    ///
    /// ⛔ THIS ASSERTION USED TO STATE THE RETIRED LAW, AND IT IS WORTH SAYING WHY. It read a note's
    /// presence as its record's existence and demanded that presence be the OPPOSITE of spent — i.e. it
    /// demanded that spending a note DELETE the record carrying it. That was the deletion model's law.
    /// Under the shape this chain now runs, a spent note's commitment stays in the append-only frontier
    /// forever and its record must stay findable; what changes is that a NULLIFIER becomes spent. Ten of
    /// twelve recorded schedules passed it only because no spend landed in them, so it read green for the
    /// wrong reason — the vacuity class this tree keeps a census for.
    ///
    /// The three laws that replace it, each one a way real money is lost if it breaks:
    ///   1. FINDABILITY — every real note's record is held by every party, spent or not. A note whose
    ///      record vanished is unspendable by its owner however correct the nullifier lane is.
    ///   2. NO DOUBLE SPEND — every nullifier the schedule published reads SPENT on every party. A party
    ///      that reads one as unspent will admit that note a second time.
    ///   3. NO FALSE POSITIVE — a nullifier the chain never published reads UNSPENT on every party. This
    ///      is the refutation half; without it laws 1 and 2 are satisfied by a lane that answers SPENT to
    ///      everything, which would refuse every honest owner their own money.
    pub fn spend_verdicts_everywhere(&self) -> Result<(), String> {
        use crate::nf_sparse::SpentVerdict;
        for (i, party) in self.parties.iter().enumerate() {
            // 1 — findability.
            for (k, (spent, findable)) in self.note_verdicts(i).iter().enumerate() {
                if *findable != Some(true) {
                    return Err(format!(
                        "party {i} cannot find real note #{k}'s record once everything is delivered \
                         (the schedule {} it; a spent note's record must survive, and an unspent note's \
                         record is its owner's only way to spend)",
                        if *spent { "spent" } else { "never spent" }
                    ));
                }
            }
            // 2a — NO DOUBLE SPEND. This is the money law, and it is about the verdict `Unspent`, not
            // about the verdict `Spent`. A party that reads a published nullifier as UNSPENT will admit
            // that note a second time. A party that reads it as UNPROVABLE refuses to answer, which is
            // the honest verdict of a node holding only roots and costs nobody their money:
            // `SpentVerdict::Unprovable` says so in its own doc, and the admission authority is the
            // recursive absence carrier, not this lane (`tx_nullifiers_absent_by_fold` — the copaths are
            // corroboration, and a spend carries them all or carries none).
            for (k, nf) in self.spent_nullifiers.iter().enumerate() {
                if party.sparse_spent_verdict(nf) == SpentVerdict::Unspent {
                    return Err(format!(
                        "party {i} reads published nullifier #{k} as Unspent — this party would admit \
                         that note a second time"
                    ));
                }
            }
            // 2b — AND A HOLDER MUST ACTUALLY ANSWER. Law 2a alone is satisfied by a node that answers
            // Unprovable to everything, so it cannot see the drift class (DB-149: the local Merkle view
            // falling behind the accumulator it is supposed to describe). A party that HOLDS the shard
            // for a nullifier has the leaves to answer and must say Spent; Unprovable from a holder means
            // its copath source no longer describes its own accumulator.
            for (k, nf) in self.spent_nullifiers.iter().enumerate() {
                if party.holds_nf_shard(nf) {
                    let v = party.sparse_spent_verdict(nf);
                    if v != SpentVerdict::Spent {
                        return Err(format!(
                            "party {i} HOLDS the shard for published nullifier #{k} and still reads it \
                             as {v:?} — its copath source has drifted from its own accumulator"
                        ));
                    }
                }
            }
            // 3 — no false positive (the refutation half).
            for (k, probe) in Self::unpublished_nullifier_probes().iter().enumerate() {
                if party.sparse_spent_verdict(probe) == SpentVerdict::Spent {
                    return Err(format!(
                        "party {i} reads never-published nullifier probe #{k} as Spent — the lane \
                         answers Spent to everything and would refuse honest owners their own money"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Nullifiers no schedule can ever publish — the control for law 3 above. Derived from a fixed
    /// domain-separated label, never from chain state, so a probe cannot collide with a real spend.
    fn unpublished_nullifier_probes() -> [[u8; 32]; 2] {
        [
            *crate::hash::Hash32::hash(b"consensus-scenarios/never-published-nullifier/0").as_bytes(),
            *crate::hash::Hash32::hash(b"consensus-scenarios/never-published-nullifier/1").as_bytes(),
        ]
    }

    /// The carry every party would ship is bounded by the fold depth and the DAG's width — the O(1)
    /// axis a checkpoint and a bundle must keep whatever the schedule did.
    pub fn bounded_carry(&self) -> Result<(), String> {
        let depth = self.parties[0].params().record_fold_depth as usize;
        let width = self.parties.len();
        let bound = (depth + 1) * width * 2 + 8;
        for (i, n) in self.parties.iter().enumerate() {
            let carry = n.unfolded_carry();
            if carry.unfolded.len() > bound {
                return Err(format!(
                    "party {i} carries {} unfolded block(s) — more than depth {depth} × width {width} allows ({bound})",
                    carry.unfolded.len()
                ));
            }
        }
        Ok(())
    }

    /// Every party must still hold the genesis record at ordinal 0 — the class gate 45 found, where an
    /// adopt evicted it and every roots run was holed at 0 forever after.
    pub fn genesis_row_intact(&self) -> Result<(), String> {
        for (i, n) in self.parties.iter().enumerate() {
            if n.da_addr_at_ordinal(0).is_none() {
                return Err(format!("party {i} has no record at ordinal 0 — the genesis row was evicted"));
            }
        }
        Ok(())
    }
}

/// Run one case to completion and check the property. Returns the failure reason, or `Ok`.
pub(crate) fn run(scenario: &Scenario) -> Result<(), String> {
    let mut sim = Sim::new(scenario.parties, 0x5EED_5EED_5EED_5EED);
    for a in &scenario.script {
        sim.step_checked(a.clone())?;
    }
    sim.drain();
    sim.verdict()
}

impl Sim {
    /// EVERY property, in the order a failure is most legible: honest refusals first (a split nobody can
    /// recover from), then agreement, then readiness, then the real records, then the bounds.
    pub fn verdict(&self) -> Result<(), String> {
        self.no_honest_refusal()?;
        self.agreement()?;
        self.genesis_row_intact()?;
        self.all_ready()?;
        self.real_records_everywhere()?;
        self.spend_verdicts_everywhere()?;
        self.bounded_carry()
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, run, scenario_node_resumed_in_at_depth, CASES};

    /// ⭐⭐⭐ THE SUITE. Every case is a class a gate run found the expensive way. They run in seconds and
    /// they run on every build, so no class can return silently. A failure names the case.
    #[test]
    fn every_recorded_consensus_class_still_holds() {
        let cases = parse(CASES).expect("the case library parses");
        assert!(cases.len() >= 8, "the library should carry every class we have paid for, got {}", cases.len());
        let mut failed: Vec<String> = Vec::new();
        for c in &cases {
            if let Err(why) = run(c) {
                failed.push(format!("  {}: {why}", c.name));
            }
        }
        assert!(
            failed.is_empty(),
            "{} of {} consensus scenarios FAILED:\n{}",
            failed.len(),
            cases.len(),
            failed.join("\n")
        );
    }

    /// A case file that does not parse is a coverage lie — every line must be understood or refused.
    #[test]
    fn a_malformed_case_is_refused_rather_than_silently_skipped() {
        assert!(parse("name x\nwiggle 3\n").is_err(), "an unknown action must be an error");
        assert!(parse("produce 0 1\n").is_err(), "an action before any name must be an error");
        assert!(parse("# only a comment\n").is_err(), "an empty library must be an error");
    }

    /// ⭐⭐⭐ THE DISK THE HARNESS OWNS IS f(PARTIES), NOT f(RUNS) — the pin that keeps the 18 GB from
    /// coming back.
    ///
    /// This is the class, not a tidiness check. Every party of every `Sim` is a PERSISTING node, so it is
    /// a real directory holding a real `state.snap`; before 2026-09-08 nothing removed one and a single
    /// campaign left 11,161 of them behind, on a volume that was 98% full. The shrinker multiplies it —
    /// `SHRINK_MAX_CANDIDATES` × `MAX_PARTIES` = 9,216 directories for ONE find — so an instrument that
    /// leaks here can take the machine down while looking perfectly green.
    ///
    /// The two properties that bound it are asserted directly, against the FILESYSTEM rather than against
    /// a counter that could agree with a broken implementation:
    ///  * three `Sim`s, each restarted, allocate exactly `3 × parties` live directories — a `Restart`
    ///    REUSES its party's directory, it does not mint one;
    ///  * dropping them takes the directory count back to where it started, leaving nothing behind.
    #[test]
    fn the_scenario_harness_owns_a_datadir_per_party_and_gives_every_one_of_them_back() {
        use crate::consensus_scenarios::{Act, Sim};
        use std::collections::BTreeSet;

        const PARTIES: usize = 3;
        const RUNS: usize = 3;

        let mut sims: Vec<Sim> = Vec::new();
        for r in 0..RUNS {
            let mut sim = Sim::new(PARTIES, 0xD15C_0000_0000_0001 ^ r as u64);
            sim.step(Act::Produce(0, 1));
            sim.drain();
            // The op that used to allocate. Twice, so "a Restart reuses its party's directory" is a
            // property rather than an off-by-one that happens to hold once.
            sim.step(Act::Restart(0));
            sim.step(Act::Restart(1));
            sim.drain();
            assert_eq!(
                sim.dirs.len(),
                PARTIES,
                "a {}-party sim must hold exactly {} datadirs after two restarts — more means a Restart \
                 minted one instead of reusing its party's",
                PARTIES,
                PARTIES
            );
            sims.push(sim);
        }

        // ⛔ ASSERT ON THE DIRECTORIES THESE RUNS OWN, BY NAME — never on a `read_dir` count of the shared
        // per-process parent. Tests in this binary run in parallel and allocate datadirs of their own, so
        // a count would be a PARALLELISM FLAKE dressed as a fund-safety pin, and this tree has already
        // lost a day to reds of exactly that kind.
        let owned: BTreeSet<std::path::PathBuf> =
            sims.iter().flat_map(|s| s.dirs.iter().map(|d| d.path().to_path_buf())).collect();
        assert_eq!(
            owned.len(),
            RUNS * PARTIES,
            "{} sims of {} parties must own exactly {} DISTINCT datadirs",
            RUNS,
            PARTIES,
            RUNS * PARTIES
        );
        for path in &owned {
            assert!(path.is_dir(), "a live party's datadir must exist on disk: {}", path.display());
        }
        // Reusing directories must not have cost the parties their persistence: a checkpoint on disk is
        // what makes a restart a restart, so an empty subtree here would mean the pin above was bought by
        // breaking the thing the cases actually prove.
        // Checkpoints land on a background thread (`Node::autosave`): wait for every party's own in-flight
        // gate to clear before reading the directories.
        for sim in &sims {
            while sim.parties.iter().any(|p| p.checkpoint_in_flight_for_test()) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        assert!(
            owned.iter().any(|p| p.join("state.snap").exists()),
            "reusing datadirs must not have stopped the parties from checkpointing"
        );

        drop(sims);
        for path in &owned {
            assert!(
                !path.exists(),
                "dropping the Sim must give the datadir back: {} is still there, which is the 11,161-\
                 directory leak returning",
                path.display()
            );
        }
    }

    /// A `Restart` reuses the party's DIRECTORY and never its CHECKPOINT.
    ///
    /// ⛔ THIS IS THE ONE THAT COULD HAVE BEEN GUTTED SILENTLY. `Node::enable_persist` restores from disk
    /// as it is called, so if the reused directory still held the previous incarnation's auto-saved
    /// `state.snap`, the "fresh" node would boot ALREADY carrying the state and `restore_snapshot` would
    /// be asserted against a node that no longer needed it — the fuzz oracle's I-8 RESTART FUND SAFETY pin
    /// (unspent set and root byte-identical across a restart) would go green without the checkpoint ever
    /// being exercised. The assertion is therefore on the SEAM, not on the outcome: after
    /// `clear_checkpoint`, a node built in that directory is at genesis.
    #[test]
    fn a_restart_reuses_the_directory_and_resumes_the_checkpoint_its_process_left_in_it() {
        use crate::consensus_scenarios::{scenario_node_in, ScenarioDataDir};
        use crate::hash::Hash32;

        let dir = ScenarioDataDir::new();
        let mut party = scenario_node_in(&dir);
        // The same production door `Sim::produce_one` uses — a real block, really committed, really
        // checkpointed, because a restart of an empty node proves nothing about restarts.
        let mut now = party
            .dag()
            .get(&party.selected_tip().expect("tip"))
            .expect("header")
            .header
            .timestamp;
        for k in 0..2u64 {
            now += party.params().target_spacing_ms;
            let tag = format!("datadir-pin-{k}");
            assert!(
                party.produce(now, Hash32::hash(tag.as_bytes()), Hash32::hash(b"miner")).is_some(),
                "the party must produce block {k}"
            );
        }
        let grown = party.dag().len();
        assert!(grown > 1, "the party must actually have moved off genesis, got dag_len {grown}");
        // Checkpoints land on a background writer — `Node::autosave`, on its own cadence — so wait for the
        // party's in-flight flag to clear first. MEASURED 2026-09-20: asserted the instant `produce` returned,
        // this test and its sibling went red while other scenario tests in the same process were saving —
        // a harness race, not a node defect; both pass alone in 11 s.
        while party.checkpoint_in_flight_for_test() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(dir.snapshot_path().exists(), "a persisting party files a checkpoint");
        // What `Sim::restart` does, in the open (G1h): the process writes its shutdown checkpoint and is gone; the
        // next process in the same directory resumes from the file — the fold record included — and nothing else.
        party.persist_blocking();
        drop(party);
        let fresh = scenario_node_resumed_in_at_depth(&dir, crate::params::RECORD_FOLD_DEPTH_DEFAULT)
            .expect("the shutdown checkpoint must resume");
        assert_eq!(
            fresh.dag().len(),
            grown,
            "the restored node must hold what the stopped one did, reached ONLY through the checkpoint"
        );
        drop(fresh);

        // A CLEARED directory boots at genesis: the resume above carried the state, not the directory.
        dir.clear_checkpoint();
        assert!(!dir.snapshot_path().exists(), "clear_checkpoint must actually remove the file");
        assert!(
            scenario_node_resumed_in_at_depth(&dir, crate::params::RECORD_FOLD_DEPTH_DEFAULT).is_none(),
            "a node built in a CLEARED directory resumes nothing"
        );
        let fresh = scenario_node_in(&dir);
        assert_eq!(
            fresh.dag().len(),
            1,
            "a node built in a CLEARED directory must be at genesis — if it boots carrying the old state, \
             every restart pin in this tree passes without the checkpoint being exercised at all"
        );
    }














}

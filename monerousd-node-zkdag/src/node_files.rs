// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — THE ONE NAME OF EVERY PER-NODE FILE (DB-341): the state directory and the port this process serves, which
//! the validator's vote key, the custody books, the reward file, the snapshot and every sibling file are named through.
//! Moved here from `persist` byte for byte by the node split (lane dcash 2026-11-11): the validator's key path is read by ledger
//! modules (`bridge`, `satoshi`, `validator`), so its directory lives below the node; `persist` re-exports every item, so every
//! `crate::persist::state_dir()` caller is unchanged and there is still exactly one definition.
//! SCALE: one `u16` and one directory name per process — no term in the bonded set, the items in flight or height.
//! AI RESISTANCE: (b) ordinary code — a path formula; it moves no value. A second formula is refused by the DB-341 census
//! (`persist::tests::db341_every_per_node_file_is_named_through_the_one_state_dir`), which now names this file as the one home.

use std::path::PathBuf;

/// The node's default loopback RPC port (re-exported as `rpc::RPC_DEFAULT_PORT`): the port [`serving_port`] falls back to.
/// Default loopback RPC port.
pub const RPC_DEFAULT_PORT: u16 = 27780;

/// The ONE base every piece of this node's on-disk state hangs from. `MONEROUSD_STATE_DIR` when set —
/// the same contract the arti (Tor) state dir already honours in `serve.rs` — else `$HOME`.
///
/// ⛔ MEASURED 2026-09-20: the snapshot and the peer/seed files ignored that variable while the arti dir
/// honoured it, so a wallet TEST's in-process node (port 27789) wrote `state-27789.snap` into the operator's
/// live `~/.usdmd-node` on 2026-08-26; twenty-five days and a hash retirement later every current binary
/// correctly REFUSED to decode it, and `live_restore_tests::the_wallet_derives_a_copath_over_real_http_with_
/// no_note_stream` failed at "the live node bound its RPC and produced blocks" — the node never started. A
/// process that wants isolated state now has one variable to set; a daemon that sets nothing is unchanged.
///
/// ⛔ DB-406 — A TEST PROCESS NEVER RESOLVES TO THE OPERATOR'S LIVE HOME. MEASURED 2026-10-07: the journey simulator's T3
/// bond posted `/provision_validator` to an in-process node; [`state_dir`] fell through to `$HOME/.usdmd-node` and
/// [`serving_port`] to the default 27780, so the test overwrote the LIVE daemon's `validator-27780.key` + `.kem` (mtime
/// 00:31:40, inside run sim-20261007-002601) with a test wallet's derived identity. A `cfg(test)` build with no
/// `MONEROUSD_STATE_DIR` now hangs every per-node file under this process's own temp home; the simulator further gives
/// each simulated node its own datadir ([`set_thread_node_files_for_test`]). A daemon build is unchanged.
/// cons: one small directory per test process under `$TMPDIR` (keys and books, a few KB), reaped by the OS temp sweep.
pub fn state_base() -> String {
    if let Some(d) = std::env::var("MONEROUSD_STATE_DIR").ok().filter(|d| !d.trim().is_empty()) {
        return d;
    }
    #[cfg(test)]
    {
        std::env::temp_dir().join(format!("usdmd-test-home-{}", std::process::id())).to_string_lossy().into_owned()
    }
    #[cfg(not(test))]
    {
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
    }
}

#[cfg(test)]
thread_local! {
    /// TEST BUILDS ONLY — the per-node file root `(datadir, port)` of the simulated PROCESS this thread is running (the
    /// twin of `params::set_thread_network_for_test`). A daemon is one process = one node = one set of per-node files
    /// (DB-341); the journey simulator runs several daemons in one test process, so each simulated node's work (its step
    /// thread, its RPC connection threads, its boot) names its validator key, custody books and reward file inside ITS
    /// datadir, exactly as its own process would.
    static THREAD_NODE_FILES_FOR_TEST: std::cell::RefCell<Option<(PathBuf, u16)>> = const { std::cell::RefCell::new(None) };
}

/// TEST BUILDS ONLY — run this thread as the process whose per-node files live in `dir` under `port` (`None` = the test
/// process's own home). See [`THREAD_NODE_FILES_FOR_TEST`].
#[cfg(test)]
pub fn set_thread_node_files_for_test(files: Option<(PathBuf, u16)>) {
    THREAD_NODE_FILES_FOR_TEST.with(|c| *c.borrow_mut() = files);
}

/// TEST BUILDS ONLY — the datadir of the simulated process this thread runs (`None`: the test process's own).
#[cfg(test)]
pub fn thread_node_dir_for_test() -> Option<PathBuf> {
    THREAD_NODE_FILES_FOR_TEST.with(|c| c.borrow().as_ref().map(|(d, _)| d.clone()))
}

/// TEST BUILDS ONLY — run `f` as the process whose per-node files are `files`, then restore this thread's own.
#[cfg(test)]
pub fn with_thread_node_files_for_test<R>(files: Option<(PathBuf, u16)>, f: impl FnOnce() -> R) -> R {
    let before = THREAD_NODE_FILES_FOR_TEST.with(|c| c.replace(files));
    let r = f();
    THREAD_NODE_FILES_FOR_TEST.with(|c| *c.borrow_mut() = before);
    r
}

/// The node's state directory — ONE definition for the snapshot, the block window and every sibling file.
/// iOS SANDBOX: `$HOME` is the app container ROOT, which is NOT writable — a dotdir there fails
/// (`Sandbox: deny file-write-create`). Persist under the writable `Library/Application Support/` instead so
/// the in-process phone node can save + O(1)-resume (#106) its snapshot across launches. Desktop keeps `~/.usdmd-node`.
pub fn state_dir() -> PathBuf {
    // ⛔ DB-341: every per-node file (validator key, custody books, custody opening, names, directory, peers, seed line,
    // onion seed, shutdown sentinel) is named through THIS function and [`serving_port`] — never a second `$HOME`
    // formula. Pinned by `db341_every_per_node_file_is_named_through_the_one_state_dir`.
    #[cfg(test)]
    if let Some(dir) = THREAD_NODE_FILES_FOR_TEST.with(|c| c.borrow().as_ref().map(|(d, _)| d.clone())) {
        return dir; // a simulated node's own datadir (DB-406)
    }
    let base = state_base();
    #[cfg(target_os = "ios")]
    let dir = PathBuf::from(base).join("Library/Application Support/usdmd-node");
    #[cfg(not(target_os = "ios"))]
    let dir = PathBuf::from(base).join(".usdmd-node");
    dir
}

/// ⛔ DB-341 — THE PORT THIS PROCESS SERVES, fixed ONCE where the process binds its RPC: the daemon right after
/// `pick_free_rpc_port`, the in-process node at the top of `serve::run_in_process`. Both entry points are exactly-once
/// per process, so one process = one node = one set of per-node files. A per-node file names itself
/// `<stem>-<serving_port()>` under [`state_dir`], never by reading `MONEROUSD_RPC_PORT` itself: a daemon whose
/// preferred port was busy auto-selects the next one, and the env var then names ANOTHER node's files — its validator
/// key included. MEASURED by code reading 2026-09-28: the key had three path formulas and a daemon ran two of them at
/// once (`/validator_id` from `$HOME` + the env port; the onion serve's finality voter, bridge signer and announce from
/// `state_base` + the served port).
/// O1-FOOTPRINT-REVIEWED: one u16, set once per process.
static SERVING_PORT: std::sync::OnceLock<u16> = std::sync::OnceLock::new();

/// Fix this process's served port (see [`SERVING_PORT`]). A second call naming a DIFFERENT port changes nothing and
/// says so: the node's files stay keyed by the port it first served.
pub fn set_serving_port(port: u16) {
    if SERVING_PORT.set(port).is_err() && SERVING_PORT.get() != Some(&port) {
        eprintln!(
            "[identity] ⛔ this process already serves port {}; its per-node files stay keyed by it (port {port} was named later)",
            SERVING_PORT.get().copied().unwrap_or(0)
        );
    }
}

/// The port this process serves: the one [`set_serving_port`] fixed; before that (a tool, a unit test) the launch
/// port `MONEROUSD_RPC_PORT`, else the default RPC port.
#[must_use]
pub fn serving_port() -> u16 {
    #[cfg(test)]
    if let Some(p) = THREAD_NODE_FILES_FOR_TEST.with(|c| c.borrow().as_ref().map(|(_, p)| *p)) {
        return p; // a simulated node's own port (DB-406)
    }
    if let Some(p) = SERVING_PORT.get() {
        return *p;
    }
    std::env::var("MONEROUSD_RPC_PORT")
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .filter(|p| *p != 0)
        .unwrap_or(RPC_DEFAULT_PORT)
}

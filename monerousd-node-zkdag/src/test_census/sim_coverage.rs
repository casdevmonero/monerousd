//! Protocol: MonerousD — test harness (no consensus or wire effect).
//!
//! ⭐⭐⭐ WHAT THE SIMULATOR TOUCHED (user 2026-10-06: "make sure the simulator has no blindspots and covers the whole
//! ecosystem always stays up to date").
//!
//! A simulator run notes every RPC route it called through the PRODUCTION router (`rpc_http::route`) and every peer
//! message kind a simulated node received (`NodeRuntime`'s per-message kind), and prints them as `[sim-coverage-row]`
//! lines. The node writes NO file: the test runner (`scratchpad/lane_run.sh` → `scratchpad/sim_ledgers.py`) turns the
//! printed rows into `scratchpad/sim-coverage.tsv`, and the hole scanner compares that against the universes it reads
//! from the TREE (`surface_census::routes`, `wire_messages`, `wallet_commands`): every surface no simulator run touched on
//! the current source is a hole with its name — a route, message or command added tomorrow is uncovered until a
//! simulator run drives it, with no list to maintain by hand.
//!
//! Off unless a run calls [`start`], and per RUN: the test's thread holds the recording, and every thread that works for
//! that run — a simulated node's step thread, an RPC connection a wallet opened — [`adopt`]s the same recording through
//! its [`handle`], so parallel tests never see each other's coverage and no thread of the run is a blind spot (MEASURED
//! 2026-10-06: the thread-local-only shape lost every route a wallet called over a node's listener thread). Production
//! builds compile no hook at all.
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// One run's recording, shared by the threads that work for it.
pub type Handle = Arc<Mutex<BTreeSet<(&'static str, String)>>>;

thread_local! {
    static SEEN: RefCell<Option<Handle>> = const { RefCell::new(None) };
}

/// Begin recording on this thread.
pub fn start() {
    SEEN.with(|s| *s.borrow_mut() = Some(Arc::new(Mutex::new(BTreeSet::new()))));
}

/// This thread's recording, to hand to a thread working for the same run (`None` when not recording).
#[must_use]
pub fn handle() -> Option<Handle> {
    SEEN.with(|s| s.borrow().clone())
}

/// Record into `h` on this thread (a node step thread or an RPC connection thread of the run that owns `h`).
pub fn adopt(h: Handle) {
    SEEN.with(|s| *s.borrow_mut() = Some(h));
}

/// Note one touched surface (`kind` = "route" | "wire"). A no-op unless this thread records for a run.
pub fn note(kind: &'static str, name: &str) {
    SEEN.with(|s| {
        if let Some(h) = s.borrow().as_ref() {
            h.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert((kind, name.to_string()));
        }
    });
}

/// Stop recording and print what was touched as `[sim-coverage-row] run \t kind \t name` lines. Returns the count.
pub fn finish(run: &str) -> usize {
    let seen = SEEN
        .with(|s| s.borrow_mut().take())
        .map(|h| std::mem::take(&mut *h.lock().unwrap_or_else(std::sync::PoisonError::into_inner)))
        .unwrap_or_default();
    for (k, n) in &seen {
        eprintln!("[sim-coverage-row] {run}\t{k}\t{}", n.replace(['\t', '\n'], " "));
    }
    eprintln!("[sim-coverage] {run}: {} surface(s) touched", seen.len());
    seen.len()
}

/// The wallet's Tauri command(s) a `wallet-harness` command line exercises, derived from the SOURCE every time (no list to
/// maintain): the harness binary's dispatch arm for the verb names a `harness::NAME(`; that function in the wallet library's
/// `pub mod harness` calls `super::X(`; `X` with its `_blocking` / `_impl` suffix removed is the command the UI invokes.
#[must_use]
pub fn wallet_commands_for(cmd_line: &str) -> Vec<String> {
    let verb = cmd_line.split_whitespace().next().unwrap_or("");
    if verb.is_empty() {
        return Vec::new();
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../monerousd-wallet-v2/src-tauri/src");
    let bin = std::fs::read_to_string(root.join("bin/wallet-harness.rs")).unwrap_or_default();
    let lib = std::fs::read_to_string(root.join("lib.rs")).unwrap_or_default();
    // every harness::NAME the verb's dispatch arm(s) call
    let mut names = Vec::new();
    let arm = format!("[\"{verb}\"");
    let mut rest = bin.as_str();
    while let Some(at) = rest.find(&arm) {
        let body = &rest[at..];
        let end = body[1..].find("            [\"").map_or(body.len(), |e| e + 1);
        let chunk = &body[..end];
        let mut c = chunk;
        while let Some(h) = c.find("harness::") {
            let tail = &c[h + "harness::".len()..];
            let name: String = tail.chars().take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_').collect();
            if !name.is_empty() && !names.contains(&name) {
                names.push(name);
            }
            c = &tail[1.min(tail.len())..];
        }
        rest = &body[1..];
    }
    // each harness fn → the wallet function it wraps → the command name
    let module = lib.find("pub mod harness {").map_or("", |a| &lib[a..]);
    let mut out = Vec::new();
    for n in names {
        let Some(f) = module.find(&format!("pub fn {n}(")) else { continue };
        let body = &module[f..];
        let body = &body[..body.find("\n    }\n").unwrap_or(body.len())];
        if let Some(sx) = body.find("super::") {
            let x: String = body[sx + 7..].chars().take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_').collect();
            let cmd = x.trim_end_matches("_blocking").trim_end_matches("_impl").to_string();
            if !cmd.is_empty() && !out.contains(&cmd) {
                out.push(cmd);
            }
        }
    }
    out
}

/// Note every wallet command a harness command line exercises (see [`wallet_commands_for`]).
pub fn note_wallet(cmd_line: &str) {
    for c in wallet_commands_for(cmd_line) {
        note("wallet", &c);
    }
}

/// Whether a touched route `(method, path)` covers a universe route `(um, up)` — `ANY` matches every method, a `/x*` prefix
/// route matches any path under it, and a path's query string never matters.
#[must_use]
pub fn route_covers(method: &str, path: &str, um: &str, up: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    let m_ok = um == "ANY" || method == "ANY" || um.eq_ignore_ascii_case(method);
    let p_ok = match up.strip_suffix('*') {
        Some(prefix) => path.starts_with(prefix),
        None => path.trim_end_matches('/') == up.trim_end_matches('/'),
    };
    m_ok && p_ok
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    #[test]
    fn coverage_is_thread_local_and_a_route_prefix_covers_its_children() {
        super::note("route", "GET /never-started"); // not started: dropped
        super::start();
        super::note("route", "GET /get_info");
        let other = std::thread::spawn(|| {
            super::note("route", "GET /other-thread");
        });
        let _ = other.join();
        let count = |h: &super::Handle| h.lock().map(|s| s.len()).unwrap_or(0);
        let h = super::handle().expect("recording");
        assert_eq!(count(&h), 1, "only this run's touches are recorded — a thread that never adopted the run is not");
        // a thread working FOR this run (a node step thread, an RPC connection a wallet opened) adopts it and is recorded
        let worker = {
            let h = h.clone();
            std::thread::spawn(move || {
                super::adopt(h);
                super::note("route", "GET /from-a-worker");
            })
        };
        let _ = worker.join();
        assert_eq!(count(&h), 2, "an adopting thread's touch is recorded in the run it adopted");
        let _ = super::SEEN.with(|s| s.borrow_mut().take());
        assert!(super::route_covers("GET", "/get_info?x=1", "GET", "/get_info"));
        assert!(super::route_covers("POST", "/dex/order/7", "ANY", "/dex/order*"));
        assert!(!super::route_covers("GET", "/get_info", "POST", "/get_info"));
        assert!(!super::route_covers("GET", "/get_infox", "GET", "/get_info"));
        // the wallet mapping is read from the source: `send` reaches the wallet's send command
        let send = super::wallet_commands_for("send x 1.0");
        assert!(send.iter().any(|c| c.contains("send")), "send maps to a send command: {send:?}");
        assert!(super::wallet_commands_for("no-such-verb").is_empty());
    }
}

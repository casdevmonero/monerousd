// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Node lifecycle control — user-owned `stop` / `start` / `restart` for the supervised node.
//!
//! The macOS LaunchAgent (`org.monerousd.node`) previously ran `KeepAlive = true`: an unconditional
//! respawn with NO way to permanently stop the node — a bootout only lasts until the next login, and a
//! crash/exit instantly relaunches. That self-resurrecting keepalive is what pinned the CPU and made the
//! node feel like it "never starts" (a respawn storm re-loading the snapshot in a tight loop).
//!
//! The fix gates the whole thing on a single DISABLED sentinel file. The node is ENABLED BY DEFAULT (a
//! fresh install just runs — absence of the sentinel means "run"); `stop` creates the sentinel, `start`
//! removes it:
//!   • `stop`    → create the disabled-sentinel, bootout the LaunchAgent, SIGTERM the running `serve`.
//!   • `start`   → remove the disabled-sentinel, (re)bootstrap + kickstart the LaunchAgent.
//!   • `restart` → `stop` then `start`.
//! The LaunchAgent's `KeepAlive` is `{ PathState: { <sentinel>: false } }` (keep alive WHILE the sentinel
//! is absent) and its args are `serve --supervised`, which calls [`supervised_enabled`] on boot and exits
//! CLEANLY when the sentinel is present. So a `stop` stays stopped across the process exiting AND across
//! reboot — until the user explicitly starts it again.
//!
//! Home is `$HOME` (the codebase convention; never a hardcoded path). The `launchctl`/`kill` calls are the
//! macOS supervisor integration and are `cfg`-gated; the sentinel + PID handling is portable.

use std::path::PathBuf;
use std::process::Command;

/// The LaunchAgent label the desktop app installs.
pub const LAUNCHD_LABEL: &str = "org.monerousd.node";

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
}

/// The DISABLED sentinel: the supervised node is administratively stopped iff this file EXISTS. `stop`
/// creates it; `start` removes it; a fresh install (no sentinel) runs by default. The LaunchAgent's
/// `KeepAlive` PathState watches this exact path, so it is the single source of truth for "should the
/// node be running" — and it survives reboot with no separate persisted daemon state.
pub fn disabled_flag_path() -> PathBuf {
    home().join(".usdmd-node").join("node-supervised.disabled")
}

/// The installed LaunchAgent plist the desktop app writes.
pub fn launchd_plist_path() -> PathBuf {
    home()
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"))
}

/// Is the supervised node administratively ENABLED (i.e. NOT stopped)? A launchd-respawned
/// `serve --supervised` calls this at boot and exits 0 when false — the belt that makes `stop` durable
/// even if launchd tries to relaunch it. Default true (absent sentinel ⇒ enabled).
pub fn supervised_enabled() -> bool {
    !disabled_flag_path().exists()
}

/// Create (`disabled = true`) or remove (`disabled = false`) the DISABLED sentinel. Idempotent — removing
/// an absent sentinel is success (the `start`/`stop` paths rely on that).
fn set_disabled(disabled: bool) -> std::io::Result<()> {
    let p = disabled_flag_path();
    if disabled {
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&p, b"administratively stopped by `usdmd-node stop`\n")
    } else {
        match std::fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// The current login user's numeric uid, for the `gui/<uid>` launchd domain target.
#[cfg(target_os = "macos")]
fn gui_uid() -> Option<String> {
    let out = Command::new("id").arg("-u").output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// PIDs of the running supervised node (`usdmd-node serve` / `serve --supervised`) — NEVER `serve-sites`
/// (different token) and never a broad match. Exact-PID handling only, per the no-broad-pkill cardinal.
fn running_serve_pids() -> Vec<u32> {
    // ERE: `serve` followed by end-of-line or whitespace excludes `serve-sites` (followed by `-`).
    let out = match Command::new("pgrep")
        .arg("-f")
        .arg(r"usdmd-node serve($|[[:space:]])")
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let me = std::process::id();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
        .filter(|&pid| pid != me)
        .collect()
}

/// Graceful SIGTERM to one exact PID (lets arti flush its onion state — a SIGKILL/broad-pkill dirties the
/// Tor cache and forces a ~14-minute re-bootstrap). Best-effort; a dead PID is not an error.
fn sigterm(pid: u32) {
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
}

/// `usdmd-node stop` — permanently stop the supervised node until an explicit `start`/`restart`.
/// Creates the disabled-sentinel FIRST (so nothing respawns), unloads the LaunchAgent, then SIGTERMs the
/// producer. The stop survives the process exiting AND reboot.
pub fn stop() -> i32 {
    if let Err(e) = set_disabled(true) {
        eprintln!(
            "stop: could not write disabled-sentinel {}: {e}",
            disabled_flag_path().display()
        );
        return 1;
    }
    #[cfg(target_os = "macos")]
    if let Some(uid) = gui_uid() {
        // Unload the job so the keepalive cannot respawn it (idempotent; ignore "not loaded").
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("gui/{uid}/{LAUNCHD_LABEL}")])
            .status();
    }
    let pids = running_serve_pids();
    for pid in &pids {
        sigterm(*pid);
    }
    println!(
        "node STOPPED — disabled-sentinel written ({}), LaunchAgent unloaded, {} producer process(es) \
         signalled. It stays stopped (across exit AND reboot) until `usdmd-node start`.",
        disabled_flag_path().display(),
        pids.len()
    );
    0
}

/// `usdmd-node start` — enable + (re)launch the supervised node. Removes the disabled-sentinel, then
/// bootstraps and kickstarts the LaunchAgent so it comes up now and on every future login.
pub fn start() -> i32 {
    if let Err(e) = set_disabled(false) {
        eprintln!(
            "start: could not clear disabled-sentinel {}: {e}",
            disabled_flag_path().display()
        );
        return 1;
    }
    #[cfg(target_os = "macos")]
    if let Some(uid) = gui_uid() {
        let plist = launchd_plist_path();
        if plist.exists() {
            // Load (ignore "already bootstrapped"), then force it running now.
            let _ = Command::new("launchctl")
                .args(["bootstrap", &format!("gui/{uid}"), &plist.to_string_lossy()])
                .status();
            let _ = Command::new("launchctl")
                .args(["kickstart", "-k", &format!("gui/{uid}/{LAUNCHD_LABEL}")])
                .status();
        } else {
            eprintln!(
                "start: LaunchAgent {} not installed — sentinel cleared; a direct `usdmd-node serve` will run.",
                plist.display()
            );
        }
    }
    println!(
        "node STARTED — disabled-sentinel cleared ({}); LaunchAgent bootstrapped + kickstarted.",
        disabled_flag_path().display()
    );
    0
}

/// `usdmd-node restart` — stop then start.
pub fn restart() -> i32 {
    let rc = stop();
    if rc != 0 {
        return rc;
    }
    start()
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    // The sentinel is process-global ($HOME-derived); serialize the tests that mutate it so parallel
    // cargo threads don't race the same file.
    static FLAG_LOCK: Mutex<()> = Mutex::new(());
    fn lock() -> MutexGuard<'static, ()> {
        FLAG_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn disabled_sentinel_gates_enabled_state_default_on() {
        let _g = lock();
        let start_state = supervised_enabled();

        // Default (sentinel absent) ⇒ ENABLED — a fresh install runs without any `start`.
        set_disabled(false).expect("clear sentinel");
        assert!(supervised_enabled(), "no sentinel ⇒ enabled by default");

        // stop writes the sentinel ⇒ administratively STOPPED; `serve --supervised` would exit clean.
        set_disabled(true).expect("write sentinel");
        assert!(
            !supervised_enabled(),
            "sentinel present ⇒ administratively stopped"
        );
        // idempotent create
        set_disabled(true).expect("write sentinel again");
        assert!(!supervised_enabled());

        // start removes it ⇒ enabled again; removing an absent sentinel is success (stop/start rely on it).
        set_disabled(false).expect("clear sentinel");
        assert!(supervised_enabled());
        set_disabled(false).expect("clear absent sentinel is ok");
        assert!(supervised_enabled());

        // leave the machine as we found it (enabled ⇒ no sentinel ⇒ disabled=false)
        set_disabled(!start_state).ok();
    }

    #[test]
    fn sentinel_path_is_home_derived_not_hardcoded() {
        let _g = lock();
        let p = disabled_flag_path();
        assert!(p.ends_with("node-supervised.disabled"));
        assert!(
            p.to_string_lossy().contains(".usdmd-node"),
            "sentinel lives in the node datadir, home-derived: {}",
            p.display()
        );
    }
}

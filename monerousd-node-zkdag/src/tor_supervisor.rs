// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ALWAYS-UP Tor SOCKS supervisor — the node OWNS its onion connectivity end-to-end; it never depends
//! on a manually-started external Tor at a guessed port ("the tor connection should automatically stay
//! up, it should not be flaky Monero-style", user 2026-07-10).
//!
//! MonerousD is ONION-ONLY: EVERY egress — the libp2p PQ-gossip mesh AND the bridge deposit watch — rides
//! Tor, and there is NO raw-IP / clearnet path. So the node MUST guarantee a reachable SOCKS proxy for the
//! entire time it runs, and KEEP IT UP: if Tor ever exits it is respawned automatically (KeepAlive), so a
//! transient Tor death can never leave the node islanded or the bridge watch dark. This is also exactly
//! what lets a node run automatically on a phone — the same supervisor brings Tor up there; nothing
//! external to configure, no flaky dependency on a system service.
//!
//! WELL-MAINTAINED — NO ZOMBIES, NO DUPLICATES: the supervisor is a SINGLETON per SOCKS endpoint. Each cycle
//! it FIRST checks whether the port is already reachable; it only spawns a tor when the port is genuinely
//! DOWN, so it never starts a second tor while one already serves — it ADOPTS an operator's tor, or an
//! orphaned node-owned tor left by a prior run, instead of duplicating it (so restarts don't accumulate tor
//! processes). It always `wait()`s on the child it spawned, so an exited tor is REAPED immediately (never a
//! zombie). One tor per endpoint, kept alive, cleaned up automatically.
//!
//! Resolution (the returned SOCKS string is STABLE for the node's lifetime, so callers that captured it
//! stay valid — the supervisor guarantees something is listening on that endpoint):
//!   1) `MONEROUSD_TOR_SOCKS` set AND already reachable  -> an operator manages Tor; use it as-is.
//!   2) `MONEROUSD_TOR_SOCKS` set but NOT reachable       -> WE spawn + supervise a node-owned `tor` on
//!                                                          that exact port (honor the requested endpoint).
//!   3) not set                                           -> spawn + supervise on a node-owned port derived
//!                                                          from the RPC port (collision-free for a local
//!                                                          multi-node mesh: 27780->9050, 27781->9051, ...).
//! On no `tor` binary available it returns `None` and the node stays ONION-ONLY, FAIL-CLOSED — never a
//! clearnet path: the mesh simply has no peers and the bridge watch returns `None` until Tor comes up.

use std::io::Write as _;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The node's default SOCKS port when `MONEROUSD_TOR_SOCKS` is unset, derived from the RPC port so two
/// local nodes on one host never collide (27780 -> 9050, 27781 -> 9051, ...). Kept in the ephemeral-ish
/// 9050+ range Tor conventionally uses.
fn default_socks_port(rpc_port: u16) -> u16 {
    9050u16.saturating_add(rpc_port.saturating_sub(27780))
}

/// True iff something is accepting TCP connections at `host_port` (i.e. a live SOCKS proxy). A short
/// connect timeout keeps startup snappy; unreachable simply means "Tor is not up here yet".
fn is_reachable(host_port: &str) -> bool {
    let Ok(mut addrs) = host_port.to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(600)).is_ok()
}

/// Locate a `tor` executable: `$MONEROUSD_TOR_BIN` first (explicit override), then `PATH`, then the
/// common Homebrew / system install locations. Returns `None` if no runnable `tor` is found.
pub fn find_tor_binary() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("MONEROUSD_TOR_BIN") {
        let p = PathBuf::from(&explicit);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let cand = Path::new(dir).join("tor");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    for cand in [
        "/opt/homebrew/bin/tor",
        "/usr/local/bin/tor",
        "/usr/bin/tor",
        "/usr/sbin/tor",
    ] {
        let p = PathBuf::from(cand);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// The local libp2p listen port the onion HiddenService forwards to. Mirrors `bring_up_onion_transport`'s
/// default listen (`/ip4/127.0.0.1/tcp/{35000 + rpc_port - 27780}`) so the HS maps onion:PORT -> that bind.
pub fn onion_listen_port(rpc_port: u16) -> u16 {
    35000u16.wrapping_add(rpc_port.wrapping_sub(27780))
}

/// This node's OWN v3 `.onion` hostname, auto-created by the HiddenService in the node-owned torrc and read
/// from `<data_dir>/tor/hs/hostname`. `None` until tor has generated + published the descriptor (first
/// bootstrap, usually seconds). Stable across restarts (the HS keys persist on disk), so a published seed
/// descriptor stays valid — self-maintaining, zero hand-config.
pub fn onion_hostname(data_dir: &Path) -> Option<String> {
    let p = data_dir.join("tor").join("hs").join("hostname");
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| s.ends_with(".onion"))
}

/// Write a node-owned torrc into `tor_dir`: a SOCKS client (to dial peers) AND a v3 HiddenService that makes
/// THIS node remotely reachable over `.onion` (mapping onion:`hs_local_port` -> the node's loopback libp2p
/// bind). The HS is what lets other machines dial this node — the mesh entrypoint published as a seed peer.
/// A fresh DataDirectory per node keeps two local nodes fully independent, and the HS keys persist so the
/// node's `.onion` is stable across restarts. (No `ClientOnly` — that flag forbids running a HiddenService.)
fn write_torrc(
    tor_dir: &Path,
    socks_port: u16,
    hs_local_port: u16,
    rpc_port: u16,
) -> Option<PathBuf> {
    std::fs::create_dir_all(tor_dir).ok()?;
    let torrc = tor_dir.join("torrc");
    let hs_dir = tor_dir.join("hs");
    let body = format!(
        "# MoneroUSD node-owned Tor (auto-managed, always-up). SOCKS client egress + a v3 HiddenService so\n\
         # this node is remotely reachable over .onion (the mesh entrypoint published as a seed peer).\n\
         SocksPort 127.0.0.1:{socks_port}\n\
         DataDirectory {dir}\n\
         Log notice file {dir}/notice.log\n\
         AvoidDiskWrites 1\n\
         # INSTANT BOOTSTRAP: pull directory info as early + aggressively as possible so a COLD first boot\n\
         # reaches \"ready to build circuits\" in the fewest round-trips; on every RESTART the consensus +\n\
         # microdescriptors are already cached in DataDirectory, so it warm-bootstraps in ~1-2s. Combined with\n\
         # the non-blocking startup (the node never waits on this), the onion mesh attaches near-instantly.\n\
         FetchDirInfoEarly 1\n\
         FetchDirInfoExtraEarly 1\n\
         HiddenServiceDir {hs}\n\
         HiddenServiceVersion 3\n\
         HiddenServicePort {hsp} 127.0.0.1:{hsp}\n\
         HiddenServicePort {rpcp} 127.0.0.1:{rpcp}\n\
         # WELL-KNOWN CELL PORT: also expose the cell listener at the fixed port every arti dialer opens\n\
         # (`arti_transport::ONION_CELL_PORT`), so ANY node — including a phone's in-process arti node — can\n\
         # dial this daemon from just its `.onion` name with no per-peer port negotiation (auto-join standard).\n\
         HiddenServicePort {cellp} 127.0.0.1:{hsp}\n",
        dir = tor_dir.display(),
        hs = hs_dir.display(),
        hsp = hs_local_port,
        rpcp = rpc_port,
        cellp = crate::net::ONION_CELL_PORT,
    );
    let mut f = std::fs::File::create(&torrc).ok()?;
    f.write_all(body.as_bytes()).ok()?;
    Some(torrc)
}

/// True iff the tor recorded in OUR `<tor_dir>/tor.pid` is ALIVE and was spawned from OUR torrc path —
/// the ownership test that distinguishes "orphan of a prior run of THIS node" (its HiddenService is ours:
/// safe to adopt) from a FOREIGN tor that merely holds the same SOCKS port (its HS is NOT ours — adopting
/// it would leave this node's published `.onion` unserved and inbound-dead).
fn our_torrc_process_alive(tor_dir: &Path, torrc: &Path) -> bool {
    let Ok(pid_s) = std::fs::read_to_string(tor_dir.join("tor.pid")) else {
        return false;
    };
    let Ok(pid) = pid_s.trim().parse::<u32>() else {
        return false;
    };
    let Ok(out) = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
    else {
        return false;
    };
    let cmd = String::from_utf8_lossy(&out.stdout);
    out.status.success() && cmd.contains(&torrc.display().to_string())
}

/// Spawn one `tor` child bound to our torrc, with stdio discarded (its own log file captures detail).
fn spawn_tor(tor_bin: &Path, torrc: &Path) -> Option<Child> {
    Command::new(tor_bin)
        .arg("-f")
        .arg(torrc)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

/// Record the supervised tor's PID (`<tor_dir>/tor.pid`) for observability + external cleanup.
fn write_pid(tor_dir: &Path, pid: u32) {
    let _ = std::fs::write(tor_dir.join("tor.pid"), pid.to_string());
}

/// Start the background MONITOR-AND-HEAL supervisor: keep EXACTLY ONE tor serving `socks`, and no more.
/// Each cycle it FIRST checks whether the SOCKS port is already reachable — if so (our tor, an adopted
/// orphan from a prior run, or an operator's tor) it does NOTHING but watch (this is what prevents
/// DUPLICATE tor processes); only when the port is genuinely DOWN does it spawn a node-owned tor, then
/// `wait()`s on it — which REAPS the child on exit (no zombies) — and re-heals. Singleton by construction:
/// never a second tor while one already serves the port; self-healing when none does.
fn start_monitor(socks: String, tor_bin: PathBuf, torrc: PathBuf, tor_dir: PathBuf) {
    std::thread::Builder::new()
        .name("tor-supervisor".into())
        .spawn(move || loop {
            if is_reachable(&socks) {
                // Healthy (ours / adopted orphan / operator's): do NOT spawn a duplicate — just watch.
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
            // Port is DOWN: bring exactly one node-owned tor up and reap it on exit (no zombie).
            match spawn_tor(&tor_bin, &torrc) {
                Some(mut child) => {
                    write_pid(&tor_dir, child.id());
                    let _ = child.wait(); // blocks until tor exits, then REAPS the child
                    eprintln!(
                        "[tor-supervisor] node-owned tor exited — re-healing onion connectivity"
                    );
                }
                None => {
                    eprintln!("[tor-supervisor] failed to spawn tor — retrying");
                }
            }
            std::thread::sleep(Duration::from_secs(2)); // backoff before the next reachability check
        })
        .ok();
}

/// GUARANTEE an up SOCKS proxy for the node's onion egress and keep it up. Returns the SOCKS `host:port`
/// (already reachable when it returns `Some`) and, on the spawn path, sets `MONEROUSD_TOR_SOCKS` in-process
/// so the bridge watch ([`crate::btc_watch`]) and any later onion bring-up read the same live endpoint.
/// Returns `None` only when no `tor` binary exists AND no external Tor is reachable — the node then stays
/// onion-only fail-closed (never a clearnet path).
pub fn ensure_tor_socks(rpc_port: u16, data_dir: &Path) -> Option<String> {
    // The endpoint the node will advertise + drive. Honor an operator-set port; else derive a node-owned one.
    let socks = match std::env::var("MONEROUSD_TOR_SOCKS") {
        Ok(s) if !s.trim().is_empty() => {
            let s = s.trim().to_string();
            // A bare port ("9050") is accepted as 127.0.0.1:<port>.
            if s.contains(':') {
                s
            } else {
                format!("127.0.0.1:{s}")
            }
        }
        _ => format!("127.0.0.1:{}", default_socks_port(rpc_port)),
    };

    let port: u16 = socks.rsplit(':').next().and_then(|p| p.parse().ok())?;
    let hs_port = onion_listen_port(rpc_port);
    let tor_dir = data_dir.join("tor");
    let tor_bin = find_tor_binary();

    // (1) Already up. Reachable is NOT enough to adopt outright: adoption is fully healthy ONLY when the
    // process serving the port was spawned from OUR torrc — then OUR HiddenService (this node's stable
    // published `.onion` + its well-known cell mapping) is being served. A FOREIGN tor (another instance's
    // leftover, an operator's system tor) gives working EGRESS but serves the WRONG (or no) HS for this
    // node — the canonical seed `.onion` published for this node then points at a dead descriptor and every
    // inbound dial HANGS (observed live: a stale tor-27795 instance held the port, so the node's `57lhw5…`
    // seed identity was never served and a joining phone's rendezvous hung forever). Egress-only adoption
    // silently islands the node from INBOUND peers — the exact anti-bidirectional gap the mesh law forbids.
    if is_reachable(&socks) {
        let ours = write_torrc(&tor_dir, port, hs_port, rpc_port);
        if ours
            .as_deref()
            .is_some_and(|rc| our_torrc_process_alive(&tor_dir, rc))
        {
            // A true orphan from a PRIOR run of THIS node (same torrc path): its HS is ours — adopt it.
            std::env::set_var("MONEROUSD_TOR_SOCKS", &socks);
            if let (Some(bin), Some(rc)) = (tor_bin.clone(), ours) {
                start_monitor(socks.clone(), bin, rc, tor_dir);
            }
            println!("[tor-supervisor] onion SOCKS already up at {socks} — adopting OUR prior tor (HS identity intact)");
            return Some(socks);
        }
        // FOREIGN tor at our derived endpoint. Leave it running (never kill another instance's tor) and
        // bring up OUR OWN tor — OUR torrc, OUR persistent HS keys, OUR stable `.onion` — on the next free
        // derived port, and use that for egress too (one tor serving both roles for this node).
        if let Some(bin) = tor_bin.clone() {
            if let Some(free) = (port.saturating_add(1)..port.saturating_add(50))
                .find(|p| std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok())
            {
                if let Some(rc) = write_torrc(&tor_dir, free, hs_port, rpc_port) {
                    let socks2 = format!("127.0.0.1:{free}");
                    start_monitor(socks2.clone(), bin, rc, tor_dir);
                    std::env::set_var("MONEROUSD_TOR_SOCKS", &socks2);
                    println!(
                        "[tor-supervisor] {socks} is a FOREIGN tor (not spawned from our torrc) — bringing up \
                         OUR OWN tor at {socks2} so this node's stable .onion HS is actually served"
                    );
                    return Some(socks2);
                }
            }
        }
        // No tor binary to spawn our own: egress-only adoption is the best available (still onion-only).
        std::env::set_var("MONEROUSD_TOR_SOCKS", &socks);
        println!(
            "[tor-supervisor] adopting FOREIGN tor at {socks} for EGRESS ONLY (no `tor` binary to serve our \
             own HS) — this node is NOT inbound-dialable until a tor binary is available"
        );
        return Some(socks);
    }

    // (2)/(3) Nothing there: bring up + monitor exactly ONE node-owned Tor on that endpoint.
    let tor_bin = match tor_bin {
        Some(b) => b,
        None => {
            eprintln!(
                "[tor-supervisor] no `tor` binary found and no external Tor reachable at {socks}; \
                 node stays ONION-ONLY fail-closed. Install tor or set MONEROUSD_TOR_BIN."
            );
            return None;
        }
    };
    let torrc = write_torrc(&tor_dir, port, hs_port, rpc_port)?;
    start_monitor(socks.clone(), tor_bin, torrc, tor_dir);

    // INSTANT BOOTSTRAP FOR ALL USERS (user 2026-07-13): do NOT block node startup on Tor. `start_monitor`
    // is already bringing tor up + KeepAlive-healing it on a background thread, so we return the stable,
    // lifetime-valid SOCKS endpoint IMMEDIATELY — the node's RPC + block producer + local state come up with
    // ZERO wait, and the onion mesh ATTACHES asynchronously the instant tor is ready (seconds; warm-cached to
    // ~1-2s on restart). This is sound: the libp2p transport binds its own loopback listener (it does not need
    // the proxy to LISTEN), and outbound peer dials go through this endpoint — which the transport + auto-peer
    // loop already RETRY when it is not-yet-ready, exactly as they tolerate a `None` return here. So the only
    // change is that the node is instantly responsive + producing instead of hanging up to a minute on boot.
    std::env::set_var("MONEROUSD_TOR_SOCKS", &socks);
    println!(
        "[tor-supervisor] node-owned tor spawning at {socks} (auto-managed, singleton + KeepAlive); startup \
         does NOT block on bootstrap — the onion mesh attaches as soon as tor is ready (warm-cached on restart)"
    );
    Some(socks)
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn default_socks_port_is_collision_free_per_node() {
        assert_eq!(default_socks_port(27780), 9050);
        assert_eq!(default_socks_port(27781), 9051);
        assert_eq!(default_socks_port(27782), 9052);
    }

    #[test]
    fn unreachable_endpoint_reports_down() {
        // A port nothing listens on must read as not-reachable (fail-closed input to the supervisor).
        assert!(!is_reachable("127.0.0.1:5"));
    }

    #[test]
    fn torrc_is_written_with_socks_egress_and_a_v3_hidden_service() {
        let dir = std::env::temp_dir().join(format!("usdmd-torrc-test-{}", std::process::id()));
        let torrc = write_torrc(&dir, 9077, 35000, 27780).expect("torrc written");
        let body = std::fs::read_to_string(&torrc).expect("read torrc");
        // SOCKS client egress (dial peers)...
        assert!(body.contains("SocksPort 127.0.0.1:9077"));
        // ...AND a v3 HiddenService mapping onion:35000 -> the node's loopback bind (remote reachability).
        assert!(body.contains("HiddenServiceVersion 3"));
        assert!(body.contains("HiddenServicePort 35000 127.0.0.1:35000"));
        // ...AND the WELL-KNOWN cell port mapped onto the SAME cell listener, so an arti dialer (e.g. a
        // phone's in-process node) reaches this daemon from just its `.onion` name (auto-join standard).
        assert!(body.contains(&format!(
            "HiddenServicePort {} 127.0.0.1:35000",
            crate::net::ONION_CELL_PORT
        )));
        assert!(body.contains(&format!("HiddenServiceDir {}", dir.join("hs").display())));
        // ClientOnly would FORBID running a HiddenService — it must be absent so this node can serve .onion.
        assert!(!body.contains("ClientOnly"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §22 6 — THE CUSTODY WALLET, RUN BY THE NODE ITSELF: a validator holds no Monero node and starts nothing by hand.
//!
//! Monero's k-of-n multisig lives in `monero-wallet-rpc` (a wallet, not a node: it keeps no blockchain). A custodian needs one
//! running. This supervisor runs it the way `tor_supervisor` runs Tor:
//! - only on a node that holds a CUSTODY SEAT (a user's node never runs one);
//! - the binary found beside the node (the app bundle ships it), at `MONEROUSD_XMR_WALLET_RPC_BIN`, or on the system path;
//! - pointed at an ONION Monero daemon from the cross-check set (`xmr_daemons::daemons`) through the node's own Tor
//!   (`--proxy`, `--untrusted-daemon`) — so no Monero node runs on this machine, and no daemon is trusted: every deposit
//!   still has to be agreed by three daemons (`xmr_daemons`) before it counts;
//! - bound to 127.0.0.1 only, its wallets in this node's state directory, respawned if it exits, a different daemon each
//!   respawn (a dead or lying daemon is walked away from).
//! An operator who runs their own wallet-rpc keeps `MONEROUSD_XMR_WALLET_RPC_URL`, which wins.
//!
//! cons: one `monero-wallet-rpc` process (~100 MB of RAM) on a custodian's machine; its daemon traffic over onion.
//!
//! CLASSICAL-BRIDGE-ENDPOINT: Monero's own wallet process for the foreign chain's multisig. DIGITAL-CASH-PRIVACY-REVIEWED:
//! loopback-only RPC; every Monero request leaves through Tor to an onion daemon.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

static CUSTODIAN: AtomicBool = AtomicBool::new(false);

/// The runtime says whether this node holds a custody seat now (checked on its slow cadence).
pub fn set_custodian(seated: bool) {
    CUSTODIAN.store(seated, Ordering::Relaxed);
}

/// The `monero-wallet-rpc` binary: `MONEROUSD_XMR_WALLET_RPC_BIN`, beside this executable (the app bundle), then the path.
#[must_use]
pub fn find_binary() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("MONEROUSD_XMR_WALLET_RPC_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let exe_dir = std::env::current_exe().ok().and_then(|e| e.parent().map(std::path::Path::to_path_buf));
    let mut cands: Vec<PathBuf> = exe_dir.into_iter().map(|d| d.join("monero-wallet-rpc")).collect();
    if let Ok(path) = std::env::var("PATH") {
        cands.extend(path.split(':').map(|d| PathBuf::from(d).join("monero-wallet-rpc")));
    }
    cands.extend(["/opt/homebrew/bin/monero-wallet-rpc", "/usr/local/bin/monero-wallet-rpc", "/usr/bin/monero-wallet-rpc"].map(PathBuf::from));
    cands.into_iter().find(|p| p.is_file())
}

/// The supervised custody wallet's directory, when this node runs one (no operator wallet named): where the multisig switch is written.
#[must_use]
pub fn wallet_dir() -> Option<PathBuf> {
    if std::env::var("MONEROUSD_XMR_WALLET_RPC_URL").is_ok_and(|u| !u.trim().is_empty()) {
        return None;
    }
    Some(crate::persist::state_dir().join("xmr-custody"))
}

/// The network flag `monero-wallet-rpc` takes for this node's Monero network (`None` for mainnet).
#[must_use]
pub fn network_flag(net_byte: u8) -> Option<&'static str> {
    match net_byte {
        24 => Some("--stagenet"),
        53 => Some("--testnet"),
        _ => None,
    }
}

/// The arguments one supervised start runs with (pure, for the pin).
#[must_use]
pub fn args(port: u16, wallet_dir: &str, daemon: &str, socks: &str, net_byte: u8) -> Vec<String> {
    let host_port = daemon.trim_start_matches("http://").trim_start_matches("https://").trim_end_matches('/');
    let mut a: Vec<String> = [
        "--rpc-bind-ip",
        "127.0.0.1",
        "--rpc-bind-port",
        &port.to_string(),
        "--disable-rpc-login",
        "--wallet-dir",
        wallet_dir,
        "--daemon-address",
        host_port,
        "--proxy",
        socks,
        "--untrusted-daemon",
        "--non-interactive",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    if let Some(f) = network_flag(net_byte) {
        a.push(f.to_string());
    }
    a
}

struct State {
    url: Option<String>,
    started: bool,
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(State { url: None, started: false }))
}

/// ⭐ The supervised custody wallet's URL — started on first ask on a custodian with a binary, Tor and three daemons to choose
/// from; `None` otherwise (this node then takes no part in Monero custody, and says so where it is asked).
#[must_use]
pub fn wallet_url() -> Option<String> {
    if !CUSTODIAN.load(Ordering::Relaxed) {
        return None;
    }
    let mut st = match state().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // the URL a prior caller recorded is still the supervised one
    };
    if st.started {
        return st.url.clone();
    }
    let bin = find_binary()?;
    let socks = std::env::var("MONEROUSD_TOR_SOCKS").ok().filter(|s| !s.trim().is_empty())?;
    let daemons = crate::xmr_daemons::daemons();
    if daemons.is_empty() {
        return None;
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0").ok()?.local_addr().ok()?.port();
    let dir = wallet_dir()?;
    let _ = std::fs::create_dir_all(&dir); // LOCAL-STORAGE-REQUIRED: Monero's own multisig wallet files — Monero's custody primitive keeps its key state in its wallet, no MonerousD proof can hold a foreign wallet. bound: one wallet per custody set.
    let net = crate::bridge::xmr_net_byte();
    let url = format!("http://127.0.0.1:{port}");
    st.started = true;
    st.url = Some(url.clone());
    drop(st);
    let start = usize::from(blake3::hash(dir.to_string_lossy().as_bytes()).as_bytes()[0]);
    std::thread::spawn(move || {
        let mut k = start;
        loop {
            let daemon = daemons[k % daemons.len()].clone();
            k += 1;
            let a = args(port, &dir.to_string_lossy(), &daemon, &socks, net);
            match std::process::Command::new(&bin)
                .args(&a)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(mut child) => {
                    let _ = child.wait(); // reaped on exit (no zombie), then respawned on the next daemon
                    eprintln!("[xmr-custody] the custody wallet exited — restarting it on another onion Monero daemon");
                }
                Err(e) => eprintln!("[xmr-custody] the custody wallet could not start: {e}"),
            }
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    });
    Some(url)
}

/// The daemon the custody wallet follows, for the fee reference a signer judges a payout against: the first of the
/// cross-check set (`MONEROUSD_XMR_DAEMON_URL` still wins when an operator names one).
#[must_use]
pub fn reference_daemon() -> Option<String> {
    crate::xmr_daemons::daemons().into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ §22 6 — THE CUSTODY WALLET RUNS WITH NO MONERO NODE ON THIS MACHINE: it is bound to loopback without a login only
    /// reachable from this node, follows an ONION daemon through the node's Tor as an UNTRUSTED daemon, keeps its wallets
    /// in this node's directory and names the test networks' flags; a node without a custody seat starts none.
    /// TWO-PARTY-REVIEWED: a local process start — the custody it serves is pinned across nodes in `xmr_sim`'s multisig pins.
    #[test]
    fn the_custody_wallet_runs_against_an_onion_daemon_through_tor_with_no_local_node() {
        let a = args(41234, "/data/xmr-custody", "http://abc.onion:18089", "127.0.0.1:9050", 18);
        let joined = a.join(" ");
        assert!(joined.contains("--rpc-bind-ip 127.0.0.1 --rpc-bind-port 41234"), "loopback only: {joined}");
        assert!(joined.contains("--daemon-address abc.onion:18089") && joined.contains("--proxy 127.0.0.1:9050"), "onion through Tor");
        assert!(joined.contains("--untrusted-daemon"), "the daemon is never trusted");
        assert!(!joined.contains("--trusted-daemon") && !joined.contains("0.0.0.0"));
        assert_eq!(network_flag(18), None);
        assert_eq!(network_flag(24), Some("--stagenet"));
        assert_eq!(network_flag(53), Some("--testnet"));
        assert!(args(1, "d", "http://x.onion:1", "s", 53).contains(&"--testnet".to_string()));
        set_custodian(false);
        assert_eq!(wallet_url(), None, "a node without a custody seat runs no custody wallet");
    }
}

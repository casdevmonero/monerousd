// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! DB-121x — A REAL MONERO DAEMON (regtest) PLUS ONE WALLET-RPC PER CUSTODIAN, raised by a test so the Monero leg is
//! judged by Monero itself: the custody wallets form their k-of-n over the mesh against this daemon, a deposit is a
//! coin the miner wallet sends to the reserve's integrated address, and the payout is the XMR arriving in a wallet
//! Monero's own daemon confirms. EXTERNAL-CHAIN code, compiled for tests and the `bridge-test-oracle` feature only.
//!
//! MEASURED 2026-09-21 (`xmr_multisig_probe.sh`, Monero v0.18.4.6): `--regtest --offline --fixed-difficulty 1` mines
//! on demand (`generateblocks`); the daemon must run with `--no-zmq` on a machine whose own monerod holds the
//! default ZMQ port; a wallet-rpc following a regtest daemon needs `--allow-mismatched-daemon-version` (regtest has
//! every hard fork at height 1); a coinbase matures after 60 blocks; a ring needs enough unlocked outputs, so the
//! chain is mined 130 deep before anything is spent. Throwaway data directories under the system temp dir, never
//! the operator's; every process this driver starts writes a pidfile and is stopped by that PID alone.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::xmr_rpc::{DaemonRpc, WalletRpc};

pub struct MoneroRegtest {
    root: PathBuf,
    bin_dir: String,
    pub daemon_port: u16,
    /// One wallet-rpc per custodian, in node order; each has its own `--wallet-dir`.
    pub custodian_ports: Vec<u16>,
    pub custodian_dirs: Vec<PathBuf>,
    miner_port: u16,
    miner_address: String,
}

fn bin_dir() -> String {
    match std::env::var("MONEROUSD_XMR_BIN_DIR") {
        Ok(d) if !d.is_empty() => d,
        _ => "/opt/homebrew/bin".to_string(),
    }
}

/// A process this driver just started is READY when its RPC answers `get_version`; a process that never answers
/// within a minute did not start (the driver reports it, nothing else waits on it).
fn wait_ready(call: &dyn Fn() -> bool, what: &str) -> Result<(), String> {
    let t = std::time::Instant::now();
    loop {
        if call() {
            return Ok(());
        }
        if t.elapsed() > Duration::from_secs(60) {
            return Err(format!("{what} did not answer within 60 s"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

impl MoneroRegtest {
    /// Raises the daemon, `custodians` custody wallet-rpcs (their wallets are created by the nodes' own custody
    /// lanes) and one miner wallet-rpc whose wallet is created here and mined 130 blocks deep.
    pub fn start(tag: &str, custodians: usize) -> Result<MoneroRegtest, String> {
        let bin_dir = bin_dir();
        // 2026-10-27: one per-instance block of 3 + custodians ports (daemon rpc, p2p, miner, custodians) — test_ports.
        let block = crate::test_ports::reserve(47000, 3 + custodians as u16)?;
        let base = block.first;
        let root = std::env::temp_dir().join(format!("usdmd_journey_xmr_{tag}_{}_{}", std::process::id(), block.instance));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("d")).map_err(|e| format!("regtest datadir: {e}"))?;
        let daemon_port = base;
        let st = Command::new(format!("{bin_dir}/monerod"))
            .args([
                "--regtest",
                "--offline",
                "--fixed-difficulty",
                "1",
                &format!("--data-dir={}", root.join("d").display()),
                &format!("--rpc-bind-port={daemon_port}"),
                &format!("--p2p-bind-port={}", base + 1),
                "--no-zmq",
                "--no-igd",
                "--hide-my-port",
                "--non-interactive",
                &format!("--log-file={}", root.join("monerod.log").display()),
                "--log-level=0",
                &format!("--pidfile={}", root.join("monerod.pid").display()),
                "--detach",
            ])
            .status()
            .map_err(|e| format!("monerod did not start: {e}"))?;
        if !st.success() {
            return Err("monerod --detach reported a failed start".into());
        }
        let daemon = DaemonRpc::at(&format!("http://127.0.0.1:{daemon_port}")).ok_or("the regtest daemon URL is not private")?;
        wait_ready(&|| daemon.call("get_version", serde_json::json!({})).is_ok(), "the regtest monerod")?;
        let mut me = MoneroRegtest {
            root: root.clone(),
            bin_dir: bin_dir.clone(),
            daemon_port,
            custodian_ports: Vec::new(),
            custodian_dirs: Vec::new(),
            miner_port: base + 2,
            miner_address: String::new(),
        };
        me.start_wallet_rpc(me.miner_port, &root.join("miner"))?;
        for i in 0..custodians {
            let port = base + 3 + i as u16;
            let dir = root.join(format!("custodian{i}"));
            me.start_wallet_rpc(port, &dir)?;
            me.custodian_ports.push(port);
            me.custodian_dirs.push(dir);
        }
        let miner = me.miner()?;
        miner.open_or_create("miner", "")?;
        me.miner_address = miner.address()?;
        me.mine(130)?;
        miner.refresh()?;
        Ok(me)
    }

    fn start_wallet_rpc(&self, port: u16, dir: &PathBuf) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("wallet dir: {e}"))?;
        let st = Command::new(format!("{}/monero-wallet-rpc", self.bin_dir))
            .args([
                &format!("--daemon-address=127.0.0.1:{}", self.daemon_port),
                &format!("--rpc-bind-port={port}"),
                "--disable-rpc-login",
                &format!("--wallet-dir={}", dir.display()),
                "--trusted-daemon",
                "--allow-mismatched-daemon-version",
                &format!("--log-file={}", dir.join("wallet-rpc.log").display()),
                "--log-level=0",
                &format!("--pidfile={}", dir.join("wallet-rpc.pid").display()),
                "--detach",
            ])
            .status()
            .map_err(|e| format!("monero-wallet-rpc did not start: {e}"))?;
        if !st.success() {
            return Err(format!("monero-wallet-rpc on {port} reported a failed start"));
        }
        let rpc = WalletRpc::at(&format!("http://127.0.0.1:{port}")).ok_or("wallet-rpc URL is not private")?;
        wait_ready(&|| rpc.get_version().is_ok(), &format!("monero-wallet-rpc on {port}"))
    }

    pub fn daemon_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.daemon_port)
    }

    pub fn custodian_url(&self, i: usize) -> String {
        format!("http://127.0.0.1:{}", self.custodian_ports[i])
    }

    fn miner(&self) -> Result<WalletRpc, String> {
        WalletRpc::at(&format!("http://127.0.0.1:{}", self.miner_port)).ok_or_else(|| "miner wallet URL is not private".to_string())
    }

    /// Mines `blocks` to the miner wallet.
    pub fn mine(&self, blocks: u64) -> Result<(), String> {
        let daemon = DaemonRpc::at(&self.daemon_url()).ok_or("daemon URL is not private")?;
        daemon
            .call("generateblocks", serde_json::json!({ "wallet_address": self.miner_address, "amount_of_blocks": blocks }))
            .map(|_| ())
    }

    /// The daemon's block count, for the journey's log lines.
    pub fn block_count(&self) -> u64 {
        match DaemonRpc::at(&self.daemon_url()).map(|d| d.height()) {
            Some(Ok(h)) => h,
            _ => 0,
        }
    }

    /// The miner wallet sends `atomic` to `address`; the tx hash.
    pub fn send(&self, address: &str, atomic: u64) -> Result<String, String> {
        let miner = self.miner()?;
        miner.refresh()?;
        let r = miner.call(
            "transfer",
            serde_json::json!({ "destinations": [{ "amount": atomic, "address": address }], "account_index": 0, "priority": 1, "get_tx_key": false }),
        )?;
        r["tx_hash"].as_str().map(|s| s.to_string()).ok_or_else(|| "transfer: no tx_hash".to_string())
    }

    /// A fresh subaddress in the miner wallet — the redeemer's, so the miner wallet reports the arrival.
    pub fn fresh_address(&self) -> Result<String, String> {
        let miner = self.miner()?;
        let r = miner.call("create_address", serde_json::json!({ "account_index": 0 }))?;
        r["address"].as_str().map(|s| s.to_string()).ok_or_else(|| "create_address: no address".to_string())
    }

    /// Atomic units the miner wallet has received at `address` with at least `min_confirmations`.
    pub fn received_atomic(&self, address: &str, min_confirmations: u64) -> u64 {
        let Ok(miner) = self.miner() else { return 0 };
        if miner.refresh().is_err() {
            return 0;
        }
        let Ok(r) = miner.call("get_transfers", serde_json::json!({ "in": true, "pool": false, "account_index": 0 })) else { return 0 };
        let mut total = 0u64;
        if let Some(list) = r["in"].as_array() {
            for t in list {
                let to = t["address"].as_str();
                let confs = t["confirmations"].as_u64();
                let amount = t["amount"].as_u64();
                if let (Some(to), Some(confs), Some(amount)) = (to, confs, amount) {
                    if to == address && confs >= min_confirmations {
                        total = total.saturating_add(amount);
                    }
                }
            }
        }
        total
    }
}

impl Drop for MoneroRegtest {
    fn drop(&mut self) {
        // kill by PID only — every process this driver started wrote its own pidfile
        let mut pids: Vec<PathBuf> = vec![self.root.join("monerod.pid"), self.root.join("miner").join("wallet-rpc.pid")];
        for d in &self.custodian_dirs {
            pids.push(d.join("wallet-rpc.pid"));
        }
        if let Some(d) = DaemonRpc::at(&self.daemon_url()) {
            let _ = d.call("stop_daemon", serde_json::json!({}));
        }
        for p in pids {
            if let Ok(s) = std::fs::read_to_string(&p) {
                if let Ok(pid) = s.trim().parse::<i32>() {
                    let _ = Command::new("kill").arg(pid.to_string()).status();
                }
            }
        }
        std::thread::sleep(Duration::from_millis(1500));
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

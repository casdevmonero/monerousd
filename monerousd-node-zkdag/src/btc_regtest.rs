// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! DB-121 (2026-09-21) — A REAL BITCOIN CORE (regtest) A TEST RAISES, so the peg's two external legs are judged
//! by Bitcoin itself: a deposit is a coin Core mined and sent to the reserve address, and a redeem is the BTC
//! ARRIVING at the redeemer's address in Core's wallet. This is EXTERNAL-CHAIN code: Bitcoin Core needs a
//! datadir on disk by its own construction, so the driver keeps one throwaway directory under the system temp
//! dir for the life of one test process (removed at drop) — never the operator's Bitcoin datadir.
//! `-daemonwait` makes readiness Core's own verdict; no readiness poll of ours stands between us and it.
//! Compiled only for tests and the `bridge-test-oracle` feature — absent from a release daemon.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

pub struct RegtestCore {
    dir: PathBuf,
    pub port: u16,
    bin_dir: String,
    miner: String,
}

impl RegtestCore {
    /// Starts Core on a PID-derived RPC port, creates the wallet `w`, mines 101 blocks so the first subsidy
    /// (100 confirmations) is spendable: the wallet holds 50 BTC.
    pub fn start(tag: &str) -> Result<RegtestCore, String> {
        let bin_dir = match std::env::var("MONEROUSD_BITCOIN_BIN_DIR") {
            Ok(d) if !d.is_empty() => d,
            _ => "/opt/homebrew/bin".to_string(),
        };
        // 2026-10-27: a per-instance block (test_ports) — two Cores of one process never share a port or a datadir.
        let block = crate::test_ports::reserve(39000, 2)?;
        let port = block.first;
        let dir = std::env::temp_dir().join(format!("usdmd_journey_btc_{tag}_{}_{}", std::process::id(), block.instance));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("regtest datadir: {e}"))?;
        let st = Command::new(format!("{bin_dir}/bitcoind"))
            .args([
                "-regtest",
                &format!("-datadir={}", dir.display()),
                &format!("-rpcport={port}"),
                &format!("-port={}", port + 1),
                "-listen=0",
                "-server=1",
                "-txindex=1",
                "-rpcuser=u",
                "-rpcpassword=p",
                "-daemonwait",
            ])
            .status()
            .map_err(|e| format!("bitcoind did not start: {e}"))?;
        if !st.success() {
            return Err(format!("bitcoind -daemonwait reported a failed start on rpcport {port}: {}", init_error(&dir)));
        }
        let mut me = RegtestCore { dir, port, bin_dir, miner: String::new() };
        if me.cli(false, &["createwallet", "w"]).is_none() {
            return Err("createwallet failed".into());
        }
        me.miner = match me.cli(true, &["getnewaddress", "", "bech32m"]) {
            Some(a) => a,
            None => return Err("getnewaddress failed".into()),
        };
        me.mine(101)?;
        Ok(me)
    }

    /// One `bitcoin-cli` call; `wallet` routes it to the wallet `w`. `None` = Core refused it (the refusal is logged).
    pub fn cli(&self, wallet: bool, args: &[&str]) -> Option<String> {
        let mut c = Command::new(format!("{}/bitcoin-cli", self.bin_dir));
        c.args([
            "-regtest",
            &format!("-datadir={}", self.dir.display()),
            &format!("-rpcport={}", self.port),
            "-rpcuser=u",
            "-rpcpassword=p",
        ]);
        if wallet {
            c.arg("-rpcwallet=w");
        }
        let out = c.args(args).output().ok()?;
        if !out.status.success() {
            eprintln!(
                "[regtest] bitcoin-cli {args:?} refused: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Mines `blocks` to the wallet's own miner address.
    pub fn mine(&self, blocks: u64) -> Result<(), String> {
        match self.cli(true, &["generatetoaddress", &blocks.to_string(), &self.miner]) {
            Some(_) => Ok(()),
            None => Err("generatetoaddress failed".into()),
        }
    }

    /// Core's wallet sends `btc` (a decimal string) to `address`; the txid.
    pub fn send(&self, address: &str, btc: &str) -> Result<String, String> {
        match self.cli(
            true,
            &["-named", "sendtoaddress", &format!("address={address}"), &format!("amount={btc}"), "fee_rate=25"],
        ) {
            Some(txid) => Ok(txid),
            None => Err("sendtoaddress failed".into()),
        }
    }

    /// A fresh bech32m address in Core's wallet — the redeemer's, so Core reports the arrival.
    pub fn fresh_address(&self) -> Result<String, String> {
        match self.cli(true, &["getnewaddress", "", "bech32m"]) {
            Some(a) => Ok(a),
            None => Err("getnewaddress failed".into()),
        }
    }

    /// Sats `address` has received with at least one confirmation, as Core's wallet counts them.
    pub fn received_sats(&self, address: &str) -> u64 {
        match self.cli(true, &["getreceivedbyaddress", address, "1"]) {
            Some(s) => match s.parse::<f64>() {
                Ok(btc) => (btc * 1e8).round() as u64,
                Err(_) => 0,
            },
            None => 0,
        }
    }

    pub fn height(&self) -> u64 {
        match self.cli(false, &["getblockcount"]) {
            Some(s) => match s.parse::<u64>() {
                Ok(h) => h,
                Err(_) => 0,
            },
            None => 0,
        }
    }
}

/// Core's own reason for a failed start: the last `Error` lines of `regtest/debug.log` (the message `-daemonwait`
/// points at), so the verdict names the cause instead of "check debug.log".
fn init_error(dir: &std::path::Path) -> String {
    match std::fs::read_to_string(dir.join("regtest").join("debug.log")) {
        Ok(log) => {
            let errs: Vec<&str> = log.lines().filter(|l| l.contains("Error") || l.contains("error")).collect();
            match errs.len() {
                0 => "debug.log names no error".to_string(),
                n => errs[n.saturating_sub(3)..].join(" | "),
            }
        }
        Err(e) => format!("no regtest/debug.log ({e})"),
    }
}

impl Drop for RegtestCore {
    fn drop(&mut self) {
        let _ = self.cli(false, &["stop"]);
        std::thread::sleep(Duration::from_millis(1500));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod pins {
    use super::RegtestCore;

    /// RED 2026-10-27 before test_ports: the second Core of one process took the first one's PID-derived rpcport and
    /// `-daemonwait` reported "Error during initialization" (certify chunk84 of 2026-10-26; PegIn / PegOut measured
    /// nothing). Two Cores raised in one process must both serve, each on its own port.
    #[test]
    fn two_regtest_cores_raised_in_one_process_serve_on_distinct_ports() {
        let a = RegtestCore::start("pin_a").unwrap_or_else(|e| panic!("first Core: {e}"));
        let b = RegtestCore::start("pin_b").unwrap_or_else(|e| panic!("second Core beside the first: {e}"));
        assert_ne!(a.port, b.port, "two Cores of one process on one rpcport");
        assert_eq!((a.height(), b.height()), (101, 101), "both Cores serve their own chain");
    }
}

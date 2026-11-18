// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! DB-121x — THE CUSTODIAN'S OWN MONERO WALLET, over its JSON-RPC (EXTERNAL-CHAIN code, the Monero twin of the
//! Bitcoin Core source in `btc_watch`).
//!
//! Monero admits exactly one k-of-n custody primitive: its own multisig, implemented in `monero-wallet-rpc`. A
//! custodian node therefore runs ITS OWN wallet-rpc (this machine, or a .onion it operates) and drives it here: the
//! key-exchange rounds that form the k-of-n wallet, the deposit reads, the export/import of multisig state, the
//! sequential `sign_multisig` round and `submit_multisig`. No Monero cryptography is re-derived in this tree — the
//! wallet does it; this module only speaks its RPC. Every call is fail-closed: an unanswered or refused call, or an
//! answer missing the field a decision rests on, is `Err` — never a default that reads as a figure.
//!
//! A user is never asked to run any of this: a node WITHOUT a wallet-rpc still serves Monero deposit addresses
//! (from the custody set's signed announcements, `xmr_custody`) and still requests mints and redeems; only the
//! bonded custodians confirm deposits and sign payouts, from their own wallets.
//!
//! MEASURED 2026-09-21 against Monero v0.18.4.6 (`xmr_multisig_probe.sh`): a 2-of-3 set formed by
//! `prepare_multisig` → `make_multisig` → two `exchange_multisig_keys` rounds (message passing only), received a
//! deposit at an integrated address (payment id read back with its confirmations), and paid out with
//! `transfer(do_not_relay)` → `sign_multisig` → `submit_multisig`; the redeemer's wallet saw the exact amount
//! confirmed. Two facts of this build the code below carries: multisig SPENDING is off until the wallet CLI writes
//! `set enable-multisig-experimental 1` into the wallet's keys file (there is no RPC for it), and a wallet talking
//! to a regtest daemon needs `--allow-mismatched-daemon-version` (an operator flag, not ours).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

/// One Monero = 1e12 atomic units (piconero) — Monero's own unit.
pub const XMR_ATOMIC_PER_XMR: u64 = 1_000_000_000_000;

/// The Monero wallet-rpc this custodian owns.
pub struct WalletRpc {
    kind: WalletKind,
}

/// Where a wallet-rpc answers from: the custodian's own `monero-wallet-rpc` over JSON-RPC, or — in a pin or a netsim
/// journey only, never in a release daemon — the simulator's in-process Monero (`xmr_sim`, one wallet per
/// `from_env`), so every caller drives the same surface unchanged.
enum WalletKind {
    Http { url: String, agent: ureq::Agent },
    #[cfg(any(test, feature = "bridge-test-oracle"))]
    Sim(crate::xmr_sim::SimWallet),
}

/// One incoming transfer as the wallet reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    pub txid: String,
    pub amount: u64,
    pub payment_id: String,
    pub confirmations: u64,
}

/// One recipient of a multisig transaction set, as the wallet describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub address: String,
    pub amount: u64,
}

/// Where a URL may point: this machine, or a Tor hidden service this node reaches through its own SOCKS route.
/// A clearnet host is refused — a custodian's wallet-rpc is never reached over the open internet.
/// ONE rule for every foreign-chain source a custodian runs (the Ethereum source reads it too, `eth_rpc`).
pub(crate) fn private_url_ok(url: &str) -> bool {
    let rest = match url.strip_prefix("http://").or_else(|| url.strip_prefix("https://")) {
        Some(r) => r,
        None => return false,
    };
    let host = match rest.split('/').next() {
        Some(h) => h,
        None => return false,
    };
    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };
    host == "127.0.0.1" || host == "localhost" || host == "[::1]" || host == "::1" || host.ends_with(".onion")
}

pub(crate) fn agent_for(url: &str) -> Option<ureq::Agent> {
    let mut b = ureq::AgentBuilder::new().timeout(Duration::from_secs(120));
    if url.contains(".onion") {
        let socks = match std::env::var("MONEROUSD_TOR_SOCKS") {
            Ok(s) if !s.is_empty() => s,
            _ => {
                eprintln!("[custody-rpc] ⛔ a custodian's foreign-chain RPC URL is a .onion but MONEROUSD_TOR_SOCKS is unset — no private route, so that chain's leg stays off");
                return None;
            }
        };
        // `socks5` in ureq resolves the host through the proxy, which is what a hidden service needs.
        let proxy = ureq::Proxy::new(format!("socks5://{socks}")).ok()?;
        b = b.proxy(proxy);
    }
    Some(b.build())
}

/// Each incoming transfer of a wallet's answers: its txid, payment id and confirmations from the transfer record
/// (`get_transfers`), and its AMOUNT from the wallet's own outputs in that transaction (`incoming_transfers`, every one,
/// spent or not) — the outputs the balance counts.
/// ⛔ A multisig wallet that has not imported every member's latest state records an incoming transfer's amount as 0
/// (`get_transfers` and `get_payments` alike) while its outputs and its balance hold the coin.
/// ROOT-LAYER: this is the one read every Monero deposit check takes its amount from (`xmr_watch::sweep_once`); the
/// record's 0 is produced by the wallet's multisig sync state, the outputs' amount by the coin itself.
/// MEASURED: before (2026-11-09, real nodes, launch_trade.py round 14) custodian 0's wallet, multisig_import_needed, read
/// the 1 XMR deposit as 0 for 35+ min at 133 confirmations while its outputs and balance held 1 XMR, so its node never
/// confirmed the deposit and the mint never had its second custodian -> after: the next real-node run of the check.
/// MUST-STAY-GREEN: the payment id and confirmations still come from the record (the watcher's matching and maturity are
/// unchanged); a transaction with no output in the list counts 0, so the deposit stays unconfirmed (fail-closed).
fn incoming_from(transfers: &Value, outputs: &Value) -> Result<Vec<Incoming>, String> {
    let mut held: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    // A wallet with no outputs answers with no `transfers` list at all.
    for o in outputs["transfers"].as_array().into_iter().flatten() {
        let tx = field_str(o, "tx_hash", "incoming_transfers")?;
        let a = field_u64(o, "amount", "incoming_transfers")?;
        let slot = held.entry(tx).or_insert(0);
        *slot = slot.saturating_add(a);
    }
    let mut out = Vec::new();
    // A wallet with no incoming transfers answers with no `in` list at all.
    for t in transfers["in"].as_array().into_iter().flatten() {
        let txid = field_str(t, "txid", "get_transfers")?;
        out.push(Incoming {
            amount: held.get(&txid).copied().unwrap_or(0),
            payment_id: field_str(t, "payment_id", "get_transfers")?,
            confirmations: field_u64(t, "confirmations", "get_transfers")?,
            txid,
        });
    }
    Ok(out)
}

fn field_u64(v: &Value, key: &str, method: &str) -> Result<u64, String> {
    v[key].as_u64().ok_or_else(|| format!("{method}: the answer carries no `{key}`"))
}

fn field_str(v: &Value, key: &str, method: &str) -> Result<String, String> {
    v[key].as_str().map(|s| s.to_string()).ok_or_else(|| format!("{method}: the answer carries no `{key}`"))
}

/// A string list that may legitimately be absent (a multisig set before it is complete has no tx hashes).
fn str_list(v: &Value, key: &str) -> Vec<String> {
    match v[key].as_array() {
        Some(a) => a.iter().filter_map(|h| h.as_str().map(|s| s.to_string())).collect(),
        None => Vec::new(),
    }
}

impl WalletRpc {
    /// The wallet-rpc named by `MONEROUSD_XMR_WALLET_RPC_URL` (this machine or a .onion), or `None` when this node
    /// has no Monero leg configured.
    pub fn from_env() -> Option<WalletRpc> {
        // §NETSIM-LAUNCH: an installed simulated Monero answers every wallet call; each `from_env` opens one more
        // wallet on it (the custody lane calls it once per node and keeps the handle).
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let Some(chain) = crate::xmr_sim::installed() {
            return Some(WalletRpc { kind: WalletKind::Sim(crate::xmr_sim::SimWallet::open(chain)) });
        }
        let url = match std::env::var("MONEROUSD_XMR_WALLET_RPC_URL") {
            Ok(u) if !u.trim().is_empty() => u.trim().trim_end_matches('/').to_string(),
            // §22 6: no operator wallet named — the node's own supervised custody wallet (custodians only)
            _ => return WalletRpc::at(&crate::xmr_supervisor::wallet_url()?),
        };
        if !private_url_ok(&url) {
            eprintln!("[xmr-rpc] ⛔ MONEROUSD_XMR_WALLET_RPC_URL names a clearnet host — a custodian's wallet-rpc is this machine (127.0.0.1) or a .onion only; ignoring it");
            return None;
        }
        let agent = agent_for(&url)?;
        Some(WalletRpc { kind: WalletKind::Http { url, agent } })
    }

    pub fn at(url: &str) -> Option<WalletRpc> {
        let url = url.trim().trim_end_matches('/').to_string();
        if !private_url_ok(&url) {
            return None;
        }
        let agent = agent_for(&url)?;
        Some(WalletRpc { kind: WalletKind::Http { url, agent } })
    }

    /// One JSON-RPC 2.0 call; a wallet error is `Err(message)`, a transport failure too.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let (url, agent) = match &self.kind {
            WalletKind::Http { url, agent } => (url, agent),
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            WalletKind::Sim(_) => return Err(format!("{method}: the simulated wallet speaks no raw JSON-RPC")),
        };
        let body = json!({ "jsonrpc": "2.0", "id": "usdmd", "method": method, "params": params });
        let resp = agent
            .post(&format!("{url}/json_rpc"))
            .set("Content-Type", "application/json")
            .send_string(&body.to_string());
        let v: Value = match resp {
            Ok(r) => r.into_json().map_err(|e| format!("{method}: unreadable answer: {e}"))?,
            Err(ureq::Error::Status(code, r)) => {
                let text = match r.into_string() {
                    Ok(t) => t,
                    Err(_) => String::new(),
                };
                return Err(format!("{method}: HTTP {code}: {}", text.trim()));
            }
            Err(e) => return Err(format!("{method}: no answer from the wallet-rpc: {e}")),
        };
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(format!("{method}: wallet error {}: {}", err["code"], err["message"]));
        }
        Ok(v["result"].clone())
    }

    pub fn get_version(&self) -> Result<u64, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.get_version();
        }
        let r = self.call("get_version", json!({}))?;
        field_u64(&r, "version", "get_version")
    }

    /// Opens the wallet `name` (its file lives in the wallet-rpc's own directory); creates it when it does not
    /// exist yet. `Ok(true)` when it was created just now.
    /// A simulated wallet has no keys file and no switch to write.
    #[must_use]
    pub fn is_simulated(&self) -> bool {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if matches!(self.kind, WalletKind::Sim(_)) {
            return true;
        }
        false
    }

    pub fn open_or_create(&self, name: &str, password: &str) -> Result<bool, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.open_or_create(name, password);
        }
        match self.call("open_wallet", json!({ "filename": name, "password": password })) {
            Ok(_) => return Ok(false),
            // Monero answers a missing wallet file with error -1 "Failed to open wallet"; anything else is a real fault.
            Err(e) if e.contains("Failed to open wallet") => {}
            Err(e) => return Err(e),
        }
        self.call("create_wallet", json!({ "filename": name, "password": password, "language": "English" }))?;
        Ok(true)
    }

    pub fn close(&self) -> Result<(), String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.close();
        }
        self.call("close_wallet", json!({})).map(|_| ())
    }

    pub fn address(&self) -> Result<String, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.address();
        }
        let r = self.call("get_address", json!({ "account_index": 0 }))?;
        field_str(&r, "address", "get_address")
    }

    /// (is multisig, ready, threshold, total)
    pub fn is_multisig(&self) -> Result<(bool, bool, u32, u32), String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.is_multisig();
        }
        let r = self.call("is_multisig", json!({}))?;
        let multisig = r["multisig"].as_bool().ok_or("is_multisig: no `multisig`")?;
        if !multisig {
            return Ok((false, false, 0, 0));
        }
        Ok((
            true,
            r["ready"].as_bool().ok_or("is_multisig: no `ready`")?,
            field_u64(&r, "threshold", "is_multisig")? as u32,
            field_u64(&r, "total", "is_multisig")? as u32,
        ))
    }

    pub fn prepare_multisig(&self) -> Result<String, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.prepare_multisig();
        }
        let r = self.call("prepare_multisig", json!({}))?;
        field_str(&r, "multisig_info", "prepare_multisig")
    }

    /// The first key-exchange round: the OTHER members' prepared infos and the threshold. Returns this wallet's
    /// next-round info (empty once the wallet is final).
    pub fn make_multisig(&self, others: &[String], threshold: u32, password: &str) -> Result<String, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.make_multisig(others, threshold);
        }
        let r = self.call("make_multisig", json!({ "multisig_info": others, "threshold": threshold, "password": password }))?;
        Ok(match r["multisig_info"].as_str() {
            Some(s) => s.to_string(),
            None => String::new(), // a final wallet returns no next-round info
        })
    }

    /// A further key-exchange round with the OTHER members' current infos; the next-round info (empty when final).
    pub fn exchange_multisig_keys(&self, others: &[String], password: &str) -> Result<String, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.exchange_multisig_keys(others);
        }
        let r = self.call("exchange_multisig_keys", json!({ "multisig_info": others, "password": password }))?;
        Ok(match r["multisig_info"].as_str() {
            Some(s) => s.to_string(),
            None => String::new(),
        })
    }

    pub fn export_multisig_info(&self) -> Result<String, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.export_multisig_info();
        }
        let r = self.call("export_multisig_info", json!({}))?;
        field_str(&r, "info", "export_multisig_info")
    }

    /// Imports the OTHER members' exported multisig state; the number of outputs the wallet can now account for.
    pub fn import_multisig_info(&self, infos: &[String]) -> Result<u64, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.import_multisig_info(infos);
        }
        let r = self.call("import_multisig_info", json!({ "info": infos }))?;
        field_u64(&r, "n_outputs", "import_multisig_info")
    }

    pub fn refresh(&self) -> Result<(), String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.refresh();
        }
        self.call("refresh", json!({})).map(|_| ())
    }

    /// (balance, unlocked, multisig import needed)
    pub fn balance(&self) -> Result<(u64, u64, bool), String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.balance();
        }
        let r = self.call("get_balance", json!({ "account_index": 0 }))?;
        Ok((
            field_u64(&r, "balance", "get_balance")?,
            field_u64(&r, "unlocked_balance", "get_balance")?,
            r["multisig_import_needed"].as_bool().ok_or("get_balance: no `multisig_import_needed`")?,
        ))
    }

    /// Every confirmed incoming transfer to this wallet (the pool is excluded: a deposit counts when mined).
    pub fn incoming(&self) -> Result<Vec<Incoming>, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.incoming();
        }
        let r = self.call("get_transfers", json!({ "in": true, "pool": false, "account_index": 0 }))?;
        let outputs = self.call("incoming_transfers", json!({ "transfer_type": "all", "account_index": 0 }))?;
        incoming_from(&r, &outputs)
    }

    /// Builds — never relays — a multisig transaction paying `destinations` at the default priority; the partially
    /// signed multisig transaction set the other custodians sign.
    pub fn transfer_multisig(&self, destinations: &[(String, u64)]) -> Result<String, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.transfer_multisig(destinations);
        }
        let dests: Vec<Value> = destinations.iter().map(|(a, v)| json!({ "address": a, "amount": v })).collect();
        // ⛔ the fee comes out of the payouts — the wallet-rpc's own `subtract_fee_from_outputs` — never out of the reserve: the
        // custody wallet then falls by EXACTLY the releases Monero's ledger committed, so it can never drift below that reserve
        let every: Vec<usize> = (0..destinations.len()).collect();
        let r = self.call(
            "transfer",
            json!({ "destinations": dests, "account_index": 0, "priority": 1, "do_not_relay": true, "get_tx_hex": false, "subtract_fee_from_outputs": every }),
        )?;
        match r["multisig_txset"].as_str() {
            Some(s) if !s.is_empty() => Ok(s.to_string()),
            _ => Err("transfer: the wallet returned no multisig transaction set".to_string()),
        }
    }

    /// A ONE-custodian set is a plain wallet: builds AND relays the payment; the tx hash. (A single bonded founder is
    /// the day-one shape; the moment a second seat bonds the set forms a real multisig wallet.)
    pub fn transfer_relay(&self, destinations: &[(String, u64)]) -> Result<String, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.transfer_relay(destinations);
        }
        let dests: Vec<Value> = destinations.iter().map(|(a, v)| json!({ "address": a, "amount": v })).collect();
        let every: Vec<usize> = (0..destinations.len()).collect(); // the fee from the payouts, as `transfer_multisig`
        let r = self.call("transfer", json!({ "destinations": dests, "account_index": 0, "priority": 1, "get_tx_key": false, "subtract_fee_from_outputs": every }))?;
        field_str(&r, "tx_hash", "transfer")
    }

    /// What a multisig transaction set PAYS, read by this wallet: recipients (change excluded) and the fee.
    pub fn describe_multisig(&self, txset: &str) -> Result<(Vec<Recipient>, u64), String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.describe_multisig(txset);
        }
        let r = self.call("describe_transfer", json!({ "multisig_txset": txset }))?;
        let descs = r["desc"].as_array().ok_or("describe_transfer: no `desc`")?;
        let mut recipients = Vec::new();
        let mut fee = 0u64;
        for d in descs {
            fee = fee.saturating_add(field_u64(d, "fee", "describe_transfer")?);
            let rs = d["recipients"].as_array().ok_or("describe_transfer: no `recipients`")?;
            for x in rs {
                recipients.push(Recipient {
                    address: field_str(x, "address", "describe_transfer")?,
                    amount: field_u64(x, "amount", "describe_transfer")?,
                });
            }
        }
        Ok((recipients, fee))
    }

    /// Adds this wallet's signature; (the new set, the tx hashes — present once the set is complete).
    pub fn sign_multisig(&self, txset: &str) -> Result<(String, Vec<String>), String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.sign_multisig(txset);
        }
        let r = self.call("sign_multisig", json!({ "tx_data_hex": txset }))?;
        let set = field_str(&r, "tx_data_hex", "sign_multisig")?;
        if set.is_empty() {
            return Err("sign_multisig: the wallet returned an empty signed set".to_string());
        }
        Ok((set, str_list(&r, "tx_hash_list")))
    }

    /// Relays a fully signed set; the tx hashes.
    pub fn submit_multisig(&self, txset: &str) -> Result<Vec<String>, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.submit_multisig(txset);
        }
        let r = self.call("submit_multisig", json!({ "tx_data_hex": txset }))?;
        let hashes = str_list(&r, "tx_hash_list");
        if hashes.is_empty() {
            return Err("submit_multisig: the wallet relayed nothing".to_string());
        }
        Ok(hashes)
    }

    /// ⭐ SAFE AT SCALE, stage three — WHAT THIS WALLET READS OF ONE TRANSACTION (`get_transfer_by_txid`): `(the
    /// amount it paid this wallet, its fee, its confirmations, whether it arrived at the wallet's MAIN address with
    /// no payment id)`; `None` for a transaction this wallet does not know. A Monero fee is public, so the wallet
    /// that receives a transfer reads the same fee the sender's does — which is how a custodian that never held an
    /// old set's wallet judges the fee of a sweep out of it (`xmr_sweep::SweepLane::judge_cost`). A deposit arrives
    /// at an integrated address (a payment id); a sweep between custody wallets arrives at the main address.
    pub fn transfer_fee(&self, txid: &str) -> Result<Option<(u64, u64, u64, bool)>, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.transfer_fee(txid);
        }
        match self.call("get_transfer_by_txid", json!({ "txid": txid })) {
            Ok(r) => {
                let t = &r["transfer"];
                let incoming = t["type"].as_str() == Some("in");
                let pid = t["payment_id"].as_str().unwrap_or("");
                let plain = pid.is_empty() || pid.bytes().all(|b| b == b'0');
                let main = t["subaddr_index"]["minor"].as_u64().unwrap_or(0) == 0;
                Ok(Some((t["amount"].as_u64().unwrap_or(0), field_u64(t, "fee", "get_transfer_by_txid")?, t["confirmations"].as_u64().unwrap_or(0), incoming && plain && main)))
            }
            // Monero answers an unknown txid with error -8 "Transaction not found" — not a fault, the tx is not seen yet.
            Err(e) if e.contains("not found") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// ⭐ SAFE AT SCALE, stage three — A TRANSACTION THIS WALLET ITSELF SENT (`get_transfer_by_txid`, type `out`):
    /// `(its fee, its confirmations)`; `None` for a transaction this wallet does not know or did not send (an
    /// incoming transfer, a stranger's). How a custodian of a retiring vault judges the fee of the sweep that empties
    /// its own current wallet into the receiving vault's (`xmr_sweep::SweepLane::judge_cost`): from the wallet that
    /// spent the coins, which it holds — never from an arrival in another vault's wallet.
    pub fn sent_fee(&self, txid: &str) -> Result<Option<(u64, u64)>, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.sent_fee(txid);
        }
        match self.call("get_transfer_by_txid", json!({ "txid": txid })) {
            Ok(r) => {
                let t = &r["transfer"];
                if t["type"].as_str() != Some("out") {
                    return Ok(None); // in, pending, pool or failed: not a sent transaction the chain holds
                }
                Ok(Some((field_u64(t, "fee", "get_transfer_by_txid")?, t["confirmations"].as_u64().unwrap_or(0))))
            }
            // Monero answers an unknown txid with error -8 "Transaction not found" — not a fault, the tx is not seen yet.
            Err(e) if e.contains("not found") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Confirmations of a transaction this wallet knows (in or out); `None` when it does not know it yet.
    pub fn tx_confirmations(&self, txid: &str) -> Result<Option<u64>, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let WalletKind::Sim(w) = &self.kind {
            return w.tx_confirmations(txid);
        }
        match self.call("get_transfer_by_txid", json!({ "txid": txid })) {
            Ok(r) => Ok(r["transfer"]["confirmations"].as_u64()),
            // Monero answers an unknown txid with error -8 "Transaction not found" — not a fault, the tx is not seen yet.
            Err(e) if e.contains("not found") => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Monero's multisig SPENDING switch is a per-wallet setting only the wallet CLI writes (`set
/// enable-multisig-experimental 1`, stored in the keys file; measured 2026-09-21: wallet-rpc has neither a flag nor
/// an RPC for it in v0.18.4.6). Run once per wallet, with the wallet CLOSED in the wallet-rpc. The password travels
/// through a 0600 file the CLI reads, never the command line.
pub fn enable_multisig_via_cli(wallet_dir: &Path, name: &str, password: &str) -> Result<(), String> {
    // the wallet CLI ships where the wallet-rpc does: the operator's directory, else beside the binary the supervisor found
    let bin_dir = match std::env::var("MONEROUSD_XMR_BIN_DIR") {
        Ok(d) if !d.is_empty() => PathBuf::from(d),
        _ => crate::xmr_supervisor::find_binary()
            .and_then(|b| b.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("/opt/homebrew/bin")),
    };
    let pw_path = wallet_dir.join(format!("{name}.pw"));
    std::fs::write(&pw_path, password).map_err(|e| format!("password file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&pw_path, std::fs::Permissions::from_mode(0o600));
    }
    // The CLI opens the wallet with the password FILE, and its `set` command then asks for the password AGAIN on
    // standard input to confirm a sensitive setting (measured 2026-09-21: with stdin closed it answered "Error:
    // invalid password" on a wallet the same password opens; with the password on stdin it applied the setting).
    let net_flag = crate::xmr_supervisor::network_flag(crate::bridge::xmr_net_byte());
    let mut child = std::process::Command::new(bin_dir.join("monero-wallet-cli"))
        .args(net_flag)
        .arg("--wallet-file")
        .arg(wallet_dir.join(name))
        .arg("--password-file")
        .arg(&pw_path)
        .arg("--offline")
        .arg("--log-file")
        .arg(wallet_dir.join(format!("{name}.cli.log")))
        .arg("--log-level")
        .arg("0")
        .arg("--command")
        .arg("set")
        .arg("enable-multisig-experimental")
        .arg("1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("monero-wallet-cli did not run: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(format!("{password}\n").as_bytes());
    }
    let mut text = String::new();
    {
        use std::io::Read;
        if let Some(mut so) = child.stdout.take() {
            let _ = so.read_to_string(&mut text);
        }
        if let Some(mut se) = child.stderr.take() {
            let _ = se.read_to_string(&mut text);
        }
    }
    let status = child.wait();
    let _ = std::fs::remove_file(&pw_path);
    let status = status.map_err(|e| format!("monero-wallet-cli did not finish: {e}"))?;
    if !status.success() || text.contains("Error") {
        let tail: String = text.trim().chars().rev().take(300).collect::<Vec<char>>().into_iter().rev().collect();
        return Err(format!("monero-wallet-cli refused the multisig setting: {tail}"));
    }
    Ok(())
}

/// The Monero daemon a custodian's wallet follows (`MONEROUSD_XMR_DAEMON_URL`, this machine or a .onion) — read
/// for the fee reference the signers judge a proposal's fee against.
pub struct DaemonRpc {
    kind: DaemonKind,
}

enum DaemonKind {
    Http { url: String, agent: ureq::Agent },
    #[cfg(any(test, feature = "bridge-test-oracle"))]
    Sim(crate::xmr_sim::SimDaemon),
}

impl DaemonRpc {
    /// A daemon at `url` (this machine or a .onion), for a test driver that raised it.
    pub fn at(url: &str) -> Option<DaemonRpc> {
        let url = url.trim().trim_end_matches('/').to_string();
        if !private_url_ok(&url) {
            return None;
        }
        let agent = agent_for(&url)?;
        Some(DaemonRpc { kind: DaemonKind::Http { url, agent } })
    }

    pub fn from_env() -> Option<DaemonRpc> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let Some(chain) = crate::xmr_sim::installed() {
            return Some(DaemonRpc { kind: DaemonKind::Sim(crate::xmr_sim::SimDaemon::new(chain)) });
        }
        let url = match std::env::var("MONEROUSD_XMR_DAEMON_URL") {
            Ok(u) if !u.trim().is_empty() => u.trim().trim_end_matches('/').to_string(),
            // §22 6: no operator daemon named — an onion daemon of the cross-check set (no Monero node on this machine)
            _ => crate::xmr_supervisor::reference_daemon()?.trim_end_matches('/').to_string(),
        };
        if !private_url_ok(&url) {
            eprintln!("[xmr-rpc] ⛔ MONEROUSD_XMR_DAEMON_URL names a clearnet host — this machine or a .onion only; ignoring it");
            return None;
        }
        let agent = agent_for(&url)?;
        Some(DaemonRpc { kind: DaemonKind::Http { url, agent } })
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let (url, agent) = match &self.kind {
            DaemonKind::Http { url, agent } => (url, agent),
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            DaemonKind::Sim(_) => return Err(format!("{method}: the simulated daemon speaks no raw JSON-RPC")),
        };
        let body = json!({ "jsonrpc": "2.0", "id": "usdmd", "method": method, "params": params });
        let v: Value = agent
            .post(&format!("{url}/json_rpc"))
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| format!("{method}: no answer from the daemon: {e}"))?
            .into_json()
            .map_err(|e| format!("{method}: unreadable answer: {e}"))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(format!("{method}: daemon error {}: {}", err["code"], err["message"]));
        }
        Ok(v["result"].clone())
    }

    /// The daemon's fee estimate in atomic units per byte at the default priority.
    pub fn fee_per_byte(&self) -> Result<u64, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let DaemonKind::Sim(w) = &self.kind {
            return w.fee_per_byte();
        }
        let r = self.call("get_fee_estimate", json!({}))?;
        match r["fee"].as_u64() {
            Some(f) if f > 0 => Ok(f),
            _ => Err("get_fee_estimate: no fee".to_string()),
        }
    }

    pub fn height(&self) -> Result<u64, String> {
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let DaemonKind::Sim(w) = &self.kind {
            return w.height();
        }
        let r = self.call("get_block_count", json!({}))?;
        field_u64(&r, "count", "get_block_count")
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// A deposit's amount comes from the wallet's own outputs, so a multisig wallet that still needs a member's state reads
    /// the coin it holds; a transaction it holds no output of counts nothing. The shapes are the ones custodian 0's
    /// wallet-rpc answered on 2026-11-09 (record amount 0, output amount 1 XMR, multisig_import_needed).
    #[test]
    fn a_deposit_reads_its_amount_from_the_wallets_outputs_not_the_transfer_record() {
        let transfers = json!({ "in": [
            { "txid": "aa", "amount": 0, "payment_id": "112c1017b6edfe49", "confirmations": 133 },
            { "txid": "bb", "amount": 5, "payment_id": "00", "confirmations": 1 },
        ]});
        let outputs = json!({ "transfers": [
            { "tx_hash": "aa", "amount": 600_000_000_000u64 },
            { "tx_hash": "aa", "amount": 400_000_000_000u64 },
        ]});
        let got = incoming_from(&transfers, &outputs).expect("parses");
        assert_eq!(got[0].amount, 1_000_000_000_000, "⛔ the deposit read the record's 0 instead of the coin the wallet holds");
        assert_eq!((got[0].payment_id.as_str(), got[0].confirmations), ("112c1017b6edfe49", 133), "the record's id and depth stand");
        assert_eq!(got[1].amount, 0, "a transaction the wallet holds no output of counts nothing (fail-closed)");
        assert!(incoming_from(&json!({}), &json!({})).expect("an empty wallet parses").is_empty());
    }

    #[test]
    fn only_this_machine_or_an_onion_is_a_monero_rpc() {
        assert!(private_url_ok("http://127.0.0.1:18083"));
        assert!(private_url_ok("http://localhost:18083/"));
        assert!(private_url_ok("http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion:18083"));
        assert!(!private_url_ok("http://10.0.0.5:18083"));
        assert!(!private_url_ok("http://wallet.example.com:18083"));
        assert!(!private_url_ok("127.0.0.1:18083"));
    }
}

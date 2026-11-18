// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ THE CUSTODIAN'S OWN ETHEREUM SOURCE, over its JSON-RPC (EXTERNAL-CHAIN code: the Ethereum twin of the Bitcoin
//! source in `btc_watch` and the Monero wallet in `xmr_rpc`; docs/BRIDGE-MORE-COINS-SPEC-20261110.md §3.1, §8).
//!
//! WHAT THIS IS. A custodian that custodies ether runs ITS OWN Ethereum node (this machine, or a .onion it operates)
//! and reads it here: what a deposit's one-time address holds, what the vault contract says of itself (its signer
//! set's hash, its epoch, whether a payout id is paid), the fee Ethereum asks now, and whether a transaction it sent
//! is in a block Ethereum has made final. It also hands Ethereum a signed transaction. No Ethereum cryptography or
//! state is re-derived from an answer: an answer is a READING by this custodian of its own source, and it decides
//! only what THIS custodian attests or signs. What mints or pays is two thirds of the vault's bond agreeing, each
//! from its own source (`peg_attest`, the payout lane).
//!
//! THE SETTLEMENT RULE IS ETHEREUM'S OWN: every read that a mint or a release rests on is asked at the `finalized`
//! tag (the block Ethereum's own consensus has made final), never at `latest`. A deposit seen only at `latest` is
//! not a deposit yet; a payout mined and not final is not released yet (flash-loan guards F2 and F5 of `btc_payout`,
//! by the same rule on this chain).
//!
//! FAIL CLOSED: an unanswered call, an RPC error, or an answer missing or malformed in the field a decision rests on
//! is `Err`, never a default that reads as a figure (a missing balance is not zero; a missing `paid` is not false).
//!
//! PRIVATE BY CONSTRUCTION: the source is this machine or a .onion reached through this node's own Tor route
//! (`xmr_rpc::private_url_ok`, the one rule for every foreign-chain source). A clearnet URL is refused: asking a
//! public endpoint about one-time deposit addresses would hand it the bridge's deposits one by one.
//! A user is never asked to run any of this: a node that is not a custodian of ether runs no Ethereum source and
//! still derives deposit addresses (`eth_vault::deposit_address`, a pure function).
//!
//! §9.6 (this is a source, not a door): nothing read here enters consensus state. A reading becomes a mint only
//! through the existing deposit door on two thirds of bond; it becomes a payout only inside the vault contract on the
//! signed weight of the custody set.
//! SCALE (question 7): one small request per reading; a custodian's readings grow with ITS vault's deposits and
//! payouts in flight (each bounded by `eth_vault`'s batch bounds per call), never with the bonded set or height.
//! AI RESISTANT (question 8): (c) one machine, deliberately: a custodian's own source can lie only to that custodian,
//! and one custodian's word mints and pays nothing. A source that lies to a quorum is two thirds of a vault's bond
//! reading compromised nodes, bounded by that vault's bond cover.
//! BORROWED: THORChain's Bifrost chain clients (each node observes the external chain itself; the network acts on
//! agreement); Ethereum's `finalized` block tag (EIP-1898 default block parameter, the merge's finality).
//! Cons, quantified: a custodian of ether runs one more daemon (an Ethereum node, or a light client that verifies
//! finality, about 1 GB of state for a light client); none for any other node.

use std::time::Duration;

use serde_json::{json, Value};

use crate::eth_vault::{keccak, Address};

/// The Ethereum node this custodian owns.
pub struct EthRpc {
    url: String,
    agent: ureq::Agent,
}

/// What the vault contract says of itself at the finalized block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultState {
    /// `signerSetHash()`: the one word the vault keeps for its custody set.
    pub signer_set_hash: [u8; 32],
    /// `epoch()`: how many hand-overs there have been.
    pub epoch: u64,
    /// The vault's ether (wei).
    pub balance_wei: u128,
    /// `owedTotal()`: ether set aside for recipients that could not be paid; not the vault's to spend.
    pub owed_total_wei: u128,
}

/// A mined transaction as its receipt reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Did the call succeed (`status` 1)? A reverted call moved nothing.
    pub success: bool,
    pub block_number: u64,
    pub gas_used: u64,
    /// Wei per gas the sender actually paid.
    pub effective_gas_price: u128,
}

/// `0x`-prefixed hex of bytes.
fn hex0x(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// A JSON-RPC DATA value (`0x` and an even number of hex digits) as bytes. `None` for anything else.
fn data_of(v: &Value) -> Option<Vec<u8>> {
    let h = v.as_str()?.strip_prefix("0x")?;
    if h.len() % 2 != 0 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()).collect()
}

/// A JSON-RPC QUANTITY (`0x` and one to 32 hex digits, no sign) as a number. `None` for anything else, an empty
/// quantity included: a missing figure is never zero.
fn quantity_of(v: &Value) -> Option<u128> {
    let h = v.as_str()?.strip_prefix("0x")?;
    if h.is_empty() || h.len() > 32 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(h, 16).ok()
}

/// One ABI word of a call's answer as a number; `None` unless the answer is exactly that one word and it fits.
fn word_as_u128(ret: &[u8]) -> Option<u128> {
    if ret.len() != 32 || ret[..16].iter().any(|b| *b != 0) {
        return None;
    }
    Some(u128::from_be_bytes(ret[16..].try_into().ok()?))
}

/// A view call's bytes: the selector of `signature` and its one optional word argument.
fn view_call(signature: &str, arg: Option<&[u8; 32]>) -> Vec<u8> {
    let mut d = keccak(signature.as_bytes())[..4].to_vec();
    if let Some(a) = arg {
        d.extend_from_slice(a);
    }
    d
}

impl EthRpc {
    /// The Ethereum node named by `MONEROUSD_ETH_RPC_URL` (this machine or a .onion), or `None` when this node
    /// custodies no ether. A clearnet host is refused.
    #[must_use]
    pub fn from_env() -> Option<EthRpc> {
        let url = std::env::var("MONEROUSD_ETH_RPC_URL").ok().filter(|u| !u.trim().is_empty())?;
        let at = EthRpc::at(&url);
        if at.is_none() {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed sentence to this node's own log; the URL is the operator's own setting.
            eprintln!("[eth-rpc] ⛔ MONEROUSD_ETH_RPC_URL names a clearnet host or has no private route: a custodian's Ethereum source is this machine (127.0.0.1) or a .onion only; ignoring it");
        }
        at
    }

    /// The Ethereum node at `url`, when it is this machine or a .onion this node can reach.
    #[must_use]
    pub fn at(url: &str) -> Option<EthRpc> {
        let url = url.trim().trim_end_matches('/').to_string();
        if !crate::xmr_rpc::private_url_ok(&url) {
            return None;
        }
        let agent = crate::xmr_rpc::agent_for(&url)?;
        Some(EthRpc { url, agent })
    }

    /// One JSON-RPC 2.0 call. A node error is `Err(message)`, a transport failure too, and so is an answer with no
    /// `result` field at all.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self.agent.post(&self.url).timeout(Duration::from_secs(60)).set("Content-Type", "application/json").send_string(&body.to_string());
        let v: Value = match resp {
            Ok(r) => r.into_json().map_err(|e| format!("{method}: unreadable answer: {e}"))?,
            Err(ureq::Error::Status(code, _)) => return Err(format!("{method}: HTTP {code}")),
            Err(e) => return Err(format!("{method}: no answer from the Ethereum node: {e}")),
        };
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(format!("{method}: node error {}: {}", err["code"], err["message"]));
        }
        v.get("result").cloned().ok_or_else(|| format!("{method}: the answer has no result"))
    }

    fn quantity(&self, method: &str, params: Value) -> Result<u128, String> {
        quantity_of(&self.call(method, params)?).ok_or_else(|| format!("{method}: the answer is not a quantity"))
    }

    /// The chain this node follows. Every digest a custodian signs binds it, so a node on another chain signs nothing
    /// usable on the vault's.
    pub fn chain_id(&self) -> Result<u64, String> {
        u64::try_from(self.quantity("eth_chainId", json!([]))?).map_err(|_| "eth_chainId: out of range".to_string())
    }

    /// The number of the newest block Ethereum's own consensus has made final.
    pub fn finalized_block(&self) -> Result<u64, String> {
        let b = self.call("eth_getBlockByNumber", json!(["finalized", false]))?;
        let n = quantity_of(&b["number"]).ok_or("eth_getBlockByNumber: the finalized block has no number")?;
        u64::try_from(n).map_err(|_| "eth_getBlockByNumber: out of range".to_string())
    }

    /// ⭐ WHAT AN ADDRESS HOLDS AT THE FINALIZED BLOCK (wei): the reading a deposit's attestation rests on.
    pub fn balance_finalized(&self, who: &Address) -> Result<u128, String> {
        self.quantity("eth_getBalance", json!([hex0x(who), "finalized"]))
    }

    /// The Keccak-256 of the code at `who` at the finalized block (`keccak("")` for an address with none): what a
    /// custodian compares with the vault's known runtime code before it trusts a word the contract says.
    pub fn code_hash_finalized(&self, who: &Address) -> Result<[u8; 32], String> {
        let code = data_of(&self.call("eth_getCode", json!([hex0x(who), "finalized"]))?).ok_or("eth_getCode: the answer is not data")?;
        Ok(keccak(&code))
    }

    /// A read-only call at the finalized block.
    pub fn call_finalized(&self, to: &Address, data: &[u8]) -> Result<Vec<u8>, String> {
        data_of(&self.call("eth_call", json!([{ "to": hex0x(to), "data": hex0x(data) }, "finalized"]))?).ok_or_else(|| "eth_call: the answer is not data".to_string())
    }

    /// ⭐ WHAT THE VAULT SAYS OF ITSELF AT THE FINALIZED BLOCK: its signer set's hash, its epoch, its ether and what
    /// is set aside. A custodian signs a payout or a hand-over only when these agree with what its own chain derives
    /// (`eth_vault::SignerSet::hash` at this epoch).
    pub fn vault_state(&self, vault: &Address) -> Result<VaultState, String> {
        let set = self.call_finalized(vault, &view_call("signerSetHash()", None))?;
        let signer_set_hash: [u8; 32] = set.as_slice().try_into().map_err(|_| "signerSetHash(): the answer is not one word (is this the vault?)".to_string())?;
        let epoch = word_as_u128(&self.call_finalized(vault, &view_call("epoch()", None))?).and_then(|e| u64::try_from(e).ok()).ok_or("epoch(): the answer is not a 64-bit number")?;
        let owed_total_wei = word_as_u128(&self.call_finalized(vault, &view_call("owedTotal()", None))?).ok_or("owedTotal(): the answer is not a number that fits")?;
        Ok(VaultState { signer_set_hash, epoch, balance_wei: self.balance_finalized(vault)?, owed_total_wei })
    }

    /// ⭐ HAS THE VAULT PAID THIS ID, AS OF THE FINALIZED BLOCK? The reading a payout's release rests on (F5: release
    /// is recorded on settlement, never on broadcast), and what a custodian reads before it signs an id (F4: one
    /// payout per burn; the contract's own set refuses a second).
    pub fn paid_finalized(&self, vault: &Address, id: &[u8; 32]) -> Result<bool, String> {
        match word_as_u128(&self.call_finalized(vault, &view_call("paid(bytes32)", Some(id)))?) {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err("paid(bytes32): the answer is not a boolean".to_string()),
        }
    }

    /// The fee Ethereum asks now: `(base fee per gas of the newest block, a tip per gas the node suggests)`, in wei.
    pub fn fees(&self) -> Result<(u128, u128), String> {
        let b = self.call("eth_getBlockByNumber", json!(["latest", false]))?;
        let base = quantity_of(&b["baseFeePerGas"]).ok_or("eth_getBlockByNumber: the newest block has no base fee")?;
        Ok((base, self.quantity("eth_maxPriorityFeePerGas", json!([]))?))
    }

    /// The next nonce of `who`, counting what it has already sent that is not mined yet.
    pub fn nonce_pending(&self, who: &Address) -> Result<u64, String> {
        u64::try_from(self.quantity("eth_getTransactionCount", json!([hex0x(who), "pending"]))?).map_err(|_| "eth_getTransactionCount: out of range".to_string())
    }

    /// The gas a call would use now, by the node's own estimate (a call that would revert is `Err`: it is never sent).
    pub fn estimate_gas(&self, from: &Address, to: Option<&Address>, data: &[u8], value_wei: u128) -> Result<u64, String> {
        let mut tx = json!({ "from": hex0x(from), "data": hex0x(data), "value": format!("0x{value_wei:x}") });
        if let Some(to) = to {
            tx["to"] = Value::String(hex0x(to));
        }
        u64::try_from(self.quantity("eth_estimateGas", json!([tx]))?).map_err(|_| "eth_estimateGas: out of range".to_string())
    }

    /// Hand Ethereum a signed transaction (`eth_tx::Tx1559::sign`). Returns its hash as the node names it; an answer
    /// that names another hash than the bytes' own is `Err` (the node is not carrying what was sent).
    pub fn send_raw(&self, raw: &[u8]) -> Result<[u8; 32], String> {
        let named = data_of(&self.call("eth_sendRawTransaction", json!([hex0x(raw)]))?).ok_or("eth_sendRawTransaction: the answer is not data")?;
        let own = crate::eth_tx::tx_hash(raw);
        if named.as_slice() != own {
            return Err("eth_sendRawTransaction: the node named another transaction than the one sent".to_string());
        }
        Ok(own)
    }

    /// A transaction's receipt, `None` while it is not mined.
    pub fn receipt(&self, hash: &[u8; 32]) -> Result<Option<Receipt>, String> {
        let r = self.call("eth_getTransactionReceipt", json!([hex0x(hash)]))?;
        if r.is_null() {
            return Ok(None);
        }
        let q = |k: &str| quantity_of(&r[k]).ok_or_else(|| format!("eth_getTransactionReceipt: no {k}"));
        let status = q("status")?;
        if status > 1 {
            return Err("eth_getTransactionReceipt: a status that is neither success nor failure".to_string());
        }
        Ok(Some(Receipt {
            success: status == 1,
            block_number: u64::try_from(q("blockNumber")?).map_err(|_| "eth_getTransactionReceipt: block number out of range".to_string())?,
            gas_used: u64::try_from(q("gasUsed")?).map_err(|_| "eth_getTransactionReceipt: gas out of range".to_string())?,
            effective_gas_price: q("effectiveGasPrice")?,
        }))
    }

    /// ⭐ IS THIS TRANSACTION SETTLED: mined, successful, and in a block at or under Ethereum's finalized block?
    /// `Ok(None)` while it is not mined or not final yet; `Ok(Some(false))` when it is final and REVERTED (it moved
    /// nothing); `Ok(Some(true))` when it is final and succeeded.
    pub fn settled(&self, hash: &[u8; 32]) -> Result<Option<bool>, String> {
        let Some(r) = self.receipt(hash)? else { return Ok(None) };
        if r.block_number > self.finalized_block()? {
            return Ok(None);
        }
        Ok(Some(r.success))
    }
}

#[cfg(test)]
mod eth_rpc_tests {
    use super::*;

    /// A reading is a figure or it is an error: nothing malformed or missing is ever read as zero, false or empty.
    #[test]
    fn a_missing_or_malformed_answer_is_never_a_figure() {
        assert_eq!(quantity_of(&json!("0x0")), Some(0));
        assert_eq!(quantity_of(&json!("0x1bc16d674ec80000")), Some(2_000_000_000_000_000_000));
        for bad in [json!("0x"), json!(""), json!("1bc1"), json!("0xzz"), json!(null), json!(12), json!("0x1".to_string() + &"0".repeat(32)), json!("-0x1")] {
            assert_eq!(quantity_of(&bad), None, "⛔ {bad} was read as a quantity");
        }
        assert_eq!(data_of(&json!("0x")), Some(vec![]));
        assert_eq!(data_of(&json!("0x00ff")), Some(vec![0, 255]));
        for bad in [json!("0x0"), json!("00ff"), json!("0xgg"), json!(null)] {
            assert_eq!(data_of(&bad), None, "⛔ {bad} was read as data");
        }
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(word_as_u128(&one), Some(1));
        assert_eq!(word_as_u128(&one[..31]), None, "⛔ a short answer was read as a word");
        assert_eq!(word_as_u128(&[one.as_slice(), one.as_slice()].concat()), None, "⛔ two words were read as one");
        let mut wide = [0u8; 32];
        wide[0] = 1;
        assert_eq!(word_as_u128(&wide), None, "⛔ a number above 128 bits was read as a smaller one");
    }

    /// The view calls name the vault's own functions (the selectors the contract's compiler gives them).
    #[test]
    fn a_view_call_names_the_vaults_own_function() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        // each value is `cast sig "<signature>"` (Foundry), run 2026-11-11
        assert_eq!(hex(&view_call("signerSetHash()", None)), "7b3a08ff");
        assert_eq!(hex(&view_call("epoch()", None)), "900cf0cf");
        assert_eq!(hex(&view_call("owedTotal()", None)), "fa1f0442");
        let id = [0xabu8; 32];
        let paid = view_call("paid(bytes32)", Some(&id));
        assert_eq!((hex(&paid[..4]), &paid[4..]), ("add89bb2".to_string(), &id[..]));
    }

    /// A custodian's Ethereum source is this machine or a .onion: a clearnet endpoint is refused before any request.
    #[test]
    fn a_clearnet_source_is_refused() {
        assert!(EthRpc::at("http://127.0.0.1:8545").is_some());
        assert!(EthRpc::at("https://mainnet.example.org").is_none(), "⛔ a clearnet Ethereum endpoint was taken as a custodian's source");
        assert!(EthRpc::at("http://10.0.0.5:8545").is_none(), "⛔ another machine on the network was taken as this custodian's own source");
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — §NETSIM-LAUNCH: the SIMULATED MONERO CHAIN (DB-121x sim world, lane b 2026-10-27).
//!
//! An in-process Monero with the semantics the bridge's Monero leg depends on, so every flow of that leg (a deposit
//! to a swap's INTEGRATED address seen by the custody wallet, matured by `xmr_watch::required_confirmations`, a
//! k-of-n multisig payout proposed → signed in turn → submitted, settled at Monero's 10-block lock, a reorg taking a
//! deposit back) runs inside the deterministic simulator on ITS clock — never against a `monerod` or a
//! `monero-wallet-rpc`. Installed, it is what `xmr_rpc::WalletRpc::from_env` / `DaemonRpc::from_env` hand every
//! caller (the `Sim` arm), so the deposit watcher, the custody lane's key exchange and the payout lane read and
//! drive it through their PRODUCTION code, unchanged — the Monero twin of `btc_sim`.
//!
//! ROOT-LAYER: this world PRODUCES the foreign-chain figures (confirmations, balances, relayed sets) that
//! `xmr_watch`, `xmr_custody` and `xmr_payout` only READ, through their production surfaces — the one layer under
//! those readers, exactly where `btc_sim` sits under `btc_watch`/`btc_payout`.
//! MEASURED (lane-verify 2026-10-27, xmr-sim-pins-20261027b.log): the four pins here pass in ≤ 0.003 s each with their
//! planted-defect calibrations RED first (IgnoreReorg, AcceptAnySigners); the two-custodian netsim pin
//! (`the_mesh_reads_one_simulated_monero_that_mines_on_the_simulated_clock`, production paused, no convergence
//! claim) 0.84 s; the Bitcoin twin's 5 pins ≤ 1.1 s.
//! MUST-STAY-GREEN: `xmr_rpc::tests`, `xmr_watch::tests`, `xmr_custody::tests`, `xmr_payout::tests`, every
//! `btc_sim::tests` pin and `the_mesh_reads_one_simulated_bitcoin_that_mines_on_the_simulated_clock`.
//!
//! BORROWED, NOT DERIVED (AGENTS.md §1): the output set is a FUNCTION OF THE CHAIN, recomputed from the blocks on
//! every query (Ethereum STF: local state is a cache), so a reorg is a truncation and nothing else; disconnected
//! transactions return to the pool (Bitcoin Core `UpdateMempoolForReorg`, Monero's own pool keeps them too); a
//! received output spends after `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` = 10 blocks; the k-of-n wallet forms by
//! Monero's own round count (`xmr_custody::final_round`: `make_multisig` consumes the round-0 infos, each
//! `exchange_multisig_keys` the next round's, the wallet is final after round n − k + 1); a multisig transaction set is
//! an object the members sign IN TURN and `submit_multisig` relays only with ≥ k DISTINCT member signatures over the
//! same body (Monero's `multisig_txset`); the fee a set carries is what the daemon's per-byte estimate prices over
//! the set's bytes, and the set is never shorter than the transaction it builds (as Monero's set carries the whole
//! unsigned transaction), so the payout lane's F7 ceiling holds exactly as it does against a real wallet.
//!
//! §9.6 NEW-DOOR CHECKLIST for `admit` (the one door a node's bytes enter this world by, behind `submit_multisig` /
//! `transfer_relay`): (1) no PoW here — this is the foreign chain, its blocks are the simulator's; (2) the set's own
//! proof is its member signatures: each a keyed BLAKE3 tag over the body under THAT member's wallet secret, verified
//! against the account's member set, ≥ threshold distinct members (a plain one-member wallet relays its own build
//! with none, as Monero's does); (3) value is created only by the miner's funding and conserved by `admit` (inputs
//! = destinations + change + fee, exactly); (4) a replay is refused by the OUTPUT SET — an input spent on the chain
//! or in the pool, a set already relayed, a funding evicted by a conflict, each refused; (5) work is bounded by the
//! chain's own length — a test scaffold, never a node's state; (6) parity with `submit_multisig` on a real wallet:
//! what it lacks is named below (no ring, no range proof, no key image — each REFUSED by construction: a set names
//! its inputs in the clear and the world checks them against the chain).
//!
//! What is NOT simulated (stated, fail-closed): CLSAG rings, RingCT amounts and range proofs, key images,
//! subaddresses, time-based unlocks, the wallet files on disk (`open_or_create` finds every wallet existing and
//! multisig-enabled, so the CLI switch is never run). The miner's funding carries no inputs and is trusted as a
//! regtest's miner wallet is. No Monero cryptography is re-derived here or anywhere in this tree.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};

use serde::{Deserialize, Serialize};

use crate::xmr_rpc::{Incoming, Recipient};

/// Monero's cadence: one block per two minutes; the simulator's clock mines one per interval (`advance_clock`).
pub const BLOCK_INTERVAL_MS: u64 = 120_000;
/// `get_fee_estimate` at the default priority on a v0.18 daemon: 20 000 atomic units (piconero) per byte.
pub const FEE_PER_BYTE_ATOMIC: u64 = 20_000;
/// Monero's own output lock (`xmr_watch::XMR_SPEND_LOCK_BLOCKS`): a received output spends after this many blocks.
pub const SPEND_LOCK_BLOCKS: u64 = crate::xmr_watch::XMR_SPEND_LOCK_BLOCKS;
/// The bytes a RingCT transaction weighs, as the wallet's fee estimate sizes it: a base, per input (a 16-ring CLSAG)
/// and per output (key, commitment, ecdh, range-proof share). The figure prices the fee; its exactness is not a
/// claim of this world.
const TX_BASE_BYTES: u64 = 1_440;
const TX_PER_IN_BYTES: u64 = 180;
const TX_PER_OUT_BYTES: u64 = 100;
/// A multisig info string this world hands round: `<prefix>:<round>:<member pubkey hex>`.
const INFO_PREFIX: &str = "MultisigxV2-sim";
const EXPORT_PREFIX: &str = "MultisigExport-sim";
/// The payment id a transfer without one reports, as `get_transfers` does.
const NO_PAYMENT_ID: [u8; 8] = [0u8; 8];

pub type OutRef = ([u8; 32], u32);

/// One output as the chain holds it: who it pays (a STANDARD address), how much, and the payment id its transfer
/// carried (the integrated address's eight bytes, or zero).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimOut {
    pub to: String,
    pub amount: u64,
    pub payment_id: [u8; 8],
}

/// A transaction as the chain holds it (an input names the output it spends; a funding has none).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimTx {
    pub txid: [u8; 32],
    pub inputs: Vec<OutRef>,
    pub outputs: Vec<SimOut>,
    pub fee: u64,
}

/// A defect PLANTED to prove a pin can fail (user: every instrument fails on a planted defect first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plant {
    None,
    /// `invalidate_block` does nothing — a world where a reorg never takes a deposit back.
    IgnoreReorg,
    /// `admit` relays a set with ANY signatures — a world where a forged or short set "arrives".
    AcceptAnySigners,
}

/// The multisig transaction set as the members pass it round (hex of its JSON; Monero's is hex of its own
/// serialization). `pad` keeps the set at least as long as the transaction it builds (see the module header).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TxSet {
    account: String,
    inputs: Vec<OutRef>,
    dests: Vec<(String, u64)>,
    change: u64,
    fee: u64,
    pad: String,
    sigs: Vec<([u8; 32], [u8; 32])>,
}

impl TxSet {
    /// The body every signature covers — everything but the signatures.
    fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"USDMD-XMR-SIM-TXSET-v1");
        h.update(self.account.as_bytes());
        h.update(&(self.inputs.len() as u64).to_le_bytes());
        for (txid, idx) in &self.inputs {
            h.update(txid);
            h.update(&idx.to_le_bytes());
        }
        h.update(&(self.dests.len() as u64).to_le_bytes());
        for (a, v) in &self.dests {
            h.update(&(a.len() as u64).to_le_bytes());
            h.update(a.as_bytes());
            h.update(&v.to_le_bytes());
        }
        h.update(&self.change.to_le_bytes());
        h.update(&self.fee.to_le_bytes());
        *h.finalize().as_bytes()
    }

    fn encode(&self) -> Result<String, String> {
        let json = serde_json::to_vec(self).map_err(|e| format!("the transaction set did not encode: {e}"))?;
        Ok(crate::btc_tx::hex(&json))
    }

    fn decode(txset: &str) -> Result<TxSet, String> {
        let bytes = crate::btc_tx::unhex(txset.trim()).ok_or("the transaction set is not hex")?;
        serde_json::from_slice(&bytes).map_err(|e| format!("the transaction set does not decode: {e}"))
    }
}

/// A member's k-of-n wallet state, by Monero's rounds (`xmr_custody::final_round`).
struct Msig {
    members: BTreeSet<[u8; 32]>,
    threshold: u32,
    /// Rounds consumed so far: 0 after `make_multisig`, +1 per `exchange_multisig_keys`.
    consumed: u8,
    ready: bool,
    address: String,
    /// The info this wallet produced last (re-sent on a recovery `exchange_multisig_keys(&[])`).
    last_info: String,
}

struct SimWalletState {
    secret: [u8; 32],
    pubkey: [u8; 32],
    own_address: String,
    msig: Option<Msig>,
}

impl SimWalletState {
    /// The address this wallet spends from and receives at: its k-of-n account once final, else its own.
    fn spend_address(&self) -> &str {
        match &self.msig {
            Some(m) if m.ready => &m.address,
            _ => &self.own_address,
        }
    }
}

/// The simulated chain and every custodian's wallet on it. Test scaffold: the block vector is bounded by the blocks
/// a fixed-length run mines; no node holds it (O1-FOOTPRINT-REVIEWED: the foreign chain of the simulator, never
/// node state).
pub struct SimMonero {
    /// `blocks[i]` is height `i + 1`; genesis (height 0) carries nothing.
    blocks: Vec<Vec<SimTx>>,
    mempool: Vec<SimTx>,
    /// Fundings a conflict evicted — never known again, as a double-spent key image's victim is not.
    evicted: BTreeSet<[u8; 32]>,
    wallets: BTreeMap<u32, SimWalletState>,
    next_wallet: u32,
    seed: u64,
    fee_per_byte: u64,
    next_block_at_ms: u64,
    pub block_interval_ms: u64,
    pub plant: Plant,
    fundings_made: u64,
}

fn blake(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// A checksummed STANDARD Monero address on this node's network from two derivation tags (the points are hash
/// bytes: nothing here is a curve point, and nothing in this tree treats them as one).
fn address_of(tag: &[u8], material: &[u8]) -> String {
    let spend = blake(b"USDMD-XMR-SIM-SPEND-v1", &[tag, material]);
    let view = blake(b"USDMD-XMR-SIM-VIEW-v1", &[tag, material]);
    crate::bridge::encode_monero_address(crate::bridge::xmr_net_byte(), &spend, &view)
}

/// The k-of-n account's address: a function of the member set and the threshold, so every member derives the same.
fn account_address(members: &BTreeSet<[u8; 32]>, threshold: u32) -> String {
    let mut material = Vec::with_capacity(4 + 32 * members.len());
    material.extend_from_slice(&threshold.to_le_bytes());
    for m in members {
        material.extend_from_slice(m);
    }
    address_of(b"account", &material)
}

fn info_of(round: u8, pubkey: &[u8; 32]) -> String {
    format!("{INFO_PREFIX}:{round}:{}", crate::btc_tx::hex(pubkey))
}

fn parse_info(s: &str) -> Option<(u8, [u8; 32])> {
    let rest = s.strip_prefix(INFO_PREFIX)?.strip_prefix(':')?;
    let (round, pk) = rest.split_once(':')?;
    let round: u8 = round.parse().ok()?;
    let pk = crate::btc_tx::unhex(pk)?;
    let pk: [u8; 32] = pk.try_into().ok()?;
    Some((round, pk))
}

/// The STANDARD address and payment id a destination names: an integrated address's parts, or the standard address
/// itself with no payment id. `None` for anything that is not a checksummed address on this node's Monero network.
fn main_and_pid(address: &str) -> Option<(String, [u8; 8])> {
    let a = address.trim();
    if crate::bridge::xmr_address_net(a) != Some(crate::bridge::xmr_net_byte()) {
        return None;
    }
    if let Some((pid, main)) = crate::bridge::xmr_integrated_parts(a) {
        return Some((main, pid));
    }
    crate::bridge::decode_monero_standard_address(a).map(|_| (a.to_string(), NO_PAYMENT_ID))
}

fn tx_bytes(n_in: usize, n_out: usize) -> u64 {
    TX_BASE_BYTES + TX_PER_IN_BYTES * n_in as u64 + TX_PER_OUT_BYTES * n_out as u64
}

impl SimMonero {
    /// A fresh chain at height 0 with no wallets: the first block is one interval in.
    pub fn new(seed: u64) -> SimMonero {
        SimMonero {
            blocks: Vec::new(),
            mempool: Vec::new(),
            evicted: BTreeSet::new(),
            wallets: BTreeMap::new(),
            next_wallet: 0,
            seed,
            fee_per_byte: FEE_PER_BYTE_ATOMIC,
            next_block_at_ms: BLOCK_INTERVAL_MS,
            block_interval_ms: BLOCK_INTERVAL_MS,
            plant: Plant::None,
            fundings_made: 0,
        }
    }

    pub fn tip_height(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// `get_block_count`: the blocks including genesis.
    pub fn block_count(&self) -> u64 {
        self.tip_height() + 1
    }

    pub fn fee_per_byte(&self) -> u64 {
        self.fee_per_byte
    }

    /// A zero rate is refused: the chain prices every byte.
    pub fn set_fee_per_byte(&mut self, atomic: u64) -> Result<(), String> {
        if atomic == 0 {
            return Err("set_fee_per_byte: a zero fee rate".into());
        }
        self.fee_per_byte = atomic;
        Ok(())
    }

    pub fn set_block_interval_ms(&mut self, ms: u64) -> Result<(), String> {
        if ms == 0 {
            return Err("set_block_interval_ms: a zero interval".into());
        }
        self.block_interval_ms = ms;
        self.next_block_at_ms = ms;
        Ok(())
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    /// Opens one more custodian wallet on this chain (what `WalletRpc::from_env` does under the Sim arm); its id.
    pub fn open_wallet(&mut self) -> u32 {
        let id = self.next_wallet;
        self.next_wallet += 1;
        let secret = blake(b"USDMD-XMR-SIM-WALLET-v1", &[&self.seed.to_le_bytes(), &id.to_le_bytes()]);
        let pubkey = blake(b"USDMD-XMR-SIM-PUB-v1", &[&secret]);
        let own_address = address_of(b"own", &pubkey);
        self.wallets.insert(id, SimWalletState { secret, pubkey, own_address, msig: None });
        id
    }

    fn wallet(&self, id: u32) -> Result<&SimWalletState, String> {
        self.wallets.get(&id).ok_or_else(|| format!("no simulated wallet {id}"))
    }

    fn wallet_mut(&mut self, id: u32) -> Result<&mut SimWalletState, String> {
        self.wallets.get_mut(&id).ok_or_else(|| format!("no simulated wallet {id}"))
    }

    fn wallet_by_pubkey(&self, pubkey: &[u8; 32]) -> Option<&SimWalletState> {
        self.wallets.values().find(|w| w.pubkey == *pubkey)
    }

    // ───────────────────────────── the chain ─────────────────────────────

    /// Mine `n` blocks: each takes the whole pool.
    pub fn mine(&mut self, n: u64) {
        for _ in 0..n {
            let txs = std::mem::take(&mut self.mempool);
            self.blocks.push(txs);
        }
    }

    /// The simulated clock at `now_ms`: one block per interval since the last.
    pub fn advance_clock(&mut self, now_ms: u64) {
        while now_ms >= self.next_block_at_ms {
            self.mine(1);
            self.next_block_at_ms = self.next_block_at_ms.saturating_add(self.block_interval_ms);
        }
    }

    /// A reorg from `height`: every block at or above it is disconnected and its transactions return to the pool in
    /// their order (Core `UpdateMempoolForReorg`); a truncation and nothing else — the output set is recomputed
    /// from the blocks on every read. A height off the chain is refused.
    pub fn invalidate_block(&mut self, height: u64) -> Result<(), String> {
        if height == 0 || height > self.tip_height() {
            return Err(format!("invalidate_block: height {height} is not on the chain (tip {})", self.tip_height()));
        }
        if self.plant == Plant::IgnoreReorg {
            return Ok(()); // the planted world: a reorg that changes nothing
        }
        let removed = self.blocks.split_off((height - 1) as usize);
        let mut back: Vec<SimTx> = removed.into_iter().flatten().collect();
        back.append(&mut self.mempool);
        self.mempool = back;
        Ok(())
    }

    /// The miner pays `atomic` to `address` (a standard or an integrated address on this network): a funding in the
    /// pool, confirmed by the next block. Trusted as a regtest's miner wallet is (no inputs).
    pub fn fund(&mut self, address: &str, atomic: u64) -> Result<[u8; 32], String> {
        let (to, pid) = main_and_pid(address).ok_or("fund: not a Monero address on this node's network")?;
        if atomic == 0 {
            return Err("fund: nothing to pay".into());
        }
        self.fundings_made += 1;
        let txid = blake(b"USDMD-XMR-SIM-FUND-v1", &[&self.seed.to_le_bytes(), &self.fundings_made.to_le_bytes()]);
        self.mempool.push(SimTx { txid, inputs: Vec::new(), outputs: vec![SimOut { to, amount: atomic, payment_id: pid }], fee: 0 });
        Ok(txid)
    }

    /// THE ATTACK after a reorg put a funding back in the pool: the depositor spends the same input elsewhere, so the
    /// funding is evicted for good and a conflicting transaction (paying nobody this world watches) confirms instead.
    pub fn double_spend_funding(&mut self, txid: &[u8; 32]) -> Result<[u8; 32], String> {
        let pos = self
            .mempool
            .iter()
            .position(|t| t.txid == *txid && t.inputs.is_empty())
            .ok_or("double_spend_funding: not a funding transaction in the pool")?;
        self.mempool.remove(pos);
        self.evicted.insert(*txid);
        let conflict = blake(b"USDMD-XMR-SIM-CONFLICT-v1", &[txid]);
        self.mempool.push(SimTx { txid: conflict, inputs: Vec::new(), outputs: Vec::new(), fee: 0 });
        Ok(conflict)
    }

    /// Where a transaction is: `Some(Some(height))` on the chain, `Some(None)` in the pool, `None` unknown.
    fn locate(&self, txid: &[u8; 32]) -> Option<Option<u64>> {
        for (i, b) in self.blocks.iter().enumerate() {
            if b.iter().any(|t| t.txid == *txid) {
                return Some(Some(i as u64 + 1));
            }
        }
        if self.mempool.iter().any(|t| t.txid == *txid) {
            return Some(None);
        }
        None
    }

    /// Confirmations of a transaction the chain or the pool knows (`get_transfer_by_txid`); `None` otherwise.
    pub fn tx_confirmations(&self, txid: &[u8; 32]) -> Option<u64> {
        match self.locate(txid)? {
            Some(h) => Some(self.tip_height() - h + 1),
            None => Some(0),
        }
    }

    /// Every input spent on the chain or in the pool — a function of the chain, recomputed on every read.
    fn spent(&self) -> BTreeSet<OutRef> {
        self.blocks.iter().flatten().chain(self.mempool.iter()).flat_map(|t| t.inputs.iter().copied()).collect()
    }

    /// The CONFIRMED outputs paying `address`: (reference, amount, payment id, confirmations), in chain order.
    fn outputs_to(&self, address: &str) -> Vec<(OutRef, u64, [u8; 8], u64)> {
        let tip = self.tip_height();
        let mut out = Vec::new();
        for (i, b) in self.blocks.iter().enumerate() {
            let conf = tip - i as u64;
            for t in b {
                for (idx, o) in t.outputs.iter().enumerate() {
                    if o.to == address {
                        out.push(((t.txid, idx as u32), o.amount, o.payment_id, conf));
                    }
                }
            }
        }
        out
    }

    /// The unspent confirmed outputs of `address` past Monero's lock, in chain order.
    fn unlocked_outputs(&self, address: &str) -> Vec<(OutRef, u64)> {
        let spent = self.spent();
        self.outputs_to(address)
            .into_iter()
            .filter(|(r, _, _, conf)| *conf >= SPEND_LOCK_BLOCKS && !spent.contains(r))
            .map(|(r, v, _, _)| (r, v))
            .collect()
    }

    /// (balance, unlocked) of `address`, as `get_balance` reports them: unspent confirmed, and of those the ones past
    /// the lock.
    fn balance_of(&self, address: &str) -> (u64, u64) {
        let spent = self.spent();
        let mut balance = 0u64;
        let mut unlocked = 0u64;
        for (r, v, _, conf) in self.outputs_to(address) {
            if spent.contains(&r) {
                continue;
            }
            balance = balance.saturating_add(v);
            if conf >= SPEND_LOCK_BLOCKS {
                unlocked = unlocked.saturating_add(v);
            }
        }
        (balance, unlocked)
    }

    /// The confirmed atomic units `address` has received on the chain (a redeemer's view; no wallet needed);
    /// `None` for a string that is not an address on this network.
    pub fn received_atomic(&self, address: &str) -> Option<u64> {
        let (main, _) = main_and_pid(address)?;
        Some(self.outputs_to(&main).iter().fold(0u64, |a, (_, v, _, _)| a.saturating_add(*v)))
    }

    /// `get_transfers { in: true, pool: false }` for `address`.
    fn incoming_for(&self, address: &str) -> Vec<Incoming> {
        self.outputs_to(address)
            .into_iter()
            .map(|((txid, _), amount, pid, confirmations)| Incoming {
                txid: crate::btc_tx::hex(&txid),
                amount,
                payment_id: crate::btc_tx::hex(&pid),
                confirmations,
            })
            .collect()
    }

    /// The members and threshold of a k-of-n account by its address, from the wallets that formed it.
    fn account(&self, address: &str) -> Option<(&BTreeSet<[u8; 32]>, u32)> {
        self.wallets.values().find_map(|w| match &w.msig {
            Some(m) if m.ready && m.address == address => Some((&m.members, m.threshold)),
            _ => None,
        })
    }

    /// Build the set a wallet proposes: the account's unlocked outputs in chain order until they cover the
    /// destinations and the fee the daemon's estimate prices over the transaction's bytes; the change back to the
    /// account.
    fn build_txset(&self, account: &str, dests: &[(String, u64)]) -> Result<TxSet, String> {
        if dests.is_empty() {
            return Err("transfer: no destinations".into());
        }
        for (a, v) in dests {
            if main_and_pid(a).is_none() {
                return Err(format!("transfer: {a} is not a Monero address on this node's network"));
            }
            if *v == 0 {
                return Err("transfer: a zero-amount destination".into());
            }
        }
        let total = dests.iter().try_fold(0u64, |a, (_, v)| a.checked_add(*v)).ok_or("transfer: amount overflow")?;
        let coins = self.unlocked_outputs(account);
        let n_out = dests.len() + 1;
        let mut chosen: Vec<OutRef> = Vec::new();
        let mut sum_in = 0u64;
        let mut fee = 0u64;
        // the wallet-rpc's `subtract_fee_from_outputs` over every destination (what the custody lanes ask for): the inputs cover
        // the destinations' sum, and the fee is taken out of the outputs — split evenly, the remainder from the first ones —
        // so the account falls by exactly the destinations' sum
        for (r, v) in &coins {
            chosen.push(*r);
            sum_in = sum_in.saturating_add(*v);
            fee = self.fee_per_byte.saturating_mul(tx_bytes(chosen.len(), n_out));
            if sum_in >= total {
                let n = dests.len() as u64;
                let (share, rem) = (fee / n, fee % n);
                let mut paid = Vec::with_capacity(dests.len());
                for (i, (a, v)) in dests.iter().enumerate() {
                    let cut = share + u64::from((i as u64) < rem);
                    if *v <= cut {
                        return Err("transfer: an output is not larger than its share of the fee".into());
                    }
                    paid.push((a.clone(), v - cut));
                }
                let change = sum_in - total;
                let pad = "0".repeat(tx_bytes(chosen.len(), n_out) as usize);
                return Ok(TxSet { account: account.to_string(), inputs: chosen, dests: paid, change, fee, pad, sigs: Vec::new() });
            }
        }
        Err(format!("transfer: not enough unlocked balance: {sum_in} atomic unlocked, {total} needed"))
    }

    /// A member's signature over the set's body: a keyed BLAKE3 tag under that wallet's secret (the sim's stand-in
    /// for the wallet's multisig signing; verified by recomputation against the member's wallet in `admit`).
    fn sign_body(secret: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
        *blake3::keyed_hash(secret, digest).as_bytes()
    }

    /// THE DOOR (§9.6 in the module header): relay a set into the pool. `multisig` = the set must carry the
    /// account's quorum; a plain one-member wallet relays its own build with none.
    fn admit(&mut self, set: &TxSet, multisig: bool) -> Result<[u8; 32], String> {
        let digest = set.digest();
        if self.locate(&digest).is_some() || self.evicted.contains(&digest) {
            return Err("submit_multisig: the set was already relayed".into());
        }
        if multisig {
            let (members, threshold) = self.account(&set.account).ok_or("submit_multisig: the set's account is not a multisig wallet this chain knows")?;
            if self.plant != Plant::AcceptAnySigners {
                let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
                for (pk, tag) in &set.sigs {
                    if !members.contains(pk) {
                        return Err("submit_multisig: a signature by a NON-MEMBER".into());
                    }
                    let w = self.wallet_by_pubkey(pk).ok_or("submit_multisig: a member with no wallet on this chain")?;
                    if Self::sign_body(&w.secret, &digest) != *tag {
                        return Err("submit_multisig: a signature does not verify over the set's body".into());
                    }
                    seen.insert(*pk);
                }
                if seen.len() < threshold as usize {
                    return Err(format!("submit_multisig: {} distinct member signatures, {threshold} needed", seen.len()));
                }
            } else if set.sigs.is_empty() {
                return Err("submit_multisig: no signatures".into());
            }
        } else if self.account(&set.account).is_some() {
            return Err("transfer: a multisig account relays only through submit_multisig".into());
        }
        // The inputs: the account's own, confirmed past the lock, unspent on the chain and in the pool.
        let unlocked: BTreeMap<OutRef, u64> = self.unlocked_outputs(&set.account).into_iter().collect();
        let mut sum_in = 0u64;
        let mut distinct: BTreeSet<OutRef> = BTreeSet::new();
        for r in &set.inputs {
            let v = unlocked.get(r).ok_or("submit_multisig: an input is not an unlocked unspent output of the account")?;
            if !distinct.insert(*r) {
                return Err("submit_multisig: an input named twice".into());
            }
            sum_in = sum_in.checked_add(*v).ok_or("submit_multisig: input overflow")?;
        }
        if set.inputs.is_empty() {
            return Err("submit_multisig: no inputs".into());
        }
        let mut outputs = Vec::with_capacity(set.dests.len() + 1);
        let mut sum_out = 0u64;
        for (a, v) in &set.dests {
            let (to, pid) = main_and_pid(a).ok_or("submit_multisig: a destination is not a Monero address on this network")?;
            if *v == 0 {
                return Err("submit_multisig: a zero-amount destination".into());
            }
            sum_out = sum_out.checked_add(*v).ok_or("submit_multisig: output overflow")?;
            outputs.push(SimOut { to, amount: *v, payment_id: pid });
        }
        let need = sum_out.checked_add(set.change).and_then(|s| s.checked_add(set.fee)).ok_or("submit_multisig: output overflow")?;
        if sum_in != need {
            return Err(format!("submit_multisig: inputs {sum_in} ≠ destinations {sum_out} + change {} + fee {}", set.change, set.fee));
        }
        let min_fee = self.fee_per_byte.saturating_mul(tx_bytes(set.inputs.len(), set.dests.len() + 1));
        if set.fee < min_fee {
            return Err(format!("submit_multisig: fee {} below the chain's {min_fee}", set.fee));
        }
        if set.change > 0 {
            outputs.push(SimOut { to: set.account.clone(), amount: set.change, payment_id: NO_PAYMENT_ID });
        }
        self.mempool.push(SimTx { txid: digest, inputs: set.inputs.clone(), outputs, fee: set.fee });
        Ok(digest)
    }

    // ───────────────────────────── the wallet-rpc surface, per wallet ─────────────────────────────

    fn w_address(&self, id: u32) -> Result<String, String> {
        Ok(self.wallet(id)?.spend_address().to_string())
    }

    fn w_is_multisig(&self, id: u32) -> Result<(bool, bool, u32, u32), String> {
        Ok(match &self.wallet(id)?.msig {
            None => (false, false, 0, 0),
            Some(m) => (true, m.ready, m.threshold, m.members.len() as u32),
        })
    }

    fn w_prepare(&self, id: u32) -> Result<String, String> {
        let w = self.wallet(id)?;
        if w.msig.is_some() {
            return Err("prepare_multisig: the wallet is already multisig".into());
        }
        Ok(info_of(0, &w.pubkey))
    }

    /// The round-0 infos of the OTHER members and the threshold: the wallet becomes multisig (not yet final) and
    /// hands back its round-1 info.
    fn w_make(&mut self, id: u32, others: &[String], threshold: u32) -> Result<String, String> {
        let me = self.wallet(id)?.pubkey;
        if self.wallet(id)?.msig.is_some() {
            return Err("make_multisig: the wallet is already multisig".into());
        }
        let mut members: BTreeSet<[u8; 32]> = BTreeSet::new();
        members.insert(me);
        for o in others {
            let (round, pk) = parse_info(o).ok_or("make_multisig: an info is not a prepared multisig info")?;
            if round != 0 {
                return Err("make_multisig: an info is not a round-0 (prepared) info".into());
            }
            if pk == me || !members.insert(pk) {
                return Err("make_multisig: a member named twice".into());
            }
        }
        let n = members.len() as u32;
        if n < 2 {
            return Err("make_multisig: a multisig wallet needs at least two members".into());
        }
        if threshold < 1 || threshold > n {
            return Err(format!("make_multisig: threshold {threshold} of {n}"));
        }
        let info = info_of(1, &me);
        self.wallet_mut(id)?.msig = Some(Msig { members, threshold, consumed: 0, ready: false, address: String::new(), last_info: info.clone() });
        Ok(info)
    }

    /// A further round: the OTHER members' infos of the round after the last consumed — all of them, no stranger.
    /// Final after round n − k + 1 (`xmr_custody::final_round`): the account address is fixed and `""` returned.
    fn w_exchange(&mut self, id: u32, others: &[String]) -> Result<String, String> {
        let me = self.wallet(id)?.pubkey;
        let w = self.wallet_mut(id)?;
        let m = w.msig.as_mut().ok_or("exchange_multisig_keys: the wallet is not multisig")?;
        if m.ready {
            return Ok(String::new());
        }
        if others.is_empty() {
            return Ok(m.last_info.clone()); // recovery: the wallet re-hands the info it produced last
        }
        let want_round = m.consumed + 1;
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        for o in others {
            let (round, pk) = parse_info(o).ok_or("exchange_multisig_keys: an info is not a multisig info")?;
            if round != want_round {
                return Err(format!("exchange_multisig_keys: an info of round {round}, round {want_round} expected"));
            }
            if pk == me || !m.members.contains(&pk) {
                return Err("exchange_multisig_keys: an info from a wallet outside the set".into());
            }
            if !seen.insert(pk) {
                return Err("exchange_multisig_keys: a member's info named twice".into());
            }
        }
        if seen.len() + 1 != m.members.len() {
            return Err(format!("exchange_multisig_keys: {} of {} other members' infos", seen.len(), m.members.len() - 1));
        }
        m.consumed = want_round;
        if m.consumed == crate::xmr_custody::final_round(m.members.len(), m.threshold) {
            m.ready = true;
            m.address = account_address(&m.members, m.threshold);
            m.last_info = String::new();
            return Ok(String::new());
        }
        m.last_info = info_of(m.consumed + 1, &me);
        Ok(m.last_info.clone())
    }

    fn w_export(&self, id: u32) -> Result<String, String> {
        let w = self.wallet(id)?;
        if !w.msig.as_ref().is_some_and(|m| m.ready) {
            return Err("export_multisig_info: the wallet is not a final multisig wallet".into());
        }
        Ok(format!("{EXPORT_PREFIX}:{}:{}", crate::btc_tx::hex(&w.pubkey), self.tip_height()))
    }

    fn w_import(&self, id: u32, infos: &[String]) -> Result<u64, String> {
        let w = self.wallet(id)?;
        let m = w.msig.as_ref().filter(|m| m.ready).ok_or("import_multisig_info: the wallet is not a final multisig wallet")?;
        for i in infos {
            let rest = i.strip_prefix(EXPORT_PREFIX).and_then(|r| r.strip_prefix(':')).ok_or("import_multisig_info: not an exported multisig info")?;
            let pk = rest.split(':').next().and_then(crate::btc_tx::unhex).ok_or("import_multisig_info: no member key")?;
            let pk: [u8; 32] = pk.try_into().map_err(|_| "import_multisig_info: a malformed member key".to_string())?;
            if !m.members.contains(&pk) {
                return Err("import_multisig_info: an info from outside the set".into());
            }
        }
        Ok(self.outputs_to(w.spend_address()).len() as u64)
    }

    fn w_balance(&self, id: u32) -> Result<(u64, u64, bool), String> {
        let (b, u) = self.balance_of(self.wallet(id)?.spend_address());
        Ok((b, u, false))
    }

    fn w_incoming(&self, id: u32) -> Result<Vec<Incoming>, String> {
        Ok(self.incoming_for(self.wallet(id)?.spend_address()))
    }

    fn w_transfer_multisig(&self, id: u32, dests: &[(String, u64)]) -> Result<String, String> {
        let w = self.wallet(id)?;
        if !w.msig.as_ref().is_some_and(|m| m.ready) {
            return Err("transfer: the wallet returned no multisig transaction set (not a final multisig wallet)".into());
        }
        self.build_txset(w.spend_address(), dests)?.encode()
    }

    fn w_transfer_relay(&mut self, id: u32, dests: &[(String, u64)]) -> Result<String, String> {
        let w = self.wallet(id)?;
        if w.msig.is_some() {
            return Err("transfer: a multisig wallet builds a set; it does not relay".into());
        }
        let set = self.build_txset(&w.own_address.clone(), dests)?;
        let txid = self.admit(&set, false)?;
        Ok(crate::btc_tx::hex(&txid))
    }

    fn w_describe(&self, txset: &str) -> Result<(Vec<Recipient>, u64), String> {
        let set = TxSet::decode(txset)?;
        Ok((set.dests.iter().map(|(a, v)| Recipient { address: a.clone(), amount: *v }).collect(), set.fee))
    }

    fn w_sign(&self, id: u32, txset: &str) -> Result<(String, Vec<String>), String> {
        let w = self.wallet(id)?;
        let m = w.msig.as_ref().filter(|m| m.ready).ok_or("sign_multisig: the wallet is not a final multisig wallet")?;
        let mut set = TxSet::decode(txset)?;
        if set.account != m.address {
            return Err("sign_multisig: the set spends another account".into());
        }
        let digest = set.digest();
        let tag = Self::sign_body(&w.secret, &digest);
        if !set.sigs.iter().any(|(pk, _)| *pk == w.pubkey) {
            set.sigs.push((w.pubkey, tag));
        }
        let hashes = if set.sigs.len() >= m.threshold as usize { vec![crate::btc_tx::hex(&digest)] } else { Vec::new() };
        Ok((set.encode()?, hashes))
    }

    fn w_submit(&mut self, id: u32, txset: &str) -> Result<Vec<String>, String> {
        let w = self.wallet(id)?;
        let m = w.msig.as_ref().filter(|m| m.ready).ok_or("submit_multisig: the wallet is not a final multisig wallet")?;
        let set = TxSet::decode(txset)?;
        if set.account != m.address {
            return Err("submit_multisig: the set spends another account".into());
        }
        let txid = self.admit(&set, true)?;
        Ok(vec![crate::btc_tx::hex(&txid)])
    }

    fn w_tx_confirmations(&self, txid: &str) -> Result<Option<u64>, String> {
        let bytes = crate::btc_tx::unhex(txid.trim()).ok_or("get_transfer_by_txid: not a hex txid")?;
        let txid: [u8; 32] = bytes.try_into().map_err(|_| "get_transfer_by_txid: a txid is 32 bytes".to_string())?;
        Ok(self.tx_confirmations(&txid))
    }

    /// `get_transfer_by_txid` as wallet `id` reads it: `(what the transaction paid this wallet's account, its fee,
    /// its confirmations, whether it paid the account's main address with no payment id)` — `None` for a
    /// transaction that neither pays this account nor spends from it (a wallet does not know a stranger's transfer).
    /// The fee is public on Monero: a receiving wallet reads it exactly as the sender's does.
    fn w_transfer_fee(&self, id: u32, txid: &str) -> Result<Option<(u64, u64, u64, bool)>, String> {
        let bytes = crate::btc_tx::unhex(txid.trim()).ok_or("get_transfer_by_txid: not a hex txid")?;
        let txid: [u8; 32] = bytes.try_into().map_err(|_| "get_transfer_by_txid: a txid is 32 bytes".to_string())?;
        let account = self.wallet(id)?.spend_address().to_string();
        let Some(tx) = self.blocks.iter().flatten().chain(self.mempool.iter()).find(|t| t.txid == txid) else { return Ok(None) };
        let paid: u64 = tx.outputs.iter().filter(|o| o.to == account).map(|o| o.amount).sum();
        let to_main = tx.outputs.iter().any(|o| o.to == account && o.payment_id == NO_PAYMENT_ID);
        let owner_of = |r: &OutRef| self.blocks.iter().flatten().find(|t| t.txid == r.0).and_then(|t| t.outputs.get(r.1 as usize)).map(|o| o.to.clone());
        let spends_mine = tx.inputs.iter().any(|r| owner_of(r).as_deref() == Some(account.as_str()));
        if paid == 0 && !spends_mine {
            return Ok(None);
        }
        Ok(Some((paid, tx.fee, self.tx_confirmations(&txid).unwrap_or(0), to_main && !spends_mine)))
    }

    /// `(fee, confirmations)` of a MINED transaction that spends this wallet's own outputs — the simulated
    /// `get_transfer_by_txid` of type `out`; `None` for any other.
    fn w_sent_fee(&self, id: u32, txid: &str) -> Result<Option<(u64, u64)>, String> {
        let bytes = crate::btc_tx::unhex(txid.trim()).ok_or("get_transfer_by_txid: not a hex txid")?;
        let txid: [u8; 32] = bytes.try_into().map_err(|_| "get_transfer_by_txid: a txid is 32 bytes".to_string())?;
        let account = self.wallet(id)?.spend_address().to_string();
        let Some(tx) = self.blocks.iter().flatten().find(|t| t.txid == txid) else { return Ok(None) };
        let owner_of = |r: &OutRef| self.blocks.iter().flatten().find(|t| t.txid == r.0).and_then(|t| t.outputs.get(r.1 as usize)).map(|o| o.to.clone());
        if !tx.inputs.iter().any(|r| owner_of(r).as_deref() == Some(account.as_str())) {
            return Ok(None);
        }
        Ok(Some((tx.fee, self.tx_confirmations(&txid).unwrap_or(0))))
    }
}

// ───────────────────────────── the installed world ─────────────────────────────

fn slot() -> &'static RwLock<Option<Arc<Mutex<SimMonero>>>> {
    static S: OnceLock<RwLock<Option<Arc<Mutex<SimMonero>>>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(None))
}

/// The installed simulated chain, if any: `WalletRpc::from_env` / `DaemonRpc::from_env` hand it to every caller.
pub fn installed() -> Option<Arc<Mutex<SimMonero>>> {
    slot().read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Holds the world installed; dropping it uninstalls. ONE process-wide slot: pins that install serialize on
/// `xmr_sim::serial()` so two cannot overwrite each other's world.
pub struct Installed(Arc<Mutex<SimMonero>>);

impl Installed {
    pub fn chain(&self) -> MutexGuard<'_, SimMonero> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn arc(&self) -> Arc<Mutex<SimMonero>> {
        self.0.clone()
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        let mut s = slot().write().unwrap_or_else(|e| e.into_inner());
        if s.as_ref().is_some_and(|a| Arc::ptr_eq(a, &self.0)) {
            *s = None;
        }
    }
}

pub fn install(sim: SimMonero) -> Installed {
    let a = Arc::new(Mutex::new(sim));
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(a.clone());
    Installed(a)
}

/// The lock pins take around an installed world (tests run in parallel threads).
pub fn serial() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

/// One custodian's wallet on the installed chain — the `Sim` arm of `xmr_rpc::WalletRpc`, every method the
/// production surface has, answered by the world.
pub struct SimWallet {
    chain: Arc<Mutex<SimMonero>>,
    /// The wallet this handle has OPEN, and every wallet FILE it holds by name. A wallet-rpc keeps one wallet file
    /// per name in its directory and has one open at a time; the custody lane names one per member set
    /// (`xmr_custody::wallet_name`), so a custodian whose set changed holds the old set's wallet beside the new one —
    /// with whatever the old one still holds (finding A-F20). Before 2026-11-11 this handle was ONE wallet whatever
    /// name was opened, so a changed set read the old set's wallet as its own and the stranded coins never showed.
    held: Mutex<(u32, BTreeMap<String, u32>)>,
}

impl SimWallet {
    /// Opens a fresh wallet on `chain` (what `WalletRpc::from_env` does once per custody lane).
    pub fn open(chain: Arc<Mutex<SimMonero>>) -> SimWallet {
        let id = chain.lock().unwrap_or_else(|e| e.into_inner()).open_wallet();
        SimWallet { chain, held: Mutex::new((id, BTreeMap::new())) }
    }

    /// The wallet this handle has open.
    pub fn id(&self) -> u32 {
        self.held.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    fn c(&self) -> MutexGuard<'_, SimMonero> {
        self.chain.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get_version(&self) -> Result<u64, String> {
        Ok(0x1_0014) // v1.20 — the shape of a wallet-rpc's `get_version`
    }
    /// Opens the wallet file `name`, creating it when this handle holds none by that name (`Ok(true)`). The first name
    /// a handle opens is the wallet it was made with (multisig-enabled already: the CLI switch is never run on a
    /// simulated wallet); every further name is a fresh wallet of its own.
    pub fn open_or_create(&self, name: &str, _password: &str) -> Result<bool, String> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(id) = held.1.get(name).copied() {
            held.0 = id;
            return Ok(false);
        }
        if held.1.is_empty() {
            let id = held.0;
            held.1.insert(name.to_string(), id);
            return self.c().wallet(id).map(|_| false);
        }
        let id = self.c().open_wallet();
        held.1.insert(name.to_string(), id);
        held.0 = id;
        Ok(true)
    }
    pub fn close(&self) -> Result<(), String> {
        self.c().wallet(self.id()).map(|_| ())
    }
    pub fn address(&self) -> Result<String, String> {
        self.c().w_address(self.id())
    }
    pub fn is_multisig(&self) -> Result<(bool, bool, u32, u32), String> {
        self.c().w_is_multisig(self.id())
    }
    pub fn prepare_multisig(&self) -> Result<String, String> {
        self.c().w_prepare(self.id())
    }
    pub fn make_multisig(&self, others: &[String], threshold: u32) -> Result<String, String> {
        self.c().w_make(self.id(), others, threshold)
    }
    pub fn exchange_multisig_keys(&self, others: &[String]) -> Result<String, String> {
        self.c().w_exchange(self.id(), others)
    }
    pub fn export_multisig_info(&self) -> Result<String, String> {
        self.c().w_export(self.id())
    }
    pub fn import_multisig_info(&self, infos: &[String]) -> Result<u64, String> {
        self.c().w_import(self.id(), infos)
    }
    pub fn refresh(&self) -> Result<(), String> {
        self.c().wallet(self.id()).map(|_| ())
    }
    pub fn balance(&self) -> Result<(u64, u64, bool), String> {
        self.c().w_balance(self.id())
    }
    pub fn incoming(&self) -> Result<Vec<Incoming>, String> {
        self.c().w_incoming(self.id())
    }
    pub fn transfer_multisig(&self, destinations: &[(String, u64)]) -> Result<String, String> {
        self.c().w_transfer_multisig(self.id(), destinations)
    }
    pub fn transfer_relay(&self, destinations: &[(String, u64)]) -> Result<String, String> {
        self.c().w_transfer_relay(self.id(), destinations)
    }
    pub fn describe_multisig(&self, txset: &str) -> Result<(Vec<Recipient>, u64), String> {
        self.c().w_describe(txset)
    }
    pub fn sign_multisig(&self, txset: &str) -> Result<(String, Vec<String>), String> {
        self.c().w_sign(self.id(), txset)
    }
    pub fn submit_multisig(&self, txset: &str) -> Result<Vec<String>, String> {
        self.c().w_submit(self.id(), txset)
    }
    pub fn tx_confirmations(&self, txid: &str) -> Result<Option<u64>, String> {
        self.c().w_tx_confirmations(txid)
    }
    pub fn transfer_fee(&self, txid: &str) -> Result<Option<(u64, u64, u64, bool)>, String> {
        self.c().w_transfer_fee(self.id(), txid)
    }
    pub fn sent_fee(&self, txid: &str) -> Result<Option<(u64, u64)>, String> {
        self.c().w_sent_fee(self.id(), txid)
    }
}

/// The daemon every custodian follows — the `Sim` arm of `xmr_rpc::DaemonRpc`.
pub struct SimDaemon {
    chain: Arc<Mutex<SimMonero>>,
}

impl SimDaemon {
    pub fn new(chain: Arc<Mutex<SimMonero>>) -> SimDaemon {
        SimDaemon { chain }
    }
    pub fn fee_per_byte(&self) -> Result<u64, String> {
        Ok(self.chain.lock().unwrap_or_else(|e| e.into_inner()).fee_per_byte())
    }
    pub fn height(&self) -> Result<u64, String> {
        Ok(self.chain.lock().unwrap_or_else(|e| e.into_inner()).block_count())
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    //! Every pin drives the world through the PRODUCTION surface (`xmr_rpc::WalletRpc::from_env` → the Sim arm, the
    //! production watcher's sweep), never through the sim's own methods where a production path exists; and every
    //! verdict is first shown to FAIL on a planted defect (`Plant`).
    use super::*;
    use crate::xmr_rpc::WalletRpc;
    use crate::xmr_watch::{confirmed_pending_cached, required_confirmations, retire_reserve_watch, sweep_now, watch_issued_reserve};

    const XMR: u64 = crate::xmr_rpc::XMR_ATOMIC_PER_XMR;

    /// Three custodians form a 2-of-3 wallet through the production `WalletRpc` surface by Monero's rounds
    /// (prepare → make → exchange × (n − k)), every member landing on the same address.
    fn form_2_of_3() -> Result<(Vec<WalletRpc>, String), String> {
        let wallets: Vec<WalletRpc> = (0..3).map(|_| WalletRpc::from_env().ok_or("the sim is not installed")).collect::<Result<_, _>>()?;
        let k = crate::xmr_custody::threshold(3);
        if k != 2 {
            return Err(format!("CALIBRATION: threshold(3) = {k}, expected 2"));
        }
        let mut infos: Vec<String> = wallets.iter().map(|w| w.prepare_multisig()).collect::<Result<_, _>>()?;
        let mut round = 0u8;
        loop {
            let mut next = Vec::with_capacity(3);
            let mut ready_count = 0;
            for (i, w) in wallets.iter().enumerate() {
                let others: Vec<String> = infos.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, s)| s.clone()).collect();
                let out = if round == 0 { w.make_multisig(&others, k, "")? } else { w.exchange_multisig_keys(&others, "")? };
                let (_, ready, kk, nn) = w.is_multisig()?;
                if (kk, nn) != (2, 3) {
                    return Err(format!("is_multisig reports {kk}-of-{nn}"));
                }
                if ready {
                    ready_count += 1;
                }
                next.push(out);
            }
            round += 1;
            if ready_count == 3 {
                break;
            }
            if ready_count != 0 || round > 4 {
                return Err(format!("the members finished out of step: {ready_count} ready after round {round}"));
            }
            infos = next;
        }
        if round != crate::xmr_custody::final_round(3, k) + 1 {
            return Err(format!("the wallet took {round} rounds, Monero's count is {}", crate::xmr_custody::final_round(3, k) + 1));
        }
        let addrs: Vec<String> = wallets.iter().map(|w| w.address()).collect::<Result<_, _>>()?;
        if addrs[0] != addrs[1] || addrs[1] != addrs[2] {
            return Err("the members derived different account addresses".into());
        }
        if crate::bridge::decode_monero_standard_address(&addrs[0]).is_none() {
            return Err("the account address is not a checksummed standard Monero address".into());
        }
        Ok((wallets, addrs[0].clone()))
    }

    /// A deposit to a swap's integrated address matures under `required_confirmations` as the PRODUCTION watcher
    /// sweeps it from the custody wallet, and a reorg whose double-spend evicts the funding takes it back.
    fn reorg_verdict(plant: Plant) -> Result<(), String> {
        let mut sim = SimMonero::new(0x5111_2026_1027);
        sim.plant = plant;
        let w = install(sim);
        let (wallets, account) = form_2_of_3()?;
        let pid = [0x5A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let integrated = crate::bridge::xmr_integrated_address(&account, &pid).ok_or("integrated address")?;
        if !watch_issued_reserve(&integrated) {
            return Err("the production watcher refused the integrated address".into());
        }
        let atomic = 12 * XMR; // 20 tail emissions: THORChain's count exceeds Monero's lock
        let need = required_confirmations(atomic);
        if need != 20 {
            return Err(format!("CALIBRATION: 12 XMR needs {need} confirmations, expected 20"));
        }
        let txid = w.chain().fund(&integrated, atomic)?;
        let custodian = &wallets[1];
        let read = |label: &str| -> Result<(u64, u64), String> {
            sweep_now(custodian)?;
            confirmed_pending_cached(&integrated).ok_or_else(|| format!("{label}: the watcher holds no read for the address"))
        };
        if read("in the pool")? != (0, 0) {
            return Err(format!("in the pool the deposit is not seen by the wallet: {:?}", read("pool")?));
        }
        w.chain().mine(1);
        if read("at 1")? != (0, atomic) {
            return Err(format!("at 1 confirmation the deposit should be pending: {:?}", read("1")?));
        }
        w.chain().mine(need - 2);
        if read("at need-1")? != (0, atomic) {
            return Err(format!("at {} confirmations the deposit should still be pending: {:?}", need - 1, read("need-1")?));
        }
        w.chain().mine(1);
        if read("at need")? != (atomic, 0) {
            return Err(format!("at {need} confirmations the deposit should be matured: {:?}", read("need")?));
        }
        let display = crate::btc_tx::hex(&txid);
        if custodian.tx_confirmations(&display)? != Some(need) {
            return Err(format!("the wallet counts {:?} confirmations, expected {need}", custodian.tx_confirmations(&display)?));
        }
        // THE ATTACK: the chain reorganizes from the deposit's block and the depositor spends the same input elsewhere.
        let deposit_height = w.chain().tip_height() - need + 1;
        w.chain().invalidate_block(deposit_height)?;
        let conflict = w.chain().double_spend_funding(&txid);
        let conflict = match (plant, conflict) {
            (_, Ok(c)) => c,
            // the planted world never put the funding back in the pool: the attack cannot even be staged, and the
            // deposit stays matured — the verdict below says so
            (Plant::IgnoreReorg, Err(_)) => [0u8; 32],
            (_, Err(e)) => return Err(e),
        };
        w.chain().mine(need + 1);
        let after = read("after the reorg")?;
        if after != (0, 0) {
            return Err(format!("⛔ the deposit SURVIVED the double-spend reorg: matured {} pending {}", after.0, after.1));
        }
        if custodian.tx_confirmations(&display)?.is_some() {
            return Err("⛔ the evicted funding is still known to the wallet".into());
        }
        if custodian.tx_confirmations(&crate::btc_tx::hex(&conflict))? != Some(need + 1) {
            return Err("the conflicting spend did not confirm".into());
        }
        retire_reserve_watch(&integrated);
        Ok(())
    }

    #[test]
    fn a_deposit_matures_by_the_production_sweep_and_a_double_spend_reorg_takes_it_back() {
        let _serial = serial().lock().unwrap_or_else(|e| e.into_inner());
        reorg_verdict(Plant::None).unwrap_or_else(|e| panic!("⛔ {e}"));
        let planted = reorg_verdict(Plant::IgnoreReorg);
        assert!(planted.is_err(), "CALIBRATION: a world that ignores reorgs must fail this verdict");
    }

    /// The 2-of-3 payout: proposed by one member (`transfer_multisig`), described and signed in turn through the
    /// production surface, relayed by `submit_multisig` only with two distinct member signatures; a flipped
    /// signature byte, a one-signature set, a copied signature, a non-member's signature, an altered body and a
    /// replay are each refused; the fee the set carries passes the payout lane's own F7 rule against the daemon's
    /// estimate.
    fn payout_verdict(plant: Plant) -> Result<(), String> {
        let mut sim = SimMonero::new(0x9A70_2026_1027);
        sim.plant = plant;
        let w = install(sim);
        let (wallets, account) = form_2_of_3()?;
        let stranger = WalletRpc::from_env().ok_or("sim")?;
        let redeemer = address_of(b"redeemer", b"redeemer-1");
        let dep = 5 * XMR;
        let pay = 2 * XMR;
        w.chain().fund(&account, dep)?;
        w.chain().mine(SPEND_LOCK_BLOCKS);
        let (bal, unlocked, import_needed) = wallets[0].balance()?;
        if (bal, unlocked, import_needed) != (dep, dep, false) {
            return Err(format!("the account balance reads {bal}/{unlocked}/{import_needed}, expected {dep}/{dep}/false"));
        }
        // 1. The honest quorum: a proposes, c signs second, submits.
        let set = wallets[0].transfer_multisig(&[(redeemer.clone(), pay)])?;
        let (recipients, fee) = wallets[2].describe_multisig(&set)?;
        // the fee comes out of the payout, by `subtract_fee_from_outputs`: the redeemer gets `pay − fee`, the account falls by `pay`
        if fee == 0 || recipients != vec![Recipient { address: redeemer.clone(), amount: pay - fee }] {
            return Err(format!("describe reads {recipients:?} (fee {fee})"));
        }
        let per_byte = crate::xmr_rpc::DaemonRpc::from_env().ok_or("no daemon")?.fee_per_byte()?;
        let ceiling = per_byte * (set.len() as u64 / 2) * crate::xmr_payout::XMR_FEE_CEIL_MULTIPLE;
        if fee == 0 || fee > ceiling {
            return Err(format!("the set's fee {fee} is outside the payout lane's F7 ceiling {ceiling}"));
        }
        let (set_a, hashes_a) = wallets[0].sign_multisig(&set)?;
        if !hashes_a.is_empty() {
            return Err("one signature of two already names a tx hash".into());
        }
        if wallets[2].submit_multisig(&set_a).is_ok() {
            return Err("⛔ a ONE-signature set of a 2-of-3 wallet was relayed".into());
        }
        let (set_ac, hashes) = wallets[2].sign_multisig(&set_a)?;
        if hashes.len() != 1 {
            return Err(format!("two signatures name {} tx hashes", hashes.len()));
        }
        let relayed = wallets[2].submit_multisig(&set_ac)?;
        if relayed != hashes {
            return Err(format!("submit relayed {relayed:?}, the signed set named {hashes:?}"));
        }
        w.chain().mine(SPEND_LOCK_BLOCKS);
        if wallets[1].tx_confirmations(&relayed[0])? != Some(SPEND_LOCK_BLOCKS) {
            return Err(format!("the payout counts {:?} confirmations", wallets[1].tx_confirmations(&relayed[0])?));
        }
        let got = w.chain().received_atomic(&redeemer).ok_or("the redeemer's address")?;
        if got != pay - fee {
            return Err(format!("the redeemer received {got} atomic, expected {} (the payout less its fee)", pay - fee));
        }
        let (bal, _, _) = wallets[1].balance()?;
        if bal != dep - pay {
            return Err(format!("the account's change reads {bal}, expected {} — it must fall by exactly the payout", dep - pay));
        }
        if wallets[2].submit_multisig(&set_ac).is_ok() {
            return Err("⛔ the same set was relayed TWICE".into());
        }
        // 2. One flipped byte in one of the two signatures.
        let set = wallets[0].transfer_multisig(&[(redeemer.clone(), pay)])?;
        let (set_a, _) = wallets[0].sign_multisig(&set)?;
        let (set_ac, _) = wallets[2].sign_multisig(&set_a)?;
        let mut forged = TxSet::decode(&set_ac)?;
        forged.sigs[0].1[10] ^= 0x01;
        if wallets[2].submit_multisig(&forged.encode()?).is_ok() {
            return Err("⛔ a set with a FLIPPED signature byte was relayed".into());
        }
        // 3. A member's signature copied under another member's key (two "distinct" members, one real signer).
        let mut copied = TxSet::decode(&set_a)?;
        let tag_a = copied.sigs[0].1;
        let pk_b = TxSet::decode(&wallets[1].sign_multisig(&set)?.0)?.sigs[0].0;
        copied.sigs.push((pk_b, tag_a));
        if wallets[2].submit_multisig(&copied.encode()?).is_ok() {
            return Err("⛔ a set with one signature COPIED under a second member's key was relayed".into());
        }
        // 4. A signer outside the quorum: the stranger's wallet is not a member and has no set to sign.
        if stranger.sign_multisig(&set_a).is_ok() {
            return Err("⛔ a NON-MEMBER wallet signed the set".into());
        }
        let mut outsider = TxSet::decode(&set_a)?;
        let digest = outsider.digest();
        outsider.sigs.push((blake(b"stranger-pub", &[b"x"]), SimMonero::sign_body(&blake(b"stranger-secret", &[b"x"]), &digest)));
        if wallets[2].submit_multisig(&outsider.encode()?).is_ok() {
            return Err("⛔ a set signed by a NON-MEMBER was relayed".into());
        }
        // 5. A body changed after signing (the destination amount doubled).
        let mut altered = TxSet::decode(&set_ac)?;
        altered.dests[0].1 = pay * 2;
        if wallets[2].submit_multisig(&altered.encode()?).is_ok() {
            return Err("⛔ a set ALTERED after signing was relayed".into());
        }
        // The honest quorum (b and c this time) still relays the untouched set.
        let (set_ab, _) = wallets[1].sign_multisig(&set_a)?;
        wallets[1].submit_multisig(&set_ab).map_err(|e| format!("the honest quorum was refused after the forgeries: {e}"))?;
        Ok(())
    }

    #[test]
    fn a_quorum_signed_payout_relays_through_the_production_surface_and_every_forgery_is_refused() {
        let _serial = serial().lock().unwrap_or_else(|e| e.into_inner());
        payout_verdict(Plant::None).unwrap_or_else(|e| panic!("⛔ {e}"));
        let planted = payout_verdict(Plant::AcceptAnySigners);
        assert!(planted.is_err(), "CALIBRATION: a world that relays any signatures must fail this verdict");
    }

    /// The founding custodian alone: a plain wallet builds AND relays (`transfer_relay`), as the payout lane does
    /// for a one-member set; a multisig account cannot take that door.
    #[test]
    fn a_one_member_set_relays_its_own_payment_and_a_multisig_account_cannot() {
        let _serial = serial().lock().unwrap_or_else(|e| e.into_inner());
        let w = install(SimMonero::new(0x1111_2026_1027));
        let founder = WalletRpc::from_env().expect("sim");
        let (is_ms, _, _, _) = founder.is_multisig().expect("is_multisig");
        assert!(!is_ms, "a fresh wallet is plain");
        let redeemer = address_of(b"redeemer", b"redeemer-2");
        let own = founder.address().expect("address");
        w.chain().fund(&own, 3 * XMR).expect("fund");
        w.chain().mine(SPEND_LOCK_BLOCKS - 1);
        assert!(founder.transfer_relay(&[(redeemer.clone(), XMR)]).is_err(), "⛔ an output under Monero's 10-block lock was spent");
        w.chain().mine(1);
        let txid = founder.transfer_relay(&[(redeemer.clone(), XMR)]).expect("the plain wallet relays its own payment");
        assert_eq!(founder.tx_confirmations(&txid).expect("known"), Some(0), "in the pool");
        w.chain().mine(1);
        // the payout bears its own fee: the redeemer receives less than XMR, and the founder's wallet falls by exactly XMR
        let got = w.chain().received_atomic(&redeemer).expect("received");
        assert!(got < XMR && got > XMR - XMR / 1_000, "the payout less Monero's network fee, got {got}");
        assert_eq!(founder.balance().expect("balance").0, 2 * XMR, "⛔ the fee came out of the reserve, not the payout");
        let (wallets, _) = form_2_of_3().expect("2-of-3");
        assert!(wallets[0].transfer_relay(&[(redeemer, XMR)]).is_err(), "⛔ a multisig wallet relayed without its quorum");
    }

    /// The simulated clock mines one block per interval, and a received output is locked for Monero's ten blocks.
    #[test]
    fn the_chain_mines_on_the_simulated_clock_and_an_output_waits_moneros_lock() {
        let mut sim = SimMonero::new(1);
        assert_eq!(sim.tip_height(), 0, "a fresh chain is at genesis");
        assert_eq!(sim.block_count(), 1);
        sim.advance_clock(3 * BLOCK_INTERVAL_MS - 1);
        assert_eq!(sim.tip_height(), 2, "two intervals passed → two blocks");
        sim.advance_clock(3 * BLOCK_INTERVAL_MS);
        assert_eq!(sim.tip_height(), 3);
        sim.block_interval_ms = 30_000; // takes effect after the block already scheduled at 4 × 120 s
        sim.advance_clock(4 * BLOCK_INTERVAL_MS + 60_000);
        assert_eq!(sim.tip_height(), 6, "a faster interval mines faster on the same clock");
        let id = sim.open_wallet();
        let own = sim.w_address(id).expect("address");
        sim.fund(&own, 7 * XMR).expect("fund");
        sim.mine(1);
        for conf in 1..SPEND_LOCK_BLOCKS {
            assert_eq!(sim.w_balance(id).expect("balance"), (7 * XMR, 0, false), "locked at {conf} confirmations");
            sim.mine(1);
        }
        assert_eq!(sim.w_balance(id).expect("balance"), (7 * XMR, 7 * XMR, false), "unlocked at {SPEND_LOCK_BLOCKS}");
        assert_eq!(sim.incoming_for(&own).len(), 1);
        assert_eq!(sim.incoming_for(&own)[0].payment_id, "0000000000000000", "a transfer without a payment id reports zeros, as get_transfers does");
        assert!(sim.invalidate_block(99).is_err(), "a reorg from a height off the chain is refused");
    }
}

//! MonerousD Protocol — §NETSIM-LAUNCH: the SIMULATED BITCOIN CHAIN (DB-121 sim world, lane b 2026-10-27).
//!
//! An in-process Bitcoin with Bitcoin Core REGTEST semantics, so every bridge flow (deposit seen, confirmations
//! counted, co-signed payout broadcast, self-refund under a relative timelock, a reorg or a double-spend taking a
//! deposit back) runs inside the deterministic simulator on ITS clock — never against mempool.space or a daemon.
//! Installed, it is what `btc_watch::btc_source` hands every caller (`BtcSource::Sim`), so the deposit watcher,
//! the payout lane and the solvency check read it through their PRODUCTION code, unchanged.
//!
//! BORROWED, NOT DERIVED (AGENTS.md §1): the UTXO set is a FUNCTION OF THE CHAIN, recomputed from the blocks on every
//! query (Ethereum STF: local state is a cache), so a reorg is a truncation and nothing else; disconnected
//! transactions return to the mempool and conflicts are dropped (Bitcoin Core `UpdateMempoolForReorg`); a
//! conflicting mempool transaction replaces only at a strictly higher fee (full-RBF, Core ≥ 28); a coinbase spends
//! after 100 blocks (`COINBASE_MATURITY`); a relative lock is judged by BIP 68 at the input and BIP 112 in the script;
//! a script-path spend is judged by BIP 341 (control block → output key) and BIP 342 (`OP_CHECKSIGADD`
//! multisig, `OP_CHECKSEQUENCEVERIFY`), signatures by BIP 340 (`btc_tx::verify_sighash_sig`).
//!
//! §9.6 NEW-DOOR CHECKLIST for `broadcast` (the one door a node's bytes enter this world by): (1) no PoW here — this
//! is the foreign chain, its blocks are the simulator's; (2) the transaction's own proof is its witness, verified by
//! `verify_script_path` (BIP 340/341/342) against the prevout it spends; (3) value is created only by the coinbase
//! and conserved by `admit` (sum in ≥ sum out, fee ≥ 1 sat/vB); (4) a replay is refused by the UTXO SET (an input
//! spent on the chain or in the mempool is refused, or replaced only under RBF); (5) work is bounded by the chain's
//! own length — a test scaffold, never a node's state; (6) parity with Bitcoin Core's `sendrawtransaction`: the
//! checks it lacks are named in `admit` (no time-based relative locks, no annex, SIGHASH_DEFAULT only — each
//! REFUSED, never assumed).
//!
//! What is NOT simulated (stated, fail-closed): the miner wallet's own spends (`fund`, the double-spend) carry no
//! witness and are trusted as Core trusts its own wallet; time-based relative locks and absolute locktimes refuse;
//! key-path spends refuse (the reserve has no key-path spender by construction, `btc_tx::NUMS_X`).

use crate::btc_tx::{self, CustodyLeaf, Payout, TxIn, TxOut};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

/// Bitcoin Core: a coinbase output spends after 100 further blocks.
pub const COINBASE_MATURITY: u64 = 100;
/// The regtest block subsidy (50 BTC) in sats.
pub const COINBASE_SATS: u64 = 5_000_000_000;
/// Core's `minrelaytxfee`, 1 sat/vB.
pub const MIN_RELAY_SAT_VB: u64 = 1;
/// Core's `incrementalrelayfee`: a replacement pays at least this much more per vB than what it evicts.
pub const INCREMENTAL_RELAY_SAT_VB: u64 = 1;
/// Mainnet's cadence; the simulator's clock mines one block per interval (`advance_clock`).
pub const BLOCK_INTERVAL_MS: u64 = 600_000;
/// The vbytes the miner wallet's own one-in-two-out taproot spend weighs (Core's own estimate for that shape).
const MINER_SPEND_VBYTES: u64 = 141;
const OP_CSV: u8 = 0xb2;
const OP_DROP: u8 = 0x75;
const SEQUENCE_DISABLE: u32 = 1 << 31;
const SEQUENCE_TIME_TYPE: u32 = 1 << 22;
const SEQUENCE_MASK: u32 = 0xffff;

pub type Outpoint = ([u8; 32], u32);

/// One input as the chain holds it (the prevout is looked up, never carried).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimIn {
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: u32,
}

/// A transaction as the chain holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimTx {
    pub txid: [u8; 32],
    pub inputs: Vec<SimIn>,
    pub outputs: Vec<TxOut>,
    pub vbytes: u64,
    pub coinbase: bool,
}

impl SimTx {
    fn total_out(&self) -> u64 {
        self.outputs.iter().fold(0u64, |a, o| a.saturating_add(o.value_sats))
    }
}

/// A defect PLANTED to prove a pin can fail (user: every instrument fails on a planted defect first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plant {
    None,
    /// `invalidate_block` does nothing — a world where a reorg never takes a deposit back.
    IgnoreReorg,
    /// `broadcast` admits any witness — a world where a forged payout "arrives".
    AcceptAnyWitness,
}

/// The simulated chain. Test scaffold: the block vector is bounded by the blocks a fixed-length run mines; no node
/// holds it (O1-FOOTPRINT-REVIEWED: the foreign chain of the simulator, never node state).
pub struct SimBitcoin {
    /// `blocks[i]` is height `i + 1`; genesis (height 0) carries nothing.
    blocks: Vec<Vec<SimTx>>,
    mempool: Vec<SimTx>,
    miner_spk: Vec<u8>,
    seed: u64,
    fee_rate_sat_vb: u64,
    next_block_at_ms: u64,
    pub block_interval_ms: u64,
    pub plant: Plant,
    coinbases_made: u64,
}

impl SimBitcoin {
    /// A fresh regtest with 101 blocks mined to the miner wallet (the first coinbase is spendable), as every regtest
    /// script begins.
    pub fn new(seed: u64) -> SimBitcoin {
        let secret: [u8; 32] = *blake3::hash(&seed.to_le_bytes()).as_bytes();
        let x = btc_tx::xonly_pubkey(&secret).expect("a hash is a valid key with overwhelming probability"); // CLASSICAL-CRYPTO-EXEMPT: the sim miner wallet's key on Bitcoin's own curve (bridge endpoint)
        let mut sim = SimBitcoin {
            blocks: Vec::new(),
            mempool: Vec::new(),
            miner_spk: btc_tx::p2tr_script_pubkey(&x),
            seed,
            fee_rate_sat_vb: 2,
            next_block_at_ms: BLOCK_INTERVAL_MS,
            block_interval_ms: BLOCK_INTERVAL_MS,
            plant: Plant::None,
            coinbases_made: 0,
        };
        sim.mine(COINBASE_MATURITY + 1);
        sim.next_block_at_ms = sim.block_interval_ms; // the initial mining is instant; the clock's first block is one interval in
        sim
    }

    pub fn tip_height(&self) -> u64 {
        self.blocks.len() as u64
    }

    pub fn fee_rate_sat_vb(&self) -> u64 {
        self.fee_rate_sat_vb
    }

    /// The block cadence, set before the clock starts: the first block comes one interval in, then one per interval.
    pub fn set_block_interval_ms(&mut self, ms: u64) {
        self.block_interval_ms = ms.max(1);
        self.next_block_at_ms = self.block_interval_ms;
    }

    pub fn set_fee_rate_sat_vb(&mut self, rate: u64) {
        self.fee_rate_sat_vb = rate.max(MIN_RELAY_SAT_VB);
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    /// The UTXO set as a function of the chain: every unspent output with the height that confirmed it.
    fn utxo_set(&self) -> BTreeMap<Outpoint, (TxOut, u64)> {
        let mut set: BTreeMap<Outpoint, (TxOut, u64)> = BTreeMap::new();
        for (i, block) in self.blocks.iter().enumerate() {
            let height = i as u64 + 1;
            for tx in block {
                for inp in &tx.inputs {
                    set.remove(&(inp.txid, inp.vout));
                }
                for (v, o) in tx.outputs.iter().enumerate() {
                    set.insert((tx.txid, v as u32), (o.clone(), height));
                }
            }
        }
        set
    }

    /// Outpoints the mempool already spends, each with the index of the spender (for RBF).
    fn mempool_spends(&self) -> BTreeMap<Outpoint, usize> {
        let mut m = BTreeMap::new();
        for (i, tx) in self.mempool.iter().enumerate() {
            for inp in &tx.inputs {
                m.insert((inp.txid, inp.vout), i);
            }
        }
        m
    }

    fn mempool_output(&self, op: &Outpoint) -> Option<TxOut> {
        self.mempool.iter().find(|t| t.txid == op.0).and_then(|t| t.outputs.get(op.1 as usize).cloned())
    }

    /// A transaction's fee against the chain + mempool prevouts (`None` when an input is unknown).
    fn fee_of(&self, tx: &SimTx, utxo: &BTreeMap<Outpoint, (TxOut, u64)>) -> Option<u64> {
        let mut total_in = 0u64;
        for inp in &tx.inputs {
            let op = (inp.txid, inp.vout);
            let value = match utxo.get(&op) {
                Some((o, _)) => o.value_sats,
                None => self.mempool_output(&op)?.value_sats,
            };
            total_in = total_in.saturating_add(value);
        }
        total_in.checked_sub(tx.total_out())
    }

    /// Bitcoin Core's mempool admission for one transaction (`AcceptToMemoryPool`), the checks this world keeps and
    /// the ones it refuses outright. Returns the replaced mempool indexes (RBF) on success.
    fn admit(&self, tx: &SimTx, version: i32, locktime: u32) -> Result<Vec<usize>, String> {
        if tx.inputs.is_empty() || tx.outputs.is_empty() {
            return Err("bad-txns-vin-empty".into());
        }
        if locktime != 0 {
            return Err("absolute locktimes are not simulated (refused, never assumed)".into());
        }
        let mut seen: BTreeSet<Outpoint> = BTreeSet::new();
        for inp in &tx.inputs {
            if !seen.insert((inp.txid, inp.vout)) {
                return Err("bad-txns-inputs-duplicate".into());
            }
        }
        let utxo = self.utxo_set();
        let tip = self.tip_height();
        let spends = self.mempool_spends();
        let mut replaced: BTreeSet<usize> = BTreeSet::new();
        for inp in &tx.inputs {
            let op = (inp.txid, inp.vout);
            if let Some(&i) = spends.get(&op) {
                if self.mempool[i].txid == tx.txid {
                    return Err("txn-already-in-mempool".into());
                }
                replaced.insert(i);
            }
            let confirmed_height = match utxo.get(&op) {
                Some((_, h)) => {
                    // A coinbase output waits COINBASE_MATURITY blocks (Core: `bad-txns-premature-spend-of-coinbase`).
                    let is_coinbase = self.blocks[*h as usize - 1].first().is_some_and(|c| c.txid == op.0);
                    if is_coinbase && tip + 1 < h + COINBASE_MATURITY {
                        return Err("bad-txns-premature-spend-of-coinbase".into());
                    }
                    Some(*h)
                }
                None => {
                    if self.mempool_output(&op).is_none() {
                        return Err(format!("missing-inputs: {}:{}", btc_tx::txid_display_hex(&op.0), op.1));
                    }
                    None
                }
            };
            // BIP 68: a relative lock on a version-2 transaction, judged against the NEXT block's height.
            if version >= 2 && inp.sequence & SEQUENCE_DISABLE == 0 {
                if inp.sequence & SEQUENCE_TIME_TYPE != 0 {
                    return Err("time-based relative locks are not simulated (refused, never assumed)".into());
                }
                let lock = u64::from(inp.sequence & SEQUENCE_MASK);
                let ok = match confirmed_height {
                    Some(h) => tip + 1 >= h + lock,
                    None => lock == 0,
                };
                if !ok {
                    return Err("non-BIP68-final".into());
                }
            }
        }
        let fee = self.fee_of(tx, &utxo).ok_or_else(|| "bad-txns-in-belowout".to_string())?;
        if fee < tx.vbytes.saturating_mul(MIN_RELAY_SAT_VB) {
            return Err(format!("min relay fee not met: {fee} sat for {} vB", tx.vbytes));
        }
        if !replaced.is_empty() {
            // Full-RBF (Core ≥ 28): the replacement pays more than everything it evicts, by the incremental relay fee.
            let evicted_fee: u64 = replaced.iter().filter_map(|&i| self.fee_of(&self.mempool[i], &utxo)).sum();
            if fee < evicted_fee.saturating_add(tx.vbytes.saturating_mul(INCREMENTAL_RELAY_SAT_VB)) {
                return Err(format!("insufficient fee, rejecting replacement: {fee} ≤ {evicted_fee} + incremental"));
            }
        }
        Ok(replaced.into_iter().collect())
    }

    fn push_mempool(&mut self, tx: SimTx, replaced: Vec<usize>) {
        let mut idx = replaced;
        idx.sort_unstable_by(|a, b| b.cmp(a));
        for i in idx {
            let gone = self.mempool.remove(i);
            eprintln!("[btc-sim] RBF: {}… replaced by {}…", h8(&gone.txid), h8(&tx.txid));
        }
        self.mempool.push(tx);
    }

    /// After a reorg or a block, every mempool transaction is judged again in order; a conflicted one is dropped
    /// (Core: `removeForReorg` / `removeConflicts`).
    fn revalidate_mempool(&mut self) {
        let old = std::mem::take(&mut self.mempool);
        for tx in old {
            match self.admit(&tx, btc_tx::TX_VERSION, btc_tx::LOCK_TIME) {
                Ok(replaced) if replaced.is_empty() => self.mempool.push(tx),
                Ok(_) => eprintln!("[btc-sim] dropped {}… (conflicts in the mempool after reorg)", h8(&tx.txid)),
                Err(e) => eprintln!("[btc-sim] dropped {}… after reorg: {e}", h8(&tx.txid)),
            }
        }
    }

    fn coinbase(&mut self, height: u64, fees: u64) -> SimTx {
        self.coinbases_made += 1;
        let mut pre = Vec::with_capacity(48);
        pre.extend_from_slice(b"usdmd-btc-sim-coinbase");
        pre.extend_from_slice(&self.seed.to_le_bytes());
        pre.extend_from_slice(&height.to_le_bytes());
        pre.extend_from_slice(&self.coinbases_made.to_le_bytes());
        SimTx {
            txid: btc_tx::sha256d(&pre),
            inputs: Vec::new(),
            outputs: vec![TxOut { value_sats: COINBASE_SATS.saturating_add(fees), script_pubkey: self.miner_spk.clone() }],
            vbytes: 100,
            coinbase: true,
        }
    }

    /// Mine `n` blocks (`generatetoaddress`): each takes every admissible mempool transaction in order, pays the fees to
    /// the coinbase, and the remainder is judged again.
    pub fn mine(&mut self, n: u64) {
        for _ in 0..n {
            let height = self.tip_height() + 1;
            let mut block: Vec<SimTx> = Vec::new();
            let mut fees = 0u64;
            let pending = std::mem::take(&mut self.mempool);
            let mut leftover = Vec::new();
            for tx in pending {
                // Judged against the chain as this block extends it: push provisionally, roll back after the verdict.
                self.blocks.push(block.clone());
                let verdict = self.admit(&tx, btc_tx::TX_VERSION, btc_tx::LOCK_TIME);
                self.blocks.pop();
                match verdict {
                    Ok(_) => {
                        fees = fees.saturating_add(self.fee_of(&tx, &self.utxo_set_with(&block)).unwrap_or(0));
                        block.push(tx);
                    }
                    Err(_) => leftover.push(tx),
                }
            }
            let cb = self.coinbase(height, fees);
            block.insert(0, cb);
            self.blocks.push(block);
            self.mempool = leftover;
            self.revalidate_mempool();
            self.next_block_at_ms = self.next_block_at_ms.saturating_add(self.block_interval_ms);
        }
    }

    fn utxo_set_with(&self, extra: &[SimTx]) -> BTreeMap<Outpoint, (TxOut, u64)> {
        let mut set = self.utxo_set();
        let height = self.tip_height() + 1;
        for tx in extra {
            for inp in &tx.inputs {
                set.remove(&(inp.txid, inp.vout));
            }
            for (v, o) in tx.outputs.iter().enumerate() {
                set.insert((tx.txid, v as u32), (o.clone(), height));
            }
        }
        set
    }

    /// The simulator's clock: one block per `block_interval_ms` of simulated time.
    pub fn advance_clock(&mut self, now_ms: u64) {
        while now_ms >= self.next_block_at_ms {
            self.mine(1);
        }
    }

    /// `invalidateblock` at `height`: that block and everything above it leave the chain; their transactions return
    /// to the mempool and are judged again (a conflicted one is dropped).
    pub fn invalidate_block(&mut self, height: u64) {
        if self.plant == Plant::IgnoreReorg {
            return;
        }
        if height == 0 || height > self.tip_height() {
            return;
        }
        let gone: Vec<Vec<SimTx>> = self.blocks.drain((height - 1) as usize..).collect();
        let mut back: Vec<SimTx> = gone.into_iter().flatten().filter(|t| !t.coinbase).collect();
        back.append(&mut self.mempool);
        self.mempool = back;
        self.revalidate_mempool();
    }

    /// A mature miner coin not spent by the mempool, worth at least `need`.
    fn miner_coin(&self, need: u64) -> Option<(Outpoint, u64)> {
        let utxo = self.utxo_set();
        let spends = self.mempool_spends();
        let tip = self.tip_height();
        utxo.iter()
            .filter(|(op, (o, h))| o.script_pubkey == self.miner_spk && tip + 1 >= *h + COINBASE_MATURITY && !spends.contains_key(op))
            .filter(|(_, (o, _))| o.value_sats >= need)
            .map(|(op, (o, _))| (*op, o.value_sats))
            .next()
    }

    fn miner_spend(&mut self, coin: Outpoint, coin_value: u64, to_spk: Vec<u8>, sats: u64, fee: u64) -> Result<[u8; 32], String> {
        let change = coin_value.checked_sub(sats.saturating_add(fee)).ok_or("the miner coin cannot cover the amount and fee")?;
        let payout = Payout {
            inputs: vec![TxIn { txid: coin.0, vout: coin.1, value_sats: coin_value, script_pubkey: self.miner_spk.clone(), sequence: 0xffff_ffff }],
            outputs: vec![TxOut { value_sats: sats, script_pubkey: to_spk }, TxOut { value_sats: change, script_pubkey: self.miner_spk.clone() }],
        };
        let tx = SimTx {
            txid: payout.txid(),
            inputs: payout.inputs.iter().map(|i| SimIn { txid: i.txid, vout: i.vout, sequence: i.sequence }).collect(),
            outputs: payout.outputs.clone(),
            vbytes: MINER_SPEND_VBYTES,
            coinbase: false,
        };
        let replaced = self.admit(&tx, btc_tx::TX_VERSION, btc_tx::LOCK_TIME)?;
        let txid = tx.txid;
        self.push_mempool(tx, replaced);
        Ok(txid)
    }

    /// `sendtoaddress` from the miner wallet: `sats` to `address`, into the mempool; returns the txid.
    pub fn fund(&mut self, address: &str, sats: u64) -> Result<[u8; 32], String> {
        let (_, spk) = btc_tx::script_pubkey_for_address(address).ok_or_else(|| format!("not a Bitcoin address: {address}"))?;
        let fee = MINER_SPEND_VBYTES * self.fee_rate_sat_vb;
        let (coin, value) = self.miner_coin(sats.saturating_add(fee)).ok_or("no mature miner coin large enough")?;
        self.miner_spend(coin, value, spk, sats, fee)
    }

    /// THE DOUBLE-SPEND: the miner wallet spends the coin that funded `txid` back to itself at a higher fee (full-RBF),
    /// so the funding transaction is evicted — on the next block the deposit never happened. Returns the conflicting
    /// txid.
    pub fn double_spend_funding(&mut self, txid: &[u8; 32]) -> Result<[u8; 32], String> {
        let funding = self.mempool.iter().find(|t| &t.txid == txid).cloned().ok_or("the funding transaction is not in the mempool (confirmed, or already gone)")?;
        let inp = funding.inputs.first().ok_or("a coinbase cannot be double-spent")?;
        let utxo = self.utxo_set();
        let (coin, _) = utxo.get(&(inp.txid, inp.vout)).ok_or("the funded coin is no longer unspent on the chain")?;
        let old_fee = self.fee_of(&funding, &utxo).unwrap_or(0);
        let fee = old_fee.saturating_add(MINER_SPEND_VBYTES * (self.fee_rate_sat_vb + INCREMENTAL_RELAY_SAT_VB));
        let value = coin.value_sats;
        let to = self.miner_spk.clone();
        self.miner_spend((inp.txid, inp.vout), value, to, 1_000, fee)
    }

    /// `sendrawtransaction`: parse, judge (`admit`), verify every input's script-path witness, then pool. Returns the
    /// txid in display order.
    pub fn broadcast(&mut self, raw_hex: &str) -> Result<String, String> {
        let raw = btc_tx::unhex(raw_hex.trim()).ok_or("TX decode failed: not hex")?;
        let parsed = parse_tx(&raw)?;
        if parsed.version != btc_tx::TX_VERSION {
            return Err(format!("transaction version {} is not simulated (the reserve builds version 2 only)", parsed.version));
        }
        let utxo = self.utxo_set();
        let mut inputs: Vec<TxIn> = Vec::with_capacity(parsed.inputs.len());
        for (txid, vout, _script_sig, sequence) in &parsed.inputs {
            let op = (*txid, *vout);
            let prev = match utxo.get(&op) {
                Some((o, _)) => o.clone(),
                None => self.mempool_output(&op).ok_or_else(|| format!("missing-inputs: {}:{}", btc_tx::txid_display_hex(txid), vout))?,
            };
            inputs.push(TxIn { txid: *txid, vout: *vout, value_sats: prev.value_sats, script_pubkey: prev.script_pubkey, sequence: *sequence });
        }
        let payout = Payout { inputs, outputs: parsed.outputs.clone() };
        let tx = SimTx {
            txid: parsed.txid,
            inputs: payout.inputs.iter().map(|i| SimIn { txid: i.txid, vout: i.vout, sequence: i.sequence }).collect(),
            outputs: payout.outputs.clone(),
            vbytes: parsed.vbytes,
            coinbase: false,
        };
        let replaced = self.admit(&tx, parsed.version, parsed.locktime)?;
        if self.plant != Plant::AcceptAnyWitness {
            for (i, w) in parsed.witnesses.iter().enumerate() {
                verify_script_path(&payout, i, w).map_err(|e| format!("mandatory-script-verify-flag-failed (input {i}): {e}"))?;
            }
        }
        let display = btc_tx::txid_display_hex(&tx.txid);
        self.push_mempool(tx, replaced);
        Ok(display)
    }

    /// Esplora `/address/{a}/utxo`: confirmed coins with their confirmations plus mempool coins at 0.
    pub fn utxos(&self, address: &str) -> Option<Vec<crate::btc_watch::ReserveCoin>> {
        let (_, spk) = btc_tx::script_pubkey_for_address(address)?;
        let tip = self.tip_height();
        let spends = self.mempool_spends();
        let mut coins = Vec::new();
        for (op, (o, h)) in self.utxo_set() {
            if o.script_pubkey == spk && !spends.contains_key(&op) {
                coins.push(crate::btc_watch::ReserveCoin { txid: op.0, vout: op.1, value_sats: o.value_sats, confirmations: tip.saturating_sub(h).saturating_add(1) });
            }
        }
        for tx in &self.mempool {
            for (v, o) in tx.outputs.iter().enumerate() {
                if o.script_pubkey == spk && !spends.contains_key(&(tx.txid, v as u32)) {
                    coins.push(crate::btc_watch::ReserveCoin { txid: tx.txid, vout: v as u32, value_sats: o.value_sats, confirmations: 0 });
                }
            }
        }
        Some(coins)
    }

    fn find_tx(&self, txid: &[u8; 32]) -> Option<(&SimTx, Option<u64>)> {
        for (i, block) in self.blocks.iter().enumerate() {
            if let Some(t) = block.iter().find(|t| &t.txid == txid) {
                return Some((t, Some(i as u64 + 1)));
            }
        }
        self.mempool.iter().find(|t| &t.txid == txid).map(|t| (t, None))
    }

    pub fn tx_out(&self, txid_display: &str, vout: u32) -> Option<(u64, Vec<u8>)> {
        let txid = btc_tx::txid_from_display_hex(txid_display)?;
        let (tx, _) = self.find_tx(&txid)?;
        let o = tx.outputs.get(vout as usize)?;
        Some((o.value_sats, o.script_pubkey.clone()))
    }

    /// The scriptPubKeys a known transaction's inputs spent; `None` for one this chain does not hold (a coinbase spends none).
    pub fn funding_scripts(&self, txid_display: &str) -> Option<Vec<Vec<u8>>> {
        let txid = btc_tx::txid_from_display_hex(txid_display)?;
        let (tx, _) = self.find_tx(&txid)?;
        tx.inputs
            .iter()
            .map(|i| self.find_tx(&i.txid).and_then(|(p, _)| p.outputs.get(i.vout as usize).map(|o| o.script_pubkey.clone())))
            .collect()
    }

    /// Confirmations of a known transaction (0 in the mempool); `None` for one this chain does not hold.
    pub fn tx_confirmations(&self, txid_display: &str) -> Option<u64> {
        let txid = btc_tx::txid_from_display_hex(txid_display)?;
        let (_, height) = self.find_tx(&txid)?;
        Some(match height {
            Some(h) => self.tip_height().saturating_sub(h).saturating_add(1),
            None => 0,
        })
    }

    /// Everything the chain ever paid to `address` in confirmed blocks (`RegtestCore::received_sats`).
    pub fn received_sats(&self, address: &str) -> u64 {
        let Some((_, spk)) = btc_tx::script_pubkey_for_address(address) else {
            return 0;
        };
        self.blocks.iter().flatten().flat_map(|t| t.outputs.iter()).filter(|o| o.script_pubkey == spk).fold(0u64, |a, o| a.saturating_add(o.value_sats))
    }
}

fn h8(id: &[u8; 32]) -> String {
    btc_tx::hex(&id[..4])
}

struct ParsedTx {
    version: i32,
    locktime: u32,
    inputs: Vec<([u8; 32], u32, Vec<u8>, u32)>,
    outputs: Vec<TxOut>,
    witnesses: Vec<Vec<Vec<u8>>>,
    txid: [u8; 32],
    vbytes: u64,
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.i.checked_add(n).ok_or("truncated")?;
        if end > self.b.len() {
            return Err("TX decode failed: truncated".into());
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| "truncated")?))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| "truncated")?))
    }
    fn varint(&mut self) -> Result<u64, String> {
        Ok(match self.u8()? {
            n @ 0..=0xfc => u64::from(n),
            0xfd => u64::from(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| "truncated")?)),
            0xfe => u64::from(self.u32()?),
            _ => self.u64()?,
        })
    }
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let n = self.varint()?;
        if n > 1 << 20 {
            return Err("TX decode failed: oversized element".into());
        }
        Ok(self.take(n as usize)?.to_vec())
    }
}

/// Bitcoin's transaction serialization (BIP 144 with the witness marker), parsed; the txid is the double-SHA256 of the
/// legacy serialization, as Core computes it.
fn parse_tx(raw: &[u8]) -> Result<ParsedTx, String> {
    let mut c = Cursor { b: raw, i: 0 };
    let version = c.u32()? as i32;
    let mut segwit = false;
    let mut n_in = c.varint()?;
    if n_in == 0 {
        let flag = c.u8()?;
        if flag != 0x01 {
            return Err("TX decode failed: bad witness flag".into());
        }
        segwit = true;
        n_in = c.varint()?;
    }
    if n_in > 10_000 {
        return Err("TX decode failed: too many inputs".into());
    }
    let mut inputs = Vec::with_capacity(n_in as usize);
    for _ in 0..n_in {
        let txid: [u8; 32] = c.take(32)?.try_into().map_err(|_| "truncated")?;
        let vout = c.u32()?;
        let script_sig = c.bytes()?;
        let sequence = c.u32()?;
        inputs.push((txid, vout, script_sig, sequence));
    }
    let n_out = c.varint()?;
    if n_out > 10_000 {
        return Err("TX decode failed: too many outputs".into());
    }
    let mut outputs = Vec::with_capacity(n_out as usize);
    for _ in 0..n_out {
        let value_sats = c.u64()?;
        let script_pubkey = c.bytes()?;
        outputs.push(TxOut { value_sats, script_pubkey });
    }
    let mut witnesses: Vec<Vec<Vec<u8>>> = Vec::with_capacity(inputs.len());
    if segwit {
        for _ in 0..n_in {
            let k = c.varint()?;
            if k > 1_000 {
                return Err("TX decode failed: witness too deep".into());
            }
            let mut w = Vec::with_capacity(k as usize);
            for _ in 0..k {
                w.push(c.bytes()?);
            }
            witnesses.push(w);
        }
    } else {
        witnesses.resize(inputs.len(), Vec::new());
    }
    let locktime = c.u32()?;
    if c.i != raw.len() {
        return Err("TX decode failed: trailing bytes".into());
    }
    // The legacy serialization, for the txid and the weight.
    let mut legacy = Vec::with_capacity(raw.len());
    legacy.extend_from_slice(&(version as u32).to_le_bytes());
    btc_tx::compact_size(inputs.len() as u64, &mut legacy);
    for (txid, vout, script_sig, sequence) in &inputs {
        legacy.extend_from_slice(txid);
        legacy.extend_from_slice(&vout.to_le_bytes());
        btc_tx::compact_size(script_sig.len() as u64, &mut legacy);
        legacy.extend_from_slice(script_sig);
        legacy.extend_from_slice(&sequence.to_le_bytes());
    }
    btc_tx::compact_size(outputs.len() as u64, &mut legacy);
    for o in &outputs {
        legacy.extend_from_slice(&o.value_sats.to_le_bytes());
        btc_tx::compact_size(o.script_pubkey.len() as u64, &mut legacy);
        legacy.extend_from_slice(&o.script_pubkey);
    }
    legacy.extend_from_slice(&locktime.to_le_bytes());
    let weight = legacy.len() as u64 * 3 + raw.len() as u64;
    Ok(ParsedTx { version, locktime, inputs, outputs, witnesses, txid: btc_tx::sha256d(&legacy), vbytes: weight.div_ceil(4) })
}

/// The two tapscript leaves the bridge builds, parsed from a witness's script element.
enum Leaf {
    /// `<k1> CHECKSIG <k2> CHECKSIGADD … <k> NUMEQUAL` — the custody quorum (BIP 342 `multi_a`).
    Custody(CustodyLeaf),
    /// `<n> CHECKSEQUENCEVERIFY DROP <key> CHECKSIG` — the depositor's self-refund after `n` blocks (BIP 112).
    Refund { blocks: u32, key: [u8; 32] },
    /// §BR-2: `<D> CHECKSIGVERIFY` then a custody `multi_a` — the co-signed sweep (the depositor AND the quorum).
    Sweep { depositor: [u8; 32], custody: CustodyLeaf },
}

fn read_scriptnum(c: &mut Cursor<'_>) -> Result<u32, String> {
    let op = c.u8()?;
    if op == 0x00 {
        return Ok(0);
    }
    if (btc_tx::OP_1..=btc_tx::OP_1 + 15).contains(&op) {
        return Ok(u32::from(op - btc_tx::OP_1) + 1);
    }
    if (1..=5).contains(&op) {
        let bytes = c.take(op as usize)?;
        if bytes.last().is_some_and(|b| b & 0x80 != 0) {
            return Err("negative scriptnum".into());
        }
        let mut v: u64 = 0;
        for (i, b) in bytes.iter().enumerate() {
            v |= u64::from(*b) << (8 * i);
        }
        return u32::try_from(v).map_err(|_| "scriptnum out of range".to_string());
    }
    Err(format!("unexpected opcode {op:#04x} where a number was expected"))
}

fn parse_leaf(script: &[u8]) -> Result<Leaf, String> {
    // §BR-2: `0x20 <D> OP_CHECKSIGVERIFY` ‖ a custody leaf — the co-signed sweep.
    if script.len() > 34 && script[0] == 0x20 && script[33] == btc_tx::OP_CHECKSIGVERIFY {
        let depositor: [u8; 32] = script[1..33].try_into().map_err(|_| "truncated")?;
        return match parse_leaf(&script[34..])? {
            Leaf::Custody(custody) => Ok(Leaf::Sweep { depositor, custody }),
            _ => Err("sweep leaf: the quorum half is not a custody leaf".into()),
        };
    }
    let mut c = Cursor { b: script, i: 0 };
    if script.first() == Some(&0x20) {
        let mut slot_keys: Vec<[u8; 32]> = Vec::new();
        loop {
            if c.b.get(c.i) != Some(&0x20) {
                break;
            }
            c.u8()?;
            let key: [u8; 32] = c.take(32)?.try_into().map_err(|_| "truncated")?;
            let op = c.u8()?;
            let want = if slot_keys.is_empty() { btc_tx::OP_CHECKSIG } else { btc_tx::OP_CHECKSIGADD };
            if op != want {
                return Err(format!("custody leaf: opcode {op:#04x} after key {}", slot_keys.len()));
            }
            slot_keys.push(key);
        }
        let k = read_scriptnum(&mut c)?;
        if c.u8()? != btc_tx::OP_NUMEQUAL || c.i != script.len() {
            return Err("custody leaf: not terminated by OP_NUMEQUAL".into());
        }
        let leaf = btc_tx::custody_leaf_with_slots(&slot_keys, k).ok_or("custody leaf: a slot key is not on the curve or k is out of range")?;
        if leaf.script != script {
            return Err("custody leaf: not the canonical encoding".into());
        }
        return Ok(Leaf::Custody(leaf));
    }
    let blocks = read_scriptnum(&mut c)?;
    if c.u8()? != OP_CSV || c.u8()? != OP_DROP || c.u8()? != 0x20 {
        return Err("not a custody leaf and not a CSV refund leaf".into());
    }
    let key: [u8; 32] = c.take(32)?.try_into().map_err(|_| "truncated")?;
    if c.u8()? != btc_tx::OP_CHECKSIG || c.i != script.len() {
        return Err("refund leaf: not terminated by OP_CHECKSIG".into());
    }
    Ok(Leaf::Refund { blocks, key })
}

/// BIP 341 script-path verification of input `i`: the control block must name the output being spent, and the leaf's
/// signature checks (BIP 340 over the BIP 341 sighash) must hold EXACTLY as the script states — an invalid non-empty
/// signature fails the script (BIP 342), the quorum count must equal `k`, and a CSV leaf needs its sequence (BIP 112).
fn verify_script_path(payout: &Payout, i: usize, witness: &[Vec<u8>]) -> Result<(), String> {
    let inp = payout.inputs.get(i).ok_or("no such input")?;
    if witness.len() == 1 {
        // BIP 341 KEY PATH (§BR-6: the wallet's single-key vault coin): one 64-byte signature by the output key itself over
        // the key-path sighash. A reserve or deposit output's internal key is NUMS-tweaked, so no key-path signature for it
        // exists — accepting the key path here is Bitcoin Core's rule, not a door around the reserve.
        let sig: [u8; 64] = witness[0].as_slice().try_into().map_err(|_| "a key-path signature must be 64 bytes (SIGHASH_DEFAULT)")?;
        if inp.script_pubkey.len() != 34 || inp.script_pubkey[0] != 0x51 || inp.script_pubkey[1] != 0x20 {
            return Err("a key-path witness spends only a taproot output".into());
        }
        let x: [u8; 32] = inp.script_pubkey[2..34].try_into().map_err(|_| "spk")?;
        let sighash = payout.sighash_key_path(i).ok_or("sighash")?;
        return if btc_tx::verify_sighash_sig(&x, &sighash, &sig) { // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own BIP-340 verify, the sim plays Bitcoin Core (bridge endpoint)
            Ok(())
        } else {
            Err("an invalid key-path signature (BIP 341)".into())
        };
    }
    if witness.len() < 2 {
        return Err("an empty witness spends nothing".into());
    }
    let control = &witness[witness.len() - 1];
    let script = &witness[witness.len() - 2];
    let stack = &witness[..witness.len() - 2];
    // BIP 341: 33 + 32·m bytes; the deposit tree is two leaves (m = 1), the reserve one (m = 0). Deeper trees are not built.
    if control.len() != 33 && control.len() != 65 {
        return Err(format!("control block of {} bytes: only one- and two-leaf trees are built", control.len()));
    }
    if control[0] & 0xfe != btc_tx::LEAF_VERSION {
        return Err("control block: not leaf version 0xc0".into());
    }
    let internal_x: [u8; 32] = control[1..33].try_into().map_err(|_| "control block")?;
    let leaf_hash = btc_tx::leaf_hash_of(script);
    // the merkle path: one sibling for the two-leaf tree (BIP 341 TapBranch, lexicographic)
    let root = if control.len() == 65 {
        let sib: [u8; 32] = control[33..65].try_into().map_err(|_| "control block")?;
        btc_tx::tap_branch(&leaf_hash, &sib)
    } else {
        leaf_hash
    };
    let (out_x, odd) = btc_tx::taproot_output_for_leaf(&internal_x, &root).ok_or("control block: internal key not on the curve")?;
    if inp.script_pubkey != btc_tx::p2tr_script_pubkey(&out_x) || odd != (control[0] & 1 == 1) {
        return Err("control block does not commit to the output being spent (BIP 341 taptweak mismatch)".into());
    }
    let sighash = payout.sighash_script_path(i, &leaf_hash).ok_or("sighash")?;
    let check = |key: &[u8; 32], sig: &[u8]| -> Result<bool, String> {
        if sig.is_empty() {
            return Ok(false);
        }
        let sig: [u8; 64] = sig.try_into().map_err(|_| "a signature must be 64 bytes (SIGHASH_DEFAULT); 65-byte sighash types are not built")?;
        if btc_tx::verify_sighash_sig(key, &sighash, &sig) { // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own BIP-340 verify, the sim plays Bitcoin Core (bridge endpoint)
            Ok(true)
        } else {
            Err("an invalid signature fails the script (BIP 342)".into())
        }
    };
    match parse_leaf(script)? {
        Leaf::Custody(leaf) => {
            let n = leaf.slot_keys.len();
            if stack.len() != n {
                return Err(format!("custody leaf: {} witness elements for {n} slots", stack.len()));
            }
            let mut count = 0u32;
            for (slot, key) in leaf.slot_keys.iter().enumerate() {
                // The script pops the top of the stack first: the last element before the script signs slot 0.
                if check(key, &stack[n - 1 - slot])? {
                    count += 1;
                }
            }
            if count != leaf.k {
                return Err(format!("custody leaf: {count} valid signatures, OP_NUMEQUAL wants exactly {}", leaf.k));
            }
            Ok(())
        }
        Leaf::Sweep { depositor, custody } => {
            let n = custody.slot_keys.len();
            if stack.len() != n + 1 {
                return Err(format!("sweep leaf: {} witness elements for the depositor and {n} slots", stack.len()));
            }
            // OP_CHECKSIGVERIFY pops the TOP element first: the depositor's signature must be present AND valid.
            if !check(&depositor, &stack[n])? {
                return Err("sweep leaf: OP_CHECKSIGVERIFY — the depositor's signature is missing".into());
            }
            let mut count = 0u32;
            for (slot, key) in custody.slot_keys.iter().enumerate() {
                if check(key, &stack[n - 1 - slot])? {
                    count += 1;
                }
            }
            if count != custody.k {
                return Err(format!("sweep leaf: {count} valid quorum signatures, OP_NUMEQUAL wants exactly {}", custody.k));
            }
            Ok(())
        }
        Leaf::Refund { blocks, key } => {
            if inp.sequence & SEQUENCE_DISABLE != 0 || inp.sequence & SEQUENCE_TIME_TYPE != 0 || inp.sequence & SEQUENCE_MASK < blocks {
                return Err(format!("OP_CHECKSEQUENCEVERIFY: the input's sequence {:#x} does not satisfy {blocks} blocks (BIP 112)", inp.sequence));
            }
            if stack.len() != 1 || !check(&key, &stack[0])? {
                return Err("refund leaf: the depositor's signature is missing".into());
            }
            Ok(())
        }
    }
}

// ───────────────────────────── the installed world ─────────────────────────────

fn slot() -> &'static RwLock<Option<Arc<Mutex<SimBitcoin>>>> {
    static S: OnceLock<RwLock<Option<Arc<Mutex<SimBitcoin>>>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(None))
}

/// The installed simulated chain, if any: `btc_watch::btc_source` hands it to every caller as `BtcSource::Sim`.
pub fn installed() -> Option<Arc<Mutex<SimBitcoin>>> {
    slot().read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Holds the world installed; dropping it uninstalls. ONE process-wide slot: pins that install serialize on
/// `btc_sim::serial()` so two cannot overwrite each other's world.
pub struct Installed(Arc<Mutex<SimBitcoin>>);

impl Installed {
    pub fn chain(&self) -> std::sync::MutexGuard<'_, SimBitcoin> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn arc(&self) -> Arc<Mutex<SimBitcoin>> {
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

pub fn install(sim: SimBitcoin) -> Installed {
    let a = Arc::new(Mutex::new(sim));
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(a.clone());
    Installed(a)
}

/// The lock pins take around an installed world (tests run in parallel threads).
pub fn serial() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    //! Every pin reads the world through the PRODUCTION source (`btc_watch::btc_source` → `BtcSource::Sim`), never
    //! through the sim's own methods where a production path exists; and every verdict is first shown to FAIL on a
    //! planted defect (`Plant`).
    use super::*;
    use crate::btc_tx::BtcNet;
    use crate::btc_watch::{btc_source, matured_and_pending, required_confirmations};

    fn secret(tag: &[u8]) -> [u8; 32] {
        *blake3::hash(tag).as_bytes()
    }

    fn key_of(tag: &[u8]) -> [u8; 32] {
        btc_tx::xonly_pubkey(&secret(tag)).expect("a hash is a valid key with overwhelming probability") // CLASSICAL-CRYPTO-EXEMPT: a test custodian's key on Bitcoin's own curve (bridge endpoint)
    }

    /// A deposit matures under THORChain's confirmation count as the production watcher reads it; a reorg that
    /// double-spends its funding takes it back on every production read.
    fn reorg_verdict(plant: Plant) -> Result<(), String> {
        let mut sim = SimBitcoin::new(0x51B1_2026_1027);
        sim.plant = plant;
        let w = install(sim);
        let addr = btc_tx::address_for_test_seed("bcrt", b"depositor-1");
        let sats = 30 * 100_000_000u64;
        let need = required_confirmations(sats);
        if need != 10 {
            return Err(format!("CALIBRATION: 30 BTC needs {need} confirmations, expected 10"));
        }
        let txid = w.chain().fund(&addr, sats)?;
        let read = || matured_and_pending(&addr).ok_or_else(|| "no Bitcoin source: the sim is not installed".to_string());
        if read()? != (0, sats) {
            return Err(format!("in the mempool the deposit should be pending: {:?}", read()?));
        }
        w.chain().mine(need - 1);
        if read()? != (0, sats) {
            return Err(format!("at {} confirmations the deposit should still be pending: {:?}", need - 1, read()?));
        }
        w.chain().mine(1);
        if read()? != (sats, 0) {
            return Err(format!("at {need} confirmations the deposit should be matured: {:?}", read()?));
        }
        let deposit_height = w.chain().tip_height() - need + 1;
        let src = btc_source(BtcNet::Regtest).ok_or("no source")?;
        let display = btc_tx::txid_display_hex(&txid);
        if src.tx_confirmations(&display) != Some(need) {
            return Err(format!("the source counts {:?} confirmations, expected {need}", src.tx_confirmations(&display)));
        }
        // THE ATTACK: the chain reorganizes from the deposit's block and the funding coin is spent elsewhere.
        w.chain().invalidate_block(deposit_height);
        let conflict = w.chain().double_spend_funding(&txid)?;
        w.chain().mine(need + 1);
        let after = read()?;
        if after != (0, 0) {
            return Err(format!("⛔ the deposit SURVIVED the double-spend reorg: matured {} pending {}", after.0, after.1));
        }
        if src.tx_confirmations(&display).is_some() {
            return Err("⛔ the evicted funding transaction is still known to the source".into());
        }
        if src.tx_confirmations(&btc_tx::txid_display_hex(&conflict)) != Some(need + 1) {
            return Err("the conflicting spend did not confirm".into());
        }
        Ok(())
    }

    #[test]
    fn a_deposit_matures_by_thorchains_count_and_a_double_spend_reorg_takes_it_back_on_the_production_watcher() {
        let _serial = serial().lock().unwrap_or_else(|e| e.into_inner());
        reorg_verdict(Plant::None).unwrap_or_else(|e| panic!("⛔ {e}"));
        let planted = reorg_verdict(Plant::IgnoreReorg);
        assert!(planted.is_err(), "CALIBRATION: a world that ignores reorgs must fail this verdict");
    }

    /// The custody quorum's payout, built by `btc_tx` exactly as the payout lane builds it, is admitted by the
    /// production broadcast and arrives; one flipped signature byte, or a signature over another message, is refused.
    fn payout_verdict(plant: Plant) -> Result<(), String> {
        let mut sim = SimBitcoin::new(0x9A70_2026_1027);
        sim.plant = plant;
        let w = install(sim);
        let tags: [&[u8]; 3] = [b"custodian-a", b"custodian-b", b"custodian-c"];
        let keys: Vec<[u8; 32]> = tags.iter().map(|t| key_of(t)).collect();
        let leaf = btc_tx::custody_leaf_with_slots(&keys, 2).ok_or("leaf")?;
        let out = btc_tx::reserve_output(&leaf, b"swap-nonce-1").ok_or("output")?;
        let reserve = btc_tx::reserve_address("bcrt", &out.output_x);
        let control = btc_tx::control_block(&out);
        let dest = btc_tx::address_for_test_seed("bcrt", b"redeemer-1");
        let (_, dest_spk) = btc_tx::script_pubkey_for_address(&dest).ok_or("dest")?;
        let src = btc_source(BtcNet::Regtest).ok_or("no source")?;
        let dep = 100_000_000u64;
        let fee = 2_000u64;
        let spend = |txid: [u8; 32], sigs_of: &dyn Fn(&[u8; 32]) -> Vec<Option<[u8; 64]>>| -> Result<(String, Option<String>), String> {
            let coins = src.utxos(&reserve).ok_or("utxos")?;
            let coin = coins.iter().find(|c| c.txid == txid).ok_or("the reserve coin is not seen by the source")?;
            let payout = Payout {
                inputs: vec![TxIn { txid: coin.txid, vout: coin.vout, value_sats: coin.value_sats, script_pubkey: btc_tx::p2tr_script_pubkey(&out.output_x), sequence: 0xffff_ffff }],
                outputs: vec![TxOut { value_sats: dep - fee, script_pubkey: dest_spk.clone() }],
            };
            let sighash = payout.sighash_script_path(0, &leaf.leaf_hash).ok_or("sighash")?;
            let witness = btc_tx::script_path_witness(&leaf, &sigs_of(&sighash), &control).ok_or("witness")?;
            let raw = btc_tx::hex(&payout.serialize_with_witness(&[witness]).ok_or("serialize")?);
            Ok((btc_tx::txid_display_hex(&payout.txid()), src.broadcast(&raw)))
        };
        let sign = |tag: &[u8], msg: &[u8; 32]| btc_tx::sign_sighash(&secret(tag), msg, &[7u8; 32]).expect("sign"); // CLASSICAL-CRYPTO-EXEMPT: a test custodian's BIP-340 signature (bridge endpoint)
        // 1. The honest quorum (a and c of a, b, c).
        let txid = w.chain().fund(&reserve, dep)?;
        w.chain().mine(1);
        let (want, got) = spend(txid, &|m| vec![Some(sign(b"custodian-a", m)), None, Some(sign(b"custodian-c", m))])?;
        if got.as_deref() != Some(want.as_str()) {
            return Err(format!("the quorum-signed payout was refused (got {got:?}, want {want})"));
        }
        w.chain().mine(1);
        let arrived = w.chain().received_sats(&dest);
        if arrived != dep - fee || src.tx_confirmations(&want) != Some(1) {
            return Err(format!("the payout did not arrive: {arrived} sats at the redeemer, {:?} confirmations", src.tx_confirmations(&want)));
        }
        // 2. One flipped byte in one of the two signatures.
        let txid = w.chain().fund(&reserve, dep)?;
        w.chain().mine(1);
        let (_, got) = spend(txid, &|m| {
            let mut bad = sign(b"custodian-a", m);
            bad[10] ^= 0x01;
            vec![Some(bad), None, Some(sign(b"custodian-c", m))]
        })?;
        if got.is_some() {
            return Err("⛔ a payout with a FLIPPED signature byte was admitted".into());
        }
        // 3. A signature over another message (the quorum count would be 1 — and an invalid signature fails the script).
        let (_, got) = spend(txid, &|m| vec![Some(sign(b"custodian-a", m)), None, Some(sign(b"custodian-c", &[9u8; 32]))])?;
        if got.is_some() {
            return Err("⛔ a payout signed over ANOTHER message was admitted".into());
        }
        // 4. A signer outside the quorum (key d is not in the leaf).
        let (_, got) = spend(txid, &|m| vec![Some(sign(b"custodian-d", m)), None, Some(sign(b"custodian-c", m))])?;
        if got.is_some() {
            return Err("⛔ a payout signed by a NON-MEMBER was admitted".into());
        }
        // The coin is still there for the honest quorum.
        let (want, got) = spend(txid, &|m| vec![None, Some(sign(b"custodian-b", m)), Some(sign(b"custodian-c", m))])?;
        if got.as_deref() != Some(want.as_str()) {
            return Err("the honest quorum was refused after the forgeries".into());
        }
        Ok(())
    }

    #[test]
    fn a_quorum_signed_payout_arrives_through_the_production_broadcast_and_every_forgery_is_refused() {
        let _serial = serial().lock().unwrap_or_else(|e| e.into_inner());
        payout_verdict(Plant::None).unwrap_or_else(|e| panic!("⛔ {e}"));
        let planted = payout_verdict(Plant::AcceptAnyWitness);
        assert!(planted.is_err(), "CALIBRATION: a world that admits any witness must fail this verdict");
    }

    /// The depositor's self-refund leaf `<10> CSV DROP <key> CHECKSIG`: refused by BIP 68 until ten blocks have passed,
    /// refused by BIP 112 when the input's sequence names fewer blocks than the script, admitted after.
    #[test]
    fn a_csv_refund_is_refused_before_its_relative_lock_by_bip68_and_bip112_and_admitted_after() {
        let _serial = serial().lock().unwrap_or_else(|e| e.into_inner());
        let w = install(SimBitcoin::new(0xC5F_2026_1027));
        let key = key_of(b"refunder");
        let blocks = 10u32;
        let mut script = vec![btc_tx::OP_1 + (blocks as u8 - 1), OP_CSV, OP_DROP, 0x20];
        script.extend_from_slice(&key);
        script.push(btc_tx::OP_CHECKSIG);
        let leaf = CustodyLeaf { slot_keys: vec![key], k: 1, script: script.clone(), leaf_hash: btc_tx::leaf_hash_of(&script) };
        let out = btc_tx::reserve_output(&leaf, b"refund-nonce").expect("output");
        let addr = btc_tx::reserve_address("bcrt", &out.output_x);
        let control = btc_tx::control_block(&out);
        let dest = btc_tx::address_for_test_seed("bcrt", b"refund-dest");
        let (_, dest_spk) = btc_tx::script_pubkey_for_address(&dest).expect("dest");
        let src = btc_source(BtcNet::Regtest).expect("source");
        let dep = 50_000_000u64;
        let txid = w.chain().fund(&addr, dep).expect("fund");
        w.chain().mine(1);
        let coin = src.utxos(&addr).expect("utxos").into_iter().find(|c| c.txid == txid).expect("coin");
        let refund = |sequence: u32| -> Option<String> {
            let payout = Payout {
                inputs: vec![TxIn { txid: coin.txid, vout: coin.vout, value_sats: coin.value_sats, script_pubkey: btc_tx::p2tr_script_pubkey(&out.output_x), sequence }],
                outputs: vec![TxOut { value_sats: dep - 2_000, script_pubkey: dest_spk.clone() }],
            };
            let sighash = payout.sighash_script_path(0, &leaf.leaf_hash).expect("sighash");
            let sig = btc_tx::sign_sighash(&secret(b"refunder"), &sighash, &[3u8; 32]).expect("sign"); // CLASSICAL-CRYPTO-EXEMPT: the depositor's BIP-340 refund signature (bridge endpoint)
            let witness = vec![sig.to_vec(), script.clone(), control.clone()];
            src.broadcast(&btc_tx::hex(&payout.serialize_with_witness(&[witness]).expect("serialize")))
        };
        assert!(refund(blocks).is_none(), "⛔ BIP 68: a refund at 1 confirmation was admitted");
        w.chain().mine(8);
        assert!(refund(blocks).is_none(), "⛔ BIP 68: a refund at 9 confirmations was admitted");
        w.chain().mine(1);
        assert!(refund(blocks - 1).is_none(), "⛔ BIP 112: a sequence of 9 blocks against a 10-block script was admitted");
        assert!(refund(blocks | SEQUENCE_DISABLE).is_none(), "⛔ BIP 112: a disabled sequence was admitted");
        let got = refund(blocks).expect("⛔ the refund at 10 confirmations was refused");
        w.chain().mine(1);
        assert_eq!(src.tx_confirmations(&got), Some(1), "the refund confirms");
        assert_eq!(w.chain().received_sats(&dest), dep - 2_000, "the refund arrives");
    }

    /// ⭐ §BR-2 (spec §14) — THE CO-SIGNED DEPOSIT, judged by the simulated Bitcoin through the production broadcast. A
    /// two-of-three custody quorum and one depositor key build the two-leaf deposit output; on Bitcoin's own rules:
    ///   * the custody quorum ALONE cannot spend an unminted deposit (the sweep leaf's `CHECKSIGVERIFY` refuses);
    ///   * the depositor ALONE cannot spend through the sweep leaf (the quorum's `NUMEQUAL` refuses);
    ///   * the self-refund is refused before 1,008 blocks (BIP 68) and with a short sequence (BIP 112), admitted after;
    ///   * a control block naming the wrong sibling is refused (BIP 341);
    ///   * the depositor AND the quorum together sweep it.
    #[test]
    fn br2_custody_alone_cannot_spend_a_deposit_and_the_depositor_alone_reclaims_it_after_a_week() {
        let _serial = serial().lock().unwrap_or_else(|e| e.into_inner());
        let w = install(SimBitcoin::new(0xB2_2026_1028));
        let slots = vec![key_of(b"custodian-a"), key_of(b"custodian-b"), key_of(b"custodian-c")];
        let custody = btc_tx::custody_leaf_with_slots(&slots, 2).expect("a 2-of-3 leaf");
        let dep_key = key_of(b"depositor");
        let out = btc_tx::deposit_output(&custody, &dep_key, b"br2-nonce").expect("a deposit output");
        let addr = btc_tx::reserve_address("bcrt", &out.output_x);
        let src = btc_source(BtcNet::Regtest).expect("source");
        let dest = btc_tx::address_for_test_seed("bcrt", b"br2-dest");
        let (_, dest_spk) = btc_tx::script_pubkey_for_address(&dest).expect("dest");
        let value = 40_000_000u64;
        let sweep_coin = w.chain().fund(&addr, value).expect("fund");
        let refund_coin = w.chain().fund(&addr, value).expect("fund");
        w.chain().mine(1);
        let coin = |txid: [u8; 32]| src.utxos(&addr).expect("utxos").into_iter().find(|c| c.txid == txid).expect("coin");
        let spend = |txid: [u8; 32], sequence: u32, sweep: bool, sibling_ok: bool, signers: &dyn Fn(&[u8; 32]) -> Vec<Vec<u8>>| {
            let c = coin(txid);
            let payout = Payout {
                inputs: vec![TxIn { txid: c.txid, vout: c.vout, value_sats: c.value_sats, script_pubkey: btc_tx::p2tr_script_pubkey(&out.output_x), sequence }],
                outputs: vec![TxOut { value_sats: value - 3_000, script_pubkey: dest_spk.clone() }],
            };
            let leaf_hash = if sweep { out.sweep_hash } else { out.refund_hash };
            let m = payout.sighash_script_path(0, &leaf_hash).expect("sighash");
            let mut control = btc_tx::deposit_control_block(&out, sweep);
            if !sibling_ok {
                let last = control.len() - 1;
                control[last] ^= 1;
            }
            let mut witness = signers(&m);
            witness.push(if sweep { out.sweep_leaf.clone() } else { out.refund_leaf.clone() });
            witness.push(control);
            src.broadcast(&btc_tx::hex(&payout.serialize_with_witness(&[witness]).expect("serialize")))
        };
        let sig = |seed: &[u8], m: &[u8; 32]| btc_tx::sign_sighash(&secret(seed), m, &[7u8; 32]).expect("sign").to_vec(); // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own BIP-340 signatures in the simulated foreign chain
        // sweep witness, bottom first: slot2, slot1, slot0 signatures, then the depositor's (popped first)
        let quorum_only = |m: &[u8; 32]| vec![Vec::new(), sig(b"custodian-b", m), sig(b"custodian-a", m), Vec::new()];
        assert!(spend(sweep_coin, 0xffff_fffd, true, true, &quorum_only).is_none(), "⛔ the custody quorum ALONE spent an unminted deposit");
        let depositor_only = |m: &[u8; 32]| vec![Vec::new(), Vec::new(), Vec::new(), sig(b"depositor", m)];
        assert!(spend(sweep_coin, 0xffff_fffd, true, true, &depositor_only).is_none(), "⛔ the depositor ALONE spent through the sweep leaf");
        let both = |m: &[u8; 32]| vec![Vec::new(), sig(b"custodian-b", m), sig(b"custodian-a", m), sig(b"depositor", m)];
        assert!(spend(sweep_coin, 0xffff_fffd, true, false, &both).is_none(), "⛔ BIP 341: a control block naming the wrong sibling was admitted");
        // the refund: refused before the week, with a short sequence, and admitted after
        let refund_sig = |m: &[u8; 32]| vec![sig(b"depositor", m)];
        let week = btc_tx::DEPOSIT_REFUND_BLOCKS;
        assert!(spend(refund_coin, week, false, true, &refund_sig).is_none(), "⛔ BIP 68: a refund at 1 confirmation was admitted");
        w.chain().mine(u64::from(week) - 2);
        assert!(spend(refund_coin, week, false, true, &refund_sig).is_none(), "⛔ BIP 68: a refund one block early was admitted");
        w.chain().mine(1);
        assert!(spend(refund_coin, week - 1, false, true, &refund_sig).is_none(), "⛔ BIP 112: a sequence one block short was admitted");
        assert!(spend(refund_coin, week, false, true, &refund_sig).is_some(), "⛔ the depositor's refund after one week was refused");
        // and the co-signed sweep spends the other coin (the honest mint's path)
        assert!(spend(sweep_coin, 0xffff_fffd, true, true, &both).is_some(), "⛔ the depositor AND the quorum could not sweep");
        w.chain().mine(1);
        assert_eq!(w.chain().received_sats(&dest), 2 * (value - 3_000), "both spends arrive");
    }

    /// The simulated clock mines one block per interval; a coinbase spends only after its maturity.
    #[test]
    fn the_chain_mines_on_the_simulated_clock_and_a_coinbase_waits_its_maturity() {
        let mut sim = SimBitcoin::new(1);
        assert_eq!(sim.tip_height(), COINBASE_MATURITY + 1, "a regtest begins with 101 blocks");
        sim.advance_clock(3 * BLOCK_INTERVAL_MS - 1);
        assert_eq!(sim.tip_height(), COINBASE_MATURITY + 3, "two intervals passed → two blocks");
        sim.advance_clock(3 * BLOCK_INTERVAL_MS);
        assert_eq!(sim.tip_height(), COINBASE_MATURITY + 4);
        sim.block_interval_ms = 60_000; // takes effect after the block already scheduled at 4 × 600 s
        sim.advance_clock(4 * BLOCK_INTERVAL_MS + 120_000);
        assert_eq!(sim.tip_height(), COINBASE_MATURITY + 7, "a faster interval mines faster on the same clock");
        // Maturity: at tip 107 the coinbases of heights ≤ 8 are spendable (tip + 1 ≥ h + 100): eight 49-BTC spends, not nine.
        let addr = btc_tx::address_for_test_seed("bcrt", b"sink");
        for _ in 0..8 {
            sim.fund(&addr, 49 * 100_000_000).expect("a mature coinbase funds");
        }
        assert!(sim.fund(&addr, 49 * 100_000_000).is_err(), "⛔ an immature coinbase was spent");
        sim.mine(1);
        sim.fund(&addr, 49 * 100_000_000).expect("one more block, one more mature coinbase");
        assert_eq!(sim.received_sats(&addr), 8 * 49 * 100_000_000, "the eight funded in the block");
    }
}

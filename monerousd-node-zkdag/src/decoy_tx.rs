// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-8 B8-a — CONDITIONAL DECOYS (docs/BR-8-LAUNCH-CROWD-SPEC-20261029.md §3): the chain objects that book a payout
//! batch's decoy legs and close them when each returns.
//!
//! BORROWED: Tor's padding cells paid from a fixed budget (cover traffic whose cost is bounded by a share of real revenue, never
//! by the principal), and the custody-attested object shape every reserve movement in this chain takes (≥ 2/3 of bonded custody
//! weight over a domain-separated statement, the object's own nullifier as its replay guard).
//!
//! A payout batch whose unit carries fewer than `CROWD_FLOOR` same-amount outputs pays `min(gap, budget)` decoy legs of that unit
//! to bonded validators' custody points (BIP-86 key-path outputs — byte-shape-identical to a recipient's taproot output). Once the
//! batch is signed, custody books it with `Class::DecoyBatch`: the decoys become OPEN obligations (`PegLedger::open_decoys`),
//! the batch's decoy fees come out of this decoy epoch's budget (a fixed share of the PREVIOUS epoch's surplus-buffer credit)
//! and out of the surplus buffer. Each validator's node returns its decoy to the reserve by an ordinary key-path spend; custody
//! attests the return (`Class::DecoyReturn`) and the obligation closes. An obligation still open at its due blue score is an
//! unauthorized reserve move by that validator: custody signs a `ReserveTheft` (v3, the decoy's sats as the loss) whose statement
//! names the decoy, the slash closes it, and §BR-3 17.5 repays the loss in layers. Principal always returns or is repaid.
//! DIGITAL-CASH-PRIVACY-REVIEWED: decoys are public Bitcoin outputs custody itself paid; no user's leg, amount or identity.

use serde::{Deserialize, Serialize};

/// A unit with fewer same-amount outputs than this in its batch gets decoys (spec §3 item 4: ≥ 20 others).
pub const CROWD_FLOOR: usize = 20;
/// The share of the previous decoy epoch's surplus-buffer credit a decoy epoch may spend on decoy Bitcoin fees (20 %).
pub const DECOY_FEE_SHARE_BPS: u64 = 2_000;
/// A decoy epoch: one hour of CHAIN TICKS (A-F60: read against `Node::chain_tick_at`; it was 7,200 blocks at 500 ms).
pub const DECOY_EPOCH_BLOCKS: u64 = crate::params::blocks_for_ms(3_600_000);
/// The chain ticks a validator has to return its decoy (one day of chain time); then it is theft evidence.
pub const DECOY_RETURN_TICKS: u64 = crate::params::BLOCKS_PER_DAY;
/// The decoy obligations open at once; a batch adds decoys only below it (the fold admits a batch past it by at most one
/// batch, so a race never drops an obligation).
pub const DECOY_OPEN_MAX: usize = 256;
/// The Bitcoin bytes one decoy costs (its output 43 vB + the return's key-path input 58 vB + output 43 vB + overhead 11 vB):
/// the per-decoy fee is this × the batch's fee rate.
pub const DECOY_VBYTES: u64 = 155;
pub const MAX_DECOY_ATTESTORS: usize = crate::params::DAG_WIDTH_CEILING;

/// One decoy leg as the batch paid it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DecoyEntry {
    pub vid: [u8; 32],
    pub sats: u64,
    pub vout: u32,
}

/// An open decoy obligation (chain state, bounded by `DECOY_OPEN_MAX` + one batch).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenDecoy {
    pub vid: [u8; 32],
    pub sats: u64,
    pub txid: [u8; 32],
    pub vout: u32,
    /// The CHAIN TICK (`Node::chain_tick_at`, a time) by which the decoy must be back: the carrying block's tick plus
    /// `DECOY_RETURN_TICKS` ticks (one day). A time, never a blue score (A-F60's class).
    pub due_tick: u64,
}

/// The one key an outpoint is booked under.
#[must_use]
pub fn decoy_key(txid: &[u8; 32], vout: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/decoy-key/v1");
    h.update(txid);
    h.update(&vout.to_le_bytes());
    *h.finalize().as_bytes()
}

/// The statement a theft certificate names for an UNRETURNED decoy (inside `RESERVE_THEFT_STATEMENT_MAX`).
#[must_use]
pub fn decoy_theft_statement(txid: &[u8; 32], vout: u32) -> Vec<u8> {
    let mut m = b"MUSD/decoy-unreturned/v1".to_vec();
    m.extend_from_slice(txid);
    m.extend_from_slice(&vout.to_le_bytes());
    m
}

/// The decoy batch as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyBatchTx {
    /// The payout transaction's id (internal byte order; a segwit txid, fixed before any signature).
    pub payout_txid: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by `peg_pool::BATCH_MAX`.
    pub decoys: Vec<DecoyEntry>,
    /// The batch's decoy Bitcoin fees valued in USDm atomic at the proposal's TWAP (what the budget and the buffer pay).
    pub fee_usdm: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by `MAX_DECOY_ATTESTORS`.
    pub attestors: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A returned decoy as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyReturnTx {
    pub txid: [u8; 32],
    pub vout: u32,
    /// The Bitcoin transaction that spent the decoy back to the reserve.
    pub return_txid: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by `MAX_DECOY_ATTESTORS`.
    pub attestors: Vec<(Vec<u8>, Vec<u8>)>,
}

fn bounded_attestors(a: &[(Vec<u8>, Vec<u8>)]) -> bool {
    !a.is_empty()
        && a.len() <= MAX_DECOY_ATTESTORS
        && a.iter().all(|(pk, sig)| pk.len() <= crate::liquidation_tx::LIQUIDATION_SIG_FIELD_MAX && sig.len() <= crate::liquidation_tx::LIQUIDATION_SIG_FIELD_MAX)
}

impl DecoyBatchTx {
    /// The statement custody signs: the payout, every decoy, the fee.
    #[must_use]
    pub fn statement(payout_txid: &[u8; 32], decoys: &[DecoyEntry], fee_usdm: u64) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.decoy-batch.v1");
        m.extend_from_slice(payout_txid);
        m.extend_from_slice(&(decoys.len() as u32).to_le_bytes());
        for d in decoys {
            m.extend_from_slice(&d.vid);
            m.extend_from_slice(&d.sats.to_le_bytes());
            m.extend_from_slice(&d.vout.to_le_bytes());
        }
        m.extend_from_slice(&fee_usdm.to_le_bytes());
        m
    }
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::DecoyBatch, &self.encode())
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = crate::chain_object::decode_exact(bytes)?;
        let ok = !t.decoys.is_empty() && t.decoys.len() <= crate::peg_pool::BATCH_MAX && bounded_attestors(&t.attestors);
        ok.then_some(t)
    }
    #[must_use]
    pub fn attestors_list(&self) -> Vec<crate::psm::MintAttestor> {
        self.attestors.iter().map(|(pubkey, sig)| crate::psm::MintAttestor { pubkey: pubkey.clone(), sig: sig.clone() }).collect()
    }
}

impl DecoyReturnTx {
    #[must_use]
    pub fn statement(txid: &[u8; 32], vout: u32, return_txid: &[u8; 32]) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.decoy-return.v1");
        m.extend_from_slice(txid);
        m.extend_from_slice(&vout.to_le_bytes());
        m.extend_from_slice(return_txid);
        m
    }
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::DecoyReturn, &self.encode())
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = crate::chain_object::decode_exact(bytes)?;
        bounded_attestors(&t.attestors).then_some(t)
    }
    #[must_use]
    pub fn attestors_list(&self) -> Vec<crate::psm::MintAttestor> {
        self.attestors.iter().map(|(pubkey, sig)| crate::psm::MintAttestor { pubkey: pubkey.clone(), sig: sig.clone() }).collect()
    }
}

/// ⭐ THE DECOY RULE — shared by the proposer and every signer (one function, one answer). For each unit of the batch's legs
/// with fewer than `CROWD_FLOOR` outputs (largest unit first), `min(gap, affordable)` decoys of that unit, `affordable` =
/// what the budget's sats cover at `DECOY_VBYTES × fee_rate` each, never past `DECOY_OPEN_MAX` open obligations; each pays
/// one bonded custodian drawn by the batch's public seed weighted by custody weight, without repeat. `candidates` is
/// `(vid, weight)` sorted by id.
#[must_use]
pub fn decoy_legs(leg_units: &[u64], budget_sats: u64, fee_rate: u64, candidates: &[([u8; 32], u128)], seed: &[u8; 32], open: usize) -> Vec<([u8; 32], u64)> {
    let per = DECOY_VBYTES.saturating_mul(fee_rate.max(1));
    let mut affordable = (budget_sats / per) as usize;
    let mut room = DECOY_OPEN_MAX.saturating_sub(open);
    let mut units: Vec<u64> = leg_units.to_vec();
    units.sort_unstable_by(|a, b| b.cmp(a));
    units.dedup();
    let mut pool: Vec<([u8; 32], u128)> = candidates.iter().filter(|(_, w)| *w > 0).copied().collect();
    let mut out = Vec::new();
    let mut draw = 0u64;
    for u in units {
        let have = leg_units.iter().filter(|x| **x == u).count();
        if have >= CROWD_FLOOR {
            continue;
        }
        let k = (CROWD_FLOOR - have).min(affordable).min(room).min(pool.len());
        for _ in 0..k {
            let total: u128 = pool.iter().map(|(_, w)| *w).sum();
            if total == 0 {
                break;
            }
            let mut h = blake3::Hasher::new_derive_key("MUSD/decoy-draw/v1");
            h.update(seed);
            h.update(&draw.to_le_bytes());
            draw += 1;
            let r = u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap_or([0; 16])) % total;
            let mut acc = 0u128;
            let at = pool.iter().position(|(_, w)| {
                acc += *w;
                r < acc
            });
            let Some(at) = at else { break };
            let (vid, _) = pool.remove(at);
            out.push((vid, u));
            affordable -= 1;
            room -= 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cands(n: u8) -> Vec<([u8; 32], u128)> {
        (1..=n).map(|i| ([i; 32], u128::from(i) * 100)).collect()
    }

    /// REFUTERS 1–3 of §3: a batch at the floor adds no decoy; under it, exactly min(gap, budget); the budget bounds the count.
    #[test]
    fn decoys_fill_a_thin_unit_to_the_floor_only_as_far_as_the_budget_pays() {
        let seed = [9u8; 32];
        let at_floor = vec![100_000u64; CROWD_FLOOR];
        assert!(decoy_legs(&at_floor, u64::MAX, 2, &cands(30), &seed, 0).is_empty(), "a batch at the floor adds no decoy");
        let thin = vec![100_000u64; 5];
        let rich = decoy_legs(&thin, u64::MAX, 2, &cands(30), &seed, 0);
        assert_eq!(rich.len(), CROWD_FLOOR - 5, "a thin unit is filled to the floor when the budget pays");
        assert!(rich.iter().all(|(_, u)| *u == 100_000), "every decoy is the thin unit's own amount");
        let per = DECOY_VBYTES * 2;
        let poor = decoy_legs(&thin, 3 * per, 2, &cands(30), &seed, 0);
        assert_eq!(poor.len(), 3, "the budget bounds the count");
        assert_eq!(decoy_legs(&thin, u64::MAX, 2, &cands(30), &seed, DECOY_OPEN_MAX - 2).len(), 2, "never past the open bound");
        let mut ids: Vec<[u8; 32]> = rich.iter().map(|(v, _)| *v).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), rich.len(), "one decoy per validator per batch");
        assert_eq!(decoy_legs(&thin, u64::MAX, 2, &cands(30), &seed, 0), rich, "one answer for the proposer and every signer");
        assert!(decoy_legs(&thin, u64::MAX, 2, &[], &seed, 0).is_empty(), "no bonded custodian: no decoy");
    }
}

/// The pool transaction that carries one decoy object (the repayment lane's builder shape: blob + anti-spam stamp; its own
/// nullifier is laid by the publisher through `lay_object_lane`).
#[must_use]
pub fn as_pq_tx(blob: Vec<u8>, stamp_bits: u32) -> crate::mempool::PqTx {
    let mut tx = crate::mempool::PqTx {
        clock_ms: 0,
        id: crate::mempool::PqTx::content_id(&blob),
        weight: blob.len() as u32,
        blob,
        nullifiers: Vec::new(),
        pow_stamp: 0,
        note_clues: Vec::new(),
        account_targets: Vec::new(),
        output_notes: Vec::new(),
        stake_notes: Vec::new(),
        bond_notes: Vec::new(),
        nullifier_witnesses: Vec::new(),
        nullifier_absence: Vec::new(),
        membership_carrier: Vec::new(),
        membership_leaf_commit: [0u8; 32],
        membership_tip: Vec::new(),
        membership_folded_through: 0,
        spend_or_decoy: Vec::new(),
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
    };
    let mut s = 0u64;
    loop {
        tx.pow_stamp = s;
        if tx.stamp_work() >= stamp_bits {
            break;
        }
        s = s.wrapping_add(1);
    }
    tx
}

/// The most a decoy's return spend may keep as its Bitcoin fee (the return's 112 vB at ~18 sat/vB); custody attests a return
/// only when at least `sats − DECOY_RETURN_FEE_MAX_SATS` came back.
pub const DECOY_RETURN_FEE_MAX_SATS: u64 = 2_000;

/// The reserve nonce a decoy returns under (so every custodian derives the one return address).
#[must_use]
pub fn decoy_return_nonce(key: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/decoy-return-nonce/v1");
    h.update(key);
    *h.finalize().as_bytes()
}

/// One custodian's signature on the decoy lanes: a batch booking, a return, or an overdue decoy's theft certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecoySig {
    Batch { payout_txid: [u8; 32], decoys: Vec<DecoyEntry>, fee_usdm: u64, pubkey: Vec<u8>, sig: Vec<u8> },
    Return { txid: [u8; 32], vout: u32, return_txid: [u8; 32], pubkey: Vec<u8>, sig: Vec<u8> },
    Theft { txid: [u8; 32], vout: u32, pubkey: Vec<u8>, sig: Vec<u8> },
}

impl DecoySig {
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: DecoySig = crate::chain_object::decode_exact(bytes)?;
        let ok = |f: &Vec<u8>| !f.is_empty() && f.len() <= crate::liquidation_tx::LIQUIDATION_SIG_FIELD_MAX;
        let fine = match &s {
            DecoySig::Batch { decoys, pubkey, sig, .. } => !decoys.is_empty() && decoys.len() <= crate::peg_pool::BATCH_MAX && ok(pubkey) && ok(sig),
            DecoySig::Return { pubkey, sig, .. } | DecoySig::Theft { pubkey, sig, .. } => ok(pubkey) && ok(sig),
        };
        fine.then_some(s)
    }
}

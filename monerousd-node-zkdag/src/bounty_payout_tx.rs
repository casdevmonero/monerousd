// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-10 / spec §8 item 4 — THE BUG BOUNTY, PAID FROM THE SURPLUS BUFFER (`Class::BountyPayout`).
//!
//! "Bug bounty paid from the surplus buffer, so disclosure pays better than exploitation." A bounty is ONE USDm note paid out of
//! the surplus buffer (the 25 % fee share, §15) to the reporter's wallet, authorised by ≥ 2/3 of custody bond — the same
//! quorum every custody action needs — over (nonce, amount, note commitment, clue digest). The chain pays it from its own pool
//! and refuses anything else.
//!
//! The borrowed shape is a treasury spend by a bonded quorum (Zcash's dev-fund lockbox disbursement / a Cosmos community-pool
//! spend), bounded by a constitutional cap: one payout is at most `BOUNTY_MAX_SURPLUS_FRACTION_BPS` of the buffer it draws on,
//! so no vote can empty the buffer in one object (§2.7: voting is bounded).
//!
//! §9.6 (a new value-moving door): (1) PoW — the carrying block's; (2) the object's proofs — every attestor's ML-DSA-65
//! signature over `bounty_statement`, weighed against the fold's bonded set (≥ 2/3), and the USDm mint carrier opening the note
//! to exactly `amount`, verified at the fold (the signatures again at admission); (3) value — the fold pays only from the
//! surplus buffer, never more than the cap or than the buffer holds, and the supply does not move (pool → note, as a miner
//! payout); (4) replay — `bounty_nf(nonce)` rides the lane and the spent set refuses a second payout of one nonce; (5) bounded
//! work — at most `MAX_CREDIT_ATTESTORS` signatures, one carrier; (6) parity with `Class::MinerPayout` / `BondYieldClaim` (pool
//! payouts): the pool covers the amount or nothing moves, the note is filed under its clue.

use serde::{Deserialize, Serialize};

/// The most one bounty may draw: 10 % of the surplus buffer it is paid from (constitutional — no vote moves it).
pub const BOUNTY_MAX_SURPLUS_FRACTION_BPS: u64 = 1_000;

/// The bounty, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BountyPayoutTx {
    /// The payout's one-time id (the report's id, chosen by the proposer).
    pub nonce: [u8; 32],
    /// The bounty, USDm atomic.
    pub amount: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload (or its 64-byte carriage reference).
    pub note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE asset mint carrier (USDm tag).
    pub carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX`.
    pub owner_clue: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `bridge_credit_tx::MAX_CREDIT_ATTESTORS` ML-DSA-65 (pubkey, signature) pairs, keys
    /// distinct and strictly ascending (one encoding).
    pub attestors: Vec<(Vec<u8>, Vec<u8>)>,
}

/// What every attestor signs.
#[must_use]
pub fn bounty_statement(nonce: &[u8; 32], amount: u64, note_cm: &[u8; 32], clue_digest: &[u8; 32]) -> Vec<u8> {
    let mut m = b"MUSD/bounty-payout/v1".to_vec();
    m.extend_from_slice(nonce);
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(note_cm);
    m.extend_from_slice(clue_digest);
    m
}

/// The payout's one-time id on the lane.
#[must_use]
pub fn bounty_nf(nonce: &[u8; 32]) -> [u8; 32] {
    let mut pre = b"MONEROUSD-BOUNTY-PAYOUT-NF-v1".to_vec();
    pre.extend_from_slice(nonce);
    crate::cover::canonical_tag_of_hash(crate::hash::Hash32::hash(&pre).as_bytes())
}

impl BountyPayoutTx {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::fixed::encode_plain(self)
    }
    /// The FRAMED blob.
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::BountyPayout, &self.encode())
    }
    /// One canonical encoding: a non-zero amount, a whole note (or its reference), a bounded clue, one to
    /// `MAX_CREDIT_ATTESTORS` attestors of exact widths, keys strictly ascending.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<BountyPayoutTx> {
        let t: BountyPayoutTx = crate::chain_object::decode_exact(bytes)?;
        let whole = t.note.len() == crate::cover::PQ_NOTE_BYTES || t.note.len() == crate::chain_object::NOTE_REF_BYTES;
        if t.amount == 0 || !whole || t.carrier.is_empty() || t.owner_clue.is_empty() || t.owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
            return None;
        }
        if t.attestors.is_empty() || t.attestors.len() > crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS {
            return None;
        }
        if t.attestors.iter().any(|(pk, sig)| pk.len() != crate::theft_tx::ML_DSA_65_PK_BYTES || sig.len() != crate::theft_tx::ML_DSA_65_SIG_BYTES) {
            return None;
        }
        if t.attestors.windows(2).any(|w| w[0].0 >= w[1].0) {
            return None;
        }
        crate::spend_frontier::note_cm_of(&t.note)?;
        Some(t)
    }
    /// The note's commitment.
    #[must_use]
    pub fn note_cm(&self) -> Option<[u8; 32]> {
        self.note.get(..32).and_then(|c| <[u8; 32]>::try_from(c).ok())
    }
    /// The statement the attestors signed.
    #[must_use]
    pub fn statement(&self) -> Option<Vec<u8>> {
        Some(bounty_statement(&self.nonce, self.amount, &self.note_cm()?, &crate::oli::owner_clue_digest(&self.owner_clue)))
    }
    /// ⭐ THE STATELESS HALF: every signature verifies over the statement and the carrier opens the note to `amount` USDm.
    /// (The WEIGHT — ≥ 2/3 of the bonded set — is the fold's: it needs the chain's set.)
    #[must_use]
    pub fn signatures_and_carrier_verify(&self) -> bool {
        let (Some(stmt), Some(leaf)) = (self.statement(), crate::spend_frontier::note_cm_of(&self.note)) else {
            return false;
        };
        self.attestors.iter().all(|(pk, sig)| crate::pqauth::ml_dsa_verify(&stmt, pk, sig))
            && usdm_decider::whir_rec_block::verify_asset_mint_validity_bytes(&self.carrier, leaf, self.amount, [0, 0, 0])
    }
    /// The attestors as the shared tally's certificate.
    #[must_use]
    pub fn cert(&self) -> crate::bond_tally::PqThresholdCert {
        crate::bond_tally::PqThresholdCert {
            attestors: self.attestors.iter().map(|(pk, sig)| crate::psm::MintAttestor { pubkey: pk.clone(), sig: sig.clone() }).collect(),
        }
    }
}

/// What applying a bounty at its block's fold did.
#[derive(Debug, PartialEq, Eq)]
pub enum BountyApply {
    NotBounty,
    Applied,
    Refused(&'static str),
}


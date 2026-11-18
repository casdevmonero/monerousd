// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-3 17.6 — A VALIDATOR CLAIMS ITS OWN-WEIGHT BONDERS' YIELD (`Class::BondYieldClaim`).
//!
//! Every unit of custody weight earns the bonders' pool pro rata through one index Y (`PegLedger::bond_yield_index`). A
//! delegation collects its share with a `SatDelegation` Claim; a seat's OWN weight (its locked bond) has no note to re-settle,
//! so the validator set keeps one settled index and one accrual per id (`ValidatorSet::settle_own_yield`), settled at every
//! own-weight change. This object pays that accrual out as ONE USDm note to the validator's wallet, out of the bonders' pool.
//!
//! The borrowed shape is the reward claim of a delegated-stake chain (Cosmos x/distribution `WithdrawValidatorCommission`): the
//! validator's key signs the withdrawal, the chain computes what is owed from its own state, and pays exactly that.
//!
//! §9.6 (a new value-moving door): (1) PoW — the carrying block's; (2) the object's proofs — the id's ML-DSA-65 signature over
//! (vid, index, amount, note commitment, clue digest), `pubkey_id(pubkey) == vid`, and the USDm mint carrier opening the note
//! to exactly `amount`, verified at admission and again at the fold; (3) value — the fold pays only `own_yield_at(vid, Y)`,
//! exactly, from the bonders' pool, never more than it holds, and zeroes the accrual in the same step; (4) replay — the
//! one-time id `claim_nf(vid, y)` rides the lane (the spent set refuses a second claim at one index), and a second claim at a
//! later index finds the accrual already zero; (5) bounded work — one signature, one carrier; (6) parity with
//! `Class::MinerPayout` (a pool payout): the pool covers the amount or nothing moves, the note is filed under its clue.

use serde::{Deserialize, Serialize};

/// The claim, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondYieldClaimTx {
    pub vid: [u8; 32],
    /// The bonders' yield index the claim settles at (judged equal to the chain's at the carrying fold).
    pub y_now: u128,
    /// The yield paid, USDm atomic (judged equal to `own_yield_at(vid, y_now)` at the fold).
    pub amount: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload (or its 64-byte carriage reference).
    pub note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE asset mint carrier (USDm tag).
    pub carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX`.
    pub owner_clue: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — an ML-DSA-65 public key (decode refuses any other width).
    pub pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — an ML-DSA-65 signature (decode refuses any other width).
    pub sig: Vec<u8>,
}

/// What the validator's key signs.
#[must_use]
pub fn claim_statement(vid: &[u8; 32], y_now: u128, amount: u64, note_cm: &[u8; 32], clue_digest: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + 16 + 8 + 64 + 32);
    m.extend_from_slice(b"MUSD/bond-yield-claim/v1");
    m.extend_from_slice(vid);
    m.extend_from_slice(&y_now.to_le_bytes());
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(note_cm);
    m.extend_from_slice(clue_digest);
    m
}

/// The claim's one-time id: one claim per (validator, index).
#[must_use]
pub fn claim_nf(vid: &[u8; 32], y_now: u128) -> [u8; 32] {
    let mut pre = Vec::with_capacity(64);
    pre.extend_from_slice(b"MONEROUSD-BOND-YIELD-CLAIM-NF-v1");
    pre.extend_from_slice(vid);
    pre.extend_from_slice(&y_now.to_le_bytes());
    crate::cover::canonical_tag_of_hash(crate::hash::Hash32::hash(&pre).as_bytes())
}

impl BondYieldClaimTx {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::fixed::encode_plain(self)
    }
    /// The FRAMED blob.
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::BondYieldClaim, &self.encode())
    }
    /// One canonical encoding, a non-zero amount, a whole note (or its reference), a bounded clue, exact key widths.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<BondYieldClaimTx> {
        let t: BondYieldClaimTx = crate::chain_object::decode_exact(bytes)?;
        let whole = t.note.len() == crate::cover::PQ_NOTE_BYTES || t.note.len() == crate::chain_object::NOTE_REF_BYTES;
        if t.amount == 0 || !whole || t.carrier.is_empty() || t.owner_clue.is_empty() || t.owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
            return None;
        }
        if t.pubkey.len() != crate::theft_tx::ML_DSA_65_PK_BYTES || t.sig.len() != crate::theft_tx::ML_DSA_65_SIG_BYTES {
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
    /// ⭐ THE STATELESS HALF: the key is the id's, it signed this claim, and the carrier opens the note to `amount` USDm.
    #[must_use]
    pub fn authorised(&self) -> bool {
        let (Some(cm), Some(leaf)) = (self.note_cm(), crate::spend_frontier::note_cm_of(&self.note)) else {
            return false;
        };
        crate::pqauth::pubkey_id(&self.pubkey) == self.vid
            && crate::pqauth::ml_dsa_verify(
                &claim_statement(&self.vid, self.y_now, self.amount, &cm, &crate::oli::owner_clue_digest(&self.owner_clue)),
                &self.pubkey,
                &self.sig,
            )
            && usdm_decider::whir_rec_block::verify_asset_mint_validity_bytes(&self.carrier, leaf, self.amount, [0, 0, 0])
    }
}

/// What applying a claim at its block's fold did.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimApply {
    NotClaim,
    Applied,
    Refused(&'static str),
}


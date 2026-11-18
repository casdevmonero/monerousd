// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ §BR-3 17.5 layer 1, realized — `Class::PotFill`: THE REPAYMENT POT IS SOLD AT THE FLOOR, AND ITS PROCEEDS ARE RETIRED
//! (docs/BR-3-17-5-LAYERED-REPAYMENT-SPEC-20261029.md §5).
//!
//! BORROWED: MakerDAO's surplus/debt auctions reduced to a fixed-price protocol sell order (the floor is the price; no auction
//! clock), and the liquidation lane's custody shape for the supply retire. A buyer burns `X` USDm (public) and receives
//! `S ≤ X × PRICE_SCALE / floor` SAT from the pot (public), where the floor is `min(twap7, low30)(SAT) × haircut` read by every
//! node at the fold. The burned USDm is RETIRED from the committed supply by a custody leg (`[new_minted, Pub(X), minted]`,
//! ≥ 2/3 of custody attesting) — that is what restores the collateral a theft drained; the pot owes the supply `V1` until its
//! sales cover it (`repayment_owed_atomic` falls by `min(X, owed)`).
//!
//! The buyer's half is the SAT delegation's shape: a bond-validity burn of exactly `X` USDm whose destroyed output is bound to
//! the SAT note's commitment (a burn cannot be lifted onto another note), its change as out1, the input's one-step membership,
//! and an asset mint carrier opening the SAT note to exactly `S` of SAT's tag. The burn's nullifier is the object's own lane
//! tag (the spent set refuses a second fill of one note).
//!
//! §9.6 (a new value-moving door): (1) PoW — the carrying block's; (2) the burn, mint and retire carriers, the membership step
//! (Fold door) and the ≥ 2/3 tally over `pot_fill_msg`, verified at the fold; (3) value — the SAT comes out of the pot word
//! (SAT that left circulation when the thief's bond was slashed: conserving), never above the pot or the floor price; the
//! USDm leaves the supply by exactly `X`; (4) replay — the burn's nullifier, refused by the spent set; (5) bounded — three
//! carriers + one member step + one tally, constant shape; (6) parity with `SatDelegation` (burn/mint/clues) and with the
//! liquidation door (the custody-attested supply transition).
//! DIGITAL-CASH-PRIVACY-REVIEWED: a public buy at a public price out of a public pot; the buyer's notes are ordinary
//! confidential notes under their own clues.

use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// A pot fill as it travels: the buyer's half (always) and the custody half (empty on a buy request, filled by the framer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PotFillTx {
    /// `X`: the USDm atomic burned (public).
    pub burn_usdm: u64,
    /// `S`: the SAT atomic taken from the pot (public).
    pub sat_out: u64,
    /// The burned input's nullifier (canonical digest) — the object's own lane tag.
    pub nullifier: [u8; 32],
    /// The membership cross-bind the burn carrier and the member step share.
    pub leaf_commit: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE bond-validity carrier.
    pub burn_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE one-step member carrier.
    pub membership_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — the fixed one-step tip.
    pub membership_tip: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload (or its carriage reference): the USDm change.
    pub change_note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `peg_in_tx::OWNER_CLUE_MAX`.
    pub change_clue: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload (or its reference): the SAT bought.
    pub sat_note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE asset mint carrier (SAT's tag).
    pub sat_mint_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `peg_in_tx::OWNER_CLUE_MAX`.
    pub sat_clue: Vec<u8>,
    /// The custody half: the supply after the retire (zero on a request).
    pub new_minted_commit: Digest4,
    /// O1-FOOTPRINT-REVIEWED: bounded by the constant WHIR proof bound — ONE retire leg (empty on a request).
    pub retire_leg: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `MAX_POT_FILL_ATTESTORS` — the bonded custodians' signatures (empty on a request).
    pub attestors: Vec<(Vec<u8>, Vec<u8>)>,
}

pub const MAX_POT_FILL_ATTESTORS: usize = crate::params::DAG_WIDTH_CEILING;

/// The opening of the burn's destroyed output, bound to the SAT note's commitment.
#[must_use]
pub fn pot_burn_opening(sat_cm: &[u8; 32]) -> Digest4 {
    let mut pre = Vec::with_capacity(64);
    pre.extend_from_slice(b"MUSD/pot-fill-burn/v1");
    pre.extend_from_slice(sat_cm);
    crate::spend_frontier::cm_bytes_to_leaf(crate::hash::Hash32::hash(&pre).as_bytes())
}

impl PotFillTx {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::PotFill, &self.encode())
    }
    /// One encoding, every width bounded; a request carries no custody half, a framed fill carries all of it.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<PotFillTx> {
        let t: PotFillTx = crate::chain_object::decode_exact(bytes)?;
        let max = crate::solvency::SolvencyProof::MAX_PROOF_BYTES;
        let clue = crate::peg_in_tx::OWNER_CLUE_MAX;
        let note_ok = |n: &Vec<u8>| !n.is_empty() && n.len() <= crate::cover::PQ_NOTE_BYTES;
        let ok = t.burn_usdm > 0
            && t.sat_out > 0
            && [&t.burn_carrier, &t.membership_carrier, &t.sat_mint_carrier].iter().all(|c| !c.is_empty() && c.len() <= max)
            && t.membership_tip.len() <= max
            && t.retire_leg.len() <= max
            && note_ok(&t.change_note)
            && note_ok(&t.sat_note)
            && !t.change_clue.is_empty()
            && t.change_clue.len() <= clue
            && !t.sat_clue.is_empty()
            && t.sat_clue.len() <= clue
            && t.attestors.len() <= MAX_POT_FILL_ATTESTORS
            && t.attestors.iter().all(|(pk, sig)| pk.len() <= crate::liquidation_tx::LIQUIDATION_SIG_FIELD_MAX && sig.len() <= crate::liquidation_tx::LIQUIDATION_SIG_FIELD_MAX);
        ok.then_some(t)
    }
    /// The buyer's half alone (the request a custodian signs over): the fill with no custody half.
    #[must_use]
    pub fn request(&self) -> PotFillTx {
        PotFillTx { new_minted_commit: [0; usdm_decider::poseidon2_compress::DIGEST_LANES], retire_leg: Vec::new(), attestors: Vec::new(), ..self.clone() }
    }
    /// The request's identity: blake3 over its one encoding.
    #[must_use]
    pub fn request_digest(&self) -> [u8; 32] {
        // ONE digest whether the notes are carried whole (the request on the custody lane) or as references (the object a
        // block carries — `chain_object`'s carriage canonicalisation): each note enters as its reference, which binds the
        // note's commitment AND the hash of its whole bytes, so nothing the custody signed can be swapped.
        let mut r = self.request();
        r.sat_note = crate::chain_object::note_ref(&r.sat_note).unwrap_or_default();
        r.change_note = crate::chain_object::note_ref(&r.change_note).unwrap_or_default();
        *blake3::hash(&r.encode()).as_bytes()
    }
    /// ⭐ THE STATELESS HALF: the burn destroys exactly `X` USDm into the output bound to the SAT note (change = out1), and the
    /// mint opens the SAT note to exactly `S` of SAT's tag.
    #[must_use]
    pub fn carriers_verify(&self) -> bool {
        let (Some(nf), Some(lc), Some(change), Some(sat)) = (
            crate::spend_frontier::cm_bytes_to_root(&self.nullifier),
            crate::spend_frontier::cm_bytes_to_root(&self.leaf_commit),
            crate::spend_frontier::note_cm_of(&self.change_note),
            crate::spend_frontier::note_cm_of(&self.sat_note),
        ) else {
            return false;
        };
        let sat_cm = crate::spend_frontier::leaf_to_cm_bytes(sat);
        let out0 = usdm_decider::whir_rec_block::asset_note_cm(self.burn_usdm, usdm_decider::whir_rec_block::USDM_ASSET_TAG, pot_burn_opening(&sat_cm));
        usdm_decider::verify_bond_validity_carrier_with_commit_bytes(
            &self.burn_carrier,
            out0,
            change,
            nf,
            self.burn_usdm,
            lc,
            usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC,
        ) && usdm_decider::whir_rec_block::verify_asset_mint_validity_bytes(&self.sat_mint_carrier, sat, self.sat_out, crate::satoshi::asset_tag())
    }
    #[must_use]
    pub fn attestors_list(&self) -> Vec<crate::psm::MintAttestor> {
        self.attestors.iter().map(|(pubkey, sig)| crate::psm::MintAttestor { pubkey: pubkey.clone(), sig: sig.clone() }).collect()
    }
}

/// ONE bonded custodian's signature over a buy request's retire (the attestation lane's unit, `WireMsg::PotFillSig`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PotFillSig {
    pub request_digest: [u8; 32],
    pub new_minted_commit: Digest4,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl PotFillSig {
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: PotFillSig = crate::chain_object::decode_exact(bytes)?;
        let ok = |f: &Vec<u8>| !f.is_empty() && f.len() <= crate::liquidation_tx::LIQUIDATION_SIG_FIELD_MAX;
        (ok(&s.pubkey) && ok(&s.sig)).then_some(s)
    }
}

/// What applying a carried pot fill did.
#[derive(Debug, PartialEq, Eq)]
pub enum PotFillApply {
    NotPotFill,
    Filled,
    Refused(&'static str),
}


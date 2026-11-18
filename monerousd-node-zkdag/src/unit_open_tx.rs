// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-4 B4-2 — `Class::UnitOpen` (41): ONE debt unit opened against ONE co-signed Bitcoin deposit
//! (docs/BR-4-7-PRIVATE-POSITIONS-SPEC-20261029.md §10.3).
//!
//! The object is an ordinary peg-in (`peg_in_tx`'s payload, unchanged: custody's ≥ 2/3 signature over the peg-in statement,
//! the solvency carrier, the USDm note's mint carrier, the sealed per-custodian deltas) plus the unit: its terms, its note and
//! the note's asset-mint carrier (value `U`, tag `terms.tag()`). The peg-in header's deposit id MUST be
//! [`unit_deposit_id`]`(base, terms, unit_cm)`, so the custody signature over the peg-in statement binds the unit.
//!
//! §9.6 — the six answers:
//! 1. PoW — the carrying block's.
//! 2. Proofs — the peg-in's solvency and mint carriers (`apply_peg_in_attested`, unchanged) and the unit note's asset-mint
//!    carrier ([`UnitOpenTx::unit_carrier_verifies`]).
//! 3. Conservation — the supply grows by `U` only when the unit's OWN deposit backs it at 110 % of its band's floor (DB-470:
//!    the peg-in carrier's `Marginal` gate at `PegLedger::mint_backing`), and only while the chain's reference price is at or
//!    above that floor. The unit note is a debt marker, not money.
//! 4. Replay — the unit deposit id AND the base deposit id enter the deposit-id SET: one Bitcoin deposit backs exactly one unit.
//! 5. Bounded work — the peg-in's own caps, one fixed-size unit, decode refuses anything wider.
//! 6. Parity with `Class::PegIn` — every peg-in check runs (the same apply), plus the unit's day/epoch exact check BEFORE any
//!    ledger move, plus the unit note's carrier.
//!
//! BORROWED: Liquity's open-trove (collateral in, debt minted at a floor ratio) on the chain's own peg-in door.

use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::debt_units::UnitTerms;
use serde::{Deserialize, Serialize};

/// The deposit id a unit's peg-in signs: binds the base deposit, the unit's terms and its note.
#[must_use]
pub fn unit_deposit_id(base: &[u8; 32], t: &UnitTerms, unit_cm: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/unit-open/deposit-id/v1");
    h.update(base);
    h.update(&t.tag_id());
    h.update(unit_cm);
    *h.finalize().as_bytes()
}

/// What a custodian checks before it signs a unit's peg-in (public: every field reaches the chain in the unit open).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitClaim {
    pub base_deposit_id: [u8; 32],
    pub terms: UnitTerms,
    pub unit_cm: [u8; 32],
}

impl UnitClaim {
    /// The deposit id the unit's peg-in signs.
    #[must_use]
    pub fn deposit_id(&self) -> [u8; 32] {
        unit_deposit_id(&self.base_deposit_id, &self.terms, &self.unit_cm)
    }

    /// ⭐ THE CUSTODIAN'S UNIT RULE (replacing the PSM's priced 150 % coverage for this leg): the sealed deposit holds at least
    /// the band's collateral, the sealed mint is exactly `U`, and the band's floor is at or under the reference price (no unit
    /// is born under its own 110 %). The aggregate ≥ 150 % is still the bound transition's, on the chain.
    #[must_use]
    pub fn covered(&self, deposit_sats: u128, mint_atomic: u128, reference_price: Option<u128>) -> Result<(), &'static str> {
        let u = self.terms.unit_atomic().ok_or("no such unit size or band")?;
        if mint_atomic != u {
            return Err("the sealed mint is not the unit's size");
        }
        if deposit_sats < crate::debt_units::collateral_sats(self.terms.l as usize, self.terms.k as usize) {
            return Err("the deposit holds less than the band's collateral");
        }
        match reference_price {
            Some(p) if p >= crate::debt_units::band_price_word(self.terms.k as usize) => Ok(()),
            Some(_) => Err("the band's floor is above the reference price: the unit would be born under 110 %"),
            None => Err("the chain holds no reference price"),
        }
    }
}

/// The unit half a wallet's peg request carries (public; the chain carries all of it in the unit open).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitPart {
    pub claim: UnitClaim,
    /// O1-FOOTPRINT-REVIEWED: exactly `PQ_NOTE_BYTES` (`UnitPart::bounded`).
    pub unit_note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `peg_in_tx::OWNER_CLUE_MAX`.
    pub unit_clue: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `UNIT_CARRIER_MAX`.
    pub unit_carrier: Vec<u8>,
}

impl UnitPart {
    /// Bounded and self-consistent: the note's commitment is the claim's, the carrier proves the note opens to `U` of the
    /// unit's tag.
    #[must_use]
    pub fn verifies(&self) -> bool {
        self.unit_note.len() == crate::cover::PQ_NOTE_BYTES
            && !self.unit_clue.is_empty()
            && self.unit_clue.len() <= crate::peg_in_tx::OWNER_CLUE_MAX
            && !self.unit_carrier.is_empty()
            && self.unit_carrier.len() <= UNIT_CARRIER_MAX
            && self.unit_note.get(..32) == Some(&self.claim.unit_cm[..])
            && UnitOpenTx {
                peg_in: Vec::new(),
                base_deposit_id: self.claim.base_deposit_id,
                terms: self.claim.terms,
                unit_note: self.unit_note.clone(),
                unit_clue: self.unit_clue.clone(),
                unit_carrier: self.unit_carrier.clone(),
            }
            .unit_carrier_verifies()
    }
}

/// One unit open as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitOpenTx {
    /// The peg-in payload exactly as `peg_in_tx::encode` writes it (decoded by `peg_in_tx::decode`).
    pub peg_in: Vec<u8>,
    /// The co-signed Bitcoin deposit this unit's collateral came from (the replay key of the deposit itself).
    pub base_deposit_id: [u8; 32],
    pub terms: UnitTerms,
    /// The unit note (`PQ_NOTE_BYTES`): value `U`, asset tag `terms.tag()`, owned by the borrower.
    pub unit_note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `peg_in_tx::OWNER_CLUE_MAX`.
    pub unit_clue: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `UNIT_CARRIER_MAX`.
    pub unit_carrier: Vec<u8>,
}

/// The widest unit-note mint carrier decode accepts: the one bound every carrier shares. MEASURED (lane funds 2026-10-29): a
/// real asset-mint carrier is ~100 KB (the SAT reward's, 100,631 B), so the first 64 KB cap refused every unit the shipped
/// wallet built ("the unit half does not verify against itself") while the bound-tier pins (small test carriers) passed.
pub const UNIT_CARRIER_MAX: usize = crate::solvency::SolvencyProof::MAX_PROOF_BYTES;

impl UnitOpenTx {
    /// The one encoding (`None` only if the in-memory value cannot serialize, which a decoded value always can).
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    #[must_use]
    pub fn wire(&self) -> Option<Vec<u8>> {
        Some(frame(Class::UnitOpen, &self.encode()?))
    }
    /// Decode one canonical, bounded unit open (the peg-in inside must decode, and its deposit id must bind the unit).
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let t: Self = decode_exact(payload)?;
        // the note travels whole on the gossip lane and as its reference inside a block's carriage (`chain_object::carriage_of`)
        let ok = (t.unit_note.len() == crate::cover::PQ_NOTE_BYTES || t.unit_note.len() == crate::chain_object::NOTE_REF_BYTES)
            && !t.unit_clue.is_empty()
            && t.unit_clue.len() <= crate::peg_in_tx::OWNER_CLUE_MAX
            && !t.unit_carrier.is_empty()
            && t.unit_carrier.len() <= UNIT_CARRIER_MAX
            && t.terms.unit_atomic().is_some();
        if !ok {
            return None;
        }
        let (h, ..) = crate::peg_in_tx::decode(&t.peg_in)?;
        (h.deposit_id == unit_deposit_id(&t.base_deposit_id, &t.terms, &t.unit_cm()?)).then_some(t)
    }

    /// The unit note's commitment bytes.
    #[must_use]
    pub fn unit_cm(&self) -> Option<[u8; 32]> {
        self.unit_note.get(..32)?.try_into().ok()
    }

    /// The unit note opens to exactly `U` of the unit's own asset tag.
    #[must_use]
    pub fn unit_carrier_verifies(&self) -> bool {
        let (Some(u), Some(cm)) = (self.terms.unit_atomic(), crate::spend_frontier::note_cm_of(&self.unit_note)) else {
            return false;
        };
        let Ok(u) = u64::try_from(u) else { return false };
        usdm_decider::whir_rec_block::verify_asset_mint_validity_bytes(&self.unit_carrier, cm, u, self.terms.tag())
    }
}

/// What applying one carried unit open did.
#[derive(Debug, PartialEq, Eq)]
pub enum UnitOpenApply {
    NotUnitOpen,
    Opened,
    Refused(&'static str),
}


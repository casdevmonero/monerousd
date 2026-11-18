// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-4 B4-3 — `Class::UnitClose` (43): ONE debt unit closed — the unit note dies, its debt plus interest is burned, and
//! custody returns the unit's collateral in payout-ladder pieces (docs/BR-4-7-PRIVATE-POSITIONS-SPEC-20261029.md §10.4).
//!
//! The owner's half (the REQUEST a custodian signs over):
//! - the unit note's destruction — an asset bond (`verify_asset_bond_validity_carrier_bytes`): output 0 welded to the public
//!   `(U, terms.tag())` and opened under [`unit_burn_opening`] (bound to this close's terms and Bitcoin ticket, so it cannot be
//!   lifted onto another close), zero change; the input's one-step membership;
//! - the debt burn — a USDm bond-validity burn of exactly `debt_atomic` (`UnitBook::close_terms` at the carrying block's day),
//!   output 0 opened under [`debt_burn_opening`] (bound to the terms, the ticket and the unit's nullifier), the change as output
//!   1 under its own clue; the input's one-step membership;
//! - the §BR-5 ticket for the release: ONE ticket for the whole close (the destination sealed under a fresh key, one share per
//!   custodian, each share's commitment), bound into `redeem_commit`.
//!
//! Custody's half: Retire `[new_minted, Pub(U), minted]` and Seize `[new_reserve, Pub(c), reserve]` with
//! `c = collateral_sats(l, k)`, and ≥ 2/3 of the bonded weight over `PegLedger::unit_close_msg`.
//!
//! §9.6 — the six answers:
//! 1. PoW — the carrying block's.
//! 2. Proofs — the two burns and two memberships (the Fold door), the two legs and the tally, all at the fold.
//! 3. Value — the supply falls by exactly `U` and the reserve by exactly the unit's collateral; the burn pays `U` plus the
//!    interest, which moves into the stakers' pool (still USDm, now the pool's). Nothing is created.
//! 4. Replay — both burns' nullifiers enter the spent set: a unit closes once, a burn pays once.
//! 5. Bounded work — a fixed shape: two burns, two member steps, two legs, one tally, one ticket.
//! 6. Parity — the unit note's door is `SatDelegation`'s asset bond, the debt burn is `PotFill`'s bond-validity burn with its
//!    member step, the legs are the liquidation lane's public-amount transitions, the ticket is `PegOut`'s.
//!
//! BORROWED: Liquity's closeTrove (repay the debt, take the collateral back), on the chain's own burn, bond and payout doors.
//! DIGITAL-CASH-PRIVACY-REVIEWED: the close reveals what §10.3 makes public (band, size, open day) and the debt that follows
//! from them; the owner, the change and the Bitcoin destination stay hidden; the collateral pays out in ladder pieces that mix
//! with every cash-out.

use crate::chain_object::{decode_exact, frame, Class};
use crate::debt_units::UnitTerms;
use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// One unit close as it travels (a request carries no custody half; a framed close carries all of it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitCloseTx {
    pub terms: UnitTerms,
    /// The unit note's nullifier (canonical 32-byte form) — the replay key that closes a unit once.
    pub unit_nullifier: [u8; 32],
    pub unit_leaf_commit: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by `SolvencyProof::MAX_PROOF_BYTES` in `decode`.
    pub unit_burn_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded in `decode`.
    pub unit_membership_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded in `decode`.
    pub unit_membership_tip: Vec<u8>,
    /// USDm atomic burned: `U × I(today) / I(open day)`, rounded up (checked EXACTLY at the fold).
    pub debt_atomic: u64,
    pub debt_nullifier: [u8; 32],
    pub debt_leaf_commit: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded in `decode`.
    pub debt_burn_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded in `decode`.
    pub debt_membership_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded in `decode`.
    pub debt_membership_tip: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: at most `PQ_NOTE_BYTES` (a reference inside a block's carriage).
    pub change_note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `peg_in_tx::OWNER_CLUE_MAX`.
    pub change_clue: Vec<u8>,
    /// §BR-5: the release ticket, its share envelopes and share commitments (bounded by `peg_out_tx::ticket_parts_well_formed`).
    pub ticket: crate::peg_out_tx::TicketParts,
    /// The ticketed commitment the custody signs (`cashout_ticket::ticketed_commit`).
    pub redeem_commit: [u8; 32],
    pub new_minted_commit: Digest4,
    pub new_reserve_commit: Digest4,
    /// O1-FOOTPRINT-REVIEWED: bounded in `decode`.
    pub retire_leg: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded in `decode`.
    pub release_leg: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `MAX_UNIT_CLOSE_ATTESTORS` — the bonded custodians' signatures (empty on a request).
    pub attestors: Vec<(Vec<u8>, Vec<u8>)>,
}

pub const MAX_UNIT_CLOSE_ATTESTORS: usize = crate::params::DAG_WIDTH_CEILING;

/// The opening of the unit note's destroyed output: bound to the close's terms and its Bitcoin ticket.
#[must_use]
pub fn unit_burn_opening(t: &UnitTerms, redeem_commit: &[u8; 32]) -> Digest4 {
    let mut h = blake3::Hasher::new_derive_key("MUSD/unit-close/unit-burn/v1");
    h.update(&t.tag_id());
    h.update(redeem_commit);
    crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
}

/// The opening of the debt burn's destroyed output: bound to the terms, the ticket and the unit note's nullifier, so one debt
/// burn pays for exactly one unit's close.
#[must_use]
pub fn debt_burn_opening(t: &UnitTerms, redeem_commit: &[u8; 32], unit_nullifier: &[u8; 32]) -> Digest4 {
    let mut h = blake3::Hasher::new_derive_key("MUSD/unit-close/debt-burn/v1");
    h.update(&t.tag_id());
    h.update(redeem_commit);
    h.update(unit_nullifier);
    crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
}

/// The payout piece `i` of a close: its obligation key (unique per close through the unit's nullifier).
#[must_use]
pub fn piece_key(unit_nullifier: &[u8; 32], i: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/unit-close/piece/v1");
    h.update(unit_nullifier);
    h.update(&(i as u64).to_le_bytes());
    *h.finalize().as_bytes()
}

/// The pieces a unit's collateral pays out in (largest first). `None` when the collateral is not an exact sum of ladder
/// pieces — which `debt_units::collateral_sats` rules out by construction.
#[must_use]
pub fn release_pieces(t: &UnitTerms) -> Option<Vec<u64>> {
    let c = u64::try_from(crate::debt_units::collateral_sats(usize::from(t.l), usize::from(t.k))).ok()?;
    let (pieces, rest) = crate::peg_pool::split_to_denoms(c);
    (rest == 0 && !pieces.is_empty()).then_some(pieces)
}

impl UnitCloseTx {
    /// The one encoding (`None` only if the in-memory value cannot serialize, which a decoded value always can).
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    #[must_use]
    pub fn wire(&self) -> Option<Vec<u8>> {
        Some(frame(Class::UnitClose, &self.encode()?))
    }
    /// Decode one canonical, bounded unit close.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = decode_exact(bytes)?;
        let max = crate::solvency::SolvencyProof::MAX_PROOF_BYTES;
        let clue = crate::peg_in_tx::OWNER_CLUE_MAX;
        let carriers = [&t.unit_burn_carrier, &t.unit_membership_carrier, &t.debt_burn_carrier, &t.debt_membership_carrier];
        let ok = t.terms.unit_atomic().is_some()
            && t.debt_atomic > 0
            && carriers.iter().all(|c| !c.is_empty() && c.len() <= max)
            && t.unit_membership_tip.len() <= max
            && t.debt_membership_tip.len() <= max
            && t.retire_leg.len() <= max
            && t.release_leg.len() <= max
            && !t.change_note.is_empty()
            && t.change_note.len() <= crate::cover::PQ_NOTE_BYTES
            && !t.change_clue.is_empty()
            && t.change_clue.len() <= clue
            && crate::peg_out_tx::ticket_parts_well_formed(&t.ticket)
            && t.attestors.len() <= MAX_UNIT_CLOSE_ATTESTORS
            && t.attestors.iter().all(|(pk, sig)| {
                pk.len() <= crate::liquidation_tx::LIQUIDATION_SIG_FIELD_MAX && sig.len() <= crate::liquidation_tx::LIQUIDATION_SIG_FIELD_MAX
            });
        ok.then_some(t)
    }
    /// The owner's half alone (the request a custodian signs over): the close with no custody half.
    #[must_use]
    pub fn request(&self) -> Self {
        let z = [0; usdm_decider::poseidon2_compress::DIGEST_LANES];
        UnitCloseTx { new_minted_commit: z, new_reserve_commit: z, retire_leg: Vec::new(), release_leg: Vec::new(), attestors: Vec::new(), ..self.clone() }
    }
    /// The request's identity: blake3 over its one encoding, the change note entering as its reference (the block carries it
    /// as one), so the custody signs one digest whether the note travels whole or by reference. `None` for a change note no
    /// reference can be formed for (such a request is refused wherever it arrives).
    #[must_use]
    pub fn request_digest(&self) -> Option<[u8; 32]> {
        let mut r = self.request();
        r.change_note = crate::chain_object::note_ref(&r.change_note)?;
        Some(*blake3::hash(&r.encode()?).as_bytes())
    }
    /// ⭐ THE STATELESS HALF: the unit note dies into the output bound to this close at exactly `(U, tag)` with no change, and
    /// the debt burn destroys exactly `debt_atomic` USDm into the output bound to this close and the unit's nullifier.
    #[must_use]
    pub fn carriers_verify(&self) -> bool {
        use usdm_decider::whir_rec_block as wr;
        let (Some(u), Some(unf), Some(ulc), Some(dnf), Some(dlc), Some(change)) = (
            self.terms.unit_atomic().and_then(|u| u64::try_from(u).ok()),
            crate::spend_frontier::cm_bytes_to_root(&self.unit_nullifier),
            crate::spend_frontier::cm_bytes_to_root(&self.unit_leaf_commit),
            crate::spend_frontier::cm_bytes_to_root(&self.debt_nullifier),
            crate::spend_frontier::cm_bytes_to_root(&self.debt_leaf_commit),
            crate::spend_frontier::note_cm_of(&self.change_note),
        ) else {
            return false;
        };
        let tag = self.terms.tag();
        let opening = unit_burn_opening(&self.terms, &self.redeem_commit);
        let unit_out0 = wr::asset_note_cm(u, tag, opening);
        let unit_out1 = wr::asset_note_cm(0, tag, opening);
        let debt_out0 = wr::asset_note_cm(self.debt_atomic, wr::USDM_ASSET_TAG, debt_burn_opening(&self.terms, &self.redeem_commit, &self.unit_nullifier));
        wr::verify_asset_bond_validity_carrier_bytes(&self.unit_burn_carrier, unit_out0, unit_out1, unf, ulc, u, tag)
            && usdm_decider::verify_bond_validity_carrier_with_commit_bytes(
                &self.debt_burn_carrier,
                debt_out0,
                change,
                dnf,
                self.debt_atomic,
                dlc,
                wr::PROTOCOL_FEE_ATOMIC,
            )
    }
    #[must_use]
    pub fn attestors_list(&self) -> Vec<crate::psm::MintAttestor> {
        self.attestors.iter().map(|(pubkey, sig)| crate::psm::MintAttestor { pubkey: pubkey.clone(), sig: sig.clone() }).collect()
    }
}

/// ONE bonded custodian's signature over a close request's two legs (the attestation lane's unit, `WireMsg::UnitCloseSig`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitCloseSig {
    pub request_digest: [u8; 32],
    pub new_minted_commit: Digest4,
    pub new_reserve_commit: Digest4,
    /// O1-FOOTPRINT-REVIEWED: bounded by `LIQUIDATION_SIG_FIELD_MAX` in `decode`.
    pub pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `LIQUIDATION_SIG_FIELD_MAX` in `decode`.
    pub sig: Vec<u8>,
}

impl UnitCloseSig {
    #[must_use]
    pub fn wire(&self) -> Option<Vec<u8>> {
        postcard::to_stdvec(self).ok()
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: UnitCloseSig = decode_exact(bytes)?;
        let ok = |f: &Vec<u8>| !f.is_empty() && f.len() <= crate::liquidation_tx::LIQUIDATION_SIG_FIELD_MAX;
        (ok(&s.pubkey) && ok(&s.sig)).then_some(s)
    }
}

/// What applying one carried unit close did.
#[derive(Debug, PartialEq, Eq)]
pub enum UnitCloseApply {
    NotUnitClose,
    Closed,
    Refused(&'static str),
}


#[cfg(test)]
mod tests {
    use super::*;

    /// A unit's collateral always pays out in exact ladder pieces; every piece has its own obligation key.
    #[test]
    fn a_units_collateral_splits_into_exact_ladder_pieces_with_distinct_keys() {
        for k in [0usize, 10, 18, 40, 63] {
            for l in 0..crate::debt_units::UNIT_ATOMIC.len() {
                let t = UnitTerms { k: k as u8, l: l as u8, day: 0, epoch: 0 };
                let pieces = release_pieces(&t).expect("⛔ a collateral that does not split into ladder pieces");
                assert_eq!(u128::from(pieces.iter().sum::<u64>()), crate::debt_units::collateral_sats(l, k));
                assert!(pieces.iter().all(|p| crate::peg_pool::is_denom(*p)));
            }
        }
        let nf = [7u8; 32];
        assert_ne!(piece_key(&nf, 0), piece_key(&nf, 1));
        assert_ne!(piece_key(&nf, 0), piece_key(&[8u8; 32], 0));
    }

    /// The two burn openings are bound to the close: another ticket or another unit gives another output.
    #[test]
    fn each_burn_is_bound_to_its_own_close() {
        let t = UnitTerms { k: 18, l: 2, day: 3, epoch: 0 };
        let (rc, rc2) = ([1u8; 32], [2u8; 32]);
        assert_ne!(unit_burn_opening(&t, &rc), unit_burn_opening(&t, &rc2));
        assert_ne!(unit_burn_opening(&t, &rc), unit_burn_opening(&UnitTerms { day: 4, ..t }, &rc));
        assert_ne!(debt_burn_opening(&t, &rc, &[3u8; 32]), debt_burn_opening(&t, &rc, &[4u8; 32]));
    }
}

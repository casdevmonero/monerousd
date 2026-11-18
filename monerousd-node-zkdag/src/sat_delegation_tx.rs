// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ §BR-3 17.3 / 17.4 — DELEGATED SAT BONDS, AS ASSET-TAG CONVERSION (`Class::SatDelegation`).
//!
//! Any SAT holder delegates SAT to a seated validator's custody weight; the delegator keeps the right to undelegate, the
//! validator gains weight and never the note. The shape is borrowed: UTXO COLOURING — a note's asset tag says what it is, and
//! a conversion object burns one colour and mints another, each step conserving value. Three kinds, one object:
//! - **Delegate:** burn `amount` SAT, mint `amount` of tag [`delegated_tag`]`(vid)` to a live, unslashed seat; its weight rises.
//! - **Undelegate:** burn a delegated note, mint the same amount of tag [`unbonding_tag`]`(matures)`, `matures` an epoch
//!   boundary ([`unbonding_epoch`]) at least the unbonding window past the carrying block; the seat's weight falls. After a
//!   slash for misbehaviour that lost no money (equivocation, epoch-key fraud) the delegations are RETURNED this way — the
//!   operator's own bond alone is burned (§22 5); after a reserve theft they were burned with the seat (17.4) and are refused.
//! - **Release:** at or after `matures`, burn the unbonding note and mint the same amount of SAT.
//! - **Claim (§17.6):** burn a delegated note settled at index `y0`, mint the same amount settled at the index now, and pay
//!   the yield since `y0` as one USDm note out of the bonders' pool (an Undelegate pays it the same way).
//!
//! A delegated or unbonding note is not SAT, so no SAT circuit can spend it — the LOCK IS THE TAG, and the chain keeps no
//! per-delegation state (one delegated word per validator id). Authority is the input note's own spend proof: no extra
//! signature, so delegations do not link through a key.
//!
//! ⭐ RECOVERABLE FROM THE SEED ALONE, AND NO GRINDING TARGETS. The delegated tag names only the validator id, and the node
//! serves every id holding a seat or a delegated word as one public list (the same bytes for every asker), so a restored
//! wallet matches its delegated notes' tags locally. The unbonding tag names an EPOCH boundary, so a restored wallet finds
//! `matures` by testing the epochs since genesis (one blake3 each), and the tag families an attacker could grind a token
//! id against stay small (ids with delegations; epochs since genesis) — 2⁹³ tag space over at most ~2¹² targets.
//! cons: an undelegation waits up to one epoch (one day at the 21-day default) longer than the window.
//!
//! §9.6 (a new value-moving door): (1) PoW — the carrying block's; (2) the object's proofs — the asset-tagged bond-validity
//! carrier (burn of exactly `amount` in the input tag, out0 bound to the minted note, change as out1) and the asset mint carrier
//! (exactly `amount` in the output tag), verified at admission and again at the fold with the input's membership (Fold door);
//! (3) value — each kind burns before it mints, never more than it burns, and the seat-weight move is the same `amount`;
//! (4) replay — the burned note's nullifier is the object's own lane tag, refused by the spent set; (5) bounded work — two
//! carriers + one member step, constant shape; (6) parity with `SatBond` (the SAT door it parallels): the seat rule (live,
//! unslashed seat), the carrier weld, the membership door and the clue filing — the bond's validator signature is replaced by
//! the input's own spend authority, since a delegation seats nobody.

use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// Which conversion this object performs. `y0` is the bonders' yield index a delegated note last settled at, `y_now` the
/// index at the carrying fold (§17.6: `PegLedger::bond_yield_index`, judged equal there).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegationKind {
    /// SAT → delegated(vid, y0), y0 = the index now
    Delegate { vid: [u8; 32], y0: u128 },
    /// delegated(vid, y0) → unbonding(matures), paying the yield since y0
    Undelegate { vid: [u8; 32], y0: u128, y_now: u128, matures: u64 },
    /// delegated(vid, y0) → delegated(vid, y_now), paying the yield since y0 (§17.6)
    Claim { vid: [u8; 32], y0: u128, y_now: u128 },
    /// unbonding(matures) → SAT
    Release { matures: u64 },
}

/// The conversion object, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SatDelegationTx {
    pub kind: DelegationKind,
    /// The burned amount = the minted amount (public, as every bond weight is).
    pub amount: u64,
    /// The burned input's nullifier (canonical digest) — the object's own lane tag.
    pub nullifier: [u8; 32],
    /// The membership cross-bind the burn carrier and the member step share (DB-363).
    pub leaf_commit: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE asset bond-validity carrier.
    pub burn_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE one-step member carrier.
    pub membership_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — the fixed one-step tip.
    pub membership_tip: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload (or its 64-byte carriage reference): the burn's
    /// change, in the INPUT tag.
    pub change_note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX`.
    pub change_clue: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload (or its reference): the minted note, OUTPUT tag.
    pub minted_note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE asset mint carrier.
    pub mint_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX`.
    pub minted_clue: Vec<u8>,
    /// §17.6 — the bonders' yield paid by an Undelegate or a Claim, as ONE USDm note (empty when the yield is zero).
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload (or its 64-byte carriage reference), or none.
    pub yield_note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE asset mint carrier (USDm tag), or none.
    pub yield_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX`, or none.
    pub yield_clue: Vec<u8>,
    /// ⭐ §22 3 — the delegated validator's uptime `(active windows, windows)` the yield is weighted by (delegators share their
    /// validator's rate): `(0, 0)` for a kind that pays none; the fold pays only what the chain's own record of that validator
    /// weighs the yield to.
    pub uptime: (u64, u64),
}

fn tag_of(domain: &[u8], parts: &[&[u8]]) -> [u64; 3] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    usdm_decider::whir_rec_block::wrapped_asset_tag(h.finalize().as_bytes())
}

/// The tag of SAT delegated to validator `vid`, settled at yield index `y0` — a colour of its own, never SAT.
#[must_use]
pub fn delegated_tag(vid: &[u8; 32], y0: u128) -> [u64; 3] {
    tag_of(b"MUSD/delegated-SAT/v3", &[vid, &y0.to_le_bytes()])
}

/// The unbonding epoch for an unbonding window of `window` CHAIN TICKS (A-F60: `Node::unbond_ticks`, a time — never a
/// block count at an assumed pace): one twenty-first of it (one day at the 21-day default), never below one tick.
/// `matures` must be a multiple of it.
#[must_use]
pub fn unbonding_epoch(window: u64) -> u64 {
    (window / 21).max(1)
}

/// The earliest epoch boundary an undelegation carried at chain tick `at` may name.
#[must_use]
pub fn earliest_matures(at: u64, window: u64) -> u64 {
    let e = unbonding_epoch(window);
    at.saturating_add(window).div_ceil(e).saturating_mul(e)
}

/// The tag of SAT unbonding until chain tick `matures`. v2 (A-F60, 2026-11-15): `matures` is a chain tick, where v1's
/// was a blue score; the domain moved with the unit so no note of one reads as the other.
#[must_use]
pub fn unbonding_tag(matures: u64) -> [u64; 3] {
    tag_of(b"MUSD/unbonding-SAT/v2", &[&matures.to_le_bytes()])
}

/// The opening of the burn's destroyed output, bound to the minted note's commitment (a burn cannot be lifted onto another
/// mint): `cm_bytes_to_leaf(H(domain ‖ minted_cm))`.
#[must_use]
pub fn delegation_burn_opening(minted_cm: &[u8; 32]) -> Digest4 {
    let mut pre = Vec::with_capacity(64);
    pre.extend_from_slice(b"MUSD/delegation-burn/v1");
    pre.extend_from_slice(minted_cm);
    crate::spend_frontier::cm_bytes_to_leaf(crate::hash::Hash32::hash(&pre).as_bytes())
}

impl SatDelegationTx {
    /// The canonical payload (the crate's one crash-free plain encoder).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::fixed::encode_plain(self)
    }
    /// The FRAMED blob — the one form this object travels in.
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::SatDelegation, &self.encode())
    }
    /// Refuses rather than guesses: one canonical encoding, non-zero amount, every carrier present, bounded clues, whole notes
    /// (or their 64-byte references), canonical digests.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<SatDelegationTx> {
        let t: SatDelegationTx = crate::chain_object::decode_exact(bytes)?;
        if t.amount == 0 || t.burn_carrier.is_empty() || t.mint_carrier.is_empty() || t.membership_carrier.is_empty() || t.membership_tip.is_empty() {
            return None;
        }
        let max = crate::peg_in_tx::OWNER_CLUE_MAX;
        if t.change_clue.is_empty() || t.change_clue.len() > max || t.minted_clue.is_empty() || t.minted_clue.len() > max {
            return None;
        }
        let whole = |n: &[u8]| n.len() == crate::cover::PQ_NOTE_BYTES || n.len() == crate::chain_object::NOTE_REF_BYTES;
        if !whole(&t.change_note) || !whole(&t.minted_note) {
            return None;
        }
        // §22 3: one encoding of the uptime — none for a kind that pays no yield, a real ratio for one that does
        let pays = matches!(t.kind, DelegationKind::Undelegate { .. } | DelegationKind::Claim { .. });
        if (!pays && t.uptime != (0, 0)) || (pays && (t.uptime.1 == 0 || t.uptime.0 > t.uptime.1)) {
            return None;
        }
        // §17.6: a yield note exactly when the kind pays a non-zero yield, whole, with its carrier and a bounded clue
        if t.yield_amount() > 0 {
            if !whole(&t.yield_note) || t.yield_carrier.is_empty() || t.yield_clue.is_empty() || t.yield_clue.len() > max {
                return None;
            }
            crate::spend_frontier::note_cm_of(&t.yield_note)?;
        } else if !t.yield_note.is_empty() || !t.yield_carrier.is_empty() || !t.yield_clue.is_empty() {
            return None;
        }
        if let DelegationKind::Claim { y0, y_now, .. } = t.kind {
            if y_now <= y0 {
                return None; // nothing to claim: one encoding, no no-op object
            }
        }
        if crate::spend_frontier::note_cm_of(&t.change_note).is_none()
            || crate::spend_frontier::note_cm_of(&t.minted_note).is_none()
            || crate::spend_frontier::cm_bytes_to_root(&t.nullifier).is_none()
            || crate::spend_frontier::cm_bytes_to_root(&t.leaf_commit).is_none()
        {
            return None;
        }
        Some(t)
    }
    /// The (input, output) tags this kind converts.
    #[must_use]
    pub fn tags(&self) -> ([u64; 3], [u64; 3]) {
        let sat = crate::satoshi::asset_tag();
        match self.kind {
            DelegationKind::Delegate { vid, y0 } => (sat, delegated_tag(&vid, y0)),
            DelegationKind::Undelegate { vid, y0, matures, .. } => (delegated_tag(&vid, y0), unbonding_tag(matures)),
            DelegationKind::Claim { vid, y0, y_now } => (delegated_tag(&vid, y0), delegated_tag(&vid, y_now)),
            DelegationKind::Release { matures } => (unbonding_tag(matures), sat),
        }
    }
    /// §17.6 — the bonders' yield this object pays: `⌊amount · (y_now − y0) / 2⁶⁴⌋` for an Undelegate or a Claim, else 0.
    #[must_use]
    pub fn yield_amount(&self) -> u64 {
        match self.kind {
            DelegationKind::Undelegate { y0, y_now, .. } | DelegationKind::Claim { y0, y_now, .. } => {
                let base = crate::peg::bond_yield_between(u128::from(self.amount), y0, y_now);
                crate::validator_activity::uptime_split(base, self.uptime.0, self.uptime.1).0 // §22 3
            }
            _ => 0,
        }
    }
    /// The yield before the validator's uptime weighs it (the bonders' index rise over the delegated amount).
    #[must_use]
    pub fn yield_base(&self) -> u64 {
        match self.kind {
            DelegationKind::Undelegate { y0, y_now, .. } | DelegationKind::Claim { y0, y_now, .. } => {
                crate::peg::bond_yield_between(u128::from(self.amount), y0, y_now)
            }
            _ => 0,
        }
    }
    /// The index the kind must find at the carrying fold (`None` for a Release).
    #[must_use]
    pub fn index_at_fold(&self) -> Option<u128> {
        match self.kind {
            DelegationKind::Delegate { y0, .. } => Some(y0),
            DelegationKind::Undelegate { y_now, .. } | DelegationKind::Claim { y_now, .. } => Some(y_now),
            DelegationKind::Release { .. } => None,
        }
    }
    /// ⭐ THE STATELESS HALF: the burn carrier destroys exactly `amount` of the input tag into the output bound to the minted
    /// note (change = `change_note`'s commitment), and the mint carrier opens `minted_note` to exactly `amount` of the output tag.
    #[must_use]
    pub fn carriers_verify(&self) -> bool {
        let (tag_in, tag_out) = self.tags();
        let (Some(nf), Some(lc), Some(change), Some(minted)) = (
            crate::spend_frontier::cm_bytes_to_root(&self.nullifier),
            crate::spend_frontier::cm_bytes_to_root(&self.leaf_commit),
            crate::spend_frontier::note_cm_of(&self.change_note),
            crate::spend_frontier::note_cm_of(&self.minted_note),
        ) else {
            return false;
        };
        let minted_cm = crate::spend_frontier::leaf_to_cm_bytes(minted);
        let out0 = usdm_decider::whir_rec_block::asset_note_cm(self.amount, tag_in, delegation_burn_opening(&minted_cm));
        let yield_ok = match self.yield_amount() {
            0 => true,
            y => crate::spend_frontier::note_cm_of(&self.yield_note).is_some_and(|cm| {
                usdm_decider::whir_rec_block::verify_asset_mint_validity_bytes(&self.yield_carrier, cm, y, [0, 0, 0])
            }),
        };
        yield_ok
            && usdm_decider::whir_rec_block::verify_asset_bond_validity_carrier_bytes(&self.burn_carrier, out0, change, nf, lc, self.amount, tag_in)
            && usdm_decider::whir_rec_block::verify_asset_mint_validity_bytes(&self.mint_carrier, minted, self.amount, tag_out)
    }
}

/// What applying a delegation at its block's fold did.
#[derive(Debug, PartialEq, Eq)]
pub enum DelegationApply {
    NotDelegation,
    Applied,
    Refused(&'static str),
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::ValidatorSet;

    /// ⭐ §BR-3 17.3 — THE DELEGATED WORD FOLLOWS THE ID: a delegation rises the seat; an unbond takes the weight out of the
    /// tally but keeps the word (its notes still exist), so a re-seat counts it again and an undelegation while unseated
    /// subtracts the word and no weight; a slash burns the word and every later undelegation is refused. TAMPERS: a
    /// delegation to an unseated or slashed id, and an undelegation above the word, are refused with nothing moved.
    #[test]
    fn the_delegated_word_follows_the_id_across_unbond_reseat_and_slash() {
        let (v, w) = ([7u8; 32], [8u8; 32]);
        let mut s = ValidatorSet::new();
        s.admit(v, 1_000, 0).expect("seat V");
        assert_eq!(s.delegate_refusal(&w, 5), Some("the validator holds no custody seat"), "⛔ a delegation to an unseated id");
        s.delegate(v, 300).expect("delegate");
        assert_eq!((s.bond_of(&v), s.delegated_to(&v), s.total_bond()), (1_300, 300, 1_300));
        assert_eq!(s.undelegate_refusal(&v, 301), Some("an undelegation larger than this validator's delegated weight"));
        assert_eq!(s.remove(&v), Some(1_300), "the unbond takes the whole weight out of the tally");
        assert_eq!((s.bond_of(&v), s.delegated_to(&v), s.total_bond()), (0, 300, 0), "⛔ the word left with the seat");
        s.admit(v, 1_000, 0).expect("re-seat V");
        assert_eq!((s.bond_of(&v), s.total_bond()), (1_300, 1_300), "⛔ a re-seat did not count the outstanding delegations");
        assert_eq!(s.undelegate(v, 100), Ok(true));
        assert_eq!((s.bond_of(&v), s.delegated_to(&v), s.total_bond()), (1_200, 200, 1_200));
        assert_eq!(s.remove(&v), Some(1_200));
        assert_eq!(s.undelegate(v, 50), Ok(false), "an unseated id's undelegation moves the word only");
        assert_eq!((s.delegated_to(&v), s.total_bond()), (150, 0));
        s.mark_slashed(v, 0);
        assert_eq!(s.delegated_to(&v), 0, "⛔ a slash did not burn the delegated word");
        assert_eq!(s.undelegate_refusal(&v, 1), Some("the validator was slashed: its delegations were burned with it"));
        assert_eq!(s.delegate_refusal(&v, 1), Some("the validator is slashed"));
    }

    /// The unbonding epoch is one twenty-first of the window (one day at 21 days), never zero, and the earliest maturity is
    /// the first boundary at or past `at + window`.
    #[test]
    fn the_unbonding_epoch_is_a_day_at_the_default_and_maturity_rounds_up_to_it() {
        let w = crate::params::UNBONDING_BLOCKS_DEFAULT;
        assert_eq!(unbonding_epoch(w), w / 21, "one twenty-first of the window: one day at the default");
        assert_eq!(unbonding_epoch(0), 1);
        assert_eq!(earliest_matures(0, w), w);
        let m = earliest_matures(1, w);
        assert!(m >= 1 + w && m % unbonding_epoch(w) == 0 && m - (1 + w) < unbonding_epoch(w));
        assert_ne!(unbonding_tag(m), unbonding_tag(m + unbonding_epoch(w)), "one tag per epoch");
        assert_ne!(delegated_tag(&[1; 32], 0), delegated_tag(&[2; 32], 0));
        assert_ne!(delegated_tag(&[1; 32], 0), delegated_tag(&[1; 32], 1), "one tag per settled index");
    }
}

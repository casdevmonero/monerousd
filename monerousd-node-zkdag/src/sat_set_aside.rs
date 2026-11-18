// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ §BR-13 — THE DEVELOPER SAT SET-ASIDE: ONE CANONICAL OBJECT, PROVEN ≤ 2,000,000 SAT, AMOUNT PRIVATE (spec §11).
//!
//! SAT has exactly three doors: the block reward, this set-aside, and a spend that conserves SAT. The set-aside is ONE
//! object whose bytes are compiled into every node (`sat_set_aside.bin`, identical in every build of a network), so no node
//! and no relay chooses it. It is the asset-tagged spend carrier over a PUBLIC input: a note of exactly
//! [`crate::satoshi::SAT_SET_ASIDE_MAX`] SAT under a published opening and blind. The carrier proves that input splits into
//! two outputs, both values hidden. Output 0 is the set-aside note, recorded and owned like any note. Output 1 is never
//! recorded, so nothing can ever spend it. Whatever the split, what enters circulation is at most 2M SAT, and the amount
//! is anywhere in [0, 2M]. An empty file means no set-aside: nothing is created.
//!
//! It rides the chain like any pooled object (the first node that holds it publishes it) and applies ONCE: the peg ledger's
//! `set_aside_applied` flag and the one-time id on the lane refuse a second.
//!
//! §9.6 (a new value-creating door): (1) PoW — the carrying block's; (2) the object's proofs — its bytes equal the canonical
//! bytes, and the spend carrier verifies over the recomputed input (`asset_note_cm(2M, SAT, opening)` bound into the
//! leaf commitment with the published blind), at admission and at the fold; (3) value — at most 2M SAT, by the carrier's
//! conservation over a public input; (4) replay — the flag and the one-time id `set_aside_nf()` on the lane; (5) bounded
//! work — one carrier; (6) parity with `Class::SatoshiReward` (the other SAT door): a fixed amount bound, applied at the
//! fold on every node, filed under its owner clue.

use serde::{Deserialize, Serialize};

/// The canonical set-aside bytes for this build's network (empty: no set-aside).
pub const CANONICAL: &[u8] = include_bytes!("sat_set_aside.bin");

/// The set-aside, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SatSetAsideTx {
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload (or its 64-byte carriage reference).
    pub note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX`.
    pub owner_clue: Vec<u8>,
    /// The unrecorded output's commitment (canonical digest bytes).
    pub out1_cm: [u8; 32],
    /// The public input's nullifier (canonical digest bytes).
    pub nullifier: [u8; 32],
    /// The public input's opening (canonical digest bytes).
    pub input_opening: [u8; 32],
    /// The published blind of the input's leaf commitment (canonical digest bytes).
    pub lc_blind: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE asset spend carrier.
    pub carrier: Vec<u8>,
}

/// The set-aside's one-time id.
#[must_use]
pub fn set_aside_nf() -> [u8; 32] {
    crate::cover::canonical_tag_of_hash(crate::hash::Hash32::hash(b"MONEROUSD-SAT-SET-ASIDE-NF-v1").as_bytes())
}

/// Test builds only: the canonical bytes the pins stand in (process-wide, because admission and the fold may run on other
/// threads), and whether THIS thread's producers offer them (so a concurrent test's producer never lays them).
#[cfg(test)]
static CANONICAL_FOR_TEST: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
#[cfg(test)]
thread_local! {
    static OFFER_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test builds only: stand in another canonical set-aside (the pins build one from a test key); this thread's producers
/// offer it.
#[cfg(test)]
pub fn set_canonical_for_test(bytes: Option<Vec<u8>>) {
    OFFER_FOR_TEST.with(|o| o.set(bytes.is_some()));
    *CANONICAL_FOR_TEST.lock().unwrap_or_else(|e| e.into_inner()) = bytes;
}

/// Test builds only: this thread's producers offer the canonical set-aside (or not) — a rogue-role pin turns the honest
/// producer's offer off so only the object it plants can apply.
#[cfg(test)]
pub fn set_offer_for_test(on: bool) {
    OFFER_FOR_TEST.with(|o| o.set(on));
}

/// The canonical bytes this node holds (`None` when the network has no set-aside).
#[must_use]
pub fn canonical_bytes() -> Option<Vec<u8>> {
    #[cfg(test)]
    if let Some(b) = CANONICAL_FOR_TEST.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return Some(b);
    }
    (!CANONICAL.is_empty()).then(|| CANONICAL.to_vec())
}

/// Does this producer offer the canonical set-aside? Always in a node binary (when one exists); in test builds only on a
/// thread that stood one in.
#[must_use]
pub fn producer_offers() -> bool {
    #[cfg(test)]
    {
        OFFER_FOR_TEST.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        true
    }
}

impl SatSetAsideTx {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::fixed::encode_plain(self)
    }
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::SatSetAside, &self.encode())
    }
    /// One canonical encoding, a whole note (or its reference), a bounded clue, canonical digests.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<SatSetAsideTx> {
        let t: SatSetAsideTx = crate::chain_object::decode_exact(bytes)?;
        let whole = t.note.len() == crate::cover::PQ_NOTE_BYTES || t.note.len() == crate::chain_object::NOTE_REF_BYTES;
        if !whole || t.carrier.is_empty() || t.owner_clue.is_empty() || t.owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
            return None;
        }
        crate::spend_frontier::note_cm_of(&t.note)?;
        for d in [&t.out1_cm, &t.nullifier, &t.input_opening, &t.lc_blind] {
            crate::spend_frontier::cm_bytes_to_root(d)?;
        }
        Some(t)
    }
    /// The recorded note's commitment.
    #[must_use]
    pub fn note_cm(&self) -> Option<[u8; 32]> {
        self.note.get(..32).and_then(|c| <[u8; 32]>::try_from(c).ok())
    }
    /// ⭐ THE BOUND: the spend carrier verifies over the PUBLIC input of exactly `SAT_SET_ASIDE_MAX` SAT — so the recorded
    /// note holds at most that, its value hidden.
    #[must_use]
    pub fn proves_the_bound(&self) -> bool {
        use crate::spend_frontier::{cm_bytes_to_root, note_cm_of};
        let (Some(out0), Some(out1), Some(nf), Some(opening), Some(blind)) = (
            note_cm_of(&self.note),
            cm_bytes_to_root(&self.out1_cm),
            cm_bytes_to_root(&self.nullifier),
            cm_bytes_to_root(&self.input_opening),
            cm_bytes_to_root(&self.lc_blind),
        ) else {
            return false;
        };
        let leaf = usdm_decider::whir_rec_block::asset_note_cm(crate::satoshi::SAT_SET_ASIDE_MAX, crate::satoshi::asset_tag(), opening);
        let lc = usdm_decider::note_membership_air::note_leaf_commitment(leaf, nf, blind);
        usdm_decider::whir_rec_block::verify_asset_spend_validity_carrier_bytes(&self.carrier, out0, out1, nf, lc)
    }
    /// The whole stateless rule: this is the canonical set-aside — every field equal to the canonical bytes', the note by its
    /// commitment (at the fold the note rides as its carriage reference, whose commitment is the same) — and it proves the
    /// bound.
    #[must_use]
    pub fn is_the_canonical_set_aside(&self) -> bool {
        let Some(c) = canonical_bytes().and_then(|b| SatSetAsideTx::decode(&b)) else {
            return false;
        };
        let same = self.note_cm().is_some()
            && self.note_cm() == c.note_cm()
            && (&self.owner_clue, &self.out1_cm, &self.nullifier, &self.input_opening, &self.lc_blind, &self.carrier)
                == (&c.owner_clue, &c.out1_cm, &c.nullifier, &c.input_opening, &c.lc_blind, &c.carrier);
        same && self.proves_the_bound()
    }
}

/// What applying the set-aside at its block's fold did.
#[derive(Debug, PartialEq, Eq)]
pub enum SetAsideApply {
    NotSetAside,
    Applied,
    Refused(&'static str),
}


/// Test builds: build a set-aside of `amount` SAT (≤ the bound) to the test owner `out0_opening`, from fixed test digests.
#[cfg(test)]
pub fn build_for_test(amount: u64, out0_opening: crate::spend_frontier::Digest4, input_value: u64) -> Option<SatSetAsideTx> {
    build_for_test_with_out1(amount, out0_opening, input_value, usdm_decider::poseidon2_compress::lanes_of(&[0x5e7a, 7, 7, 7]))
}

/// Test builds: [`build_for_test`] with the unrecorded output's opening named (the launch position splits that output, so
/// its test owner's opening goes here).
#[cfg(test)]
pub fn build_for_test_with_out1(
    amount: u64,
    out0_opening: crate::spend_frontier::Digest4,
    input_value: u64,
    out1_opening: crate::spend_frontier::Digest4,
) -> Option<SatSetAsideTx> {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block as wr;
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let owner = wr::NoteOwner::from_test_key(lanes_of(&[0x5e7a, 1, 2, 3]));
    let lc_blind = lanes_of(&[0x5e7a, 9, 9, 9]);
    let w = wr::AssetSpendValidityWitness {
        value_in: input_value,
        owner,
        value_out: input_value,
        fee: 0,
        lc_blind,
        out0_value: amount,
        out0_opening,
        out1_value: input_value.checked_sub(amount)?,
        out1_opening,
        asset: crate::satoshi::asset_tag(),
    };
    let (carrier, cms, nf, _lc) = wr::prove_asset_spend_validity_carrier_bytes(&w)?;
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&b32(cms[0]));
    Some(SatSetAsideTx {
        note,
        owner_clue: vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX],
        out1_cm: b32(cms[1]),
        nullifier: b32(nf),
        input_opening: b32(owner.opening()),
        lc_blind: b32(lc_blind),
        carrier,
    })
}

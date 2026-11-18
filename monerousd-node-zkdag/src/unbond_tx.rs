// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ §AS — AN UNBOND IS A CHAIN OBJECT, BECAUSE IT MOVES MONEY.
//!
//! ROOT-LAYER: the unbond is PRODUCED here — the release of a validator's weight and the return of its
//! bonded note. Before this class, that value was produced by a local mutation inside
//! `Node::unbond_validator` and never travelled; patching any reader (the finality tally, the served
//! index, the wallet's balance) would have papered over a divergence whose source is the transition
//! itself. The transition is the layer, so the transition becomes an object the block carries.
//!
//! ## Why the local mutation was a funds hole
//! 1. **THE FINALITY DENOMINATOR DIVERGES.** `total_bond` is what every ≥2/3 gate measures against, so
//!    the mesh finalises against a quorum that no longer exists.
//! 2. **THE SAME BOND IS RETURNED AGAIN** on every node that never saw the first unbond — one bonded
//!    note, withdrawn once per node.
//!
//! That is the cardinal stated word for word — *every value-moving transition MUST be a chain object the
//! block carries, NEVER a local mutation, however soundly the local node verified it* — and it is the
//! 2026-09-03 shape that paid a maker's lot out twice, wearing a validator's clothes.
//!
//! ⭐ THE ADMISSION ALREADY TRAVELLED (`Node::apply_bond_set`, the ONE admission path for produce AND
//! ingest). Only the direction that HANDS MONEY BACK did not. This is that direction, in the same shape.
//!
//! ⭐ SHAPE BORROWED FROM `wrapped_asset_tx`, WHICH ALREADY TRAVELS: the struct holds **no collection at
//! all** — only fixed-width fields — and the variable-length PQ material rides the payload tuple beside
//! it, bounded at `decode` by the ML-DSA-65 / ML-KEM-768 parameter sets themselves. Material that is not
//! a valid public key, signature or encapsulation key cannot exist in a decoded object, which is a
//! stronger bound than any byte cap and needs no exemption to state.
//!
//! ⛔ IT CARRIES NO NOTE. The bonded note already rides the block that admitted it (`Block::bond_set`:
//! *"the locked note rides so ANY node can return it on an authenticated unbond"*), so this object carries
//! only the AUTHORISATION. A wrapper claiming any note for one is a forgery
//! `chain_object::wrapper_binds_object` refuses.
//!
//! Per-object work is one strict decode, one signature verify and one indexed set removal — every term a
//! protocol constant, with no dependence on height, block count, note count or peer count.

use crate::chain_object::decode_exact;
use serde::{Deserialize, Serialize};

/// The fixed-width head of an unbond: whose the returned bond is.
///
/// ⛔ NO OWNERLESS RETURN. Without an owner clue the returned note is filed nowhere a seed-only restore looks, and the
/// owner would have to search the note stream for their own money. The clue is not optional here (DB-273 §19.3 L2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UnbondHeader {
    /// ⭐ DB-273 §19.3 L2 — `oli::owner_clue_digest(clue)` of the returned note's OLI clue (the clue itself rides the
    /// payload), signed in `validator_unbond_msg` v4 and hashed into the one-shot right. Never a wallet's static bucket.
    pub owner_clue_digest: [u8; 32],
    /// ⛔ DB-258 — WHICH bonding of the validator this unbond ends (`Node::bond_instance_of`). Signed with the rest of
    /// the statement, and every stateful door requires it to equal its OWN chain-derived instance for the validator:
    /// an old unbond names an old bonding and releases nothing.
    pub bond_instance: [u8; 32],
    /// ⛔ DB-258d — a SIGNER-CHOSEN value, fresh per unbond request (`fresh_unbond_nonce`) and signed with the rest, so each
    /// request is a distinct ONE-SHOT RIGHT (`unbond_right_nf`). A seat locks no collateral, so its instance is the same
    /// for every seating of V: without this, V's public unbond of one seating replayed against every later one.
    pub nonce: [u8; 32],
}

/// The EXACT payload type this class's bytes deserialize to: the fixed-width header plus the three raw PQ
/// blobs (validator public key, unbond signature, the returned note's OLI owner clue — DB-273 §19.3 L2). Named so the
/// wire-malleability fuzz family can name the real type this arm decodes rather than approximate it.
pub type UnbondPayload = (UnbondHeader, Vec<u8>, Vec<u8>, Vec<u8>);

/// The canonical payload bytes (unframed), or `None` if they cannot be produced.
///
/// ⛔ FAIL-CLOSED, NEVER DEFAULTED. An encode that answered with empty bytes on failure would hand the
/// caller something that frames cleanly and authorises nothing, and the caller would publish it.
#[must_use]
pub fn encode(
    header: &UnbondHeader,
    pubkey: &[u8],
    sig: &[u8],
    owner_clue: &[u8],
) -> Option<Vec<u8>> {
    postcard::to_stdvec(&(header, pubkey, sig, owner_clue)).ok()
}

/// The FRAMED blob — the one form this object travels in, so a peer knows WHICH rule to judge it by.
#[must_use]
pub fn wire(
    header: &UnbondHeader,
    pubkey: &[u8],
    sig: &[u8],
    owner_clue: &[u8],
) -> Option<Vec<u8>> {
    Some(crate::chain_object::frame(
        crate::chain_object::Class::Unbond,
        &encode(header, pubkey, sig, owner_clue)?,
    ))
}

/// Refuses rather than guesses.
///
/// ⭐⭐⭐ THE BOUND IS THE PQ PARAMETER SET, NOT A BYTE CAP. `MlDsaVerifier::verify` refuses a public key
/// or signature of any other length, and the owner clue is at most one clue (`peg_in_tx::OWNER_CLUE_MAX`); a decoded
/// unbond therefore has fixed-bound material by construction, at every height and for every submitter.
/// ⭐ DB-273 §19.3 L2: the owner clue is non-empty and its canonical digest is the header's `owner_clue_digest` (which
/// the validator signs), so a stripped or replaced clue is not an unbond.
///
/// Strict full-consumption decode, so `encode(a) || junk` is not a second, differently-identified copy of
/// one unbond (the wire-malleability class that cost the creation object a pin).
#[must_use]
pub fn decode(payload: &[u8]) -> Option<(UnbondHeader, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (header, pubkey, sig, owner_clue) = decode_exact::<UnbondPayload>(payload)?;
    if owner_clue.is_empty()
        || owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX
        || crate::oli::owner_clue_digest(&owner_clue) != header.owner_clue_digest
    {
        return None; // no owner, or not the owner the validator signed
    }
    if pubkey.is_empty() || sig.is_empty() {
        return None;
    }
    Some((header, pubkey, sig, owner_clue))
}

/// The validator id an unbond releases — `H(pubkey)`, RECOMPUTED by every node.
///
/// ⛔ NEVER A CLAIMED ID. Taking an id from the object is how you release someone else's bond.
#[must_use]
pub fn validator_id(pubkey: &[u8]) -> [u8; 32] {
    crate::pqauth::pubkey_id(pubkey)
}

/// ⭐ SELF-VERIFYING: the signature must be the key-holder's over THIS id's unbond message. Every node
/// reaches the same verdict from the object alone and never from the submitting node's word for it.
///
/// ⛔ DB-258: over the object's WHOLE statement (validator, bonding, owner, nonce), never the id alone. The owner is the
/// header's clue digest (DB-273 §19.3 L2), which `decode` already required the carried clue to open.
#[must_use]
pub fn is_authorised(
    header: &UnbondHeader,
    pubkey: &[u8],
    sig: &[u8],
    v: &dyn crate::pqauth::PqVerifier,
) -> bool {
    v.verify(
        pubkey,
        &crate::pqauth::validator_unbond_msg(
            &validator_id(pubkey),
            &header.bond_instance,
            &header.owner_clue_digest,
            &header.nonce,
        ),
        sig,
    )
}


/// ⛔⛔⛔ DB-258d — THE UNBOND'S ONE-SHOT RIGHT: `H(domain ‖ id ‖ every signed field)`, DERIVABLE from the object (the seat's
/// `membership_bond_tx::seat_right_nf`, in an unbond's clothes). The request's transaction carries it in its lane
/// (`chain_object::object_own_nullifiers`, checked at the pool door by `wrapper_binds_object`) and the block that releases
/// must carry it in ITS lane (`authorised_in_block`), so the sparse nullifier set retires it exactly once and a re-carried
/// copy of V's old unbond ends nothing. MEASURED (the DB-258d pin): without it, V's public unbond of seating #1 ended V's
/// seating #2 when anyone re-carried it.
/// ⭐ DB-273 §19.3 L2 (v2): the owner enters as the header's clue digest — every signed field, as before.
#[must_use]
pub fn unbond_right_nf(id: &[u8; 32], header: &UnbondHeader) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"musdm.validator.unbond-right.v2");
    h.update(id);
    h.update(&header.bond_instance);
    h.update(&header.owner_clue_digest);
    h.update(&header.nonce);
    crate::cover::canonical_tag_of_hash(h.finalize().as_bytes())
}

/// DB-258d — a fresh unbond-request nonce, by the crate's entropy idiom (both halves of a throwaway ML-KEM-768 keypair are
/// CSPRNG-minted, so their hash is uniform; the seat's nonce is minted the same way). Never a fixed value: two requests
/// with one nonce and one owner are one right, and the second could never release.
#[must_use]
pub fn fresh_unbond_nonce() -> [u8; 32] {
    let (ek, dk) = crate::pqkem::keypair();
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/unbond-nonce/v1");
    h.update(&ek);
    h.update(&dk);
    *h.finalize().as_bytes()
}


/// What applying an unbond object did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnbondApply {
    /// Not an unbond object — left entirely alone.
    NotUnbond,
    /// The weight was removed and the bonded note returned to its owner's bucket.
    Released(u128),
    /// Refused before anything moved, with the reason a node can act on.
    Refused(&'static str),
}


/// TEST-ONLY (DB-273 §19.3 L2): the unbond owner a fixture names — one clue-width value derived from the fixture's old
/// `(bucket, ek)` pair, so two fixtures that differed in EITHER still name different owners (a pin that re-points the
/// owner still re-points it), and every owner is a valid clue for `decode` and the doors.
#[cfg(test)]
pub fn unbond_clue_for_test(bucket: &[u8; 32], ek: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; crate::peg_in_tx::OWNER_CLUE_MAX];
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/test/unbond-clue/v1");
    h.update(bucket);
    h.update(ek);
    h.finalize_xof().fill(&mut out);
    out
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// ⭐ DB-273 §19.3 L2 — THE UNBOND'S OWNER IS UNDER THE VALIDATOR'S SIGNATURE: the carried clue must open the header's
    /// signed digest, so a stripped, replaced or oversized clue is not an unbond, and a re-pointed digest breaks the
    /// signature. CALIBRATION: the honest clue decodes and authorises; the right hashes the owner (two owners, two rights).
    #[test]
    fn an_unbond_whose_owner_clue_was_stripped_replaced_or_repointed_is_refused() {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let clue = unbond_clue_for_test(&[1u8; 32], b"owner");
        let hdr = |c: &[u8]| UnbondHeader {
            owner_clue_digest: crate::oli::owner_clue_digest(c),
            bond_instance: [9u8; 32],
            nonce: [5u8; 32],
        };
        let h = hdr(&clue);
        let msg = crate::pqauth::validator_unbond_msg(&validator_id(&pk), &h.bond_instance, &h.owner_clue_digest, &h.nonce);
        let sig = crate::pqauth::ml_dsa_sign(&msg, &sk).expect("the validator signs");
        let v = crate::pqauth::MlDsaVerifier;
        let (dh, _, _, dclue) = decode(&encode(&h, &pk, &sig, &clue).expect("encodes")).expect("CALIBRATION: decodes");
        assert_eq!(dclue, clue, "CALIBRATION: the decoded unbond carries its owner clue");
        assert!(is_authorised(&dh, &pk, &sig, &v), "CALIBRATION: the honest unbond authorises");
        let thief = unbond_clue_for_test(&[2u8; 32], b"thief");
        assert!(decode(&encode(&h, &pk, &sig, &[]).expect("encodes")).is_none(), "⛔ a STRIPPED owner clue decoded");
        assert!(decode(&encode(&h, &pk, &sig, &thief).expect("encodes")).is_none(), "⛔ a REPLACED owner clue decoded");
        let long = vec![7u8; crate::peg_in_tx::OWNER_CLUE_MAX + 1];
        assert!(decode(&encode(&hdr(&long), &pk, &sig, &long).expect("encodes")).is_none(), "⛔ an oversized clue decoded");
        let repointed = hdr(&thief);
        assert!(
            !is_authorised(&repointed, &pk, &sig, &v),
            "⛔ a RE-POINTED owner digest still carried the validator's signature"
        );
        assert_ne!(
            unbond_right_nf(&validator_id(&pk), &h),
            unbond_right_nf(&validator_id(&pk), &repointed),
            "the one-shot right hashes the owner"
        );
    }
}

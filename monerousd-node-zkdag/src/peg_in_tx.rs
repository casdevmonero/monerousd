// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ §CS — THE BTC/XMR PEG-IN IS A CHAIN OBJECT, BECAUSE IT IS HOW USDm COMES INTO EXISTENCE.
//!
//! ROOT-LAYER: this is the PRIMARY ISSUANCE ROUTE of the chain. A depositor sends BTC or XMR, a ≥2/3
//! bonded threshold attests an amount, and a confidential note is credited. Until this class existed that
//! credit was a LOCAL MUTATION: `Node::peg_in_confidential` ended in `record_account_target` +
//! `record_note_payload`, and `peg::peg_in_confidential` advanced `reserve_commit` / `minted_commit`, all
//! on the one node that answered the RPC.
//!
//! ## Why the local mutation was the worst hole on the chain
//! 1. **THE DEPOSITOR'S USDm DOES NOT EXIST ANYWHERE ELSE.** Every peer holds no note for it, so the
//!    money is real on one machine and absent on the network.
//! 2. **THE SAME DEPOSIT CAN BE RE-PEGGED PER NODE.** The replay set `confidential_deposit_ids` and the
//!    solvency commitments are per-node, and they diverge the moment one node mints. A depositor (or an
//!    attacker holding one attested request) re-submits to the next node and mints again.
//!
//! That is the cardinal, word for word — *every value-moving transition MUST be a chain object the block
//! carries, NEVER a local mutation, however soundly the local node verified it* — on the route that
//! matters most for real funds. `node.rs`'s own wrapped-mint apply site states the same rule: *"the peg
//! transition advances HERE on every node — never in the handler on the one that answered the request."*
//!
//! ## ⛔ WHY IT IS NOT `Class::WrappedMint`, WHICH LOOKS LIKE IT WOULD FIT
//! `WrappedMintHeader` carries an `asset_id` and `peg::psm_commits` already routes `NATIVE_PEG_ASSET_ID`,
//! so riding the existing class looked like the cheap borrow. Reading the two doors refutes it:
//!   * `wrapped_mint_confidential` opens with `if self.wrapped_assets.get(&asset_id).is_none() { return
//!     BadRequest }`, and the native peg is not in `wrapped_assets` — it is the native PSM;
//!   * it keys replay on `wrapped_deposit_key(asset_id, deposit_id)`, a DIFFERENT key space from the
//!     native `confidential_deposit_ids` — so one deposit could mint once through each door;
//!   * it tallies over `wrapped_mint_confidential_msg`, a different domain from
//!     `peg_in_confidential_msg`, so an attestation for one is not an attestation for the other;
//!   * it has no bond backstop, while the native path refuses `Underbonded`.
//!
//! Routing the native peg through it would have dropped the backstop and split the replay set — a pillar
//! trade wearing a code-reuse costume. This class carries exactly what `peg::peg_in_confidential` needs so
//! every peer re-runs THAT function, with its own message domain, its own replay key and its own backstop.
//!
//! ⭐ SHAPE BORROWED FROM `wrapped_mint_tx`, WHICH ALREADY TRAVELS: a fixed-width header plus the
//! variable-length PQ material beside it, bounded at `decode` by the parameter sets themselves.
//! ⭐ DB-273 §17b/§19 L1: the recipient's OWNER CLUE rides INSIDE the object as its last payload element, and the
//! header's `recipient` IS `peg::peg_in_recipient(deposit_id, clue)` — a commitment the quorum signs over — so a relay
//! that strips or swaps the clue leaves an object `decode` refuses. No per-wallet (bucket, ek) target exists any more.

use crate::chain_object::{decode_exact, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// The fixed-width head of a peg-in: everything `peg::peg_in_confidential` decides on, byte for byte.
///
/// ⛔ EVERY FIELD IS BOUND INTO THE ATTESTED MESSAGE. `peg::peg_in_confidential_msg` covers the deposit
/// id, both new commitments and the recipient, so a peer that re-tallies the quorum is re-tallying over
/// exactly these bytes. A field an attacker could change without invalidating the attestation would be a
/// field the quorum never authorised.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PegInHeader {
    /// The foreign-chain deposit this mint is against — the native replay key.
    pub deposit_id: [u8; 32],
    /// Who the confidential note is credited to.
    pub recipient: [u8; 32],
    /// The committed reserve AFTER the deposit leg (opaque digest — no value is readable).
    pub new_reserve_commit: crate::spend_frontier::Digest4,
    /// The committed circulating supply AFTER the mint leg (opaque digest).
    pub new_minted_commit: crate::spend_frontier::Digest4,
    /// DB-80: the COMMITTED mint delta both carriers open — `solvency_commit_256(mint, d_blind)`. The
    /// amount itself is nowhere on the object; the note credits what the commitment hides.
    pub delta_commit: crate::spend_frontier::Digest4,
    /// The executor's per-proposal nonce the quorum signed over (`peg::peg_in_confidential_msg` v2), so
    /// every node rebuilds the attested statement at apply and a stale signature can never complete
    /// another proposal for the same deposit.
    pub proposal_nonce: [u8; 32],
}

/// The EXACT payload type this class's bytes deserialize to: header, the confidential peg-in carrier, the
/// mint-validity carrier for the credited note, the bond backstop, the attestations as raw `(pubkey, sig)`
/// pairs, and the credited note.
pub type PegInPayload = (
    PegInHeader,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<(Vec<u8>, Vec<u8>)>,
    Vec<u8>,
    Vec<([u8; 32], Vec<u8>)>, // O1-FOOTPRINT-REVIEWED: the sealed per-custodian deltas, bounded by PEG_ATTEST_SEALED_MAX (decode refuses wider) — the block CARRIES what every custodian needs to apply it (DB-58)
    Vec<u8>, // DB-273 §17b: the owner clue — O1-FOOTPRINT-REVIEWED: bounded by OWNER_CLUE_MAX (decode refuses wider)
);

/// ⭐ DB-273 §17b — the largest owner clue a peg-family object carries: one OLI v2 tag (`oli::tag_clue_bytes_v2`),
/// whose length IS `omr::Clue::BYTES` — derived from the tag encoder, never a literal.
pub const OWNER_CLUE_MAX: usize = crate::omr::Clue::BYTES;

/// The canonical payload bytes (unframed).
///
/// ⛔ FAIL-CLOSED, NEVER DEFAULTED: an encode failure yields EMPTY bytes, which do not `unframe` into a
/// decodable object, so `decode` refuses them, `chain_object::admissible` refuses them and
/// `apply_chain_peg_in` reports `NotPegIn` — the same contract `wrapped_mint_tx::encode` carries.
#[must_use]
pub fn encode(
    header: &PegInHeader,
    peg_carrier: &[u8],
    mint_carrier: &[u8],
    bond_backstop: &[u8],
    attestors: &[MintAttestor],
    note: &[u8],
    sealed: &[([u8; 32], Vec<u8>)],
    owner_clue: &[u8],
) -> Vec<u8> {
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = attestors
        .iter()
        .map(|a| (a.pubkey.clone(), a.sig.clone()))
        .collect();
    postcard::to_stdvec(&(
        header,
        peg_carrier.to_vec(),
        mint_carrier.to_vec(),
        bond_backstop.to_vec(),
        pairs,
        note.to_vec(),
        sealed.to_vec(),
        owner_clue.to_vec(),
    ))
    .unwrap_or_default()
}

/// The FRAMED blob — the one form this object travels in, so a peer knows WHICH rule to judge it by.
#[must_use]
pub fn wire(
    header: &PegInHeader,
    peg_carrier: &[u8],
    mint_carrier: &[u8],
    bond_backstop: &[u8],
    attestors: &[MintAttestor],
    note: &[u8],
    sealed: &[([u8; 32], Vec<u8>)],
    owner_clue: &[u8],
) -> Vec<u8> {
    crate::chain_object::frame(
        Class::PegIn,
        &encode(header, peg_carrier, mint_carrier, bond_backstop, attestors, note, sealed, owner_clue),
    )
}

// CHAIN-PUBLISH-REVIEWED: a wire-field parser (bytes → typed object), a read of the request; it moves
// nothing — the signature is `fn(&[u8]) -> Option<..>` with no `&mut Node` to mutate.
/// Refuses rather than guesses. Strict full-consumption decode, so `encode(a) || junk` is not a second,
/// differently-identified copy of one peg-in (the wire-malleability class that cost the creation object a
/// pin).
///
/// ⭐⭐⭐ THE BOUNDS LIVE HERE, so no out-of-bounds shape ever reaches a signature verify or the door: an
/// unattested peg-in, one with no carrier, a zero amount, or a note too short to carry a commitment is not
/// an object at all. The attestor ceiling is `bridge_credit_tx::MAX_CREDIT_ATTESTORS`
/// (= `params::DAG_WIDTH_CEILING`), a fixed protocol constant, so a decoded peg-in's footprint carries no
/// term in height, supply or peer count.
/// ⭐ DB-273 §17b: the last element is the OWNER CLUE; a peg-in whose clue is empty (an owner nobody can find — a burn
/// wearing a default, §17 condition 1), longer than one tag, or does not open the header's recipient
/// (`peg::peg_in_recipient(deposit_id, clue)`, the value the quorum signed) is not an object.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<PegInDecoded> {
    let (h, peg_carrier, mint_carrier, backstop, pairs, note, sealed, owner_clue) =
        decode_exact::<PegInPayload>(payload)?;
    if owner_clue.is_empty() || owner_clue.len() > OWNER_CLUE_MAX {
        return None;
    }
    if crate::peg::peg_in_recipient(&h.deposit_id, &owner_clue) != h.recipient {
        return None; // a stripped or swapped clue: the signed recipient does not commit to it
    }
    if sealed.len() > crate::peg_attest::PEG_ATTEST_SEALED_MAX {
        return None; // more envelopes than the bonded custodian set can hold
    }
    if peg_carrier.is_empty() || mint_carrier.is_empty() {
        return None; // a peg-in with no proof authorises nothing
    }
    if pairs.is_empty() {
        return None; // unattested is not a peg-in
    }
    if pairs.len() > crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS {
        return None; // more signatures than the bonded set can hold
    }
    if h.delta_commit.iter().all(|x| *x == 0) {
        return None; // no committed mint delta credits nobody
    }
    if note.len() < 32 {
        return None; // a note too short to carry a commitment credits nobody
    }
    let attestors: Vec<MintAttestor> = pairs
        .into_iter()
        .map(|(pubkey, sig)| MintAttestor { pubkey, sig })
        .collect();
    Some((h, peg_carrier, mint_carrier, backstop, attestors, note, sealed, owner_clue))
}

/// A decoded peg-in: header, peg carrier, mint carrier, bond backstop, attestors, note, sealed envelopes, owner clue.
pub type PegInDecoded = (
    PegInHeader,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<MintAttestor>,
    Vec<u8>,
    Vec<([u8; 32], Vec<u8>)>,
    Vec<u8>,
);

/// What applying a peg-in object did.
#[derive(PartialEq, Eq, Debug)]
pub enum PegInApply {
    /// Not a peg-in object — left entirely alone.
    NotPegIn,
    /// The deposit minted: the peg commitments advanced and the note was credited, on THIS node, from
    /// the object's own bytes.
    Minted,
    /// Refused before anything moved, with the peg's own verdict.
    Refused(crate::peg::PegOutcome),
}

// CHAIN-PUBLISH-REVIEWED: the apply half, driven by the PegIn chain object at graft — every node runs it
// on the bytes a block carries, and the publish half is `Node::peg_in_confidential`.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn clue() -> Vec<u8> {
        vec![0xC7u8; OWNER_CLUE_MAX]
    }

    fn header() -> PegInHeader {
        PegInHeader {
            deposit_id: [1u8; 32],
            recipient: crate::peg::peg_in_recipient(&[1u8; 32], &clue()),
            new_reserve_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            new_minted_commit: usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
            delta_commit: usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]),
            proposal_nonce: [3u8; 32],
        }
    }

    /// ⭐ DB-273 §19 L1 — THE PEG-IN'S OWNER IS UNDER THE QUORUM'S SIGNATURE: the signed `recipient` commits to exactly
    /// one clue, so a stripped (empty), replaced (another tag) or oversized clue is not an object — refused at every
    /// door that decodes it (pool, graft, apply). CALIBRATION: the honest clue decodes, and the replaced copy differs
    /// from it ONLY in the clue (the statement the quorum signs is a function of the header alone, which is unchanged).
    #[test]
    fn a_peg_in_whose_clue_was_stripped_replaced_or_widened_is_not_an_object() {
        let a = vec![MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }];
        let enc = |c: &[u8]| encode(&header(), &[3u8; 16], &[4u8; 16], &[5u8; 16], &a, &[9u8; 64], &[], c);
        let honest = decode(&enc(&clue())).expect("CALIBRATION: the honest clue decodes");
        assert_eq!(honest.7, clue(), "CALIBRATION: the decoded object carries its owner's clue");
        assert!(decode(&enc(&[])).is_none(), "⛔ a peg-in whose clue a relay STRIPPED decoded");
        let replaced = vec![0xD8u8; OWNER_CLUE_MAX];
        assert!(decode(&enc(&replaced)).is_none(), "⛔ a peg-in whose clue a relay REPLACED decoded");
        assert!(decode(&enc(&vec![0xC7u8; OWNER_CLUE_MAX + 1])).is_none(), "⛔ an oversized clue decoded");
        // The object-derived record (what every node stages) is the object's own (cm, clue).
        let blob = wire(&header(), &[3u8; 16], &[4u8; 16], &[5u8; 16], &a, &[9u8; 64], &[], &clue());
        assert_eq!(unframe(&blob).map(|(c, _)| c), Some(Class::PegIn), "PRECONDITION: framed as a peg-in");
        let recs =
            crate::chain_object::object_owner_clue_records(&blob).expect("a peg-in names its owner in the object");
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&[9u8; 64][..32]);
        assert_eq!(recs, vec![(cm, clue())], "the staged record is the object's own note and clue");
    }
}

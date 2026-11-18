// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! A WRAPPED MINT IS A CHAIN OBJECT — the note AND the peg transition it performs, on ONE object.
//!
//! WHY THIS CLASS EXISTS. `POST /wrapped_mint_execute` already published the minted NOTE as a
//! `Class::BridgeCredit`, so the route passed every "does this publish?" check — and it was still wrong.
//! `BridgeCreditTx` carries `{deposit_id, asset_tag, amount, note, owner}` and has NO field for the peg's
//! new reserve/minted commitments, while `apply_chain_bridge_credit` never advances them. The note
//! travelled; the COMMITMENT ADVANCE that `Node::execute_wrapped_mint` performed stayed on whichever node
//! answered the HTTP request.
//!
//! MEASURED by `chain_action_carriage_tests::a_wrapped_mint_carries_its_peg_transition_to_a_node_fed_only_the_chain`
//! — a peer that genuinely RECEIVED the published credit (`Credited(2000)`) still diverged on three
//! things:
//!   * the wrapped-asset PSM commitments (what actually backs the token),
//!   * the per-asset reserve high-water mark (what bounds a liquidation re-mark of that asset), and
//!   * the confidential deposit-id set — the replay guard that makes one confirmed foreign deposit mint
//!     EXACTLY ONCE. A peer short of that set will mint AGAIN against a deposit that already paid out.
//! The third is an inflation path, not a bookkeeping difference.
//!
//! ⛔ THE LESSON THIS CLASS ENCODES: "the route publishes something" is not the property that matters.
//! The property is that what it publishes carries the WHOLE transition. A static check can see the first;
//! only a two-party replay can see the second, which is why `chain_action_carriage_tests` exists beside
//! `chain_action_manifest_tests`.
//!
//! THE BORROW: the same shape [`crate::liquidation_tx`] uses for a collateral re-mark — the object
//! carries the new committed pair plus the WHIR carrier plus the bonded attestations, and the door
//! re-verifies all of it against THIS node's own persisted digests at apply. Nothing is taken on the
//! publisher's word.
//!
//! ONE OBJECT, NOT TWO. The note rides this object's wrapper (`output_notes`, bound by
//! `chain_object::wrapper_binds_object` against [`carried note`]) and the peg transition rides its
//! payload, so a block can never carry the credit without the advance or the advance without the credit.
//! Publishing them as two objects would reintroduce exactly the split this class closes.
//!
//! ROOT-LAYER: the transition is applied at the block-apply seam by
//! [`apply_chain_wrapped_mint`] -> [`crate::node::Node::apply_wrapped_mint_attested`] ->
//! [`crate::peg::PegLedger::wrapped_mint_confidential`], which is the only code that may move a wrapped
//! PSM's committed pair. The handler's job ends at publishing.
//! MEASURED, before -> after: the carriage pin named 3 divergences on a peer fed the published bytes;
//! after this class it names none.
//! MUST-STAY-GREEN: the peg + psm threshold pins, `bridge_credit_tx`'s own pins (its class is untouched),
//! every `*_with_trailing_bytes_*` decode pin (this class calls the shared `decode_exact`), and the
//! wrapped-mint route test.
//!
//! COST: the object carries one note (the block already carries notes), one constant-bounded WHIR carrier
//! and a bonded attestation list bounded by [`MAX_MINT_ATTESTORS`]. A mint is a bridge event, not
//! something a block or a note produces, so nothing here is charged per block, per note or per unit of
//! history.

use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// Bounded by the same protocol constant the re-mark uses — the bonded set cannot exceed
/// [`crate::params::DAG_WIDTH_CEILING`].
pub const MAX_MINT_ATTESTORS: usize = crate::params::DAG_WIDTH_CEILING;

/// The FIXED-WIDTH header of a block-carried wrapped mint: which asset, which foreign deposit, who is
/// credited, and the committed pair the PSM advances to. Every field is an id or an opaque digest —
/// never an amount in the clear except the credited `amount`, which the note's own carrier binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedMintHeader {
    pub asset_id: u32,
    /// The foreign-chain deposit this mint is against. The door's replay set makes it pay out once.
    pub deposit_id: [u8; 32],
    /// Who the confidential note is credited to.
    pub recipient: [u8; 32],
    /// The committed reserve AFTER the deposit leg (opaque digest).
    pub new_reserve_commit: crate::spend_frontier::Digest4,
    /// The committed circulating supply AFTER the mint leg (opaque digest).
    pub new_minted_commit: crate::spend_frontier::Digest4,
    /// DB-80b: the COMMITTED credited amount — `solvency_commit_256(amount, d_blind)` — the fifth commitment
    /// the transition carrier opens and the asset-mint-validity carrier binds the note to. The amount itself
    /// never rides the object; the asset (the door's decision) does.
    pub delta_commit: crate::spend_frontier::Digest4,
}

/// The EXACT payload type this class's bytes deserialize to.
/// DB-77 (2026-09-19): the object now CARRIES ITS JUSTIFICATION like `Class::PegIn` does — the
/// asset-mint-validity carrier (so every node verifies the note opens to the attested amount in the
/// attested asset, §BA/§BB) and the per-custodian sealed deltas (so a custodian advances its wrapped
/// opening FROM THE BLOCK, DB-58). Before this, peers applied the ledger move on the attestors' word
/// and never credited the note at all — a wrapped-asset note existed on the executor alone.
pub type WrappedMintPayload = (
    WrappedMintHeader,
    Vec<u8>,
    Vec<u8>,
    Vec<(Vec<u8>, Vec<u8>)>,
    Vec<u8>,
    Vec<([u8; 32], Vec<u8>)>, // O1-FOOTPRINT-REVIEWED: the sealed per-custodian legs, bounded by PEG_ATTEST_SEALED_MAX (decode refuses wider)
    Vec<u8>, // DB-273 §17b: the owner clue — O1-FOOTPRINT-REVIEWED: bounded by peg_in_tx::OWNER_CLUE_MAX (decode refuses wider)
);

/// The canonical payload bytes (unframed): header, the mint carrier, the attestations as raw
/// `(pubkey, sig)` pairs, and the minted note.
///
/// An encoding failure yields EMPTY bytes rather than a panic, and that is NOT a silent rescue: an empty
/// payload does not `unframe` into a decodable object, so [`decode`] refuses it,
/// `chain_object::admissible` refuses it, and [`apply_chain_wrapped_mint`] reports `NotWrappedMint`. The
/// failure surfaces as a refusal on the offending object alone instead of taking a node down mid-block —
/// the same fail-closed contract [`crate::liquidation_tx::encode`] carries.
pub fn encode(
    header: &WrappedMintHeader,
    carrier: &[u8],
    mint_carrier: &[u8],
    attestors: &[MintAttestor],
    note: &[u8],
    sealed: &[([u8; 32], Vec<u8>)],
    owner_clue: &[u8],
) -> Vec<u8> {
    // DB-273 §17b: the owner clue is the payload's last element.
    // ROOT-LAYER: the object's one encoding is where its owner enters the wire; every reader goes through `decode`.
    // MEASURED: READ — before, the owner rode an UNBOUND (bucket, ek) sidecar a relay could strip; after → the §19 L1
    // pins (a stripped or swapped clue refused on a second node), run with this landing.
    // MUST-STAY-GREEN: this module's round-trip and bounds pins; the chain-action carriage wrapped-mint pins.
    let att: Vec<(&[u8], &[u8])> = attestors
        .iter()
        .map(|a| (a.pubkey.as_slice(), a.sig.as_slice()))
        .collect();
    postcard::to_stdvec(&(header, carrier, mint_carrier, &att, note, sealed, owner_clue)).unwrap_or_default()
}

/// The ONE wire encoding: the canonical payload framed under this object's own class.
pub fn wire(
    header: &WrappedMintHeader,
    carrier: &[u8],
    mint_carrier: &[u8],
    attestors: &[MintAttestor],
    note: &[u8],
    sealed: &[([u8; 32], Vec<u8>)],
    owner_clue: &[u8],
) -> Vec<u8> {
    frame(Class::WrappedMint, &encode(header, carrier, mint_carrier, attestors, note, sealed, owner_clue))
}

/// THE ONE DECODE, and the ONE place this class's bounds live. Goes through the shared [`decode_exact`],
/// so `encode(x) || junk` is REFUSED rather than decoding to the same object under a different content
/// id. Then the bounds, BEFORE anything is returned: a non-empty carrier within
/// [`crate::peg::MAX_REVALUATION_CARRIER_BYTES`], a non-empty attestation list within
/// [`MAX_MINT_ATTESTORS`], a non-zero amount, and a note long enough to carry a commitment.
/// ⭐ DB-273 §17b: the last element is the OWNER CLUE; an empty one (§17 condition 1), one longer than a tag, or one
/// that does not open the header's recipient (`peg::peg_in_recipient(deposit_id, clue)`, which the quorum signs over
/// in `wrapped_mint_confidential_msg`) is not an object — a relay cannot strip or swap the owner.
#[allow(clippy::type_complexity)]
pub fn decode(
    payload: &[u8],
) -> Option<(WrappedMintHeader, Vec<u8>, Vec<u8>, Vec<MintAttestor>, Vec<u8>, Vec<([u8; 32], Vec<u8>)>, Vec<u8>)> {
    let (header, carrier, mint_carrier, pairs, note, sealed, owner_clue) =
        decode_exact::<WrappedMintPayload>(payload)?;
    if owner_clue.is_empty() || owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
        return None;
    }
    if crate::peg::peg_in_recipient(&header.deposit_id, &owner_clue) != header.recipient {
        return None;
    }
    if carrier.is_empty() || carrier.len() > crate::peg::MAX_REVALUATION_CARRIER_BYTES {
        return None;
    }
    if mint_carrier.is_empty() || mint_carrier.len() > crate::peg_attest::PEG_ATTEST_CARRIER_MAX {
        return None; // a mint whose note proves nothing credits nobody (§BA)
    }
    if sealed.len() > crate::peg_attest::PEG_ATTEST_SEALED_MAX {
        return None; // more envelopes than the bonded custodian set can hold
    }
    if pairs.is_empty() || pairs.len() > MAX_MINT_ATTESTORS {
        return None;
    }
    if header.delta_commit == usdm_decider::poseidon2_compress::zero_digest() || note.len() < 32 {
        return None; // an uncommitted mint is not a mint, and a note too short credits nobody
    }
    let attestors = pairs
        .into_iter()
        .map(|(pubkey, sig)| MintAttestor { pubkey, sig })
        .collect();
    Some((header, carrier, mint_carrier, attestors, note, sealed, owner_clue))
}

/// Wrap this object as the transaction that carries it into a block. The note rides `output_notes`,
/// which `chain_object::wrapper_binds_object` binds byte-exactly to the note inside the object — so the
/// credit and the peg advance cannot be separated in flight.
pub fn as_pq_tx(
    header: &WrappedMintHeader,
    carrier: &[u8],
    mint_carrier: &[u8],
    attestors: &[MintAttestor],
    note: &[u8],
    sealed: &[([u8; 32], Vec<u8>)],
    owner_clue: &[u8],
    stamp_bits: u32,
) -> crate::mempool::PqTx {
    let blob = wire(header, carrier, mint_carrier, attestors, note, sealed, owner_clue);
    // ⭐ DB-273 §19 L1: the note's OLI record is read from the OBJECT's own clue (`chain_object::object_owner_clue_records`,
    // bound by the signed recipient) on every node that stages it, so the relay-mutable sidecar stays EMPTY — a second
    // copy of the clue would add 642 B to every gossip hop and be ignored. No per-wallet (bucket, ek) target is written.
    let note_clues = Vec::new();
    let account_targets = Vec::new();
    let mut tx = crate::mempool::PqTx {
        clock_ms: 0,
        id: crate::mempool::PqTx::content_id(&blob),
        weight: blob.len() as u32,
        blob,
        nullifiers: Vec::new(),
        pow_stamp: 0,
        note_clues,
        account_targets,
        output_notes: note.to_vec(),
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
    // Grind the anti-spam stamp exactly as a real submit does — `bridge_credit_tx` records the measured
    // trap this avoids ("the bare blob with pow_stamp 0 was refused at the door and at the floor").
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

/// What the block-apply loop learned from one blob.
#[derive(Debug, PartialEq, Eq)]
pub enum WrappedMintApply {
    /// Not a framed, in-bounds wrapped mint — nothing touched.
    NotWrappedMint,
    /// The door advanced this asset's committed pair and recorded the deposit as spent.
    Minted,
    /// The door refused it (no >=2/3 weight, a carrier that does not verify against THIS node's digests,
    /// an unregistered asset, or a deposit that already paid out). Nothing touched.
    Refused(crate::peg::PegOutcome),
}


#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// A test owner clue (one tag's length), and the header whose recipient commits to it (§17b).
    fn clue() -> Vec<u8> {
        vec![0xC7u8; crate::peg_in_tx::OWNER_CLUE_MAX]
    }

    fn header() -> WrappedMintHeader {
        WrappedMintHeader {
            asset_id: 11,
            deposit_id: [1u8; 32],
            recipient: crate::peg::peg_in_recipient(&[1u8; 32], &clue()),
            new_reserve_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            new_minted_commit: usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
            delta_commit: usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]),
        }
    }

    fn att() -> Vec<MintAttestor> {
        vec![MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }]
    }

    /// The wire is ONE encoding, and a tolerated tail is refused — the shared `decode_exact` contract.
    #[test]
    fn the_wire_round_trips_under_its_own_class_and_refuses_a_trailing_tail() {
        let (h, a, note) = (header(), att(), vec![9u8; 64]);
        let blob = wire(&h, &[3u8; 16], &[4u8; 16], &a, &note, &[], &clue());
        let (class, payload) = unframe(&blob).expect("it frames");
        assert_eq!(class, Class::WrappedMint, "it frames under its own class");
        let (gh, gc, _gm, ga, gn, _gs, gclue) = decode(payload).expect("it decodes");
        assert_eq!(gclue, clue(), "the owner clue round-trips inside the object");
        assert_eq!((gh, gc.len(), ga.len(), gn.len()), (h, 16, 1, 64));

        let mut tailed = payload.to_vec();
        tailed.push(0u8);
        assert!(decode(&tailed).is_none(), "a tolerated tail would give one object two content ids");
    }

    /// The decode is where the bounds live: an unattested, carrier-less, zero-amount or note-less mint
    /// never becomes an object, so none of them can reach a signature verify or the door.
    #[test]
    fn the_decode_refuses_every_out_of_bounds_shape() {
        let (h, a, note) = (header(), att(), vec![9u8; 64]);
        assert!(decode(&encode(&h, &[], &[4u8; 16], &a, &note, &[], &clue())).is_none(), "no carrier is not a mint");
        assert!(decode(&encode(&h, &[3u8; 16], &[], &a, &note, &[], &clue())).is_none(), "a mint whose note proves nothing is not a mint (DB-77)");
        assert!(decode(&encode(&h, &[3u8; 16], &[4u8; 16], &[], &note, &[], &clue())).is_none(), "unattested is not a mint");
        assert!(
            decode(&encode(&h, &[3u8; 16], &[4u8; 16], &a, &[9u8; 8], &[], &clue())).is_none(),
            "a note too short to carry a commitment credits nobody"
        );
        let zero = WrappedMintHeader { delta_commit: usdm_decider::poseidon2_compress::zero_digest(), ..h };
        assert!(decode(&encode(&zero, &[3u8; 16], &[4u8; 16], &a, &note, &[], &clue())).is_none(), "an uncommitted mint is not a mint");
        // ⭐ DB-273 §17b — the OWNER: a stripped (empty), swapped (another tag) or oversized clue is not an object,
        // because the signed recipient commits to exactly one clue. CALIBRATION: the honest clue decodes.
        assert!(decode(&encode(&h, &[3u8; 16], &[4u8; 16], &a, &note, &[], &clue())).is_some(), "CALIBRATION");
        assert!(decode(&encode(&h, &[3u8; 16], &[4u8; 16], &a, &note, &[], &[])).is_none(), "⛔ a stripped owner decoded");
        let swapped = vec![0xD8u8; crate::peg_in_tx::OWNER_CLUE_MAX];
        assert!(decode(&encode(&h, &[3u8; 16], &[4u8; 16], &a, &note, &[], &swapped)).is_none(), "⛔ a swapped owner decoded");
        let long = vec![0xC7u8; crate::peg_in_tx::OWNER_CLUE_MAX + 1];
        assert!(decode(&encode(&h, &[3u8; 16], &[4u8; 16], &a, &note, &[], &long)).is_none(), "⛔ an oversized clue decoded");
    }

    /// The wrapper must carry EXACTLY the object's own note — the binding that stops a credit and its
    /// peg advance being separated, or a wrapper smuggling an extra chunk.
    #[test]
    fn the_object_justifies_exactly_its_own_note() {
        let (h, a, note) = (header(), att(), vec![9u8; 64]);
        let blob = wire(&h, &[3u8; 16], &[4u8; 16], &a, &note, &[], &clue());
        let justified = crate::chain_object::carried_note_payloads(&blob)
            .expect("a wrapped mint justifies its note");
        assert_eq!(justified, vec![note], "exactly its own note, byte for byte");
    }
}

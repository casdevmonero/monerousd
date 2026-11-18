// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::peg_in_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `peg_in_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::peg_in_tx::*;
use crate::chain_object::{decode_exact, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// ⭐⭐⭐ THE GRAFT-SIDE DOOR — every node that admits the block runs this, so the peg transition advances
/// and the note is credited on ALL of them, from the same bytes.
///
/// Total and deliberately dumb: bytes that are not a peg-in return `NotPegIn` untouched, so it can be
/// called on every framed blob with no type tag on the wire.
///
/// ⛔ NOTHING IS TRUSTED FROM THE PUBLISHER. The ≥2/3 tally runs against THIS node's own folded validator
/// set, the carrier verifies against THIS node's own persisted commitments, and the replay set is THIS
/// node's — `peg::peg_in_confidential` is re-run in full. A forged attestation, a carrier built for
/// another commitment pair, or a deposit already minted here all refuse, and the block still grafts
/// (fail-closed on the ITEM, never on chain progress).
pub fn apply_chain_peg_in(
    node: &mut crate::node::Node,
    blob: &[u8],
    verifier: &dyn crate::pqauth::PqVerifier,
) -> PegInApply {
    let Some((class, payload)) = unframe(blob) else {
        return PegInApply::NotPegIn;
    };
    if class != Class::PegIn {
        return PegInApply::NotPegIn;
    }
    // DB-273 §17b: `decode` already refused an empty clue or one that does not open the signed recipient.
    let Some((h, peg_carrier, mint_carrier, backstop, attestors, note, sealed, _owner_clue)) = decode(payload) else {
        return PegInApply::NotPegIn;
    };
    let outcome = node.apply_peg_in_attested(
        h.deposit_id,
        &peg_carrier,
        h.new_reserve_commit,
        h.new_minted_commit,
        h.recipient,
        h.proposal_nonce,
        &backstop,
        verifier,
        &attestors,
        h.delta_commit,
        &mint_carrier,
        &note,
        &sealed,
        None,
    );
    if !matches!(outcome, crate::peg::PegOutcome::ConfidentialMinted) {
        // DIGITAL-CASH-PRIVACY-REVIEWED: a deposit-id prefix and an outcome name — public chain structure.
        // MEASURED run 70 (2026-09-18): the attesting custodian showed NO mint-apply line at all, so a
        // refused or duplicate apply was invisible; a mint the block carries that this node did not apply
        // is a ledger divergence and must be loud.
        eprintln!(
            "[peg-in] ⛔ the block's mint for deposit {} was NOT applied on this node: {:?} (sealed envelopes: {})",
            &crate::hash::Hash32(h.deposit_id).to_hex()[..8],
            outcome,
            sealed.len()
        );
    }
    match outcome {
        crate::peg::PegOutcome::ConfidentialMinted => {
            // ⭐⭐⭐ §BA — THE CREDITED NOTE RIDES THIS NODE'S NEXT BLOCK; ITS JUSTIFICATION RIDES WITH IT.
            //
            // Under the constant-256 cover a peer resolves almost none of a block's bodies, so a note
            // arriving with nothing saying why used to mean RECEIVED. This object declares exactly the one
            // note it credits (`carried_note_payloads` for `Class::PegIn`), so carrying it in
            // `Block::credit_set` lets the peer check the note against the object's own bytes.
            //
            // ⛔ NO RE-STAGE (2026-10-04, DB-274 P4b): this apply runs at the FOLD of the block that already carries the
            // object and its note — that block IS the justification. Staging here re-carried the object in this node's
            // next block, where it was refused as re-carried and, worse, its one-time tag entered the DB-358 contest
            // ahead of an honest later object with the same tag (`an_executor_whose_mint_block_is_abandoned_by_a_jump…`).
            // The law is stated once at `Node::apply_fold_class_object`.
            PegInApply::Minted
        }
        other => PegInApply::Refused(other),
    }
}

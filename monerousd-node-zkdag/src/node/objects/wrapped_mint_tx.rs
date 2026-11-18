// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::wrapped_mint_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `wrapped_mint_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::wrapped_mint_tx::*;
use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// APPLY a block-carried wrapped mint — the single production path from a block's bytes to the door.
///
/// FAIL-CLOSED: the class is READ, never guessed. Everything that decides whether value moves — the
/// >=2/3 bonded tally, the carrier against THIS node's own digests, and the deposit-id replay set —
/// happens inside [`crate::peg::PegLedger::wrapped_mint_confidential`], so a forged object reaching this
/// function is refused and the block still grafts.
pub fn apply_chain_wrapped_mint(
    node: &mut crate::node::Node,
    blob: &[u8],
    verifier: &dyn crate::pqauth::PqVerifier,
) -> WrappedMintApply {
    let Some((class, payload)) = unframe(blob) else {
        return WrappedMintApply::NotWrappedMint;
    };
    if class != Class::WrappedMint {
        return WrappedMintApply::NotWrappedMint;
    }
    // DB-273 §17b: `decode` already refused an empty clue or one that does not open the signed recipient.
    let Some((h, carrier, mint_carrier, attestors, note, sealed, _owner_clue)) = decode(payload) else {
        return WrappedMintApply::NotWrappedMint;
    };
    let outcome = node.apply_wrapped_mint_attested(
        h.asset_id,
        h.deposit_id,
        &carrier,
        h.new_reserve_commit,
        h.new_minted_commit,
        h.recipient,
        verifier,
        &attestors,
        h.delta_commit,
        &mint_carrier,
        &note,
        &sealed,
    );
    if !matches!(outcome, crate::peg::PegOutcome::ConfidentialMinted) {
        eprintln!(
            "[wrapped-mint] ⛔ the block's wrapped mint (asset {}) for deposit {} was NOT applied on this node: {:?}",
            h.asset_id,
            &crate::hash::Hash32(h.deposit_id).to_hex()[..8],
            outcome
        );
    }
    match outcome {
        crate::peg::PegOutcome::ConfidentialMinted => {
            // ⭐⭐⭐ §BA — THE MINTED NOTE RIDES THIS NODE'S NEXT BLOCK; ITS JUSTIFICATION RIDES WITH IT.
            //
            // `apply_wrapped_mint_attested` credits through `record_note_payload`, which STAGES the note.
            // On every other node that note arrives with nothing saying why, and under the constant-256
            // cover a peer resolves almost none of a block's bodies — "nothing to judge from" used to mean
            // RECEIVED (§BA). This object declares exactly that one note (`carried_note_payloads` for
            // `Class::WrappedMint`), so carrying it in `Block::credit_set` lets the peer check the note
            // against the object's own bytes instead of the producer's word.
            //
            // ⛔ NO RE-STAGE (2026-10-04, DB-274 P4b): applied at the FOLD of the block that carries the object and its
            // note — that block is the justification; re-staging re-carried it. Law: `Node::apply_fold_class_object`.
            WrappedMintApply::Minted
        }
        other => WrappedMintApply::Refused(other),
    }
}

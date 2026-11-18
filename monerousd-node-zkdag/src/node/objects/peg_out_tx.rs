// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::peg_out_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `peg_out_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::peg_out_tx::*;
use crate::chain_object::{decode_exact, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// ⭐⭐⭐ THE GRAFT-SIDE DOOR — every node that admits the block retires the burn and advances the
/// reduction, so one USDm note redeems ONCE across the network instead of once per node.
///
/// ⛔ NOTHING IS TRUSTED FROM THE PUBLISHER: the ≥2/3 tally runs against THIS node's own folded validator
/// set, the redeem-floor carrier verifies against THIS node's own persisted commitments, and `spent_burns`
/// is THIS node's. A forged attestation, a carrier built for another commitment pair, or a nullifier
/// already retired here all refuse, and the block still grafts.
/// OWED — the custodian's half of a peg-out this node's ledger already holds as an owed release: decode the chain object
/// and hand its parts to [`crate::node::Node::recover_peg_out_leg`] (its doc carries the door checklist). `false` for any
/// other class, a blob that does not decode, or a leg that is not recovered. Moves nothing in the ledger.
pub fn recover_chain_peg_out_leg(node: &mut crate::node::Node, blob: &[u8], verifier: &dyn crate::pqauth::PqVerifier, burn_height: u64) -> bool {
    let Some((class, payload)) = unframe(blob) else {
        return false;
    };
    if class != Class::PegOut {
        return false;
    }
    let Some((h, carrier, redeem_commit, attestors, _change_note, sealed, _owner_clue, ticket)) = decode(payload) else {
        return false;
    };
    node.recover_peg_out_leg(
        h.usdm_nullifier,
        &carrier,
        h.new_reserve_commit,
        h.new_minted_commit,
        &redeem_commit,
        &h.proposal_nonce,
        h.leaf_commit,
        &h.change_owner,
        &h.change_cm,
        verifier,
        &attestors,
        &sealed,
        &ticket,
        burn_height,
    )
}

pub fn apply_chain_peg_out(
    node: &mut crate::node::Node,
    blob: &[u8],
    verifier: &dyn crate::pqauth::PqVerifier,
) -> PegOutApply {
    let Some((class, payload)) = unframe(blob) else {
        return PegOutApply::NotPegOut;
    };
    if class != Class::PegOut {
        return PegOutApply::NotPegOut;
    }
    let Some((h, carrier, redeem_commit, attestors, change_note, sealed, _owner_clue, ticket)) = decode(payload) else {
        return PegOutApply::NotPegOut;
    };
    let outcome = node.apply_peg_out_attested(
        h.usdm_nullifier,
        &carrier,
        h.new_reserve_commit,
        h.new_minted_commit,
        &redeem_commit,
        &h.proposal_nonce,
        h.leaf_commit,
        &h.change_owner,
        &h.change_cm,
        verifier,
        &attestors,
        &change_note,
        &sealed,
        &ticket,
    );
    match outcome {
        crate::peg::PegOutcome::ConfidentialRedeemed => {
            // ⛔ NO RE-STAGE (2026-10-04, DB-274 P4b): applied at the FOLD of the block that carries the object and its
            // change note — that block is the justification; re-staging re-carried it. Law: `Node::apply_fold_class_object`.
            PegOutApply::Redeemed
        }
        other => PegOutApply::Refused(other),
    }
}

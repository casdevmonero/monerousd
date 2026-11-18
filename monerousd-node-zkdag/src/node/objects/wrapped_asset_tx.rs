// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::wrapped_asset_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `wrapped_asset_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::wrapped_asset_tx::*;
use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// APPLY a block-carried wrapped-asset registration — the single production path from a block's bytes to
/// the door.
///
/// ROOT-LAYER: this is the seam where a block's bytes become a class-specific action, exactly where
/// [`crate::node::objects::liquidation_tx::apply_chain_liquidation`] sits for its own class; the value itself is set one
/// layer down, inside [`crate::peg::PegLedger::register_wrapped_asset_attested`], which is the only code
/// that may move a wrapped asset's ratio. Deciding a registration anywhere else — in an RPC handler, in a
/// wallet — would be a second encoding of the same thing that could reach a different verdict on the same
/// bytes, which is the defect this class exists to remove.
///
/// FAIL-CLOSED: the class is READ, never guessed; a blob of another class, or a payload that is not an
/// in-bounds registration, returns `NotRegistration` and changes nothing. Everything that decides whether
/// the ratio moves — the >=2/3 bonded tally over the domain-separated message, and the commitment-chain
/// check that the attested `prev_ratio_bps` is what this node holds — happens inside the door, so a forged
/// object reaching this function is simply refused and the block still grafts.
pub fn apply_chain_wrapped_asset_register(
    node: &mut crate::node::Node,
    blob: &[u8],
    verifier: &dyn crate::pqauth::PqVerifier,
) -> RegisterApply {
    let Some((class, payload)) = unframe(blob) else {
        return RegisterApply::NotRegistration;
    };
    if class != Class::WrappedAssetRegister {
        return RegisterApply::NotRegistration;
    }
    let Some((h, attestors)) = decode(payload) else {
        return RegisterApply::NotRegistration;
    };
    let outcome = node.register_wrapped_asset_attested(
        h.epoch_id,
        h.asset_id,
        h.prev_ratio_bps,
        h.ratio_bps,
        verifier,
        &attestors,
    );
    // The real-node journeys read these two lines from each process's own log (the claim is what EACH process applied
    // from a block). They lived in the graft arm DB-274 P4b 2a deleted (b760746), so since then no journey could see a
    // registration apply — restored here, at the one fold-time apply. DIGITAL-CASH-PRIVACY-REVIEWED: an asset id and a
    // collateral ratio — public governance values every node must agree on; no amount, key or owner.
    match outcome {
        crate::peg::PegOutcome::WrappedAssetRegistered => {
            eprintln!("[wrapped-register] applied: asset {} ratio {}", h.asset_id, h.ratio_bps);
            RegisterApply::Registered
        }
        other => {
            eprintln!("[wrapped-register] refused: {other:?}");
            RegisterApply::Refused(other)
        }
    }
}

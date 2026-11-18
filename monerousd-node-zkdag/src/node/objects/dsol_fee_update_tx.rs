// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::dsol_fee_update_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `dsol_fee_update_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::dsol_fee_update_tx::*;
use crate::contract_state::{update_root, PathWire};
use crate::dsol_deploy_tx::{ContractManifest, DSOL_PUBLISHER_FEE_MAX_ATOMIC, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES};
use crate::spend_frontier::Digest4;

/// The fold door: the stateless half, then the leaf against this node's root; the leaf moves under the new manifest.
pub fn apply_chain_dsol_fee_update(node: &mut crate::node::Node, blob: &[u8]) -> FeeUpdateApply {
    let Some((crate::chain_object::Class::DsolFeeUpdate, payload)) = crate::chain_object::unframe(blob) else {
        return FeeUpdateApply::NotUpdate;
    };
    let Some(t) = DsolFeeUpdateTx::decode(payload) else {
        return FeeUpdateApply::Refused("the payload is not a fee update");
    };
    if let Some(why) = node.dsol_fee_update_refusal(&t) {
        eprintln!("[fold-refuse] class=DsolFeeUpdate why={why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
        return FeeUpdateApply::Refused(why);
    }
    match node.apply_dsol_fee_update_state(&t) {
        Some(root) => FeeUpdateApply::Applied(root),
        None => FeeUpdateApply::Refused("its contract-state path does not open this node's current root — the leaf moved; re-prove on the new state"),
    }
}

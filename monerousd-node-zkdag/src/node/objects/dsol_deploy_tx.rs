// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::dsol_deploy_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `dsol_deploy_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::dsol_deploy_tx::*;
use crate::asset_tx::CreationFee;
use crate::contract_state::{contract_leaf, insert_root, PathWire};
use crate::spend_frontier::Digest4;

/// ⭐ THE FOLD DOOR — every node, in canonical order, from the block's bytes alone: the fee note's membership
/// (`MemberDoor::Fold`), the burn carrier, the signature, then the state insert against the node's CURRENT root. A refusal is
/// on the item only (the block stands); a stale path is the expected refusal of a deploy that raced another in one block —
/// the deployer re-proves on the new root (A3's shape).
pub fn apply_chain_dsol_deploy(node: &mut crate::node::Node, blob: &[u8]) -> DeployApply {
    let Some((crate::chain_object::Class::DsolDeploy, payload)) = crate::chain_object::unframe(blob) else {
        return DeployApply::NotDeploy;
    };
    let Some(d) = DsolDeployTx::decode(payload) else {
        return DeployApply::Refused("the payload is not a deploy");
    };
    if let Some(why) = node.dsol_deploy_refusal(&d, crate::respend::MemberDoor::Fold) {
        eprintln!("[fold-refuse] class=DsolDeploy why={why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
        return DeployApply::Refused(why);
    }
    match node.apply_dsol_deploy_state(&d) {
        Some(root) => {
            let h = node.tip_height();
            node.record_note_payload(h, &d.fee.change_note);
            DeployApply::Applied(root)
        }
        None => DeployApply::Refused(
            "its contract-state path does not open this node's current root (the root moved since it was built, or the cid is taken) — re-prove on the new root",
        ),
    }
}

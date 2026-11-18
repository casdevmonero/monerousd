// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::dsol_call_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `dsol_call_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::dsol_call_tx::*;
use crate::contract_state::{update_root, PathWire};
use crate::dsol_deploy_tx::{ContractManifest, DSOL_CODE_BYTES_MAX, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES};
use crate::spend_frontier::Digest4;
use usdm_decider::dsol_cpu_air::{DsolCallProof, DsolStatement, ProvenCall};
use usdm_decider::dsol_vm::Effect;

/// ⭐ THE FOLD DOOR — every node, in canonical order, from the block's bytes and its own root: the stateless verdict, the fee
/// note's membership, the carrying block's epoch, the state leaf; then the leaf moves and the two notes are recorded.
/// Refusals are on the ITEM; the block stands. (D3 — a refused call still paying its fee — is L3: today a refused call's tags
/// all leave the step, so its fee note is not spent; the tx stamp paid is the cost of the attempt.)
pub fn apply_chain_dsol_call(node: &mut crate::node::Node, blob: &[u8], carrying_blue: Option<u64>) -> CallApply {
    let Some((crate::chain_object::Class::DsolCall, payload)) = crate::chain_object::unframe(blob) else {
        return CallApply::NotCall;
    };
    let Some(t) = DsolCallTx::decode(payload) else {
        return CallApply::Refused("the payload is not a call");
    };
    if let Some(why) = node.dsol_call_refusal(&t, crate::respend::MemberDoor::Fold, carrying_blue) {
        eprintln!("[fold-refuse] class=DsolCall why={why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
        return CallApply::Refused(why);
    }
    match node.apply_dsol_call_state(&t) {
        Some(root) => {
            let h = node.tip_height();
            node.record_note_payload(h, &t.fee.publisher_note);
            node.record_note_payload(h, &t.fee.change_note);
            CallApply::Applied(root)
        }
        None => CallApply::Refused("its contract-state path does not open this node's current root — the leaf moved; re-prove on the new state"),
    }
}

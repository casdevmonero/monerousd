// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::sat_delegation_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `sat_delegation_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::sat_delegation_tx::*;
use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// ⭐ THE FOLD-SIDE DOOR — run by `Node::apply_fold_class_object` at the carrying block's canonical fold on every node: the
/// carriers, the input's membership (Fold door), then the kind's rule against this node's validator set and the carrying
/// block's CHAIN TICK (`carrying_tick`, A-F60: a maturity is a time); the minted note and the change are credited only
/// after every rule passed.
pub fn apply_chain_sat_delegation(node: &mut crate::node::Node, blob: &[u8], carrying_tick: Option<u64>) -> DelegationApply {
    let Some((crate::chain_object::Class::SatDelegation, payload)) = crate::chain_object::unframe(blob) else {
        return DelegationApply::NotDelegation;
    };
    let Some(t) = SatDelegationTx::decode(payload) else {
        return DelegationApply::Refused("the payload is not a delegation");
    };
    if let Some(why) = node.sat_delegation_refusal(&t, crate::respend::MemberDoor::Fold, carrying_tick) {
        eprintln!("[sat-delegation] refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason only
        return DelegationApply::Refused(why);
    }
    if let Err(why) = node.sat_delegation_move(&t) {
        eprintln!("[sat-delegation] refused by the set: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason only
        return DelegationApply::Refused(why);
    }
    let h = node.tip_height();
    node.record_note_payload(h, &t.minted_note);
    node.record_note_payload(h, &t.change_note);
    if !t.yield_note.is_empty() {
        node.record_note_payload(h, &t.yield_note);
    }
    DelegationApply::Applied
}

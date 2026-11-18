// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::sat_set_aside` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `sat_set_aside.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::sat_set_aside::*;
use serde::{Deserialize, Serialize};

/// ⭐ THE FOLD-SIDE DOOR: the canonical bytes, the bound, and the once-only flag; then the note is recorded under its clue.
pub fn apply_chain_set_aside(node: &mut crate::node::Node, blob: &[u8]) -> SetAsideApply {
    let Some((crate::chain_object::Class::SatSetAside, payload)) = crate::chain_object::unframe(blob) else {
        return SetAsideApply::NotSetAside;
    };
    let Some(t) = SatSetAsideTx::decode(payload) else {
        return SetAsideApply::Refused("the payload is not a set-aside");
    };
    if let Some(why) = node.set_aside_refusal(&t) {
        eprintln!("[sat-set-aside] refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason only
        return SetAsideApply::Refused(why);
    }
    node.mark_set_aside_applied();
    let h = node.tip_height();
    node.record_note_payload(h, &t.note);
    SetAsideApply::Applied
}

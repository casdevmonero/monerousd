// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::pot_fill_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `pot_fill_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::pot_fill_tx::*;
use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// ⭐ THE FOLD-SIDE DOOR — the carriers, the membership (Fold door), then the node's door (tally, retire leg, the pot and the
/// floor); the SAT note and the change are credited only after every rule passed.
pub fn apply_chain_pot_fill(node: &mut crate::node::Node, blob: &[u8]) -> PotFillApply {
    let Some((crate::chain_object::Class::PotFill, payload)) = crate::chain_object::unframe(blob) else {
        return PotFillApply::NotPotFill;
    };
    let Some(t) = PotFillTx::decode(payload) else {
        return PotFillApply::Refused("the payload is not a pot fill");
    };
    if let Err(why) = node.pot_fill(&t, &crate::pqauth::MlDsaVerifier) {
        eprintln!("[pot-fill] refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason only
        return PotFillApply::Refused(why);
    }
    let h = node.tip_height();
    node.record_note_payload(h, &t.sat_note);
    node.record_note_payload(h, &t.change_note);
    PotFillApply::Filled
}

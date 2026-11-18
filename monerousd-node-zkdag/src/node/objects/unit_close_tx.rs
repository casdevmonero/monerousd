// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::unit_close_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `unit_close_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::unit_close_tx::*;
use crate::chain_object::{decode_exact, frame, Class};
use crate::debt_units::UnitTerms;
use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// ⭐ THE FOLD-SIDE UNIT CLOSE (`today` = the carrying block's day): every check before anything moves (the node's door), then
/// the change note is credited.
pub fn apply_chain_unit_close(node: &mut crate::node::Node, blob: &[u8], today: Option<u64>, verifier: &dyn crate::pqauth::PqVerifier) -> UnitCloseApply {
    let Some((Class::UnitClose, payload)) = crate::chain_object::unframe(blob) else {
        return UnitCloseApply::NotUnitClose;
    };
    let Some(today) = today else {
        return UnitCloseApply::Refused("no carrying block to date the close by");
    };
    let Some(t) = UnitCloseTx::decode(payload) else {
        return UnitCloseApply::Refused("not one canonical, bounded unit close");
    };
    if let Err(why) = node.unit_close(&t, today, verifier) {
        eprintln!("[unit-close] refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason only
        return UnitCloseApply::Refused(why);
    }
    let h = node.tip_height();
    node.record_note_payload(h, &t.change_note);
    UnitCloseApply::Closed
}

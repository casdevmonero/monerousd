// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::bond_yield_claim_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `bond_yield_claim_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::bond_yield_claim_tx::*;
use serde::{Deserialize, Serialize};

/// ⭐ THE FOLD-SIDE DOOR — the stateless half again, then the chain's own figures: the index is this fold's, the amount is
/// exactly the id's own-weight yield at it, and the bonders' pool covers it. The note is credited only after the accrual is
/// zeroed and the pool paid.
pub fn apply_chain_bond_yield_claim(node: &mut crate::node::Node, blob: &[u8]) -> ClaimApply {
    let Some((crate::chain_object::Class::BondYieldClaim, payload)) = crate::chain_object::unframe(blob) else {
        return ClaimApply::NotClaim;
    };
    let Some(t) = BondYieldClaimTx::decode(payload) else {
        return ClaimApply::Refused("the payload is not a yield claim");
    };
    if let Some(why) = node.bond_yield_claim_refusal(&t) {
        eprintln!("[bond-yield] refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason only
        return ClaimApply::Refused(why);
    }
    if let Err(why) = node.bond_yield_claim_move(&t) {
        eprintln!("[bond-yield] refused by the pool: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason only
        return ClaimApply::Refused(why);
    }
    let h = node.tip_height();
    node.record_note_payload(h, &t.note);
    ClaimApply::Applied
}

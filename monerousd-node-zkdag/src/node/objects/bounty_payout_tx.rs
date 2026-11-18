// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::bounty_payout_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `bounty_payout_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::bounty_payout_tx::*;
use serde::{Deserialize, Serialize};

/// ⭐ THE FOLD-SIDE DOOR — the signatures and carrier, then the chain's own figures: ≥ 2/3 of the bonded set signed, the amount
/// is within the cap and the buffer covers it. The note is credited only after the buffer paid.
pub fn apply_chain_bounty_payout(node: &mut crate::node::Node, blob: &[u8]) -> BountyApply {
    let Some((crate::chain_object::Class::BountyPayout, payload)) = crate::chain_object::unframe(blob) else {
        return BountyApply::NotBounty;
    };
    let Some(t) = BountyPayoutTx::decode(payload) else {
        return BountyApply::Refused("the payload is not a bounty payout");
    };
    if let Some(why) = node.bounty_payout_refusal(&t) {
        eprintln!("[bounty] refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason only
        return BountyApply::Refused(why);
    }
    if !node.bounty_payout_move(t.amount) {
        eprintln!("[bounty] refused by the buffer"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason only
        return BountyApply::Refused("the surplus buffer cannot cover the bounty");
    }
    let h = node.tip_height();
    node.record_note_payload(h, &t.note);
    BountyApply::Applied
}

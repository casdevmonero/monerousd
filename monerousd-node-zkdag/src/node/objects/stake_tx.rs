// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::stake_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `stake_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::stake_tx::*;
use crate::chain_object::{decode_exact, unframe, Class};
use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// ⭐⭐⭐ THE FOLD-SIDE DOOR — every node that folds the block runs every gate from the object's bytes against its OWN
/// state: the epoch of the block, its governance rate, its folded records, its committed supply and reserve.
pub fn apply_chain_stake(node: &mut crate::node::Node, blob: &[u8], block_ts_ms: u64) -> StakeApply {
    let Some((class, payload)) = unframe(blob) else {
        return StakeApply::NotStake;
    };
    if class != Class::YieldClaim {
        return StakeApply::NotStake;
    }
    let Some(d) = decode(payload) else {
        return StakeApply::NotStake;
    };
    match node.apply_stake_at_fold(&d, block_ts_ms) {
        Ok(()) => {
            // ⛔ NO RE-STAGE (2026-10-04, DB-274 P4b): the carrying block is the justification. Law: `Node::apply_fold_class_object`.
            StakeApply::Applied
        }
        Err(why) => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a FIXED reason — no amount, key, note or owner.
            eprintln!("[stake-apply] refused: {why}");
            StakeApply::Refused(why)
        }
    }
}

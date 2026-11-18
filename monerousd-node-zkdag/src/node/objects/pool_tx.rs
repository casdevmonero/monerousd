// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::pool_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `pool_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::pool_tx::*;
use crate::chain_object::{decode_exact, unframe, Class};
use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// The fold-side door: every node runs every gate from the object's bytes against its OWN pool words.
pub fn apply_chain_pool_deposit(node: &mut crate::node::Node, blob: &[u8]) -> PoolDepositApply {
    let Some((class, payload)) = unframe(blob) else {
        return PoolDepositApply::NotPoolDeposit;
    };
    if class != Class::PoolDeposit {
        return PoolDepositApply::NotPoolDeposit;
    }
    let Some(d) = decode(payload) else {
        return PoolDepositApply::NotPoolDeposit;
    };
    match node.apply_pool_deposit_at_fold(&d) {
        Ok(()) => {
            // ⛔ NO RE-STAGE (2026-10-04, DB-274 P4b): the carrying block is the justification. Law: `Node::apply_fold_class_object`.
            PoolDepositApply::Applied
        }
        Err(why) => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a FIXED reason — no amount, key, note or owner.
            eprintln!("[pool-apply] refused: {why}");
            PoolDepositApply::Refused(why)
        }
    }
}

/// The fold-side door.
pub fn apply_chain_pool_withdraw(node: &mut crate::node::Node, blob: &[u8]) -> PoolWithdrawApply {
    let Some((class, payload)) = unframe(blob) else {
        return PoolWithdrawApply::NotPoolWithdraw;
    };
    if class != Class::PoolWithdraw {
        return PoolWithdrawApply::NotPoolWithdraw;
    }
    let Some(d) = decode_withdraw(payload) else {
        return PoolWithdrawApply::NotPoolWithdraw;
    };
    match node.apply_pool_withdraw_at_fold(&d) {
        Ok(()) => {
            // ⛔ NO RE-STAGE (2026-10-04, DB-274 P4b): the carrying block is the justification. Law: `Node::apply_fold_class_object`.
            PoolWithdrawApply::Applied
        }
        Err(why) => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a FIXED reason — no amount, key, note or owner.
            eprintln!("[pool-apply] refused a withdrawal: {why}");
            PoolWithdrawApply::Refused(why)
        }
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::order_post_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `order_post_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::order_post_tx::*;
use crate::chain_object::Class;
use crate::mempool::PqTx;
use crate::order_book::{OrderWire, RestingOrder};

/// APPLY a block-carried order post — the single production path from a block's bytes to the book.
///
/// ⛔ FAIL-CLOSED AND NEVER FATAL. A blob of another class returns `NotOrderPost`; a malformed payload
/// or an offer the book refuses returns without touching anything. A bad object must never stop the
/// block that carried it from grafting — gates fail closed on the BAD ITEM, never on chain progress.
pub fn apply_chain_order_post(node: &mut crate::node::Node, blob: &[u8]) -> OrderPostApply {
    let Some((class, payload)) = crate::chain_object::unframe(blob) else {
        return OrderPostApply::NotOrderPost;
    };
    if class != Class::OrderPost {
        return OrderPostApply::NotOrderPost;
    }
    let Some(wire) = crate::chain_object::decode_exact::<OrderWire>(payload) else {
        return OrderPostApply::NotOrderPost;
    };
    // ⛔ THE BOOK'S OWN DOOR, not a second spelling of it: `post` re-verifies the maker half and
    // re-derives the level, so this object can put nothing in the book that its submitter could not.
    match node.post_order(wire.into_order()) {
        Ok(level) => OrderPostApply::Posted(level),
        Err(_) => {
            // Privacy: a branch only — no tag, amount, key, owner or level.
            eprintln!("[order-post] a block-carried offer was refused by this node's own book door.");
            OrderPostApply::Refused
        }
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::price_mark_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `price_mark_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::price_mark_tx::*;
use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// APPLY a block-carried price mark — the single production path from a block's bytes to the door.
///
/// ROOT-LAYER: this is the seam where a block's bytes become a class-specific action, exactly where
/// [`crate::node::objects::wrapped_asset_tx::apply_chain_wrapped_asset_register`] sits for its own class; the mark itself
/// is set one layer down, inside [`crate::peg::PegLedger::mark_price_attested`], which is the only code that
/// may move an asset's price. Deciding a mark anywhere else — in an RPC handler, in a wallet — would be a
/// second encoding of the same thing that could reach a different verdict on the same bytes, which is the
/// defect this class exists to remove. A price read from a socket is a price the chain never set.
///
/// FAIL-CLOSED: the class is READ, never guessed; a blob of another class returns `NotPriceMark` and changes
/// nothing. Everything that decides whether the mark moves — the >=2/3 bonded tally over each attestor's OWN
/// signed price, and the monotone-epoch check — happens inside the door, so a forged object reaching this
/// function is simply refused and the block still grafts.
pub fn apply_chain_price_mark(
    node: &mut crate::node::Node,
    blob: &[u8],
    verifier: &dyn crate::pqauth::PqVerifier,
) -> PriceMarkApply {
    let Some((class, payload)) = unframe(blob) else {
        return PriceMarkApply::NotPriceMark;
    };
    if class != Class::PriceMark {
        return PriceMarkApply::NotPriceMark;
    }
    let Some((h, quotes)) = decode(payload) else {
        return PriceMarkApply::NotPriceMark;
    };
    match node.mark_price_attested(h.epoch_id, h.asset_id, &quotes, verifier) {
        crate::peg::PegOutcome::PriceMarked(p) => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a price mark is chain-public by definition (every node must stand
            // on the same one to agree on solvency); epoch, asset id and price only — no amount, owner or key.
            eprintln!("[price-mark] applied: epoch {} asset {} price {}", h.epoch_id, h.asset_id, p);
            PriceMarkApply::Marked(p)
        }
        other => PriceMarkApply::Refused(other),
    }
}

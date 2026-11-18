// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::liquidation_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `liquidation_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::liquidation_tx::*;
use serde::{Deserialize, Serialize};
use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;

/// ⭐ APPLY a block-carried liquidation — the single production path from a block's bytes to the door.
///
/// ROOT-LAYER: this is the seam where a block's bytes become a class-specific action, which is exactly where
/// [`crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit`] sits for its own class; the value itself is produced
/// one layer down, inside the door, which is the only code that may move a PSM's committed pair. Deciding a
/// liquidation anywhere else — in the mempool, in an RPC handler, in a wallet — would be a second encoding of
/// a position close that could reach a different verdict from the door on the same bytes.
/// MEASURED: `grep -c liquidate_position src/node.rs` 0 -> 1 and `grep -c liquidate_confidential src/node.rs`
/// 0 -> 1; before this module the door had no production caller at all, so no block could ever reach it.
/// MUST-STAY-GREEN: `apply_chain_bridge_credit`'s own pins (this is additive and shares only the framing
/// helpers), the three door pins in `peg.rs`, and the crash simulation in `crate::liquidation`.
///
/// FAIL-CLOSED: the class is READ, never guessed; a blob of another class, or a payload that is not an
/// in-bounds liquidation, returns `NotLiquidation` and changes nothing. Everything that decides whether value
/// moves — the >=2/3 bonded tally over the domain-separated message, and the WHIR carrier against THIS node's
/// own persisted digests — happens inside [`crate::node::Node::liquidate_position`] and the door beneath it,
/// so a forged object reaching this function is simply refused.
pub fn apply_chain_liquidation(
    node: &mut crate::node::Node,
    blob: &[u8],
    verifier: &dyn crate::pqauth::PqVerifier,
) -> LiquidationApply {
    let Some((class, payload)) = unframe(blob) else {
        return LiquidationApply::NotLiquidation;
    };
    if class != Class::Liquidation {
        return LiquidationApply::NotLiquidation;
    }
    let Some((h, legs, attestors)) = decode(payload) else {
        return LiquidationApply::NotLiquidation;
    };
    let outcome = node.liquidate_position(&h, &legs, verifier, &attestors);
    match outcome {
        crate::peg::PegOutcome::Liquidated => LiquidationApply::Closed,
        other => LiquidationApply::Refused(other),
    }
}

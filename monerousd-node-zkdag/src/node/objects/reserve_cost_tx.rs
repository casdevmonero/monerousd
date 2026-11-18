// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::reserve_cost_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `reserve_cost_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::reserve_cost_tx::*;
use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// APPLY a block-carried cost — the single production path from a block's bytes to the door
/// (`Node::apply_reserve_cost` → `PegLedger::reserve_cost`). FAIL-CLOSED on the item: a blob of another class or an
/// out-of-bounds payload is `NotCost`; a forged or stale cost is refused by the door and the block still grafts.
pub fn apply_chain_reserve_cost(node: &mut crate::node::Node, blob: &[u8], verifier: &dyn crate::pqauth::PqVerifier) -> CostApply {
    let Some((class, payload)) = unframe(blob) else { return CostApply::NotCost };
    if class != Class::ReserveCost {
        return CostApply::NotCost;
    }
    let Some(cost) = decode(payload) else { return CostApply::NotCost };
    match node.apply_reserve_cost(&cost, verifier) {
        crate::peg::PegOutcome::ConfidentialRedeemed => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a ledger id and a foreign miner fee — both public (the fee on its own chain).
            eprintln!("[reserve-cost] booked: ledger {:#x} fell by a foreign fee of {}", cost.header.ledger, cost.header.cost);
            CostApply::Booked
        }
        other => {
            eprintln!("[reserve-cost] refused: {other:?}");
            CostApply::Refused(other)
        }
    }
}

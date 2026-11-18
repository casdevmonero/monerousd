// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::vault_rebalance_tx` that moves the node: its apply at the fold, kept
//! here (as every class's node half is, lane dcash 2026-11-11) so the object module never reaches up into the node.

#![allow(unused_imports)]
use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::vault_rebalance_tx::*;

/// APPLY a block-carried rebalance step — the single production path from a block's bytes to the doors
/// (`Node::apply_vault_rebalance` → `PegLedger::vault_carve` / `vault_take` / `vault_cancel`), at the carrying block's
/// CHAIN TICK (`carrying_tick`, A-F60: a carve records it in the slot and a cancel's wait — a time — is judged against
/// it, so a step with no carrying block to place it is refused). FAIL-CLOSED on the item: a blob of another class or
/// an out-of-bounds payload is `NotRebalance`; a forged or stale step is refused by its door and the block still grafts.
pub fn apply_chain_vault_rebalance(node: &mut crate::node::Node, blob: &[u8], carrying_tick: Option<u64>, verifier: &dyn crate::pqauth::PqVerifier) -> RebalanceApply {
    let Some((class, payload)) = unframe(blob) else { return RebalanceApply::NotRebalance };
    if class != Class::VaultRebalance {
        return RebalanceApply::NotRebalance;
    }
    let Some(r) = decode(payload) else { return RebalanceApply::NotRebalance };
    let Some(tick) = carrying_tick else { return RebalanceApply::Refused(crate::peg::PegOutcome::BadRequest) };
    match node.apply_vault_rebalance(&r, tick, verifier) {
        crate::peg::PegOutcome::ConfidentialMinted => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a step name, a vault index and a leg count — public chain structure; no
            // amount, key or owner.
            eprintln!("[vault-rebalance] applied: {:?} of {} ledger(s)", r.header, r.legs.len());
            RebalanceApply::Moved
        }
        other => {
            eprintln!("[vault-rebalance] refused: {other:?}");
            RebalanceApply::Refused(other)
        }
    }
}

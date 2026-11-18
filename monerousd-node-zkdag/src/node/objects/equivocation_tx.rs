// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::equivocation_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `equivocation_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::equivocation_tx::*;
use crate::chain_object::{decode_exact, unframe, Class};
use crate::pqauth::PqVerifier;

/// ⭐⭐⭐ THE GRAFT-SIDE DOOR — every node that grafts a block carrying the evidence verifies it from the object's own
/// bytes and slashes the voter if it is bonded here. A replay finds the voter removed and barred, so it is a no-op.
pub fn apply_chain_equivocation(
    node: &mut crate::node::Node,
    blob: &[u8],
    v: &dyn PqVerifier,
) -> EquivocationApply {
    let Some((class, payload)) = unframe(blob) else {
        return EquivocationApply::NotEquivocation;
    };
    if class != Class::Equivocation {
        return EquivocationApply::NotEquivocation;
    }
    let Some(voter) = proves_equivocation(payload, v) else {
        return EquivocationApply::Refused("the evidence does not prove an equivocation by one key");
    };
    match node.apply_slash_no_loss(voter) { // §22 5: an equivocation loses no money — the operator's own bond only
        Some(burned) => EquivocationApply::Slashed(burned),
        None => EquivocationApply::Refused("the voter is not bonded here (already slashed, or never bonded)"),
    }
}

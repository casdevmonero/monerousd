// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::epoch_fraud_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `epoch_fraud_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::epoch_fraud_tx::*;
use crate::chain_object::{unframe, Class};
use crate::epoch_release::FraudProof;

/// ⭐⭐⭐ THE BOND-STEP DOOR — every node applying the carrying block's bond lane checks the proof against its own epoch-key
/// ledger and slashes the dealer if it is bonded here. A replay finds the dealer slashed and barred: a no-op.
pub fn apply_chain_epoch_fraud(node: &mut crate::node::Node, blob: &[u8]) -> FraudApply {
    let Some((class, payload)) = unframe(blob) else { return FraudApply::NotFraud };
    if class != Class::EpochKeyFraud {
        return FraudApply::NotFraud;
    }
    let Some(p) = decode(payload) else {
        return FraudApply::Refused("the evidence is not one canonical, bounded fraud proof");
    };
    let holds = node.peg().epoch_keys().epochs.get(&p.epoch).is_some_and(|r| crate::epoch_release::fraud_proof_holds(r, &p));
    if !holds {
        return FraudApply::Refused("the proof does not convict its dealer against this node's epoch-key ledger");
    }
    match node.apply_slash_no_loss(p.dealer) { // §22 5: a faulty deal loses no money — the operator's own bond only
        Some(burned) => FraudApply::Slashed(burned),
        None => FraudApply::Refused("the dealer is not bonded here (already slashed, or never bonded)"),
    }
}

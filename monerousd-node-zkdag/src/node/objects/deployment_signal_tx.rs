// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::deployment_signal_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `deployment_signal_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::deployment_signal_tx::*;
use serde::{Deserialize, Serialize};

/// ⭐ THE FOLD-SIDE DOOR: the signature, a live custody seat, then the ledger counts the signal for the open window.
pub fn apply_chain_deployment_signal(node: &mut crate::node::Node, blob: &[u8]) -> SignalApply {
    let Some((crate::chain_object::Class::DeploymentSignal, payload)) = crate::chain_object::unframe(blob) else {
        return SignalApply::NotSignal;
    };
    let Some(t) = DeploymentSignalTx::decode(payload) else {
        return SignalApply::Refused("the payload is not a deployment signal");
    };
    if let Some(why) = node.deployment_signal_refusal(&t) {
        return SignalApply::Refused(why);
    }
    node.apply_deployment_signal(&t);
    SignalApply::Applied
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::theft_repayment_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `theft_repayment_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::theft_repayment_tx::*;
use serde::{Deserialize, Serialize};
use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use crate::spend_frontier::Digest4;

/// ⭐ APPLY a block-carried repayment — the one production path from a block's bytes to the door.
pub fn apply_chain_theft_repayment(node: &mut crate::node::Node, blob: &[u8], verifier: &dyn crate::pqauth::PqVerifier) -> TheftRepayApply {
    let Some((Class::TheftRepayment, payload)) = unframe(blob) else {
        return TheftRepayApply::NotRepayment;
    };
    let Some((h, legs, attestors)) = decode(payload) else {
        return TheftRepayApply::NotRepayment;
    };
    match node.repay_theft(&h, &legs, verifier, &attestors) {
        crate::peg::PegOutcome::TheftRepaid => TheftRepayApply::Repaid,
        other => TheftRepayApply::Refused(other),
    }
}

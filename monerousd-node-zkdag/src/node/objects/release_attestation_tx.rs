// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::release_attestation_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `release_attestation_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::release_attestation_tx::*;
use serde::{Deserialize, Serialize};

/// ⭐ THE FOLD-SIDE DOOR: authorised, then the registry keeps it as the builder's latest attestation.
pub fn apply_chain_release_attestation(node: &mut crate::node::Node, blob: &[u8]) -> AttestationApply {
    let Some((crate::chain_object::Class::ReleaseAttestation, payload)) = crate::chain_object::unframe(blob) else {
        return AttestationApply::NotAttestation;
    };
    let Some(t) = ReleaseAttestationTx::decode(payload) else {
        return AttestationApply::Refused("the payload is not a release attestation");
    };
    if !t.authorised() {
        return AttestationApply::Refused("not signed by a builder of this release's set");
    }
    node.record_release_attestation(&t);
    AttestationApply::Applied
}

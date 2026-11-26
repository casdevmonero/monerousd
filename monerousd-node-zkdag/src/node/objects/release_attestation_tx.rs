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
    // ⭐ A-F114 — A BUILDER'S ATTESTATIONS ONLY MOVE FORWARD (from the network upgrade, `params::CANON_LIVE`). The constant
    // chain holds no set of seen attestations, and the record keeps each builder's latest by overwriting, so a producer
    // re-carrying a builder's OLD attestation past the window would roll that builder's attested release back. The record
    // is chained to its own state instead: a version not newer than the one held changes nothing (the same one) or is
    // refused (an older one). BORROWED: a monotone version per signer (TUF's snapshot and timestamp roles refuse a
    // rollback). cons: a builder cannot attest an older version again; a rollback ships as a new, higher version.
    if crate::params::canon_live() {
        if let Some(held) = node.peg().release_attestations().get(&t.builder()) {
            match release_version_order(&t.version, &held.version) {
                Some(std::cmp::Ordering::Greater) => {}
                Some(std::cmp::Ordering::Equal) if held == &t => return AttestationApply::Applied,
                _ => return AttestationApply::Refused("not newer than this builder's attested release"),
            }
        }
    }
    node.record_release_attestation(&t);
    AttestationApply::Applied
}

/// The order of two dotted release versions (`0.3.4` against `0.3.10`: numeric, part by part, a missing part reading 0);
/// `None` when either is not dotted digits (an unreadable version is never "newer").
#[must_use]
pub fn release_version_order(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    let parse = |v: &str| -> Option<Vec<u64>> {
        let v = v.trim().trim_start_matches('v');
        if v.is_empty() {
            return None;
        }
        v.split('.').map(|p| p.parse::<u64>().ok()).collect()
    };
    let (mut x, mut y) = (parse(a)?, parse(b)?);
    let n = x.len().max(y.len());
    x.resize(n, 0);
    y.resize(n, 0);
    Some(x.cmp(&y))
}

#[cfg(test)]
mod a_f114_tests {
    use super::release_version_order;
    use std::cmp::Ordering::{Equal, Greater, Less};

    /// A builder's attestations only move forward: numeric part by part, a missing part reading 0, an unreadable version never
    /// ordered (so never "newer").
    #[test]
    fn release_versions_order_numerically_and_an_unreadable_one_never_orders() {
        assert_eq!(release_version_order("0.3.10", "0.3.4"), Some(Greater));
        assert_eq!(release_version_order("0.3.4", "0.3.10"), Some(Less));
        assert_eq!(release_version_order("v0.3", "0.3.0"), Some(Equal));
        assert_eq!(release_version_order("0.3.x", "0.3.4"), None);
        assert_eq!(release_version_order("", "0.3.4"), None);
    }
}

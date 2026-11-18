// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::vault_merge_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `vault_merge_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::vault_merge_tx::*;
use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// APPLY a block-carried merge — the single production path from a block's bytes to the door
/// (`Node::apply_vault_merge` → `PegLedger::vault_merge`). FAIL-CLOSED on the item: a blob of another class or an
/// out-of-bounds payload is `NotMerge`; a forged or stale merge is refused by the door and the block still grafts.
pub fn apply_chain_vault_merge(node: &mut crate::node::Node, blob: &[u8], verifier: &dyn crate::pqauth::PqVerifier) -> MergeApply {
    let Some((class, payload)) = unframe(blob) else { return MergeApply::NotMerge };
    if class != Class::VaultMerge {
        return MergeApply::NotMerge;
    }
    let Some(merge) = decode(payload) else { return MergeApply::NotMerge };
    match node.apply_vault_merge(&merge, verifier) {
        crate::peg::PegOutcome::ConfidentialMinted => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: two vault indexes — public chain structure; no amount, key or owner.
            eprintln!("[vault-merge] applied: vault {} merged into vault {}", merge.header.from, merge.header.into);
            MergeApply::Merged
        }
        other => {
            eprintln!("[vault-merge] refused: {other:?}");
            MergeApply::Refused(other)
        }
    }
}

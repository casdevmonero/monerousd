// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::vault_key_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `vault_key_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::vault_key_tx::*;
use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// APPLY a block-carried key statement — the single production path from a block's bytes to the doors
/// (`Node::apply_vault_key` → `PegLedger::vault_key_take` / `vault_key_retire`), at the carrying block's CHAIN TICK
/// (`carrying_tick`, A-F60: the record's dates are times; a statement with no carrying block to place it is refused).
/// FAIL-CLOSED on the item: a blob of another class or an out-of-bounds payload is `NotKey`; a forged or stale
/// statement is refused by the door and the block still grafts.
pub fn apply_chain_vault_key(node: &mut crate::node::Node, blob: &[u8], carrying_tick: Option<u64>, verifier: &dyn crate::pqauth::PqVerifier) -> KeyApply {
    let Some((class, payload)) = unframe(blob) else { return KeyApply::NotKey };
    if class != Class::VaultKey {
        return KeyApply::NotKey;
    }
    let Some(key) = decode(payload) else { return KeyApply::NotKey };
    let Some(tick) = carrying_tick else { return KeyApply::Refused(crate::peg::PegOutcome::BadRequest) };
    match node.apply_vault_key(&key, tick, verifier) {
        crate::peg::PegOutcome::ConfidentialMinted => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a vault index — public chain structure; no member id, address or amount.
            eprintln!("[vault-key] vault {} took the key of its members", key.header.vault());
            KeyApply::Taken
        }
        crate::peg::PegOutcome::ConfidentialRedeemed => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a vault index — public chain structure.
            eprintln!("[vault-key] vault {} retired a key it had replaced", key.header.vault());
            KeyApply::Retired
        }
        other => {
            eprintln!("[vault-key] refused: {other:?}");
            KeyApply::Refused(other)
        }
    }
}

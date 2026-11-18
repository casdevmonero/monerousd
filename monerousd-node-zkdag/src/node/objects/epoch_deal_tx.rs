// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::epoch_deal_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `epoch_deal_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::epoch_deal_tx::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// ⭐ THE FOLD-SIDE DOOR: the signature, then the ledger's rule, then the sum — and this custodian captures its own share.
pub fn apply_chain_epoch_key_deal(node: &mut crate::node::Node, blob: &[u8]) -> DealApply {
    let Some((crate::chain_object::Class::EpochKeyDeal, payload)) = crate::chain_object::unframe(blob) else {
        return DealApply::NotDeal;
    };
    let Some(t) = EpochKeyDealTx::decode(payload) else {
        return DealApply::Refused("the payload is not an epoch-key deal");
    };
    if let Some(why) = node.epoch_key_deal_refusal(&t) {
        return DealApply::Refused(why);
    }
    node.apply_epoch_key_deal(&t);
    DealApply::Applied
}

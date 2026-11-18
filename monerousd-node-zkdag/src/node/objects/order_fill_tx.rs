// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::order_fill_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `order_fill_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::order_fill_tx::*;
use serde::{Deserialize, Serialize};
use usdm_decider::whir_rec_block::{MakerHalfPublic, OrderTerms, TakerHalfPublic};

/// ⛔⛔⛔ DB-368 — A BLOCK-CARRIED FILL IS JUDGED AT ITS BLOCK'S CANONICAL FOLD BY THE ONE FILL RULE
/// (docs/DB-368-A-CARRIED-FILL-IS-JUDGED-BY-THE-FILL-RULE.md).
///
/// A peer never runs the publisher door for a carried fill (DB-224 skips the fill arm at graft). Its notes were
/// justified at graft by `chain_object::admissible`, which re-verifies the composed proof and nothing else. MEASURED on
/// the baseline (`dex_cross_party_scenarios::a_peer_does_not_credit_a_fill_whose_inputs_never_existed_when_a_rogue_producer_
/// carries_it`): a rogue producer's fill with a SUBSTITUTED payout was credited on the peer, and so were 3/3 notes of a
/// fill whose inputs NEVER EXISTED.
///
/// Here every node runs `Node::order_fill_refusal`, the same function the publisher runs, at `MemberDoor::Fold`, with the
/// carrying block's blue score as the expiry height. A refusal makes the fold step strip the fill's three notes from the
/// record and un-admit its two burns (`objects_decide_at_fold`). An invalid fill spends nothing and credits nothing:
/// Zcash's shape.
///
/// §9.6:
/// - (1) the header grind was verified at the block doors;
/// - (2) the composed proof and both membership carriers are re-verified HERE against this node's own records;
/// - (3) payout binding + the conserving proof + existing inputs ⇒ no free value;
/// - (4) a replay is refused by the nullifier set (the respend loser is skipped before this runs);
/// - (5) bounded: one composed verify, two one-step membership verifies, three 32-byte compares per fill;
/// - (6) every publisher check runs through the one function. The publisher-only pool-claim and local spent verdict
///   are its own liveness courtesies; here the SET decides.
///
/// cons: one extra composed-proof verify and two membership verifies per carried fill per node, at the fold. No bytes,
/// no storage. A fill whose carrying block passes the order's expiry is refused (nothing burns, nothing credits).
pub fn apply_chain_fill_at_fold(node: &crate::node::Node, blob: &[u8], carrying_score: Option<u64>) -> FillFoldApply {
    let Some((class, payload)) = crate::chain_object::unframe(blob) else {
        return FillFoldApply::NotFill;
    };
    if class != crate::chain_object::Class::OrderFill {
        return FillFoldApply::NotFill;
    }
    let Some(f) = OrderFillTx::decode(payload) else {
        return FillFoldApply::Malformed;
    };
    let Some(height) = carrying_score else {
        return FillFoldApply::ScoreUnknown;
    };
    match node.order_fill_refusal(&f, crate::respend::MemberDoor::Fold, height) {
        None => FillFoldApply::Settled,
        Some(why) => {
            // DIGITAL-CASH-PRIVACY-REVIEWED: the refusal's variant name only — no tag, commitment, amount, key or owner.
            eprintln!("[fill-fold] ⛔ DB-368: a carried fill was refused at its fold ({why:?}); its notes leave the record");
            FillFoldApply::Refused(why)
        }
    }
}

/// ⭐ THE GRAFT-SIDE DOOR — one call, so no node can be tempted to apply a DEX object its own way.
///
/// Every node that admits a block runs THIS function over the block's transaction blobs, so every node
/// applies the same bytes through the same gates and reaches the same book and the same burns. That is the
/// half the double-fill was missing: acceptance published, and applied identically everywhere.
///
/// It is deliberately total and deliberately dumb: bytes that are not a DEX object are `NotDex` and are
/// left entirely alone, so this can be called on every transaction without a type tag on the wire.
pub fn apply_chain_dex_object(node: &mut crate::node::Node, blob: &[u8]) -> DexApply {
    // ⛔ THE CLASS IS READ, NEVER GUESSED. This used to try each decode in turn and rely on "a fill cannot
    // be mistaken for an order" — true between these two types, and false the moment the mempool learned to
    // carry a third. A bare `postcard` decode is not injective across types, so the frame decides.
    let Some((class, payload)) = crate::chain_object::unframe(blob) else {
        return DexApply::NotDex;
    };
    if class == crate::chain_object::Class::OrderFill {
        let Some(f) = OrderFillTx::decode(payload) else {
            return DexApply::NotDex;
        };
        let (t, maker, taker) = (f.terms(), f.maker(), f.taker());
        // DB-150: the two membership cross-binds ride the object, so the apply re-checks them on every
        // node exactly as the submitting node did. An empty bind is no bind and the fill is refused.
        let maker_bind = (!f.maker_membership_carrier.is_empty() && !f.maker_membership_tip.is_empty())
            .then(|| (f.maker_membership_carrier.clone(), f.maker_membership_tip.clone()));
        let taker_bind = (!f.taker_membership_carrier.is_empty() && !f.taker_membership_tip.is_empty())
            .then(|| (f.taker_membership_carrier.clone(), f.taker_membership_tip.clone()));
        return DexApply::Fill(node.execute_order_fill(
            &f.maker_bytes,
            &maker,
            &f.taker_bytes,
            &taker,
            &t,
            &f.notes[0],
            &f.notes[1],
            &f.notes[2],
            f.owner_clues.clone(),
            [maker_bind, taker_bind],
        ));
    }
    if class == crate::chain_object::Class::OrderPost {
        let Some(w) = crate::chain_object::decode_exact::<crate::order_book::OrderWire>(payload) else {
            return DexApply::NotDex;
        };
        return match node.post_order(w.into_order()) {
            Ok(level) => DexApply::OrderRested(level),
            Err(e) => DexApply::OrderRefused(e),
        };
    }
    DexApply::NotDex
}

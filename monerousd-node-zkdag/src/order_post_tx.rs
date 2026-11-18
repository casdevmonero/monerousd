// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ A RESTING ORDER IS A CHAIN OBJECT — the half `Class::OrderPost` was declared for and never given.
//!
//! WHAT WAS WRONG. `POST /post_order` called `Node::post_order`, which mutates THIS node's book and
//! nothing else. `Class::OrderPost = 2` has existed since the class enum was written, with an
//! `admissible` arm that decodes an [`crate::order_book::OrderWire`] — but NOTHING ever framed one,
//! NOTHING ever published one, and no apply seam ever applied one. The book was replicated by epidemic
//! re-flood (`OrderBook::reflood_page`) alone: best-effort gossip, not consensus.
//!
//! WHY THAT IS A FUNDS DEFECT AND NOT A UX ONE. A resting order is a maker's standing commitment to
//! trade a locked lot. If node A holds it and node B does not — or B retired it and A did not — then the
//! same lot can be filled on both, which is precisely the shape MEASURED on 2026-09-03: *two honest
//! nodes each self-verified the SAME DEX fill, both were right to accept it, and the maker's lot paid
//! out TWICE.* Self-verification decides whether a node ACCEPTS a transition; only inclusion in a block
//! decides whether it HAPPENED. A book entry that never rode a block never happened.
//!
//! ⛔ THE CENSUS COULD NOT SEE IT EITHER, which is why it survived. The I-CP refutation
//! `icp_order_book_half_fires_when_a_book_entry_is_not_derivable_from_the_chain` exists to fire exactly
//! here, and it could not: a node fed ONLY the blocks derives no book at all, so `cold_peer_verdict`
//! had nothing to disagree with and returned Ok. A detector with nothing to compare against is silent
//! in the same way a clean tree is.
//!
//! WHAT THIS MODULE IS. The producer and the apply seam, in the shape every other carried class uses
//! ([`crate::price_mark_tx`], [`crate::unbond_tx`]): frame the offer as a `Class::OrderPost`, publish it
//! from the route as an ordinary pooled-and-GOSSIPED transaction, and apply it at the block-apply seam
//! on EVERY node through the book's own door.
//!
//! ⛔ NOTHING HERE IS TRUSTED. `OrderWire::into_order` rebuilds the offer and hands it to
//! `OrderBook::post`, which re-verifies the maker's half and re-derives the level — the identical gate
//! the submitting node applied. A forged object applied here puts nothing in the book.
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: this carries the SAME `OrderWire` bytes the re-flood lane already
//! gossips in the clear, to the same peers, with no field added and none revealed earlier. The terms of
//! a resting offer are public by construction — a book nobody can read is a book nobody can fill. No
//! note key, owner, scan key or amount beyond the offer's own published terms appears, and the object
//! names no which-item question.

use crate::chain_object::Class;
use crate::mempool::PqTx;
use crate::order_book::{OrderWire, RestingOrder};

/// FRAME one resting offer as the chain object its class was declared for.
#[must_use]
pub fn encode(order: &RestingOrder) -> Vec<u8> {
    let payload = postcard::to_allocvec(&OrderWire::of(order)).unwrap_or_default();
    crate::chain_object::frame(Class::OrderPost, &payload)
}

/// The publishable transaction — an ordinary pooled object, so it gossips and a block carries it.
///
/// ⛔ THE ANTI-SPAM STAMP IS GROUND HERE, for the measured reason `wrapped_asset_tx::as_pq_tx`
/// records: a bare blob with `pow_stamp 0` is refused at the door and at the floor, so a publishing
/// route that skipped it would emit objects every node refuses.
#[must_use]
pub fn as_pq_tx(order: &RestingOrder, stamp_bits: u32) -> PqTx {
    let blob = encode(order);
    let mut tx = PqTx {
        clock_ms: 0,
        id: crate::mempool::PqTx::content_id(&blob),
        weight: blob.len() as u32,
        blob,
        nullifiers: Vec::new(),
        pow_stamp: 0,
        note_clues: Vec::new(),
        account_targets: Vec::new(),
        output_notes: Vec::new(),
        stake_notes: Vec::new(),
        bond_notes: Vec::new(),
        nullifier_witnesses: Vec::new(),
        nullifier_absence: Vec::new(),
        membership_carrier: Vec::new(),
        membership_leaf_commit: [0u8; 32],
        membership_tip: Vec::new(),
        membership_folded_through: 0,
        spend_or_decoy: Vec::new(),
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
    };
    // Grind the anti-spam stamp exactly as a real submit does — the measured reason
    // [`crate::wrapped_asset_tx::as_pq_tx`] records: a bare blob with `pow_stamp 0` is refused at the door
    // and at the floor, so a publishing route that skipped this would emit objects every node refuses.
    // Bounded BY CONSTRUCTION: 2^stamp_bits expected tries (~256 at the live 8-bit floor).
    let mut s = 0u64;
    loop {
        tx.pow_stamp = s;
        if tx.stamp_work() >= stamp_bits {
            break;
        }
        s = s.wrapping_add(1);
    }
    tx
}

/// What the apply seam did with one blob.
#[derive(Debug, PartialEq, Eq)]
pub enum OrderPostApply {
    /// The blob is not a framed order post — nothing to do, and nothing was touched.
    NotOrderPost,
    /// The book took it at this level.
    Posted(u32),
    /// The book's own door refused it. Nothing was touched, and the block still grafts.
    Refused,
}


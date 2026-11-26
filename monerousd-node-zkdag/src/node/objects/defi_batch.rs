// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::defi_batch` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `defi_batch.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::defi_batch::*;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use usdm_decider::br15_audit as ba;
use usdm_decider::hiding_decider::Fa4;

/// ⭐ THE ONE FOLD DOOR of the four DeFi classes: each object's verdict against THIS node's own book (and, for the order and
/// the claim, its member leg at the Fold door), then the book's move. A refused object's carried notes leave the block's row
/// (DB-274 P4b) and its nullifiers retire nothing — fail-closed on the item, never on the chain.
/// `chain_ms` is the carrying block's chain clock (`Node::chain_time_ms_at`): it stamps a batch's open (`DefiBook::opened_ms`)
/// whenever an apply opens one, and judges an expiry.
pub fn apply_chain_defi(node: &mut crate::node::Node, blob: &[u8], block_ts: u64, chain_ms: u64, carrying_score: Option<u64>) -> DefiApply {
    let stamp = |book: &mut DefiBook, before: (u64, u64)| {
        if (book.batch, book.opened_at) != before || book.opened_ms == 0 {
            book.opened_ms = chain_ms;
        }
    };
    use crate::chain_object::Class;
    let Some((class, payload)) = crate::chain_object::unframe(blob) else {
        return DefiApply::NotDefi;
    };
    // a batch's clock is the carrying block's blue score (the same on every node); an object whose block has none waits nowhere —
    // it is refused (the order, settlement or expiry is re-published into a block that has one)
    let score = || carrying_score.ok_or("the carrying block's blue score is not known at this fold step");
    let verdict: Result<(), &'static str> = match class {
        // ⭐ spec §18.12: an order or a claim reaches the chain only inside its batch's slots — a lone one would show a count
        Class::DefiOrder | Class::DefiClaim => Err("an order or a claim rides only in its batch's slots (spec §18.12)"),
        Class::DefiSlots => (|| {
            let t = DefiSlotsTx::decode(payload).ok_or("not the batch's slots")?;
            let mut book = node.peg().defi_book_of(t.pair).ok_or("the slots name no pair")?.clone();
            t.verdict(&book, score()?)?;
            // ⭐ A-F26 (2026-11-11): every slot of one batch must name ONE anchor — a partition by anchor tells real slots
            // from covers. The door derives the one allowed anchor from the slots and refuses any that differs.
            let mut batch_anchor: Option<crate::spend_frontier::Digest4> = None;
            let check_anchor = |tuple: &[u8], batch_anchor: &mut Option<crate::spend_frontier::Digest4>| -> Result<(), &'static str> {
                let t = crate::member_transition::read_tuple(tuple).ok_or("a slot's tuple does not decode")?;
                match *batch_anchor {
                    None => { *batch_anchor = Some(t.anchor); Ok(()) }
                    Some(a) if a == t.anchor => Ok(()),
                    Some(_) => Err("a slot names a different anchor than the batch's first slot (A-F26: every slot of one batch names one anchor)"),
                }
            };
            // ⭐ A-F114: under the constant chain a slot carries no member leg: its leg is its wrapper, judged per tag where the
            // record takes its position (`Node::canon_tag_spent`, the object's `Leg` roles); a member leg is one encoding too
            // many. A-F26's one-anchor rule becomes one END per batch, judged where the wrappers are seen
            // (`Node::canon_object_absent`).
            let canon = crate::params::canon_live();
            if canon
                && (t.orders.iter().any(|o| !o.member_tuple.is_empty() || !o.member_carrier.is_empty())
                    || t.claims.iter().any(|c| !c.member_tuple.is_empty() || !c.member_carrier.is_empty()))
            {
                return Err("a slot carries a member leg under the constant chain (its wrapper is its leg)");
            }
            for o in t.orders.iter().filter(|_| !canon) {
                check_anchor(&o.member_tuple, &mut batch_anchor)?;
                if !node.defi_member_leg(&o.member_carrier, &o.member_tuple, o.leaf_commit, o.nullifier) {
                    return Err("an order slot's note is not under an anchor this node's fold produced");
                }
            }
            for c in t.claims.iter().filter(|_| !canon) {
                check_anchor(&c.member_tuple, &mut batch_anchor)?;
                if !node.defi_member_leg(&c.member_carrier, &c.member_tuple, c.leaf_commit, c.nullifier) {
                    return Err("a claim slot's leaf is not under an anchor this node's fold produced");
                }
            }
            let first = apply_slots(&mut book, &t);
            if book.opened_ms == 0 {
                book.opened_ms = chain_ms; // a batch opened at launch: its first object starts its clock
            }
            let pair = t.pair;
            *node.defi_book_mut(pair).ok_or("the slots name no pair")? = book;
            for (k, o) in t.orders.into_iter().enumerate() {
                let index = u32::try_from(first + k).map_err(|_| "a slot index past u32")?;
                node.push_defi_event(pair, crate::defi_lane::DefiEvent::Order { batch: t.batch, index, epoch: o.epoch, epoch_ct: o.epoch_ct, sealed: o.sealed });
            }
            Ok(())
        })(),
        Class::DefiSettle => (|| {
            let t = DefiSettleTx::decode(payload).ok_or("not a settlement")?;
            let mut book = node.peg().defi_book_of(t.pair).ok_or("the settlement names no pair")?.clone();
            let step = t.chunk_verdict(&book)?;
            let before = (book.batch, book.opened_at);
            apply_settlement(&mut book, &t, score()?, block_ts);
            stamp(&mut book, before);
            *node.defi_book_mut(t.pair).ok_or("the settlement names no pair")? = book;
            if matches!(step, SettleStep::Closed(_)) {
                node.push_defi_event(t.pair, crate::defi_lane::DefiEvent::Closed { batch: t.batch });
            }
            Ok(())
        })(),
        Class::DefiExpire => (|| {
            let t = DefiExpireTx::decode(payload).ok_or("not an expiry")?;
            let mut book = node.peg().defi_book_of(t.pair).ok_or("the expiry names no pair")?.clone();
            let at = score()?;
            t.verdict(&book, at, chain_ms)?;
            let before = (book.batch, book.opened_at);
            apply_expiry(&mut book, at, block_ts);
            stamp(&mut book, before);
            *node.defi_book_mut(t.pair).ok_or("the expiry names no pair")? = book;
            node.push_defi_event(t.pair, crate::defi_lane::DefiEvent::Closed { batch: t.batch });
            Ok(())
        })(),
        // ⭐ EARN STEP 3 — the EarnEpoch: a verdict against EVERY pair's book (each one's close commitments and counters), then
        // the raise of every pair at once. CHAIN-OBJECT: the folded DefiEarnEpochTx; the books move only as it says.
        Class::DefiEarnEpoch => (|| {
            let t = DefiEarnEpochTx::decode(payload).ok_or("not an EarnEpoch")?;
            let mut books: Vec<DefiBook> = (0..PAIRS).map(|p| node.peg().defi_book_of(p).cloned().ok_or("a pair's book is missing")).collect::<Result<_, _>>()?;
            let closing = t.verdict(&books)?;
            apply_earn_epoch(&mut books, &t, closing);
            for (p, b) in (0..PAIRS).zip(books) {
                *node.defi_book_mut(p).ok_or("a pair's book is missing")? = b;
            }
            Ok(())
        })(),
        Class::DefiHandover => (|| {
            let t = crate::defi_handover::DefiHandoverTx::decode(payload).ok_or("not a handover object")?;
            let pair = t.pair();
            let mut book = node.peg().defi_book_of(pair).ok_or("the handover names no pair")?.clone();
            let canonical = crate::defi_handover::canonical_roster(&node.validators().bonded_custodian_eks());
            t.verdict(&book, &canonical)?;
            let before = (book.batch, book.opened_at);
            crate::defi_handover::apply_handover(&mut book, &t, score()?);
            stamp(&mut book, before);
            *node.defi_book_mut(pair).ok_or("the handover names no pair")? = book;
            if let crate::defi_handover::DefiHandoverTx::Deal { batch, from, sealed, .. } = t {
                node.push_defi_event(pair, crate::defi_lane::DefiEvent::HandoverDeal { batch, from, sealed });
            }
            Ok(())
        })(),
        _ => return DefiApply::NotDefi,
    };
    match verdict {
        Ok(()) => DefiApply::Applied,
        Err(why) => {
            eprintln!("[fold-refuse] class={class:?} why={why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a class and a fixed reason only
            DefiApply::Refused(why)
        }
    }
}

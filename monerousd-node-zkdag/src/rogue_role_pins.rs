// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⛔⛔⛔ ROGUE-ROLE CENSUS CELLS — one pin per (class × attack), judged on a PEER (lane-harness, 2026-10-04).
//!
//! The census (`harness/rogue_census.rs`) names every chain class × {forge, strip, substitute, replay, burn}. A cell is
//! Pinned only by a GREEN pin here (or one the census names elsewhere) that mounts exactly that attack through a ROGUE
//! PRODUCER — a node that lays its own block around the hostile object, skipping every publisher door — and asserts what
//! the HONEST PEER holds afterwards. Every pin carries:
//!   * a CALIBRATION arm: the hostile object is armed (it passes the doors a rogue can satisfy on its own — the proof,
//!     the decode), and the rogue block GRAFTS on the peer, so the refusal measured is the object rule's, never a
//!     structural door's;
//!   * a CONTROL arm — the DB-377 burn class: after the rogue block, the HONEST object still lays and lands on BOTH
//!     nodes, exactly once. A refused object that names a victim's id must cost the victim nothing.
//!
//! Two parties in every pin: `node_a` is the honest peer (and the honest publisher in the control), `node_b` the rogue.
//! Both judge the same rogue block, so the honest blocks that follow connect on both.
//!
//! The fixtures are CALLED, never copied: `crate::node::tests::dd_*` (rogue block, graft-then-settle) and
//! `crate::dex_cross_party_scenarios::tests::*` (a real two-half trade, its on-chain inputs and binds).
//!
//! cons: none — test-only code (`#[cfg(test)]` in lib.rs): in-memory testnet nodes, a handful of blocks each, persists
//! nothing; every count is a function of one fixed trade's shape, no history term.

use crate::chain_action_carriage_tests::tests::{
    owner_clue as wm_owner_clue, pair as wm_pair, recipient_of as wm_recipient_of, ASSET as WM_ASSET,
};
use crate::dex_cross_party_scenarios::tests::{
    a_block_carrying_the_fill, a_real_trade, cm_occurrences, deliver_planted, gossip_order, note_for, owner, party,
    trade_binds,
};
use crate::hash::Hash32;
use crate::node::tests::{dd_graft_then_settle, dd_rogue_block_carrying};
use crate::node::{Node, OrderFillOutcome};
use crate::order_book::{OrderBook, PostRefusal, RestingOrder};
use crate::order_fill_tx::OrderFillTx;
use crate::relay::RelayOutcome;
use usdm_decider::whir_rec_block::{prove_order_taker_half, OrderTerms, TakerHalfPublic, TakerHalfWitness};

type Bind = (Vec<u8>, Vec<u8>);

fn cm_of(note: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(&note[..32]).expect("a note leads with its commitment")
}

/// A tag no order rests under and no note owns — the rogue block's own lane entry where the cell is not about the lane
/// (blake3 output: either not a canonical digest encoding or a digest nothing holds, exactly like a cover tag).
fn cover_tag() -> [u8; 32] {
    Hash32::hash(b"rogue-role census: a cover tag naming nothing").0
}

/// The maker's lot tag as a fill publishes it (`OrderFillTx::nullifier_tags`: `leaf_to_cm_bytes(maker.nullifier)`).
fn maker_tag(resting: &RestingOrder) -> [u8; 32] {
    crate::spend_frontier::leaf_to_cm_bytes(resting.maker.nullifier)
}

/// The fill object for `resting` taken by the taker half `(tc, tp)` over `notes` with these binds — the struct the
/// publisher frames, field for field (`dex_cross_party_scenarios`' `fill_with`).
fn fill_of(t: &OrderTerms, resting: &RestingOrder, tc: &[u8], tp: &TakerHalfPublic, notes: &[Vec<u8>; 3], binds: [Bind; 2]) -> OrderFillTx {
    let [(mc, mt), (kc, kt)] = binds;
    OrderFillTx {
        lot: t.lot,
        pay_b: t.pay_b,
        asset_a: t.asset_a,
        asset_b: t.asset_b,
        expires_at_height: t.expires_at_height,
        maker_nullifier: resting.maker.nullifier,
        maker_leaf_commit: resting.maker.leaf_commit,
        maker_payout_cm: resting.maker.payout_cm,
        maker_bytes: resting.maker_bytes.clone(),
        taker_nullifier: tp.nullifier,
        taker_leaf_commit: tp.leaf_commit,
        taker_payout_cm: tp.payout_cm,
        taker_change_cm: tp.change_cm,
        taker_bytes: tc.to_vec(),
        maker_membership_carrier: mc,
        maker_membership_tip: mt,
        taker_membership_carrier: kc,
        taker_membership_tip: kt,
        notes: notes.clone(),
        owner_clues: [owner(1), owner(2), owner(3)],
    }
}

/// One real trade between two parties: the maker's order rests on `node_a` and reaches `node_b` by the runtime's gossip
/// wire; both input notes are planted on `node_a`'s chain and the planting blocks folded on `node_b`, so the fill's
/// membership binds verify on both nodes.
struct Market {
    t: OrderTerms,
    resting: RestingOrder,
    tc: Vec<u8>,
    tp: TakerHalfPublic,
    notes: [Vec<u8>; 3],
    binds: [Bind; 2],
}

fn a_market(node_a: &mut Node, node_b: &mut Node, plant_at: u64) -> Market {
    let (t, resting, (tc, tp), notes) = a_real_trade();
    node_a.post_order(resting.clone()).expect("the order rests on node_a");
    let _ = gossip_order(&resting, node_b);
    let (mb, tb, planted) = trade_binds(node_a, &t, &resting.maker, &tp, plant_at);
    deliver_planted(&planted, node_b, plant_at);
    Market { t, resting, tc, tp, notes, binds: [mb, tb] }
}

/// Both nodes judge the SAME rogue block (the rogue publishes it). Returns the PEER's verdict; asserts it grafted, so the
/// object reached the doors the cell asks about.
fn both_judge(node_a: &mut Node, node_b: &mut Node, rogue: crate::block::Block, at: u64, what: &str) {
    // The rogue publishes every block it builds on — its own unmutated sibling of an earlier rogue block included (the
    // block `produce` placed in its DAG before the rogue rewrote a copy). MEASURED 2026-10-04: without it a second rogue
    // block is `Buffered { missing }` on the peer, a fixture artifact rather than a verdict on the object.
    for parent in &rogue.header.parents {
        if node_a.dag().get(parent).is_none() {
            if let Some(sibling) = node_b.full_block_by_id(parent) {
                let _ = node_a.ingest_block_preverified(sibling, at);
            }
        }
    }
    let out_b = node_b.ingest_block_preverified(rogue.clone(), at);
    let out_a = node_a.ingest_block_preverified(rogue, at);
    eprintln!("[rogue-role] node_a's verdict on a block carrying {what}: {out_a:?} (the rogue's own: {out_b:?})");
    assert!(
        matches!(out_a, RelayOutcome::Added(_)),
        "CALIBRATION: the rogue block grafts on the peer — the object reaches its class door, not a structural one: {out_a:?}"
    );
    let _ = node_a.fold_canonical_records();
    let _ = node_b.fold_canonical_records();
}

/// The STRIP judge: an object the codec refuses has no carriage form, so the peer may refuse the whole block at the
/// credit-set shape door (`Invalid(CreditSetNotCarriage)`, MEASURED 2026-10-04 for the PegIn strip arm) or graft it and
/// refuse the object at its class door. Either is a refusal on the peer; ANY other verdict (buffered, a different
/// structural refusal) means the arm measured something else, so it fails.
fn both_judge_strip(node_a: &mut Node, node_b: &mut Node, rogue: crate::block::Block, at: u64, what: &str) {
    let out_b = node_b.ingest_block_preverified(rogue.clone(), at);
    let out_a = node_a.ingest_block_preverified(rogue, at);
    eprintln!("[rogue-role] node_a's verdict on a block carrying {what}: {out_a:?} (the rogue's own: {out_b:?})");
    assert!(
        matches!(out_a, RelayOutcome::Added(_) | RelayOutcome::Invalid(crate::consensus::ConsensusError::CreditSetNotCarriage)),
        "CALIBRATION: the peer judged the stripped object at the shape door or its class door, nothing else: {out_a:?}"
    );
    let _ = node_a.fold_canonical_records();
    let _ = node_b.fold_canonical_records();
}

/// CONTROL — THE BURN CLASS: the honest taker's fill still SETTLES at the publisher door on `node_a` (not
/// `OrderAlreadyFilled`: nothing the rogue named was burned), `node_a` lays it, `node_b` grafts it, and each of the three
/// notes sits in exactly one record on BOTH nodes.
fn the_honest_fill_settles_on_both_nodes(node_a: &mut Node, node_b: &mut Node, m: &Market, at: u64, seed: &[u8]) {
    let v = node_a.execute_order_fill(
        &m.resting.maker_bytes,
        &m.resting.maker,
        &m.tc,
        &m.tp,
        &m.t,
        &m.notes[0],
        &m.notes[1],
        &m.notes[2],
        [owner(1), owner(2), owner(3)],
        [Some(m.binds[0].clone()), Some(m.binds[1].clone())],
    );
    assert_eq!(
        v,
        OrderFillOutcome::Settled,
        "⛔ BURN: after the rogue block the honest fill no longer settles on node_a — the refused object burned the maker's lot or the taker's input"
    );
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest fill");
    assert!(
        !honest.credit_set.is_empty(),
        "⛔ DB-377 CLASS: node_a laid a block WITHOUT its pooled fill — the rogue block's note bytes poisoned its assembler"
    );
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    for (i, n) in m.notes.iter().enumerate() {
        let cm = cm_of(n);
        assert_eq!(cm_occurrences(node_a, &cm), 1, "CONTROL: fill note {i} sits in exactly one record on node_a");
        assert_eq!(cm_occurrences(node_b, &cm), 1, "CONTROL: fill note {i} sits in exactly one record on node_b");
    }
}

/// How many offers resting under `order`'s maker nullifier the node's book holds at the order's (pair, level).
fn rests(node: &Node, order: &RestingOrder) -> usize {
    node.book_level(order.pair(), order.level()).0.iter().filter(|o| o.maker.nullifier == order.maker.nullifier).count()
}

/// The maker's node rests the offer and POOLS its framed `Class::OrderPost` — what `POST /post_order` does
/// (`rpc_http.rs`: `post_order`, then `order_post_tx::as_pq_tx` into the pool), so its next block carries the offer.
fn publish_post(node: &mut Node, order: &RestingOrder) {
    let _ = node.post_order(order.clone());
    let bits = node.mempool().required_stamp_bits();
    assert!(
        node.ingest_tx(crate::order_post_tx::as_pq_tx(order, bits)).is_ok(),
        "the maker's node pools its framed offer"
    );
}

/// The honest offer rides `node_a`'s block and rests on BOTH nodes from it.
fn the_honest_post_rests_on_both_nodes(node_a: &mut Node, node_b: &mut Node, order: &RestingOrder, at: u64, seed: &[u8]) {
    publish_post(node_a, order);
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest offer");
    assert!(!honest.credit_set.is_empty(), "the maker's node laid its pooled offer in the block");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    assert_eq!(rests(node_a, order), 1, "CONTROL: the honest offer rests on node_a");
    assert_eq!(rests(node_b, order), 1, "CONTROL: the honest offer rests on node_b — from the block alone");
}

/// A rogue block carrying `order` framed as a `Class::OrderPost` (its own carriage: an offer names no note).
fn rogue_post_block(rogue: &mut Node, order: &RestingOrder, at: u64, seed: &[u8]) -> crate::block::Block {
    let carriage = crate::chain_object::carriage_of(&crate::order_post_tx::encode(order))
        .expect("an offer that decodes is its own carriage");
    dd_rogue_block_carrying(rogue, carriage, Vec::new(), cover_tag(), at, seed)
}

// ═══════════════════════════════════════════ OrderFill ═══════════════════════════════════════════

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — OrderFill × STRIP, through a peer. The inputs are REAL (planted on both nodes' chains), the
/// composed proof is valid, and the rogue `node_b` carries the fill with both membership binds REMOVED. The one fill
/// rule (DB-368: publisher and fold judge alike) must refuse a fill that cannot show where its inputs are, whether or not
/// they happen to exist: the peer `node_a` credits none of the three notes. CONTROL: the same trade with its binds then
/// settles on both nodes, each note exactly once.
#[test]
fn a_fill_over_real_inputs_stripped_of_its_membership_binds_carried_by_a_rogue_producer_credits_nothing_on_the_peer() {
    let mut node_a = party();
    let mut node_b = party();
    let m = a_market(&mut node_a, &mut node_b, 74_000);
    let stripped = fill_of(&m.t, &m.resting, &m.tc, &m.tp, &m.notes, [(Vec::new(), Vec::new()), (Vec::new(), Vec::new())]);
    assert!(
        crate::chain_object::admissible(&stripped.wire(), node_a.params().order_fill_fee_bps, 0, false),
        "CALIBRATION: the stripped fill is admissible on its proof alone — the strip is armed"
    );
    let rogue = a_block_carrying_the_fill(&mut node_b, &stripped, 80_000);
    both_judge(&mut node_a, &mut node_b, rogue, 80_500, "a fill over real inputs with its membership binds stripped");
    for (i, n) in m.notes.iter().enumerate() {
        assert_eq!(
            cm_occurrences(&node_a, &cm_of(n)),
            0,
            "⛔ ROGUE PRODUCER: the peer credited fill note {i} from a fill carrying NO membership binds"
        );
    }
    the_honest_fill_settles_on_both_nodes(&mut node_a, &mut node_b, &m, 84_000, b"fill-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — OrderFill × BURN, through a peer. The victim maker's order is PUBLIC (its half rests in every
/// book), so an attacker needs no key to NAME its lot: the rogue `node_b` proves its own taker half against the victim's
/// resting maker half — a valid composed proof — over a taker input that never existed, and carries that fill. Its lane
/// carries the victim maker's lot tag. The fill is refused; the peer `node_a` must credit none of its notes AND must not
/// have burned the maker's lot: the honest taker's fill then settles on both nodes, the maker paid exactly once.
#[test]
fn a_refused_fill_naming_a_victim_makers_lot_carried_by_a_rogue_producer_does_not_stop_the_real_fill_on_the_peer() {
    let mut node_a = party();
    let mut node_b = party();
    let m = a_market(&mut node_a, &mut node_b, 74_000);
    let lanes = |a: u64| usdm_decider::poseidon2_compress::lanes_of(&[a, a + 1, a + 2, a + 3]);
    let attacker = TakerHalfWitness {
        value_in: 10_000_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes(9_001)),
        change_opening: lanes(9_011),
        payout_opening: lanes(9_021),
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
    };
    let (atc, atp) = prove_order_taker_half(&attacker, &m.t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT)
        .expect("the attacker's taker half proves against the victim's public order");
    let anotes = [m.resting.payout_note.clone(), note_for(atp.payout_cm), note_for(atp.change_cm)];
    let rogue_fill = fill_of(&m.t, &m.resting, &atc, &atp, &anotes, [(Vec::new(), Vec::new()), (Vec::new(), Vec::new())]);
    assert!(
        crate::chain_object::admissible(&rogue_fill.wire(), node_a.params().order_fill_fee_bps, 0, false),
        "CALIBRATION: the attacker's fill composes against the victim's order — the burn is armed"
    );
    assert!(
        rogue_fill.nullifier_tags().iter().any(|tag| tag.0 == maker_tag(&m.resting)),
        "CALIBRATION: the rogue fill's lane names the victim maker's lot"
    );
    let rogue = a_block_carrying_the_fill(&mut node_b, &rogue_fill, 80_000);
    both_judge(&mut node_a, &mut node_b, rogue, 80_500, "an attacker's fill naming a victim maker's lot");
    for (i, n) in anotes.iter().enumerate() {
        assert_eq!(
            cm_occurrences(&node_a, &cm_of(n)),
            0,
            "⛔ ROGUE PRODUCER: the peer credited note {i} of an attacker's fill whose taker input never existed"
        );
    }
    the_honest_fill_settles_on_both_nodes(&mut node_a, &mut node_b, &m, 84_000, b"fill-burn-settle");
}

// ═══════════════════════════════════════════ OrderPost ═══════════════════════════════════════════

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — OrderPost × FORGE, through a peer: the maker's offer with its maker-half proof corrupted,
/// carried by the rogue `node_b` before the honest offer exists anywhere. The book's own door (`OrderBook::post` →
/// `verify_order_maker_half`) runs inside the apply seam on every node, so the peer `node_a` rests nothing. CONTROL: the
/// honest offer — same maker nullifier — then rides `node_a`'s block and rests on both nodes.
#[test]
fn a_forged_offer_carried_by_a_rogue_producer_rests_in_no_peer_book() {
    let mut node_a = party();
    let mut node_b = party();
    let (_t, resting, _taker, _notes) = a_real_trade();
    let mut forged = resting.clone();
    let mid = forged.maker_bytes.len() / 2;
    forged.maker_bytes[mid] ^= 0x01;
    assert_eq!(OrderBook::new().post(forged.clone(), 0), Err(PostRefusal::ProofRefused), "CALIBRATION: the forgery is armed — the book door refuses its proof");
    assert!(OrderBook::new().post(resting.clone(), 0).is_ok(), "CALIBRATION: the honest offer posts");
    let rogue = rogue_post_block(&mut node_b, &forged, 20_000, b"post-forge-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 20_500, "an offer with a forged maker half");
    assert_eq!(rests(&node_a, &resting), 0, "⛔ ROGUE PRODUCER: a forged offer rests in the peer's book");
    assert_eq!(rests(&node_b, &resting), 0, "the rogue's own book rests nothing either");
    the_honest_post_rests_on_both_nodes(&mut node_a, &mut node_b, &resting, 24_000, b"post-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — OrderPost × STRIP, through a peer: the offer stripped of its payout owner clue (DB-273 §19.6
/// L3 — a payout filed for nobody is money no seed restore finds). The book door refuses it (`MissingPayoutOwner`) on the
/// peer; the honest offer then rests on both nodes.
#[test]
fn an_offer_stripped_of_its_payout_owner_carried_by_a_rogue_producer_rests_in_no_peer_book() {
    let mut node_a = party();
    let mut node_b = party();
    let (_t, resting, _taker, _notes) = a_real_trade();
    let mut stripped = resting.clone();
    stripped.payout_clue = Vec::new();
    assert_eq!(OrderBook::new().post(stripped.clone(), 0), Err(PostRefusal::MissingPayoutOwner), "CALIBRATION: the strip is armed");
    let rogue = rogue_post_block(&mut node_b, &stripped, 20_000, b"post-strip-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 20_500, "an offer stripped of its payout owner");
    assert_eq!(rests(&node_a, &resting), 0, "⛔ ROGUE PRODUCER: an offer with no payout owner rests in the peer's book");
    assert_eq!(rests(&node_b, &resting), 0, "the rogue's own book rests nothing either");
    the_honest_post_rests_on_both_nodes(&mut node_a, &mut node_b, &resting, 24_000, b"post-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — OrderPost × SUBSTITUTE, through a peer: the offer's payout NOTE swapped for one that does
/// not carry the commitment the maker's half proved — an unfillable order every taker would pay to discover. The book
/// door refuses it (`PayoutNoteMismatch`) on the peer; the honest offer then rests on both nodes.
#[test]
fn an_offer_whose_payout_note_was_swapped_carried_by_a_rogue_producer_rests_in_no_peer_book() {
    let mut node_a = party();
    let mut node_b = party();
    let (_t, resting, _taker, _notes) = a_real_trade();
    let mut swapped = resting.clone();
    swapped.payout_note[..32].copy_from_slice(&Hash32::hash(b"a payout the maker's half never proved").0);
    assert_eq!(OrderBook::new().post(swapped.clone(), 0), Err(PostRefusal::PayoutNoteMismatch), "CALIBRATION: the substitution is armed");
    let rogue = rogue_post_block(&mut node_b, &swapped, 20_000, b"post-swap-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 20_500, "an offer whose payout note was swapped");
    assert_eq!(rests(&node_a, &resting), 0, "⛔ ROGUE PRODUCER: an offer with a swapped payout note rests in the peer's book");
    assert_eq!(rests(&node_b, &resting), 0, "the rogue's own book rests nothing either");
    the_honest_post_rests_on_both_nodes(&mut node_a, &mut node_b, &resting, 24_000, b"post-swap-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — OrderPost × REPLAY, through a peer, in BOTH places a replay can land:
///   1. WHILE IT RESTS — the rogue `node_b` re-carries the honest, already-resting offer: one note is one offer
///      (`Duplicate`), so the peer `node_a` holds it exactly once;
///   2. AFTER IT FILLED — the order's maker note is SPENT (the fill's burn retired it from both books) and the rogue
///      re-carries the original offer: a book must never serve an offer whose note the chain says is spent
///      (`mature_chain_invariants`' book law) — every taker who read it would build a fill, pay the proving cost, and be
///      refused as already filled. The peer must not re-rest it.
#[test]
fn a_re_carried_offer_rests_once_while_live_and_never_again_after_its_fill_on_the_peer() {
    let mut node_a = party();
    let mut node_b = party();
    let (t, resting, (tc, tp), notes) = a_real_trade();
    the_honest_post_rests_on_both_nodes(&mut node_a, &mut node_b, &resting, 20_000, b"post-replay-honest");
    // 1. re-carried while live
    let rogue = rogue_post_block(&mut node_b, &resting, 23_000, b"post-replay-live");
    both_judge(&mut node_a, &mut node_b, rogue, 23_500, "a re-carried live offer");
    let live_a = rests(&node_a, &resting);
    let live_b = rests(&node_b, &resting);
    // the order fills: inputs planted on node_a's chain and folded on node_b's, the fill laid by node_a
    let (mb, tb, planted) = trade_binds(&mut node_a, &t, &resting.maker, &tp, 30_000);
    deliver_planted(&planted, &mut node_b, 30_000);
    let m = Market { t, resting: resting.clone(), tc, tp, notes, binds: [mb, tb] };
    the_honest_fill_settles_on_both_nodes(&mut node_a, &mut node_b, &m, 36_000, b"post-replay-fill");
    assert_eq!((rests(&node_a, &resting), rests(&node_b, &resting)), (0, 0), "CALIBRATION: the fill's burn retired the order from both books");
    // 2. re-carried after the fill
    let rogue = rogue_post_block(&mut node_b, &resting, 40_000, b"post-replay-dead");
    both_judge(&mut node_a, &mut node_b, rogue, 40_500, "a re-carried offer whose maker note is spent");
    let dead_a = rests(&node_a, &resting);
    let dead_b = rests(&node_b, &resting);
    eprintln!("[rogue-role] MEASURED OrderPost replay: while live node_a/node_b hold {live_a}/{live_b}; after its fill {dead_a}/{dead_b}");
    assert_eq!((live_a, live_b), (1, 1), "⛔ ROGUE PRODUCER: a re-carried live offer rests TWICE (or vanished) on the peer");
    assert_eq!(
        dead_a, 0,
        "⛔ ROGUE PRODUCER: the peer's book re-rested a FILLED order from a re-carried post — it serves an offer whose maker note the chain says is spent"
    );
    assert_eq!(dead_b, 0, "⛔ the rogue's own book re-rested the filled order too");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — OrderPost × BURN (the filed griefing), through a peer. A resting offer is keyed by its
/// maker's nullifier, and both book-retirement sites (`node.rs` graft, and the apply tail) retire every order whose
/// nullifier appears in a block's padded tag lane. The rogue `node_b` lays a block carrying NOTHING but the victim
/// maker's lot tag in its lane — no fill, no proof. The tag is unjustified (DB-367: the fold admits only justified lane
/// tags), so the maker's note is not spent; the peer `node_a`'s book must therefore STILL rest the order, and the lot must
/// still fill on both nodes.
#[test]
fn a_rogue_producer_naming_a_makers_lot_tag_in_its_lane_does_not_cancel_the_resting_order_on_the_peer() {
    let mut node_a = party();
    let mut node_b = party();
    let (t, resting, (tc, tp), notes) = a_real_trade();
    the_honest_post_rests_on_both_nodes(&mut node_a, &mut node_b, &resting, 20_000, b"post-burn-honest");
    let (mb, tb, planted) = trade_binds(&mut node_a, &t, &resting.maker, &tp, 26_000);
    deliver_planted(&planted, &mut node_b, 26_000);
    assert_eq!((rests(&node_a, &resting), rests(&node_b, &resting)), (1, 1), "CALIBRATION: the offer rests on both nodes before the rogue block");
    // the rogue's block: an ordinary block of its own, with the victim's lot tag added to its lane and the root resealed
    let mut rogue = node_b.produce(32_000, Hash32::hash(b"post-burn-rogue"), Hash32::hash(b"rogue-mc")).expect("the rogue lays a block");
    rogue.nullifier_proof.padded_tags.push(maker_tag(&resting));
    rogue.header.nullifier_tags_root = crate::block::nullifier_tags_root_of(&rogue.nullifier_proof.padded_tags);
    crate::node::tests::lay_tag_evidence_for_test(&node_b, &mut rogue, &[maker_tag(&resting)]);
    both_judge(&mut node_a, &mut node_b, rogue, 32_500, "only a victim maker's lot tag in its lane");
    let after_a = rests(&node_a, &resting);
    let after_b = rests(&node_b, &resting);
    eprintln!("[rogue-role] MEASURED OrderPost burn: after a lane-only block naming the maker's lot, node_a/node_b rest {after_a}/{after_b}");
    let m = Market { t, resting: resting.clone(), tc, tp, notes, binds: [mb, tb] };
    the_honest_fill_settles_on_both_nodes(&mut node_a, &mut node_b, &m, 36_000, b"post-burn-fill");
    assert_eq!(
        after_a, 1,
        "⛔ GRIEFING: a producer cancelled the maker's resting order on the peer by naming its lot tag in its lane — no fill, no proof, the note unspent"
    );
    assert_eq!(after_b, 1, "⛔ GRIEFING: the rogue's own book dropped the order too");
}

// ═══════════════════════════════════════════ WrappedMint ═══════════════════════════════════════════

type WmParts = (
    crate::wrapped_mint_tx::WrappedMintHeader,
    Vec<u8>,
    Vec<u8>,
    Vec<crate::psm::MintAttestor>,
    Vec<u8>,
    Vec<([u8; 32], Vec<u8>)>,
    Vec<u8>,
);

/// The quorum pair (`chain_action_carriage_tests::pair`: one bonded validator seated on both nodes, the asset registered
/// through its chain object on both) with an honest confidential wrapped mint of `dep` PUBLISHED on `node_a` — pooled,
/// not laid. Returns both nodes, the minted note's commitment and the full wire of the framed object as `node_a` carries it.
fn wm_published(dep: [u8; 32], addr: &str) -> (Node, Node, [u8; 32], Vec<u8>) {
    let (mut node_a, node_b, pk, sk) = wm_pair();
    let lanes = |a: u64| usdm_decider::poseidon2_compress::lanes_of(&[a, a + 1, a + 2, a + 3]);
    let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(WM_ASSET);
    let wdb = lanes(0xdb80);
    let (wcarrier, wcm, _) =
        // DB-395: the minted note opens to its OWNER (`as_published` spends it as `NoteOwner::from_test_key(lanes(5))`).
        usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(
            2_000,
            wtag,
            &usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes(5)).opening(),
            &wdb,
        )
            .expect("an authorized amount proves its own commitment in its own asset");
    let cm = crate::spend_frontier::leaf_to_cm_bytes(wcm);
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&cm);
    crate::btc_watch::inject_confirmed_for_test(addr, 1_000_000);
    let out = node_a.publish_wrapped_mint(
        WM_ASSET,
        dep,
        3_000,
        2_000,
        wm_recipient_of(&dep),
        &note,
        &wcarrier,
        addr,
        &pk,
        &sk,
        &[],
        &crate::pqauth::MlDsaVerifier,
        &wm_owner_clue(),
        wdb,
    );
    assert_eq!(out, crate::peg::PegOutcome::ConfidentialPublished, "PRECONDITION: the honest wrapped mint publishes on node_a");
    let wire = node_a
        .mempool()
        .all_tx_ids()
        .into_iter()
        .filter_map(|id| node_a.mempool().get(&Hash32(id)).map(|tx| tx.blob.clone()))
        .find(|blob| matches!(crate::chain_object::unframe(blob), Some((crate::chain_object::Class::WrappedMint, _))))
        .expect("CALIBRATION: node_a pooled its framed wrapped mint for its next block");
    (node_a, node_b, cm, wire)
}

fn wm_parts(wire: &[u8]) -> WmParts {
    let (_, payload) = crate::chain_object::unframe(wire).expect("framed");
    crate::wrapped_mint_tx::decode(payload).expect("the honest object decodes")
}

/// The honest object re-encoded with `edit` applied — for edits the codec still accepts (the apply judges them).
fn wm_rewired(wire: &[u8], edit: impl FnOnce(&mut WmParts)) -> Vec<u8> {
    let mut p = wm_parts(wire);
    edit(&mut p);
    let (h, c, mc, att, note, sealed, clue) = &p;
    crate::wrapped_mint_tx::wire(h, c, mc, att, note, sealed, clue)
}

/// A ROGUE carriage laid by hand: `edit` applied, the HONEST note replaced by its 64-byte reference `cm ‖ blake3(note)` —
/// for edits the codec refuses (`carriage_of` would return None), so the block reaches the codec door, not the shape
/// door's `CreditSetNotCarriage` (the shape `dd_peg_in_rogue_carriage` lays for a peg-in).
fn wm_rogue_carriage(wire: &[u8], edit: impl FnOnce(&mut WmParts)) -> Vec<u8> {
    let mut p = wm_parts(wire);
    let note = p.4.clone();
    edit(&mut p);
    let mut note_ref = note[..32].to_vec();
    note_ref.extend_from_slice(&Hash32::hash(&note).0);
    p.4 = note_ref;
    let (h, c, mc, att, n, sealed, clue) = &p;
    crate::wrapped_mint_tx::wire(h, c, mc, att, n, sealed, clue)
}

/// The deposit's one-time id the object retires (`chain_object::object_own_nullifiers`' WrappedMint arm).
fn wm_tag(dep: &[u8; 32]) -> [u8; 32] {
    crate::peg::one_time_id_nf(crate::peg::ONE_TIME_DEPOSIT, &crate::peg::wrapped_deposit_key(WM_ASSET, dep))
}

fn wm_note_body(wire: &[u8]) -> Vec<u8> {
    crate::chain_object::carried_note_payloads(wire).expect("the object names its note").concat()
}

type WmCommits = Option<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)>;

/// Neither node minted the deposit, the peer's asset commitments did not move, and the peer holds no record of `cm`.
fn wm_nothing_moved(node_a: &Node, node_b: &Node, dep: &[u8; 32], cm: &[u8; 32], commits: &WmCommits, what: &str) {
    assert!(!node_a.peg().wrapped_deposit_minted(WM_ASSET, dep), "⛔ ROGUE PRODUCER: {what} minted the deposit on the peer");
    assert!(!node_b.peg().wrapped_deposit_minted(WM_ASSET, dep), "the rogue's own chain minted nothing either ({what})");
    assert_eq!(&node_a.peg().wrapped_asset_commits(WM_ASSET), commits, "⛔ ROGUE PRODUCER: {what} moved the peer's wrapped commitments");
    assert_eq!(cm_occurrences(node_a, cm), 0, "⛔ ROGUE PRODUCER: {what} credited its note on the peer");
}

/// CONTROL — THE BURN CLASS: the honest mint `node_a` still holds pooled lays and lands on BOTH nodes, its note in
/// exactly one record each.
fn wm_the_honest_mint_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, dep: &[u8; 32], cm: &[u8; 32], at: u64, seed: &[u8]) {
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest mint");
    assert!(!honest.credit_set.is_empty(), "⛔ DB-377 CLASS: node_a laid a block WITHOUT its pooled wrapped mint");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    assert!(
        node_a.peg().wrapped_deposit_minted(WM_ASSET, dep) && node_b.peg().wrapped_deposit_minted(WM_ASSET, dep),
        "CONTROL: the honest wrapped mint lands on both nodes"
    );
    assert_eq!(cm_occurrences(node_a, cm), 1, "CONTROL: the minted note sits in exactly one record on node_a");
    assert_eq!(cm_occurrences(node_b, cm), 1, "CONTROL: the minted note sits in exactly one record on node_b");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — WrappedMint × FORGE, through a peer: the honest object with its attestation replaced by one
/// from a key that holds no bond (zero attested weight of the quorum), carried by the rogue `node_b`. The peer `node_a`
/// mints nothing; CONTROL: the honest, attested mint then lands on both nodes.
#[test]
fn an_under_attested_wrapped_mint_carried_by_a_rogue_producer_mints_nothing_on_the_peer() {
    let dep = [0x51u8; 32];
    let (mut node_a, mut node_b, cm, wire) = wm_published(dep, "bc1prolewmforge");
    let commits = node_a.peg().wrapped_asset_commits(WM_ASSET);
    let (spk, ssk) = crate::pqauth::ml_dsa_keypair();
    let forged = wm_rewired(&wire, |p| {
        p.3 = vec![crate::psm::MintAttestor {
            pubkey: spk.clone(),
            sig: crate::pqauth::ml_dsa_sign(b"a stranger signs anything", &ssk).expect("signs"),
        }];
    });
    let carriage = crate::chain_object::carriage_of(&forged)
        .expect("an object with an unbonded attestor still decodes: the quorum is judged at the apply");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, wm_note_body(&wire), wm_tag(&dep), 4_000, b"wm-forge-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 4_500, "a wrapped mint attested by a key holding no bond");
    wm_nothing_moved(&node_a, &node_b, &dep, &cm, &commits, "an under-attested wrapped mint");
    wm_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &dep, &cm, 6_000, b"wm-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — WrappedMint × STRIP, through a peer: the honest object with its attestations REMOVED (the
/// codec refuses it, so the rogue lays the bytes by hand). The peer mints nothing; the honest mint then lands on both.
#[test]
fn a_wrapped_mint_stripped_of_its_attestations_carried_by_a_rogue_producer_mints_nothing_on_the_peer() {
    let dep = [0x52u8; 32];
    let (mut node_a, mut node_b, cm, wire) = wm_published(dep, "bc1prolewmstrip");
    let commits = node_a.peg().wrapped_asset_commits(WM_ASSET);
    let stripped = wm_rogue_carriage(&wire, |p| p.3.clear());
    let rogue = dd_rogue_block_carrying(&mut node_b, stripped, wm_note_body(&wire), wm_tag(&dep), 4_000, b"wm-strip-rogue");
    both_judge_strip(&mut node_a, &mut node_b, rogue, 4_500, "a wrapped mint with NO attestations");
    wm_nothing_moved(&node_a, &node_b, &dep, &cm, &commits, "a wrapped mint stripped of its attestations");
    wm_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &dep, &cm, 6_000, b"wm-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — WrappedMint × SUBSTITUTE, through a peer: the credited NOTE swapped under the quorum's
/// signatures for one the rogue chose (any value it likes), and that note laid in the block. The peer credits neither
/// note and mints nothing; the honest mint then lands on both.
#[test]
fn a_wrapped_mint_whose_note_was_swapped_under_the_quorum_carried_by_a_rogue_producer_mints_nothing_on_the_peer() {
    let dep = [0x53u8; 32];
    let (mut node_a, mut node_b, cm, wire) = wm_published(dep, "bc1prolewmswap");
    let commits = node_a.peg().wrapped_asset_commits(WM_ASSET);
    let mut swapped_note = wm_note_body(&wire);
    swapped_note[..32].copy_from_slice(&Hash32::hash(b"a wrapped note the quorum never attested").0);
    let swapped_cm = cm_of(&swapped_note);
    let swapped = wm_rewired(&wire, |p| p.4 = swapped_note.clone());
    let carriage = crate::chain_object::carriage_of(&swapped).expect("a swapped note still decodes: the binding is judged at the apply");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, swapped_note.clone(), wm_tag(&dep), 4_000, b"wm-swap-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 4_500, "a wrapped mint whose note was swapped under the quorum");
    assert_eq!(cm_occurrences(&node_a, &swapped_cm), 0, "⛔ ROGUE PRODUCER: the peer credited a wrapped note the quorum never attested");
    wm_nothing_moved(&node_a, &node_b, &dep, &cm, &commits, "a wrapped mint with a swapped note");
    wm_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &dep, &cm, 6_000, b"wm-swap-settle");
}

/// ⛔⛔⛔ F-LEG FOR A WRAPPED MINT (2026-11-11; the census row of docs/BRIDGE-CUSTODY-OBJECTS-20261110.md for WrappedMint) —
/// WrappedMint × RE-SEAL, through a peer: the honest, quorum-signed object with a sealed leg the rogue made itself (a leg
/// is sealed to a custodian's PUBLIC key, so anyone can) laid beside the honest note. Until the statement named the legs
/// (`peg::peg_in_signed_recipient`, `musdm.wrap.mint.conf.v3`) the signatures still verified, the mint applied, and the
/// custodian the leg was sealed to advanced or stranded its wrapped opening on the rogue's word. Now the object differs
/// from the honest one in its legs alone and carries no signature: the peer mints nothing.
/// CALIBRATION: the forged object decodes (the quorum is judged at the apply); the honest mint then lands on both nodes.
// TWO-PARTY-REVIEWED: node_b lays the forged block, node_a judges it from the block alone; both ledgers are read.
#[test]
fn a_wrapped_mint_given_a_sealed_leg_under_the_quorum_carried_by_a_rogue_producer_mints_nothing_on_the_peer() {
    let dep = [0x56u8; 32];
    let (mut node_a, mut node_b, cm, wire) = wm_published(dep, "bc1prolewmreseal");
    let commits = node_a.peg().wrapped_asset_commits(WM_ASSET);
    // the custodian the leg names is the one that attested; the envelope only has to be well formed, and anyone can
    // make one (this fixture's custodian registers no ML-KEM key, so the rogue seals to a key of its own)
    let victim = crate::pqauth::pubkey_id(&wm_parts(&wire).3.first().expect("CALIBRATION: the honest object is attested").pubkey);
    let (ek, _dk) = crate::pqkem::keypair();
    let lie = crate::peg_attest::PegInDelta {
        deposit_value: 9,
        mint: 6,
        reserve_address: "bc1prolewmreseal".to_string(),
        d_blind: usdm_decider::poseidon2_compress::lanes_of(&[0x51, 0x52, 0x53, 0x54]),
        pay_after: 0,
        sweep: None,
    };
    let blob = crate::peg_attest::seal_delta_to(&ek, &lie).expect("anyone seals to a public key");
    let honest_legs = wm_parts(&wire).5;
    let forged = wm_rewired(&wire, |p| {
        // one leg of the rogue's own for the custodian: replacing its honest leg when the object carries one
        p.5.retain(|(id, _)| *id != victim);
        p.5.push((victim, blob.clone()));
    });
    assert_ne!(wm_parts(&forged).5, honest_legs, "CALIBRATION: the forged object's legs are not the honest ones");
    let carriage = crate::chain_object::carriage_of(&forged).expect("a re-sealed object still decodes: the quorum is judged at the apply");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, wm_note_body(&wire), wm_tag(&dep), 4_000, b"wm-reseal-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 4_500, "a wrapped mint with a sealed leg placed under the quorum's signatures");
    wm_nothing_moved(&node_a, &node_b, &dep, &cm, &commits, "a wrapped mint with a re-sealed leg");
    wm_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &dep, &cm, 6_000, b"wm-reseal-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — WrappedMint × REPLAY, through a peer: the honest mint lands on both nodes; then the rogue
/// `node_b` re-carries the SAME framed object with the deposit's one-time id in its lane. The peer `node_a` mints nothing
/// more: its wrapped commitments unchanged, the note in exactly one record; the rogue's own chain stands where its honest
/// block left it.
#[test]
fn a_wrapped_mint_re_carried_by_a_rogue_producer_mints_once_on_the_peer() {
    let dep = [0x54u8; 32];
    let (mut node_a, mut node_b, cm, wire) = wm_published(dep, "bc1prolewmreplay");
    wm_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &dep, &cm, 4_000, b"wm-replay-honest");
    let (commits_a, commits_b) = (node_a.peg().wrapped_asset_commits(WM_ASSET), node_b.peg().wrapped_asset_commits(WM_ASSET));
    let carriage = crate::chain_object::carriage_of(&wire).expect("the honest object has a carriage form");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, wm_note_body(&wire), wm_tag(&dep), 8_000, b"wm-replay-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 8_500, "a RE-CARRIED, already applied wrapped mint");
    assert_eq!(node_a.peg().wrapped_asset_commits(WM_ASSET), commits_a, "⛔ ROGUE PRODUCER: a re-carried wrapped mint moved the peer's commitments");
    assert_eq!(cm_occurrences(&node_a, &cm), 1, "⛔ ROGUE PRODUCER: the re-carried wrapped mint credited its note a second time on the peer");
    assert_eq!(node_b.peg().wrapped_asset_commits(WM_ASSET), commits_b, "the rogue's own chain stands where its honest block left it");
    // The rogue's own RECORD count is a different claim — the DB-379 class — pinned on its own below
    // (`db379_a_late_sibling_re_carrying_a_mint_leaves_its_note_unstripped_on_the_node_that_folded_past_it`).
}

/// ⛔⛔⛔ DB-379 CLASS, measured through the WrappedMint replay arm (2026-10-04, RED-FIRST, filed in known-reds.txt).
/// `node_b` lays an ordinary block at a height (`produce` folds it at the tip, record_fold_depth 0), then receives a
/// SIBLING at the same height — here its own rewritten copy re-carrying an already-applied wrapped mint. The peer
/// `node_a`, which never held the first sibling, folds the late block and strips the re-carried note (1 record). `node_b`
/// keeps the note in TWO records: the late sibling landed below its moving fold cursor, so the fold that strips a
/// refused or re-carried object's notes never ran on it — the same never-folded class DB-379 names for an honest block.
/// Two honest nodes holding one block set disagree on a note's records. Fix is lane-consensus's (DB-379 re-walk).
#[test]
fn db379_a_late_sibling_re_carrying_a_mint_leaves_its_note_unstripped_on_the_node_that_folded_past_it() {
    let dep = [0x56u8; 32];
    let (mut node_a, mut node_b, cm, wire) = wm_published(dep, "bc1prolewmdb379");
    wm_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &dep, &cm, 4_000, b"wm-db379-honest");
    let carriage = crate::chain_object::carriage_of(&wire).expect("the honest object has a carriage form");
    let late = dd_rogue_block_carrying(&mut node_b, carriage, wm_note_body(&wire), wm_tag(&dep), 8_000, b"wm-db379-late");
    both_judge(&mut node_a, &mut node_b, late, 8_500, "a late sibling re-carrying an applied wrapped mint");
    let (at_graft_a, at_graft_b) = (cm_occurrences(&node_a, &cm), cm_occurrences(&node_b, &cm));
    // SETTLE (lane-consensus §9.3 ask, 19:48): if the late sibling LOST the tie-break on node_b it is a side block whose
    // record was written at graft and folds only when the NEXT chain block merges it — a measurement taken before any later
    // block reads that transient. One more block each way (both merge every tip) before the verdict.
    let next_b = node_b.produce(10_000, Hash32::hash(b"wm-db379-next-b"), Hash32::hash(b"mc")).expect("node_b produces on");
    let _ = node_a.ingest_block(next_b, 10_500);
    let next_a = node_a.produce(11_000, Hash32::hash(b"wm-db379-next-a"), Hash32::hash(b"mc")).expect("node_a produces on");
    let _ = node_b.ingest_block(next_a, 11_500);
    let _ = node_a.fold_canonical_records();
    let _ = node_b.fold_canonical_records();
    let (on_a, on_b) = (cm_occurrences(&node_a, &cm), cm_occurrences(&node_b, &cm));
    eprintln!(
        "[rogue-role] MEASURED DB-379 class: the re-carried note's records — at graft node_a {at_graft_a} / node_b {at_graft_b}; after one more block each way node_a {on_a} / node_b {on_b}"
    );
    assert_eq!(on_a, 1, "CALIBRATION: the node that never held the first sibling strips the re-carried note");
    assert_eq!(on_b, 1, "⛔ DB-379: the node that folded past the height keeps a re-carried note in a second record — two honest nodes, one block set, two ledgers of records");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — WrappedMint × BURN, through a peer: a REFUSED mint naming the victim's deposit key — the
/// honest object with its validity carrier corrupted, so it proves nothing — carried by the rogue `node_b` with the
/// deposit's one-time id in its lane. The refused object must cost the victim nothing: the peer mints nothing from it,
/// and the real mint then lands on both nodes, its note exactly once.
#[test]
fn a_refused_wrapped_mint_naming_a_deposit_does_not_stop_its_real_mint_on_the_peer() {
    let dep = [0x55u8; 32];
    let (mut node_a, mut node_b, cm, wire) = wm_published(dep, "bc1prolewmburn");
    let commits = node_a.peg().wrapped_asset_commits(WM_ASSET);
    let broken = wm_rewired(&wire, |p| {
        let mid = p.2.len() / 2;
        p.2[mid] ^= 0x01;
    });
    let carriage = crate::chain_object::carriage_of(&broken).expect("a corrupted carrier still decodes: it is judged at the apply");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, wm_note_body(&wire), wm_tag(&dep), 4_000, b"wm-burn-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 4_500, "a refused wrapped mint naming the victim's deposit key");
    wm_nothing_moved(&node_a, &node_b, &dep, &cm, &commits, "a wrapped mint whose validity carrier proves nothing");
    wm_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &dep, &cm, 6_000, b"wm-burn-settle");
}

// ═══════════════════════════════════════════ PriceMark ═══════════════════════════════════════════

/// The bonded validator's signed quote of `price` for `(epoch, WM_ASSET)` — the quote the DB-240 lane gathers.
fn pm_quote(pk: &[u8], sk: &[u8], epoch: u64, price: u128) -> crate::price_mark_tx::PriceQuote {
    crate::price_mark_tx::PriceQuote {
        price,
        pubkey: pk.to_vec(),
        sig: crate::pqauth::ml_dsa_sign(&crate::peg::PegLedger::price_mark_msg(epoch, WM_ASSET, price), sk)
            .expect("the key signs its quote"),
    }
}

fn pm_header(epoch: u64) -> crate::price_mark_tx::PriceMarkHeader {
    crate::price_mark_tx::PriceMarkHeader { epoch_id: epoch, asset_id: WM_ASSET }
}

/// The price each node stands on for the asset, as `(price, epoch)`.
fn pm_marks(node_a: &Node, node_b: &Node) -> (Option<(u128, u64)>, Option<(u128, u64)>) {
    let read = |n: &Node| n.price_mark_for(WM_ASSET).map(|m| (m.price, m.epoch_id));
    (read(node_a), read(node_b))
}

/// CONTROL: the bonded quorum's honest mark for `epoch` rides `node_a`'s block and BOTH nodes stand on it.
fn pm_the_honest_mark_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, pk: &[u8], sk: &[u8], epoch: u64, price: u128, at: u64, seed: &[u8]) {
    let bits = node_a.mempool().required_stamp_bits();
    let tx = crate::price_mark_tx::as_pq_tx(&pm_header(epoch), &[pm_quote(pk, sk, epoch, price)], bits);
    assert!(node_a.ingest_tx(tx).is_ok(), "node_a pools the honest mark");
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest mark");
    assert!(!honest.credit_set.is_empty(), "node_a laid its pooled mark in the block");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    assert_eq!(pm_marks(node_a, node_b), (Some((price, epoch)), Some((price, epoch))), "CONTROL: both nodes stand on the honest mark");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PriceMark × FORGE, through a peer: a mark whose only quote is signed by a key holding NO
/// bond (zero attested weight), at a price 10× the honest one, carried by the rogue `node_b`. The peer `node_a` stands on
/// no mark; CONTROL: the bonded quorum's honest mark then lands on both nodes.
#[test]
fn an_under_attested_price_mark_carried_by_a_rogue_producer_moves_no_peer_price() {
    let (mut node_a, mut node_b, pk, sk) = wm_pair();
    let (spk, ssk) = crate::pqauth::ml_dsa_keypair();
    let forged = crate::price_mark_tx::wire(&pm_header(1), &[pm_quote(&spk, &ssk, 1, 150_000)]);
    let carriage = crate::chain_object::carriage_of(&forged).expect("an unbonded quote still decodes: the tally is the door's");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, Vec::new(), cover_tag(), 4_000, b"pm-forge-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 4_500, "a price mark quoted by a key holding no bond");
    assert_eq!(pm_marks(&node_a, &node_b), (None, None), "⛔ ROGUE PRODUCER: an under-attested mark set a price on the peer");
    pm_the_honest_mark_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, 1, 15_000, 6_000, b"pm-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PriceMark × STRIP, through a peer: a mark with its quotes REMOVED (the codec refuses an empty
/// list, so the rogue lays the raw bytes). The peer stands on no mark; the honest mark then lands on both.
#[test]
fn a_price_mark_stripped_of_its_quotes_carried_by_a_rogue_producer_moves_no_peer_price() {
    let (mut node_a, mut node_b, pk, sk) = wm_pair();
    let stripped = crate::price_mark_tx::wire(&pm_header(1), &[]);
    let rogue = dd_rogue_block_carrying(&mut node_b, stripped, Vec::new(), cover_tag(), 4_000, b"pm-strip-rogue");
    both_judge_strip(&mut node_a, &mut node_b, rogue, 4_500, "a price mark with NO quotes");
    assert_eq!(pm_marks(&node_a, &node_b), (None, None), "⛔ ROGUE PRODUCER: a quote-less mark set a price on the peer");
    pm_the_honest_mark_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, 1, 15_000, 6_000, b"pm-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PriceMark × SUBSTITUTE, through a peer: the bonded validator's real quote of 15,000 with its
/// PRICE swapped to 150,000 under the signature (each quote is signed over its OWN price). The peer stands on no mark;
/// the honest mark then lands on both.
#[test]
fn a_price_mark_whose_price_was_swapped_under_its_signature_carried_by_a_rogue_producer_moves_no_peer_price() {
    let (mut node_a, mut node_b, pk, sk) = wm_pair();
    let mut swapped = pm_quote(&pk, &sk, 1, 15_000);
    swapped.price = 150_000;
    let blob = crate::price_mark_tx::wire(&pm_header(1), &[swapped]);
    let carriage = crate::chain_object::carriage_of(&blob).expect("a swapped price still decodes: the signature is the door's");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, Vec::new(), cover_tag(), 4_000, b"pm-swap-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 4_500, "a price mark whose price was swapped under the signature");
    assert_eq!(pm_marks(&node_a, &node_b), (None, None), "⛔ ROGUE PRODUCER: a mark with a swapped price set it on the peer");
    pm_the_honest_mark_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, 1, 15_000, 6_000, b"pm-swap-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PriceMark × REPLAY (a stale mark), through a peer: the honest epoch-1 mark (15,000) lands on
/// both nodes, then the honest epoch-2 mark (9,000 — the market fell). The rogue `node_b` re-carries the epoch-1 object.
/// The door's epoch is strictly monotone per asset, so the peer `node_a` keeps standing on the epoch-2 price — a stale
/// mark cannot roll a price back (which would un-trigger a due liquidation or over-cover a mint).
#[test]
fn a_stale_price_mark_re_carried_by_a_rogue_producer_does_not_roll_back_the_peer_price() {
    let (mut node_a, mut node_b, pk, sk) = wm_pair();
    pm_the_honest_mark_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, 1, 15_000, 4_000, b"pm-replay-e1");
    let stale = crate::price_mark_tx::wire(&pm_header(1), &[pm_quote(&pk, &sk, 1, 15_000)]);
    pm_the_honest_mark_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, 2, 9_000, 7_000, b"pm-replay-e2");
    let carriage = crate::chain_object::carriage_of(&stale).expect("the honest epoch-1 object has a carriage form");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, Vec::new(), cover_tag(), 10_000, b"pm-replay-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 10_500, "a re-carried epoch-1 price mark after epoch 2");
    assert_eq!(
        pm_marks(&node_a, &node_b),
        (Some((9_000, 2)), Some((9_000, 2))),
        "⛔ ROGUE PRODUCER: a stale re-carried mark rolled the price back on the peer"
    );
}

// ═══════════════════════════════════════ WrappedAssetRegister ═══════════════════════════════════════

/// A wrapped asset NOT registered by the pair fixture (which registers `WM_ASSET` directly) — these cells register it
/// through the chain object.
const WR_ASSET: u32 = 12;

fn wr_header(epoch: u64, prev: u32, ratio: u32) -> crate::wrapped_asset_tx::WrappedAssetRegisterHeader {
    crate::wrapped_asset_tx::WrappedAssetRegisterHeader { epoch_id: epoch, asset_id: WR_ASSET, prev_ratio_bps: prev, ratio_bps: ratio }
}

/// The attestation `pk`/`sk` signs over the registration message of `h`.
fn wr_attest(h: &crate::wrapped_asset_tx::WrappedAssetRegisterHeader, pk: &[u8], sk: &[u8]) -> crate::psm::MintAttestor {
    let msg = crate::peg::PegLedger::wrapped_register_msg(h.epoch_id, h.asset_id, h.prev_ratio_bps, h.ratio_bps);
    crate::psm::MintAttestor { pubkey: pk.to_vec(), sig: crate::pqauth::ml_dsa_sign(&msg, sk).expect("the key signs") }
}

fn wr_ratios(node_a: &Node, node_b: &Node) -> (Option<u32>, Option<u32>) {
    (node_a.peg().wrapped_asset_ratio_bps(WR_ASSET), node_b.peg().wrapped_asset_ratio_bps(WR_ASSET))
}

/// CONTROL: the bonded quorum's honest registration `h` rides `node_a`'s block and BOTH nodes hold its ratio.
fn wr_the_honest_registration_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, pk: &[u8], sk: &[u8], h: crate::wrapped_asset_tx::WrappedAssetRegisterHeader, at: u64, seed: &[u8]) {
    let bits = node_a.mempool().required_stamp_bits();
    let tx = crate::wrapped_asset_tx::as_pq_tx(&h, &[wr_attest(&h, pk, sk)], bits);
    assert!(node_a.ingest_tx(tx).is_ok(), "node_a pools the honest registration");
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest registration");
    assert!(!honest.credit_set.is_empty(), "node_a laid its pooled registration in the block");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    assert_eq!(wr_ratios(node_a, node_b), (Some(h.ratio_bps), Some(h.ratio_bps)), "CONTROL: both nodes hold the honest registration");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — WrappedAssetRegister × FORGE, through a peer: a registration attested only by a key holding
/// NO bond, carried by the rogue `node_b`. The peer `node_a` registers nothing; CONTROL: the bonded quorum's honest
/// registration then lands on both nodes.
#[test]
fn an_under_attested_wrapped_asset_registration_carried_by_a_rogue_producer_registers_nothing_on_the_peer() {
    let (mut node_a, mut node_b, pk, sk) = wm_pair();
    let (spk, ssk) = crate::pqauth::ml_dsa_keypair();
    let h = wr_header(1, 0, 15_000);
    let forged = crate::wrapped_asset_tx::wire(&h, &[wr_attest(&h, &spk, &ssk)]);
    let carriage = crate::chain_object::carriage_of(&forged).expect("an unbonded attestor still decodes: the tally is the door's");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, Vec::new(), cover_tag(), 4_000, b"wr-forge-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 4_500, "a wrapped-asset registration attested by a key holding no bond");
    assert_eq!(wr_ratios(&node_a, &node_b), (None, None), "⛔ ROGUE PRODUCER: an under-attested registration registered the asset on the peer");
    wr_the_honest_registration_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, h, 6_000, b"wr-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — WrappedAssetRegister × STRIP, through a peer: a registration with its attestations REMOVED
/// (the codec refuses it; the rogue lays the raw bytes). The peer registers nothing; the honest registration then lands.
#[test]
fn a_wrapped_asset_registration_stripped_of_its_attestations_carried_by_a_rogue_producer_registers_nothing_on_the_peer() {
    let (mut node_a, mut node_b, pk, sk) = wm_pair();
    let h = wr_header(1, 0, 15_000);
    let stripped = crate::wrapped_asset_tx::wire(&h, &[]);
    let rogue = dd_rogue_block_carrying(&mut node_b, stripped, Vec::new(), cover_tag(), 4_000, b"wr-strip-rogue");
    both_judge_strip(&mut node_a, &mut node_b, rogue, 4_500, "a wrapped-asset registration with NO attestations");
    assert_eq!(wr_ratios(&node_a, &node_b), (None, None), "⛔ ROGUE PRODUCER: an unattested registration registered the asset on the peer");
    wr_the_honest_registration_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, h, 6_000, b"wr-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — WrappedAssetRegister × SUBSTITUTE, through a peer: the quorum attested a 150 % ratio; the
/// rogue swaps the header to 100 % (1:1 backing — the dangerous direction: every later mint over-issues against its
/// deposit) under the same attestation. The peer registers nothing; the honest 150 % registration then lands on both.
#[test]
fn a_wrapped_asset_registration_whose_ratio_was_swapped_under_the_quorum_carried_by_a_rogue_producer_registers_nothing_on_the_peer() {
    let (mut node_a, mut node_b, pk, sk) = wm_pair();
    let h = wr_header(1, 0, 15_000);
    let att = wr_attest(&h, &pk, &sk);
    let swapped = crate::wrapped_asset_tx::wire(&wr_header(1, 0, 10_000), &[att]);
    let carriage = crate::chain_object::carriage_of(&swapped).expect("a swapped ratio still decodes: the attestation is the door's");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, Vec::new(), cover_tag(), 4_000, b"wr-swap-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 4_500, "a wrapped-asset registration whose ratio was swapped under the quorum");
    assert_eq!(wr_ratios(&node_a, &node_b), (None, None), "⛔ ROGUE PRODUCER: a registration with a swapped ratio registered the asset on the peer");
    wr_the_honest_registration_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, h, 6_000, b"wr-swap-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — WrappedAssetRegister × REPLAY, through a peer: the honest first registration (0 → 150 %)
/// lands on both nodes, then the honest retune (150 % → 200 %, epoch 2). The rogue `node_b` re-carries the FIRST object.
/// Its `prev_ratio_bps` (0) no longer matches what the peer holds — the commitment chain that makes the object
/// replay-proof — so the peer `node_a` keeps 200 %.
#[test]
fn a_wrapped_asset_registration_re_carried_by_a_rogue_producer_does_not_roll_back_the_peer_ratio() {
    let (mut node_a, mut node_b, pk, sk) = wm_pair();
    let first = wr_header(1, 0, 15_000);
    let first_blob = crate::wrapped_asset_tx::wire(&first, &[wr_attest(&first, &pk, &sk)]);
    wr_the_honest_registration_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, first, 4_000, b"wr-replay-first");
    wr_the_honest_registration_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, wr_header(2, 15_000, 20_000), 7_000, b"wr-replay-retune");
    let carriage = crate::chain_object::carriage_of(&first_blob).expect("the honest first registration has a carriage form");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, Vec::new(), cover_tag(), 10_000, b"wr-replay-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 10_500, "a re-carried first registration after a retune");
    assert_eq!(wr_ratios(&node_a, &node_b), (Some(20_000), Some(20_000)), "⛔ ROGUE PRODUCER: a re-carried registration rolled the ratio back on the peer");
}

// ═══════════════════════════════════════════ MembershipBond ═══════════════════════════════════════════

/// A BOND-LANE rogue block: the rogue POOLS `blob` past its own door (`ingest_tx_unverified`) with `lane` as the tx's
/// nullifiers (padded to the fixed width as every publisher pads), then lays its own block — so the object rides
/// `Block::bond_set` exactly as a producer that skips its door would lay it, with every root sealed by `produce`. The shape
/// `asset_tx::a_peer_does_not_credit_an_asset_transfer_whose_input_never_existed` uses for its rogue producer.
fn rogue_bond_lane_block(rogue: &mut Node, blob: Vec<u8>, lane: &[[u8; 32]], at: u64, seed: &[u8]) -> crate::block::Block {
    let id = crate::mempool::PqTx::content_id(&blob);
    let nullifiers: Vec<Hash32> = if lane.is_empty() {
        Vec::new()
    } else {
        crate::cover::pad_tx_nullifiers_to_fixed(lane, id.as_bytes()).expect("the lane pads").into_iter().map(Hash32).collect()
    };
    let mut tx = crate::mempool::PqTx {
        clock_ms: 0,
        id,
        weight: blob.len() as u32,
        blob,
        nullifiers,
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
    let need = rogue.mempool().required_stamp_bits();
    tx.pow_stamp = (0..1u64 << 24).find(|s| {
        tx.pow_stamp = *s;
        tx.stamp_work() >= need
    }).expect("the stamp grinds");
    rogue.ingest_tx_unverified(tx).expect("the rogue pools its object past its own door");
    let blk = rogue.produce(at, Hash32::hash(seed), Hash32::hash(b"rogue-mc")).expect("the rogue lays its block");
    assert!(!blk.bond_set.is_empty(), "CALIBRATION: the rogue's block carries the object on its bond lane");
    blk
}

/// The peer judges a block the rogue PRODUCED (the rogue already holds it); asserts it grafted.
fn peer_judges(node_a: &mut Node, blk: crate::block::Block, at: u64, what: &str) {
    let out = node_a.ingest_block_preverified(blk, at);
    eprintln!("[rogue-role] node_a's verdict on a block carrying {what}: {out:?}");
    assert!(matches!(out, RelayOutcome::Added(_)), "CALIBRATION: the rogue block grafts on the peer — the object reaches its class door: {out:?}");
    let _ = node_a.fold_canonical_records();
}

/// The STRIP form of `peer_judges` for the bond lane: a codec-refused object may graft and be refused at its class door,
/// or the peer may refuse the whole block structurally (`Invalid`) — both are the peer refusing it. A `Buffered` or a
/// duplicate verdict means the arm measured something else, so it fails. The verdict is printed for the record.
fn peer_judges_strip(node_a: &mut Node, blk: crate::block::Block, at: u64, what: &str) {
    let out = node_a.ingest_block_preverified(blk, at);
    eprintln!("[rogue-role] node_a's verdict on a block carrying {what}: {out:?}");
    assert!(
        matches!(out, RelayOutcome::Added(_) | RelayOutcome::Invalid(_)),
        "CALIBRATION: the peer judged the stripped object (class door or structural refusal), nothing else: {out:?}"
    );
    let _ = node_a.fold_canonical_records();
}

/// A fresh seat request for `pk` (free custody points, the key's own ML-KEM encapsulation key, a fresh one-shot nonce).
fn mb_header(ek: &[u8]) -> crate::membership_bond_tx::MembershipBondHeader {
    crate::membership_bond_tx::MembershipBondHeader {
        secp33: vec![2u8; 33],
        ed32: [9u8; 32],
        kem_ek: ek.to_vec(),
        nonce: crate::membership_bond_tx::fresh_seat_nonce(),
    }
}

fn mb_sign(pk: &[u8], sk: &[u8], h: &crate::membership_bond_tx::MembershipBondHeader) -> Vec<u8> {
    crate::pqauth::ml_dsa_sign(&crate::pqauth::validator_membership_msg(&crate::pqauth::pubkey_id(pk), &h.digest()), sk).expect("signs")
}

fn mb_right(pk: &[u8], h: &crate::membership_bond_tx::MembershipBondHeader) -> [u8; 32] {
    crate::membership_bond_tx::seat_right_nf(&crate::membership_bond_tx::validator_id(pk), h)
}

fn mb_seated(node_a: &Node, node_b: &Node, vid: &[u8; 32]) -> (bool, bool) {
    (node_a.validators().bonded_ids().contains(vid), node_b.validators().bonded_ids().contains(vid))
}

/// CONTROL: the honest seat request publishes on `node_a`, rides its block and seats the validator on BOTH nodes.
fn mb_the_honest_seat_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, pk: &[u8], sk: &[u8], h: crate::membership_bond_tx::MembershipBondHeader, at: u64, seed: &[u8]) {
    let vid = crate::pqauth::pubkey_id(pk);
    let sig = mb_sign(pk, sk, &h);
    assert_eq!(
        node_a.publish_membership_bond(pk, &sig, h),
        crate::node::AssetSpendOutcome::Published,
        "⛔ BURN: node_a refused to publish the honest seat — its one-shot right reads as already spent"
    );
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest seat");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    assert_eq!(mb_seated(node_a, node_b, &vid), (true, true), "CONTROL: the honest seat lands on both nodes");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — MembershipBond × FORGE, through a peer: a seat request for a victim's key signed by a
/// DIFFERENT key, carried with its right by the rogue `node_b`. The peer `node_a` seats no one; CONTROL: the victim's
/// own, signed request (a fresh one) then seats it on both nodes.
#[test]
fn a_seat_not_signed_by_its_key_carried_by_a_rogue_producer_seats_no_one_on_the_peer() {
    let mut node_a = crate::node::tests::dd_node();
    let mut node_b = crate::node::tests::dd_node();
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (ek, _dk) = crate::pqkem::keypair();
    let (_spk, ssk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let h = mb_header(&ek);
    let forged = crate::membership_bond_tx::wire(&h, &pk, &mb_sign(&pk, &ssk, &h)).expect("encodes");
    let rogue = rogue_bond_lane_block(&mut node_b, forged, &[mb_right(&pk, &h)], 6_000, b"mb-forge-rogue");
    peer_judges(&mut node_a, rogue, 6_500, "a seat request not signed by the key it names");
    assert_eq!(mb_seated(&node_a, &node_b, &vid), (false, false), "⛔ ROGUE PRODUCER: a seat not signed by its key seated the validator");
    mb_the_honest_seat_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, mb_header(&ek), 9_000, b"mb-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — MembershipBond × STRIP, through a peer: a genuine, signed seat request carried WITHOUT its
/// one-shot right in the block's lane (DB-258b — the bond set is a lane separate from the nullifier lane). The peer seats
/// no one; CONTROL: the same request, published honestly WITH its right, then seats on both nodes.
#[test]
fn a_seat_carried_without_its_one_shot_right_by_a_rogue_producer_seats_no_one_on_the_peer() {
    let mut node_a = crate::node::tests::dd_node();
    let mut node_b = crate::node::tests::dd_node();
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (ek, _dk) = crate::pqkem::keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let h = mb_header(&ek);
    let signed = crate::membership_bond_tx::wire(&h, &pk, &mb_sign(&pk, &sk, &h)).expect("encodes");
    let rogue = rogue_bond_lane_block(&mut node_b, signed, &[], 6_000, b"mb-strip-rogue");
    peer_judges(&mut node_a, rogue, 6_500, "a signed seat request WITHOUT its one-shot right");
    assert_eq!(mb_seated(&node_a, &node_b, &vid), (false, false), "⛔ ROGUE PRODUCER: a seat carried without its right seated the validator");
    mb_the_honest_seat_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, h, 9_000, b"mb-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — MembershipBond × SUBSTITUTE, through a peer: the victim's signed request with its custody
/// ENCAPSULATION KEY swapped for the attacker's after signing (deposits sealed to this validator would open for the
/// attacker), carried with the substituted header's right. The peer seats no one; CONTROL: the honest request seats on
/// both nodes with the key the validator signed.
#[test]
fn a_seat_whose_custody_key_was_swapped_after_signing_carried_by_a_rogue_producer_seats_no_one_on_the_peer() {
    let mut node_a = crate::node::tests::dd_node();
    let mut node_b = crate::node::tests::dd_node();
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (ek, _dk) = crate::pqkem::keypair();
    let (attacker_ek, _adk) = crate::pqkem::keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let h = mb_header(&ek);
    let sig = mb_sign(&pk, &sk, &h);
    let mut swapped = h.clone();
    swapped.kem_ek = attacker_ek;
    let blob = crate::membership_bond_tx::wire(&swapped, &pk, &sig).expect("encodes");
    let rogue = rogue_bond_lane_block(&mut node_b, blob, &[mb_right(&pk, &swapped)], 6_000, b"mb-swap-rogue");
    peer_judges(&mut node_a, rogue, 6_500, "a seat request whose custody key was swapped after signing");
    assert_eq!(mb_seated(&node_a, &node_b, &vid), (false, false), "⛔ ROGUE PRODUCER: a seat with a swapped custody key seated the validator");
    mb_the_honest_seat_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, h, 9_000, b"mb-swap-settle");
    // SATOSHI: a membership seat is a FINALITY seat — its signed KEM key is registered for it, but it is a CUSTODIAN
    // (`bonded_custodian_eks`) only once it bonds SAT (custody weight); the reserve group is SAT-weighted members only.
    assert_eq!(node_a.validators().registered_kem_ek(&vid), Some(ek.clone()), "CONTROL: node_a holds the custody key the validator SIGNED");
    assert!(!node_a.validators().bonded_custodian_eks().iter().any(|(id, _)| *id == vid), "a finality-only seat is not a reserve custodian");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — MembershipBond × REPLAY, through a peer: the honest seat lands on both nodes; the rogue
/// `node_b` re-carries the SAME signed request with its (already retired) right. The peer's validator set is unchanged:
/// the validator holds the same weight, nobody is seated twice.
#[test]
fn a_seat_request_re_carried_by_a_rogue_producer_seats_once_on_the_peer() {
    let mut node_a = crate::node::tests::dd_node();
    let mut node_b = crate::node::tests::dd_node();
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (ek, _dk) = crate::pqkem::keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let h = mb_header(&ek);
    let signed = crate::membership_bond_tx::wire(&h, &pk, &mb_sign(&pk, &sk, &h)).expect("encodes");
    mb_the_honest_seat_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, h.clone(), 6_000, b"mb-replay-honest");
    let before = (node_a.validators().len(), node_a.validators().bond_of(&vid), node_a.validators().total_bond());
    let rogue = rogue_bond_lane_block(&mut node_b, signed, &[mb_right(&pk, &h)], 9_000, b"mb-replay-rogue");
    peer_judges(&mut node_a, rogue, 9_500, "a RE-CARRIED, already applied seat request");
    let after = (node_a.validators().len(), node_a.validators().bond_of(&vid), node_a.validators().total_bond());
    assert_eq!(after, before, "⛔ ROGUE PRODUCER: a re-carried seat request changed the peer's validator set");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — MembershipBond × BURN, through a peer: a REFUSED request naming the victim's seat right —
/// the victim's own header signed by a stranger, so the forgery's right IS the victim's — carried with that right in its
/// lane by the rogue `node_b`. The refused object must cost the victim nothing: its real, signed request (the SAME
/// header, the SAME right) then publishes on `node_a` and seats on both nodes.
#[test]
fn a_refused_seat_naming_a_validators_seat_right_does_not_stop_its_real_seat_on_the_peer() {
    let mut node_a = crate::node::tests::dd_node();
    let mut node_b = crate::node::tests::dd_node();
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (ek, _dk) = crate::pqkem::keypair();
    let (_spk, ssk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let h = mb_header(&ek);
    let forged = crate::membership_bond_tx::wire(&h, &pk, &mb_sign(&pk, &ssk, &h)).expect("encodes");
    let rogue = rogue_bond_lane_block(&mut node_b, forged, &[mb_right(&pk, &h)], 6_000, b"mb-burn-rogue");
    peer_judges(&mut node_a, rogue, 6_500, "a refused seat request naming the victim's seat right");
    assert_eq!(mb_seated(&node_a, &node_b, &vid), (false, false), "the forged request seated no one");
    mb_the_honest_seat_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, h, 9_000, b"mb-burn-settle");
}

// ═══════════════════════════════════════════ Equivocation ═══════════════════════════════════════════

/// Two conflicting blocks at ONE height held by BOTH nodes (each produces one and grafts the other's), and a validator
/// `V` bonded 50,000 on both — the `db266` evidence fixture. Returns the two blocks, their height and V's keys.
fn eq_fixture(node_a: &mut Node, node_b: &mut Node) -> (crate::block::Block, crate::block::Block, u64, Vec<u8>, Vec<u8>, [u8; 32]) {
    let x = node_a.produce(4_500, Hash32::hash(b"eq-x"), Hash32::hash(b"eq-mc")).expect("node_a produces X");
    let y = node_b.produce(4_600, Hash32::hash(b"eq-y"), Hash32::hash(b"eq-mc")).expect("node_b produces Y");
    assert!(matches!(node_a.ingest_block(y.clone(), 5_000), RelayOutcome::Added(_)), "node_a holds Y");
    assert!(matches!(node_b.ingest_block(x.clone(), 5_000), RelayOutcome::Added(_)), "node_b holds X");
    let h = node_a.dag().get(&x.id()).map(|n| n.blue_score).expect("X in node_a's DAG");
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let mut locked = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    locked[..32].copy_from_slice(&Hash32::hash(b"eq-locked").0);
    node_a.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
    node_b.admit_bond_unverified(vid, 50_000, locked, 0);
    (x, y, h, pk, sk, vid)
}

fn eq_vote(blk: &crate::block::Block, height: u64, pk: &[u8], sk: &[u8]) -> crate::validator::VoteCert {
    crate::validator::VoteCert {
        pubkey: pk.to_vec(),
        block: blk.id(),
        height,
        sig: crate::pqauth::ml_dsa_sign(&crate::pqauth::finality_vote_msg(&blk.id(), height), sk).expect("a vote signs"),
    }
}

fn eq_bonds(node_a: &Node, node_b: &Node, vid: &[u8; 32]) -> (u128, u128) {
    (node_a.validators().bond_of(vid), node_b.validators().bond_of(vid))
}

/// CONTROL: the honest evidence (V's two signed votes at one height) publishes on `node_a`, rides its block and slashes
/// V on BOTH nodes at the fold.
fn eq_the_honest_evidence_slashes_on_both_nodes(
    node_a: &mut Node,
    node_b: &mut Node,
    vx: &crate::validator::VoteCert,
    vy: &crate::validator::VoteCert,
    vid: &[u8; 32],
    at: u64,
    seed: &[u8],
) {
    assert_eq!(node_a.publish_equivocation(vx, vy), crate::node::AssetSpendOutcome::Published, "node_a publishes the honest evidence");
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the evidence");
    assert!(!honest.bond_set.is_empty(), "the evidence rides the validator-object lane");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    assert_eq!(eq_bonds(node_a, node_b, vid), (0, 0), "CONTROL: the honest evidence slashed V on both nodes");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — Equivocation × FORGE, through a peer: evidence against an INNOCENT validator — its one real
/// vote paired with a second "vote" naming its key but signed by a stranger — carried by the rogue `node_b`. The peer
/// `node_a` slashes nothing; CONTROL: genuine evidence (V really signed both) then slashes V on both nodes.
#[test]
fn equivocation_evidence_not_signed_by_the_accused_carried_by_a_rogue_producer_slashes_no_one_on_the_peer() {
    let mut node_a = crate::node::tests::dd_node();
    let mut node_b = crate::node::tests::dd_node();
    let (x, y, h, pk, sk, vid) = eq_fixture(&mut node_a, &mut node_b);
    let (_spk, ssk) = crate::pqauth::ml_dsa_keypair();
    let vx = eq_vote(&x, h, &pk, &sk);
    let framed_y = eq_vote(&y, h, &pk, &ssk);
    let blob = crate::equivocation_tx::wire(&vx, &framed_y).expect("the forged evidence frames");
    let rogue = rogue_bond_lane_block(&mut node_b, blob, &[], 6_000, b"eq-forge-rogue");
    peer_judges(&mut node_a, rogue, 6_500, "equivocation evidence whose second vote V never signed");
    assert_eq!(eq_bonds(&node_a, &node_b, &vid), (50_000, 50_000), "⛔ ROGUE PRODUCER: evidence V never signed slashed an innocent validator");
    eq_the_honest_evidence_slashes_on_both_nodes(&mut node_a, &mut node_b, &vx, &eq_vote(&y, h, &pk, &sk), &vid, 9_000, b"eq-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — Equivocation × SUBSTITUTE, through a peer: two votes V REALLY signed, but at DIFFERENT
/// heights (one vote per height is honest), presented as one height. The peer slashes nothing; CONTROL: genuine
/// one-height evidence then slashes V on both nodes.
#[test]
fn two_votes_at_different_heights_presented_as_equivocation_by_a_rogue_producer_slash_no_one_on_the_peer() {
    let mut node_a = crate::node::tests::dd_node();
    let mut node_b = crate::node::tests::dd_node();
    let (x, y, h, pk, sk, vid) = eq_fixture(&mut node_a, &mut node_b);
    let vx = eq_vote(&x, h, &pk, &sk);
    let mut vy_other_height = eq_vote(&y, h + 1, &pk, &sk);
    vy_other_height.height = h;
    let blob = crate::equivocation_tx::wire(&vx, &vy_other_height).expect("the substituted evidence frames");
    let rogue = rogue_bond_lane_block(&mut node_b, blob, &[], 6_000, b"eq-swap-rogue");
    peer_judges(&mut node_a, rogue, 6_500, "two votes at different heights presented as one");
    assert_eq!(eq_bonds(&node_a, &node_b, &vid), (50_000, 50_000), "⛔ ROGUE PRODUCER: two honest votes at two heights slashed the validator");
    eq_the_honest_evidence_slashes_on_both_nodes(&mut node_a, &mut node_b, &vx, &eq_vote(&y, h, &pk, &sk), &vid, 9_000, b"eq-swap-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — Equivocation × REPLAY, through a peer: genuine evidence slashes V on both nodes; the rogue
/// `node_b` re-carries the SAME evidence. The voter is removed and barred, so the replay moves nothing: V stays at zero
/// and the peer's validator count and total bonded weight are unchanged.
#[test]
fn equivocation_evidence_re_carried_by_a_rogue_producer_after_the_slash_moves_nothing_on_the_peer() {
    let mut node_a = crate::node::tests::dd_node();
    let mut node_b = crate::node::tests::dd_node();
    let (x, y, h, pk, sk, vid) = eq_fixture(&mut node_a, &mut node_b);
    let (vx, vy) = (eq_vote(&x, h, &pk, &sk), eq_vote(&y, h, &pk, &sk));
    eq_the_honest_evidence_slashes_on_both_nodes(&mut node_a, &mut node_b, &vx, &vy, &vid, 6_000, b"eq-replay-honest");
    let before = (node_a.validators().len(), node_a.validators().total_bond());
    let blob = crate::equivocation_tx::wire(&vx, &vy).expect("the honest evidence frames");
    let rogue = rogue_bond_lane_block(&mut node_b, blob, &[], 9_000, b"eq-replay-rogue");
    peer_judges(&mut node_a, rogue, 9_500, "RE-CARRIED equivocation evidence after the slash");
    assert_eq!(node_a.validators().bond_of(&vid), 0, "the slashed voter stays slashed");
    assert_eq!((node_a.validators().len(), node_a.validators().total_bond()), before, "⛔ ROGUE PRODUCER: re-carried evidence moved the peer's validator set again");
}

// ═══════════════════════════════════════════════ Unbond ═══════════════════════════════════════════════

/// V's unbond statement for THIS chain's live bonding of V (`bond_instance_of`), the returned note's clue and `nonce`.
fn ub_header(node: &Node, vid: &[u8; 32], clue: &[u8], nonce: [u8; 32]) -> crate::unbond_tx::UnbondHeader {
    crate::unbond_tx::UnbondHeader {
        owner_clue_digest: crate::oli::owner_clue_digest(clue),
        bond_instance: node.bond_instance_of(vid).expect("V holds an anchored bonding"),
        nonce,
    }
}

fn ub_sign(vid: &[u8; 32], h: &crate::unbond_tx::UnbondHeader, sk: &[u8]) -> Vec<u8> {
    crate::pqauth::ml_dsa_sign(&crate::pqauth::validator_unbond_msg(vid, &h.bond_instance, &h.owner_clue_digest, &h.nonce), sk).expect("signs")
}

fn ub_clue() -> Vec<u8> {
    let (ek, _dk) = crate::pqkem::keypair();
    crate::unbond_tx::unbond_clue_for_test(&crate::account_da::bucket_id(b"rogue-role-unbond-owner"), &ek)
}

/// CONTROL: V's honest unbond (signed by V, nonce `nonce`) publishes on `node_a`, rides its block, and after the fold V
/// holds NO weight on BOTH nodes. Returns the ts after the fold.
fn ub_the_honest_unbond_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, pk: &[u8], sk: &[u8], vid: &[u8; 32], clue: &[u8], nonce: [u8; 32], at: u64, seed: &[u8]) -> u64 {
    let h = ub_header(node_a, vid, clue, nonce);
    assert_eq!(
        node_a.publish_unbond(pk, &ub_sign(vid, &h, sk), clue, nonce),
        crate::node::AssetSpendOutcome::Published,
        "⛔ BURN: node_a refused V's honest unbond — its one-shot right reads as already spent"
    );
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the unbond");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    let ts = node_a.fold_past_for_test(&mut [&mut *node_b], at + 2_000, seed);
    assert_eq!((node_a.validators().bond_of(vid), node_b.validators().bond_of(vid)), (0, 0), "CONTROL: V's honest unbond released its weight on both nodes");
    ts
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — Unbond × FORGE, through a peer: an unbond of V's bond signed by a key that is NOT the bond's
/// owner, carried with its right by the rogue `node_b`. Past the fold, the peer `node_a` still holds V's full weight;
/// CONTROL: V's own signed unbond (a fresh nonce) then releases it on both nodes.
#[test]
fn an_unbond_not_signed_by_the_bonds_owner_carried_by_a_rogue_producer_releases_nothing_on_the_peer() {
    let (mut node_a, mut node_b, pk, sk, vid, _locked) = crate::chain_action_carriage_tests::tests::db257_bonded_pair(b"rr-ub-forge");
    let (_spk, ssk) = crate::pqauth::ml_dsa_keypair();
    let clue = ub_clue();
    let h = ub_header(&node_b, &vid, &clue, crate::unbond_tx::fresh_unbond_nonce());
    let forged = crate::unbond_tx::wire(&h, &pk, &ub_sign(&vid, &h, &ssk), &clue).expect("the forged unbond frames");
    let right = crate::unbond_tx::unbond_right_nf(&vid, &h);
    let rogue = rogue_bond_lane_block(&mut node_b, forged, &[right], 5_500, b"ub-forge-rogue");
    peer_judges(&mut node_a, rogue, 6_000, "an unbond of V's bond not signed by V");
    let ts = node_a.fold_past_for_test(&mut [&mut node_b], 7_000, b"ub-forge-fold");
    assert_eq!(
        (node_a.validators().bond_of(&vid), node_b.validators().bond_of(&vid)),
        (50_000, 50_000),
        "⛔ ROGUE PRODUCER: an unbond V never signed released V's bond"
    );
    let _ = ub_the_honest_unbond_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, &vid, &clue, crate::unbond_tx::fresh_unbond_nonce(), ts + 1_000, b"ub-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — Unbond × BURN, through a peer: a REFUSED unbond naming V's unbond right — V's own statement
/// (the SAME nonce, so the SAME one-shot right) signed by a stranger — carried with that right in its lane by the rogue
/// `node_b`. The refused object must cost V nothing: V's real unbond with that nonce then publishes on `node_a` and
/// releases V on both nodes.
#[test]
fn a_refused_unbond_naming_a_validators_unbond_right_does_not_stop_its_real_unbond_on_the_peer() {
    let (mut node_a, mut node_b, pk, sk, vid, _locked) = crate::chain_action_carriage_tests::tests::db257_bonded_pair(b"rr-ub-burn");
    let (_spk, ssk) = crate::pqauth::ml_dsa_keypair();
    let clue = ub_clue();
    let nonce = crate::unbond_tx::fresh_unbond_nonce();
    let h = ub_header(&node_b, &vid, &clue, nonce);
    let forged = crate::unbond_tx::wire(&h, &pk, &ub_sign(&vid, &h, &ssk), &clue).expect("the forged unbond frames");
    let rogue = rogue_bond_lane_block(&mut node_b, forged, &[crate::unbond_tx::unbond_right_nf(&vid, &h)], 5_500, b"ub-burn-rogue");
    peer_judges(&mut node_a, rogue, 6_000, "a refused unbond naming V's unbond right");
    let ts = node_a.fold_past_for_test(&mut [&mut node_b], 7_000, b"ub-burn-fold");
    assert_eq!(node_a.validators().bond_of(&vid), 50_000, "the forged unbond released nothing");
    let _ = ub_the_honest_unbond_lands_on_both_nodes(&mut node_a, &mut node_b, &pk, &sk, &vid, &clue, nonce, ts + 1_000, b"ub-burn-settle");
}

// ═══════════════════════ H11 — ECONOMIC ADVERSARY: ORACLE COLLUSION (DB-381 §2.1 / §2.2) ═══════════════════════

const ORACLE_HONEST: u128 = 15_000;

/// The quorum pair widened to `n` equal-weight bonded custodians (20,000 each — the pair fixture's own weight) seated on
/// BOTH nodes. Signer 0 is the colluder.
fn oracle_quorum(n: usize) -> (Node, Node, Vec<(Vec<u8>, Vec<u8>)>) {
    let (mut node_a, mut node_b, pk0, sk0) = wm_pair();
    let mut keys = vec![(pk0, sk0)];
    for _ in 1..n {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let vid = crate::pqauth::pubkey_id(&pk);
        node_a.admit_validator(vid, 20_000, 0).expect("seats on node_a");
        node_b.admit_validator(vid, 20_000, 0).expect("seats on node_b");
        keys.push((pk, sk));
    }
    (node_a, node_b, keys)
}

/// ONE ROGUE-PRODUCER ATTEMPT: on a fresh quorum of `n`, the rogue `node_b` carries a mark whose quotes are exactly the
/// signers in `subset` (bit i = signer i) — the colluder (signer 0) quoting `colluder_price`, every honest signer quoting
/// `ORACLE_HONEST`. Every quote is GENUINELY SIGNED by its signer (honest quotes are public: the DB-240 lane gossips them),
/// so the only adversarial choice is WHICH quotes the block carries. Returns the price each node then stands on.
fn oracle_attempt(n: usize, colluder_price: u128, subset: u32) -> (Option<u128>, Option<u128>) {
    let (mut node_a, mut node_b, keys) = oracle_quorum(n);
    let quotes: Vec<crate::price_mark_tx::PriceQuote> = (0..n)
        .filter(|i| subset >> i & 1 == 1)
        .map(|i| pm_quote(&keys[i].0, &keys[i].1, 1, if i == 0 { colluder_price } else { ORACLE_HONEST }))
        .collect();
    let carriage = crate::chain_object::carriage_of(&crate::price_mark_tx::wire(&pm_header(1), &quotes)).expect("a genuine quote set decodes");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, Vec::new(), cover_tag(), 4_000, b"oracle-subset");
    both_judge(&mut node_a, &mut node_b, rogue, 4_500, "a price mark of a producer-chosen quote subset");
    let (a, b) = pm_marks(&node_a, &node_b);
    (a.map(|m| m.0), b.map(|m| m.0))
}

/// Every quote subset a rogue producer can carry that MEETS the ≥ 2/3 tally (equal weights: ⌈2n/3⌉ signers or more),
/// with the colluder quoting 10× high and 10× low. Returns every (colluder price, subset, peer price) where the peer
/// stood on a price other than the honest one, and how many attempts set a mark at all.
fn oracle_violations(n: usize) -> (Vec<(u128, u32, Option<u128>)>, usize) {
    let need = (2 * n).div_ceil(3);
    let mut bad = Vec::new();
    let mut marked = 0usize;
    for colluder_price in [ORACLE_HONEST * 10, ORACLE_HONEST / 10] {
        for subset in 1u32..(1u32 << n) {
            if (subset.count_ones() as usize) < need {
                continue;
            }
            // The PEER's verdict is the claim. The rogue's own node folded its unmutated sibling at that height first, so
            // it never folds the rewritten copy — MEASURED 2026-10-04 batch 4 (`Some(15000)` vs `None`): the DB-379 class,
            // pinned on its own by `db379_a_late_sibling_re_carrying_a_mint_leaves_its_note_unstripped_on_the_node_that_folded_past_it`.
            let (on_a, _on_rogue) = oracle_attempt(n, colluder_price, subset);
            marked += usize::from(on_a.is_some());
            if on_a.is_some_and(|p| p != ORACLE_HONEST) {
                bad.push((colluder_price, subset, on_a));
            }
        }
    }
    eprintln!("[oracle-sim] MEASURED n={n} (colluder = 1 signer, {:.0}% of the bond): {marked} carried subsets set a mark; manipulated marks {bad:?}", 100.0 / n as f64);
    (bad, marked)
}

/// ⛔⛔⛔ H11 DB-381 §2.1 — ORACLE COLLUSION BELOW THE BOUND, through a peer. Four equal custodians; the colluder holds 25 %
/// of the bond (< 1/3) and quotes 10× high, then 10× low. The rogue producer tries EVERY quote subset that meets the
/// ≥ 2/3 tally (its one free choice). The peer must stand on the honest price after every one: the bond-weighted median
/// of any threshold-meeting set is honest while the colluder holds < 1/3. CALIBRATION: some subsets mark at all (the
/// honest-only and mixed sets), so a green run is not a door that refuses everything.
#[test]
fn an_oracle_colluder_below_a_third_of_the_bond_cannot_move_the_mark_with_any_quote_subset_a_rogue_producer_carries() {
    let (bad, marked) = oracle_violations(4);
    assert!(marked > 0, "CALIBRATION: threshold-meeting quote sets mark a price on the peer");
    assert!(bad.is_empty(), "⛔ ORACLE: a colluder with 25 % of the bond moved the peer's mark: {bad:?}");
}

/// ⛔⛔⛔ H11 DB-381 §2.2 → DB-387 — THE BOUND AT EXACTLY ONE THIRD, CLOSED (user ruling 2026-10-04, fix A). Three equal
/// custodians, the colluder holds EXACTLY 1/3. MEASURED before the fix (lane-harness, 2026-10-04 16:40): a rogue producer
/// carrying {colluder quoting 10× low, ONE honest quote} met the ≥ 2/3 tally (`attested·3 ≥ total·2`) and the median walk
/// returned the FIRST price where cumulative counted weight reaches half (`2·acc ≥ total`) — the LOWER median, the
/// colluder's — so one third of the bond set the price DOWN at will (a healthy position became liquidatable). The mark's
/// tally is now STRICTLY more than two thirds (`peg::mark_price_attested`, `2f + 1` of `3f + 1`): a 2-of-3 set marks
/// nothing, the 3-of-3 set (one colluder, two honest) marks the honest median. This pin asserts the move does NOT happen in
/// either direction at exactly 1/3, and — CALIBRATION — that the full set still marks at all (the door is not shut).
#[test]
fn an_oracle_colluder_holding_one_third_of_the_bond_cannot_move_the_mark_in_either_direction() {
    let (bad, marked) = oracle_violations(3);
    assert!(marked > 0, "CALIBRATION: the full (3-of-3) quote set still marks a price on the peer — the door is open");
    assert!(
        bad.is_empty(),
        "⛔ DB-387 REOPENED: a colluder holding exactly 1/3 of the bond moved the peer's mark (down or up) — the mark's tally \
         must be strictly more than 2/3 of bonded weight: {bad:?}"
    );
}

// ═══════════════════════════════════════════ BridgeCredit ═══════════════════════════════════════════

/// Two MAINNET nodes (open-mint allowance 0, so every credit needs the bonded quorum) folding at the tip, with one bonded
/// validator seated on both. Returns the nodes and the validator's keys.
fn bc_mainnet_pair() -> (Node, Node, Vec<u8>, Vec<u8>) {
    let node = || {
        let mut p = crate::params::ChainParams::default();
        p.genesis_parity_commit = crate::params::network_genesis_prefix("mainnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        p.record_fold_depth = 0;
        let mut g = crate::node::tests::genesis_block();
        g.header = crate::block::genesis_header_for_network(&crate::params::network_genesis_prefix("mainnet"));
        Node::with_params(g, p).expect("a mainnet node builds")
    };
    let (mut node_a, mut node_b) = (node(), node());
    assert_eq!(node_a.params().genesis_mint_allowance(), 0, "PRECONDITION: mainnet derives no open mint — every credit here needs the quorum");
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    node_a.admit_validator(vid, 20_000, 0).expect("seats on node_a");
    node_b.admit_validator(vid, 20_000, 0).expect("seats on node_b");
    (node_a, node_b, pk, sk)
}

/// A credit of 25 USDm-units against one foreign deposit, attested by the bonded validator over
/// `bridge_credit_msg(deposit, asset, amount, cm, owner)`.
fn bc_attested(tag: &[u8], pk: &[u8], sk: &[u8]) -> crate::bridge_credit_tx::BridgeCreditTx {
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&Hash32::hash(tag).0);
    let mut c = crate::bridge_credit_tx::BridgeCreditTx {
        deposit_id: Hash32::hash(b"rogue-role foreign deposit").0,
        asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
        amount: 25_000_000,
        note,
        owner_clue: Vec::new(),
        attestors: Vec::new(),
    };
    let cm = c.note_cm().expect("cm");
    let msg = crate::peg::PegLedger::bridge_credit_msg(&c.deposit_id, &c.asset_tag, c.amount, &cm, &c.owner_clue);
    c.attestors = vec![(pk.to_vec(), crate::pqauth::ml_dsa_sign(&msg, sk).expect("the bonded validator signs"))];
    c
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — BridgeCredit × SUBSTITUTE, through a peer, on MAINNET: the bonded validator attested a credit
/// of note N; the rogue `node_b` swaps the credited NOTE for one it chose (any value) under that attestation, and lays
/// it — past its own assembly door, the shape `an_attested_mainnet_credit_lands_on_the_peer_at_graft_and_an_unattested_
/// one_does_not` models a modified binary with (staged note + its object as justifier). The peer `node_a` records neither
/// note; CONTROL: the honest attested credit then lands on both nodes exactly once (the refused copy did not spend the
/// deposit in the credit ledger).
#[test]
fn a_credit_whose_note_was_swapped_under_its_attestation_carried_by_a_rogue_producer_credits_nothing_on_the_peer() {
    let (mut node_a, mut node_b, pk, sk) = bc_mainnet_pair();
    let honest = bc_attested(b"rogue-role credit note", &pk, &sk);
    let honest_cm = honest.note_cm().expect("cm");
    let mut swapped = honest.clone();
    swapped.note[..32].copy_from_slice(&Hash32::hash(b"a credit note the quorum never attested").0);
    let swapped_cm = swapped.note_cm().expect("cm");
    node_b.stage_credit_note(swapped.note.clone());
    node_b.stage_credit_justifier(swapped.wire());
    let rogue = node_b.produce(5_000, Hash32::hash(b"bc-swap-rogue"), Hash32::hash(b"rogue-mc")).expect("the rogue lays its block");
    assert!(
        rogue.output_notes.chunks(crate::cover::PQ_NOTE_BYTES).any(|n| n.len() >= 32 && n[..32] == swapped_cm),
        "CALIBRATION: the rogue's block genuinely CARRIES the swapped note — else this measures the rogue's own door"
    );
    peer_judges(&mut node_a, rogue, 5_500, "a mainnet credit whose note was swapped under its attestation");
    assert!(!node_a.holds_record_with_cm(&swapped_cm), "⛔⛔⛔ ROGUE PRODUCER: the peer recorded a credit note no bonded quorum attested — a mint of any value");
    let bits = node_a.required_stamp_bits();
    assert!(node_a.ingest_tx(honest.as_pq_tx(bits)).is_ok(), "⛔ BURN: node_a's pool refused the honest attested credit after the rogue copy");
    let blk = node_a.produce(7_000, Hash32::hash(b"bc-swap-honest"), Hash32::hash(b"mc")).expect("node_a lays the honest credit");
    dd_graft_then_settle(&mut node_a, &mut node_b, blk, 7_500, b"bc-swap-settle");
    assert_eq!(cm_occurrences(&node_a, &honest_cm), 1, "CONTROL: the honest credit sits in exactly one record on node_a");
    assert_eq!(cm_occurrences(&node_b, &honest_cm), 1, "CONTROL: the honest credit sits in exactly one record on node_b");
}

// ═══════════════════════════════════════════════ AssetMint ═══════════════════════════════════════════════

/// A token created on `node_a` and grafted on `node_b` (both folding at the tip) by the creator key `pk` — the
/// `asset_tx::a_second_mint_of_one_asset_carried_by_a_rogue_producer_credits_no_peer` fixture's creation.
fn am_created_pair(symbol: &str, pk: &[u8]) -> (Node, Node, crate::asset_tx::AssetCreateTx) {
    let mk = crate::node::tests::testnet_party_folding_at_tip; // §BR-14: the testnet identity funds the creation fee
    let (mut node_a, mut node_b) = (mk(), mk());
    let name = "rogue-role census token";
    let mut c = crate::asset_tx::AssetCreateTx {
        kind: crate::asset_tx::AssetKind::Token,
        symbol: symbol.to_string(),
        name: name.to_string(),
        logo: [0u8; 32],
        bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, symbol, name).bytecode,
        creator: crate::pqauth::pubkey_id(pk),
        asset_id: [0u8; 32],
        fee: crate::asset_tx::CreationFee::default(),
        art: Vec::new(),
        supply: None,
    };
    c.asset_id = c.derived_id();
    // §BR-14: the creation pays its fee — a USDm note funded and folded on both nodes first.
    crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut node_a, &mut [&mut node_b], &mut c, 0xa11, 1_000);
    assert!(matches!(node_a.publish_asset_create(&c), crate::node::AssetSpendOutcome::Published), "the creation is admitted on node_a");
    let blk = node_a.produce(5_000, Hash32::hash(symbol.as_bytes()), Hash32::hash(b"am-create-mc")).expect("the creation block");
    assert!(matches!(node_b.ingest_block(blk, 5_000), RelayOutcome::Added(_)), "node_b grafts the creation");
    // §BR-14: the creation is decided at its block's fold, on both nodes.
    crate::node::tests::produce_past_the_fold(&mut node_a, &mut [&mut node_b], 5_000, 100);
    (node_a, node_b, c)
}

/// A mint of `amount` of `c` into a fresh note (a real WHIR mint carrier), signed by `signer_sk` over
/// `asset_mint_msg` — the creator's key for an honest mint, any other key for a forgery.
fn am_mint(c: &crate::asset_tx::AssetCreateTx, creator_pk: &[u8], signer_sk: &[u8], amount: u64, seed: u64) -> crate::asset_tx::AssetMintTx {
    let clue = vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX];
    let (registry_path, registry_dirs) =
        crate::dsol::token_membership_path(&[crate::dsol::descriptor_leaf(&c.descriptor())], 0).expect("the minter's own path");
    let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[seed, seed, seed, seed]);
    let (mint_carrier, cm) =
        usdm_decider::whir_rec_block::prove_asset_mint_validity_bytes(amount, c.asset_tag(), &note_sk).expect("a real WHIR mint carrier");
    let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(cm);
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&cm_bytes);
    let creator_sig = crate::pqauth::ml_dsa_sign(
        &crate::asset_tx::asset_mint_msg(&c.asset_id, amount, &cm_bytes, &crate::oli::owner_clue_digest(&clue), ""),
        signer_sk,
    )
    .expect("signs");
    crate::asset_tx::AssetMintTx {
        asset_id: c.asset_id,
        kind: crate::asset_tx::AssetKind::Token,
        amount,
        note,
        mint_carrier,
        owner_clue: clue,
        creator_pubkey: creator_pk.to_vec(),
        creator_sig,
        symbol: c.symbol.clone(),
        asset_name: c.name.clone(),
        registry_path,
        registry_dirs,
        logo: [0u8; 32],
        collection: String::new(),
    }
}

/// CONTROL — THE BURN CLASS: the creator's honest mint `m` still PUBLISHES on `node_a` (its issuance right unspent),
/// rides its block, and its note sits in exactly one record on BOTH nodes.
fn am_the_honest_mint_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, m: &crate::asset_tx::AssetMintTx, at: u64, seed: &[u8]) {
    assert!(
        matches!(node_a.publish_asset_mint(m), crate::node::AssetSpendOutcome::Published),
        "⛔ BURN: node_a refused the creator's honest mint — its issuance right reads as already spent"
    );
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest mint");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    let cm = cm_of(&m.note);
    assert_eq!(cm_occurrences(node_a, &cm), 1, "CONTROL: the honest mint's note sits in exactly one record on node_a");
    assert_eq!(cm_occurrences(node_b, &cm), 1, "CONTROL: the honest mint's note sits in exactly one record on node_b");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetMint × STRIP, through a peer (DB-278): the creator's genuine, signed first mint carried
/// by the rogue `node_b` WITHOUT its issuance-right nullifier in the lane (a cover tag in its place) — a mint that would
/// retire nothing, so the asset could be issued again. The peer `node_a` credits nothing; CONTROL: the same mint,
/// published honestly WITH its right, then lands on both nodes exactly once.
#[test]
fn an_asset_mint_stripped_of_its_issuance_right_carried_by_a_rogue_producer_credits_nothing_on_the_peer() {
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (mut node_a, mut node_b, c) = am_created_pair("STRIP", &pk);
    let m = am_mint(&c, &pk, &sk, 4_200, 7);
    let carriage = crate::chain_object::carriage_of(&m.wire()).expect("the genuine mint has a carriage form");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, m.note.clone(), cover_tag(), 6_000, b"am-strip-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 6_500, "a genuine asset mint WITHOUT its issuance-right nullifier");
    assert_eq!(cm_occurrences(&node_a, &cm_of(&m.note)), 0, "⛔ ROGUE PRODUCER: a mint that retired no issuance right credited its note on the peer");
    am_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &m, 8_000, b"am-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetMint × BURN, through a peer: a REFUSED mint naming the asset's issuance right — signed
/// by a STRANGER, not the creator — carried by the rogue `node_b` with `issue_right_nf(asset)` in its lane. The refused
/// object must cost the creator nothing: the creator's real mint then publishes on `node_a` and lands on both nodes.
#[test]
fn a_refused_asset_mint_naming_an_issuance_right_does_not_stop_the_creators_real_mint_on_the_peer() {
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (_spk, ssk) = crate::pqauth::ml_dsa_keypair();
    let (mut node_a, mut node_b, c) = am_created_pair("BURN", &pk);
    let forged = am_mint(&c, &pk, &ssk, 9_999_999, 8);
    let carriage = crate::chain_object::carriage_of(&forged.wire()).expect("a stranger-signed mint still decodes: the signature is the door's");
    let right = crate::asset_tx::issue_right_nf(&c.asset_id);
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, forged.note.clone(), right, 6_000, b"am-burn-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 6_500, "a stranger-signed mint naming the asset's issuance right");
    assert_eq!(cm_occurrences(&node_a, &cm_of(&forged.note)), 0, "⛔ ROGUE PRODUCER: a mint the creator never signed credited its note on the peer");
    am_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &am_mint(&c, &pk, &sk, 4_200, 7), 8_000, b"am-burn-settle");
}

/// ⛔⛔⛔ A-F31 (2026-11-11, lane goods) — THE TOKEN REGISTRY UN-FOLDS WITH ITS STEP. A creation is folded on both nodes;
/// then `node_a`'s fold leaves every step it made (what a reorg below the creation's step does) and folds the same
/// blocks again, while `node_b` never rewinds. The registry is the chain's, so: the rewind takes the registration back,
/// the re-fold registers it once (the root `node_b` holds), and the creator's mint, whose path is built against that
/// one leaf, lands on both nodes.
/// RED-first: before the fix the registry was a field of the node that no rewind restored. The sibling cell
/// `a_creation_laid_by_a_rogue_naming_a_victim_creator_gives_the_rogue_no_issuance_on_the_peer`, whose rogue blocks
/// re-order the newest fold steps twice across the creation, was MEASURED RED at its control on that tree (the
/// creator's honest mint in 0 records on both nodes: each fold of the creation's block had registered it again).
#[test]
fn af31_a_rewound_creation_is_unregistered_and_its_refold_registers_it_once_like_the_peer_that_never_rewound() {
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (mut node_a, mut node_b, c) = am_created_pair("REFOLD", &pk);
    let one = node_b.dsol_registry_root();
    assert_eq!(
        (node_a.dsol_registry_size().0, node_b.dsol_registry_size().0),
        (1, 1),
        "CALIBRATION: the creation registered once on each node"
    );
    assert_eq!(node_a.dsol_registry_root(), one, "CALIBRATION: one registry on both nodes");
    let genesis = node_a.dag().genesis().expect("genesis");
    node_a.rewind_fold_to_common_for_test(genesis);
    assert!(!node_a.spine_stale_for_test(), "CALIBRATION: the rewind is inside every fold journal's reach");
    assert_eq!(
        node_a.dsol_registry_size().0,
        0,
        "⛔⛔⛔ A-F31: a rewind below a creation's fold step left it registered — its re-fold registers it a second time, and \
         this node's registry is no longer a function of the chain"
    );
    for _ in 0..8 {
        let _ = node_a.fold_canonical_records();
    }
    assert_eq!(node_a.dsol_registry_size().0, 1, "⛔⛔⛔ A-F31: the re-folded creation is not registered exactly once");
    assert_eq!(
        node_a.dsol_registry_root(),
        one,
        "⛔⛔⛔ A-F31: two registry roots on one chain — the node that re-folded and the node that never rewound"
    );
    am_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &am_mint(&c, &pk, &sk, 4_200, 33), 9_000, b"af31-settle");
}

// ═══════════════════════════════════════════════ PoolDeposit ═══════════════════════════════════════════════

/// A stability-pool deposit PUBLISHED on the custodian `node_a` (pooled, not laid) — the production doors of
/// `node::tests::a_stability_pool_deposit_and_its_withdrawal_travel_to_a_peer_with_one_pool`: one bonded custodian seated on
/// both nodes, a real USDm note minted by a peg-in and grafted on `node_b`, the pool snapshot `node_a` grants, a proven
/// deposit of 600 and its one-step membership bind. Returns both nodes, the deposit's header (receipt / change / nullifier)
/// and the full wire of the framed object exactly as `node_a` would carry it.
fn pd_published(tag: u64) -> (Node, Node, crate::pool_tx::PoolDepositHeader, Vec<u8>) {
    let (node_a, node_b, _grant, _w, wire) = pd_core(tag);
    let (_, payload) = crate::chain_object::unframe(&wire).expect("framed");
    let h = crate::pool_tx::decode(payload).expect("the honest deposit decodes").h;
    (node_a, node_b, h, wire)
}

/// `pd_published`'s production sequence, also returning the snapshot grant and the deposit witness a WITHDRAWAL of the
/// same receipt needs (`pw_published`).
fn pd_core(tag: u64) -> (Node, Node, crate::node::PoolSnapshotGrant, usdm_decider::whir_rec_block::PoolDepositWitness, Vec<u8>) {
    let (node_a, node_b, grant, w, wire, _pk, _sk) = pd_core_with(tag, 600);
    (node_a, node_b, grant, w, wire)
}

/// `pd_core` with the pool deposit sized `deposit` (a liquidation needs the pool to cover what it retires), also returning
/// the ONE bonded custodian's keys (the key that marks the price and signs the liquidation, as in the node pin).
#[allow(clippy::type_complexity)]
fn pd_core_with(tag: u64, deposit: u64) -> (Node, Node, crate::node::PoolSnapshotGrant, usdm_decider::whir_rec_block::PoolDepositWitness, Vec<u8>, Vec<u8>, Vec<u8>) {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block as wr;
    use crate::node::tests::{reserve_for, test_d_blind, test_owner, test_recipient};
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let mk = || Node::new_folding_at_tip_for_test(crate::node::tests::genesis_block()).expect("a node builds");
    let (mut node_a, mut node_b) = (mk(), mk());
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (ek, dk) = crate::pqkem::keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    for n in [&mut node_a, &mut node_b] {
        n.admit_validator(vid, 20_000, 0).expect("seats");
        n.register_validator_custody(vid, vec![2u8; 33], [9u8; 32]);
        n.register_custody_kem(vid, ek.clone());
    }
    node_a.set_custodian_identity(vid, dk);
    let v: u64 = 1_000;
    let note_sk_owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x9301, tag, 2, 3]));
    let note_sk = note_sk_owner.opening(); // DB-395: the note's opening, under its owner
    let (mint_carrier, cm, _dc) = wr::prove_mint_validity_committed_bytes(v, &note_sk, &test_d_blind()).expect("the mint proves");
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&b32(cm));
    let reserve = reserve_for(&node_a, &test_d_blind());
    crate::node::tests::fund_test_deposit(&mut node_a, &reserve, &test_d_blind(), 1_000_000); // §BR-2: the coin and the depositor's sweep authorization
    let dep = [0x93u8; 32];
    let out = node_a.execute_peg_in(
        dep, 3_000, u128::from(v), test_recipient(&dep), &note, &mint_carrier, &reserve, &pk, &sk, &[],
        &crate::pqauth::MlDsaVerifier, &test_owner(), [0x79u8; 32], test_d_blind(),
    );
    assert!(matches!(out, crate::peg::PegOutcome::ConfidentialPublished), "PRECONDITION: the mint publishes: {out:?}");
    let blk = node_a.produce(6_000, Hash32::hash(b"pd-mint"), Hash32::hash(b"pd-mint-m")).expect("the mint block");
    assert!(matches!(node_b.ingest_block(blk, 6_500), RelayOutcome::Added(_)), "node_b grafts the mint block");
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    let grant = node_a.pool_snapshot_grant(asset, 7).expect("node_a holds the pool's genesis opening");
    let w = wr::PoolDepositWitness {
        value_in: v,
        owner: note_sk_owner,
        lc_blind: lanes_of(&[0x9301, tag, 4, 4]),
        deposit,
        owner_sk: lanes_of(&[0x9301, tag, 5, 5]),
        change_opening: lanes_of(&[0x9301, tag, 6, 6]),
        dv_blind: lanes_of(&[0x9301, tag, 7, 7]),
    };
    let (carrier, stmt) = wr::prove_pool_deposit_bytes(&w, &grant.pd, &grant.sd, asset, grant.epoch).expect("the deposit proves");
    let (mem, tip) = crate::node::tests::one_step_membership_for_test(&node_a, &b32(cm), cm, stmt.nullifier, w.lc_blind)
        .expect("node_a holds the input note");
    let note_of = |c: crate::spend_frontier::Digest4| {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..32].copy_from_slice(&b32(c));
        n
    };
    let out = node_a.execute_pool_deposit(
        stmt.clone(), &carrier, deposit, w.dv_blind, 7, &mem, &tip, &note_of(stmt.receipt_cm), &note_of(stmt.change_cm),
        &[test_owner(), test_owner()],
    );
    assert!(matches!(out, crate::peg::PegOutcome::ConfidentialMinted), "PRECONDITION: node_a publishes the deposit: {out:?}");
    let wire = node_a
        .mempool()
        .all_tx_ids()
        .into_iter()
        .filter_map(|id| node_a.mempool().get(&Hash32(id)).map(|tx| tx.blob.clone()))
        .find(|blob| matches!(crate::chain_object::unframe(blob), Some((crate::chain_object::Class::PoolDeposit, _))))
        .expect("CALIBRATION: node_a pooled its framed deposit for its next block");
    (node_a, node_b, grant, w, wire, pk, sk)
}

fn pd_decoded(wire: &[u8]) -> crate::pool_tx::PoolDepositDecoded {
    let (_, payload) = crate::chain_object::unframe(wire).expect("framed");
    crate::pool_tx::decode(payload).expect("the honest deposit decodes")
}

fn pd_notes(d: &crate::pool_tx::PoolDepositDecoded) -> Vec<u8> {
    [d.receipt.clone(), d.change.clone()].concat()
}

/// CONTROL — THE BURN CLASS: the deposit `node_a` still holds pooled lays and lands on BOTH nodes — the receipt in
/// exactly one record each, and one pool.
fn pd_the_honest_deposit_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, h: &crate::pool_tx::PoolDepositHeader, at: u64, seed: &[u8]) {
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest deposit");
    assert!(!honest.credit_set.is_empty(), "⛔ DB-377 CLASS: node_a laid a block WITHOUT its pooled deposit");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    let receipt = crate::spend_frontier::leaf_to_cm_bytes(h.receipt_cm);
    assert_eq!(cm_occurrences(node_a, &receipt), 1, "CONTROL: the receipt sits in exactly one record on node_a");
    assert_eq!(cm_occurrences(node_b, &receipt), 1, "CONTROL: the receipt sits in exactly one record on node_b");
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    assert_eq!(node_a.peg().pool_words(asset), node_b.peg().pool_words(asset), "CONTROL: one pool on both nodes");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PoolDeposit × STRIP, through a peer: the honest deposit with its MEMBERSHIP CARRIER stripped
/// (the one bind that proves its input note was ever received; the codec refuses it, so the rogue lays the bytes by
/// hand). The peer `node_a` holds no receipt and its pool does not move; CONTROL: the honest deposit then lands on both.
#[test]
fn a_pool_deposit_stripped_of_its_membership_carrier_carried_by_a_rogue_producer_moves_no_peer_pool() {
    let (mut node_a, mut node_b, h, wire) = pd_published(1);
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    let pool0 = node_a.peg().pool_words(asset);
    let honest = pd_decoded(&wire);
    let mut d = honest.clone();
    d.membership_carrier.clear();
    let note_ref = |n: &[u8]| [n[..32].to_vec(), Hash32::hash(n).0.to_vec()].concat();
    d.receipt = note_ref(&honest.receipt);
    d.change = note_ref(&honest.change);
    let stripped = crate::pool_tx::wire(&d);
    let rogue = dd_rogue_block_carrying(&mut node_b, stripped, pd_notes(&honest), h.nullifier, 12_000, b"pd-strip-rogue");
    both_judge_strip(&mut node_a, &mut node_b, rogue, 12_500, "a pool deposit with its membership carrier stripped");
    assert_eq!(cm_occurrences(&node_a, &crate::spend_frontier::leaf_to_cm_bytes(h.receipt_cm)), 0, "⛔ ROGUE PRODUCER: the peer holds the receipt of a deposit with no membership bind");
    assert_eq!(node_a.peg().pool_words(asset), pool0, "⛔ ROGUE PRODUCER: a deposit with no membership bind moved the peer's pool");
    pd_the_honest_deposit_lands_on_both_nodes(&mut node_a, &mut node_b, &h, 15_000, b"pd-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PoolDeposit × REPLAY, through a peer: the honest deposit lands on both nodes; the rogue
/// `node_b` re-carries the SAME object with its input nullifier in the lane. The peer's pool moves no further and the
/// receipt stays in exactly one record — the input note is spent on its canonical state.
#[test]
fn a_pool_deposit_re_carried_by_a_rogue_producer_moves_the_peer_pool_once() {
    let (mut node_a, mut node_b, h, wire) = pd_published(2);
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    pd_the_honest_deposit_lands_on_both_nodes(&mut node_a, &mut node_b, &h, 12_000, b"pd-replay-honest");
    let pool1 = node_a.peg().pool_words(asset);
    let honest = pd_decoded(&wire);
    let carriage = crate::chain_object::carriage_of(&wire).expect("the honest deposit has a carriage form");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, pd_notes(&honest), h.nullifier, 16_000, b"pd-replay-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 16_500, "a RE-CARRIED, already applied pool deposit");
    assert_eq!(node_a.peg().pool_words(asset), pool1, "⛔ ROGUE PRODUCER: a re-carried deposit moved the peer's pool a SECOND time");
    assert_eq!(cm_occurrences(&node_a, &crate::spend_frontier::leaf_to_cm_bytes(h.receipt_cm)), 1, "⛔ ROGUE PRODUCER: the re-carried deposit credited its receipt again on the peer");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PoolDeposit × BURN, through a peer: a REFUSED deposit naming the victim's input-note
/// nullifier — the honest object with its deposit carrier corrupted, so it proves nothing — carried by the rogue
/// `node_b` with that nullifier in its lane. The refused object must cost the victim nothing: the peer's pool does not
/// move, and the victim's real deposit (the same input) then lands on both nodes.
#[test]
fn a_refused_pool_deposit_naming_a_victims_note_does_not_stop_its_real_deposit_on_the_peer() {
    let (mut node_a, mut node_b, h, wire) = pd_published(3);
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    let pool0 = node_a.peg().pool_words(asset);
    let honest = pd_decoded(&wire);
    let mut d = honest.clone();
    let mid = d.deposit_carrier.len() / 2;
    d.deposit_carrier[mid] ^= 0x01;
    let carriage = crate::chain_object::carriage_of(&crate::pool_tx::wire(&d)).expect("a corrupted carrier still decodes: it is judged at the fold");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, pd_notes(&honest), h.nullifier, 12_000, b"pd-burn-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 12_500, "a refused pool deposit naming the victim's input nullifier");
    assert_eq!(node_a.peg().pool_words(asset), pool0, "⛔ ROGUE PRODUCER: a deposit whose carrier proves nothing moved the peer's pool");
    pd_the_honest_deposit_lands_on_both_nodes(&mut node_a, &mut node_b, &h, 15_000, b"pd-burn-settle");
}

// ═══════════════════════════════════════════ ReserveTheft ═══════════════════════════════════════════

/// Three custodians bonded 5,000 each on BOTH nodes (the DB-274 P4b fixture, `node::tests::p4b_*`); custodian 2 is the thief.
fn rt_fixture() -> (Node, Node, Vec<crate::bridge::Custodian>) {
    let custodians = crate::node::tests::p4b_custodians();
    let mut node_a = crate::node::tests::dd_node();
    let mut node_b = crate::node::tests::dd_node();
    crate::node::tests::p4b_bond(&mut node_a, &custodians);
    crate::node::tests::p4b_bond(&mut node_b, &custodians);
    (node_a, node_b, custodians)
}

fn rt_bonds(node_a: &Node, node_b: &Node, id: &[u8; 32]) -> (u128, u128) {
    (node_a.validators().bond_of(id), node_b.validators().bond_of(id))
}

/// CONTROL: the honest ≥ 2/3 (custodians 0 and 1) theft evidence naming the thief publishes on `node_a`, rides its block,
/// and past the fold the thief's bond is forfeit on BOTH nodes.
fn rt_the_honest_evidence_slashes_the_thief_on_both_nodes(node_a: &mut Node, node_b: &mut Node, custodians: &[crate::bridge::Custodian], at: u64, seed: &[u8]) {
    let (thief, stolen) = (custodians[2].id(), crate::node::tests::p4b_stolen());
    let cert = crate::node::tests::p4b_cert(&[&custodians[0], &custodians[1]], &stolen, &[thief]);
    assert_eq!(node_a.publish_reserve_theft(&stolen, &cert, &[thief], crate::node::tests::P4B_LOSS), crate::node::AssetSpendOutcome::Published, "node_a publishes the honest evidence");
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the evidence");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    let _ = node_a.fold_past_for_test(&mut [&mut *node_b], at + 2_000, seed);
    assert_eq!(rt_bonds(node_a, node_b, &thief), (0, 0), "CONTROL: the honest evidence slashed the thief on both nodes");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — ReserveTheft × FORGE, through a peer: theft evidence against an INNOCENT custodian (0) signed
/// by ONE custodian of three (below the ≥ 2/3 the door weighs), carried by the rogue `node_b`. The peer slashes no one;
/// CONTROL: the honest ≥ 2/3 evidence against the real thief then slashes it on both nodes.
#[test]
fn theft_evidence_against_an_innocent_custodian_below_the_quorum_carried_by_a_rogue_producer_slashes_no_one_on_the_peer() {
    let (mut node_a, mut node_b, custodians) = rt_fixture();
    let (innocent, stolen) = (custodians[0].id(), crate::node::tests::p4b_stolen());
    let one = crate::node::tests::p4b_cert(&[&custodians[2]], &stolen, &[innocent]);
    let blob = crate::theft_tx::wire(&stolen, &[innocent], crate::node::tests::P4B_LOSS, &one).expect("structurally one canonical object");
    let rogue = rogue_bond_lane_block(&mut node_b, blob, &[], 6_000, b"rt-forge-rogue");
    peer_judges(&mut node_a, rogue, 6_500, "theft evidence against an innocent custodian signed by 1 of 3");
    let ts = node_a.fold_past_for_test(&mut [&mut node_b], 7_000, b"rt-forge-fold");
    assert_eq!(rt_bonds(&node_a, &node_b, &innocent), (5_000, 5_000), "⛔ ROGUE PRODUCER: sub-quorum evidence slashed an innocent custodian");
    rt_the_honest_evidence_slashes_the_thief_on_both_nodes(&mut node_a, &mut node_b, &custodians, ts + 1_000, b"rt-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — ReserveTheft × STRIP, through a peer: the genuine evidence with its certificate REMOVED (the
/// codec refuses an empty attestor list; the rogue lays the raw bytes on the bond lane). The thief keeps its bond until the
/// honest evidence; CONTROL: the honest evidence then slashes it on both nodes.
#[test]
fn theft_evidence_stripped_of_its_certificate_carried_by_a_rogue_producer_slashes_no_one_on_the_peer() {
    let (mut node_a, mut node_b, custodians) = rt_fixture();
    let (thief, stolen) = (custodians[2].id(), crate::node::tests::p4b_stolen());
    let payload: crate::theft_tx::ReserveTheftPayload = (stolen.clone(), vec![thief], crate::node::tests::P4B_LOSS, Vec::new());
    let stripped = crate::chain_object::frame(crate::chain_object::Class::ReserveTheft, &postcard::to_allocvec(&payload).expect("encodes"));
    let rogue = rogue_bond_lane_block(&mut node_b, stripped, &[], 6_000, b"rt-strip-rogue");
    peer_judges_strip(&mut node_a, rogue, 6_500, "theft evidence with NO certificate");
    let ts = node_a.fold_past_for_test(&mut [&mut node_b], 7_000, b"rt-strip-fold");
    assert_eq!(rt_bonds(&node_a, &node_b, &thief), (5_000, 5_000), "⛔ ROGUE PRODUCER: uncertified evidence slashed a custodian");
    rt_the_honest_evidence_slashes_the_thief_on_both_nodes(&mut node_a, &mut node_b, &custodians, ts + 1_000, b"rt-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — ReserveTheft × SUBSTITUTE, through a peer, ON THE BLOCK PATH: the genuine ≥ 2/3 certificate
/// over (theft, [thief]) re-carried by the rogue `node_b` naming honest custodian 0 instead. The offender list is bound by
/// the signatures, so the peer slashes no one; CONTROL: the untampered evidence then slashes the thief on both nodes.
/// (`db274_p4b_a_genuine_theft_cert_never_slashes_a_validator_it_does_not_name` pins this at `apply_bond_set` directly;
/// this is the same attack through a block a peer grafts.)
#[test]
fn a_genuine_theft_certificate_retargeted_at_an_honest_custodian_by_a_rogue_producer_slashes_no_one_on_the_peer() {
    let (mut node_a, mut node_b, custodians) = rt_fixture();
    let (thief, honest, stolen) = (custodians[2].id(), custodians[0].id(), crate::node::tests::p4b_stolen());
    let cert = crate::node::tests::p4b_cert(&[&custodians[0], &custodians[1]], &stolen, &[thief]);
    let retargeted = crate::theft_tx::wire(&stolen, &[honest], crate::node::tests::P4B_LOSS, &cert).expect("structurally one canonical object");
    let rogue = rogue_bond_lane_block(&mut node_b, retargeted, &[], 6_000, b"rt-swap-rogue");
    peer_judges(&mut node_a, rogue, 6_500, "a genuine theft certificate retargeted at an honest custodian");
    let ts = node_a.fold_past_for_test(&mut [&mut node_b], 7_000, b"rt-swap-fold");
    assert_eq!(rt_bonds(&node_a, &node_b, &honest), (5_000, 5_000), "⛔ ROGUE PRODUCER: a retargeted certificate slashed an honest custodian");
    rt_the_honest_evidence_slashes_the_thief_on_both_nodes(&mut node_a, &mut node_b, &custodians, ts + 1_000, b"rt-swap-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — ReserveTheft × REPLAY, through a peer: the honest evidence slashes the thief on both nodes;
/// the rogue `node_b` re-carries the SAME evidence. The thief is removed and barred, so the replay moves nothing: the
/// peer's validator count and total bond are unchanged and no other custodian loses weight.
#[test]
fn theft_evidence_re_carried_by_a_rogue_producer_after_the_slash_moves_nothing_on_the_peer() {
    let (mut node_a, mut node_b, custodians) = rt_fixture();
    let (thief, stolen) = (custodians[2].id(), crate::node::tests::p4b_stolen());
    rt_the_honest_evidence_slashes_the_thief_on_both_nodes(&mut node_a, &mut node_b, &custodians, 6_000, b"rt-replay-honest");
    let before = (node_a.validators().len(), node_a.validators().total_bond());
    let cert = crate::node::tests::p4b_cert(&[&custodians[0], &custodians[1]], &stolen, &[thief]);
    let blob = crate::theft_tx::wire(&stolen, &[thief], crate::node::tests::P4B_LOSS, &cert).expect("the honest evidence frames");
    let rogue = rogue_bond_lane_block(&mut node_b, blob, &[], 14_000, b"rt-replay-rogue");
    peer_judges(&mut node_a, rogue, 14_500, "RE-CARRIED theft evidence after the slash");
    let _ = node_a.fold_past_for_test(&mut [&mut node_b], 15_000, b"rt-replay-fold");
    assert_eq!((node_a.validators().len(), node_a.validators().total_bond()), before, "⛔ ROGUE PRODUCER: re-carried theft evidence moved the peer's validator set again");
}

// ═══════════════════════════════════════════════ AssetCreate ═══════════════════════════════════════════════

/// A token descriptor naming `creator_pk` as the only identity that may mint it (unsigned by design: a creation grants no
/// supply; the MINT is the authority, signed by the creator).
fn ac_token(symbol: &str, creator_pk: &[u8]) -> crate::asset_tx::AssetCreateTx {
    let name = "rogue-role census creation";
    let mut c = crate::asset_tx::AssetCreateTx {
        kind: crate::asset_tx::AssetKind::Token,
        symbol: symbol.to_string(),
        name: name.to_string(),
        logo: [0u8; 32],
        bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, symbol, name).bytecode,
        creator: crate::pqauth::pubkey_id(creator_pk),
        asset_id: [0u8; 32],
        fee: crate::asset_tx::CreationFee::default(),
        art: Vec::new(),
        supply: None,
    };
    c.asset_id = c.derived_id();
    c
}

fn ac_fresh_pair() -> (Node, Node) {
    let mk = crate::node::tests::testnet_party_folding_at_tip; // §BR-14: the testnet identity funds the creation fee
    (mk(), mk())
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetCreate × FORGE, through a peer: the rogue `node_b` lays a creation naming a VICTIM as
/// creator (a creation carries no signature — anyone may register a descriptor). What a forged creation must NOT buy:
/// issuance. The peer registers it; a mint signed by the ROGUE's key is refused on the peer (nothing credited); the
/// VICTIM's own mint then lands on both nodes exactly once — the creator field, not the producer, holds the right.
#[test]
fn a_creation_laid_by_a_rogue_naming_a_victim_creator_gives_the_rogue_no_issuance_on_the_peer() {
    let (vpk, vsk) = crate::pqauth::ml_dsa_keypair();
    let (rpk, rsk) = crate::pqauth::ml_dsa_keypair();
    let (mut node_a, mut node_b) = ac_fresh_pair();
    let mut c = ac_token("ACFORGE", &vpk);
    // §BR-14: the rogue pays the creation's fee itself (a creation names a creator but anyone may pay for it).
    crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut node_b, &mut [&mut node_a], &mut c, 0xf09, 1_000);
    let carriage = crate::chain_object::carriage_of(&c.wire()).expect("a creation is its own carriage");
    // the creation DERIVES its issue-right note and the credit-set door requires the block to commit it (MEASURED
    // batch 5: laid without it, the peer refused the block `Invalid(CreditObjectWithoutSubject)` before the class door)
    let derived = crate::chain_object::carried_note_payloads(&c.wire()).expect("a creation names its derived note").concat();
    // §BR-14: the creation's OWN tags ride the lane (its one-time id and its fee note's nullifier), as a producer must lay
    // them (DB-278) — the census cell's subject is issuance, so the rogue lays a creation every door would otherwise accept.
    let own = crate::chain_object::object_own_nullifiers(&c.wire()).expect("a creation names its own tags");
    let mut rogue = dd_rogue_block_carrying(&mut node_b, carriage, derived, own[0], 5_000, b"ac-forge-rogue");
    rogue.nullifier_proof.padded_tags.extend_from_slice(&own[1..]);
    rogue.header.nullifier_tags_root = crate::block::nullifier_tags_root_of(&rogue.nullifier_proof.padded_tags);
    crate::node::tests::lay_tag_evidence_for_test(&node_b, &mut rogue, &own);
    both_judge(&mut node_a, &mut node_b, rogue, 5_500, "a creation naming a victim as creator");
    let rogue_mint = am_mint(&c, &rpk, &rsk, 7_777, 31);
    let carriage = crate::chain_object::carriage_of(&rogue_mint.wire()).expect("the rogue's mint decodes");
    let blk = dd_rogue_block_carrying(&mut node_b, carriage, rogue_mint.note.clone(), crate::asset_tx::issue_right_nf(&c.asset_id), 7_000, b"ac-forge-mint");
    both_judge(&mut node_a, &mut node_b, blk, 7_500, "a mint of the victim's asset signed by the rogue");
    assert_eq!(cm_occurrences(&node_a, &cm_of(&rogue_mint.note)), 0, "⛔ ROGUE PRODUCER: the rogue minted an asset whose creation names someone else");
    // A-F31: the rogue's two blocks re-order the newest fold steps, so the creation's block folds more than once on each
    // node. It is registered once (before the fix: once per fold, and the control below was RED on both nodes).
    assert_eq!(
        (node_a.dsol_registry_size().0, node_b.dsol_registry_size().0),
        (1, 1),
        "⛔⛔⛔ A-F31: a creation whose block re-folded after a reorg is registered more than once"
    );
    am_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &am_mint(&c, &vpk, &vsk, 4_200, 32), 9_000, b"ac-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetCreate × SUBSTITUTE, through a peer: a creation whose claimed `asset_id` is NOT its own
/// descriptor's derived id (an identity hijack: the rogue claims a victim's id for a different contract). The codec
/// refuses it (the rogue lays the raw bytes); the peer's registry does not move. CONTROL: the honest creation then lands.
#[test]
fn a_creation_claiming_an_id_that_is_not_its_descriptors_carried_by_a_rogue_producer_registers_nothing_on_the_peer() {
    let (pk, _sk) = crate::pqauth::ml_dsa_keypair();
    let (mut node_a, mut node_b) = ac_fresh_pair();
    let root0 = node_a.dsol_registry_root();
    let mut honest = ac_token("ACSWAP", &pk);
    // §BR-14: the honest control pays its fee first.
    crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut node_a, &mut [&mut node_b], &mut honest, 0x5a9, 1_000);
    let mut hijack = ac_token("ACOTHER", &pk);
    hijack.asset_id = honest.asset_id;
    let rogue = dd_rogue_block_carrying(&mut node_b, hijack.wire(), Vec::new(), cover_tag(), 5_000, b"ac-swap-rogue");
    both_judge_strip(&mut node_a, &mut node_b, rogue, 5_500, "a creation claiming another descriptor's id");
    assert_eq!(node_a.dsol_registry_root(), root0, "⛔ ROGUE PRODUCER: a creation with a hijacked id moved the peer's registry");
    assert!(matches!(node_a.publish_asset_create(&honest), crate::node::AssetSpendOutcome::Published), "CONTROL: the honest creation publishes");
    let blk = node_a.produce(7_000, Hash32::hash(b"ac-swap-honest"), Hash32::hash(b"mc")).expect("node_a lays the creation");
    dd_graft_then_settle(&mut node_a, &mut node_b, blk, 7_500, b"ac-swap-settle");
    assert_ne!(node_a.dsol_registry_root(), root0, "CONTROL: the honest creation registered on node_a");
    assert_eq!(node_a.dsol_registry_root(), node_b.dsol_registry_root(), "CONTROL: one registry on both nodes");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetCreate × STRIP, through a peer: a creation with its contract BYTECODE stripped (a
/// registered asset with no contract). The codec refuses it; the peer's registry does not move.
#[test]
fn a_creation_stripped_of_its_bytecode_carried_by_a_rogue_producer_registers_nothing_on_the_peer() {
    let (pk, _sk) = crate::pqauth::ml_dsa_keypair();
    let (mut node_a, mut node_b) = ac_fresh_pair();
    let root0 = node_a.dsol_registry_root();
    let mut stripped = ac_token("ACSTRIP", &pk);
    stripped.bytecode.clear();
    let rogue = dd_rogue_block_carrying(&mut node_b, stripped.wire(), Vec::new(), cover_tag(), 5_000, b"ac-strip-rogue");
    both_judge_strip(&mut node_a, &mut node_b, rogue, 5_500, "a creation with NO bytecode");
    assert_eq!(node_a.dsol_registry_root(), root0, "⛔ ROGUE PRODUCER: a creation with no contract moved the peer's registry");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetCreate × REPLAY, through a peer: the honest creation lands on both nodes; the rogue
/// re-carries it. The peer's registry root is unchanged (one descriptor, one leaf), and the creation grants no second
/// issuance right: the creator's one mint lands exactly once on both nodes afterwards.
#[test]
fn a_creation_re_carried_by_a_rogue_producer_moves_no_peer_registry_and_grants_no_second_issuance() {
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (mut node_a, mut node_b, c) = am_created_pair("ACREPLAY", &pk);
    let root1 = node_a.dsol_registry_root();
    let carriage = crate::chain_object::carriage_of(&c.wire()).expect("a creation is its own carriage");
    let derived = crate::chain_object::carried_note_payloads(&c.wire()).expect("a creation names its derived note").concat();
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, derived, cover_tag(), 7_000, b"ac-replay-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 7_500, "a RE-CARRIED creation");
    assert_eq!(node_a.dsol_registry_root(), root1, "⛔ ROGUE PRODUCER: a re-carried creation moved the peer's registry");
    am_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &am_mint(&c, &pk, &sk, 4_200, 33), 9_000, b"ac-replay-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetCreate × BURN, through a peer (live since DB-388: a creation retires
/// `one_time_id_nf(ONE_TIME_ASSET_CREATE, asset_id)`). The rogue `node_b` lays a block whose lane carries ONLY a victim
/// creation's one-time id — no creation, nothing that justifies it. The tag is unjustified (DB-367), so it must not enter
/// the peer's spent set: the victim's real creation then publishes on `node_a` and registers on BOTH nodes, and its creator
/// mints once.
#[test]
fn a_rogue_producer_naming_a_creations_one_time_id_does_not_stop_its_real_creation_on_the_peer() {
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (mut node_a, mut node_b) = ac_fresh_pair();
    let root0 = node_a.dsol_registry_root();
    let mut c = ac_token("ACBURN", &pk);
    // §BR-14: the victim's creation pays its fee first.
    crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut node_a, &mut [&mut node_b], &mut c, 0xb04, 1_000);
    let id = crate::peg::one_time_id_nf(crate::peg::ONE_TIME_ASSET_CREATE, &c.derived_id());
    let mut rogue = node_b.produce(5_000, Hash32::hash(b"ac-burn-rogue"), Hash32::hash(b"rogue-mc")).expect("the rogue lays a block");
    rogue.nullifier_proof.padded_tags.push(id);
    rogue.header.nullifier_tags_root = crate::block::nullifier_tags_root_of(&rogue.nullifier_proof.padded_tags);
    crate::node::tests::lay_tag_evidence_for_test(&node_b, &mut rogue, &[id]);
    both_judge(&mut node_a, &mut node_b, rogue, 5_500, "only a victim creation's one-time id in its lane");
    assert_eq!(node_a.dsol_registry_root(), root0, "CALIBRATION: a lane-only block registered nothing");
    assert!(
        matches!(node_a.publish_asset_create(&c), crate::node::AssetSpendOutcome::Published),
        "⛔ BURN: node_a refused the victim's real creation after a rogue block named its one-time id"
    );
    let blk = node_a.produce(7_000, Hash32::hash(b"ac-burn-honest"), Hash32::hash(b"mc")).expect("node_a lays the creation");
    dd_graft_then_settle(&mut node_a, &mut node_b, blk, 7_500, b"ac-burn-settle");
    assert_ne!(node_a.dsol_registry_root(), root0, "⛔ BURN: the victim's creation did not register on node_a");
    assert_eq!(node_a.dsol_registry_root(), node_b.dsol_registry_root(), "CONTROL: one registry on both nodes");
    am_the_honest_mint_lands_on_both_nodes(&mut node_a, &mut node_b, &am_mint(&c, &pk, &sk, 4_200, 34), 9_000, b"ac-burn-mint");
}

// ═══════════════════════════════════════════════ YieldClaim ═══════════════════════════════════════════════

/// §BR-3 17.6: node_a lays the first block of stake epoch `e` and node_b grafts it — the epoch's stakers' pool snapshot, which
/// every claim of the epoch is bounded by.
fn yc_open_epoch(node_a: &mut Node, node_b: &mut Node, e: u64, tag: u64) {
    let tick = node_a.produce(yc_ts(e) - 400, Hash32::hash(&[b'y', b'e', tag as u8, (e % 251) as u8]), Hash32::hash(b"yc-epoch-tick")).expect("an epoch block");
    assert!(matches!(node_b.ingest_block(tick, yc_ts(e) - 300), RelayOutcome::Added(_)), "node_b grafts the epoch block");
    assert!(node_a.peg().stakers_pool_snapshot(e).is_some(), "PRECONDITION: epoch {e}'s pool snapshot is held");
}

fn yc_ts(e: u64) -> u64 {
    e * usdm_decider::whir_rec_block::STAKE_EPOCH_MS + 1_000
}

/// DB-395 — a yield-chain fixture note's KEY and the OPENING its note commits to. A later witness spends the note as
/// `NoteOwner::from_test_key(key)`, whose opening `P(spk, seed)` is what the earlier witness must have sealed — an output
/// sealed to a raw opening can be spent by nobody (its owner would have to invert `P`).
fn yc_key(tag: u64, slot: u64) -> crate::spend_frontier::Digest4 {
    usdm_decider::poseidon2_compress::lanes_of(&[0x2370, tag, slot, slot])
}
fn yc_opening(tag: u64, slot: u64) -> crate::spend_frontier::Digest4 {
    usdm_decider::whir_rec_block::NoteOwner::from_test_key(yc_key(tag, slot)).opening()
}

fn yc_note(c: crate::spend_frontier::Digest4) -> Vec<u8> {
    let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    n[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(c));
    n
}

/// PUBLISH one stake object on `node_a` (its own door, `execute_stake`) for witness `w` over input `in_cm` at epoch `e` —
/// pooled, not laid. The production sequence of `node::tests::db237_a_private_stake_and_its_claim_travel_to_a_peer_with_one_supply`.
fn yc_publish(node_a: &mut Node, w: &usdm_decider::whir_rec_block::StakeWitness, in_cm: [u8; 32], e: u64) -> (crate::peg::PegOutcome, usdm_decider::whir_rec_block::StakeOutputs) {
    use usdm_decider::whir_rec_block as wr;
    let rate = node_a.params().stake_reward_apr_bps;
    let (carrier, o) = wr::prove_stake_carrier_bytes(w, e, u64::from(rate)).expect("the stake carrier proves");
    let leaf = wr::stake_input_leaf(w); // O1-INFINITY-REVIEWED: a pure leaf derivation of one witness (the guard's regex reads "put_" inside "input_"); this test writes nothing to disk
    let (mem, tip) = crate::node::tests::one_step_membership_for_test(node_a, &in_cm, leaf, o.nullifier, w.lc_blind)
        .expect("node_a holds the input note in a folded record");
    let stmt = crate::stake_tx::StakeHeader {
        nullifier: crate::spend_frontier::leaf_to_cm_bytes(o.nullifier),
        e_now: e,
        rate_bps: rate,
        out0_cm: o.out_cms[0],
        out1_cm: o.out_cms[1],
        leaf_commit: o.leaf_commit,
        reward_commit: o.reward_commit,
        new_paid_commit: usdm_decider::poseidon2_compress::zero_digest(),
    };
    let owner = crate::node::tests::test_owner();
    let out = node_a.execute_stake(stmt, &carrier, o.reward, w.reward_blind, &mem, &tip, &yc_note(o.out_cms[0]), &yc_note(o.out_cms[1]), &[owner.clone(), owner]);
    (out, o)
}

/// THE CLAIM UNDER TEST: on a fresh pair (one bonded custodian on both), a real USDm note minted by a peg-in, STAKED at
/// epoch e1 (laid by `node_a`, grafted by `node_b`), and the reward CLAIM 365 epochs later PUBLISHED on `node_a` — pooled,
/// not laid. Returns both nodes, the claim's epoch, its outputs, and its full wire as `node_a` would carry it.
fn yc_claim_published(tag: u64) -> (Node, Node, u64, usdm_decider::whir_rec_block::StakeOutputs, Vec<u8>) {
    yc_claim_published_after(tag, 365)
}

/// `yc_claim_published` with the claim `delta` epochs after the stake (e1 = 20,000; the claim at e1 + delta).
fn yc_claim_published_after(tag: u64, delta: u64) -> (Node, Node, u64, usdm_decider::whir_rec_block::StakeOutputs, Vec<u8>) {
    let (node_a, node_b, e2, claim, wire, _w) = yc_claim_published_full(tag, delta, false);
    (node_a, node_b, e2, claim, wire)
}

/// The full claim fixture: `unstake` returns the principal as plain USDm (`out0_staked = false`) instead of re-staking it;
/// also returns the claim's witness (its `out1_sk` opens the reward note, for a re-stake).
#[allow(clippy::type_complexity)]
fn yc_claim_published_full(
    tag: u64,
    delta: u64,
    unstake: bool,
) -> (Node, Node, u64, usdm_decider::whir_rec_block::StakeOutputs, Vec<u8>, usdm_decider::whir_rec_block::StakeWitness) {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block as wr;
    use crate::node::tests::{reserve_for, test_d_blind, test_owner, test_recipient};
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let mk = || Node::new_folding_at_tip_for_test(crate::node::tests::genesis_block()).expect("a node builds");
    let (mut node_a, mut node_b) = (mk(), mk());
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (ek, dk) = crate::pqkem::keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    for n in [&mut node_a, &mut node_b] {
        n.admit_validator(vid, 20_000, 0).expect("seats");
        n.register_validator_custody(vid, vec![2u8; 33], [9u8; 32]);
        n.register_custody_kem(vid, ek.clone());
    }
    node_a.set_custodian_identity(vid, dk);
    let (e1, e2) = (20_000u64, 20_000u64 + delta);
    let v: u64 = 1_000;
    let note_sk_owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x2370, tag, 2, 3]));
    let note_sk = note_sk_owner.opening(); // DB-395: the note's opening, under its owner
    let (mint_carrier, cm, _dc) = wr::prove_mint_validity_committed_bytes(v, &note_sk, &test_d_blind()).expect("the mint proves");
    let reserve = reserve_for(&node_a, &test_d_blind());
    crate::node::tests::fund_test_deposit(&mut node_a, &reserve, &test_d_blind(), 1_000_000); // §BR-2: the coin and the depositor's sweep authorization
    let dep = [0x23u8; 32];
    let out = node_a.execute_peg_in(
        dep, 3_000, u128::from(v), test_recipient(&dep), &yc_note(cm), &mint_carrier, &reserve, &pk, &sk, &[],
        &crate::pqauth::MlDsaVerifier, &test_owner(), [0x7au8; 32], test_d_blind(),
    );
    assert!(matches!(out, crate::peg::PegOutcome::ConfidentialPublished), "PRECONDITION: the mint publishes: {out:?}");
    let blk = node_a.produce(yc_ts(e1) - 500, Hash32::hash(b"yc-mint"), Hash32::hash(b"yc-mint-m")).expect("the mint block");
    assert!(matches!(node_b.ingest_block(blk, yc_ts(e1)), RelayOutcome::Added(_)), "node_b grafts the mint block");
    let w_stake = wr::StakeWitness {
        value_in: v,
        owner: note_sk_owner,
        in_staked: false,
        e0: 0,
        lc_blind: lanes_of(&[0x2370, tag, 4, 4]),
        out0_value: v,
        out0_opening: yc_opening(tag, 5),
        out0_staked: true,
        out1_opening: lanes_of(&[0x2370, tag, 6, 6]),
        reward_blind: lanes_of(&[0x2370, tag, 7, 7]),
    };
    let (out, staked) = yc_publish(&mut node_a, &w_stake, b32(cm), e1);
    assert!(matches!(out, crate::peg::PegOutcome::ConfidentialMinted), "PRECONDITION: node_a publishes the stake: {out:?}");
    let blk = node_a.produce(yc_ts(e1), Hash32::hash(b"yc-stake"), Hash32::hash(b"yc-stake-m")).expect("the stake block");
    assert!(matches!(node_b.ingest_block(blk, yc_ts(e1) + 500), RelayOutcome::Added(_)), "node_b grafts the stake block");
    let staked_cm = b32(staked.out_cms[0]);
    assert!(node_a.holds_record_with_cm(&staked_cm) && node_b.holds_record_with_cm(&staked_cm), "PRECONDITION: both hold the staked note");
    let w_claim = wr::StakeWitness {
        value_in: v,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(yc_key(tag, 5)),
        in_staked: true,
        e0: e1,
        lc_blind: lanes_of(&[0x2370, tag, 8, 8]),
        out0_value: v,
        out0_opening: lanes_of(&[0x2370, tag, 9, 9]),
        out0_staked: !unstake,
        out1_opening: yc_opening(tag, 10),
        reward_blind: lanes_of(&[0x2370, tag, 11, 11]),
    };
    // §BR-3 17.6: a reward is paid from the stakers' pool — it collects fees (the same credit on both nodes, as their folds of
    // the same fee payers make it) and epoch e2's first block snapshots it before the claim is built against it
    for n in [&mut node_a, &mut node_b] {
        assert!(n.peg_mut_for_test().credit_fee_pools(1_000_000), "the stakers' share");
    }
    yc_open_epoch(&mut node_a, &mut node_b, e2, tag);
    assert!(node_a.peg().stakers_pool_snapshot(e2).is_some_and(|p| p > 0), "PRECONDITION: epoch e2's pool snapshot holds the fees");
    let (out, claim) = yc_publish(&mut node_a, &w_claim, staked_cm, e2);
    assert!(matches!(out, crate::peg::PegOutcome::ConfidentialMinted), "PRECONDITION: node_a publishes the claim: {out:?}");
    let rate = u64::from(node_a.params().stake_reward_apr_bps);
    assert_eq!(
        Some(claim.reward),
        wr::stake_reward(v, rate, delta),
        "CALIBRATION: the claim's proven reward is EXACTLY the closed form floor(v · rate · Δ / (10,000 · 365)) for Δ = {delta}"
    );
    let wire = node_a
        .mempool()
        .all_tx_ids()
        .into_iter()
        .filter_map(|id| node_a.mempool().get(&Hash32(id)).map(|tx| tx.blob.clone()))
        .find(|blob| matches!(crate::chain_object::unframe(blob), Some((crate::chain_object::Class::YieldClaim, _))))
        .expect("CALIBRATION: node_a pooled its framed claim for its next block");
    (node_a, node_b, e2, claim, wire, w_claim)
}

fn yc_decoded(wire: &[u8]) -> crate::stake_tx::StakeDecoded {
    let (_, payload) = crate::chain_object::unframe(wire).expect("framed");
    crate::stake_tx::decode(payload).expect("the honest claim decodes")
}

/// CONTROL — THE BURN CLASS: the claim `node_a` still holds pooled lays (in its epoch) and lands on BOTH nodes: the
/// reward note in exactly one record each and one committed supply.
fn yc_the_honest_claim_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, e: u64, claim: &usdm_decider::whir_rec_block::StakeOutputs, seed: &[u8]) {
    let honest = node_a.produce(yc_ts(e) + 4_000, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest claim");
    assert!(!honest.credit_set.is_empty(), "⛔ DB-377 CLASS: node_a laid a block WITHOUT its pooled claim");
    dd_graft_then_settle(node_a, node_b, honest, yc_ts(e) + 4_500, seed);
    let reward = crate::spend_frontier::leaf_to_cm_bytes(claim.out_cms[1]);
    assert_eq!(cm_occurrences(node_a, &reward), 1, "CONTROL: the reward note sits in exactly one record on node_a");
    assert_eq!(cm_occurrences(node_b, &reward), 1, "CONTROL: the reward note sits in exactly one record on node_b");
    assert_eq!(node_a.peg().minted_commit(), node_b.peg().minted_commit(), "CONTROL: one committed supply on both nodes");
}

fn yc_notes(d: &crate::stake_tx::StakeDecoded) -> Vec<u8> {
    [d.out0.clone(), d.out1.clone()].concat()
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — YieldClaim × FORGE, through a peer: the claim with its STAKE CARRIER corrupted (a reward
/// nothing proves), carried by the rogue `node_b` in the claim's epoch. The peer credits no reward and its supply does
/// not move; CONTROL: the honest claim then lands on both nodes.
#[test]
fn a_yield_claim_whose_stake_carrier_proves_nothing_carried_by_a_rogue_producer_pays_no_reward_on_the_peer() {
    let (mut node_a, mut node_b, e2, claim, wire) = yc_claim_published(1);
    let minted0 = node_a.peg().minted_commit();
    let mut d = yc_decoded(&wire);
    let mid = d.stake_carrier.len() / 2;
    d.stake_carrier[mid] ^= 0x01;
    let carriage = crate::chain_object::carriage_of(&crate::stake_tx::wire(&d)).expect("a corrupted carrier still decodes: it is judged at the fold");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, yc_notes(&d), d.h.nullifier, yc_ts(e2) + 1_000, b"yc-forge-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, yc_ts(e2) + 1_500, "a yield claim whose stake carrier proves nothing");
    assert_eq!(cm_occurrences(&node_a, &crate::spend_frontier::leaf_to_cm_bytes(claim.out_cms[1])), 0, "⛔ ROGUE PRODUCER: the peer paid a reward no stake carrier proves");
    assert_eq!(node_a.peg().minted_commit(), minted0, "⛔ ROGUE PRODUCER: an unproven claim moved the peer's committed supply");
    yc_the_honest_claim_lands_on_both_nodes(&mut node_a, &mut node_b, e2, &claim, b"yc-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — YieldClaim × STRIP, through a peer: the claim with its MEMBERSHIP CARRIER stripped (the bind
/// that its staked input exists; the codec refuses it, so the rogue lays the bytes by hand). The peer pays nothing;
/// CONTROL: the honest claim then lands on both nodes.
#[test]
fn a_yield_claim_stripped_of_its_membership_carrier_carried_by_a_rogue_producer_pays_no_reward_on_the_peer() {
    let (mut node_a, mut node_b, e2, claim, wire) = yc_claim_published(2);
    let minted0 = node_a.peg().minted_commit();
    let honest = yc_decoded(&wire);
    let mut d = honest.clone();
    d.membership_carrier.clear();
    let note_ref = |n: &[u8]| [n[..32].to_vec(), Hash32::hash(n).0.to_vec()].concat();
    d.out0 = note_ref(&honest.out0);
    d.out1 = note_ref(&honest.out1);
    let rogue = dd_rogue_block_carrying(&mut node_b, crate::stake_tx::wire(&d), yc_notes(&honest), honest.h.nullifier, yc_ts(e2) + 1_000, b"yc-strip-rogue");
    both_judge_strip(&mut node_a, &mut node_b, rogue, yc_ts(e2) + 1_500, "a yield claim with its membership carrier stripped");
    assert_eq!(cm_occurrences(&node_a, &crate::spend_frontier::leaf_to_cm_bytes(claim.out_cms[1])), 0, "⛔ ROGUE PRODUCER: the peer paid a claim with no membership bind");
    assert_eq!(node_a.peg().minted_commit(), minted0, "⛔ ROGUE PRODUCER: a claim with no membership bind moved the peer's supply");
    yc_the_honest_claim_lands_on_both_nodes(&mut node_a, &mut node_b, e2, &claim, b"yc-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — YieldClaim × SUBSTITUTE, through a peer (DB-365 class): the claim's REWARD NOTE swapped for
/// one the rogue chose (header and note consistent, so it decodes) under the stake carrier that proved the original. The
/// peer credits neither note and its supply does not move; CONTROL: the honest claim then lands on both nodes.
#[test]
fn a_yield_claim_whose_reward_note_was_swapped_carried_by_a_rogue_producer_pays_no_reward_on_the_peer() {
    let (mut node_a, mut node_b, e2, claim, wire) = yc_claim_published(3);
    let minted0 = node_a.peg().minted_commit();
    let mut d = yc_decoded(&wire);
    let forged_cm = usdm_decider::poseidon2_compress::lanes_of(&[0xBAD, 0x5E1, 0x365, 3]);
    d.h.out1_cm = forged_cm;
    d.out1 = yc_note(forged_cm);
    let carriage = crate::chain_object::carriage_of(&crate::stake_tx::wire(&d)).expect("a consistent swapped note decodes: the carrier is the fold's");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, yc_notes(&d), d.h.nullifier, yc_ts(e2) + 1_000, b"yc-swap-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, yc_ts(e2) + 1_500, "a yield claim whose reward note was swapped");
    assert_eq!(cm_occurrences(&node_a, &crate::spend_frontier::leaf_to_cm_bytes(forged_cm)), 0, "⛔ ROGUE PRODUCER: the peer credited a reward note the carrier never proved");
    assert_eq!(node_a.peg().minted_commit(), minted0, "⛔ ROGUE PRODUCER: a swapped reward moved the peer's supply");
    yc_the_honest_claim_lands_on_both_nodes(&mut node_a, &mut node_b, e2, &claim, b"yc-swap-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — YieldClaim × REPLAY, through a peer, ON THE BLOCK PATH: the honest claim lands on both
/// nodes; the rogue `node_b` re-carries the SAME claim (its staked input's nullifier in the lane) later in the epoch. The
/// peer pays the reward ONCE: the reward note in one record, the committed supply unchanged by the replay.
#[test]
fn a_yield_claim_re_carried_by_a_rogue_producer_pays_its_reward_once_on_the_peer() {
    let (mut node_a, mut node_b, e2, claim, wire) = yc_claim_published(4);
    yc_the_honest_claim_lands_on_both_nodes(&mut node_a, &mut node_b, e2, &claim, b"yc-replay-honest");
    let minted1 = node_a.peg().minted_commit();
    let d = yc_decoded(&wire);
    let carriage = crate::chain_object::carriage_of(&wire).expect("the honest claim has a carriage form");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, yc_notes(&d), d.h.nullifier, yc_ts(e2) + 9_000, b"yc-replay-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, yc_ts(e2) + 9_500, "a RE-CARRIED, already paid yield claim");
    assert_eq!(cm_occurrences(&node_a, &crate::spend_frontier::leaf_to_cm_bytes(claim.out_cms[1])), 1, "⛔ ROGUE PRODUCER: the peer paid one stake's reward TWICE");
    assert_eq!(node_a.peg().minted_commit(), minted1, "⛔ ROGUE PRODUCER: a re-carried claim moved the peer's supply again");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — YieldClaim × BURN, through a peer: a REFUSED claim naming the victim's staked-note nullifier
/// — the honest object with its SUPPLY carrier corrupted — carried by the rogue `node_b` with that nullifier in its lane.
/// The refused object must cost the staker nothing: the peer pays nothing from it, and the staker's real claim then lands
/// on both nodes.
#[test]
fn a_refused_yield_claim_naming_a_victims_stake_does_not_stop_its_real_claim_on_the_peer() {
    let (mut node_a, mut node_b, e2, claim, wire) = yc_claim_published(5);
    let minted0 = node_a.peg().minted_commit();
    let mut d = yc_decoded(&wire);
    let mid = d.supply_carrier.len() / 2;
    d.supply_carrier[mid] ^= 0x01;
    let carriage = crate::chain_object::carriage_of(&crate::stake_tx::wire(&d)).expect("a corrupted carrier still decodes");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, yc_notes(&d), d.h.nullifier, yc_ts(e2) + 1_000, b"yc-burn-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, yc_ts(e2) + 1_500, "a refused yield claim naming the victim's stake nullifier");
    assert_eq!(node_a.peg().minted_commit(), minted0, "⛔ ROGUE PRODUCER: a claim whose supply carrier proves nothing moved the peer's supply");
    yc_the_honest_claim_lands_on_both_nodes(&mut node_a, &mut node_b, e2, &claim, b"yc-burn-settle");
}

// ═══════════════════════════════════════════════ PoolWithdraw ═══════════════════════════════════════════════

/// The receipt of `pd_core`'s deposit LANDED on both nodes, then its full withdrawal (600, no liquidation in between so it
/// compounds to itself) PUBLISHED on the custodian `node_a` — pooled, not laid. The production doors of
/// `node::tests::a_stability_pool_deposit_and_its_withdrawal_travel_to_a_peer_with_one_pool`. Returns both nodes, the
/// withdrawn note's commitment and the full wire of the framed withdrawal as `node_a` would carry it.
fn pw_published(tag: u64) -> (Node, Node, [u8; 32], Vec<u8>) {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block as wr;
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let (mut node_a, mut node_b, grant, w, deposit_wire) = pd_core(tag);
    let receipt_cm = pd_decoded(&deposit_wire).h.receipt_cm;
    let blk = node_a.produce(12_000, Hash32::hash(b"pw-deposit"), Hash32::hash(b"pw-deposit-m")).expect("the deposit block");
    dd_graft_then_settle(&mut node_a, &mut node_b, blk, 12_500, b"pw-deposit-settle");
    assert!(node_a.holds_record_with_cm(&b32(receipt_cm)) && node_b.holds_record_with_cm(&b32(receipt_cm)), "PRECONDITION: both hold the receipt");
    let rw = wr::PoolReceiptWitness {
        owner_sk: w.owner_sk,
        deposit: 600,
        p_dep: grant.p,
        p_blind: grant.pd_blind,
        p_blind2: lanes_of(&[0x9401, tag, 1, 1]),
        s_dep: grant.s,
        s_blind: grant.sd_blind,
        s_blind2: lanes_of(&[0x9401, tag, 2, 2]),
        lc_blind: lanes_of(&[0x9401, tag, 3, 3]),
        d_blind2: lanes_of(&[0x9401, tag, 4, 4]),
        compounded: 600,
        out_opening: lanes_of(&[0x9401, tag, 5, 5]),
        u_blind: lanes_of(&[0x9401, tag, 6, 6]),
    };
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    let (rc, rs) = wr::prove_pool_receipt_bytes(&rw, asset, grant.epoch).expect("the receipt carrier proves");
    let (rmem, rtip) = crate::node::tests::one_step_membership_for_test(&node_a, &b32(receipt_cm), receipt_cm, rs.nullifier, rw.lc_blind)
        .expect("node_a holds the receipt");
    let out = node_a.execute_pool_withdraw(
        rs.clone(), &rc, 600, rw.d_blind2, grant.p, rw.p_blind2, grant.s, rw.s_blind2, 600, rw.u_blind, &rmem, &rtip,
        &yc_note(rs.out_cm), &crate::node::tests::test_owner(), "bc1qrolerolewithdraw", lanes_of(&[0x9401, tag, 7, 7]),
    );
    assert!(matches!(out, crate::peg::PegOutcome::ConfidentialMinted), "PRECONDITION: node_a publishes the withdrawal: {out:?}");
    let wire = node_a
        .mempool()
        .all_tx_ids()
        .into_iter()
        .filter_map(|id| node_a.mempool().get(&Hash32(id)).map(|tx| tx.blob.clone()))
        .find(|blob| matches!(crate::chain_object::unframe(blob), Some((crate::chain_object::Class::PoolWithdraw, _))))
        .expect("CALIBRATION: node_a pooled its framed withdrawal for its next block");
    (node_a, node_b, b32(rs.out_cm), wire)
}

fn pw_decoded(wire: &[u8]) -> crate::pool_tx::PoolWithdrawDecoded {
    let (_, payload) = crate::chain_object::unframe(wire).expect("framed");
    crate::pool_tx::decode_withdraw(payload).expect("the honest withdrawal decodes")
}

/// CONTROL — THE BURN CLASS: the withdrawal `node_a` still holds pooled lays and lands on BOTH nodes: the withdrawn note
/// in exactly one record each, one pool.
fn pw_the_honest_withdrawal_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, out_cm: &[u8; 32], at: u64, seed: &[u8]) {
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest withdrawal");
    assert!(!honest.credit_set.is_empty(), "⛔ DB-377 CLASS: node_a laid a block WITHOUT its pooled withdrawal");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    assert_eq!(cm_occurrences(node_a, out_cm), 1, "CONTROL: the withdrawn note sits in exactly one record on node_a");
    assert_eq!(cm_occurrences(node_b, out_cm), 1, "CONTROL: the withdrawn note sits in exactly one record on node_b");
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    assert_eq!(node_a.peg().pool_words(asset), node_b.peg().pool_words(asset), "CONTROL: one pool on both nodes");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PoolWithdraw × FORGE, through a peer: the withdrawal with its WITHDRAW carrier (the gain /
/// compounding leg) corrupted, carried by the rogue `node_b` with the receipt's nullifier in its lane. The peer credits
/// no note and its pool does not move; CONTROL: the honest withdrawal then lands on both nodes.
#[test]
fn a_pool_withdrawal_with_a_forged_withdraw_leg_carried_by_a_rogue_producer_moves_no_peer_pool() {
    let (mut node_a, mut node_b, out_cm, wire) = pw_published(11);
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    let pool0 = node_a.peg().pool_words(asset);
    let mut d = pw_decoded(&wire);
    let mid = d.withdraw_carrier.len() / 2;
    d.withdraw_carrier[mid] ^= 0x01;
    let carriage = crate::chain_object::carriage_of(&crate::pool_tx::wire_withdraw(&d)).expect("a corrupted leg still decodes: it is judged at the fold");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, d.out.clone(), d.h.nullifier, 16_000, b"pw-forge-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 16_500, "a pool withdrawal whose withdraw leg proves nothing");
    assert_eq!(cm_occurrences(&node_a, &out_cm), 0, "⛔ ROGUE PRODUCER: the peer credited a withdrawal whose leg proves nothing");
    assert_eq!(node_a.peg().pool_words(asset), pool0, "⛔ ROGUE PRODUCER: a forged withdrawal moved the peer's pool");
    pw_the_honest_withdrawal_lands_on_both_nodes(&mut node_a, &mut node_b, &out_cm, 19_000, b"pw-forge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PoolWithdraw × FORGE the EPOCH BRIDGE (H11 §2.5), through a peer, twice: (1) the bridge carrier
/// corrupted; (2) the bridged pair `(PB, SB)` re-pointed at the receipt's OWN snapshot `(PD, SD)` — the claim that the
/// pool never moved since the deposit (no retire absorbed, no gain owed), the shape a frozen-words settlement would pay.
/// Each is carried by the rogue `node_b` with the receipt's nullifier in its lane; the peer credits no note and its pool
/// does not move. CONTROL: the honest withdrawal then lands on both nodes.
#[test]
fn a_pool_withdrawal_with_a_forged_epoch_bridge_carried_by_a_rogue_producer_moves_no_peer_pool() {
    let (mut node_a, mut node_b, out_cm, wire) = pw_published(15);
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    let pool0 = node_a.peg().pool_words(asset);
    let mut corrupted = pw_decoded(&wire);
    let mid = corrupted.bridge_carrier.len() / 2;
    corrupted.bridge_carrier[mid] ^= 0x01;
    let mut repointed = pw_decoded(&wire);
    (repointed.h.pb, repointed.h.sb) = (repointed.h.pd, repointed.h.sd);
    for (k, (d, what, seed)) in [
        (corrupted, "a pool withdrawal whose epoch bridge proves nothing", b"pw-bridge-rogue-1"),
        (repointed, "a pool withdrawal bridged to its own deposit snapshot", b"pw-bridge-rogue-2"),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 16_000 + 1_000 * k as u64;
        let carriage = crate::chain_object::carriage_of(&crate::pool_tx::wire_withdraw(&d)).expect("a forged bridge still decodes: it is judged at the fold");
        let rogue = dd_rogue_block_carrying(&mut node_b, carriage, d.out.clone(), d.h.nullifier, at, seed);
        both_judge(&mut node_a, &mut node_b, rogue, at + 500, what);
        assert_eq!(cm_occurrences(&node_a, &out_cm), 0, "⛔ ROGUE PRODUCER: the peer credited {what}");
        assert_eq!(node_a.peg().pool_words(asset), pool0, "⛔ ROGUE PRODUCER: {what} moved the peer's pool");
    }
    pw_the_honest_withdrawal_lands_on_both_nodes(&mut node_a, &mut node_b, &out_cm, 19_000, b"pw-bridge-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PoolWithdraw × STRIP, through a peer: the withdrawal with its MEMBERSHIP CARRIER stripped (the
/// bind that the receipt was ever deposited; the codec refuses it, so the rogue lays the bytes by hand). The peer credits
/// nothing; CONTROL: the honest withdrawal then lands on both nodes.
#[test]
fn a_pool_withdrawal_stripped_of_its_membership_carrier_carried_by_a_rogue_producer_moves_no_peer_pool() {
    let (mut node_a, mut node_b, out_cm, wire) = pw_published(12);
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    let pool0 = node_a.peg().pool_words(asset);
    let honest = pw_decoded(&wire);
    let mut d = honest.clone();
    d.membership_carrier.clear();
    d.out = [honest.out[..32].to_vec(), Hash32::hash(&honest.out).0.to_vec()].concat();
    let rogue = dd_rogue_block_carrying(&mut node_b, crate::pool_tx::wire_withdraw(&d), honest.out.clone(), honest.h.nullifier, 16_000, b"pw-strip-rogue");
    both_judge_strip(&mut node_a, &mut node_b, rogue, 16_500, "a pool withdrawal with its membership carrier stripped");
    assert_eq!(cm_occurrences(&node_a, &out_cm), 0, "⛔ ROGUE PRODUCER: the peer credited a withdrawal with no membership bind");
    assert_eq!(node_a.peg().pool_words(asset), pool0, "⛔ ROGUE PRODUCER: a withdrawal with no membership bind moved the peer's pool");
    pw_the_honest_withdrawal_lands_on_both_nodes(&mut node_a, &mut node_b, &out_cm, 19_000, b"pw-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PoolWithdraw × SUBSTITUTE, through a peer: the withdrawn NOTE swapped for one the rogue chose
/// (header and note made consistent so it decodes) under the receipt carrier that proved the original. The peer credits
/// neither note and its pool does not move; CONTROL: the honest withdrawal then lands on both nodes.
#[test]
fn a_pool_withdrawal_whose_output_note_was_swapped_carried_by_a_rogue_producer_moves_no_peer_pool() {
    let (mut node_a, mut node_b, out_cm, wire) = pw_published(13);
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    let pool0 = node_a.peg().pool_words(asset);
    let mut d = pw_decoded(&wire);
    let forged = usdm_decider::poseidon2_compress::lanes_of(&[0xBAD, 0x9401, 13, 13]);
    d.h.out_cm = forged;
    d.out = yc_note(forged);
    let carriage = crate::chain_object::carriage_of(&crate::pool_tx::wire_withdraw(&d)).expect("a consistent swapped note decodes: the carrier is the fold's");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, d.out.clone(), d.h.nullifier, 16_000, b"pw-swap-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 16_500, "a pool withdrawal whose output note was swapped");
    assert_eq!(cm_occurrences(&node_a, &crate::spend_frontier::leaf_to_cm_bytes(forged)), 0, "⛔ ROGUE PRODUCER: the peer credited a withdrawn note the receipt never proved");
    assert_eq!(node_a.peg().pool_words(asset), pool0, "⛔ ROGUE PRODUCER: a swapped withdrawal moved the peer's pool");
    pw_the_honest_withdrawal_lands_on_both_nodes(&mut node_a, &mut node_b, &out_cm, 19_000, b"pw-swap-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — PoolWithdraw × BURN, through a peer: a REFUSED withdrawal naming the victim's receipt
/// nullifier — the honest object with its TRANSITION carrier corrupted — carried by the rogue `node_b` with that nullifier
/// in its lane. The refused object must cost the depositor nothing: the receipt still withdraws on both nodes.
#[test]
fn a_refused_pool_withdrawal_naming_a_victims_receipt_does_not_stop_its_real_withdrawal_on_the_peer() {
    let (mut node_a, mut node_b, out_cm, wire) = pw_published(14);
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    let pool0 = node_a.peg().pool_words(asset);
    let mut d = pw_decoded(&wire);
    let mid = d.transition_carrier.len() / 2;
    d.transition_carrier[mid] ^= 0x01;
    let carriage = crate::chain_object::carriage_of(&crate::pool_tx::wire_withdraw(&d)).expect("a corrupted transition still decodes");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, d.out.clone(), d.h.nullifier, 16_000, b"pw-burn-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 16_500, "a refused pool withdrawal naming the victim's receipt");
    assert_eq!(node_a.peg().pool_words(asset), pool0, "⛔ ROGUE PRODUCER: a withdrawal whose transition proves nothing moved the peer's pool");
    pw_the_honest_withdrawal_lands_on_both_nodes(&mut node_a, &mut node_b, &out_cm, 19_000, b"pw-burn-settle");
}

// ═══════════════════════════════════════════════ Liquidation ═══════════════════════════════════════════════

type LqSnap = (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, crate::peg::PoolWords);

fn lq_snap(n: &Node) -> LqSnap {
    (n.peg().reserve_commit(), n.peg().minted_commit(), n.peg().pool_words(crate::peg::NATIVE_PEG_ASSET_ID))
}

/// A DUE liquidation PUBLISHED on the custodian `node_a` (pooled, not laid) — the production sequence of
/// `node::tests::a_due_psm_liquidation_through_the_stability_pool_travels_to_a_peer_with_one_peg_and_one_pool`: the PSM
/// (3,000 deposited / 1,000 minted by a real peg-in), 900 of that USDm in the stability pool (laid, both nodes), the bonded
/// quorum marks 0.41 on both nodes (1,230 of value against 1,000: under the 125 % due line), the custodian signs its due
/// liquidation, both nodes gather the signature, and `node_a` builds the five legs and frames them. Returns both nodes, the
/// header and the full wire as `node_a` would carry it.
fn lq_published(tag: u64) -> (Node, Node, crate::liquidation_tx::LiquidationHeader, Vec<u8>) {
    let (mut node_a, mut node_b, _grant, _w, _deposit_wire, pk, sk) = pd_core_with(tag, 900);
    let blk = node_a.produce(9_000, Hash32::hash(b"lq-deposit"), Hash32::hash(b"lq-deposit-m")).expect("the deposit block");
    assert!(matches!(node_b.ingest_block(blk, 9_500), RelayOutcome::Added(_)), "node_b grafts the deposit block");
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    assert_eq!(node_a.peg().pool_census(), node_b.peg().pool_census(), "PRECONDITION: one pool before the liquidation");
    let v = crate::pqauth::MlDsaVerifier;
    let epoch = node_a.current_price_epoch();
    let quotes = vec![crate::price_quote::sign_quote(epoch, asset, 410_000, &pk, &sk).expect("the bonded key quotes").quote];
    for n in [&mut node_a, &mut node_b] {
        let marked = n.mark_price_attested(epoch, asset, &quotes, &v);
        assert!(matches!(marked, crate::peg::PegOutcome::PriceMarked(_)), "PRECONDITION: the bonded quorum marks 0.41: {marked:?}");
    }
    let sigs = node_a.own_liquidation_sigs(&pk, &sk);
    assert_eq!(sigs.len(), 1, "PRECONDITION: the custodian signs exactly the one due liquidation");
    let wire_sig = crate::liquidation_tx::LiquidationSig::decode(&sigs[0].wire()).expect("the signature crosses the lane");
    assert!(node_a.liquidation_sig_ingest(&wire_sig, &v) && node_b.liquidation_sig_ingest(&wire_sig, &v), "PRECONDITION: both gather it");
    let (due, att) = node_a.liquidation_ready_to_frame(&v).expect("PRECONDITION: node_a holds ≥ 2/3 over its own due header");
    let h = due.header;
    let legs = due.prove_legs().expect("the five legs prove off the lock");
    node_a.publish_liquidation(&h, &legs, &att).expect("node_a frames and pools the liquidation");
    let wire = node_a
        .mempool()
        .all_tx_ids()
        .into_iter()
        .filter_map(|id| node_a.mempool().get(&Hash32(id)).map(|tx| tx.blob.clone()))
        .find(|blob| matches!(crate::chain_object::unframe(blob), Some((crate::chain_object::Class::Liquidation, _))))
        .expect("CALIBRATION: node_a pooled its framed liquidation for its next block");
    (node_a, node_b, h, wire)
}

fn lq_tag(h: &crate::liquidation_tx::LiquidationHeader) -> [u8; 32] {
    crate::peg::one_time_id_nf(crate::peg::ONE_TIME_LIQUIDATION, &crate::peg::liquidation_key(h.epoch_id, h.asset_id, &h.position_id))
}

fn lq_parts(wire: &[u8]) -> (crate::liquidation_tx::LiquidationHeader, crate::liquidation_tx::LiquidationLegs, Vec<crate::psm::MintAttestor>) {
    let (_, payload) = crate::chain_object::unframe(wire).expect("framed");
    crate::liquidation_tx::decode(payload).expect("the honest liquidation decodes")
}

/// CONTROL — THE BURN CLASS: the liquidation `node_a` still holds pooled lays and lands on BOTH nodes: both stand on the
/// header's new PSM commitments and its new pool T.
fn lq_the_honest_close_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, h: &crate::liquidation_tx::LiquidationHeader, at: u64, seed: &[u8]) {
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest liquidation");
    assert!(!honest.credit_set.is_empty(), "⛔ DB-377 CLASS: node_a laid a block WITHOUT its pooled liquidation");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    for (who, n) in [("node_a", &*node_a), ("node_b", &*node_b)] {
        assert_eq!((n.peg().reserve_commit(), n.peg().minted_commit()), (h.new_reserve_commit, h.new_minted_commit), "CONTROL: {who} holds the liquidated PSM");
        assert_eq!(n.peg().pool_words(crate::peg::NATIVE_PEG_ASSET_ID).t, h.new_pool_t, "CONTROL: {who}'s pool burned the retired USDm");
    }
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — Liquidation × STRIP, through a peer: the due liquidation with its ATTESTATIONS removed (the
/// codec refuses it; the rogue lays the raw object). The peer's PSM and pool do not move; CONTROL: the honest close lands.
#[test]
fn a_liquidation_stripped_of_its_attestations_carried_by_a_rogue_producer_moves_no_peer_psm() {
    let (mut node_a, mut node_b, h, wire) = lq_published(21);
    let before = lq_snap(&node_a);
    let (hh, legs, _att) = lq_parts(&wire);
    let stripped = crate::liquidation_tx::wire(&hh, &legs, &[]);
    let rogue = dd_rogue_block_carrying(&mut node_b, stripped, Vec::new(), lq_tag(&h), 11_000, b"lq-strip-rogue");
    both_judge_strip(&mut node_a, &mut node_b, rogue, 11_500, "a liquidation with NO attestations");
    assert_eq!(lq_snap(&node_a), before, "⛔ ROGUE PRODUCER: an unattested liquidation moved the peer's PSM or pool");
    lq_the_honest_close_lands_on_both_nodes(&mut node_a, &mut node_b, &h, 13_000, b"lq-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — Liquidation × SUBSTITUTE, through a peer, ON THE BLOCK PATH: the attested liquidation with its
/// AMOUNT and POOL-STEP legs swapped under the attestation (the node pin's tamper, applied there through the apply door
/// directly; here a peer grafts it in a rogue block). The peer's PSM and pool do not move; CONTROL: the honest close lands.
#[test]
fn a_liquidation_whose_legs_were_swapped_under_its_attestation_carried_by_a_rogue_producer_moves_no_peer_psm() {
    let (mut node_a, mut node_b, h, wire) = lq_published(22);
    let before = lq_snap(&node_a);
    let (hh, mut legs, att) = lq_parts(&wire);
    std::mem::swap(&mut legs.amount, &mut legs.pool_step);
    let carriage = crate::chain_object::carriage_of(&crate::liquidation_tx::wire(&hh, &legs, &att)).expect("swapped legs still decode: the fold judges them");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, Vec::new(), lq_tag(&h), 11_000, b"lq-swap-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 11_500, "a liquidation whose legs were swapped under its attestation");
    assert_eq!(lq_snap(&node_a), before, "⛔ ROGUE PRODUCER: a liquidation with swapped legs moved the peer's PSM or pool");
    lq_the_honest_close_lands_on_both_nodes(&mut node_a, &mut node_b, &h, 13_000, b"lq-swap-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — Liquidation × REPLAY, through a peer: the honest close lands on both nodes; the rogue
/// `node_b` re-carries the SAME object with the position's one-time id in its lane. The peer's PSM and pool stand where
/// the honest close left them.
#[test]
fn a_liquidation_re_carried_by_a_rogue_producer_closes_the_position_once_on_the_peer() {
    let (mut node_a, mut node_b, h, wire) = lq_published(23);
    lq_the_honest_close_lands_on_both_nodes(&mut node_a, &mut node_b, &h, 11_000, b"lq-replay-honest");
    let after = lq_snap(&node_a);
    let carriage = crate::chain_object::carriage_of(&wire).expect("the honest liquidation has a carriage form");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, Vec::new(), lq_tag(&h), 15_000, b"lq-replay-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 15_500, "a RE-CARRIED, already applied liquidation");
    assert_eq!(lq_snap(&node_a), after, "⛔ ROGUE PRODUCER: a re-carried liquidation moved the peer's PSM or pool a second time");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — Liquidation × BURN, through a peer: a REFUSED liquidation naming the position's one-time id —
/// the attested object with its SEIZE leg corrupted — carried by the rogue `node_b` with that id in its lane. The refused
/// object must not close (or pre-retire) the position: the peer stays put, then the real close lands on both nodes.
#[test]
fn a_refused_liquidation_naming_a_position_does_not_stop_its_real_close_on_the_peer() {
    let (mut node_a, mut node_b, h, wire) = lq_published(24);
    let before = lq_snap(&node_a);
    let (hh, mut legs, att) = lq_parts(&wire);
    let mid = legs.seize.len() / 2;
    legs.seize[mid] ^= 0x01;
    let carriage = crate::chain_object::carriage_of(&crate::liquidation_tx::wire(&hh, &legs, &att)).expect("a corrupted leg still decodes");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, Vec::new(), lq_tag(&h), 11_000, b"lq-burn-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 11_500, "a refused liquidation naming the position's one-time id");
    assert_eq!(lq_snap(&node_a), before, "⛔ ROGUE PRODUCER: a liquidation whose seize leg proves nothing moved the peer");
    lq_the_honest_close_lands_on_both_nodes(&mut node_a, &mut node_b, &h, 13_000, b"lq-burn-settle");
}

/// ⛔⛔⛔ H11 DB-381 §2.9 — LIQUIDATION GRIEFING AND BAD DEBT, through a peer. A due position (the PSM marked under 125 %).
/// The griefer is a producer that tries to PRE-RETIRE the position's liquidation key: its block carries NOTHING but
/// `one_time_id_nf(ONE_TIME_LIQUIDATION, liquidation_key(epoch, asset, position))` in its lane — no liquidation, no proof.
/// ASSERT on the PEER: the PSM and pool do not move; the honest close then lands on BOTH nodes (DB-367: the unjustified
/// key was never retired); and the close moves EXACTLY the rule's plan — supply −C, pool −C, reserve −S, the custodian's
/// opening = `plan_liquidation(..).after` — so the position's bad debt is the rule's bound, not more.
#[test]
fn a_griefer_naming_a_due_positions_liquidation_key_cannot_block_its_close_and_the_close_moves_exactly_the_rules_plan() {
    let (mut node_a, mut node_b, h, _wire) = lq_published(25);
    let asset = crate::peg::NATIVE_PEG_ASSET_ID;
    let opening = node_a.liquidation_opening_now(asset).expect("CALIBRATION: the custodian's opening is current before the close");
    let rule = node_a.peg().liquidation_rule(asset).expect("CALIBRATION: the PSM has a rule at the chain's mark");
    let plan = crate::peg::plan_liquidation(&opening, &rule).expect("CALIBRATION: the position is due and the pool covers C");
    let before = lq_snap(&node_a);
    let mut rogue = node_b.produce(11_000, Hash32::hash(b"lq-grief-rogue"), Hash32::hash(b"rogue-mc")).expect("the griefer lays a block");
    rogue.nullifier_proof.padded_tags.push(lq_tag(&h));
    rogue.header.nullifier_tags_root = crate::block::nullifier_tags_root_of(&rogue.nullifier_proof.padded_tags);
    crate::node::tests::lay_tag_evidence_for_test(&node_b, &mut rogue, &[lq_tag(&h)]);
    both_judge(&mut node_a, &mut node_b, rogue, 11_500, "only a due position's liquidation key in its lane");
    assert_eq!(lq_snap(&node_a), before, "⛔ GRIEFING: a lane-only block moved the peer's PSM or pool");
    lq_the_honest_close_lands_on_both_nodes(&mut node_a, &mut node_b, &h, 13_000, b"lq-grief-settle");
    let after = node_a.liquidation_opening_now(asset).expect("the custodian's opening advanced with its own close");
    eprintln!(
        "[liquidation-grief-sim] MEASURED: before (reserve {}, minted {}, pool T {}); plan C = {}, S = {}; after (reserve {}, minted {}, pool T {})",
        opening.reserve, opening.minted, opening.pool_t, plan.c, plan.s, after.reserve, after.minted, after.pool_t
    );
    assert_eq!(after, plan.after, "⛔ BAD DEBT: the close did not move exactly the rule's plan");
    assert_eq!((after.minted, after.pool_t), (opening.minted - plan.c, opening.pool_t - plan.c), "the pool burned exactly the C the supply retired");
    assert_eq!(after.reserve, opening.reserve - plan.s, "the reserve released exactly the seized S");
}

// ═══════════════════════════════════════════════ AssetSpend ═══════════════════════════════════════════════

/// A wrapped note minted to a holder (laid on both nodes), then a TRANSFER of it PUBLISHED on `node_a` (pooled, not laid)
/// — the production sequence of `chain_action_carriage_tests::a_wrapped_note_minted_to_a_holder_is_moved_and_a_node_fed_
/// only_blocks_retires_it`: the in-record copath served by `node_b`, the one-step membership carrier, the validity carrier.
/// Returns both nodes, the published transfer `t` (700 / 1,300) and a SECOND, unpublished transfer of the SAME note with
/// different outputs (1,000 / 1,000) for the replay cell.
fn as_published(dep: [u8; 32], addr: &str) -> (Node, Node, crate::asset_tx::AssetSpendTx, crate::asset_tx::AssetSpendTx) {
    use usdm_decider::note_membership_air::NoteMembershipCarrier;
    use usdm_decider::whir_rec_block::{prove_asset_spend_validity_carrier_bytes, AssetSpendValidityWitness};
    let (mut node_a, mut node_b, cm, _wire) = wm_published(dep, addr);
    let mint_blk = node_a.produce(4_000, Hash32::hash(b"as-mint"), Hash32::hash(b"mc")).expect("node_a lays the wrapped mint");
    let mint_id = mint_blk.id();
    dd_graft_then_settle(&mut node_a, &mut node_b, mint_blk, 4_500, b"as-mint-settle");
    assert!(node_a.holds_record_with_cm(&cm) && node_b.holds_record_with_cm(&cm), "PRECONDITION: both hold the minted wrapped note");
    let lanes = |a: u64| usdm_decider::poseidon2_compress::lanes_of(&[a, a + 1, a + 2, a + 3]);
    let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(WM_ASSET);
    let rid = Node::da_record_id_for_block(&mint_id, 0);
    let want_leaf = crate::spend_frontier::note_leaf_of(&cm);
    let rec = node_b.da_block_leaves(rid).expect("node_b holds the mint block's record");
    let slot = rec.iter().position(|l| *l == want_leaf).expect("the wrapped note sits in its block's record") as u8;
    let (sibs, dirs, root) = node_b.da_note_copath_in_block(rid, slot).expect("node_b serves the in-record copath");
    let build = |out0: u64, seed: u64| -> crate::asset_tx::AssetSpendTx {
        let w = AssetSpendValidityWitness {
            value_in: 2_000,
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes(5)),
            value_out: 2_000,
            fee: 0,
            lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            out0_value: out0,
            out0_opening: lanes(seed),
            out1_value: 2_000 - out0,
            out1_opening: lanes(seed + 10),
            asset: wtag,
        };
        let (validity_carrier, cms, nf, lc) = prove_asset_spend_validity_carrier_bytes(&w).expect("an honest transfer proves");
        let mut mc = NoteMembershipCarrier::new(want_leaf, root, Node::MEMBERSHIP_GENESIS_ACC, nf, crate::spend_frontier::TEST_LC_BLIND);
        assert!(mc.attach_membership(want_leaf, &sibs, &dirs), "the record copath reaches the record root");
        assert!(mc.step(root), "the one fold step proves");
        let (membership_carrier, tip_acc, tip_prev, tip_root) = mc.finalize_one_step().expect("certifies");
        crate::asset_tx::AssetSpendTx {
            notes: [yc_note(cms[0]), yc_note(cms[1])],
            nullifier: crate::spend_frontier::leaf_to_cm_bytes(nf),
            leaf_commit: lc,
            validity_carrier,
            membership_carrier,
            member_tuple: Vec::new(),
            named_record: rid,
            tip_prev,
            tip_root,
            tip_acc,
            owner_clues: vec![vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX]; crate::asset_tx::ASSET_SPEND_OUTPUTS],
            slot_tag: None,
        }
    };
    let t = build(700, 61);
    let t2 = build(1_000, 81);
    let published = node_a.execute_asset_spend(&t);
    assert!(matches!(published, crate::node::AssetSpendOutcome::Published), "PRECONDITION: the holder's transfer publishes: {published:?}");
    (node_a, node_b, t, t2)
}

fn as_outs(t: &crate::asset_tx::AssetSpendTx) -> Vec<[u8; 32]> {
    t.notes.iter().map(|n| cm_of(n)).collect()
}

/// CONTROL — THE BURN CLASS: the transfer `node_a` still holds pooled lays and lands on BOTH nodes, each output in
/// exactly one record each.
fn as_the_honest_transfer_lands_on_both_nodes(node_a: &mut Node, node_b: &mut Node, t: &crate::asset_tx::AssetSpendTx, at: u64, seed: &[u8]) {
    let honest = node_a.produce(at, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays the honest transfer");
    assert!(!honest.credit_set.is_empty(), "⛔ DB-377 CLASS: node_a laid a block WITHOUT its pooled transfer");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, seed);
    for (i, cm) in as_outs(t).iter().enumerate() {
        assert_eq!(cm_occurrences(node_a, cm), 1, "CONTROL: transfer output {i} sits in exactly one record on node_a");
        assert_eq!(cm_occurrences(node_b, cm), 1, "CONTROL: transfer output {i} sits in exactly one record on node_b");
    }
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetSpend × STRIP, through a peer: the holder's transfer with its MEMBERSHIP CARRIER stripped
/// (the bind that the wrapped note was ever received; the codec refuses it, so the rogue lays the bytes by hand). The peer
/// holds neither output; CONTROL: the honest transfer then lands on both nodes.
#[test]
fn an_asset_transfer_stripped_of_its_membership_carrier_carried_by_a_rogue_producer_credits_nothing_on_the_peer() {
    let (mut node_a, mut node_b, t, _t2) = as_published([0x61u8; 32], "bc1proleasstrip");
    let mut stripped = t.clone();
    stripped.membership_carrier.clear();
    stripped.notes = [
        [t.notes[0][..32].to_vec(), Hash32::hash(&t.notes[0]).0.to_vec()].concat(),
        [t.notes[1][..32].to_vec(), Hash32::hash(&t.notes[1]).0.to_vec()].concat(),
    ];
    let rogue = dd_rogue_block_carrying(&mut node_b, stripped.wire(), t.notes.concat(), t.nullifier, 7_000, b"as-strip-rogue");
    both_judge_strip(&mut node_a, &mut node_b, rogue, 7_500, "an asset transfer with its membership carrier stripped");
    for (i, cm) in as_outs(&t).iter().enumerate() {
        assert_eq!(cm_occurrences(&node_a, cm), 0, "⛔ ROGUE PRODUCER: the peer credited output {i} of a transfer with no membership bind");
    }
    as_the_honest_transfer_lands_on_both_nodes(&mut node_a, &mut node_b, &t, 9_000, b"as-strip-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetSpend × SUBSTITUTE, through a peer: the holder's transfer with an OUTPUT swapped for a
/// note the rogue chose (any value) under the conservation carrier that proved the original outputs. The peer credits
/// neither the swapped nor the honest outputs from it; CONTROL: the honest transfer then lands on both nodes.
#[test]
fn an_asset_transfer_whose_output_was_swapped_under_its_carrier_carried_by_a_rogue_producer_credits_nothing_on_the_peer() {
    let (mut node_a, mut node_b, t, _t2) = as_published([0x62u8; 32], "bc1proleasswap");
    let mut swapped = t.clone();
    swapped.notes[0] = yc_note(usdm_decider::poseidon2_compress::lanes_of(&[0xBAD, 0xA55E7, 62, 62]));
    let forged = cm_of(&swapped.notes[0]);
    let carriage = crate::chain_object::carriage_of(&swapped.wire()).expect("a swapped output still decodes: conservation is the fold's");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, swapped.notes.concat(), t.nullifier, 7_000, b"as-swap-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 7_500, "an asset transfer whose output was swapped under its carrier");
    assert_eq!(cm_occurrences(&node_a, &forged), 0, "⛔ ROGUE PRODUCER: the peer credited an asset output the carrier never proved");
    as_the_honest_transfer_lands_on_both_nodes(&mut node_a, &mut node_b, &t, 9_000, b"as-swap-settle");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetSpend × REPLAY, ON THE BLOCK PATH, through a peer: the holder's transfer lands on both
/// nodes; the rogue `node_b` then carries a SECOND, fully valid transfer of the SAME note (new outputs, same nullifier) in
/// a block. The peer credits none of the second transfer's outputs — the note is spent on its canonical state.
#[test]
fn a_second_transfer_of_a_spent_asset_note_carried_by_a_rogue_producer_credits_nothing_on_the_peer() {
    let (mut node_a, mut node_b, t, t2) = as_published([0x63u8; 32], "bc1proleasreplay");
    as_the_honest_transfer_lands_on_both_nodes(&mut node_a, &mut node_b, &t, 7_000, b"as-replay-honest");
    assert_eq!(t2.nullifier, t.nullifier, "CALIBRATION: the second transfer spends the same note");
    let carriage = crate::chain_object::carriage_of(&t2.wire()).expect("the second transfer has a carriage form");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, t2.notes.concat(), t2.nullifier, 11_000, b"as-replay-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 11_500, "a SECOND transfer of an already spent asset note");
    for (i, cm) in as_outs(&t2).iter().enumerate() {
        assert_eq!(cm_occurrences(&node_a, cm), 0, "⛔ ROGUE PRODUCER: the peer credited output {i} of a double-spend of one asset note");
    }
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — AssetSpend × BURN, through a peer: a REFUSED transfer naming the holder's asset nullifier —
/// the honest transfer with its validity carrier corrupted — carried by the rogue `node_b` with that nullifier in its lane.
/// The refused object must cost the holder nothing: the real transfer then lands on both nodes.
#[test]
fn a_refused_asset_transfer_naming_a_holders_note_does_not_stop_its_real_transfer_on_the_peer() {
    let (mut node_a, mut node_b, t, _t2) = as_published([0x64u8; 32], "bc1proleasburn");
    let mut broken = t.clone();
    let mid = broken.validity_carrier.len() / 2;
    broken.validity_carrier[mid] ^= 0x01;
    let carriage = crate::chain_object::carriage_of(&broken.wire()).expect("a corrupted carrier still decodes");
    let rogue = dd_rogue_block_carrying(&mut node_b, carriage, t.notes.concat(), t.nullifier, 7_000, b"as-burn-rogue");
    both_judge(&mut node_a, &mut node_b, rogue, 7_500, "a refused asset transfer naming the holder's nullifier");
    as_the_honest_transfer_lands_on_both_nodes(&mut node_a, &mut node_b, &t, 9_000, b"as-burn-settle");
}

// ═══════════════════════════════════ USDm BOND (retired — validator bonds are SAT-only) ═══════════════════════════════════
// cons: none — test-only (`#[cfg(test)]`): two in-memory nodes and three blocks; nothing is persisted; every size is f(one
// bond's fixed shape), no history term.

/// The bond lane's entries — `u32 length ‖ postcard(PqTx)` each, the lane's one wire form (`note_transition::bond_lane_entry`).
fn bt_entries(bond_set: &[u8]) -> Vec<crate::mempool::PqTx> {
    let mut out = Vec::new();
    let mut off = 0usize;
    // §POLES: the lane is padded to a constant behind a `u32::MAX` sentinel — walk the real frames only (RED since the
    // padding landed: "range end index 4294967299 out of range", node-101.log; last green 10-23)
    let end = crate::block::sidecar_real_len(bond_set);
    while off + 4 <= end {
        let len = u32::from_le_bytes(bond_set[off..off + 4].try_into().expect("a 4-byte length")) as usize;
        out.push(postcard::from_bytes(&bond_set[off + 4..off + 4 + len]).expect("a carried entry decodes"));
        off += 4 + len;
    }
    out
}

fn bt_is_statement(e: &crate::mempool::PqTx) -> bool {
    matches!(crate::chain_object::unframe(&e.blob), Some((crate::chain_object::Class::BondTransition, _)))
}

/// Two testnet nodes folding at the tip; a real USDm note funded on `node_a` (its block grafted and folded on `node_b`),
/// and a REAL bond of 300,000,000 over it signed by V — the DB-345 production sequence (`real_bond_tx_for_test`). The bond
/// tx is pooled on BOTH nodes (the rogue `node_b` pools it too, so its own block welds the producer's statement over it).
/// Returns both nodes, V's id, the bond's weight and the bond tx.
fn bt_fixture(tag: u64) -> (Node, Node, [u8; 32], u128, crate::mempool::PqTx) {
    use usdm_decider::poseidon2_compress::lanes_of;
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let weight: u64 = 300_000_000;
    let w = usdm_decider::whir_rec_block::SpendValidityWitness {
        value_in: 500_000_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x3130, tag, 2, 3])),
        value_out: (500_000_000) - 100000,
        fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
        lc_blind: lanes_of(&[0x3130, tag, 4, 4]),
        out0_value: (weight) - 100000,
        out0_opening: lanes_of(&[0x3130, tag, 5, 5]),
        out1_value: 200_000_000,
        out1_opening: lanes_of(&[0x3130, tag, 6, 6]),
    };
    let (note, cm) = crate::node::tests::note_of_witness_for_test(&w);
    let (funding, _) = node_a.carry_notes_in_a_block_for_test(5_000, &note);
    assert!(matches!(node_b.ingest_block(funding, 5_500), RelayOutcome::Added(_)), "PRECONDITION: node_b holds the funding block");
    let _ = node_a.fold_canonical_records();
    let _ = node_b.fold_canonical_records();
    assert!(node_a.holds_record_with_cm(&cm) && node_b.holds_record_with_cm(&cm), "PRECONDITION: both hold the bond's input note");
    // (a valid bond: the rule cell's subject is that even a VALID USDm bond, laid with its proven statement, seats nothing)
    let tx = crate::node::tests::real_bond_tx_for_test(&node_a, &w, &pk, &sk).expect("the real bond builds");
    node_a.ingest_tx_prechecked(tx.clone()).expect("node_a pools the real bond");
    node_b.ingest_tx_prechecked(tx.clone()).expect("the rogue pools the real bond too");
    (node_a, node_b, vid, u128::from(weight), tx)
}

/// The peer judges the rogue's block (structurally refused or grafted — either refuses the tampered lane).
fn bt_peer_judges(node_a: &mut Node, node_b: &mut Node, rogue: crate::block::Block, at: u64, what: &str) {
    for parent in &rogue.header.parents {
        if node_a.dag().get(parent).is_none() {
            if let Some(sibling) = node_b.full_block_by_id(parent) {
                let _ = node_a.ingest_block_preverified(sibling, at);
            }
        }
    }
    // the rogue publishes its block and holds it itself — `produce` placed only its UNMUTATED copy in its DAG, so without
    // this the peer's next honest block (whose parent is the mutated copy) is `Buffered` on the rogue: a fixture artifact
    // (MEASURED 2026-10-04 20:53, the four BondTransition cells once DB-389 let the honest bond be laid)
    let _ = node_b.ingest_block_preverified(rogue.clone(), at);
    let out = node_a.ingest_block_preverified(rogue, at);
    eprintln!("[rogue-role] node_a's verdict on a block carrying {what}: {out:?}");
    assert!(matches!(out, RelayOutcome::Added(_) | RelayOutcome::Invalid(_)), "CALIBRATION: the peer judged the tampered bond lane: {out:?}");
    let _ = node_a.fold_canonical_records();
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — USDm BOND × LAY, through a peer. VALIDATOR BONDS ARE SAT-ONLY (`Node::USDM_BOND_RETIRED`,
/// 2026-10-07: a USDm bond is a claim on the reserve it would secure — DB-391 — and two bond assets need a price to add).
/// An honest template never lays a pooled USDm bond; a ROGUE producer whose template still lays one — with its proven
/// welded statement, the full pre-ruling shape — seats NOTHING: no finality weight and no seat, on the peer fed its block
/// and on the rogue itself. RED before the ruling: this exact sequence seated V's full weight on both nodes (the five
/// BondTransition cells' CONTROL, `bt_the_honest_bond_lands_on_both_nodes`, green in batch 10). The per-tamper cells
/// (forge, strip, substitute, replay, burn) are retired with the class they attacked: every one of them now reads a
/// zero that holds whatever the tamper, an assertion that cannot fail.
/// TWO-PARTY-REVIEWED: node_a is the honest producer and the peer; node_b is the rogue producer; the claim is asserted on
/// BOTH nodes' validator sets.
#[test]
fn a_usdm_bond_a_rogue_producer_lays_with_its_proven_statement_seats_nothing_on_the_peer() {
    let (mut node_a, mut node_b, vid, _weight, tx) = bt_fixture(1);
    // CALIBRATION — the honest template: node_a's block does not lay the pooled USDm bond
    let honest = node_a.produce(6_000, Hash32::hash(b"usdm-bond-honest"), Hash32::hash(b"mc")).expect("node_a lays its block");
    assert!(
        !honest.tx_ids.contains(&tx.id) && bt_entries(&honest.bond_set).iter().all(|e| e.id != tx.id),
        "⛔ an honest template laid a USDm bond — validator bonds are SAT-only"
    );
    // THE ROGUE — node_b's template lays the bond with its welded statement, the pre-ruling block exactly
    Node::set_rogue_lays_usdm_bonds_for_test(true);
    let rogue = node_b.produce(7_000, Hash32::hash(b"usdm-bond-rogue"), Hash32::hash(b"rogue-mc"));
    Node::set_rogue_lays_usdm_bonds_for_test(false);
    let rogue = rogue.expect("the rogue lays its block");
    let entries = bt_entries(&rogue.bond_set);
    assert!(
        entries.iter().any(bt_is_statement) && entries.iter().any(|e| e.id == tx.id),
        "CALIBRATION: the rogue's block carries the USDm bond AND its proven statement (the pre-ruling shape)"
    );
    bt_peer_judges(&mut node_a, &mut node_b, rogue, 7_500, "a USDm bond with its proven statement");
    let _ = node_b.fold_canonical_records();
    for (who, n) in [("the peer (node_a)", &node_a), ("the rogue itself (node_b)", &node_b)] {
        assert_eq!(
            (n.validators().finality_weight_of(&vid), n.validators().is_seated(&vid)),
            (0, false),
            "⛔⛔⛔ ROGUE PRODUCER: a USDm bond seated weight on {who} — validator bonds are SAT-only"
        );
    }
}

// ═══════════════════ H11 — ECONOMIC ADVERSARY: STAKE / YIELD AT EPOCH EDGES (DB-381 §2.6) ═══════════════════

/// ⛔⛔⛔ H11 DB-381 §2.6 — A STAKER GAMING THE EPOCH EDGE, through a peer. A real stake at e1 and its reward claim for epoch
/// e2 = e1 + Δ (Δ ∈ {1, 365}); the claim is laid in a block whose timestamp sits at each EDGE: the last ms of e2 − 1, the
/// first and the last ms of e2, the first ms of e2 + 1. The claim's carrier proves the reward for e2 exactly (asserted
/// against the closed form by the fixture). ASSERT on the PEER for every edge: the reward note is credited IFF the block's
/// own epoch is e2 (a claim cannot be cashed in a neighbouring epoch to earn an extra epoch or cash early), and both nodes
/// hold ONE committed supply. The double claim of one stake is pinned by
/// `a_yield_claim_re_carried_by_a_rogue_producer_pays_its_reward_once_on_the_peer`.
#[test]
fn a_yield_claim_pays_exactly_its_closed_form_and_only_in_its_own_epoch_on_the_peer_at_every_epoch_edge() {
    let ep = usdm_decider::whir_rec_block::STAKE_EPOCH_MS;
    let mut rows = Vec::new();
    for (k, delta) in [1u64, 365].into_iter().enumerate() {
        let e2 = 20_000 + delta;
        for (j, (edge, ts, expect_paid)) in [
            ("last ms of e2 − 1", e2 * ep - 1, false),
            ("first ms of e2", e2 * ep, true),
            ("last ms of e2", (e2 + 1) * ep - 1, true),
            ("first ms of e2 + 1", (e2 + 1) * ep, false),
        ]
        .into_iter()
        .enumerate()
        {
            let (mut node_a, mut node_b, e, claim, _wire) = yc_claim_published_after(40 + (k as u64) * 10 + j as u64, delta);
            assert_eq!(e, e2, "CALIBRATION: the claim is for e2");
            let reward = crate::spend_frontier::leaf_to_cm_bytes(claim.out_cms[1]);
            if let Some(blk) = node_a.produce(ts, Hash32::hash(b"yc-edge"), Hash32::hash(b"mc")) {
                let _ = node_b.ingest_block(blk, ts + 500);
                if let Some(next) = node_a.produce(ts + 1_000, Hash32::hash(b"yc-edge-next"), Hash32::hash(b"mc")) {
                    let _ = node_b.ingest_block(next, ts + 1_500);
                }
            }
            let _ = node_a.fold_canonical_records();
            let _ = node_b.fold_canonical_records();
            let paid_on_peer = cm_occurrences(&node_b, &reward) == 1;
            let one_supply = node_a.peg().minted_commit() == node_b.peg().minted_commit();
            rows.push((delta, edge, claim.reward, expect_paid, paid_on_peer, one_supply));
        }
    }
    eprintln!("[stake-edge-sim] MEASURED (Δ, edge, proven reward, expected paid, paid on peer, one supply): {rows:?}");
    for (delta, edge, _reward, expect_paid, paid_on_peer, one_supply) in &rows {
        assert!(*one_supply, "⛔ two committed supplies after a claim at Δ = {delta}, {edge}");
        assert_eq!(paid_on_peer, expect_paid, "⛔ EPOCH EDGE: a claim for e2 at Δ = {delta} laid at the {edge} was paid = {paid_on_peer} on the peer");
    }
}

/// ⛔⛔⛔ H11 DB-381 §2.6 — LEAVING AT THE EDGE, through a peer: the same staker UNSTAKES (principal returned as plain USDm,
/// `out0_staked = false`) for e2 = e1 + 365, laid at each epoch edge. ASSERT on the PEER: the principal note and the reward
/// note are credited IFF the block's epoch is e2, the reward is the closed form, and both nodes hold one supply.
#[test]
fn an_unstake_returns_its_principal_and_pays_its_reward_only_in_its_own_epoch_on_the_peer_at_every_epoch_edge() {
    let ep = usdm_decider::whir_rec_block::STAKE_EPOCH_MS;
    let e2 = 20_365u64;
    let mut rows = Vec::new();
    for (j, (edge, ts, expect)) in [
        ("last ms of e2 − 1", e2 * ep - 1, false),
        ("first ms of e2", e2 * ep, true),
        ("last ms of e2", (e2 + 1) * ep - 1, true),
        ("first ms of e2 + 1", (e2 + 1) * ep, false),
    ]
    .into_iter()
    .enumerate()
    {
        let (mut node_a, mut node_b, _e, claim, _wire, _w) = yc_claim_published_full(60 + j as u64, 365, true);
        let (principal, reward) = (crate::spend_frontier::leaf_to_cm_bytes(claim.out_cms[0]), crate::spend_frontier::leaf_to_cm_bytes(claim.out_cms[1]));
        if let Some(blk) = node_a.produce(ts, Hash32::hash(b"unstake-edge"), Hash32::hash(b"mc")) {
            let _ = node_b.ingest_block(blk, ts + 500);
            if let Some(next) = node_a.produce(ts + 1_000, Hash32::hash(b"unstake-edge-next"), Hash32::hash(b"mc")) {
                let _ = node_b.ingest_block(next, ts + 1_500);
            }
        }
        let _ = node_a.fold_canonical_records();
        let _ = node_b.fold_canonical_records();
        let got = (cm_occurrences(&node_b, &principal) == 1, cm_occurrences(&node_b, &reward) == 1);
        rows.push((edge, claim.reward, expect, got, node_a.peg().minted_commit() == node_b.peg().minted_commit()));
    }
    eprintln!("[unstake-edge-sim] MEASURED (edge, proven reward, expected, (principal, reward) on peer, one supply): {rows:?}");
    for (edge, _r, expect, (principal, reward), one_supply) in &rows {
        assert!(*one_supply, "⛔ two committed supplies after an unstake at the {edge}");
        assert_eq!((*principal, *reward), (*expect, *expect), "⛔ EPOCH EDGE: an unstake for e2 laid at the {edge} returned (principal, reward) = ({principal}, {reward}) on the peer");
    }
}

/// ⛔⛔⛔ H11 DB-381 §2.6 — RE-STAKING THE REWARD, through a peer: the claim for e2 = e1 + 365 lands on both nodes (reward 50
/// on 1,000 at 5 %); the staker stakes the REWARD NOTE itself in e2, and claims it 365 epochs later at e3. ASSERT on the
/// PEER: the compounded reward is EXACTLY `stake_reward(50, rate, 365)` (no rounding up, no extra epoch), it is credited
/// once, and both nodes hold one committed supply after every step. (Reward-follows-principal for a moved principal is the
/// circuit weld pinned by the DB-365 gate pins, e.g. `db365_a_swapped_reward_note_verifies_beside_no_principal_its_prover_does_not_own`.)
#[test]
fn a_re_staked_reward_compounds_by_exactly_the_closed_form_on_the_peer() {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block as wr;
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let (mut node_a, mut node_b, e2, claim, _wire, w_claim) = yc_claim_published_full(70, 365, false);
    yc_the_honest_claim_lands_on_both_nodes(&mut node_a, &mut node_b, e2, &claim, b"restake-claim");
    let rate = u64::from(node_a.params().stake_reward_apr_bps);
    let w_restake = wr::StakeWitness {
        value_in: claim.reward,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(yc_key(70, 10)),
        in_staked: false,
        e0: 0,
        lc_blind: lanes_of(&[0x2371, 1, 1, 1]),
        out0_value: claim.reward,
        out0_opening: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x2371, 2, 2, 2])).opening(),
        out0_staked: true,
        out1_opening: lanes_of(&[0x2371, 3, 3, 3]),
        reward_blind: lanes_of(&[0x2371, 4, 4, 4]),
    };
    let (out, restaked) = yc_publish(&mut node_a, &w_restake, b32(claim.out_cms[1]), e2);
    assert!(matches!(out, crate::peg::PegOutcome::ConfidentialMinted), "the reward note re-stakes on node_a: {out:?}");
    let blk = node_a.produce(yc_ts(e2) + 8_000, Hash32::hash(b"restake"), Hash32::hash(b"mc")).expect("the re-stake block");
    dd_graft_then_settle(&mut node_a, &mut node_b, blk, yc_ts(e2) + 8_500, b"restake-settle");
    let staked = b32(restaked.out_cms[0]);
    assert!(node_a.holds_record_with_cm(&staked) && node_b.holds_record_with_cm(&staked), "the re-staked reward is held on both nodes");
    let e3 = e2 + 365;
    let w_claim2 = wr::StakeWitness {
        value_in: claim.reward,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x2371, 2, 2, 2])),
        in_staked: true,
        e0: e2,
        lc_blind: lanes_of(&[0x2371, 5, 5, 5]),
        out0_value: claim.reward,
        out0_opening: lanes_of(&[0x2371, 6, 6, 6]),
        out0_staked: true,
        out1_opening: lanes_of(&[0x2371, 7, 7, 7]),
        reward_blind: lanes_of(&[0x2371, 8, 8, 8]),
    };
    yc_open_epoch(&mut node_a, &mut node_b, e3, 70);
    let (out, claim2) = yc_publish(&mut node_a, &w_claim2, staked, e3);
    assert!(matches!(out, crate::peg::PegOutcome::ConfidentialMinted), "the compounded claim publishes: {out:?}");
    let want = wr::stake_reward(claim.reward, rate, 365).expect("in range");
    eprintln!("[restake-sim] MEASURED: first reward {} on 1,000; compounded reward {} on {} (closed form {want})", claim.reward, claim2.reward, claim.reward);
    assert_eq!(claim2.reward, want, "⛔ the compounded reward is not EXACTLY the closed form");
    yc_the_honest_claim_lands_on_both_nodes(&mut node_a, &mut node_b, e3, &claim2, b"restake-claim2");
}

// ═══════════════════════ H10 — NETWORK ADVERSARY: CLOCK SKEW / TIMESTAMP MANIPULATION ═══════════════════════

/// ⛔⛔⛔ H10 — A PRODUCER THAT LIES ABOUT THE TIME, through a peer. `consensus.rs` refuses a header stamped beyond
/// `now + max_ts_drift_ms` (`TimestampTooFarFuture`) and one at or below the median-time-past (`TimestampTooEarly`). The
/// rogue `node_b` re-stamps (and re-mines) copies of one of its blocks: one ms past the drift bound, exactly AT the bound,
/// and far below the median past. ASSERT on the PEER `node_a` at its own clock `now`: the future block and the past block
/// are REFUSED with those exact errors, the at-bound block is accepted (the bound is the rule, not a margin), and the
/// honest chain continues on both nodes afterwards.
#[test]
fn a_block_stamped_past_the_drift_bound_or_at_the_median_past_is_refused_by_the_peer_and_the_honest_chain_continues() {
    let mut node_a = crate::node::tests::dd_node();
    let mut node_b = crate::node::tests::dd_node();
    let mut t = 10_000u64;
    for i in 0..4u8 {
        let blk = node_a.produce(t, Hash32::hash(&[b's', b'k', i]), Hash32::hash(b"mc")).expect("node_a produces");
        assert!(matches!(node_b.ingest_block(blk, t + 100), RelayOutcome::Added(_)), "CALIBRATION: node_b follows the shared chain");
        t += 4_000;
    }
    let drift = node_a.params().max_ts_drift_ms;
    let now = t;
    let base = node_b.produce(now, Hash32::hash(b"skew-base"), Hash32::hash(b"rogue-mc")).expect("the rogue lays a block");
    let restamp = |ts: u64| {
        let mut b = base.clone();
        b.header.timestamp = ts;
        crate::node::tests::mine_fixture_block(&mut b);
        b
    };
    let future = node_a.ingest_block(restamp(now + drift + 1), now);
    let at_bound_blk = restamp(now + drift);
    let at_bound = node_a.ingest_block(at_bound_blk.clone(), now);
    let past = node_a.ingest_block(restamp(10_000), now);
    // the rogue publishes what it lays: node_b holds the accepted at-bound block too, so the honest block (whose parent it
    // is on node_a) connects on both
    let _ = node_b.ingest_block(at_bound_blk, now + drift + 500);
    eprintln!("[clock-skew-sim] MEASURED at now = {now}, drift = {drift} ms: +drift+1 → {future:?}; +drift → {at_bound:?}; ts 10,000 (≤ MTP) → {past:?}");
    assert!(
        matches!(future, RelayOutcome::Invalid(crate::consensus::ConsensusError::TimestampTooFarFuture { .. })),
        "⛔ CLOCK SKEW: a block stamped one ms past the drift bound was not refused as too far in the future: {future:?}"
    );
    assert!(matches!(at_bound, RelayOutcome::Added(_)), "CALIBRATION: a block stamped exactly at the bound is accepted (the bound is the rule): {at_bound:?}");
    assert!(
        matches!(past, RelayOutcome::Invalid(crate::consensus::ConsensusError::TimestampTooEarly { .. })),
        "⛔ CLOCK SKEW: a block stamped at or below the median-time-past was not refused: {past:?}"
    );
    let honest = node_a.produce(now + drift + 1_000, Hash32::hash(b"skew-honest"), Hash32::hash(b"mc")).expect("node_a produces on");
    assert!(matches!(node_b.ingest_block(honest, now + drift + 1_100), RelayOutcome::Added(_)), "CONTROL: the honest chain continues on both nodes");
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// H11 §2.5 (DB-381) — THE STABILITY POOL'S ARITHMETIC AT EXTREME RATIOS. The pool is Liquity's product/sum shape: a
// deposit `d` made at `(P_dep, S_dep)` is owed `⌊d·P_now/P_dep⌋` USDm and `⌊d·(S_now − S_dep)/P_dep⌋` collateral; a
// liquidation retiring `C` of `T` moves `P ← ⌊P·(T−C)/T⌋`. The ONE rules driven here are the node's own:
// `peg::plan_liquidation` (the step, its close bit, and the opening AFTER it — what every custodian and the door apply,
// `peg.rs` liquidate_confidential (6)), `peg::receipt_bridge_sources` + `cs::pool_bridge` (the `(P, S)` a receipt settles
// against — its epoch's words bridged through the next epoch's, H11 §2.5) and `cs::pool_withdraw` (what a receipt is paid;
// the withdraw door debits the LIVE `T` for a receipt of any epoch, `node.rs` execute_pool_withdraw). Measured after every step: the pool never owes
// more than it holds — Σ live receipts' compounded ≤ T and Σ their gains ≤ the seized collateral not yet paid.
// cons: none — test-only arithmetic over the node's public rules; no proving, no node, a few MB.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

type SpU256 = usdm_decider::confidential_solvency::U256;

#[derive(Clone, Copy)]
struct SpReceipt {
    d: u128,
    p: SpU256,
    s: SpU256,
    epoch: u64,
}

struct SpPool {
    t: u128,
    p: SpU256,
    s: SpU256,
    epoch: u64,
    closes: std::collections::BTreeMap<u64, (SpU256, SpU256)>,
    receipts: Vec<SpReceipt>,
    seized_unpaid: u128,
    /// The residual `T` each close carried into the next epoch (0 for a drain).
    close_residuals: Vec<u128>,
}

fn sp_u256(v: u128) -> SpU256 {
    [v as u64, (v >> 64) as u64, 0, 0]
}

fn sp_u128(v: SpU256) -> u128 {
    assert!(v[2] == 0 && v[3] == 0, "a pool amount above 2^128");
    u128::from(v[0]) | (u128::from(v[1]) << 64)
}

/// The rule the ledger forms for the native PSM at `mark` (`PegLedger::liquidation_rule`'s fields, its constants).
fn sp_rule(mark: u64) -> usdm_decider::confidential_solvency::LiqRule {
    let rule = usdm_decider::confidential_solvency::LiqRule {
        p: mark,
        delta_bps: crate::peg::LIQ_POOL_DISCOUNT_BPS,
        rho_target_bps: 15_000,
        rho_liq_bps: u64::from(crate::peg::PegLedger::new(15_000).liquidation_threshold_bps(crate::peg::NATIVE_PEG_ASSET_ID)),
    };
    assert!(rule.admissible(), "CALIBRATION: the ledger's own rule is admissible");
    rule
}

impl SpPool {
    fn genesis() -> Self {
        Self {
            t: 0,
            p: crate::peg::POOL_P_SCALE,
            s: [0; 4],
            epoch: 0,
            closes: std::collections::BTreeMap::new(),
            receipts: Vec::new(),
            seized_unpaid: 0,
            close_residuals: Vec::new(),
        }
    }

    /// `execute_pool_deposit`: `T + d`, the receipt snapshots the live `(P, S)` and epoch.
    fn deposit(&mut self, d: u128) {
        self.t += d;
        self.receipts.push(SpReceipt { d, p: self.p, s: self.s, epoch: self.epoch });
    }

    /// A receipt settles against the BRIDGE of its epoch's words through the next epoch's — the door's own selection rule
    /// (`peg::receipt_bridge_sources`: live ⊗ opening, close ⊗ live, close ⊗ next close) and value rule (`cs::pool_bridge`).
    fn owed(&self, r: &SpReceipt) -> (u128, u128) {
        use crate::peg::BridgeSource;
        let pair = |src: BridgeSource| match src {
            BridgeSource::Live => (self.p, self.s),
            BridgeSource::Closed(e) => self.closes[&e],
            BridgeSource::Opening => (crate::peg::POOL_P_SCALE, [0; 4]),
        };
        let (first, second) = crate::peg::receipt_bridge_sources(r.epoch, self.epoch).expect("a receipt of an epoch the pool reached");
        let ((p1, s1), (p2, s2)) = (pair(first), pair(second));
        let (pn, sn) = usdm_decider::confidential_solvency::pool_bridge(p1, s1, p2, s2).expect("the rule bridges every receipt");
        let (co, ga) = usdm_decider::confidential_solvency::pool_withdraw(sp_u256(r.d), r.p, r.s, pn, sn).expect("the rule prices every receipt");
        (sp_u128(co), sp_u128(ga))
    }

    /// The rule's retire for a `(reserve, minted)` position against a pool too large to cap it.
    fn uncapped_retire(reserve: u128, minted: u128, rule: &usdm_decider::confidential_solvency::LiqRule) -> u128 {
        let mut probe = Self::genesis();
        probe.t = 1 << 100;
        probe.liquidate(reserve, minted, rule).c
    }

    /// `plan_liquidation` against the live words; a close keeps the closing `(P, S)` and starts the next epoch from the
    /// opening AFTER (exactly the door's apply).
    fn liquidate(&mut self, reserve: u128, minted: u128, rule: &usdm_decider::confidential_solvency::LiqRule) -> crate::peg::LiquidationPlan {
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let open = crate::peg::LiquidationOpening {
            reserve,
            reserve_blind: l(&[1, 2, 3, 4]),
            minted,
            minted_blind: l(&[5, 6, 7, 8]),
            pool_t: self.t,
            pool_t_blind: l(&[9, 10, 11, 12]),
            pool_p: self.p,
            pool_p_blind: l(&[13, 14, 15, 16]),
            pool_s: self.s,
            pool_s_blind: l(&[17, 18, 19, 20]),
        };
        let plan = crate::peg::plan_liquidation(&open, rule).expect("CALIBRATION: the position is due under the rule");
        if plan.close {
            self.closes.insert(self.epoch, (plan.p_new, plan.s_new));
            self.close_residuals.push(plan.after.pool_t);
            self.epoch += 1;
        }
        self.t = plan.after.pool_t;
        self.p = plan.after.pool_p;
        self.s = plan.after.pool_s;
        self.seized_unpaid += plan.s;
        plan
    }

    /// `(Σ compounded − T, Σ gains − seized unpaid)`: both ≤ 0 is the pool holding what it owes.
    fn excess(&self) -> (i128, i128) {
        let (mut c, mut g) = (0u128, 0u128);
        for r in &self.receipts {
            let (a, b) = self.owed(r);
            c += a;
            g += b;
        }
        (c as i128 - self.t as i128, g as i128 - self.seized_unpaid as i128)
    }

    /// Withdraw receipt `i` through the door's rule: `T − u` must not go negative (the transition refuses it).
    fn withdraw(&mut self, i: usize) -> Result<(u128, u128), u128> {
        let r = self.receipts[i];
        let (u, g) = self.owed(&r);
        if u > self.t || g > self.seized_unpaid {
            return Err(u);
        }
        self.t -= u;
        self.seized_unpaid -= g;
        self.receipts.swap_remove(i);
        Ok((u, g))
    }
}

/// H11 §2.7 (DB-381 / DB-391) — A TWO-THIRDS TALLY IS NOT FREE, RESTATED UNDER THE 10/05 + 10/07 RULINGS. The ≥ 2/3
/// bond-weighted custody tally gates every mint attestation and peg-out. The original claim priced the floor at
/// `2 × TVL`, but TVL is confidential (#75) and the user ruled (2026-10-05, on THIS pin): "NOT a red to fix by a gate:
/// restate it as increment 4's measured properties (price manipulation refused, pendulum moves yield, cost shown)";
/// and (2026-10-07) custody weight is SAT only. So "not free" is measured as, on TWO nodes, with custody seated through
/// the REAL SAT bond door and a REAL peg-in landed:
///  1. ZERO-WEIGHT RULE — before any SAT is bonded every seat's custody weight is zero and the seats' joint attestation
///     does not clear: deposit attestation waits (the only automatic behaviour ruled).
///  2. THE COST IS PUBLIC AND SHOWN — `takeover_figures` is the same on both nodes, reads only bonded SAT (identical
///     before and after the reserve moved from 0 to the deposit — no reserve term, no price term), and is > 0.
///  3. THE COST IS EXACT — an attacker bonding exactly the shown cost clears the REAL custody tally
///     (`peg::quorum_weight_met`) against the honest set; one base unit less does not. A shown figure that is not the
///     tally's own threshold misstates what capture costs.
///  4. THE PENDULUM MOVES YIELD — the bonders' share (thornode getPoolShare on public SAT figures) rises as the bonded
///     share of issued SAT falls, and the custody rate with it.
#[test]
fn after_a_real_peg_in_the_validator_bond_floor_rises_above_zero_on_both_nodes_so_a_two_thirds_tally_is_not_free() {
    use crate::node::AssetSpendOutcome;
    use crate::node::tests::{dd_gossip, dd_lane_mint, dd_node, dd_sat_bond, dd_sat_custody, reserve_for, test_d_blind};
    let mut node_a = dd_node();
    let mut node_b = dd_node();
    let seat = |n: &mut Node, other: &mut Node, ts: u64| {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let (ek, dk) = crate::pqkem::keypair();
        let vid = crate::pqauth::pubkey_id(&pk);
        let header = crate::membership_bond_tx::MembershipBondHeader {
            secp33: vec![2u8; 33],
            ed32: [9u8; 32],
            kem_ek: ek,
            nonce: crate::membership_bond_tx::fresh_seat_nonce(),
        };
        let sig = crate::pqauth::ml_dsa_sign(&crate::pqauth::validator_membership_msg(&vid, &header.digest()), &sk).expect("signs");
        assert_eq!(n.publish_membership_bond(&pk, &sig, header), AssetSpendOutcome::Published);
        let blk = n.produce(ts, Hash32::hash(b"fr"), Hash32::hash(b"mc")).expect("the seat block");
        other.ingest_block(blk.clone(), ts + 3_000);
        (pk, sk, dk, vid, blk)
    };
    let (a_pk, a_sk, _a_dk, a_id, seat_blk_a) = seat(&mut node_a, &mut node_b, 6_000);
    let (b_pk, b_sk, b_dk, b_id, seat_blk_b) = seat(&mut node_b, &mut node_a, 9_000);
    for (who, n) in [("node_a", &node_a), ("node_b", &node_b)] {
        assert_eq!(n.validators().len(), 2, "CALIBRATION: {who} holds both free seats");
        assert_eq!(n.validators().total_bond(), 0, "PRECONDITION: {who}: a free seat carries no custody weight");
        assert!(
            !crate::peg::quorum_weight_met(n.validators(), &[a_id, b_id]),
            "⛔ (1) {who}: with ZERO custody weight both seats' attestation cleared the custody tally — it must wait"
        );
    }
    let bonds = [dd_sat_bond(&mut node_a, &seat_blk_a, &a_pk, &a_sk), dd_sat_bond(&mut node_b, &seat_blk_b, &b_pk, &b_sk)];
    let (ts, _) = dd_sat_custody(&mut node_a, &mut [&mut node_b], &bonds, 10_000, b"r3-custody-sat");
    let before = node_a.validators().takeover_figures();
    for (who, n) in [("node_a", &node_a), ("node_b", &node_b)] {
        assert!(n.validators().bond_of(&a_id) > 0 && n.validators().bond_of(&b_id) > 0, "CALIBRATION: {who} seats both SAT bonds");
        assert!(n.peg().reserve_is_zero(), "PRECONDITION: {who} is in the launch window");
    }
    const DEPOSIT_SATS: u64 = 100_000_000;
    let reserve_s = reserve_for(&node_a, &test_d_blind());
    let reserve = reserve_s.as_str();
    crate::node::tests::fund_test_deposit(&mut node_a, reserve, &test_d_blind(), DEPOSIT_SATS); // §BR-2: the coin and the depositor's sweep authorization
    let dep = crate::peg::deposit_id_for_reserve_address(reserve);
    let _ = dd_lane_mint(&mut node_a, &mut node_b, &a_pk, &a_sk, &b_pk, &b_sk, &b_dk, reserve, dep);
    dd_gossip(&node_a, &mut node_b);
    let mint_blk = node_a.produce(ts + 2_000, Hash32::hash(b"h11-2.7-mint"), Hash32::hash(b"mc")).expect("node_a produces the mint block");
    node_b.ingest_block(mint_blk, ts + 5_000);
    assert!(node_a.peg().deposit_minted(&dep) && node_b.peg().deposit_minted(&dep), "CALIBRATION: the real peg-in landed on both nodes");
    assert!(!node_b.peg().reserve_is_zero(), "CALIBRATION: the peer's reserve holds the deposit");
    let (honest, _effective, cost) = node_b.validators().takeover_figures();
    println!(
        "[h11-2.7] MEASURED after a real {DEPOSIT_SATS}-sat peg-in: custody {honest} SAT base units on both; shown takeover cost \
         {cost}; figures before the peg-in {before:?}"
    );
    for (who, n) in [("node_a", &node_a), ("node_b", &node_b)] {
        let figures = n.validators().takeover_figures();
        assert_eq!(figures, node_b.validators().takeover_figures(), "⛔ (2) {who}: the two nodes show different takeover figures");
        assert_eq!(figures, before, "⛔ (2) {who}: the takeover figures moved with the reserve — a reserve term leaks the confidential TVL");
        assert!(honest > 0 && cost > 0, "⛔ (2) {who}: custody {honest}, cost {cost} — a two-thirds tally over a funded reserve is free");
        for (w, clears) in [(cost, true), (cost - 1, false)] {
            let mut set = n.validators().clone();
            set.admit([0xEE; 32], w, 0).expect("a newcomer's custody seat admits");
            assert_eq!(
                crate::peg::quorum_weight_met(&set, &[[0xEE; 32]]),
                clears,
                "⛔ (3) {who}: an attacker bonding {w} SAT base units against {honest} honest — the shown cost {cost} is not the \
                 custody tally's own threshold"
            );
        }
    }
    let issued = 3 * honest; // `secured` = issued / 3 = honest: the 50/50 point
    let shares: Vec<u32> = [4 * honest, 2 * honest, honest].iter().map(|s| crate::sat_schedule::bonder_share_bps(*s, issued)).collect();
    assert!(shares.windows(2).all(|p| p[0] < p[1]), "⛔ (4) the bonders' share {shares:?} does not rise as bonding falls");
    let rates: Vec<u64> = shares.iter().map(|s| crate::sat_schedule::custody_rate(1_000, *s)).collect();
    assert!(rates.windows(2).all(|p| p[0] < p[1]), "⛔ (4) the custody rate {rates:?} does not rise as bonding falls");
}

/// H11 §2.5, the within-epoch half: seeded deposits, liquidations retiring 10^−6 … 100 % of the pool at sizes up to
/// ~10^12, and withdrawals. After EVERY step the pool owes no more than it holds. A seed stops at its first NON-DRAIN
/// close (the class the next pin measures), so this pin's subject is exactly: rounding within an epoch and drain closes.
#[test]
fn the_stability_pool_never_owes_more_than_it_holds_within_an_epoch_at_any_liquidation_ratio_or_size() {
    let rule = sp_rule(750_000);
    let c_unit = SpPool::uncapped_retire(3_000, 2_000, &rule);
    assert!(c_unit > 0, "CALIBRATION: the liq_v2 position (3,000 / 2,000 at mark 750,000) is due, retire {c_unit}");
    let (mut steps, mut liquidations, mut drains, mut stopped_at_non_drain) = (0u32, 0u32, 0u32, 0u32);
    for seed in 0..6u64 {
        let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut pool = SpPool::genesis();
        pool.deposit(1 + u128::from(next() % 1_000_000_000_000));
        for _ in 0..150 {
            steps += 1;
            match next() % 3 {
                0 => pool.deposit(1 + u128::from(next() % 10u64.pow(1 + (next() % 12) as u32))),
                1 if pool.t > 0 => {
                    // a position scaled by k retires ≈ k·c_unit; the pool is topped up to make the retire a fraction
                    // 10^−e of it (e = 0 is a drain)
                    let k = 1 + u128::from(next() % 1_000_000);
                    let c = SpPool::uncapped_retire(3_000 * k, 2_000 * k, &rule);
                    let e = (next() % 7) as u32;
                    let want_t = c.saturating_mul(10u128.pow(e));
                    if pool.t < want_t {
                        pool.deposit(want_t - pool.t);
                    }
                    let plan = pool.liquidate(3_000 * k, 2_000 * k, &rule);
                    liquidations += 1;
                    if plan.close && plan.after.pool_t == 0 {
                        drains += 1;
                    }
                    if plan.close && plan.after.pool_t > 0 {
                        stopped_at_non_drain += 1;
                        break;
                    }
                }
                _ if !pool.receipts.is_empty() => {
                    let i = (next() % pool.receipts.len() as u64) as usize;
                    let r = pool.receipts[i];
                    assert!(pool.withdraw(i).is_ok(), "⛔ seed {seed}: a receipt (d {}, epoch {}) could not be paid — the pool ran short", r.d, r.epoch);
                }
                _ => {}
            }
            let (ec, eg) = pool.excess();
            assert!(ec <= 0 && eg <= 0, "⛔ seed {seed}: the pool owes {ec} USDm / {eg} collateral MORE than it holds within an epoch");
        }
    }
    println!(
        "[h11-2.5] MEASURED within-epoch: {steps} steps over 6 seeds, {liquidations} liquidations ({drains} drain closes), every step owed ≤ held; \
         {stopped_at_non_drain} seeds stopped at a NON-DRAIN close (the next pin's class)"
    );
    assert!(liquidations > 50 && drains > 0, "CALIBRATION: the walk exercised liquidations ({liquidations}) and drain closes ({drains})");
}

/// H11 §2.5, the epoch-close half — RED-FIRST. The close bit is `P_new < 2^64`, so a pool that keeps absorbing partial
/// liquidations closes its epoch with value still in it: 64 half-pool liquidations take `P` from 2^128 to 2^64 and the
/// 65th closes with HALF the pool as residual. The door then keeps the closing `(P, S)` for the old receipts AND carries
/// the residual `T` into the new epoch at `P = 2^128` — so the residual is counted twice: the old receipts claim it at the
/// frozen closing words, while the new epoch's liquidations retire it pro rata with the new deposits. After one more
/// liquidation retiring `C2` from `T = L + D`, the pool owes `C2·L/(L+D)` more USDm than it holds (the last withdrawer
/// is refused), and `S_c2·L/(L+D)` of the seized collateral is owed to no receipt at all. Liquity's shape never closes an
/// epoch with `T > 0`: its epoch moves only on an empty pool, and a `P` that falls under its floor is RESCALED (a scale
/// counter), never restarted. CONTROL: the identical walk whose closing liquidation DRAINS the pool keeps the invariant.
#[test]
fn a_non_drain_epoch_close_must_not_leave_the_stability_pool_owing_more_than_it_holds() {
    let rule = sp_rule(750_000);
    let c0 = SpPool::uncapped_retire(3_000, 2_000, &rule);
    // the walk: T = 2·c0 before every liquidation, each retires exactly c0, so P halves exactly
    let walk = |drain_at_close: bool| -> (SpPool, usize) {
        let mut pool = SpPool::genesis();
        pool.deposit(2 * c0);
        for k in 1..=65usize {
            if k > 1 && !(drain_at_close && k == 65) {
                pool.deposit(2 * c0 - pool.t);
            }
            let plan = pool.liquidate(3_000, 2_000, &rule);
            assert_eq!(plan.c, c0, "CALIBRATION: every liquidation retires exactly c0 (step {k})");
            let (ec, eg) = pool.excess();
            assert!(ec <= 0 && eg <= 0, "CALIBRATION: within the epoch the pool holds what it owes (step {k}: {ec} / {eg})");
            if plan.close {
                return (pool, k);
            }
        }
        (pool, 0)
    };
    // CALIBRATION: the close comes from P's floor at step 65 with half the pool left
    let (mut red, k) = walk(false);
    assert_eq!(k, 65, "CALIBRATION: 64 halvings take P to 2^64; the 65th closes");
    assert_eq!(red.close_residuals, vec![c0], "CALIBRATION: the close is NON-DRAIN — it carries {c0} USDm into epoch 1");
    // CONTROL: the identical walk whose closing liquidation drains the pool
    let (mut control, kc) = walk(true);
    assert_eq!((kc, control.close_residuals.clone()), (65, vec![0]), "CONTROL: the closing liquidation drained the pool");
    for (who, pool) in [("CONTROL (drain close)", &mut control), ("RED (non-drain close)", &mut red)] {
        // epoch 1: a new depositor matches the pool, then one liquidation retires c0 (no close: P 2^128 → 2^127)
        pool.deposit(if pool.t == 0 { 2 * c0 } else { c0 });
        let plan = pool.liquidate(3_000, 2_000, &rule);
        assert!(!plan.close, "{who}: the epoch-1 liquidation does not close");
        let (ec, eg) = pool.excess();
        let (mut refused, mut unpaid) = (0u32, 0u128);
        while !pool.receipts.is_empty() {
            if let Err(u) = pool.withdraw(0) {
                refused += 1;
                unpaid += u;
                pool.receipts.swap_remove(0);
            }
        }
        println!(
            "[h11-2.5] MEASURED {who}: after the epoch-1 liquidation (c0 {c0}, seized {}) the pool owes {ec} USDm / {eg} collateral \
             beyond what it holds; withdrawing every receipt: {refused} refused, {unpaid} USDm unpaid, {} collateral stranded (owed to no receipt)",
            plan.s, pool.seized_unpaid
        );
        assert!(
            ec <= 0 && eg <= 0 && refused == 0,
            "⛔⛔⛔ {who}: the stability pool owes {ec} USDm more than it holds after a {} close — {refused} withdrawal(s) refused, \
             {unpaid} USDm of depositors' money unpayable (the closed epoch's residual T is claimed at the closing words AND \
             retired by the new epoch's liquidations)",
            if pool.close_residuals == vec![0] { "drain" } else { "NON-DRAIN" }
        );
    }
}

/// H11 §2.5, the span — a receipt TWO OR MORE closes behind settles through `(Closed(e), Closed(e + 1))` (Liquity's span-1
/// truncation: both closing `P` are under 2^64, so nothing compounds, and later epochs' gains are dust the pool keeps).
/// The walk forces THREE non-drain closes (64 halvings each, the pool topped back to `2·c0` before every liquidation, so
/// every epoch mints receipts), keeps every receipt alive across them, and asserts after EVERY step that the pool holds
/// what it owes; then every receipt of every epoch withdraws, none refused. CALIBRATION: receipts of epoch 0 are still
/// live once the pool is at epoch 3 (the two-behind path is exercised, not skipped), and every close is non-drain.
///
/// TWO-PARTY-REVIEWED: arithmetic over the ONE public rule set every node applies identically (`plan_liquidation`,
/// `receipt_bridge_sources`, `pool_bridge`, `pool_withdraw`) — no endpoint is played; the two-node door for the same rules
/// is `node::tests::a_drained_pool_epochs_receipt_withdraws_its_seized_collateral_against_the_closing_words` (a second
/// node applies the bridged withdrawal from the block) and `…a_stability_pool_deposit_and_its_withdrawal_travel_to_a_peer…`.
#[test]
fn a_receipt_several_non_drain_closes_behind_never_leaves_the_stability_pool_owing_more_than_it_holds() {
    let rule = sp_rule(750_000);
    let c0 = SpPool::uncapped_retire(3_000, 2_000, &rule);
    let mut pool = SpPool::genesis();
    pool.deposit(2 * c0);
    let mut steps = 0u32;
    while pool.epoch < 3 {
        pool.deposit(2 * c0 - pool.t);
        let plan = pool.liquidate(3_000, 2_000, &rule);
        assert_eq!(plan.c, c0, "CALIBRATION: every liquidation retires exactly c0");
        steps += 1;
        let (ec, eg) = pool.excess();
        assert!(ec <= 0 && eg <= 0, "⛔ step {steps} (epoch {}): the pool owes {ec} USDm / {eg} collateral MORE than it holds", pool.epoch);
        assert!(steps < 400, "CALIBRATION: three closes come from P's floor within 3 × 65 steps");
    }
    assert!(pool.close_residuals.len() == 3 && pool.close_residuals.iter().all(|&r| r > 0), "CALIBRATION: three NON-DRAIN closes {:?}", pool.close_residuals);
    let behind = pool.receipts.iter().filter(|r| r.epoch + 2 <= pool.epoch).count();
    assert!(behind > 0, "CALIBRATION: receipts two or more closes behind are live");
    let (held_t, held_g) = (pool.t, pool.seized_unpaid);
    let (mut refused, mut paid, mut gains) = (0u32, 0u128, 0u128);
    while !pool.receipts.is_empty() {
        match pool.withdraw(0) {
            Ok((u, g)) => {
                paid += u;
                gains += g;
            }
            Err(_) => {
                refused += 1;
                pool.receipts.swap_remove(0);
            }
        }
    }
    println!(
        "[h11-2.5] MEASURED span: {steps} liquidations, 3 non-drain closes {:?}, {behind} receipts ≥ 2 closes behind; withdrawing every receipt: \
         {refused} refused, {paid} of {held_t} USDm paid, {gains} of {held_g} collateral paid (the rest is rounding and span dust the pool keeps)",
        pool.close_residuals
    );
    assert_eq!(refused, 0, "⛔⛔⛔ {refused} withdrawal(s) refused — the pool owed a receipt more than it held");
}

// ── EpochKeyFraud (§BR-9a) ──

/// node_a and node_b with custodian V seated (custody ML-KEM key registered) on a 4-block epoch and a two-epoch deal lead
/// (the test seams), V's deal for the dealing epoch applied on both: when `bad`, V publishes its true public part but the
/// shares of ANOTHER seed (re-signed). Returns both nodes, V's id, the evidence built from t of V's own committed shares,
/// and the next timestamp.
fn ekf_fixture(bad: bool) -> (Node, Node, [u8; 32], crate::epoch_release::FraudProof, u64) {
    crate::epoch_deal_tx::set_test_epoch_blocks(4);
    crate::epoch_deal_tx::TEST_DEAL_LEAD.with(|c| c.set(Some(2)));
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let (ek, dk) = crate::validator::custody_kem_from_vote_sk(&sk);
    let (mut node_a, mut node_b) = (crate::node::tests::testnet_party_folding_at_tip(), crate::node::tests::testnet_party_folding_at_tip());
    for n in [&mut node_a, &mut node_b] {
        n.admit_validator(vid, 1_000_000, 0).expect("V is seated");
        n.register_custody_kem(vid, ek.clone());
    }
    node_a.set_custodian_identity(vid, dk);
    let step = |a: &mut Node, b: &mut Node| {
        let now = a.dag().get(&a.selected_tip().expect("tip")).expect("hdr").header.timestamp + a.params().target_spacing_ms;
        let blk = a.produce(now, Hash32::hash(&now.to_le_bytes()), Hash32::hash(b"ekf")).expect("node_a produces");
        let _ = b.ingest_block(blk, now + 1);
        let _ = a.fold_canonical_records();
        let _ = b.fold_canonical_records();
    };
    for _ in 0..24 {
        let blue = node_a.dag().get(&node_a.selected_tip().expect("tip")).expect("hdr").blue_score;
        if let Some((epoch, roster)) = node_a.epoch_key_deal_due(&vid).pop() {
            let dealing = node_a.peg().epoch_keys().epochs.get(&epoch).map_or(u64::MAX, |r| r.opened_in);
            if (blue + 1) / 4 == dealing {
                let t = crate::shamir::two_thirds_threshold(roster.len());
                let coeffs = vec![0x3cu8; t.saturating_sub(1) * 32];
                let (mut deal, plains) =
                    crate::epoch_deal_tx::build_with_plain(&pk, &sk, epoch, &roster, &[7u8; 32], &coeffs).expect("a deal");
                let plains = if bad {
                    let (shadow, shadow_plains) =
                        crate::epoch_deal_tx::build_with_plain(&pk, &sk, epoch, &roster, &[8u8; 32], &coeffs).expect("a shadow");
                    deal.shares = shadow.shares;
                    deal.sig = crate::pqauth::ml_dsa_sign(&crate::epoch_deal_tx::deal_msg(&vid, epoch, &deal.b, &deal.shares), &sk)
                        .expect("V re-signs its bad deal");
                    shadow_plains
                } else {
                    plains
                };
                assert_eq!(
                    node_a.publish_epoch_key_deal(&deal),
                    crate::node::AssetSpendOutcome::Published,
                    "V's deal enters node_a's pool"
                );
                step(&mut node_a, &mut node_b);
                assert!(
                    node_b.peg().epoch_keys().epochs.get(&epoch).is_some_and(|r| r.dealers.contains_key(&vid)),
                    "CALIBRATION: V's deal applied on the peer"
                );
                let proof = crate::epoch_release::FraudProof {
                    dealer: vid,
                    epoch,
                    shares: roster.iter().zip(&plains).take(t).map(|((id, _), p)| (*id, p.to_vec())).collect(),
                };
                let ts = node_a.dag().get(&node_a.selected_tip().expect("tip")).expect("hdr").header.timestamp + 1_000;
                return (node_a, node_b, vid, proof, ts);
            }
        }
        step(&mut node_a, &mut node_b);
    }
    panic!("CALIBRATION: V never owed a deal with room in its dealing epoch");
}

fn ekf_bonds(node_a: &Node, node_b: &Node, vid: &[u8; 32]) -> (u128, u128) {
    (node_a.validators().bond_of(vid), node_b.validators().bond_of(vid))
}

/// CONTROL: the honest evidence publishes on node_a, rides its block's bond lane and slashes V on BOTH nodes.
fn ekf_the_honest_evidence_slashes_on_both_nodes(node_a: &mut Node, node_b: &mut Node, p: &crate::epoch_release::FraudProof, at: u64) {
    assert_eq!(node_a.publish_epoch_fraud(p), crate::node::AssetSpendOutcome::Published, "node_a publishes the honest evidence");
    let honest = node_a.produce(at, Hash32::hash(b"ekf-honest"), Hash32::hash(b"mc")).expect("node_a lays the evidence");
    assert!(!honest.bond_set.is_empty(), "the evidence rides the validator-object lane");
    dd_graft_then_settle(node_a, node_b, honest, at + 500, b"ekf-settle");
    assert_eq!(ekf_bonds(node_a, node_b, &p.dealer), (0, 0), "CONTROL: the honest evidence slashed V on both nodes");
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — EpochKeyFraud × FORGE, through a peer: "evidence" against an HONEST dealer — V dealt its true
/// seed's shares, so its own committed shares rebuild its public part — carried by the rogue node_b. The peer slashes
/// nothing, and node_a's own publication door refuses it too.
#[test]
fn epoch_key_fraud_evidence_against_an_honest_dealer_carried_by_a_rogue_producer_slashes_no_one_on_the_peer() {
    let (mut node_a, mut node_b, vid, proof, ts) = ekf_fixture(false);
    let blob = crate::epoch_fraud_tx::wire(&proof).expect("the evidence frames");
    let rogue = rogue_bond_lane_block(&mut node_b, blob, &[], ts, b"ekf-forge-rogue");
    peer_judges(&mut node_a, rogue, ts + 500, "epoch-key fraud evidence against an honest dealer");
    assert_eq!(ekf_bonds(&node_a, &node_b, &vid), (1_000_000, 1_000_000), "⛔ ROGUE PRODUCER: an honest dealer was slashed");
    assert!(
        matches!(node_a.publish_epoch_fraud(&proof), crate::node::AssetSpendOutcome::Refused(_)),
        "the publication door refuses evidence that convicts no one"
    );
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — EpochKeyFraud × STRIP, through a peer: V's real conviction with one share REMOVED (below t, or
/// no share at all). The peer slashes nothing; CONTROL: the whole evidence then slashes V on both nodes.
#[test]
fn epoch_key_fraud_evidence_stripped_of_a_share_carried_by_a_rogue_producer_slashes_no_one_on_the_peer() {
    let (mut node_a, mut node_b, vid, proof, ts) = ekf_fixture(true);
    let mut stripped = proof.clone();
    stripped.shares.pop();
    let blob = crate::chain_object::frame(crate::chain_object::Class::EpochKeyFraud, &crate::fixed::encode_plain(&stripped));
    let rogue = rogue_bond_lane_block(&mut node_b, blob, &[], ts, b"ekf-strip-rogue");
    peer_judges_strip(&mut node_a, rogue, ts + 500, "epoch-key fraud evidence stripped of a share");
    assert_eq!(ekf_bonds(&node_a, &node_b, &vid).0, 1_000_000, "⛔ ROGUE PRODUCER: stripped evidence slashed V on the peer");
    ekf_the_honest_evidence_slashes_on_both_nodes(&mut node_a, &mut node_b, &proof, ts + 3_000);
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — EpochKeyFraud × SUBSTITUTE, through a peer: V's real conviction with one share's bytes changed —
/// no longer under the commitment V signed to that member. The peer slashes nothing; CONTROL: the true evidence then
/// slashes V on both nodes.
#[test]
fn epoch_key_fraud_evidence_with_a_substituted_share_carried_by_a_rogue_producer_slashes_no_one_on_the_peer() {
    let (mut node_a, mut node_b, vid, proof, ts) = ekf_fixture(true);
    let mut swapped = proof.clone();
    swapped.shares[0].1[9] ^= 1;
    let blob = crate::epoch_fraud_tx::wire(&swapped).expect("the substituted evidence frames");
    let rogue = rogue_bond_lane_block(&mut node_b, blob, &[], ts, b"ekf-sub-rogue");
    peer_judges(&mut node_a, rogue, ts + 500, "epoch-key fraud evidence with a substituted share");
    assert_eq!(ekf_bonds(&node_a, &node_b, &vid).0, 1_000_000, "⛔ ROGUE PRODUCER: a substituted share slashed V on the peer");
    ekf_the_honest_evidence_slashes_on_both_nodes(&mut node_a, &mut node_b, &proof, ts + 3_000);
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — EpochKeyFraud × REPLAY, through a peer: V's conviction slashes it on both nodes; the rogue node_b
/// re-carries the same evidence. The peer's validator set does not move (V is slashed and barred).
#[test]
fn epoch_key_fraud_evidence_re_carried_by_a_rogue_producer_after_the_slash_moves_nothing_on_the_peer() {
    let (mut node_a, mut node_b, vid, proof, ts) = ekf_fixture(true);
    ekf_the_honest_evidence_slashes_on_both_nodes(&mut node_a, &mut node_b, &proof, ts);
    let before = node_a.validators().total_bond();
    let blob = crate::epoch_fraud_tx::wire(&proof).expect("the evidence frames");
    let rogue = rogue_bond_lane_block(&mut node_b, blob, &[], ts + 6_000, b"ekf-replay-rogue");
    peer_judges(&mut node_a, rogue, ts + 6_500, "re-carried epoch-key fraud evidence");
    assert_eq!(node_a.validators().total_bond(), before, "⛔ ROGUE PRODUCER: replayed evidence moved the peer's set");
    assert_eq!(ekf_bonds(&node_a, &node_b, &vid), (0, 0));
}

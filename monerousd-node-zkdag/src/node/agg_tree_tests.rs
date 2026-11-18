// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ THE LEVEL AGGREGATE, MILESTONE 2 — THE NODE'S SIDE OF THE PROOF TREE, TWO-NODE PINS (lane aggnode, piece F;
//! docs/LEVEL-AGGREGATE-SPEC-20261115.md §11).
//!
//! WHAT THESE PIN, AND WHAT THEY DO NOT. The tree itself (the leaf and merge proofs and their verifier) is lane agg's
//! crate (`usdm_agg::tree_ssa`, its own lying-prover pins); the first pin below is a real peer refusing a root the tree
//! did not make. The others run under `agg_root::with_plumbing_stand_in`, a TEST-ONLY stand-in that PROVES NOTHING (a
//! keyed hash of the statements in order). They pin the node's own rules, which hold whatever the tree is: a tree-form
//! body carries no carrier and is its own statement's; the block carries exactly one root; the root is judged over the
//! statements the PEER derives from the bodies it was handed, in carried order; a block whose root is another block's,
//! missing, doubled or altered, or whose body states something else, enters no peer and no peer holds its payment.
//! Soundness — that a root exists only for carriers that verify — is the tree's own lying-prover row, never these.
//!
//! THE CLAIM IS THE PEER'S: `node_b` never saw the payment, is fed the block as a peer receives it (`gossip_encode` →
//! `gossip_decode`) and judges it at its own door.
use super::tests::testnet_party_folding_at_tip;
use super::*;

type History = Vec<(Block, u64)>;

fn fresh_peer_node(history: &History) -> Node {
    let mut peer_node = testnet_party_folding_at_tip();
    for (b, at) in history {
        let whole = crate::block::gossip_decode(&crate::block::gossip_encode(b)).expect("the envelope decodes");
        assert!(matches!(peer_node.ingest_block(whole, *at), RelayOutcome::Added(_)), "PRECONDITION: a peer grafts the producer's history");
    }
    peer_node
}

/// On `node_a`, under the stand-in: a funded, confirmed note; one production-shaped spend of it HELD in tree form and
/// laid in A's next block. Returns the history before the spend block, the spend block, its arrival time, the first
/// output and the FULL tx.
fn lay_one_tree_spend(node_a: &mut Node, seed: u64) -> (History, Block, u64, [u8; 32], PqTx) {
    let mut history: History = Vec::new();
    let mut ts = 5_000u64;
    let (note, cm) = Node::test_spendable_note(seed);
    let (funding, _) = node_a.carry_notes_in_a_block_for_test(ts, &note);
    history.push((funding, ts + 100));
    ts += 600;
    for i in 0..6u64 {
        if node_a.member_path_ready_for_test(&cm) {
            break;
        }
        let blk = node_a.produce(ts, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"tree-a")).expect("A produces an empty block");
        history.push((blk, ts + 100));
        ts += 600;
    }
    assert!(node_a.member_path_ready_for_test(&cm), "PRECONDITION: the note confirmed on the producer");
    let (mut tx, _nf) = node_a.production_spend_tx_for_test(&cm, seed).expect("the wallet-shaped spend builds");
    tx.membership_carrier.clear();
    tx.membership_tip.clear();
    let held = node_a.hold_for_aggregation(tx.clone(), usize::MAX);
    let crate::node::AggHold::Held(tree_id) = held else { panic!("⛔ the holder did not hold an honest pushed send: {held:?}") };
    assert!(node_a.mempool().get(&tx.id).is_none(), "⛔ the FULL send stayed pooled beside its tree form");
    assert!(node_a.mempool().get(&tree_id).is_some(), "⛔ the tree form is not pooled");
    let mut out = [0u8; 32];
    out.copy_from_slice(&tx.output_notes[..32]);
    let blk = node_a.produce(ts, Hash32::hash(b"tree-spend"), Hash32::hash(b"tree-a")).expect("A lays the tree-form spend's block");
    (history, blk, ts + 100, out, tx)
}

fn delivered(b: &Block) -> Block {
    crate::block::gossip_decode(&crate::block::gossip_encode(b)).expect("the envelope decodes")
}

/// ⛔⛔⛔ A ROOT THE TREE DID NOT MAKE IS REFUSED: a block whose tree-form payment rides a STAND-IN root (made under the
/// test-only stand-in, which proves nothing) is judged by a peer WITHOUT the stand-in — by the real tree
/// (`usdm_agg::tree_ssa::verify_root`), as every node of this build judges — and enters no peer, nor does its payment.
#[test]
fn tree_a_block_whose_root_the_tree_did_not_make_is_refused_by_every_peer() {
    let mut node_a = testnet_party_folding_at_tip();
    let (history, blk, at, out, _tx) = crate::agg_root::with_plumbing_stand_in(|| lay_one_tree_spend(&mut node_a, 2201));
    let mut node_b = fresh_peer_node(&history);
    let got = node_b.ingest_block(delivered(&blk), at);
    assert!(
        !matches!(got, RelayOutcome::Added(_) | RelayOutcome::Buffered { .. }),
        "⛔⛔⛔ a peer of this build grafted a block whose payment no proof it can check established: {got:?}"
    );
    assert!(!node_b.holds_record_with_cm(&out), "⛔⛔⛔ a peer holds a payment whose carriers nobody verified to it");
}

/// ⭐ THE HONEST PATH'S PLUMBING (stand-in): the holder's block carries the payment as a TREE-FORM body — no carrier,
/// a 36-byte blob that is the tree tag and its own statement's commitment, a new id that is that blob's — and exactly
/// one root; the hashed block carries neither; the envelope delivers both; a peer that never saw the payment derives
/// the statement itself, judges the root over it, grafts the block and holds the payment. Prints the bytes a peer pulls.
#[test]
fn tree_a_peer_fed_only_the_block_derives_the_statement_judges_the_root_and_holds_the_payment() {
    crate::agg_root::with_plumbing_stand_in(|| {
        let mut node_a = testnet_party_folding_at_tip();
        let (history, blk, at, out, tx) = lay_one_tree_spend(&mut node_a, 2202);
        assert_eq!(blk.tx_bodies.len(), 1, "⛔ the block does not carry its stated spend");
        let body = crate::chain_object::decode_exact::<PqTx>(&blk.tx_bodies[0]).expect("the carried body is a transaction");
        assert!(crate::spend_evidence::is_tree_form(&body), "⛔ the carried body is not the tree form");
        assert!(body.member_carrier.is_empty() && body.spend_or_decoy.is_empty() && body.blob.len() == 36, "⛔ a tree-form body carries a carrier");
        assert_eq!(body.blob[4..], crate::spend_evidence::tree_statement_commit(&body), "the blob is its own statement's commitment");
        assert_ne!(body.id, tx.id, "the tree-form body has its own id");
        assert_eq!(body.id, PqTx::content_id(&body.blob), "the tree-form body's id is its own blob's");
        assert_eq!((&body.nullifiers, &body.output_notes), (&tx.nullifiers, &tx.output_notes), "the payment itself is unchanged");
        assert_eq!(blk.agg_tables.len(), 1, "⛔ the block does not carry exactly one root");
        eprintln!(
            "[tree-node] a payment on the envelope: full {} B → tree-form body {} B + one root of {} B (the stand-in's; the real root's size is lane agg's to measure)",
            postcard::to_allocvec(&tx).expect("encodes").len(),
            blk.tx_bodies[0].len(),
            blk.agg_tables[0].len()
        );
        let bare: Block = postcard::from_bytes(&postcard::to_allocvec(&blk).expect("the hashed block encodes")).expect("decodes");
        assert!(bare.agg_tables.is_empty() && bare.tx_bodies.is_empty(), "⛔ the hashed block carries a body or a root");
        let whole = delivered(&blk);
        assert_eq!((&whole.agg_tables, &whole.tx_bodies), (&blk.agg_tables, &blk.tx_bodies), "the envelope delivers the root and the body");
        let mut node_b = fresh_peer_node(&history);
        assert!(node_b.mempool().get(&tx.id).is_none() && node_b.mempool().get(&body.id).is_none(), "PRECONDITION: the peer never saw the payment");
        let outcome = node_b.ingest_block(whole, at);
        assert!(matches!(outcome, RelayOutcome::Added(_)), "⛔ the peer refused an honest tree-form block: {outcome:?}");
        assert!(node_b.holds_record_with_cm(&out), "⛔ node B does not hold the tree-form payment");
        assert!(node_a.holds_record_with_cm(&out), "CONTROL: the holder holds it too");
    });
}

/// ⭐⭐ THE LYING PRODUCER, at the node's own rules (stand-in): each block is RE-SEALED and RE-MINED by its producer, so
/// its id commits every lie and no copy check stands in the way. CONTROL: the honest block re-sealed and re-mined
/// unchanged enters. Refused, each by a fresh peer that then holds nothing: another block's root; no root; two roots;
/// one root byte moved; a tree-form body that carries a carrier after all; a body whose blob is not its own statement's
/// commitment; the tree-form body replaced by its FULL twin (a copy the block does not name).
#[test]
fn tree_a_producer_that_seals_a_root_that_is_not_its_payments_is_refused_by_every_peer() {
    crate::agg_root::with_plumbing_stand_in(|| {
        let mut node_a = testnet_party_folding_at_tip();
        let (history, blk, at, out, tx) = lay_one_tree_spend(&mut node_a, 2203);
        let mut other_node = testnet_party_folding_at_tip();
        let (_, other_blk, _, _, _) = lay_one_tree_spend(&mut other_node, 2204);
        assert_ne!(other_blk.agg_tables, blk.agg_tables, "CALIBRATION: two payments have two roots");
        let body = crate::chain_object::decode_exact::<PqTx>(&blk.tx_bodies[0]).expect("a transaction");
        let sealed = |f: &dyn Fn(&mut Block)| -> Block {
            let mut b = blk.clone();
            f(&mut b);
            b.seal_transitions_root();
            super::tests::mine_fixture_block(&mut b);
            b
        };
        let with_body = |b: &mut Block, t: &PqTx| {
            b.tx_ids.iter_mut().filter(|i| **i == body.id).for_each(|i| *i = t.id);
            b.tx_bodies = vec![postcard::to_allocvec(t).expect("encodes")];
        };
        let mut peer = fresh_peer_node(&history);
        let got = peer.ingest_block(delivered(&sealed(&|_| {})), at);
        assert!(matches!(got, RelayOutcome::Added(_)), "CALIBRATION: the honest block re-sealed and re-mined must enter: {got:?}");
        assert!(peer.holds_record_with_cm(&out), "CALIBRATION: and deliver the payment");
        let lies: Vec<(&str, Block)> = vec![
            ("the producer sealed another block's root", sealed(&|b| b.agg_tables = other_blk.agg_tables.clone())),
            ("the producer sealed its tree-form payment with no root", sealed(&|b| b.agg_tables.clear())),
            ("the producer sealed two roots", sealed(&|b| b.agg_tables.push(blk.agg_tables[0].clone()))),
            ("the producer moved one byte of the root", sealed(&|b| b.agg_tables[0][0] ^= 1)),
            ("the producer sealed a tree-form body that carries a carrier after all", sealed(&|b| {
                let mut t = body.clone();
                t.member_carrier = tx.member_carrier.clone();
                with_body(b, &t);
            })),
            ("the producer sealed a body whose blob is not its own statement's commitment", sealed(&|b| {
                let mut t = body.clone();
                t.blob[35] ^= 1;
                t.id = PqTx::content_id(&t.blob);
                with_body(b, &t);
            })),
            ("the tree-form body replaced by its FULL twin", {
                let mut b = blk.clone();
                b.tx_bodies = vec![postcard::to_allocvec(&tx).expect("encodes")];
                b
            }),
        ];
        for (what, lie) in lies {
            let mut node_b = fresh_peer_node(&history);
            let got = node_b.ingest_block(delivered(&lie), at);
            eprintln!("[tree-node] {what}: {got:?}");
            assert!(
                !matches!(got, RelayOutcome::Added(_) | RelayOutcome::Buffered { .. }),
                "⛔⛔⛔ a peer grafted a block whose root is not its payments' — {what}: {got:?}"
            );
            assert!(!node_b.holds_record_with_cm(&out), "⛔⛔⛔ a peer holds a payment no root established — {what}");
        }
    });
}

/// ⭐ THE HYBRID NEVER HOLDS WHAT IT CANNOT PROVE: no room, nothing held (the send then takes today's path); a pushed
/// send that is not an ordinary send (no member leg) is never held; with room the same send is held in tree form and
/// the full send leaves the pool. Carried over from milestone 1's room pin when its core form was deleted (2026-11-16).
#[test]
fn tree_the_holder_holds_only_what_its_room_covers() {
    let mut node_a = testnet_party_folding_at_tip();
    let (note, cm) = Node::test_spendable_note(2204);
    let mut ts = 5_000u64;
    let _ = node_a.carry_notes_in_a_block_for_test(ts, &note);
    ts += 600;
    for i in 0..6u64 {
        if node_a.member_path_ready_for_test(&cm) {
            break;
        }
        let _ = node_a.produce(ts, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"tree-room"));
        ts += 600;
    }
    let (mut tx, _nf) = node_a.production_spend_tx_for_test(&cm, 2204).expect("the wallet-shaped spend builds");
    tx.membership_carrier.clear();
    tx.membership_tip.clear();
    assert_eq!(node_a.hold_for_aggregation(tx.clone(), 0), crate::node::AggHold::NotHeld, "⛔ held with no room");
    assert!(node_a.mempool().get(&tx.id).is_none(), "⛔ a refused hold pooled the send (the caller's ordinary path pools it)");
    let mut framed = tx.clone();
    framed.member_carrier.clear();
    assert_eq!(node_a.hold_for_aggregation(framed, usize::MAX), crate::node::AggHold::NotHeld, "⛔ held a send with no member leg");
    let held = node_a.hold_for_aggregation(tx.clone(), usize::MAX);
    let crate::node::AggHold::Held(tree_id) = held else { panic!("CONTROL: with room the same send is held — {held:?}") };
    assert!(node_a.mempool().get(&tx.id).is_none(), "⛔ the FULL send stayed pooled beside its tree form");
    let pooled = node_a.mempool().get(&tree_id).expect("the tree form is pooled");
    assert!(crate::spend_evidence::is_tree_form(pooled), "⛔ the held form is not the tree form");
}

/// The room rule's arithmetic is the tree's own: `agg_root::merges_for(k)` is the number of merges in
/// `usdm_agg::tree_ssa::tree_of(k)` (a merge of one child counts: it is proved like any other), for every k a hold admits.
#[test]
fn tree_merges_for_counts_the_canonical_trees_merges() {
    fn count(t: &usdm_agg::tree_ssa::Tree) -> usize {
        match t {
            usdm_agg::tree_ssa::Tree::Leaf(_) | usdm_agg::tree_ssa::Tree::Ledger => 0,
            usdm_agg::tree_ssa::Tree::Merge(cs) => 1 + cs.iter().map(count).sum::<usize>(),
        }
    }
    for k in 1..=crate::node::AGG_HOLD_MAX {
        let t = usdm_agg::tree_ssa::tree_of(k).expect("a tree");
        assert_eq!(crate::agg_root::merges_for(k), count(&t), "⛔ merges_for({k}) is not the canonical tree's merge count");
    }
    assert_eq!((crate::agg_root::merges_for(1), crate::agg_root::merges_for(2), crate::agg_root::merges_for(3)), (0, 1, 3), "CONTROL: the shapes the pins prove");
}

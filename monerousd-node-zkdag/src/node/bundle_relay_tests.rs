// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §14 THE BUNDLE RELAY — the node's rules, pinned across real `Node`s (docs/LEVEL-AGGREGATE-SPEC-20261115.md §14.7 N1).
//!
//! WHAT THESE PIN, AND WHAT THEY DO NOT. They run under `agg_root::with_plumbing_stand_in` (a TEST-ONLY stand-in that
//! proves nothing: a keyed hash of the statements in order, with the payments it covers in front). They pin the node's own
//! rules, which hold whatever the tree is: a block may carry SEVERAL roots, one a run of tree-form bodies in carried
//! order; a bundle taken by ANOTHER producer is laid by it and held by a peer that never saw the payments; a lying holder
//! (a root over other statements, a member whose full body is not its tree form) makes the taker adopt NOTHING; a
//! holder never lays a bundle it leased out. Soundness of a root is the tree's own lying-prover rows.
//!
//! THE CLAIM IS THE PEER'S: the peer never saw the payments, is fed the block as a peer receives it, and judges it alone.
use super::tests::testnet_party_folding_at_tip;
use super::*;

type History = Vec<(Block, u64)>;

fn delivered(b: &Block) -> Block {
    crate::block::gossip_decode(&crate::block::gossip_encode(b)).expect("the envelope decodes")
}

fn fresh_peer_node(history: &History) -> Node {
    let mut peer_node = testnet_party_folding_at_tip();
    for (b, at) in history {
        assert!(matches!(peer_node.ingest_block(delivered(b), *at), RelayOutcome::Added(_)), "PRECONDITION: a peer grafts the producer's history");
    }
    peer_node
}

/// On `node_a`: `n` funded, confirmed notes and one production-shaped spend of each, all HELD in tree form (none laid).
/// Returns the history, the next block time, the FULL txs, their tree-form ids and their first outputs.
fn hold_payments(node_a: &mut Node, seed: u64, n: usize) -> (History, u64, Vec<PqTx>, Vec<Hash32>, Vec<[u8; 32]>) {
    let mut history: History = Vec::new();
    let mut ts = 5_000u64;
    let mut cms = Vec::new();
    for k in 0..n as u64 {
        let (note, cm) = Node::test_spendable_note(seed + k);
        let (funding, _) = node_a.carry_notes_in_a_block_for_test(ts, &note);
        history.push((funding, ts + 100));
        ts += 600;
        cms.push(cm);
    }
    for i in 0..8u64 {
        if cms.iter().all(|cm| node_a.member_path_ready_for_test(cm)) {
            break;
        }
        let blk = node_a.produce(ts, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"bundle-a")).expect("A produces an empty block");
        history.push((blk, ts + 100));
        ts += 600;
    }
    assert!(cms.iter().all(|cm| node_a.member_path_ready_for_test(cm)), "PRECONDITION: every note confirmed on the holder");
    let (mut fulls, mut trees, mut outs) = (Vec::new(), Vec::new(), Vec::new());
    for (k, cm) in cms.iter().enumerate() {
        let (mut tx, _nf) = node_a.production_spend_tx_for_test(cm, seed + k as u64).expect("the wallet-shaped spend builds");
        tx.membership_carrier.clear();
        tx.membership_tip.clear();
        let held = node_a.hold_for_aggregation(tx.clone(), usize::MAX);
        let crate::node::AggHold::Held(tree_id) = held else { panic!("⛔ the holder did not hold an honest pushed send: {held:?}") };
        let mut out = [0u8; 32];
        out.copy_from_slice(&tx.output_notes[..32]);
        fulls.push(tx);
        trees.push(tree_id);
        outs.push(out);
    }
    (history, ts, fulls, trees, outs)
}

/// The stand-in leaf of one held payment and its bundle of one, recorded on the holder as the bundle worker records it.
fn bundle_of_one(node: &mut Node, id: Hash32) {
    let (st, spend, member, cover) = node.leaf_input_of(&id).expect("held");
    let leaf = crate::agg_root::prove_leaf(&st, &spend, &member, &cover).expect("the stand-in leaf");
    let root = crate::agg_root::prove_merge(&[(st, leaf)]).expect("a root of one");
    node.add_bundle(vec![id], root, false);
}

/// ⭐ SEVERAL ROOTS, ONE A RUN: two bundles of one on the holder lay ONE block with TWO roots; a peer that never saw the
/// payments grafts it and holds both. Then the same two merged into one bundle of two lay a block with ONE root. Refused
/// by a fresh peer, each re-sealed by its producer so the id commits the lie: the roots swapped, one root dropped.
#[test]
fn bundle_a_block_carries_one_root_a_bundle_and_a_peer_holds_every_payment() {
    crate::agg_root::with_plumbing_stand_in(|| {
        let mut node_a = testnet_party_folding_at_tip();
        node_a.bundle_worker = true;
        let (history, ts, _fulls, trees, outs) = hold_payments(&mut node_a, 3301, 2);
        bundle_of_one(&mut node_a, trees[0]);
        bundle_of_one(&mut node_a, trees[1]);
        let blk = node_a.produce(ts, Hash32::hash(b"two-roots"), Hash32::hash(b"bundle-a")).expect("A lays both bundles");
        assert_eq!(blk.tx_bodies.len(), 2, "⛔ the block does not carry both held payments");
        assert_eq!(blk.agg_tables.len(), 2, "⛔ the block does not carry one root a bundle");
        // the honest block, judged by a peer that never saw either payment
        let mut node_b = fresh_peer_node(&history);
        let got = node_b.ingest_block(delivered(&blk), ts + 100);
        assert!(matches!(got, RelayOutcome::Added(_)), "⛔ a peer refused an honest two-root block: {got:?}");
        assert!(outs.iter().all(|o| node_b.holds_record_with_cm(o)), "⛔ the peer does not hold both payments");
        // CALIBRATION: the honest block re-sealed and re-mined unchanged enters, so a refusal below is the lie's
        let resealed = |b: &Block, f: fn(&mut Block)| -> Block {
            let mut b = b.clone();
            f(&mut b);
            b.seal_transitions_root();
            super::tests::mine_fixture_block(&mut b);
            b
        };
        let mut calib = fresh_peer_node(&history);
        let got = calib.ingest_block(delivered(&resealed(&blk, |_| {})), ts + 100);
        assert!(matches!(got, RelayOutcome::Added(_)), "CALIBRATION: the honest block re-sealed and re-mined must enter: {got:?}");
        // the lies: the producer re-seals and re-mines each, so its id commits it
        for (what, edit) in [
            ("the roots swapped", (|b: &mut Block| b.agg_tables.swap(0, 1)) as fn(&mut Block)),
            ("one root dropped", |b: &mut Block| {
                b.agg_tables.pop();
            }),
        ] {
            let lie = resealed(&blk, edit);
            let mut fresh = fresh_peer_node(&history);
            let got = fresh.ingest_block(delivered(&lie), ts + 100);
            assert!(!matches!(got, RelayOutcome::Added(_) | RelayOutcome::Buffered { .. }), "⛔⛔⛔ {what}: a peer grafted it: {got:?}");
            assert!(!outs.iter().any(|o| fresh.holds_record_with_cm(o)), "⛔⛔⛔ {what}: a peer holds a payment");
        }
    });
}

/// ⭐ A BUNDLE OF TWO: two bundles of one merge (`agg_root::merge_bundles`, the worker's merge) into one bundle of two
/// over both members in order; the holder's block carries ONE root for both and a fresh peer holds both payments.
#[test]
fn bundle_two_bundles_merge_into_one_and_its_block_carries_one_root() {
    crate::agg_root::with_plumbing_stand_in(|| {
        let mut node_a = testnet_party_folding_at_tip();
        node_a.bundle_worker = true;
        let (history, ts, _fulls, trees, outs) = hold_payments(&mut node_a, 3311, 2);
        bundle_of_one(&mut node_a, trees[0]);
        bundle_of_one(&mut node_a, trees[1]);
        let (a, b) = node_a.merge_pair(0).expect("two free bundles of one size merge");
        let side = |n: &Node, id: &Hash32| {
            let x = n.agg_bundles.iter().find(|x| x.id == *id).expect("the bundle");
            (n.bundle_statements(&x.members).expect("held"), x.root.clone())
        };
        let ((sa, ra), (sb, rb)) = (side(&node_a, &a), side(&node_a, &b));
        let merged = crate::agg_root::merge_bundles((&sa, &ra), (&sb, &rb)).expect("the merge proves");
        node_a.finish_bundle_merge(&a, &b, Some(merged));
        assert_eq!(node_a.agg_bundles.len(), 1, "⛔ the two halves did not become one bundle");
        assert_eq!(node_a.agg_bundles[0].members.len(), 2, "⛔ the merged bundle does not cover both payments");
        let blk = node_a.produce(ts, Hash32::hash(b"one-root"), Hash32::hash(b"bundle-a")).expect("A lays the bundle");
        assert_eq!((blk.tx_bodies.len(), blk.agg_tables.len()), (2, 1), "⛔ the block does not carry two payments under one root");
        let mut node_b = fresh_peer_node(&history);
        let got = node_b.ingest_block(delivered(&blk), ts + 100);
        assert!(matches!(got, RelayOutcome::Added(_)), "⛔ a peer refused an honest one-root bundle block: {got:?}");
        assert!(outs.iter().all(|o| node_b.holds_record_with_cm(o)), "⛔ the peer does not hold both payments");
    });
}

/// ⭐⭐ ANOTHER PRODUCER LAYS IT — THE WALL REMOVED: the holder A leases its bundle to producer C (head, then each member's
/// full body under the lease, exactly what kinds 31 and 32 serve); C adopts it, judging every member and the root itself;
/// C's block carries the payments; peer B, which never saw them, holds them. While leased, A's own template lays none of
/// them. LYING HOLDERS, each refused WHOLE by a fresh taker that then pools nothing: a root over other statements, and a
/// member's full body swapped for another payment's.
#[test]
fn bundle_a_bundle_taken_by_another_producer_is_laid_by_it_and_held_by_a_peer() {
    crate::agg_root::with_plumbing_stand_in(|| {
        let mut node_a = testnet_party_folding_at_tip();
        node_a.bundle_worker = true;
        let (history, ts, _fulls, trees, outs) = hold_payments(&mut node_a, 3321, 2);
        bundle_of_one(&mut node_a, trees[0]);
        bundle_of_one(&mut node_a, trees[1]);
        let (a, b) = node_a.merge_pair(0).expect("merge pair");
        let side = |n: &Node, id: &Hash32| {
            let x = n.agg_bundles.iter().find(|x| x.id == *id).expect("the bundle");
            (n.bundle_statements(&x.members).expect("held"), x.root.clone())
        };
        let ((sa, ra), (sb, rb)) = (side(&node_a, &a), side(&node_a, &b));
        node_a.finish_bundle_merge(&a, &b, crate::agg_root::merge_bundles((&sa, &ra), (&sb, &rb)));
        let id = node_a.agg_bundles[0].id;
        let now = 1_000_000u64;
        let head = node_a.lease_bundle(&id, now, now + 30_000).expect("A leases its free bundle");
        assert!(node_a.lease_bundle(&id, now + 1, now + 30_000).is_none(), "⛔ a leased bundle was leased twice");
        let fulls: Vec<PqTx> = (0..head.tree.len()).map(|i| node_a.leased_member_full(&id, i, now + 1).expect("the lease serves").clone()).collect();
        assert!(node_a.leased_member_full(&id, 0, now + 31_000).is_none(), "⛔ a member served past its lease");
        // A, while the lease runs, lays none of them
        let mut keep: Vec<Hash32> = trees.clone();
        keep = node_a.order_tree_selection(keep, now + 2);
        assert!(keep.is_empty(), "⛔ the holder would lay a bundle it leased to another producer: {keep:?}");
        // lying holders: the taker adopts nothing
        let mut wrong_root = head.clone();
        wrong_root.root = crate::agg_root::prove_merge(&[(sa[0].clone(), crate::agg_root::prove_leaf(&sa[0], b"x", b"y", b"z").expect("stand-in"))]).expect("a root of one");
        let mut swapped = fulls.clone();
        swapped.swap(0, 1);
        for (what, h, f) in [("a root over other statements", wrong_root, fulls.clone()), ("two members' full bodies swapped", head.clone(), swapped)] {
            let mut taker = fresh_peer_node(&history);
            let got = taker.adopt_bundle(h, f);
            assert!(got.is_err(), "⛔⛔⛔ {what}: the taker adopted it");
            assert!(taker.agg_held.is_empty() && taker.agg_bundles.is_empty(), "⛔⛔⛔ {what}: the taker kept a member");
            assert!(trees.iter().all(|t| taker.mempool().get(t).is_none()), "⛔⛔⛔ {what}: the taker pooled a member");
        }
        // the honest take
        let mut node_c = fresh_peer_node(&history);
        node_c.bundle_worker = true;
        assert_eq!(node_c.adopt_bundle(head, fulls), Ok(2), "⛔ the taker refused an honest bundle");
        let blk = node_c.produce(ts, Hash32::hash(b"taken"), Hash32::hash(b"bundle-c")).expect("C lays the taken bundle");
        assert_eq!((blk.tx_bodies.len(), blk.agg_tables.len()), (2, 1), "⛔ the taker's block does not carry the bundle under one root");
        let mut node_b = fresh_peer_node(&history);
        let got = node_b.ingest_block(delivered(&blk), ts + 100);
        assert!(matches!(got, RelayOutcome::Added(_)), "⛔ a peer refused the taker's honest block: {got:?}");
        assert!(outs.iter().all(|o| node_b.holds_record_with_cm(o)), "⛔ the peer does not hold the taken payments");
        // the holder grafts the taker's block: its copies leave the pool and the hold
        let got = node_a.ingest_block(delivered(&blk), ts + 100);
        assert!(matches!(got, RelayOutcome::Added(_)), "⛔ the holder refused the taker's block: {got:?}");
        node_a.prune_agg_held();
        assert!(node_a.agg_held.is_empty() && node_a.agg_bundles.is_empty(), "⛔ the holder still holds payments a block laid");
    });
}

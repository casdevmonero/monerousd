// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::nf_fold_order_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::{canon_nf_for_test, genesis_block, grind_tx};
use super::Node;
use crate::block::Block;
use crate::hash::Hash32;
use crate::mempool::PqTx;

/// Produce `n` blocks on a fresh node; return the blocks AND the txs they carry, so a verifier can be
/// given them in either order — which is the point, because gossip guarantees no order between them.
fn mine(n: usize) -> (Vec<Block>, Vec<PqTx>) {
    let mut p = Node::new(genesis_block()).unwrap();
    let (mut blocks, mut txs) = (Vec::with_capacity(n), Vec::with_capacity(n));
    for i in 0..n {
        let need = p.mempool().required_stamp_bits();
        let tx = grind_tx(
            format!("nf-order-tx-{i}").as_bytes(),
            1000,
            vec![canon_nf_for_test(format!("nf-order-nf-{i}").as_bytes())],
            need,
        );
        txs.push(tx.clone());
        p.ingest_tx_unverified(tx)
            .expect("the pool takes the real tx");
        blocks.push(
            p.produce(5_000 + i as u64, Hash32::hash(b"f"), Hash32::hash(b"r"))
                .expect("mined"),
        );
    }
    (blocks, txs)
}

// ⛔ `which_secret_derivation_reproduces_the_live_folded_tags` DELETED 2026-08-15 with the machinery it tested.
// It exercised the per-block fold-input store / stream serve, which is gone: those maps held one
// entry per block in RAM forever and nothing consumed their output. A test of a deleted growth
// store must go WITH it — keeping it would force the store back to keep the test green.

/// ⛔⛔⛔ THE "SENDS STOP WORKING FOREVER" REGRESSION.
///
/// A block's decoy seed comes from its nullifier-bearing txs' CONFIDENTIAL blobs — seeding from the
/// block's public nullifiers instead would let any observer recompute the decoy set and pick the real
/// spend out of it. A node builds that blob from its own MEMPOOL, so a node that has not yet received
/// those txs derives an EMPTY blob, seeds different decoys, and its fold cannot reach the producer's
/// proven post-root. It then used to DROP the block, permanently, with nothing ever retrying it.
///
/// Measured: the same 9 blocks fold 9/9 on a node holding the txs and 0/9 on one that does not. The
/// note-payload record advances either way, so `served_seq` outran `nf_fold_seq` and the gap GREW without
/// bound — 474 -> 510 -> 545 in 50s on a live pair. Wallets fold the served stream to its END, so once
/// the gap opens EVERY spender names an endpoint the node never held and every send is refused with
/// `[nf-gate] REJECT: the base this proof names is not an accumulator this chain ever held`. Sends work on
/// a young chain and stop, permanently, on an older one.
///
/// Two parties, adverse on BOTH orderings: the second node gets the blocks REVERSED (each arrives before
/// the block it chains onto) and gets the txs only afterwards. It must still fold every block and land on
/// the same absence endpoint as a node that saw everything in the friendly order.
#[test]
fn a_verifying_node_folds_every_block_even_when_they_arrive_out_of_order() {
    let (blocks, txs) = mine(9);

    // Reference: txs first, then blocks in order.
    let mut want = Node::new(genesis_block()).unwrap();
    for t in &txs {
        let _ = want.ingest_tx_unverified(t.clone());
    }
    for b in &blocks {
        want.ingest_block(b.clone(), 9_000);
    }
    let want_seq = want.nf_fold_seq();
    let want_acc = want.nf_unspent_acc();
    assert!(
        want_seq >= 9,
        "the reference node must fold every block, got {want_seq}"
    );

    // Adverse: the blocks arrive BEFORE the txs they carry. This is the ordinary case on a live mesh —
    // a block relays as one message and its txs as others, so a node routinely holds a block whose txs it
    // has not seen (and after a restart or an eviction, holds none of them).
    let mut late = Node::new(genesis_block()).unwrap();
    for b in &blocks {
        late.ingest_block(b.clone(), 9_000);
    }
    // ⭐ INVERTED ON PURPOSE — THIS ASSERTION USED TO ENCODE THE BUG.
    // It previously demanded `nf_fold_seq() == 0` here: "with no txs yet, no block's decoy seed can be
    // derived, so nothing may fold". That WAS the behaviour, and it was the fund-loss defect — measured
    // live as `served_seq - nf_fold_seq` = 10,419 and rising, i.e. ten thousand accepted blocks outside
    // the accumulator, so every spender named a base the node had never held. A block now CARRIES the
    // padded tag set its fold proof is checked against, so a node folds it on arrival without ever
    // holding its txs. That is the Bitcoin/Kaspa invariant: accepting the block applies its spends.
    assert_eq!(
        late.nf_fold_seq(),
        want_seq,
        "a node that holds NONE of these blocks' txs must still fold every one of them from the tags the \
         blocks carry — parking them is what made nf_fold_seq fall permanently behind served_seq"
    );
    assert_eq!(
        late.nf_unspent_acc(),
        want_acc,
        "and it must reach the SAME accumulator as the node that had every tx — otherwise the endpoint a \
         wallet names still depends on which node it asked"
    );
    for t in &txs {
        let _ = late.ingest_tx_unverified(t.clone());
    }

    assert_eq!(
        late.nf_fold_seq(),
        want_seq,
        "a node that received the SAME blocks BEFORE their txs folded {} of them \
         instead of {want_seq}. Every unfolded block is one the served note stream has already counted, \
         so the gap between served_seq and nf_fold_seq opens and never closes — and every wallet that \
         folds to the end of that stream names an endpoint this node cannot recognise, so every send is \
         refused.",
        late.nf_fold_seq()
    );
    assert_eq!(
        late.nf_unspent_acc(),
        want_acc,
        "arrival order must not change the absence endpoint — a spender's proof binds to A_tip, so two \
         nodes holding the same blocks must agree on it, or a send verifies on one node and fails on the \
         other"
    );
}

/// The drain must not be a hole in the gate: a block carrying a BAD fold is refused, in order or not.
#[test]
fn an_out_of_order_block_with_a_forged_fold_never_advances_the_accumulator() {
    let (blocks, txs) = mine(4);
    let mut n = Node::new(crate::node::tests::genesis_block()).unwrap();
    for t in &txs {
        let _ = n.ingest_tx_unverified(t.clone());
    }

    let mut forged = blocks[3].clone();
    forged.nullifier_proof.post_root = Hash32::hash(b"forged-post-root");
    n.ingest_block(forged, 9_000);
    assert_eq!(
        n.nf_fold_seq(),
        0,
        "an out-of-order block is BUFFERED (unknown parent) — nothing may advance before its ancestors arrive"
    );

    // Deliver the real predecessors; the buffered block cascades in behind them.
    for i in 0..3usize {
        n.ingest_block(blocks[i].clone(), 9_000);
    }
    // The honest control takes the SAME four blocks with the post field UNTAMPERED.
    let mut clean = Node::new(genesis_block()).unwrap();
    for t in &txs {
        let _ = clean.ingest_tx_unverified(t.clone());
    }
    for i in 0..4usize {
        clean.ingest_block(blocks[i].clone(), 9_000);
    }
    assert_eq!(
        n.nf_fold_seq(),
        clean.nf_fold_seq(),
        "a tampered post field must not PARK a block — parking is what left tens of thousands of accepted \
         blocks outside the accumulator on the live pair, refusing every send"
    );
    assert_eq!(
        n.nf_unspent_acc(),
        clean.nf_unspent_acc(),
        "and the forged post did not CORRUPT the accumulator: A_tip is a function of the block's carried \
         TAGS alone, so a tampered post reaches the identical endpoint an honest copy reaches"
    );
}

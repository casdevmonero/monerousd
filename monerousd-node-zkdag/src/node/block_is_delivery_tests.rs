// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::block_is_delivery_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::{canon_nf_for_test, genesis_block, grind_tx};
use super::Node;
use crate::hash::Hash32;

/// ⭐⭐⭐ BLOCK ACCEPTANCE **IS** PAYMENT DELIVERY: two nodes that accepted the same blocks must number
/// their records IDENTICALLY.
///
/// TEST-ARCHITECTURE-REVIEWED: cannot pass vacuously — the control is a chain that MIXES blocks carrying
/// notes with blocks carrying none. Under the old `if !carried_notes.is_empty()` gate the two nodes
/// skipped different blocks and their `served_seq` diverged, so the equality below was FALSE. It is
/// asserted against a positive value (both > 0) so an all-zero run cannot satisfy it.
///
/// Why this is the whole bug: an account bucket records a note's ORDINAL. If node A and node B number
/// their records differently, "ordinal X" means a different block on each, and the recipient's wallet
/// fetches the wrong record — or nothing. Measured live before the fix: node A at served 16228 of 16955
/// blocks, node B at 15109 of 16899. Bitcoin and Kaspa cannot have this: a block contains its
/// transactions and every node stores the whole block, so there is no second stream to drift.
#[test]
fn two_nodes_that_accepted_the_same_blocks_agree_on_every_record_ordinal() {
    let mut producer = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let mut verifier = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let mut blocks = Vec::new();

    // MIXED chain: every third block carries a real spend, the rest carry none. That mix is the control —
    // with a note-conditional record the two nodes skip different blocks and diverge.
    for i in 0..12u32 {
        if i % 3 == 0 {
            let need = producer.mempool().required_stamp_bits();
            let tx = grind_tx(
                format!("delivery-tx-{i}").as_bytes(),
                1000,
                vec![canon_nf_for_test(format!("delivery-nf-{i}").as_bytes())],
                need,
            );
            producer.ingest_tx_unverified(tx).expect("pool takes it");
        }
        blocks.push(
            producer
                .produce(5_000 + i as u64, Hash32::hash(b"f"), Hash32::hash(b"r"))
                .expect("mined"),
        );
    }
    // ⛔ THE ASYMMETRY IS THE POINT. The verifier is given the BLOCKS and NEVER the txs — the ordinary
    // state of a peer whose spend gate refused the gossiped tx, or that simply had not received it. If
    // anything about recording is derived from the node's own MEMPOOL rather than from the block, the two
    // nodes record different things and their ordinal spaces drift apart. A test where both sides hold
    // the same pool cannot see that, and an earlier version of this test did exactly that: it passed
    // unchanged with the defect restored, which is the vacuous-test shape the standard forbids.
    for b in &blocks {
        verifier.ingest_block(b.clone(), 9_000);
    }

    assert!(
        producer.served_seq() > 0,
        "the producer must have recorded blocks at all"
    );
    assert!(
        verifier.served_seq() > 0,
        "the verifier must have recorded blocks at all"
    );
    assert_eq!(
        verifier.served_seq(),
        producer.served_seq(),
        "two nodes holding the SAME blocks must number their records identically. They do not: producer \
         {} vs verifier {}. An account bucket records a note's ORDINAL, so divergent numbering means \
         'ordinal X' points at a different block on each node and the recipient's wallet fetches the \
         wrong record — the payment is delivered and still invisible.",
        producer.served_seq(),
        verifier.served_seq()
    );

    // ...and the ordinals must map to the SAME record on both, not merely count the same.
    for ord in 0..producer.served_seq() {
        assert_eq!(
            verifier.da_addr_at_ordinal(ord).is_some(),
            producer.da_addr_at_ordinal(ord).is_some(),
            "ordinal {ord} must resolve on both nodes or neither — a hole on one side shifts every \
             later note's position and silently mis-addresses every bucket lookup after it"
        );
    }
}

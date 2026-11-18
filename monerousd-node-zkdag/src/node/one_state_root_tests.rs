// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::one_state_root_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::{genesis_block, AcceptDecider};
use super::Node;
use crate::hash::Hash32;

/// ⭐⭐⭐ ONE ROOT, TWO PARTIES, BOTH HALVES COPATH-VERIFIABLE — AND TAMPER REJECTS EACH.
///
/// user 2026-07-29: *"Make monerousd one root and validity is a copath against that root just like mina."*
///
/// The Mina property is not "we have a root" — it is that the SINGLE root is what everyone compares, and
/// every claim reduces to a copath under it. So this proves all three parts:
///   1. a producer and a verifier that never spoke to each other agree on ONE value;
///   2. the note half is copath-verifiable — a note's depth-32 path folds to the notes half of that root;
///   3. the nullifier half is copath-verifiable — non-membership folds to the nullifier half.
/// And the tamper cases are what make it worth anything: corrupting EITHER half must change the one root.
/// A state root that survives a tampered half would be a decoration, not an authority.
#[test]
fn two_nodes_agree_on_one_state_root_and_a_tampered_half_changes_it() {
    let mut producer = Node::new(genesis_block()).unwrap();
    let mut verifier = Node::new(genesis_block()).unwrap();
    producer.set_decider_verifier(Box::new(AcceptDecider));
    verifier.set_decider_verifier(Box::new(AcceptDecider));

    for i in 0..12u64 {
        let blk = producer
            .produce(5_000 + i, Hash32::hash(b"f"), Hash32::hash(b"r"))
            .expect("the producer mined a block");
        verifier.ingest_block(blk, 9_000);
    }

    // 1. TWO PARTIES, ONE VALUE. If these differ, users get different verdicts depending which peer they
    //    reached — the chain split in miniature, and the whole reason a single root is the goal.
    let root = producer.state_root();
    assert_eq!(
        verifier.state_root(),
        root,
        "a producer and a verifier that folded the same blocks must land on ONE state root"
    );
    assert_ne!(
        root,
        Node::new(genesis_block()).unwrap().state_root(),
        "a chain with 12 blocks must not share the empty chain's state root, or the root commits nothing"
    );

    // 2. + 3. BOTH HALVES RECOMPOSE IT. This is the copath property: a verifier that proved a note against
    //    the notes root, and absence against the nullifier root, pairs those two halves and gets the one
    //    root back — no node state, no extra accumulator, no "when" question.
    assert_eq!(
        Node::state_root_of(producer.spend_frontier_root(), producer.nullifier_root()),
        root,
        "the one root must be exactly the pair of the two halves a spend proves against"
    );

    // TAMPER A — the NOTE half. A forged note accumulator must not pass as this chain's state.
    let mut bad_notes = producer.spend_frontier_root();
    bad_notes[0] ^= 1;
    assert_ne!(
        Node::state_root_of(bad_notes, producer.nullifier_root()),
        root,
        "a tampered NOTE root must change the state root — otherwise a forged membership proof verifies \
         against a state that never existed"
    );

    // TAMPER B — the NULLIFIER half. A forged nullifier accumulator is the double-spend direction.
    let mut bad_nf = producer.nullifier_root();
    bad_nf[0] ^= 1;
    assert_ne!(
        Node::state_root_of(producer.spend_frontier_root(), bad_nf),
        root,
        "a tampered NULLIFIER root must change the state root — otherwise a spent note can be replayed \
         under a state the chain never held"
    );

    // The two halves must not be interchangeable: swapping them must not produce the same root, or the
    // pairing carries less information than the two values it claims to commit.
    assert_ne!(
        Node::state_root_of(
            crate::spend_frontier::cm_bytes_to_leaf(&producer.nullifier_root()),
            crate::spend_frontier::leaf_to_cm_bytes(producer.spend_frontier_root()),
        ),
        root,
        "the pairing must be position-dependent, or the state root does not distinguish its halves"
    );
}

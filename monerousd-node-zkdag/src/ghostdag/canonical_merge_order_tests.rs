// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `ghostdag::canonical_merge_order_tests` — the tests of `ghostdag` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `ghostdag` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`ghostdag::canonical_merge_order_tests::…`), and `use super::*` reaches `ghostdag`'s items through the node's re-export.

// the imports of `ghostdag` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use std::collections::HashMap;
#[allow(unused_imports)]
use std::collections::HashSet;
#[allow(unused_imports)]
use std::collections::VecDeque;
#[allow(unused_imports)]
use crate::block::BlockId;

use crate::block::{Block, BlockHeader};
use crate::dag::Dag;
use crate::hash::Hash32;

pub(crate) fn blk(parents: Vec<Hash32>, dag: &Dag, salt: u64) -> Block {
    let sp = parents
        .iter()
        .max_by(|a, b| dag.order_key(a).cmp(&dag.order_key(b)))
        .copied();
    Block {
        cover_key: None,
        wide_objects: Vec::new(),
        tx_bodies: Vec::new(),
        agg_tables: Vec::new(),
        note_commitments: Vec::new(),
        header: BlockHeader {
        note_commitments_root: crate::hash::Hash32::hash(&[]),
            nullifier_tags_root: crate::hash::Hash32::hash(&[]),
            output_notes_root: crate::hash::Hash32::hash(&[]),
            // P4'a fixture: this block ships no locator tags and no account targets, so both sidecar
            // commitments are the empty-payload hash the verifier re-derives.
            oli_tags_root: crate::block::da_sidecar_root_of(&[]),
            // ⭐ §BA — no credit set here, so the DERIVED empty sidecar root, never a magic constant.
            credit_set_root: crate::block::da_sidecar_root_of(&[]),
            transitions_root: crate::block::empty_transitions_root(),
            cover_seed_commit: crate::hash::Hash32::ZERO,
            member_ring_commit: crate::hash::Hash32::ZERO,
            account_targets_root: crate::block::da_sidecar_root_of(&[]),
            bond_set_root: crate::block::da_sidecar_root_of(&[]),
            dir_set_root: crate::block::da_sidecar_root_of(&[]),
            letter_set_root: crate::block::da_sidecar_root_of(&[]),
            tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
            level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
            version: 1,
            parents,
            timestamp: 2_000 + salt,
            nonce: salt,
            work: crate::miner::adaptive_work(dag, sp.as_ref().copied()),
            pow_bind: Hash32::ZERO,
            tx_merkle_root: Hash32::ZERO,
            frontier_root: Hash32::ZERO,
            nullifier_root: Hash32::ZERO,
            sparse_root: Hash32::ZERO,
            chain_acc: [0u8; 16],
            miner_commitment: Hash32::hash(&salt.to_le_bytes()),
            account_root: Hash32::ZERO,
        },
        tx_ids: vec![],
        pow_proof: Vec::new(),
        output_notes: Vec::new(),
        oli_tags: Vec::new(),
        account_targets: Vec::new(),
        bond_set: Vec::new(),
        // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
        credit_set: Vec::new(),
        dir_set: Vec::new(),
        letter_set: Vec::new(),
        tag_evidence: Vec::new(),
        note_transition: None,
        nullifier_proof: crate::block::NfBlockProof::default(),
        cover_transition: None,
        member_transition: None,
    }
}

/// ⭐⭐⭐ TWO NODES HANDED THE SAME BLOCKS IN DIFFERENT ORDERS MUST COLOUR THEM IDENTICALLY.
///
/// TWO-PARTY-REVIEWED: two INDEPENDENT `Dag`s standing in for two nodes, fed the identical block set in
/// DIFFERENT arrival orders — the disagreement this exists to catch is between them, and it is asserted
/// directly. Sharing no state, they must still derive the same colouring.
///
/// The mergeset used to be ordered by `topo_order`, this node's local INSERTION counter, and the k-cluster
/// colouring walks that order. So the blues/reds a node computed depended on the sequence packets happened
/// to arrive in — two honest peers could land on different `blue_score`/`blue_work` for the very same DAG
/// and disagree about the canonical chain. A same-chain split with no attacker and no fork: exactly the
/// class that cannot be allowed to exist by construction.
#[test]
fn cross_node_the_colouring_does_not_depend_on_the_order_blocks_arrived_in() {
    // Node A's arrival order: b1, b2, b3 (siblings off genesis), then a merge block over all three.
    let mut node_a = Dag::new();
    let g = node_a
        .add_block(crate::node::tests::genesis_block())
        .expect("genesis A");
    let s1 = blk(vec![g], &node_a, 11);
    let s2 = blk(vec![g], &node_a, 22);
    let s3 = blk(vec![g], &node_a, 33);
    let (i1, i2, i3) = (
        node_a.add_block(s1.clone()).expect("a1"),
        node_a.add_block(s2.clone()).expect("a2"),
        node_a.add_block(s3.clone()).expect("a3"),
    );
    let merge = blk(vec![i1, i2, i3], &node_a, 44);
    let ma = node_a.add_block(merge.clone()).expect("merge A");

    // Node B saw the SAME blocks, in the REVERSE sibling order — the only difference between the peers.
    let mut node_b = Dag::new();
    let gb = node_b
        .add_block(crate::node::tests::genesis_block())
        .expect("genesis B");
    assert_eq!(
        g, gb,
        "both nodes share one genesis or nothing below is comparable"
    );
    node_b.add_block(s3).expect("b3");
    node_b.add_block(s2).expect("b2");
    node_b.add_block(s1).expect("b1");
    let mb = node_b.add_block(merge).expect("merge B");
    assert_eq!(
        ma, mb,
        "the same block bytes must have the same id on both nodes"
    );

    let ga = node_a.ghostdag_data(&[i1, i2, i3]);
    let gbd = node_b.ghostdag_data(&[i1, i2, i3]);

    assert_eq!(
        ga.mergeset_blues, gbd.mergeset_blues,
        "the two nodes coloured DIFFERENT blocks blue for the identical DAG — blue_score then diverges and \
         they disagree about the canonical chain, purely because blocks arrived in a different order"
    );
    assert_eq!(
        ga.mergeset_reds, gbd.mergeset_reds,
        "the two nodes coloured different blocks red for the identical DAG"
    );
    assert_eq!(
        ga.blue_score, gbd.blue_score,
        "blue_score must be a function of the DAG, not of arrival order"
    );
    assert_eq!(
        ga.blue_work, gbd.blue_work,
        "blue_work must be a function of the DAG, not of arrival order"
    );
    assert_eq!(
        node_a.selected_tip(),
        node_b.selected_tip(),
        "two nodes with the identical DAG must select the identical tip — anything else IS the split"
    );

    // And every block is accounted for: nothing may vanish from the merge. A block dropped from the
    // mergeset is a block whose notes no one applies.
    // The mergeset is the three siblings (genesis is in past(sp), so it is not re-merged) and EVERY one
    // of them must be coloured. A block missing from the merge is a block whose notes nobody applies.
    let total = ga.mergeset_blues.len() + ga.mergeset_reds.len();
    assert_eq!(
        total, 3,
        "all 3 merged siblings must be coloured, none silently dropped: {total}"
    );
}

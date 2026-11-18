// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `dag::selected_tip_ancestry_is_o1_tests` — the tests of `dag` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `dag` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`dag::selected_tip_ancestry_is_o1_tests::…`), and `use super::*` reaches `dag`'s items through the node's re-export.

// the imports of `dag` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use std::collections::BTreeMap;
#[allow(unused_imports)]
use std::collections::HashMap;
#[allow(unused_imports)]
use std::collections::HashSet;
#[allow(unused_imports)]
use crate::params::ChainParams;

use super::*;
use crate::block::{Block, BlockHeader, BlockId};
use crate::hash::Hash32;

/// The same distinct-per-nonce builder `dag::tests::hdr`/`blk` use — that pair is private to its own
/// module, so this module carries its own copy for the record-key pin below (which referenced `blk`
/// without any definition in scope and left the whole tree test-RED on 2026-09-06; compile fix only,
/// the pin's assertions are untouched).
fn hdr(parents: Vec<BlockId>, nonce: u64) -> BlockHeader {
    BlockHeader {
        note_commitments_root: crate::hash::Hash32::hash(&[]),
        nullifier_tags_root: crate::hash::Hash32::hash(&[]),
        output_notes_root: crate::hash::Hash32::hash(&[]),
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
        timestamp: nonce,
        nonce,
        work: 100, // a real, uniform per-block work for the test; production sets it via the DAA
        pow_bind: Hash32::ZERO,
        tx_merkle_root: Hash32::ZERO,
        frontier_root: Hash32::ZERO,
        nullifier_root: Hash32::ZERO,
        sparse_root: Hash32::ZERO,
        chain_acc: [0u8; 16],
        miner_commitment: Hash32::ZERO,
        account_root: Hash32::ZERO,
    }
}
fn blk(parents: Vec<BlockId>, nonce: u64) -> Block {
    Block {
        cover_key: None,
        wide_objects: Vec::new(),
        tx_bodies: Vec::new(),
        agg_tables: Vec::new(),
        note_commitments: Vec::new(),
        header: hdr(parents, nonce),
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

/// `salt` distinguishes two chains built in one test. Without it both builders emit BYTE-IDENTICAL
/// headers from the same genesis, so "a block from a different chain" is literally the same block id —
/// a negative case that could never fail for the reason it claims to test.
fn chain_of_salted(n: usize, salt: u64) -> (Dag, Vec<crate::hash::Hash32>) {
    let mut dag = Dag::new();
    let g = dag
        .add_block(crate::node::tests::genesis_block())
        .expect("genesis");
    let mut ids = vec![g];
    let mut prev = g;
    for i in 0..n {
        let h = BlockHeader {
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
            parents: vec![prev],
            timestamp: 1000 + i as u64,
            nonce: i as u64,
            work: crate::miner::adaptive_work(&dag, Some(prev)),
            pow_bind: crate::hash::Hash32::ZERO,
            tx_merkle_root: crate::hash::Hash32::ZERO,
            frontier_root: crate::hash::Hash32::ZERO,
            nullifier_root: crate::hash::Hash32::ZERO,
            sparse_root: crate::hash::Hash32::ZERO,
            chain_acc: [0u8; 16],
            miner_commitment: crate::hash::Hash32::hash(
                &[(i as u64).to_le_bytes(), salt.to_le_bytes()].concat(),
            ),
            account_root: crate::hash::Hash32::ZERO,
        };
        let b = Block {
        cover_key: None,
        wide_objects: Vec::new(),
        tx_bodies: Vec::new(),
        agg_tables: Vec::new(),
        note_commitments: Vec::new(),
            header: h,
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
        };
        prev = dag.add_block(b).expect("extend");
        ids.push(prev);
    }
    (dag, ids)
}

/// ⭐⭐⭐ ANCESTRY OF THE TIP COSTS THE SAME AT ANY CHAIN LENGTH — the O(1) evidence standard.
///
/// TWO-PARTY-REVIEWED: this measures a COST PROPERTY of one node's index, not a boundary crossing. The
/// cross-node behaviour that depends on it (a spend admitted on a peer) is covered by the cross-device
/// send.
///
/// The live tx-ingest path asks "is this block an ancestor of the tip?" for every spend. That was a walk
/// back along selected parents — O(selected-depth), so the cost grew forever with the chain and every
/// user's spend paid more than the last. Per the canonical definition a counter must be FLAT across
/// wildly different N; a ratio or a wall-clock proves nothing.
#[test]
fn answering_tip_ancestry_touches_the_same_number_of_blocks_at_any_height() {
    let (short, short_ids) = chain_of_salted(8, 1);
    let (tall, tall_ids) = chain_of_salted(800, 1); // 100x

    // Ask the genesis-adjacent block — the WORST case for a walk, which would traverse the whole chain.
    assert!(
        short.is_ancestor_of_selected_tip(&short_ids[1]),
        "block 1 is an ancestor of the short tip"
    );
    let steps_short = short.last_ancestry_steps();
    assert!(
        tall.is_ancestor_of_selected_tip(&tall_ids[1]),
        "block 1 is an ancestor of the tall tip"
    );
    let steps_tall = tall.last_ancestry_steps();

    assert_eq!(
        steps_short, steps_tall,
        "tip-ancestry touched {steps_short} blocks on an 8-block chain but {steps_tall} on an 800-block \
         chain. Any difference is growth with history on the path every spend takes — O(chain), which is \
         banned at every layer."
    );

    // A block that is NOT on the chain must still be answered, and answered NEGATIVELY.
    let (other, other_ids) = chain_of_salted(4, 99); // a genuinely DIFFERENT chain, not a prefix twin
    assert!(
        !tall.is_ancestor_of_selected_tip(&other_ids[2]),
        "a block from a different chain is not an ancestor of this tip"
    );
    let _ = other;
}

/// The index must be CORRECT, not merely cheap — it has to agree with the exact walk on every block,
/// including after the chain grows. A fast wrong answer on the spend path is worse than a slow right one.
#[test]
fn the_indexed_answer_equals_the_exact_walk_for_every_block() {
    let (dag, ids) = chain_of_salted(120, 7);
    let tip = dag.selected_tip().expect("tip");
    for (i, id) in ids.iter().enumerate() {
        let indexed = dag.is_ancestor_of_selected_tip(id);
        let walked = dag.is_selected_chain_ancestor(id, &tip);
        assert_eq!(
            indexed, walked,
            "block {i} disagreed: index says {indexed}, the exact selected-parent walk says {walked}"
        );
    }
}

// (The record-key pin below builds its blocks with this module's own `blk` fixture above — one
// helper, not a per-pin copy; a duplicate `rk_blk` twin was folded onto it 2026-09-06.)

/// ⭐ THE RECORD-KEY INDEX AGREES WITH THE FULL SCAN IT REPLACED — ON BOTH PARTIES, ACROSS A PRUNE.
///
/// `Node::block_for_record_addr` used to invert a record address by scanning a fresh Vec of EVERY
/// block id per call; [`Dag::record_key_index`] replaced that with one indexed read maintained at
/// [`Dag::insert_block`] and rebuilt by the prune sweep. This pin holds the two shapes to the SAME
/// answer on every key the store can be asked about, on a PRODUCING party and on a party that
/// INGESTS the same blocks, at the one point the index can silently drift from its store: the prune
/// sweep, which deletes blocks in bulk on each side independently.
///
/// ROOT-LAYER: the index lives where the block store is WRITTEN (insert_block / prune's rebuild), so
/// the pin drives those two writers directly on both parties; asserting at any reader would leave a
/// third insert site free to skip the index and only fail far away.
/// MEASURED: RED run 2026-09-06 — with `insert_block` filing nothing (the drift this pin exists to
/// catch), every lookup answered None against 1100 driven blocks and the assertion named the first
/// disagreeing key; the incident that motivated the index measured 2479 `[record-regen]` lines at
/// 1-in-256 sampling (~633000 full-DAG scans) in one 25-minute rolling-restart run.
/// MUST-STAY-GREEN: `the_indexed_answer_equals_the_exact_walk_for_every_block` (the sibling index of
/// this shape) and the two-party runtime agreement pin in `mesh_runtime_scenarios`
/// (produce/ingest/adopt over the real wire); this one owns the insert+prune lanes.
#[test]
fn the_record_key_index_agrees_with_a_full_scan_across_insert_and_prune() {
    // Small caps so the prune horizon is actually crossed in-test: keep_depth = 2*4 + 4 + 256 = 268,
    // + DAG_PRUNE_SLACK 512 ⇒ the sweep fires once the store passes 780 blocks.
    let mut params = ChainParams::default();
    params.merge_depth_cap = 4;
    params.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
    params.daa_sample_len = 4;
    // TWO PARTIES: `producer` originates every block; `ingester` receives the same blocks the way a
    // peer does (same add_block door, its own store, its own prune sweeps). A one-party pin could
    // never see the failure that matters — the two sides answering a consensus question differently.
    let mut producer = Dag::with_params(params.clone());
    let mut ingester = Dag::with_params(params);
    let genesis = blk(vec![], 0);
    let mut prev = producer.add_block(genesis.clone()).unwrap();
    assert_eq!(ingester.add_block(genesis).unwrap(), prev, "both parties start on one genesis");
    let driven = 1100u64;
    for nonce in 1..=driven {
        let b = blk(vec![prev], nonce);
        prev = producer.add_block(b.clone()).unwrap();
        assert_eq!(ingester.add_block(b).unwrap(), prev, "the ingester grafts the same block");
    }
    assert!(
        (producer.len() as u64) < driven,
        "setup: the prune sweep never fired ({} blocks held of {} driven) — the lane this pin \
         exists for was not exercised",
        producer.len(),
        driven
    );
    for (who, dag) in [("producer", &producer), ("ingester", &ingester)] {
        // THE OLD DERIVATION, verbatim in shape: linearly scan every held block id for the key.
        // Unique holder ⇒ that block; collision ⇒ the index answers None by design (fail-closed,
        // see `record_key_index`) where the old scan answered an arbitrary one of them.
        let held = dag.block_ids();
        for id in &held {
            let key = Dag::record_key(id);
            let holders = held.iter().filter(|x| Dag::record_key(x) == key).count();
            let expect = if holders == 1 { Some(*id) } else { None };
            assert_eq!(
                dag.block_for_record_key(key),
                expect,
                "{who}: key {key:#x} — the index disagrees with the full scan over {} held blocks \
                 ({holders} holder(s) of this key)",
                held.len()
            );
        }
        // A key NO held block folds to must answer None — a pruned block's entry may not outlive it.
        let ghost = Dag::record_key(&crate::hash::Hash32::hash(b"record-key-never-inserted"));
        if held.iter().all(|x| Dag::record_key(x) != ghost) {
            assert_eq!(
                dag.block_for_record_key(ghost),
                None,
                "{who}: a key no held block folds to answered Some — a stale entry survived the prune"
            );
        }
        // THE BOUND, stated and asserted: the index mirrors the block store exactly — total filed
        // equals blocks held, distinct keys never exceed it — so it inherits the prune horizon's
        // bound and adds no growth axis of its own.
        let (distinct, filed) = dag.record_key_index_census();
        assert_eq!(
            filed,
            dag.len(),
            "{who}: the index files {filed} blocks but the store holds {} — the two structures \
             drifted",
            dag.len()
        );
        assert!(
            distinct <= dag.len(),
            "{who}: {distinct} distinct keys over {} blocks — an entry outlived its block",
            dag.len()
        );
    }
    // AND THE TWO PARTIES AGREE WITH EACH OTHER — the disagreement between the sides is where every
    // real failure has lived (`block_declares_no_notes` turns this answer into "this row IS an idle
    // record", a question consensus reads).
    for id in producer.block_ids() {
        let key = Dag::record_key(&id);
        assert_eq!(
            producer.block_for_record_key(key),
            ingester.block_for_record_key(key),
            "the producer and the ingester answer key {key:#x} differently for a block both hold"
        );
    }
}

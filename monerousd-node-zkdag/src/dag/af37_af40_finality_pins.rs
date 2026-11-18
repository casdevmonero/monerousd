// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `dag::af37_af40_finality_pins` — A-F37 and A-F40 pin tests for template_parents finality.
//! Kept in the node crate because `dag` itself compiles in the ledger crate.
//! `use super::*` reaches `dag`'s items through the node's re-export.

use super::*;
use crate::block::{Block, BlockHeader, BlockId};
use crate::hash::Hash32;

fn hdr(parents: Vec<BlockId>, nonce: u64) -> BlockHeader {
    BlockHeader {
        note_commitments_root: crate::hash::Hash32::hash(&[]),
        nullifier_tags_root: crate::hash::Hash32::hash(&[]),
        output_notes_root: crate::hash::Hash32::hash(&[]),
        oli_tags_root: crate::block::da_sidecar_root_of(&[]),
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
        work: 100,
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
fn blk_w(parents: Vec<BlockId>, nonce: u64, work: u128) -> Block {
    let mut h = hdr(parents, nonce);
    h.work = work;
    Block {
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

fn honest_chain_and_a_heavier_abandoning_rival() -> (Dag, BlockId, BlockId, BlockId) {
    let mut dag = Dag::new();
    let g = dag.add_block(blk(vec![], 1)).unwrap();
    let a = dag.add_block(blk(vec![g], 2)).unwrap();
    let b = dag.add_block(blk(vec![a], 3)).unwrap();
    let c = dag.add_block(blk(vec![b], 4)).unwrap();
    let x1 = dag.add_block(blk_w(vec![g], 5, 10_000)).unwrap();
    let x2 = dag.add_block(blk(vec![x1], 6)).unwrap();
    assert!(
        dag.get(&x2).unwrap().blue_work > dag.get(&c).unwrap().blue_work,
        "fixture must actually be work-heavier, else the pin proves nothing"
    );
    (dag, b, c, x2)
}

/// A-F37 PIN (RED-first): a block template builds on the FINALITY-RESPECTING head, not the
/// plain-heaviest tip.
#[test]
fn af37_a_template_builds_on_the_finality_respecting_head_not_the_plain_heaviest_tip() {
    let (mut dag, b, c, x) = honest_chain_and_a_heavier_abandoning_rival();
    dag.set_finality_floor(Some(b));
    assert_eq!(dag.selected_tip(), Some(c), "setup: the finality head is c");
    assert!(dag.get(&x).unwrap().blue_work > dag.get(&c).unwrap().blue_work, "setup: x is heavier");

    let parents = dag.template_parents();
    assert_eq!(
        parents[0], c,
        "⛔ A-F37: template_parents[0] must be the finality-respecting head (c), not the \
         plain-heaviest tip (x) — a template built on the abandoning branch halts the fold"
    );

    let n = dag.add_block(blk(parents, 4242)).unwrap();
    assert!(
        dag.is_selected_chain_ancestor(&b, &n),
        "⛔ A-F37: the honestly-produced block does not keep the finalized block on its \
         selected chain — the template ignored finality"
    );
    assert_eq!(dag.selected_tip(), Some(n), "production continues on the admissible chain");
}

/// A-F40 PIN (RED-first): after a foreign block merges the admissible head from a heavier
/// branch, the NEXT template still builds on an admissible parent.
#[test]
fn af40_after_a_merge_that_consumes_the_admissible_head_the_next_template_keeps_finality() {
    let (mut dag, b, c, x) = honest_chain_and_a_heavier_abandoning_rival();
    dag.set_finality_floor(Some(b));
    assert_eq!(dag.selected_tip(), Some(c), "setup: the finality head is c");

    let foreign = dag.add_block(blk(vec![x, c], 9999)).unwrap();
    assert_eq!(
        dag.get(&foreign).unwrap().selected_parent,
        Some(x),
        "setup: GHOSTDAG picks x as selected parent (heavier)"
    );
    assert!(!dag.is_selected_chain_ancestor(&b, &foreign),
        "setup: the foreign block does not keep finality (its selected chain goes through x)");

    assert!(!dag.tips().contains(&c), "setup: c was consumed");
    assert!(dag.tips().contains(&foreign), "setup: foreign is a tip");

    // A-F40 + A-F54: the HEAD stays on the heaviest block that keeps the floor (c, the block just consumed) and the template
    // builds on it — never on the finality floor b itself, which sits below every node's fold cursor (the arm that built on
    // b halted the chain on real nodes, A-F54).
    assert_eq!(dag.selected_tip(), Some(c), "⛔ A-F40: one merge carried the head off the finalized block");
    let parents = dag.template_parents();
    // the only tip (foreign) leaves the floor behind and is not merged in: the template is exactly [c]
    assert_eq!(parents, vec![c], "⛔ A-F54: the template does not build on c, the heaviest block that keeps the floor (or it builds on the floor itself, below the fold)");
    let n = dag.add_block(blk(parents, 5555)).unwrap();
    assert_eq!(dag.selected_tip(), Some(n), "A-F40: the chain goes on above the finalized block");
    assert!(
        dag.is_selected_chain_ancestor(&b, &n),
        "⛔ A-F40: the block built on the admissible head does not keep finality"
    );

    let (mut dag2, b2, c2, _x2) = honest_chain_and_a_heavier_abandoning_rival();
    dag2.set_finality_floor(Some(b2));
    let parents2 = dag2.template_parents();
    assert_eq!(parents2[0], c2, "before the foreign merge, the template builds on c");
    let honest = dag2.add_block(blk(parents2, 7777)).unwrap();
    assert!(
        dag2.is_selected_chain_ancestor(&b2, &honest),
        "⛔ A-F40: the honest template's block does not keep finality — it built on the \
         abandoning branch instead of the admissible head"
    );
}

/// The selected-chain block `levels` below `tip`.
fn below(dag: &Dag, tip: BlockId, levels: u64) -> BlockId {
    let mut at = tip;
    for _ in 0..levels {
        at = dag.get(&at).and_then(|n| n.selected_parent).expect("a parent");
    }
    at
}

/// ⭐ FOLD-REORG PIN (RED-first by its calibration; spec §11.13, lane goodshalt 2026-11-15): the fold root under the finality
/// rule never sits on a block the fork choice can still abandon. A chain a1..a9 is final at a3; a heavier branch forks at
/// a4 and takes the head. The old root (four levels below a9, a5) leaves the new selected chain, so the fold rewinds (35 to
/// 38 times in 40 minutes on real nodes); the rule's root (a3, the final block) stays on it.
#[test]
fn the_fold_root_is_the_final_block_and_a_reorg_above_it_rewinds_nothing() {
    let mut dag = Dag::new();
    let g = dag.add_block(blk(vec![], 1)).unwrap();
    let mut a = vec![g];
    for i in 1..=9u64 {
        let p = *a.last().unwrap();
        a.push(dag.add_block(blk(vec![p], 100 + i)).unwrap());
    }
    let (a3, a9) = (a[3], a[9]);
    dag.set_finality_floor(Some(a3));
    assert_eq!(dag.selected_tip(), Some(a9), "setup: the head is a9");
    let delay = crate::params::FINALITY_SEAT_ACTIVATION_DELAY;
    assert!(delay > 6, "setup: the final block lies inside the seat-activation distance");
    let depth = crate::params::RECORD_FOLD_DEPTH_DEFAULT;
    let old_root = below(&dag, a9, depth);
    let (root, by_finality) = dag.fold_root_by_finality(&a9, Some(a3), delay, depth).expect("a root");
    assert_eq!((root, by_finality), (a3, true), "⛔ the fold root is not the block this node has seen final");

    // a heavier branch from a4 takes the head (it keeps the final block a3 on its selected chain)
    let mut b = vec![a[4]];
    for i in 5..=10u64 {
        let p = *b.last().unwrap();
        b.push(dag.add_block(blk_w(vec![p], 200 + i, if i == 5 { 100_000 } else { 100 })).unwrap());
    }
    let b10 = *b.last().unwrap();
    assert_eq!(dag.selected_tip(), Some(b10), "setup: the heavier branch took the head");
    assert!(
        !dag.is_selected_chain_ancestor(&old_root, &b10),
        "CALIBRATION: the old root (four levels below the tip) must leave the new chain — else the pin proves nothing"
    );
    assert!(
        dag.is_selected_chain_ancestor(&root, &b10),
        "⛔ FOLD REORG: the root the rule folded to left the selected chain — the fold would rewind below finality"
    );

    // nothing final: the depth rule's root, exactly as before the rule (a chain with no bonded voters folds as it did)
    let (r, f) = dag.fold_root_by_finality(&a9, None, delay, depth).expect("a root");
    assert_eq!((r, f), (old_root, false), "⛔ with nothing final the root is not the depth rule's");
    // finality further behind than the seat-activation delay: the depth rule holds the root (never waits on a committee)
    let (r, f) = dag.fold_root_by_finality(&a9, Some(a[1]), 3, depth).expect("a root");
    assert_eq!((r, f), (old_root, false), "⛔ a final block past the delay held the root back: a halt");
    // finality shallower than the depth rule: the root is the final block itself (money settles sooner, safely)
    let (r, f) = dag.fold_root_by_finality(&a9, Some(a[7]), delay, depth).expect("a root");
    assert_eq!((r, f), (a[7], true), "⛔ a final block above the depth rule's root was not taken as the root");
}

/// ⛔⛔ A-F85 (lane speed5, 2026-11-16) — WHILE FINALITY IS LIVE BUT LATE, THE DEPTH RULE NEVER FOLDS MORE NON-FINAL STEPS THAN THE
/// FOLD CAN UNDO. MEASURED on the verifier's rig (main 7d357574): the final block more than the seat-activation delay down, the
/// depth rule folded to two levels under the tip, a late branch rewound 70 non-final steps past the 64-step journal and the node
/// stopped folding for good. A chain a1..a60 (one level a block), final at a1: the root stands at most `NON_FINAL_FOLD_REACH`
/// levels above a1; the same chain with its stamps forty seconds apart (the final block more than `FINALITY_STALL_DAA_WINDOWS`
/// DAA windows old) is read as stalled finality and folds by the depth rule, so a dead committee never holds money.
#[test]
fn a_af85_the_depth_rule_never_folds_past_the_undo_reach_above_a_live_final_block() {
    let reach = crate::dag::NON_FINAL_FOLD_REACH;
    let delay = crate::params::FINALITY_SEAT_ACTIVATION_DELAY;
    let depth = crate::dag::FOLD_DEPTH_MIN;
    let chain = |gap_ms: u64| {
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 1)).unwrap();
        let mut a = vec![g];
        for i in 1..=60u64 {
            let p = *a.last().unwrap();
            a.push(dag.add_block(blk(vec![p], 1_000 + i * gap_ms)).unwrap());
        }
        (dag, a)
    };
    let blue = |dag: &Dag, id: &BlockId| dag.get(id).map_or(0, |n| n.blue_score);
    // live finality, one second a block: the cap holds the root
    let (dag, a) = chain(1_000);
    let (tip, fin) = (a[60], a[1]);
    assert!(blue(&dag, &tip) > blue(&dag, &fin) + delay + reach + depth, "setup: finality lags past the delay AND the reach");
    let (root, by_finality) = dag.fold_root_by_finality(&tip, Some(fin), delay, depth).expect("a root");
    assert!(!by_finality, "setup: the final block is past the delay, so the depth rule sets the root");
    assert!(
        blue(&dag, &root) <= blue(&dag, &fin) + reach,
        "⛔ A-F85: the depth rule folded {} non-final levels above the final block, past the fold's undo reach of {reach}",
        blue(&dag, &root) - blue(&dag, &fin)
    );
    assert!(dag.is_selected_chain_ancestor(&fin, &root), "the capped root stays on the final block's chain");
    assert_eq!(blue(&dag, &root), blue(&dag, &fin) + reach, "the root stands exactly at the reach (no further back than needed)");
    // CALIBRATION: with nothing final the depth rule alone sets the root, two levels under the tip (unchanged)
    let (r, _) = dag.fold_root_by_finality(&tip, None, delay, depth).expect("a root");
    assert_eq!(blue(&dag, &r), blue(&dag, &tip) - depth, "CALIBRATION: no final block, the depth rule as before");
    // stalled finality: the final block's stamp is more than the stall bound under the tip's, so the depth rule folds alone
    let (dag, a) = chain(40_000);
    let (tip, fin) = (a[60], a[1]);
    let window = crate::params::ChainParams::default().daa_sample_len * crate::dag::MESH_TARGET_SPACING_MS;
    assert!(59 * 40_000 > crate::dag::FINALITY_STALL_DAA_WINDOWS * window, "setup: the final block is older than the stall bound");
    let (r, f) = dag.fold_root_by_finality(&tip, Some(fin), delay, depth).expect("a root");
    assert_eq!((blue(&dag, &r), f), (blue(&dag, &tip) - depth, false), "⛔ a stalled committee held settlement (a halt)");
}

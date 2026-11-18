// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ DB-396 — A BAND THAT CANNOT KEEP UP MUST MAKE THE FOLD WAIT, NEVER DROP A STEP (T0 liveness of the money path;
//! `docs/DB-396-BAND-LAG-DROP-WEDGES-THE-FOLD.md`). MEASURED on the live pair 2026-10-05: the band fell 64 steps behind,
//! the door DROPPED a step and went stale, the fold-point set went blind, and the record fold stopped forever at the first
//! block carrying a spend or a credit (both nodes `fold_wedged`, ~1,300 blocks unfolded). In process the drop needs no
//! slow prover: `Node::produce` never proves a band step, so a pair that lays more than the lag cap of non-empty steps
//! (every block carries its SAT reward's own nullifier) before anyone proves one reaches the same state.

use crate::hash::Hash32;
use crate::node::Node;

/// Lay `n` blocks on `a`, each grafted and folded on `b`, with nobody proving a band step. Every block carries its SAT
/// reward, so every fold step is non-empty and awaits a band carrier.
fn lay_unproven_steps(a: &mut Node, b: &mut Node, n: u64, from_ts: u64) -> u64 {
    let mut ts = from_ts;
    for i in 0..n {
        ts = from_ts + i * 1_000;
        let blk = a.produce(ts, Hash32::hash(&ts.to_le_bytes()), Hash32::hash(b"db396-mc")).expect("A lays a block");
        let _ = a.fold_canonical_records();
        let _ = b.ingest_block(blk, ts + 500);
        let _ = b.fold_canonical_records();
    }
    ts
}

/// ⛔⛔⛔ DB-396 pin 1 — A BAND THAT CANNOT KEEP UP MAKES THE FOLD WAIT AND NEVER DROPS A STEP; WHEN IT CATCHES UP, A SPEND
/// MADE DURING THE BACKLOG SETTLES ON THE PEER. A note is paid and folded, then A lays the lag cap + 8 reward-carrying
/// blocks with no band step proven, then the payee spends.
/// - Neither node may have dropped a step or gone stale, and each must hold its fold back (blocks unfolded, the band's lag
///   within the cap).
/// - Then the band is released: A proves every awaiting step (the bound double: microseconds a step) and relays each to B,
///   as the mesh's band worker does, and both fold. The spend made during the backlog must settle on the peer.
/// RED on the pre-fix tree: the 65th step drops, the door goes stale, and the spend's block can never be decided at the fold.
#[test]
fn db396_a_band_that_cannot_keep_up_makes_the_fold_wait_and_never_drops_a_step() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    a.arm_band_double_for_test();
    b.arm_band_double_for_test();
    let cap = Node::SPINE_RING_LEN as u64;
    // A paid note, folded on both while the band still has room: the money the backlog must not strand.
    let (note, cm, payee, _) = crate::db395_pins::a_note_paid_to_a_payee(&mut a, &mut b, &[0x96; 32], [0x39; 32], 5_000);
    let (_, owner, _) = payee.open_asset(&note).expect("the payee opens the note it was paid");
    // THE BACKLOG: more non-empty steps than the door can hold, and nobody proves one.
    let last = lay_unproven_steps(&mut a, &mut b, cap + 8, 10_000);
    for (who, n) in [("producer", &a), ("peer", &b)] {
        eprintln!(
            "[db396] {who}: band lag {} dropped {} stale {} unfolded {}",
            n.band_lag(),
            n.band_dropped_for_lag(),
            n.band_door_is_stale(),
            n.unfolded_blocks_len()
        );
        assert_eq!(n.band_dropped_for_lag(), 0, "⛔⛔⛔ DB-396: the {who}'s band door DROPPED a fold step for lag");
        assert!(!n.band_door_is_stale(), "⛔⛔⛔ DB-396: the {who}'s band door went STALE — only a certified re-adopt moves it");
        assert!(n.band_lag() <= Node::SPINE_RING_LEN, "the {who}'s door holds at most the lag cap");
        assert!(n.unfolded_blocks_len() > 0, "⛔ DB-396: the {who}'s fold ran past the band instead of waiting for it");
    }
    // A SPEND DURING THE BACKLOG.
    let nf = crate::db395_pins::spend_and_relay(&mut a, &mut b, &cm, &crate::db395_pins::a_spend_under(owner, 0x396), last + 2_000)
        .expect("the payee pools a spend of its folded note");
    // THE RELEASE: the band catches up as the mesh's worker and relay would carry it, and both folds resume.
    let mut relayed = 0usize;
    for _round in 0..8 {
        let steps = a.band_catch_up_for_test();
        if steps.is_empty() && a.unfolded_blocks_len() == 0 && b.unfolded_blocks_len() == 0 {
            break;
        }
        for t in steps {
            relayed += 1;
            let _ = b.band_offer(t, false);
        }
        let _ = a.fold_canonical_records();
        let _ = b.fold_canonical_records();
    }
    eprintln!(
        "[db396] after release: relayed {relayed} step(s); unfolded A {} B {}; band lag A {} B {}",
        a.unfolded_blocks_len(),
        b.unfolded_blocks_len(),
        a.band_lag(),
        b.band_lag()
    );
    assert!(relayed as u64 >= cap, "CALIBRATION: the release proved and relayed the backlog ({relayed} step(s))");
    assert!(
        b.is_nullifier_spent(&Hash32(nf)),
        "⛔⛔⛔ DB-396: a spend made while the band lagged never settled on the peer once the band caught up — the fold is wedged"
    );
    assert_eq!(b.unfolded_blocks_len(), 0, "⛔ DB-396: the peer's fold did not catch up with the band");
}

/// ⛔⛔ DB-396 C3 — A REORG WHILE THE DOOR IS FULL RE-FOLDS, AND BOTH FOLDS RESUME. A and B grow SEPARATE chains past the lag
/// cap with no band step proven (each door full, each fold waiting), then exchange them: one chain wins on both, and the
/// node that folded the loser rewinds (`BandDoor::rewind_to` frees the rewound ordinals) and re-folds the winner into that
/// room. Merge blocks bring the losing branch into the tip's past. Neither door may drop or go stale, and once the band is
/// released both fold every block at the same ordinal.
#[test]
fn db396_c3_a_reorg_while_the_door_is_full_re_folds_and_both_folds_resume() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    a.arm_band_double_for_test();
    b.arm_band_double_for_test();
    let cap = Node::SPINE_RING_LEN as u64;
    let (mut a_chain, mut b_chain) = (Vec::new(), Vec::new());
    for k in 0..cap + 4 {
        let ts = 10_000 + k * 1_000;
        a_chain.push(a.produce(ts, Hash32::hash(format!("c3-a{k}").as_bytes()), Hash32::hash(b"mc")).expect("A lays its own block"));
        b_chain.push(b.produce(ts + 7, Hash32::hash(format!("c3-b{k}").as_bytes()), Hash32::hash(b"mc")).expect("B lays its own block"));
    }
    for (who, n) in [("A", &a), ("B", &b)] {
        assert_eq!(n.band_dropped_for_lag(), 0, "⛔⛔⛔ DB-396: {who}'s door dropped a step on its own chain");
        assert!(n.unfolded_blocks_len() > 0, "CALIBRATION: {who}'s fold waits at the cap before the exchange");
    }
    // THE EXCHANGE: one chain wins; the loser's folder rewinds below its fold root and re-folds the winner.
    for (k, blk) in b_chain.iter().enumerate() {
        let _ = a.ingest_block(blk.clone(), 200_000 + k as u64);
    }
    for (k, blk) in a_chain.iter().enumerate() {
        let _ = b.ingest_block(blk.clone(), 200_000 + k as u64);
    }
    let _ = (a.fold_canonical_records(), b.fold_canonical_records());
    // merge blocks bring the losing branch into the tip's past
    let mut merges = Vec::new();
    for k in 0..4u64 {
        let ts = 300_000 + k * 1_000;
        let m = a.produce(ts, Hash32::hash(format!("c3-merge{k}").as_bytes()), Hash32::hash(b"mc")).expect("A lays a merge block");
        let _ = b.ingest_block(m.clone(), ts + 500);
        merges.push(m);
    }
    for (who, n) in [("A", &a), ("B", &b)] {
        eprintln!(
            "[db396-c3] {who} after the exchange: lag {} dropped {} stale {} unfolded {}",
            n.band_lag(),
            n.band_dropped_for_lag(),
            n.band_door_is_stale(),
            n.unfolded_blocks_len()
        );
        assert_eq!(n.band_dropped_for_lag(), 0, "⛔⛔⛔ DB-396 C3: {who}'s door dropped a step across the reorg");
        assert!(!n.band_door_is_stale(), "⛔⛔⛔ DB-396 C3: {who}'s door went STALE across the reorg");
    }
    // THE RELEASE: each node proves its own awaiting steps (the same chain now) and folds.
    for _round in 0..12 {
        let moved = a.band_catch_up_for_test().len() + b.band_catch_up_for_test().len();
        let _ = (a.fold_canonical_records(), b.fold_canonical_records());
        if moved == 0 && a.unfolded_blocks_len() == 0 && b.unfolded_blocks_len() == 0 {
            break;
        }
    }
    let all: Vec<crate::block::Block> = a_chain.iter().chain(b_chain.iter()).chain(merges.iter()).cloned().collect();
    // DIAGNOSTIC (2026-10-27): WHICH blocks differ and HOW — side, blue score, A's ordinal, B's ordinal; the first 12.
    let mut shown = 0usize;
    for (i, blk) in all.iter().enumerate() {
        let rid = Node::da_record_id_for_block(&blk.id(), 0);
        let (oa, ob) = (a.da_record_ordinal(rid), b.da_record_ordinal(rid));
        if oa != ob && shown < 12 {
            shown += 1;
            let side = if i < a_chain.len() { "A-chain" } else if i < a_chain.len() + b_chain.len() { "B-chain" } else { "merge" };
            let bs = a.dag().get(&blk.id()).map(|n| n.blue_score).unwrap_or(0);
            eprintln!("[db396-c3-diag] {side} #{i} blue {bs}: A ordinal {oa:?} · B ordinal {ob:?}");
        }
    }
    eprintln!(
        "[db396-c3-diag] A: unfolded {} lag {} · B: unfolded {} lag {}",
        a.unfolded_blocks_len(), a.band_lag(), b.unfolded_blocks_len(), b.band_lag()
    );
    let differ = all
        .iter()
        .filter(|blk| {
            let rid = Node::da_record_id_for_block(&blk.id(), 0);
            a.da_record_ordinal(rid) != b.da_record_ordinal(rid)
        })
        .count();
    assert_eq!(differ, 0, "⛔ DB-396 C3: the two nodes folded {differ} block(s) at different ordinals after the release");
    assert_eq!(a.unfolded_blocks_len(), 0, "⛔ DB-396 C3: A's fold did not catch up with the band after the reorg");
    assert_eq!(b.unfolded_blocks_len(), 0, "⛔ DB-396 C3: B's fold did not catch up with the band after the reorg");
}

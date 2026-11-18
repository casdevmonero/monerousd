// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::db353_band_door_node_pins` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::{genesis_block, grind_tx};
use super::*;
use crate::nf_sparse::{BandReceipt, RefSparseNf};

/// A produced block with NO pooled tx still carries the constant WIRE lane (256 pure decoys — MEASURED here, the first
/// draft of this pin assumed an empty lane and was refuted by the run). ⛔ DB-367: none of those decoys is justified —
/// no transition states them and no object owns them; they are the producer's fill, which nobody can check — so the
/// block's fold step ADMITS NOTHING and applies at once on both nodes: the band does not move, and nothing waits for a
/// carrier. (Before DB-367 this pin asserted the 256 fill decoys were admitted as a band step; that admission is the
/// hole by which a fill tag naming a victim's nullifier retired it.) A step with a real admitted set is the next pin's.
#[test]
fn db353_db367_a_block_with_no_pooled_tx_carries_the_constant_lane_and_its_step_admits_nothing_on_both_nodes() {
    let mut a = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let mut b = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    // The premise is a block whose lane holds NO justified tag. Since SATOSHI increment 1 a node with a provisioned reward
    // recipient lays a reward whose own nullifier is a justified tag in EVERY block; these parties run without one — a
    // real configuration — so the subject (unjustified fill admits nothing) is measured alone.
    a.set_reward_recipient(None);
    b.set_reward_recipient(None);
    let empty = a.band_root();
    assert_eq!(b.band_root(), empty, "CALIBRATION: two fresh nodes hold the empty band");
    assert_eq!((a.band_pointer(), b.band_pointer()), (None, None), "CALIBRATION: nothing awaits before any block folds");
    let blk = a.produce(5_000, Hash32::hash(b"band-fr1"), Hash32::hash(b"band-mc1")).expect("a block with no tx");
    assert_eq!(
        blk.nullifier_proof.padded_tags.len(),
        crate::cover::BLOCK_FIXED_NULLIFIER_COUNT,
        "CALIBRATION: no pooled tx, and still the constant wire lane (pure decoys)"
    );
    assert!(matches!(b.ingest_block(blk, 9_000), crate::relay::RelayOutcome::Added(_)), "B grafts the block");
    let folded_a = a.fold_canonical_records();
    let folded_b = b.fold_canonical_records();
    eprintln!("[band-door-pin] folded A {folded_a} B {folded_b}; pointers A {:?} B {:?}", a.band_pointer(), b.band_pointer());
    assert_eq!(
        (a.band_pointer(), b.band_pointer()),
        (None, None),
        "⛔ DB-367: a step waits on a block whose lane holds only unjustified fill — the fill was admitted"
    );
    assert_eq!((a.band_root(), b.band_root()), (empty, empty), "the fill moved neither band");
    assert_eq!((a.band_door.lag(), b.band_door.lag()), (0, 0));
}

/// A REAL nullifier lane, two parties: A pools a spend and lays the block, B ingests it; on BOTH the fold step awaits a
/// carrier with the lane's JUSTIFIED tags as its admitted set (DB-367: the spend's stated tags, never the fill; no
/// losers). Two holders serve, a producer proves ONE
/// transition, and `band_receive` applies it at the pointer on B first (the PEER is what is asserted) and then on A: both
/// bands are the full view's root over exactly the step's admitted tags. RED-first: a copy naming another block is refused
/// before the honest copy; a replay is refused by the set after it.
/// PROOF-BINDS-STATE-REVIEWED: each door verifies against ITS OWN fold-point root and the post root its own band folds
/// to; nothing carried names a root the door trusts.
#[test]
fn db353_a_spend_block_awaits_its_carried_transition_and_the_peer_applies_it_from_header_values() {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block::SpendValidityWitness;
    // DB-223 Q7: the spent note is FUNDED on chain, so the parties run the testnet identity (whose open-mint allowance
    // admits the funding credit, DB-354).
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    // The subject is the SPEND block's step. Since SATOSHI increment 1 every block a reward-carrying producer lays (the
    // funding block too) holds a justified reward tag, so its step awaits a carrier first; these parties run without a
    // reward recipient — a real configuration — so the spend's step is the one awaiting.
    a.set_reward_recipient(None);
    b.set_reward_recipient(None);
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let w = SpendValidityWitness {
        value_in: 1_000_000_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x353, 0x0f, 2, 2])),
        value_out: (1_000_000_000) - 100000,
        fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        out0_value: (999_999_000) - 100000,
        out0_opening: lanes_of(&[1, 1, 1, 1]),
        out1_value: 1_000,
        out1_opening: lanes_of(&[7, 1, 1, 1]),
    };
    let (blob, cms, nf, lc, _d) =
        crate::note_transition::prove_wallet_spend(&w).expect("an honest validity proof");
    let mut output_notes = Vec::with_capacity(2 * crate::cover::PQ_NOTE_BYTES);
    for cm in cms {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..32].copy_from_slice(&b32(cm));
        output_notes.extend_from_slice(&n);
    }
    let nfs = crate::note_transition::test_spend_tag_list(nf, &w, "db353-band");
    let mut tx = grind_tx(&blob, blob.len() as u32, nfs, a.mempool().required_stamp_bits());
    tx.output_notes = output_notes;
    tx.note_clues = crate::note_transition::fixture_note_clues(&cms);
    tx.membership_leaf_commit = b32(lc);
    // DB-223 Q7: the spent note EXISTS — funded in a block both nodes fold — and the spend proves it (its member leg).
    let funded = crate::node::tests::fund_inputs_for_test(&mut a, &mut [&mut b], &[&w], 2_000);
    crate::node::tests::attach_member_leg_for_test(&a, &mut tx, &funded[0], &w, nf, &cms);
    a.ingest_tx_unverified(tx).expect("A pools the spend");
    let blk = a.produce(5_000, Hash32::hash(b"band-fr2"), Hash32::hash(b"band-mc2")).expect("A lays the block");
    let lane = blk.nullifier_proof.padded_tags.clone();
    let block_id = blk.id().0;
    assert_eq!(lane.len(), crate::cover::BLOCK_FIXED_NULLIFIER_COUNT, "CALIBRATION: a spend block carries the constant lane");
    let outcome = b.ingest_block(blk, 9_000);
    assert!(matches!(outcome, crate::relay::RelayOutcome::Added(_)), "B grafts the spend block: {outcome:?}");
    let _ = a.fold_canonical_records();
    let _ = b.fold_canonical_records();
    let step = b.band_pointer().expect("on the PEER, the spend block's fold step awaits its carrier");
    assert_eq!(a.band_pointer(), Some(step), "the producer waits at the same fold step");
    eprintln!("[band-door-pin] the spend block's step {step} awaits on both nodes");
    // ⛔ DB-367: the step admits the lane's JUSTIFIED tags — the spend's nullifier and claim tag, stated by the block's
    // note transition — never the producer's fill around them. The carrier is built over what the step admitted.
    let admitted_on = |n: &Node| {
        n.band_door
            .awaiting_steps()
            .into_iter()
            .find(|(o, _, _)| *o == step)
            .and_then(|(_, _, a)| a)
            .expect("the node noted the step's admitted set")
    };
    let admitted = admitted_on(&b);
    assert_eq!(admitted_on(&a), admitted, "both nodes admit the same set at the same step");
    assert!(admitted.contains(&b32(nf)), "CALIBRATION: the spend's own nullifier is admitted");
    // DIGITAL-CASH-PRIVACY-REVIEWED: three counts in a test — no tag, cm, amount, key or owner.
    eprintln!(
        "[band-door-pin] admitted {} of a {}-tag lane; {} admitted tag(s) are not in the lane",
        admitted.len(),
        lane.len(),
        admitted.iter().filter(|t| !lane.contains(t)).count()
    );
    // §18 (2026-10-28): on a LEDGER block every lane cell is a published ledger cell the block PROVES — a spend head's
    // tags by its carrier, its 15 tail rows' tags by the tag ledger's chain over the carrier's 32-tag set (each decoy a
    // PRF of the spend's own witness secret, proven in-circuit by the spend-or-decoy carrier: no spender can plant a
    // victim's nullifier), and every cover row's tags by the seed (`slot_ledger` H2: a planted real-shaped tag in any
    // cover cell fails the row). There is no fill left to refuse, and the admitted count is the SAME CONSTANT on a quiet
    // and a busy block (the flags leak F2-red-found-20261027k: a 2-of-256 admitted set was a public function of the real
    // spend count). MEASURED before this re-statement (node-84.log): admitted 256 of 256, 0 outside the lane.
    // DIGITAL-CASH-PRIVACY-REVIEWED: three counts in a test — no tag, cm, amount, key or owner.
    assert!(
        admitted.len() == lane.len() && admitted.iter().all(|t| lane.contains(t)),
        "⛔ §18: a ledger block's step admits exactly its proven lane ({} of {} admitted; {} outside the lane)",
        admitted.len(),
        lane.len(),
        admitted.iter().filter(|t| !lane.contains(t)).count()
    );
    // two holders (even/odd shards) at the fold-point pre-state: the empty band, no earlier step touched it
    let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
    let shards = 1u32 << bits;
    let mut holders = vec![
        RefSparseNf::with_shards(bits, (0..shards).filter(|s| s % 2 == 0)),
        RefSparseNf::with_shards(bits, (0..shards).filter(|s| s % 2 == 1)),
    ];
    let (_touched, _ordered, by_shard) = crate::nf_sparse::admitted_order(&admitted);
    // A short admitted set is padded to the constant step width by FILLERS (applied and taken back, never spent), the
    // shape `BandCursor::serve_and_absorb` serves from index 0 — each holder serves the fillers that land in its shards.
    let need = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER - admitted.len();
    let mut fill_by_shard: std::collections::BTreeMap<u32, Vec<u64>> = std::collections::BTreeMap::new();
    for i in 0..need as u64 {
        fill_by_shard
            .entry(crate::nf_sparse::key_shard(&crate::nf_sparse::band_filler_key(i), bits))
            .or_default()
            .push(i);
    }
    let shards_touched: std::collections::BTreeSet<u32> =
        by_shard.keys().chain(fill_by_shard.keys()).copied().collect();
    let (mut serves, mut fillers) = (Vec::new(), Vec::new());
    for s in shards_touched {
        let ts: &[[u8; 32]] = by_shard.get(&s).map_or(&[], Vec::as_slice);
        let fs: &[u64] = fill_by_shard.get(&s).map_or(&[], Vec::as_slice);
        let (lows, entry, fl) =
            holders[s as usize % 2].serve_fold_copaths(ts, fs).expect("the holder serves its shard");
        if !ts.is_empty() {
            serves.push((s, entry, ts.iter().copied().zip(lows).collect()));
        }
        for (i, (low, after)) in fs.iter().zip(fl) {
            fillers.push((*i, s, low, after));
        }
    }
    assert_eq!(fillers.len(), need, "CALIBRATION: every filler the step's width needs is served");
    let band_pre = b.band_door.band().to_vec();
    assert_eq!(band_pre, a.band_door.band().to_vec(), "CALIBRATION: both nodes hold one pre band");
    let t0 = std::time::Instant::now();
    let t = crate::nf_sparse::build_band_transition(block_id, &band_pre, &serves, &fillers, b.band_door.chain_k())
        .expect("the producer lays the transition");
    eprintln!(
        "[band-door-pin] prove {} ms, {} B",
        t0.elapsed().as_millis(),
        t.slices.iter().map(|(_, _, s)| s.len()).sum::<usize>()
    );
    let mut oracle = RefSparseNf::new();
    for tg in &admitted {
        let cp = oracle.copath(tg);
        oracle.apply_spend(tg, &cp);
    }
    // the PEER first — RED-first: a copy naming another block is refused, the band stands
    let mut wrong = t.clone();
    wrong.for_block = [9u8; 32];
    // H3 (6c98bf3): a structurally sound copy for a block this door has not noted is PARKED (early gossip, bounded by
    // the lag cap, re-offered when its block is noted) — never verified, never applied. The property: it moves nothing.
    let receipt = b.band_receive(wrong);
    assert!(
        matches!(receipt, BandReceipt::Held | BandReceipt::Refused(_)),
        "⛔ a copy naming another block must be parked or refused, never accepted — the door answered {receipt:?}"
    );
    assert_eq!(b.band_pointer(), Some(step), "B still awaits");
    assert_ne!(b.band_root(), oracle.root(), "CALIBRATION: B's band has not moved");
    assert_eq!(b.band_receive(t.clone()), BandReceipt::Verified);
    assert_eq!(b.band_pointer(), None, "B applied it at the pointer");
    assert_eq!(b.band_root(), oracle.root(), "the PEER's band is the full view over the step's admitted tags");
    assert_eq!(b.band_root_at(step), Some(oracle.root()), "the peer's ring records the step's root");
    assert!(matches!(b.band_receive(t.clone()), BandReceipt::Refused(_)), "REPLAY on the peer: refused by the set");
    // the producer applies the same carried object and lands on the peer's band
    assert_eq!(a.band_receive(t), BandReceipt::Verified);
    assert_eq!((a.band_pointer(), a.band_root()), (None, b.band_root()), "A holds what B holds");
}

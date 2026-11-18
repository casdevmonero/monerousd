// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::da_sparse_copath_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::{canon_nf_for_test, genesis_block, grind_tx};
use super::Node;
use crate::hash::Hash32;

/// ⭐⭐⭐ THE ORDINAL MUST BE CONSENSUS-DERIVED, NOT WRITE-ORDER.
///
/// TEST-ARCHITECTURE-REVIEWED: the control is ARRIVAL ORDER — one verifier receives the blocks forwards,
/// the other backwards. Earlier versions of this test fed both nodes the same order, so both assigned the
/// same write-order counter and agreed trivially; each passed unchanged with the defect restored, which
/// is the vacuous shape the standard forbids. Different arrival order is the only control that can expose
/// a per-node counter, and it is exactly what a real mesh produces.
///
/// Measured live on two peered nodes before this: NOT ONE ordinal named the same block on both — 7 of 7
/// probes diverged, including ordinal 100 near genesis. An account bucket records a note's ORDINAL, so
/// "ordinal X" pointed at a different block on the recipient's node and the payment was delivered but
/// invisible. `dag.rs` already names the cause in another comment: a RECEIVE-order counter is
/// "node-divergent", while `canonical_order` (blue_work, tie-broken by content hash) is deterministic and
/// node-independent. Bitcoin and Kaspa cannot have this defect because their record IS the block.
#[test]
fn two_nodes_receiving_the_same_blocks_in_different_order_agree_on_every_ordinal() {
    let mut producer = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let mut blocks = Vec::new();
    for i in 0..9u32 {
        let need = producer.mempool().required_stamp_bits();
        let tx = grind_tx(
            format!("ord-tx-{i}").as_bytes(),
            1000,
            vec![canon_nf_for_test(format!("ord-nf-{i}").as_bytes())],
            need,
        );
        producer.ingest_tx_unverified(tx).expect("pool takes it");
        blocks.push(
            producer
                .produce(5_000 + i as u64, Hash32::hash(b"f"), Hash32::hash(b"r"))
                .expect("mined"),
        );
    }

    let mut fwd = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    for b in &blocks {
        fwd.ingest_block(b.clone(), 9_000);
    }
    let mut rev = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    for b in blocks.iter().rev() {
        rev.ingest_block(b.clone(), 9_000);
    }

    assert!(
        fwd.served_seq() > 0 && rev.served_seq() > 0,
        "both nodes must have recorded something"
    );

    let mut diverged = Vec::new();
    for ord in 0..fwd.served_seq().min(rev.served_seq()) {
        let a = fwd.da_addr_at_ordinal(ord);
        let b = rev.da_addr_at_ordinal(ord);
        if a != b {
            diverged.push(ord);
        }
    }
    assert!(
        diverged.is_empty(),
        "arrival ORDER changed which block each ordinal names — diverged at {:?} of {} ordinals. A wallet's \
         account bucket records a note's ORDINAL, so on the recipient's node that ordinal addresses a \
         DIFFERENT block: the payment settles on chain and stays invisible to its owner. The ordinal must \
         come from consensus order (`Dag::canonical_order`, deterministic and node-independent), never \
         from the order this node happened to write records.",
        diverged, fwd.served_seq().min(rev.served_seq())
    );
}

/// ⛔ THE ADOPT-BOUNDARY HALF OF THE ISLAND CLASS: after a joiner ADOPTS a certified state, a LATE
/// cascade of a block at or below the adopted score must NOT re-fold (it is already inside the
/// inherited accumulator — re-folding was the boot-race double-count), while a block ABOVE the
/// boundary folds normally on BOTH parties so producer and adopter converge.
#[test]
fn an_adopting_peer_gates_pre_boundary_folds_and_converges_with_the_producer_above_it() {
    let mut a = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let mut b = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    // A produces two blocks; B ingests only the FIRST (the second will arrive late, post-adopt).
    let mut blocks = Vec::new();
    for i in 0..2u32 {
        let need = a.mempool().required_stamp_bits();
        let tx = grind_tx(
            format!("adopt-gate-{i}").as_bytes(),
            1000,
            vec![canon_nf_for_test(format!("adopt-gate-nf-{i}").as_bytes())],
            need,
        );
        let _ = a.ingest_tx_unverified(tx);
        blocks.push(a.produce(5_000 + i as u64, Hash32::hash(b"f"), Hash32::hash(b"r")).expect("A produces"));
    }
    let _ = b.ingest_block(blocks[0].clone(), 9_000);
    // D-49b: the adopter takes A's certified state through the REAL door — `instant_sync` — which
    // places A's blocks in B's DAG with the sum that covers them (a direct field assignment was the
    // old shape here, and it modelled a state adoption no production path performs: a sum without
    // the DAG behind it). Block 1 then arriving by gossip is a `Duplicate`, never re-applied.
    let a_tip = a.selected_tip().unwrap();
    let a_bs = a.dag().get(&a_tip).unwrap().blue_score;
    let frontier = crate::sync::FrontierSnapshot {
        root: *a.note_frontier_root().as_bytes(),
        height: a.note_frontier_count(),
        peaks_hex: a.spend_frontier_peaks_hex(), // the serve's REAL spine (DB-376)
    };
    let bundle = a.build_sync_bundle(vec![1u8; 4096], frontier).expect("A serves a bundle");
    b.set_decider_verifier(Box::new(super::tests::AcceptDecider));
    assert!(
        matches!(b.instant_sync(bundle), crate::sync::AdoptOutcome::Adopted(_)),
        "B adopts A's certified state"
    );
    let o = b.ingest_block(blocks[1].clone(), 9_000);
    assert!(
        matches!(o, crate::relay::RelayOutcome::Duplicate(_)),
        "a block inside the adopted past is already in the DAG — never re-applied: {o:?}"
    );
    assert_eq!(
        a.letter_acc(),
        b.letter_acc(),
        "a block inside the adopted past must not double-fold on the adopter"
    );
    // A block ABOVE the boundary folds on BOTH — still converged.
    let need = a.mempool().required_stamp_bits();
    let tx = grind_tx(b"adopt-gate-above", 1000, vec![canon_nf_for_test(b"adopt-gate-nf-above")], need);
    let _ = a.ingest_tx_unverified(tx);
    let above = a.produce(6_000, Hash32::hash(b"f"), Hash32::hash(b"r")).expect("A produces above");
    let _ = b.ingest_block(above, 9_500);
    assert_eq!(a.letter_acc(), b.letter_acc(), "post-boundary blocks fold on both — still ONE accumulator");
}

/// ⛔ THE ISLAND CLASS, PINNED WITH TWO PRODUCERS: each node produces its own block and ingests the
/// other's — so each accepts the two blocks in the OPPOSITE order. Under the replaced hash-chain fold
/// this diverged the mesh permanently (MEASURED live 2026-08-23, minutes after a fresh boot: origin acc
/// 8ca44670… vs joiner 1daeedbd… over the same blocks). The commutative-sum fold must land BOTH nodes on
/// ONE accumulator.
#[test]
fn two_producers_cross_ingesting_in_opposite_orders_converge_on_one_letter_acc() {
    let mut a = Node::new(genesis_block()).unwrap();
    let mut b = Node::new(genesis_block()).unwrap();
    for (tag, node) in [("a", &mut a), ("b", &mut b)] {
        let need = node.mempool().required_stamp_bits();
        let tx = grind_tx(
            format!("acc-order-{tag}").as_bytes(),
            1000,
            vec![canon_nf_for_test(format!("acc-order-nf-{tag}").as_bytes())],
            need,
        );
        let _ = node.ingest_tx_unverified(tx);
    }
    let blk_a = a.produce(5_000, Hash32::hash(b"f"), Hash32::hash(b"r")).expect("A produces");
    let blk_b = b.produce(5_000, Hash32::hash(b"f"), Hash32::hash(b"r")).expect("B produces");
    // A accepted (A, then B); B accepted (B, then A) — the opposite order the live pair hit.
    let oa = a.ingest_block(blk_b.clone(), 9_000);
    let ob = b.ingest_block(blk_a.clone(), 9_000);
    assert!(matches!(oa, crate::relay::RelayOutcome::Added(_)), "A ingests B's block: {oa:?}");
    assert!(matches!(ob, crate::relay::RelayOutcome::Added(_)), "B ingests A's block: {ob:?}");
    assert_eq!(
        a.letter_acc(),
        b.letter_acc(),
        "opposite accept orders MUST converge on one letter accumulator (the island fix)"
    );
    assert_ne!(a.letter_acc(), crate::letter::letter_acc_genesis(), "both folded real sets");
}

/// ⭐ THE LETTER STREAM IS TWO-PARTY BY CONSTRUCTION: node A anchors a REAL sealed letter's commitment in
/// a block it produces; node B INGESTS that block and folds the identical letter accumulator — the exact
/// agreement a recipient's history restore depends on. A third node handed a TAMPERED letter set refuses
/// the block outright (header binding) and its accumulator stays untouched — no forged mail anchor can
/// enter, and no relay can strip one without changing the block id.
#[test]
fn a_letter_anchored_by_the_producer_folds_identically_on_the_ingesting_peer_and_a_tampered_set_is_refused(
) {
    let mut a = Node::new(genesis_block()).unwrap();
    let mut b = Node::new(genesis_block()).unwrap();
    let seed_acc = crate::letter::letter_acc_genesis();
    assert_eq!(
        a.letter_acc(),
        seed_acc,
        "fresh nodes start at the letter genesis seed"
    );

    // A REAL sealed letter reaches A's relay (gossip/send path) and awaits a block.
    let blob = b"opaque-sealed-letter-bytes-for-the-carrier-test".to_vec();
    let cm = crate::letter::letter_cm(&blob);
    assert!(
        crate::rpc_http::letter_relay_admit(blob.clone()),
        "a new blob must admit"
    );

    // A produces: the block must carry the FULL constant shape with the real commitment in front.
    let need = a.mempool().required_stamp_bits();
    let tx = grind_tx(
        b"letter-carrier-tx",
        1000,
        vec![canon_nf_for_test(b"letter-carrier-nf")],
        need,
    );
    let _ = a.ingest_tx_unverified(tx);
    let blk = a
        .produce(5_000, Hash32::hash(b"f"), Hash32::hash(b"r"))
        .expect("A produces");
    assert_eq!(
        blk.letter_set.len(),
        crate::letter::LETTER_CMS_PER_BLOCK * 32,
        "a produced block wears the constant cover-padded letter shape"
    );
    assert_eq!(
        &blk.letter_set[..32],
        &cm[..],
        "the real letter's commitment is anchored in slot 0"
    );
    assert_ne!(
        a.letter_acc(),
        seed_acc,
        "the producer folded its own carried set"
    );

    // B ingests the SAME block — the two accumulators must agree (the cross-node property).
    let outcome = b.ingest_block(blk.clone(), 9_000);
    assert!(
        matches!(outcome, crate::relay::RelayOutcome::Added(_)),
        "B must accept A's block: {outcome:?}"
    );
    assert_eq!(
        a.letter_acc(),
        b.letter_acc(),
        "producer and ingester fold ONE letter accumulator"
    );

    // The anchored blob remains fetchable by its on-chain commitment (the backfill read), and it is
    // SELF-VERIFYING: the served bytes re-hash to the committed value.
    let served =
        crate::rpc_http::letter_blob_of(&cm).expect("the anchored blob serves by commitment");
    assert_eq!(
        crate::letter::letter_cm(&served),
        cm,
        "served bytes re-hash to the block-committed value"
    );

    // ⭐ MAIL PERSISTS IN THE LEDGER ROW, NOT THE HOT RING: A's graft filed the blob into the block's
    // record row, so a REPLICATION PAGE (the same codec every backfill uses) carries it to a peer that
    // never saw the gossip, and that peer serves the identical bytes from ITS OWN row — the whole
    // history-restore property in one assertion chain.
    let rid = match a.record_addr_for_block(&blk.id()) {
        Some(r) => r,
        None => Node::da_record_id_for_block(&blk.id(), 0),
    };
    let a_column = a.da_letters_wire(rid);
    assert!(!a_column.is_empty(), "A filed the anchored blob into the block's ledger row at graft");
    let page = crate::protocol::encode_ledger_page(&[crate::protocol::LedgerRecord::assemble(
        rid,
        (
            match a.da_record_notes(rid) {
                Some(nb) => nb,
                None => Vec::new(),
            },
            a.da_load_account_targets(rid),
            a.da_tags_wire(rid),
            Vec::new(),
            a_column.clone(),
        ),
        a.da_cover_key(rid),
    )]);
    let mut cold = Node::new(genesis_block()).unwrap();
    let adopted = cold.apply_backfilled_notes(&crate::protocol::decode_ledger_page(&page));
    assert!(adopted >= 1, "the cold peer adopts the page");
    assert_eq!(
        cold.da_letters_wire(rid),
        a_column,
        "the cold peer serves the IDENTICAL letter bytes from its own row — mail is mesh-durable"
    );
    // And the recovered blob inside the column still re-hashes to the block-committed value.
    let recovered = cold.da_letters_wire(rid);
    let blob_len =
        u32::from_le_bytes([recovered[0], recovered[1], recovered[2], recovered[3]]) as usize;
    assert_eq!(
        crate::letter::letter_cm(&recovered[4..4 + blob_len]),
        cm,
        "the page-recovered blob re-hashes to the block-committed value (trustless at any age)"
    );

    // ADVERSARIAL: a relay hands a third node the same block with ONE flipped byte in the letter set —
    // refused outright, and the victim's accumulator never moves.
    let mut c = Node::new(genesis_block()).unwrap();
    let mut forged = blk.clone();
    forged.letter_set[5] ^= 0x01;
    let refused = c.ingest_block(forged, 9_000);
    assert!(
        matches!(
            refused,
            crate::relay::RelayOutcome::Invalid(
                crate::consensus::ConsensusError::LetterSetRootMismatch
            )
        ),
        "a tampered letter set must be refused: {refused:?}"
    );
    assert_eq!(
        c.letter_acc(),
        seed_acc,
        "a refused block must not move the accumulator"
    );
}

#[test]
fn two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal() {
    let mut a = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let mut b = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let (mut a_blocks, mut b_blocks) = (Vec::new(), Vec::new());

    // BOTH mine, alternating — the ordinary mesh shape.
    for i in 0..6u32 {
        for (tag, node, out) in [("a", &mut a, &mut a_blocks), ("b", &mut b, &mut b_blocks)] {
            let need = node.mempool().required_stamp_bits();
            let tx = grind_tx(
                format!("mine-{tag}-{i}").as_bytes(),
                1000,
                vec![canon_nf_for_test(format!("mine-nf-{tag}-{i}").as_bytes())],
                need,
            );
            let _ = node.ingest_tx_unverified(tx);
            if let Some(blk) =
                node.produce(5_000 + i as u64, Hash32::hash(b"f"), Hash32::hash(b"r"))
            {
                out.push(blk);
            }
        }
    }
    // ...then each ingests the other's blocks. Each node has now written its OWN blocks first and its
    // peer's second — a different interleaving on each side.
    for blk in &b_blocks {
        a.ingest_block(blk.clone(), 9_000);
    }
    for blk in &a_blocks {
        b.ingest_block(blk.clone(), 9_000);
    }

    assert!(
        a.served_seq() > 0 && b.served_seq() > 0,
        "both nodes must have recorded blocks"
    );

    // ⛔ COMPARE THE COORDINATE A WALLET ACTUALLY RECEIVES. The account bucket files a note's position,
    // and that is what the recipient's node must resolve to the same block. Comparing the LOCAL frontier
    // ordinal instead asks the wrong question: that index is per-node by design (a copath is verified
    // against the node's OWN root, so it never travels), and it will always differ.
    // ⛔ ASSERT THE PROPERTY A USER DEPENDS ON: the position filed in the account bucket must resolve to
    // the SAME BLOCK on both nodes. That is the coordinate a recipient's wallet is handed; if the two
    // nodes disagree, the payment settles on chain and stays invisible to its owner.
    //
    // An earlier version compared each node's LOCAL frontier ordinal, went green after I rewrote the
    // assertion, and then passed with the defect deliberately restored — a test weakened until the
    // failure disappeared. This one is written against the BLOCK a filed position names, which
    // renumbering cannot satisfy.
    let mut diverged = Vec::new();
    let mut first_shapes = String::new();
    for ord in 0..a.served_seq().min(b.served_seq()) {
        let Some(pos) = a.da_addr_at_ordinal(ord) else {
            continue;
        };
        let ra = a.da_note_copath_in_block(pos, 0).map(|(_, _, root)| root);
        let rb = b.da_note_copath_in_block(pos, 0).map(|(_, _, root)| root);
        if ra != rb {
            if first_shapes.is_empty() {
                // Say WHICH way they differ. Without this, "the nodes disagree" is compatible with a
                // missing record, a different block, or the same block stored differently — three
                // defects with three different fixes and one identical symptom.
                first_shapes = format!(
                    " FIRST DIVERGENCE ord={ord} addr={pos}: A shape={:?} B shape={:?}; \
                     A_ord_of_addr={:?} B_ord_of_addr={:?}; A_served_seq={} B_served_seq={}; \
                     A_dag={} B_dag={}",
                    a.da_record_shape(pos),
                    b.da_record_shape(pos),
                    a.da_record_ordinal(pos),
                    b.da_record_ordinal(pos),
                    a.served_seq(),
                    b.served_seq(),
                    a.dag_len(),
                    b.dag_len(),
                );
            }
            diverged.push(ord);
        }
    }
    assert!(
        diverged.is_empty(),
        "two mining nodes holding the SAME blocks disagree on what {} of {} ordinals name (first: {:?}). \
         A wallet's account bucket records a note's ORDINAL, so on the recipient's node that ordinal \
         addresses a DIFFERENT block — the payment settles and stays invisible to its owner. The ordinal \
         must be an index into consensus order (`Dag::canonical_order`, deterministic and \
         node-independent), never the order this node happened to write records.{}",
        diverged.len(), a.served_seq().min(b.served_seq()), diverged.first(), first_shapes
    );
}

/// ⭐ ITEM-14 PIN A (two-party): a parked orphan stranded behind an OUT-OF-BAND parent is
/// released by the parent's duplicate re-delivery — into the caller's re-inject lane, never
/// inline — and then grafts AND records through the full gate path.
///
/// cons: none — test-only code: two in-memory nodes, two blocks, persists nothing.
///
/// WHAT IT CATCHES: P produces g->a->b. Q hears b first (parks on a); a then enters Q's DAG
/// without a relay `receive` (the fold-carry/bundle graft shape), so `drain_from` never fires
/// and b is stranded. The only event that ever names a again is a duplicate delivery of a —
/// which, before the fix, returned `Duplicate` without flagging `waiting[a]`, so b stayed
/// parked FOREVER behind a present parent. RED was confirmed by running this with the
/// `strand_hint` assignment removed from the relay's Duplicate arm: nothing releases b, it
/// never enters Q's DAG, and the dag-contains assertion fails. GREEN with it.
#[test]
fn a_stranded_orphan_behind_an_out_of_band_parent_is_released_and_recorded() {
    let mut p = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let mut q = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let a_blk = p
        .produce(5_000, Hash32::hash(b"f"), Hash32::hash(b"r"))
        .expect("P produces a");
    let b_blk = p
        .produce(6_000, Hash32::hash(b"f"), Hash32::hash(b"r"))
        .expect("P produces b");
    assert!(matches!(
        q.ingest_block(b_blk.clone(), 9_000),
        crate::relay::RelayOutcome::Buffered { .. }
    ));
    // a enters Q's DAG OUT-OF-BAND — no relay receive, so no drain ever fires for it.
    q.relay.dag_mut().add_block(a_blk.clone()).unwrap();
    assert!(
        q.take_stranded_blocks().is_empty(),
        "no strand flagged yet — the release is event-driven, not a per-tick walk"
    );
    assert!(
        q.dag().get(&b_blk.id()).is_none(),
        "the strand is real before the echo: b is parked, not in the DAG"
    );
    // The duplicate echo of a is the only event that ever names the present parent again. The
    // relay's Duplicate arm flags the strand, and the strand consumer releases b back through
    // the SAME full-gate ingest as fresh gossip within this call (on the live runtime path the
    // release rides the preverify/FIFO lane instead — same gates, budgeted).
    assert!(matches!(
        q.ingest_block(a_blk.clone(), 9_000),
        crate::relay::RelayOutcome::Duplicate(_)
    ));
    assert!(
        q.dag().get(&b_blk.id()).is_some(),
        "the stranded child grafts through the full gate path after the duplicate echo — RED \
         without the relay Duplicate-arm strand flag: nothing ever releases it and it is not \
         in the DAG"
    );
    assert!(
        q.da_record_notes(Node::da_record_id_for_block(&b_blk.id(), 0))
            .is_some(),
        "...and leaves a ledger record on Q (block acceptance IS payment delivery)"
    );
    assert_eq!(q.relay_buffered_len(), 0, "nothing stays parked behind a present parent");
}

/// ⭐⭐⭐ ITEM-6 PIN (two-party): a graft cascade wider than the remaining rt-lock apply budget
/// releases only its PAGE; the remainder stays parked and the strand lane delivers every block
/// — grafted AND recorded — through the full gates on the following drains.
///
/// cons: none — test-only code: two in-memory nodes, four blocks, persists nothing.
///
/// WHAT IT CATCHES (and how RED was confirmed): before the cascade page, ONE `relay.receive`
/// released EVERY parked descendant inline whatever the remaining budget was — the 200 ms
/// budget in `apply_preverified_blocks` gated only BETWEEN ingest calls. MEASURED live:
/// `[tick-slow] drain held the rt lock 8368ms`, 232 occurrences in one boot. RED: run this
/// with the page neutralized (`None` as the budget argument on the budgeted graft — the exact
/// pre-fix unbounded shape): Z grafts INLINE in the same call and the "Z stays parked" assert
/// FAILS. GREEN as written (a budget instant already in the past ⇒ page = the one-release
/// progress minimum).
///
/// ROOT-LAYER: the relay's `drain_from` is where the cascade is PRODUCED, so the page lives
/// there; the strand lane is the release path that already existed for exactly this shape.
/// MUST-STAY-GREEN: `a_peer_block_cascading_behind_an_own_mined_block_is_recorded_and_served`
/// (an in-budget cascade still applies inline), `reverse_order_gossip_all_grafts`, the
/// recorded_case runtime-backend suite.
#[test]
fn item6_a_cascade_past_the_apply_page_reparks_and_the_strand_lane_releases_every_block() {
    let mut a = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let mut b = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    // A's own next block X, mined but NOT yet grafted (the off-lock mine interval).
    let (mut x, cover_ids, tmpl_tx_ids, tmpl_notes) = a
        .produce_template(5_000, Hash32::hash(b"f"), Hash32::hash(b"r"))
        .expect("A builds a template");
    if let Some(m) = a.pow_miner.as_ref() {
        x.pow_proof = m.mine(&mut x.header).expect("A's template mines");
    }
    // B builds a two-deep child chain on X: Y, then Z.
    assert!(matches!(
        b.ingest_block(x.clone(), 6_000),
        crate::relay::RelayOutcome::Added(_)
    ));
    let y = b
        .produce(7_000, Hash32::hash(b"f"), Hash32::hash(b"r"))
        .expect("B produces Y on X");
    let z = b
        .produce(8_000, Hash32::hash(b"f"), Hash32::hash(b"r"))
        .expect("B produces Z on Y");
    assert!(
        y.header.parents.contains(&x.id()) && z.header.parents.contains(&y.id()),
        "chain shape X <- Y <- Z"
    );
    // Both park on A: their ancestors are not yet in A's DAG.
    assert!(matches!(
        a.ingest_block(y.clone(), 9_000),
        crate::relay::RelayOutcome::Buffered { .. }
    ));
    assert!(matches!(
        a.ingest_block(z.clone(), 9_100),
        crate::relay::RelayOutcome::Buffered { .. }
    ));
    // A grafts its own X with the apply budget ALREADY spent (an instant taken before the
    // call): the page is the one-release progress minimum, so exactly Y cascades now and Z
    // re-parks on its (now present) parent.
    let budget_spent = crate::budget_clock::Stamp::now();
    assert!(
        a.graft_mined_own_budgeted(
            x.clone(),
            cover_ids,
            tmpl_tx_ids,
            tmpl_notes,
            9_200,
            Some(budget_spent)
        )
        .is_some(),
        "A's own block grafts"
    );
    assert!(
        a.dag().get(&y.id()).is_some(),
        "the page admits ONE cascaded descendant (Y) — the call always makes progress"
    );
    assert!(
        a.dag().get(&z.id()).is_none(),
        "Z stays parked past the page — the pre-fix inline cascade grafts it here, which is \
         the un-budgeted lock hold this pin exists to refuse"
    );
    // The strand lane releases the remainder through the FULL ingest gates (the runtime tick's
    // exact drain), and the page defers LOCK TIME only — never a block, never a record.
    let mut released = 0usize;
    loop {
        let ws = a.take_stranded_blocks();
        if ws.is_empty() {
            break;
        }
        for w in ws {
            let _ = a.ingest_block_preverified(w, 9_300);
            released += 1;
        }
    }
    assert!(released >= 1, "the strand lane must release the re-parked remainder");
    assert!(
        a.dag().get(&z.id()).is_some(),
        "Z enters the DAG through the strand lane"
    );
    for id in [y.id(), z.id()] {
        assert!(
            a.da_record_notes(Node::da_record_id_for_block(&id, 0)).is_some(),
            "every released block leaves the lane WITH its DA record on A — the page must \
             never become a ledger hole"
        );
    }
    assert_eq!(a.relay_buffered_len(), 0, "nothing stays parked once the strand lane drains");
}

/// ⭐ ITEM-14 PIN B (two-party): a parked child whose parent is PRESENT must be releasable, on the
/// production adopt shape.
///
/// cons: none — test-only code: two in-memory nodes, three blocks, persists nothing.
///
/// WHAT IT CATCHES: P produces g->a->b->c. Q parks c on b, parks b on a, then b enters Q's DAG as an
/// ANCHOR through the production door (`admit_anchor_block`, the #29 DSYNC adopt — out-of-band, no
/// `receive`, no drain). From that instant b is Q's SETTLED BASE (DB-282, `Dag::add_anchor`): a is
/// pre-anchor history and can never graft (`BelowSettledBase`), so no graft of a will ever fire
/// `drain_from` for the parked b, and no graft of b will ever fire it for c — c sits parked behind a
/// PRESENT parent, invisible (`relay_buffered_len` stuck). The runtime's post-adopt step
/// (node_runtime.rs adopt arm; `page_above_anchor` is the in-process copy) is what releases it:
/// DB-297 `relay_drop_orphans_the_dag_cannot_attach` drops b (parked against history the adopted DAG
/// cannot attach) and FLAGS the strand for c (its parent b is held), and the strand lane
/// `take_stranded_blocks` hands c back through the full-gate ingest. RED when the strand flag is
/// removed from `drop_orphans_the_dag_cannot_attach`: `take_stranded_blocks` returns nothing and c
/// stays parked forever (buffered_len stuck at 1). GREEN with it.
/// (The released c then re-runs the FULL gates; against a raw test anchor that carries no DAA window its
/// work expectation legitimately differs — MEASURED `Invalid(WrongWork { expected: 4, got: 3 })`, regs5.log —
/// so this pin asserts the RELEASE contract: c leaves the park through the lane, never re-parks.)
/// (The pin's previous premise — a arrives LAST and grafts, draining b and c — is refused by
/// construction since DB-282: a is below the settled base. That refusal is asserted here as the rule
/// it is, never weakened. 2026-10-05 → 2026-10-27 this pin NEVER PASSED for that premise.)
#[test]
fn a_waiter_already_in_the_dag_releases_its_parked_children_for_the_lane() {
    let mut p = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let mut q = Node::new_folding_at_tip_for_test(genesis_block()).unwrap();
    let a_blk = p
        .produce(5_000, Hash32::hash(b"f"), Hash32::hash(b"r"))
        .expect("P produces a");
    let b_blk = p
        .produce(6_000, Hash32::hash(b"f"), Hash32::hash(b"r"))
        .expect("P produces b");
    let c_blk = p
        .produce(7_000, Hash32::hash(b"f"), Hash32::hash(b"r"))
        .expect("P produces c");
    assert!(matches!(
        q.ingest_block(c_blk.clone(), 9_000),
        crate::relay::RelayOutcome::Buffered { .. }
    )); // c parks on b
    assert!(matches!(
        q.ingest_block(b_blk.clone(), 9_000),
        crate::relay::RelayOutcome::Buffered { .. }
    )); // b parks on a
    // b enters Q's DAG OUT-OF-BAND as an anchor through the production door (the DSYNC adopt shape;
    // b carries P's real grind, so the header door admits it).
    assert!(q.admit_anchor_block(b_blk.clone(), u128::MAX, 2), "the anchor installs on Q");
    assert_eq!(
        q.relay_buffered_len(),
        2,
        "the strand is real before the post-adopt step: b and c are both parked"
    );
    // THE RUNTIME'S POST-ADOPT STEP, in order (node_runtime.rs adopt arm): DB-297 drops every orphan
    // parked against the DAG the adopt replaced — b, parked on the pre-anchor a — and flags the strand
    // of c, whose parent b the DAG now holds.
    let dropped = q.relay_drop_orphans_the_dag_cannot_attach();
    assert_eq!(dropped, 1, "exactly b is dropped: it waits on pre-anchor history the adopted DAG cannot attach");
    assert_eq!(q.relay_buffered_len(), 1, "c is the surviving strand, parked behind a PRESENT parent");
    let stranded = q.take_stranded_blocks();
    assert_eq!(
        stranded.iter().map(|b| b.id()).collect::<Vec<_>>(),
        vec![c_blk.id()],
        "the strand lane releases exactly c — RED without the strand flag in \
         `drop_orphans_the_dag_cannot_attach`: nothing is released and c stays parked forever"
    );
    for b in stranded {
        let out = q.ingest_block(b, 9_000);
        assert!(
            !matches!(out, crate::relay::RelayOutcome::Buffered { .. }),
            "a released child of a HELD parent never re-parks: {out:?}"
        );
        eprintln!("[item14-pin-b] released c through the full gates -> {out:?}");
    }
    assert_eq!(q.relay_buffered_len(), 0, "nothing remains parked behind a PRESENT parent");
    // THE RULE THE OLD PREMISE VIOLATED, asserted as the rule it is (DB-282): a is pre-anchor history
    // on Q and is refused, and the refusal parks nothing.
    let a_out = q.ingest_block(a_blk.clone(), 9_000);
    assert!(
        matches!(
            a_out,
            crate::relay::RelayOutcome::DagRejected(crate::dag::DagError::BelowSettledBase(_))
        ),
        "a block below the settled base is refused, never grafted: {a_out:?}"
    );
    assert_eq!(q.relay_buffered_len(), 0, "a refused history block parks nothing");
}

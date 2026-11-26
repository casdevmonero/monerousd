// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ THE LEVEL AGGREGATE, MILESTONE 2 — THE NODE'S SIDE OF THE PROOF TREE, TWO-NODE PINS (lane aggnode, piece F;
//! docs/LEVEL-AGGREGATE-SPEC-20261115.md §11).
//!
//! WHAT THESE PIN, AND WHAT THEY DO NOT. The tree itself (the leaf and merge proofs and their verifier) is lane agg's
//! crate (`usdm_agg::tree_ssa`, its own lying-prover pins); the first pin below is a real peer refusing a root the tree
//! did not make. The others run under `agg_root::with_plumbing_stand_in`, a TEST-ONLY stand-in that PROVES NOTHING (a
//! keyed hash of the statements in order). They pin the node's own rules, which hold whatever the tree is: a tree-form
//! body carries no carrier and is its own statement's; the block carries exactly one root; the root is judged over the
//! statements the PEER derives from the bodies it was handed, in carried order; a block whose root is another block's,
//! missing, doubled or altered, or whose body states something else, enters no peer and no peer holds its payment.
//! Soundness — that a root exists only for carriers that verify — is the tree's own lying-prover row, never these.
//!
//! THE CLAIM IS THE PEER'S: `node_b` never saw the payment, is fed the block as a peer receives it (`gossip_encode` →
//! `gossip_decode`) and judges it at its own door.
use super::tests::testnet_party_folding_at_tip;
use super::*;

type History = Vec<(Block, u64)>;

fn fresh_peer_node(history: &History) -> Node {
    let mut peer_node = testnet_party_folding_at_tip();
    for (b, at) in history {
        let whole = crate::block::gossip_decode(&crate::block::gossip_encode(b)).expect("the envelope decodes");
        assert!(matches!(peer_node.ingest_block(whole, *at), RelayOutcome::Added(_)), "PRECONDITION: a peer grafts the producer's history");
    }
    peer_node
}

/// On `node_a`, under the stand-in: a funded, confirmed note; one production-shaped spend of it HELD in tree form and
/// laid in A's next block. Returns the history before the spend block, the spend block, its arrival time, the first
/// output and the FULL tx.
fn lay_one_tree_spend(node_a: &mut Node, seed: u64) -> (History, Block, u64, [u8; 32], PqTx) {
    let mut history: History = Vec::new();
    let mut ts = 5_000u64;
    let (note, cm) = Node::test_spendable_note(seed);
    let (funding, _) = node_a.carry_notes_in_a_block_for_test(ts, &note);
    history.push((funding, ts + 100));
    ts += 600;
    for i in 0..6u64 {
        if node_a.member_path_ready_for_test(&cm) {
            break;
        }
        let blk = node_a.produce(ts, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"tree-a")).expect("A produces an empty block");
        history.push((blk, ts + 100));
        ts += 600;
    }
    assert!(node_a.member_path_ready_for_test(&cm), "PRECONDITION: the note confirmed on the producer");
    let (mut tx, _nf) = node_a.production_spend_tx_for_test(&cm, seed).expect("the wallet-shaped spend builds");
    tx.membership_carrier.clear();
    tx.membership_tip.clear();
    let held = node_a.hold_for_aggregation(tx.clone(), usize::MAX);
    let crate::node::AggHold::Held(tree_id) = held else { panic!("⛔ the holder did not hold an honest pushed send: {held:?}") };
    assert!(node_a.mempool().get(&tx.id).is_none(), "⛔ the FULL send stayed pooled beside its tree form");
    assert!(node_a.mempool().get(&tree_id).is_some(), "⛔ the tree form is not pooled");
    let mut out = [0u8; 32];
    out.copy_from_slice(&tx.output_notes[..32]);
    let blk = node_a.produce(ts, Hash32::hash(b"tree-spend"), Hash32::hash(b"tree-a")).expect("A lays the tree-form spend's block");
    (history, blk, ts + 100, out, tx)
}

fn delivered(b: &Block) -> Block {
    crate::block::gossip_decode(&crate::block::gossip_encode(b)).expect("the envelope decodes")
}

/// ⛔⛔⛔ A ROOT THE TREE DID NOT MAKE IS REFUSED: a block whose tree-form payment rides a STAND-IN root (made under the
/// test-only stand-in, which proves nothing) is judged by a peer WITHOUT the stand-in — by the real tree
/// (`usdm_agg::tree_ssa::verify_root`), as every node of this build judges — and enters no peer, nor does its payment.
#[test]
fn tree_a_block_whose_root_the_tree_did_not_make_is_refused_by_every_peer() {
    let mut node_a = testnet_party_folding_at_tip();
    let (history, blk, at, out, _tx) = crate::agg_root::with_plumbing_stand_in(|| lay_one_tree_spend(&mut node_a, 2201));
    let mut node_b = fresh_peer_node(&history);
    let got = node_b.ingest_block(delivered(&blk), at);
    assert!(
        !matches!(got, RelayOutcome::Added(_) | RelayOutcome::Buffered { .. }),
        "⛔⛔⛔ a peer of this build grafted a block whose payment no proof it can check established: {got:?}"
    );
    assert!(!node_b.holds_record_with_cm(&out), "⛔⛔⛔ a peer holds a payment whose carriers nobody verified to it");
}

/// ⭐ THE HONEST PATH'S PLUMBING (stand-in): the holder's block carries the payment as a TREE-FORM body — no carrier,
/// a 36-byte blob that is the tree tag and its own statement's commitment, a new id that is that blob's — and exactly
/// one root; the hashed block carries neither; the envelope delivers both; a peer that never saw the payment derives
/// the statement itself, judges the root over it, grafts the block and holds the payment. Prints the bytes a peer pulls.
#[test]
fn tree_a_peer_fed_only_the_block_derives_the_statement_judges_the_root_and_holds_the_payment() {
    crate::agg_root::with_plumbing_stand_in(|| {
        let mut node_a = testnet_party_folding_at_tip();
        let (history, blk, at, out, tx) = lay_one_tree_spend(&mut node_a, 2202);
        assert_eq!(blk.tx_bodies.len(), 1, "⛔ the block does not carry its stated spend");
        let body = crate::chain_object::decode_exact::<PqTx>(&blk.tx_bodies[0]).expect("the carried body is a transaction");
        assert!(crate::spend_evidence::is_tree_form(&body), "⛔ the carried body is not the tree form");
        assert!(body.member_carrier.is_empty() && body.spend_or_decoy.is_empty() && body.blob.len() == 36, "⛔ a tree-form body carries a carrier");
        assert_eq!(body.blob[4..], crate::spend_evidence::tree_statement_commit(&body), "the blob is its own statement's commitment");
        assert_ne!(body.id, tx.id, "the tree-form body has its own id");
        assert_eq!(body.id, PqTx::content_id(&body.blob), "the tree-form body's id is its own blob's");
        assert_eq!((&body.nullifiers, &body.output_notes), (&tx.nullifiers, &tx.output_notes), "the payment itself is unchanged");
        assert_eq!(blk.agg_tables.len(), 1, "⛔ the block does not carry exactly one root");
        eprintln!(
            "[tree-node] a payment on the envelope: full {} B → tree-form body {} B + one root of {} B (the stand-in's; the real root's size is lane agg's to measure)",
            postcard::to_allocvec(&tx).expect("encodes").len(),
            blk.tx_bodies[0].len(),
            blk.agg_tables[0].len()
        );
        let bare: Block = postcard::from_bytes(&postcard::to_allocvec(&blk).expect("the hashed block encodes")).expect("decodes");
        assert!(bare.agg_tables.is_empty() && bare.tx_bodies.is_empty(), "⛔ the hashed block carries a body or a root");
        let whole = delivered(&blk);
        assert_eq!((&whole.agg_tables, &whole.tx_bodies), (&blk.agg_tables, &blk.tx_bodies), "the envelope delivers the root and the body");
        let mut node_b = fresh_peer_node(&history);
        assert!(node_b.mempool().get(&tx.id).is_none() && node_b.mempool().get(&body.id).is_none(), "PRECONDITION: the peer never saw the payment");
        let outcome = node_b.ingest_block(whole, at);
        assert!(matches!(outcome, RelayOutcome::Added(_)), "⛔ the peer refused an honest tree-form block: {outcome:?}");
        assert!(node_b.holds_record_with_cm(&out), "⛔ node B does not hold the tree-form payment");
        assert!(node_a.holds_record_with_cm(&out), "CONTROL: the holder holds it too");
    });
}

/// ⭐⭐ THE LYING PRODUCER, at the node's own rules (stand-in): each block is RE-SEALED and RE-MINED by its producer, so
/// its id commits every lie and no copy check stands in the way. CONTROL: the honest block re-sealed and re-mined
/// unchanged enters. Refused, each by a fresh peer that then holds nothing: another block's root; no root; two roots;
/// one root byte moved; a tree-form body that carries a carrier after all; a body whose blob is not its own statement's
/// commitment; the tree-form body replaced by its FULL twin (a copy the block does not name).
#[test]
fn tree_a_producer_that_seals_a_root_that_is_not_its_payments_is_refused_by_every_peer() {
    crate::agg_root::with_plumbing_stand_in(|| {
        let mut node_a = testnet_party_folding_at_tip();
        let (history, blk, at, out, tx) = lay_one_tree_spend(&mut node_a, 2203);
        let mut other_node = testnet_party_folding_at_tip();
        let (_, other_blk, _, _, _) = lay_one_tree_spend(&mut other_node, 2204);
        assert_ne!(other_blk.agg_tables, blk.agg_tables, "CALIBRATION: two payments have two roots");
        let body = crate::chain_object::decode_exact::<PqTx>(&blk.tx_bodies[0]).expect("a transaction");
        let sealed = |f: &dyn Fn(&mut Block)| -> Block {
            let mut b = blk.clone();
            f(&mut b);
            b.seal_transitions_root();
            super::tests::mine_fixture_block(&mut b);
            b
        };
        let with_body = |b: &mut Block, t: &PqTx| {
            b.tx_ids.iter_mut().filter(|i| **i == body.id).for_each(|i| *i = t.id);
            b.tx_bodies = vec![postcard::to_allocvec(t).expect("encodes")];
        };
        let mut peer = fresh_peer_node(&history);
        let got = peer.ingest_block(delivered(&sealed(&|_| {})), at);
        assert!(matches!(got, RelayOutcome::Added(_)), "CALIBRATION: the honest block re-sealed and re-mined must enter: {got:?}");
        assert!(peer.holds_record_with_cm(&out), "CALIBRATION: and deliver the payment");
        let lies: Vec<(&str, Block)> = vec![
            ("the producer sealed another block's root", sealed(&|b| b.agg_tables = other_blk.agg_tables.clone())),
            ("the producer sealed its tree-form payment with no root", sealed(&|b| b.agg_tables.clear())),
            ("the producer sealed two roots", sealed(&|b| b.agg_tables.push(blk.agg_tables[0].clone()))),
            ("the producer moved one byte of the root", sealed(&|b| b.agg_tables[0][0] ^= 1)),
            ("the producer sealed a tree-form body that carries a carrier after all", sealed(&|b| {
                let mut t = body.clone();
                t.member_carrier = tx.member_carrier.clone();
                with_body(b, &t);
            })),
            ("the producer sealed a body whose blob is not its own statement's commitment", sealed(&|b| {
                let mut t = body.clone();
                t.blob[35] ^= 1;
                t.id = PqTx::content_id(&t.blob);
                with_body(b, &t);
            })),
            ("the tree-form body replaced by its FULL twin", {
                let mut b = blk.clone();
                b.tx_bodies = vec![postcard::to_allocvec(&tx).expect("encodes")];
                b
            }),
        ];
        for (what, lie) in lies {
            let mut node_b = fresh_peer_node(&history);
            let got = node_b.ingest_block(delivered(&lie), at);
            eprintln!("[tree-node] {what}: {got:?}");
            assert!(
                !matches!(got, RelayOutcome::Added(_) | RelayOutcome::Buffered { .. }),
                "⛔⛔⛔ a peer grafted a block whose root is not its payments' — {what}: {got:?}"
            );
            assert!(!node_b.holds_record_with_cm(&out), "⛔⛔⛔ a peer holds a payment no root established — {what}");
        }
    });
}

/// ⭐ THE HYBRID NEVER HOLDS WHAT IT CANNOT PROVE: no room, nothing held (the send then takes today's path); a pushed
/// send that is not an ordinary send (no member leg) is never held; with room the same send is held in tree form and
/// the full send leaves the pool. Carried over from milestone 1's room pin when its core form was deleted (2026-11-16).
#[test]
fn tree_the_holder_holds_only_what_its_room_covers() {
    let mut node_a = testnet_party_folding_at_tip();
    let (note, cm) = Node::test_spendable_note(2204);
    let mut ts = 5_000u64;
    let _ = node_a.carry_notes_in_a_block_for_test(ts, &note);
    ts += 600;
    for i in 0..6u64 {
        if node_a.member_path_ready_for_test(&cm) {
            break;
        }
        let _ = node_a.produce(ts, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"tree-room"));
        ts += 600;
    }
    let (mut tx, _nf) = node_a.production_spend_tx_for_test(&cm, 2204).expect("the wallet-shaped spend builds");
    tx.membership_carrier.clear();
    tx.membership_tip.clear();
    assert_eq!(node_a.hold_for_aggregation(tx.clone(), 0), crate::node::AggHold::NotHeld, "⛔ held with no room");
    assert!(node_a.mempool().get(&tx.id).is_none(), "⛔ a refused hold pooled the send (the caller's ordinary path pools it)");
    let mut framed = tx.clone();
    framed.member_carrier.clear();
    assert_eq!(node_a.hold_for_aggregation(framed, usize::MAX), crate::node::AggHold::NotHeld, "⛔ held a send with no member leg");
    let held = node_a.hold_for_aggregation(tx.clone(), usize::MAX);
    let crate::node::AggHold::Held(tree_id) = held else { panic!("CONTROL: with room the same send is held — {held:?}") };
    assert!(node_a.mempool().get(&tx.id).is_none(), "⛔ the FULL send stayed pooled beside its tree form");
    let pooled = node_a.mempool().get(&tree_id).expect("the tree form is pooled");
    assert!(crate::spend_evidence::is_tree_form(pooled), "⛔ the held form is not the tree form");
}

/// The room rule's arithmetic is the tree's own: `agg_root::merges_for(k)` is the number of merges in
/// `usdm_agg::tree_ssa::tree_of(k)` (a merge of one child counts: it is proved like any other), for every k a hold admits.
#[test]
fn tree_merges_for_counts_the_canonical_trees_merges() {
    fn count(t: &usdm_agg::tree_ssa::Tree) -> usize {
        match t {
            usdm_agg::tree_ssa::Tree::Leaf(_) | usdm_agg::tree_ssa::Tree::Ledger => 0,
            usdm_agg::tree_ssa::Tree::Merge(cs) => 1 + cs.iter().map(count).sum::<usize>(),
        }
    }
    for k in 1..=crate::node::AGG_HOLD_MAX {
        let t = usdm_agg::tree_ssa::tree_of(k).expect("a tree");
        assert_eq!(crate::agg_root::merges_for(k), count(&t), "⛔ merges_for({k}) is not the canonical tree's merge count");
    }
    assert_eq!((crate::agg_root::merges_for(1), crate::agg_root::merges_for(2), crate::agg_root::merges_for(3)), (0, 1, 3), "CONTROL: the shapes the pins prove");
}

/// ⭐⭐⭐ A-F114 (B′) — A TREE-FORM PAYMENT UNDER THE CONSTANT CHAIN, ON TWO PARTIES, BY THE REAL TREE. The switch on for this
/// thread; a note funded on both parties and one span of records after it; the production spend of it, its member leg
/// dropped, its blinded wrapper (the production `CanonCarrier` over A's window) attached; A holds it for aggregation, so it
/// rides A's block as a TREE-FORM body (no carrier, its wrapper's END only) under A's REAL root (the canon leaf verifies the
/// wrapper in circuit, `usdm_agg::tree_ssa` t9). B is fed the block as a peer, admits it at its own door (the root over the
/// statements it derives), and both parties fold it by the ROOT-PROVEN path (the fold re-checks the roots, then judges the
/// nullifier by its window): the nullifier is a tag of both windows.
#[test]
fn af114_under_the_switch_a_tree_form_payment_folds_on_two_parties_by_its_root() {
    crate::params::set_canon_live_for_test(Some(true));
    let seed = 2_301u64;
    let mut a = testnet_party_folding_at_tip();
    let mut b = testnet_party_folding_at_tip();
    let mut ts = 5_000u64;
    let (note, cm) = Node::test_spendable_note(seed);
    let (funding, _) = a.carry_notes_in_a_block_for_test(ts, &note);
    assert!(matches!(b.ingest_block(delivered(&funding), ts + 100), RelayOutcome::Added(_)), "PRECONDITION: B grafts the funding");
    let _ = a.fold_canonical_records();
    let _ = b.fold_canonical_records();
    ts += 600;
    let mut step = |a: &mut Node, b: &mut Node, ts: &mut u64, tag: &[u8]| {
        let blk = a.produce(*ts, Hash32::hash(tag), Hash32::hash(b"af114-tree")).expect("A produces");
        let got = b.ingest_block(delivered(&blk), *ts + 100);
        assert!(matches!(got, RelayOutcome::Added(_)), "⛔ B refused A's block: {got:?}");
        let _ = a.fold_canonical_records();
        let _ = b.fold_canonical_records();
        *ts += 600;
    };
    // the record that made the note, then one span after it
    let leaf = crate::spend_frontier::note_leaf_of(&cm);
    let span = crate::canon_carrier_core::SPAN;
    let mut made: Option<(u64, crate::spend_frontier::Digest4)> = None;
    for k in 0..400u64 {
        if made.is_none() {
            let ring = a.canon_recent.range(0, crate::canon_chain::CANON_RECENT_RECORDS);
            if let Some(i) = ring.iter().position(|(_, _, _, l, _)| l.contains(&leaf)) {
                let before = if i > 0 { ring[i - 1].1 } else { crate::canon_chain::genesis() };
                made = Some((ring[i].0, before));
            }
        }
        if let Some((m, _)) = made {
            if a.canon_recent.range(m, span).len() == span {
                break;
            }
        }
        step(&mut a, &mut b, &mut ts, &k.to_le_bytes());
    }
    let (made_ord, start_end) = made.expect("⛔ CALIBRATION: no record in A's window outputs the funded note's commitment");
    let recs = a.canon_recent.range(made_ord, span);
    assert_eq!(recs.len(), span, "⛔ A's window never held a span after the note's record");
    // the production spend, its member leg dropped, its wrapper attached
    let w = Node::test_spend_witness(seed);
    let (mut tx, nf) = a.production_spend_tx_for_test(&cm, seed).expect("the wallet-shaped spend builds");
    tx.membership_carrier.clear();
    tx.membership_tip.clear();
    tx.member_carrier.clear();
    tx.member_tuple.clear();
    let mut car = crate::canon_carrier_core::CanonCarrier::starting_at(crate::canon_chain::to_lanes(&start_end), made_ord);
    car.pending = vec![(crate::canon_chain::tag_lanes(&nf), crate::canon_chain::to_lanes(&leaf))];
    for (ord, _, tags, leaves, _) in &recs {
        car.absorb(*ord, &crate::canon_chain::record(tags, leaves, *ord)).expect("the carrier follows the window");
    }
    let binder = crate::spend_frontier::cm_bytes_to_root(&nf).expect("canonical nullifier");
    let (wrapper, end) = car.spend(0, crate::canon_chain::to_lanes(&binder), crate::canon_chain::to_lanes(&w.lc_blind)).expect("the wrapper proves");
    tx.nullifier_absence = vec![crate::nf_sparse::NfAbsenceWitness {
        proof: postcard::to_allocvec(&vec![crate::nf_sparse::CanonAbsence { proof: wrapper, end: crate::canon_chain::of_lanes(&end) }]).expect("encodes"),
        ..Default::default()
    }];
    let held = a.hold_for_aggregation(tx.clone(), usize::MAX);
    let crate::node::AggHold::Held(tree_id) = held else { panic!("⛔ A did not hold the switch-form payment for the tree: {held:?}") };
    let body = a.mempool().get(&tree_id).expect("⛔ the tree form is not pooled").clone();
    assert!(
        crate::nf_sparse::canon_wrappers(body.nullifier_absence.first().expect("the body keeps its wrapper's end")).iter().all(|c| c.proof.is_empty()),
        "⛔ the tree-form body carries the wrapper's bytes"
    );
    for k in 0..(a.params().record_fold_depth + 3) {
        step(&mut a, &mut b, &mut ts, &(50_000 + k).to_le_bytes());
    }
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.canon_recent.holds(&nf), "⛔ {who}'s canonical chain does not carry the tree-form payment's nullifier: it did not fold");
    }
    crate::params::set_canon_live_for_test(None);
}

/// ⛔⛔⛔ A-F114 RED TEAM — A DOUBLE SPEND OF ONE NOTE IN TWO CONCURRENT BLOCKS UNDER THE CONSTANT CHAIN. Two valid spends of the
/// SAME note (one witness, two output sets: `production_spend_tx_for_test`'s salt moves only the outputs), each carrying the
/// note's real wrapper at the same end; A pools one, B pools the other, and both produce on the SAME parent (concurrent
/// blocks, the DAG's width). Both blocks enter both parties. REFUSED when: the nullifier is spent on both parties, EXACTLY
/// ONE of the two spends' outputs is credited, and both parties credit the SAME one (the canonically first fold spends the
/// note; the second spend reads "spent after its end" and loses). Anything else is a double spend.
#[test]
fn af114_red_a_double_spend_in_two_concurrent_blocks_under_the_switch_pays_once_on_both_parties() {
    red_double_spend_concurrent(true);
}

/// The same attack on TODAY's chain (the switch off, the spent set and member legs): the control that tells a defect the
/// switch adds from one it inherits.
#[test]
fn af114_red_control_a_double_spend_in_two_concurrent_blocks_without_the_switch() {
    red_double_spend_concurrent(false);
}

fn red_double_spend_concurrent(switch: bool) {
    crate::params::set_canon_live_for_test(Some(switch));
    let seed = 2_401u64;
    let mut a = testnet_party_folding_at_tip();
    let mut b = testnet_party_folding_at_tip();
    let mut ts = 5_000u64;
    let (note, cm) = Node::test_spendable_note(seed);
    let (funding, _) = a.carry_notes_in_a_block_for_test(ts, &note);
    assert!(matches!(b.ingest_block(delivered(&funding), ts + 100), RelayOutcome::Added(_)), "PRECONDITION: B grafts the funding");
    let _ = a.fold_canonical_records();
    let _ = b.fold_canonical_records();
    ts += 600;
    let mut step = |a: &mut Node, b: &mut Node, ts: &mut u64, tag: &[u8]| {
        let blk = a.produce(*ts, Hash32::hash(tag), Hash32::hash(b"af114-red")).expect("A produces");
        let got = b.ingest_block(delivered(&blk), *ts + 100);
        assert!(matches!(got, RelayOutcome::Added(_)), "⛔ B refused A's block: {got:?}");
        let _ = a.fold_canonical_records();
        let _ = b.fold_canonical_records();
        *ts += 600;
    };
    let leaf = crate::spend_frontier::note_leaf_of(&cm);
    let span = crate::canon_carrier_core::SPAN;
    let mut made: Option<(u64, crate::spend_frontier::Digest4)> = None;
    for k in 0..400u64 {
        if made.is_none() {
            let ring = a.canon_recent.range(0, crate::canon_chain::CANON_RECENT_RECORDS);
            if let Some(i) = ring.iter().position(|(_, _, _, l, _)| l.contains(&leaf)) {
                made = Some((ring[i].0, if i > 0 { ring[i - 1].1 } else { crate::canon_chain::genesis() }));
            }
        }
        if let Some((m, _)) = made {
            if a.canon_recent.range(m, span).len() == span {
                break;
            }
        }
        step(&mut a, &mut b, &mut ts, &k.to_le_bytes());
    }
    let (made_ord, start_end) = made.expect("⛔ CALIBRATION: no record outputs the funded note");
    let recs = a.canon_recent.range(made_ord, span);
    // the two spends of ONE note, each with the note's wrapper
    let w = Node::test_spend_witness(seed);
    let mut spend = |salt: u64| -> (PqTx, [u8; 32]) {
        let (mut tx, nf) = a.production_spend_tx_for_test(&cm, salt).expect("the wallet-shaped spend builds");
        tx.membership_carrier.clear();
        tx.membership_tip.clear();
        if switch {
            tx.member_carrier.clear();
            tx.member_tuple.clear();
        }
        (tx, nf)
    };
    let (mut tx1, nf) = spend(1);
    let (mut tx2, nf2) = spend(2);
    assert_eq!(nf, nf2, "PRECONDITION: the two spends spend ONE note (one nullifier)");
    assert_ne!(tx1.output_notes, tx2.output_notes, "PRECONDITION: the two spends pay different outputs");
    let mut car = crate::canon_carrier_core::CanonCarrier::starting_at(crate::canon_chain::to_lanes(&start_end), made_ord);
    car.pending = vec![(crate::canon_chain::tag_lanes(&nf), crate::canon_chain::to_lanes(&leaf))];
    for (ord, _, tags, leaves, _) in &recs {
        car.absorb(*ord, &crate::canon_chain::record(tags, leaves, *ord)).expect("the carrier follows the window");
    }
    let binder = crate::spend_frontier::cm_bytes_to_root(&nf).expect("canonical nullifier");
    let (wrapper, end) = car.spend(0, crate::canon_chain::to_lanes(&binder), crate::canon_chain::to_lanes(&w.lc_blind)).expect("the wrapper proves");
    let witness = vec![crate::nf_sparse::NfAbsenceWitness {
        proof: postcard::to_allocvec(&vec![crate::nf_sparse::CanonAbsence { proof: wrapper, end: crate::canon_chain::of_lanes(&end) }]).expect("encodes"),
        ..Default::default()
    }];
    if switch {
        tx1.nullifier_absence = witness.clone();
        tx2.nullifier_absence = witness;
    }
    let out = |tx: &PqTx| -> [u8; 32] { tx.output_notes[..32].try_into().expect("an output") };
    let (o1, o2) = (out(&tx1), out(&tx2));
    assert!(a.ingest_tx(tx1).is_ok(), "⛔ A's pool refused spend 1");
    assert!(b.ingest_tx(tx2).is_ok(), "⛔ B's pool refused spend 2");
    // two CONCURRENT blocks on one parent, each carrying its own spend of the note
    let ba = a.produce(ts, Hash32::hash(b"red-a"), Hash32::hash(b"af114-red-a")).expect("A produces its block");
    let bb = b.produce(ts + 1, Hash32::hash(b"red-b"), Hash32::hash(b"af114-red-b")).expect("B produces its block");
    let _ = a.ingest_block(delivered(&bb), ts + 200);
    let _ = b.ingest_block(delivered(&ba), ts + 200);
    let _ = a.fold_canonical_records();
    let _ = b.fold_canonical_records();
    ts += 600;
    for k in 0..(a.params().record_fold_depth + 3) {
        step(&mut a, &mut b, &mut ts, &(60_000 + k).to_le_bytes());
    }
    if switch {
        for (who, n) in [("A", &a), ("B", &b)] {
            assert!(n.canon_recent.holds(&nf), "⛔ {who} never spent the note at all");
        }
    }
    // ⭐ A-F114 U3 (docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md U3) — under the switch, what each party CREDITED is consensus state:
    // the output leaf a record of its canonical window carries (a loser's notes leave the row before the record steps the
    // chain), and the two parties' chains must be ONE chain (index, end, nothing missing). `holds_record_with_cm` read only the
    // DA rows a node holds, so a node without a row read "not credited" whatever its fold decided.
    if switch {
        for (who, n) in [("A", &a), ("B", &b)] {
            assert_eq!(n.canon_missing, 0, "⛔ {who} folded a record whose tags or leaves it did not hold");
        }
        assert_eq!((a.canon_index, a.canon_c), (b.canon_index, b.canon_c), "⛔⛔⛔ A SPLIT: the parties' canonical chains differ");
    }
    let in_window = |n: &Node, o: &[u8; 32]| {
        let leaf = crate::spend_frontier::note_leaf_of(o);
        n.canon_recent.range(0, usize::MAX).iter().any(|(_, _, _, l, _)| l.contains(&leaf))
    };
    let paid = |n: &Node| {
        if switch {
            (in_window(n, &o1), in_window(n, &o2))
        } else {
            (n.holds_record_with_cm(&o1), n.holds_record_with_cm(&o2))
        }
    };
    let (pa, pb) = (paid(&a), paid(&b));
    eprintln!("[af114-red] switch {switch}: credited on A (spend 1, spend 2) = {pa:?}, on B = {pb:?}");
    assert!(!(pa.0 && pa.1), "⛔⛔⛔ DOUBLE SPEND on A: both spends of one note credited");
    assert!(!(pb.0 && pb.1), "⛔⛔⛔ DOUBLE SPEND on B: both spends of one note credited");
    assert!(pa.0 || pa.1, "⛔ neither spend credited on A (a spend that pays nothing burned the note)");
    assert_eq!(pa, pb, "⛔ the parties credit DIFFERENT spends of one note (a split)");
    crate::params::set_canon_live_for_test(None);
}

/// ⭐ A-F114 UPGRADE (U2, docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md) — A JOINER UNDER THE SWITCH STANDS ON THE VOUCHED
/// CANONICAL CHAIN. Its bundle commits `(index, end, window digest, counters)` in the state the 32 mined vouchers vouch; the
/// joiner installs the index and end, PULLS the window run by run from a peer, checking each record link by link back from
/// the vouched end, and only then folds; from there it keeps ONE chain with its peer. Two tamper arms: a bundle whose
/// canonical end was edited is refused at the join door, and a page with one record edited is refused by the pull.
/// RED before U2: the joiner started at `canon_c = genesis`, index 0, and every record it folded left its peer's chain.
#[test]
fn af114_upgrade_a_joiner_under_the_switch_pulls_the_vouched_window_and_keeps_one_chain_with_its_peer() {
    crate::params::set_canon_live_for_test(Some(true));
    let mut a = testnet_party_folding_at_tip();
    let resp = a.serve_production_bundle_for_test(5_000, "u2-join");
    let crate::protocol::WireMsg::SyncResponse(wire) = &resp else { unreachable!() };
    let bundle = crate::sync::SyncBundle::from_wire(wire).expect("the bundle decodes");
    let vouched = bundle.nullifier.canon;
    assert!(vouched.index > 0, "CALIBRATION: the served state stands past record 0 (index {})", vouched.index);
    // TAMPER 1: a bundle whose canonical end was edited is not adopted
    let mut forged = bundle.clone();
    forged.nullifier.canon.c[0] ^= 1;
    let mut d = testnet_party_folding_at_tip();
    let got = d.handle_sync_response(&crate::protocol::WireMsg::SyncResponse(forged.to_wire()));
    assert!(!matches!(got, Some(AdoptOutcome::Adopted(_))), "⛔ a bundle with a forged canonical end was adopted: {got:?}");
    let mut c = testnet_party_folding_at_tip();
    let outcome = c.handle_sync_response(&resp);
    assert!(matches!(outcome, Some(AdoptOutcome::Adopted(_))), "PRECONDITION: the joiner adopts the honest bundle: {outcome:?}");
    assert_eq!((c.canon_index, crate::canon_chain::digest_bytes(&c.canon_c)), (vouched.index, vouched.c), "⛔ the joiner did not install the vouched chain");
    assert!(c.canon_fill.is_some(), "⛔ the joiner did not start pulling its window");
    assert_eq!(c.fold_canonical_records(), 0, "⛔ the joiner folded past its anchor before its window was whole");
    // TAMPER 2: one record of an honest page edited
    let req = c.canon_fill_ask().expect("the pull asks for a run");
    let honest = a.canon_page_serve(&req);
    assert!(honest.len() > 8, "PRECONDITION: the peer serves the asked run");
    let mut page: crate::canon_chain::CanonPage = crate::chain_object::decode_exact(&honest[8..]).expect("the page decodes");
    match page.records[0].leaves.first_mut() {
        Some(l) => l[0] ^= 1,
        None => page.records[0].end[0] ^= 1,
    }
    assert!(!c.canon_page_take(&postcard::to_allocvec(&page).expect("encodes")), "⛔ a page with an edited record was taken");
    assert_eq!(c.canon_fill_ask(), Some(req), "the refused page leaves the pull where it was");
    let mut pages = 0usize;
    while let Some(req) = c.canon_fill_ask() {
        let ans = a.canon_page_serve(&req);
        assert!(c.canon_page_take(&ans[8..]), "⛔ an honest page was refused (run {req:?})");
        pages += 1;
        assert!(pages <= 64, "⛔ the pull does not end");
    }
    assert!(c.canon_fill.is_none(), "⛔ the pull ended without installing the window");
    assert_eq!(c.canon_recent.window_digest(), vouched.window, "⛔ the installed window is not the vouched one");
    // from here the two parties fold the same blocks and must keep one chain
    let step = a.params().target_spacing_ms.max(1);
    let mut ts = a.selected_tip().and_then(|t| a.dag().get(&t).map(|n| n.header.timestamp)).unwrap_or(5_000);
    let _ = crate::node::tests::db270_backfill_pages(&a, &mut c, ts);
    let _ = c.fold_canonical_records();
    for k in 0..12u64 {
        ts += step;
        a.produce(ts, Hash32::hash(&k.to_le_bytes()), Hash32::hash(b"u2-follow")).expect("A produces");
        let _ = crate::node::tests::db270_backfill_pages(&a, &mut c, ts + 100);
        let _ = a.fold_canonical_records();
        let _ = c.fold_canonical_records();
    }
    eprintln!("[af114-u2] window {} pages; A at record {}, the joiner at record {}", pages, a.canon_index, c.canon_index);
    assert!(c.canon_index > vouched.index, "⛔ the joiner never folded a record past its anchor (at {})", c.canon_index);
    assert_eq!(c.canon_missing, 0, "⛔ the joiner folded a record whose tags or leaves it did not hold");
    assert_eq!((c.canon_index, c.canon_c), (a.canon_index, a.canon_c), "⛔⛔⛔ the joiner's canonical chain left its peer's");
    crate::params::set_canon_live_for_test(None);
}

/// ⭐ A-F114 UPGRADE (U5, docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md) — A RESTARTED NODE RESUMES THE SAME CANONICAL CHAIN, and a
/// chain written AHEAD of its checkpoint (a crash between the two writes) is rolled back to the checkpoint's fold.
/// RED before U5: the chain was written only at a clean shutdown, so every crash resumed a chain older than its checkpoint.
#[test]
fn af114_upgrade_a_restart_resumes_the_canonical_chain_and_a_chain_ahead_of_its_checkpoint_rolls_back() {
    crate::params::set_canon_live_for_test(Some(true));
    let dir = std::env::temp_dir().join(format!(
        "usdmd-u5-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let snap_path = dir.join("state.snap");
    let mut p = crate::params::ChainParams::default();
    p.record_fold_depth = 0;
    let boot = |p: &crate::params::ChainParams| Node::with_params(super::tests::genesis_block(), p.clone()).expect("a node builds");
    let mut first = boot(&p);
    first.enable_persist(snap_path.clone()).expect("the persist door");
    let step = first.params().target_spacing_ms.max(1);
    let mut ts = 5_000u64;
    let mut grow = |n: &mut Node, k: u64, ts: &mut u64| {
        for i in 0..k {
            *ts += step;
            n.produce(*ts, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"u5")).expect("produces");
            let _ = n.fold_canonical_records();
        }
    };
    grow(&mut first, 12, &mut ts);
    assert!(first.canon_index >= 12, "CALIBRATION: the chain stepped a record per block (at {})", first.canon_index);
    let at_stop = (first.canon_index, first.canon_c, first.canon_recent.window_digest());
    first.persist_blocking();
    // a chain written AHEAD of the checkpoint: three more blocks fold, and only the canonical ring reaches the disk
    grow(&mut first, 3, &mut ts);
    let (head, slots, _, _, _) = first.capture_canon_ring().expect("the switch is on");
    crate::persist::save_canon_ring(&snap_path, &head, &slots).expect("the ring writes");
    assert!(first.canon_index > at_stop.0, "CALIBRATION: the ring on disk stands past the checkpoint");
    drop(first);
    let mut second = boot(&p);
    assert!(second.enable_persist(snap_path.clone()).expect("the persist door"), "PRECONDITION: resumes the checkpoint");
    assert!(second.canon_fill.is_none(), "⛔ the restart did not hold its window (it would pull from a peer a lone node does not have)");
    assert_eq!(
        (second.canon_index, second.canon_c, second.canon_recent.window_digest()),
        at_stop,
        "⛔ the resumed canonical chain is not the checkpoint's (a chain ahead of it was not rolled back)"
    );
    // and it keeps folding on from there, one record a block
    let before = second.canon_index;
    grow(&mut second, 2, &mut ts);
    assert_eq!(second.canon_missing, 0, "⛔ the resumed node folded a record whose tags or leaves it did not hold");
    assert!(second.canon_index > before, "⛔ the resumed node's chain did not move on");
    let _ = std::fs::remove_dir_all(&dir);
    crate::params::set_canon_live_for_test(None);
}

/// ⭐ A-F139 (lane selfheal, 2026-11-25) — A RING FILE THAT DOES NOT LINK AT A RESTART IS RECOVERED FROM THIS NODE'S OWN DISK.
/// The head names an end its run does not reach (what a write that a rewind undid leaves: the live origin and wallet node,
/// 06:37/06:38, each pulled its window from the other for good). RED before A-F139: the node adopted a window pull
/// (`canon_fill`), so a lone node — or two that both restarted — never folded again. Now it resumes at the newest rewind state
/// its linked part reaches and the fold re-folds the steps after it: the chain it ends at is the checkpoint's, no peer asked.
#[test]
fn af139_a_ring_that_does_not_link_resumes_at_its_rewind_state_and_refolds_to_the_checkpoint_with_no_peer() {
    crate::params::set_canon_live_for_test(Some(true));
    let dir = std::env::temp_dir().join(format!(
        "usdmd-af139-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let snap_path = dir.join("state.snap");
    let mut p = crate::params::ChainParams::default();
    p.record_fold_depth = 0;
    let boot = |p: &crate::params::ChainParams| Node::with_params(super::tests::genesis_block(), p.clone()).expect("a node builds");
    let mut first = boot(&p);
    first.enable_persist(snap_path.clone()).expect("the persist door");
    let step = first.params().target_spacing_ms.max(1);
    let mut ts = 5_000u64;
    for i in 0..12u64 {
        ts += step;
        first.produce(ts, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"af139")).expect("produces");
        let _ = first.fold_canonical_records();
    }
    assert!(first.canon_index >= 12 && !first.canon_rewind.is_empty(), "CALIBRATION: a chain with a rewind ring (at {})", first.canon_index);
    let at_stop = (first.canon_index, first.canon_c, first.canon_recent.window_digest());
    first.persist_blocking();
    // the head names an end its run does not reach: the run's records stay, the head's end is another value
    let (mut head, _, _, _, _) = first.capture_canon_ring().expect("the switch is on");
    head.1 = crate::canon_chain::genesis();
    crate::persist::save_canon_ring(&snap_path, &head, &[]).expect("the head writes");
    drop(first);
    let mut second = boot(&p);
    assert!(second.enable_persist(snap_path.clone()).expect("the persist door"), "PRECONDITION: resumes the checkpoint");
    assert!(second.canon_fill.is_none(), "⛔ A-F139: a ring that does not link sent the node to a window pull (a lone node waits for ever)");
    assert!(second.canon_resume_rewind.is_some(), "⛔ A-F139: the resume named no fold step to re-fold from");
    assert!(second.canon_index < at_stop.0, "CALIBRATION: the resume stands before the checkpoint's chain (at {})", second.canon_index);
    // the daemon folds every tick: the first pass rewinds to the resume's step, the next re-folds what it evicted
    for _ in 0..4 {
        let _ = second.fold_canonical_records();
    }
    assert_eq!(second.canon_missing, 0, "⛔ the re-fold stepped a record whose tags or leaves it did not hold");
    assert_eq!(
        (second.canon_index, second.canon_c, second.canon_recent.window_digest()),
        at_stop,
        "⛔⛔⛔ A-F139: the re-folded canonical chain is not the one the node held before its restart"
    );
    let _ = std::fs::remove_dir_all(&dir);
    crate::params::set_canon_live_for_test(None);
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! §22c (audit F14, 2026-11-10) — TWO-NODE PINS OF THE BLOCK DOOR'S SPEND EVIDENCE (`crate::spend_evidence`).
//!
//! THE CLAIM IS THE PEER'S. `node_a` produces; `node_b` (and every fresh peer an attack meets) is fed A's block exactly
//! as a peer receives it (the gossip envelope, `block::gossip_encode` → `gossip_decode`) and judged at ITS door. What is
//! asserted is what that peer holds.
//!
//! MEASURED BEFORE (the hole these close): `usdm-decider`
//! `settlement_delta::producer_forgery_tests::a_block_cannot_state_a_spend_whose_carrier_nobody_proved` (2026-11-10 12:09) —
//! a block aggregate that lays a carrier no wallet proved VERIFIES, because it reads the carrier's opened row from its
//! bytes and never checks the carrier's own opening. So the aggregate cannot be what admits a spend; the peer's own
//! verification of the carried transaction is.
use super::tests::testnet_party_folding_at_tip;
use super::*;

/// The producer's blocks so far with their arrival times, so each attack meets a FRESH peer with the same history.
type History = Vec<(Block, u64)>;

/// Feed a peer every block of `history` as a peer receives it.
fn feed(peer_node: &mut Node, history: &History) {
    for (b, at) in history {
        let whole = crate::block::gossip_decode(&crate::block::gossip_encode(b)).expect("the envelope decodes");
        assert!(matches!(peer_node.ingest_block(whole, *at), RelayOutcome::Added(_)), "PRECONDITION: a peer grafts the producer's history");
    }
}

/// A fresh peer holding the producer's history.
fn fresh_peer_node(history: &History) -> Node {
    let mut peer_node = testnet_party_folding_at_tip();
    feed(&mut peer_node, history);
    peer_node
}

/// On `node_a`: a funded, confirmed note and one production-shaped spend of it, pooled and laid in A's next block.
/// Returns the history BEFORE the spend block, the spend block, its arrival time, the spend's first output and its tx.
fn lay_one_honest_spend(node_a: &mut Node, seed: u64) -> (History, Block, u64, [u8; 32], PqTx) {
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
        let blk = node_a.produce(ts, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"f14-a")).expect("A produces an empty block");
        history.push((blk, ts + 100));
        ts += 600;
    }
    assert!(node_a.member_path_ready_for_test(&cm), "PRECONDITION: the note confirmed on the producer");
    let (tx, _nf) = node_a.production_spend_tx_for_test(&cm, seed).expect("the wallet-shaped spend builds");
    let arms = node_a.send_verdict(&tx).expect("CONTROL: the submit door admits the wallet-shaped send");
    assert!(arms.spend && arms.cover, "CONTROL: its spend and cover carriers verify");
    node_a.ingest_tx_prechecked(tx.clone()).expect("CONTROL: A pools the send");
    let mut out = [0u8; 32];
    out.copy_from_slice(&tx.output_notes[..32]);
    let blk = node_a.produce(ts, Hash32::hash(b"f14-spend"), Hash32::hash(b"f14-a")).expect("A lays the spend's block");
    assert!(blk.note_transition.is_some(), "CALIBRATION: the block states a transition");
    assert!(
        blk.output_notes.chunks(crate::cover::PQ_NOTE_BYTES).any(|n| n.len() >= 32 && n[..32] == out),
        "CALIBRATION: the block carries the spend's output"
    );
    (history, blk, ts + 100, out, tx)
}

/// THE HONEST PATH, AND WHAT RIDES IT: the producer carries the stated spend's transaction beside its block, the
/// envelope delivers it with the body and the key, and a peer that never pooled the transaction verifies it itself,
/// grafts the block and holds the payment.
#[test]
fn a_peer_fed_only_the_block_verifies_the_spend_it_states_and_holds_the_payment() {
    let mut node_a = testnet_party_folding_at_tip();
    let (history, blk, at, out, tx) = lay_one_honest_spend(&mut node_a, 1401);
    assert_eq!(blk.tx_bodies.len(), 1, "⛔ the producer did not carry its stated spend's transaction beside the block");
    let body_tx = crate::chain_object::decode_exact::<PqTx>(&blk.tx_bodies[0]).expect("the carried body is a transaction");
    assert_eq!(body_tx.id, tx.id, "the carried body is the stated spend's own transaction");
    let env = crate::block::gossip_encode(&blk);
    let wire = postcard::to_allocvec(&blk).expect("the hashed block encodes");
    eprintln!(
        "[f14-door] the spend block: {} B hashed form, {} B node-to-node envelope ({} B of it the carried transaction)",
        wire.len(),
        env.len(),
        blk.tx_bodies[0].len()
    );
    // the hashed block (what a wallet route, a page or an explorer serves) carries no transaction, body or key
    let bare: Block = postcard::from_bytes(&wire).expect("decodes");
    assert!(bare.tx_bodies.is_empty() && bare.output_notes.is_empty() && bare.cover_key.is_none(), "⛔ the hashed block carries a body");
    let whole = crate::block::gossip_decode(&env).expect("the envelope decodes");
    assert_eq!(whole.tx_bodies, blk.tx_bodies, "the envelope delivers the carried transaction");
    assert_eq!(whole.output_notes, blk.output_notes, "the envelope delivers the body");
    assert_eq!(whole.cover_key, blk.cover_key, "the envelope delivers the key");
    let mut node_b = testnet_party_folding_at_tip();
    feed(&mut node_b, &history);
    assert!(node_b.mempool().get(&tx.id).is_none(), "PRECONDITION: the peer never pooled the transaction");
    let t = std::time::Instant::now();
    let outcome = node_b.ingest_block(whole, at);
    eprintln!("[f14-door] a peer that never saw the transaction judged the block in {} ms: {outcome:?}", t.elapsed().as_millis());
    assert!(matches!(outcome, RelayOutcome::Added(_)), "⛔ the peer refused an honest block that carries its spend: {outcome:?}");
    assert!(node_b.holds_record_with_cm(&out), "⛔ node B does not hold the payment the block carries");
    assert!(node_a.holds_record_with_cm(&out), "CONTROL: the producer holds it too");
}

/// THE ATTACKS. Each is the same block as a different COPY; each meets a fresh peer; none may enter, and no peer may
/// hold the payment. A refusal condemns the copy, never the id: the whole copy is then accepted by that same peer.
#[test]
fn a_block_whose_stated_spend_no_carried_transaction_proves_is_refused_by_every_peer() {
    let mut node_a = testnet_party_folding_at_tip();
    let (history, blk, at, out, _tx) = lay_one_honest_spend(&mut node_a, 1402);
    let flip_in = |field: &dyn Fn(&mut PqTx) -> &mut Vec<u8>| -> Block {
        let mut t = crate::chain_object::decode_exact::<PqTx>(&blk.tx_bodies[0]).expect("a transaction");
        let v = field(&mut t);
        let i = v.len() / 2;
        v[i] ^= 1;
        let mut copy = blk.clone();
        copy.tx_bodies = vec![postcard::to_allocvec(&t).expect("encodes")];
        copy
    };
    let attacks: Vec<(&str, Block)> = vec![
        ("its transactions stripped (a spend stated, nothing carried)", {
            let mut b = blk.clone();
            b.tx_bodies.clear();
            b
        }),
        ("the carried transaction's member leg does not verify", flip_in(&|t| &mut t.member_carrier)),
        ("the carried transaction's cover arm does not verify", flip_in(&|t| &mut t.spend_or_decoy)),
        ("the carried transaction's spend carrier is another proof's bytes (its id no longer names it)", flip_in(&|t| &mut t.blob)),
        ("the carried transaction names another anchor than its member leg proves", {
            let mut t = crate::chain_object::decode_exact::<PqTx>(&blk.tx_bodies[0]).expect("a transaction");
            t.member_tuple[64] ^= 1; // the anchor's first byte (tuple = leaf_commit ‖ binder ‖ anchor ‖ outs)
            let mut b = blk.clone();
            b.tx_bodies = vec![postcard::to_allocvec(&t).expect("encodes")];
            b
        }),
        ("the copy without its body (rows cannot be told apart)", {
            let mut b = blk.clone();
            b.output_notes.clear();
            b
        }),
        ("the copy without its cover key", {
            let mut b = blk.clone();
            b.cover_key = None;
            b
        }),
    ];
    for (what, copy) in attacks {
        let mut node_b = fresh_peer_node(&history);
        // the copy as a peer receives it: through the envelope (which drops a body the block does not name)
        let delivered = crate::block::gossip_decode(&crate::block::gossip_encode(&copy)).expect("the envelope decodes");
        let outcome = node_b.ingest_block(delivered, at);
        eprintln!("[f14-door] {what}: {outcome:?}");
        assert!(
            !matches!(outcome, RelayOutcome::Added(_) | RelayOutcome::Buffered { .. }),
            "⛔⛔⛔ node B grafted a block whose stated spend it never verified — {what}: {outcome:?}"
        );
        assert!(!node_b.holds_record_with_cm(&out), "⛔⛔⛔ node B holds a payment no transaction proved to it — {what}");
        assert!(node_b.dag().get(&blk.id()).is_none(), "⛔ the refused copy left its block in node B's DAG — {what}");
        // the id is not condemned: the whole copy is judged afresh by the same peer
        let whole = crate::block::gossip_decode(&crate::block::gossip_encode(&blk)).expect("the envelope decodes");
        let again = node_b.ingest_block(whole, at + 100);
        assert!(matches!(again, RelayOutcome::Added(_)), "⛔ a refused copy condemned the block's id — {what}: {again:?}");
        assert!(node_b.holds_record_with_cm(&out), "⛔ node B does not hold the payment after the whole copy — {what}");
    }
    assert!(node_a.holds_record_with_cm(&out), "CONTROL: the producer holds the payment throughout");
}

/// ⛔ THE RELAY'S SWAP (found reviewing this fix, 2026-11-10): a carried transaction's id is its spend carrier's hash, so
/// its member leg is NOT named by the block's `tx_ids`. A relay can replace the leg with ANOTHER VALID one: an honest
/// proof that the same input sits in a tree the relay invented, cross-bound to the same spend. Every proof of that copy
/// verifies, so the copy would enter; at the fold its anchor is in no ring and the spend is refused THERE, on the
/// nodes that got that copy and on no others — two nodes holding one block and deciding its payment differently.
/// The block therefore commits its carried transactions (`NoteTransition::bodies`, sealed into the id): node B, fed the
/// swapped copy, must refuse it at the door and must hold the payment once it receives the whole copy, as node A does.
#[test]
fn a_relay_that_swaps_a_carried_spends_member_leg_for_another_valid_one_is_refused_at_the_door() {
    use usdm_decider::poseidon2_compress::lanes_of;
    let mut node_a = testnet_party_folding_at_tip();
    let seed = 1403u64;
    let (history, blk, at, out, tx) = lay_one_honest_spend(&mut node_a, seed);
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    // the same input, proven a member of a tree the relay invented (the rogue shape of
    // `a_peer_does_not_credit_the_outputs_of_a_spend_whose_input_never_existed`, here on an HONEST spend)
    let w = Node::test_spend_witness(seed);
    let input_leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w).expect("the witness's input leaf");
    let nf = crate::spend_frontier::cm_bytes_to_root(tx.nullifiers[0].as_bytes()).expect("a canonical nullifier");
    let depth = usdm_decider::member_path_gate::MEMBER_PATH_DEPTH;
    let sibs: Vec<crate::spend_frontier::Digest4> = (0..depth as u64).map(|l| lanes_of(&[0x5a4b, l])).collect();
    let dirs: Vec<bool> = (0..depth).map(|l| l % 3 == 0).collect();
    let mut o1 = [0u8; 32];
    o1.copy_from_slice(&tx.output_notes[crate::cover::PQ_NOTE_BYTES..crate::cover::PQ_NOTE_BYTES + 32]);
    let outs = crate::member_transition::outs_digest(&out, &o1).expect("canonical outputs");
    let (leg, tuple) = usdm_decider::member_path_gate::prove_member_path_carrier(input_leaf, &sibs, &dirs, nf, w.lc_blind, outs)
        .expect("an honest member proof in an invented tree");
    let mut swapped_tx = tx.clone();
    swapped_tx.member_carrier = leg;
    swapped_tx.member_tuple.clear();
    crate::member_transition::write_tuple(&tuple, &mut swapped_tx.member_tuple);
    let honest_anchor = crate::member_transition::read_tuple(&tx.member_tuple).expect("the honest tuple").anchor;
    assert_ne!(b32(tuple.anchor), b32(honest_anchor), "CALIBRATION: the swapped leg stands under another root");
    assert!(
        crate::spend_evidence::spend_evidence_of(&swapped_tx).is_some(),
        "CALIBRATION: every proof of the swapped transaction verifies on its own — only the block's commitment can tell the copies apart"
    );
    let mut copy = blk.clone();
    copy.tx_bodies = vec![postcard::to_allocvec(&swapped_tx).expect("encodes")];
    let mut node_b = fresh_peer_node(&history);
    let delivered = crate::block::gossip_decode(&crate::block::gossip_encode(&copy)).expect("the envelope decodes");
    assert_eq!(delivered.tx_bodies.len(), 1, "CALIBRATION: the envelope kept the swapped body (its id is the block's)");
    let outcome = node_b.ingest_block(delivered, at);
    eprintln!("[f14-door] a carried spend's member leg swapped for another valid one: {outcome:?}");
    assert!(
        !matches!(outcome, RelayOutcome::Added(_) | RelayOutcome::Buffered { .. }),
        "⛔⛔⛔ node B grafted a copy whose carried transaction is not the one the block commits: {outcome:?}"
    );
    assert!(!node_b.holds_record_with_cm(&out), "⛔ node B holds the payment from a copy it must refuse");
    let whole = crate::block::gossip_decode(&crate::block::gossip_encode(&blk)).expect("the envelope decodes");
    assert!(matches!(node_b.ingest_block(whole, at + 100), RelayOutcome::Added(_)), "⛔ the refused copy condemned the block's id");
    assert!(node_b.holds_record_with_cm(&out), "⛔⛔⛔ node B does not hold a payment node A holds: one block, two verdicts");
    assert!(node_a.holds_record_with_cm(&out), "CONTROL: node A holds the payment");
}

/// A QUIET BLOCK STATES NO SPEND AND NEEDS NO TRANSACTION: every row is the block's own cover or its objects', so the
/// door asks for no evidence — and node B, fed the envelope, grafts it.
#[test]
fn a_quiet_block_carries_no_transaction_and_a_peer_grafts_it() {
    let mut node_a = testnet_party_folding_at_tip();
    let mut node_b = testnet_party_folding_at_tip();
    let blk = node_a.produce(5_000, Hash32::hash(b"f14-quiet"), Hash32::hash(b"f14-a")).expect("A produces a quiet block");
    assert!(blk.tx_bodies.is_empty(), "a quiet block carries no transaction");
    let whole = crate::block::gossip_decode(&crate::block::gossip_encode(&blk)).expect("the envelope decodes");
    let outcome = node_b.ingest_block(whole, 5_100);
    eprintln!("[f14-door] a quiet block (transition {}): {outcome:?}", blk.note_transition.is_some());
    assert!(matches!(outcome, RelayOutcome::Added(_)), "⛔ node B refused an honest quiet block: {outcome:?}");
    assert!(node_b.dag().get(&blk.id()).is_some(), "node B holds the quiet block");
}

/// §22c × RESTART — A RESTARTED NODE SERVES ITS UNFOLDED BLOCKS WHOLE (lane vaults, 2026-11-11).
///
/// MEASURED ON REAL NODES (rig-btc1 on 200fb7a8, rig-btc2 on c0f2aa33, `btc_bridge.py`): node 0 produced block ab93b16c
/// ("carries 2306 output-note byte(s)"), restarted 43 log lines later, and from then on answered every by-id pull of that
/// block with a copy 2,385 bytes shorter (1,178,581 against 1,180,966). Node 1, itself restarting when the block was
/// announced, pulled it six times and refused each copy: "a ledger block without its body cannot be judged" →
/// `Invalid(SpendNotEvidenced)`. Its descendants parked behind it, the two nodes forked, node 1 took the certified jump and
/// its fold stood still. The cause: a checkpoint's carry restores a held body's cover key, wide objects and spend
/// transactions (`FoldCarry::sidecars`) but not its notes, which are `#[serde(skip)]` and live in the node's own record.
///
/// THE CLAIM IS THE PEER'S: a peer that never saw the block takes the copy the RESTARTED producer serves by id (the
/// envelope, as on the wire) and grafts it, and holds the payment. The restart goes through the bytes a boot decodes.
/// TAMPER: a record whose notes are not the ones the header commits completes nothing, and the body-less copy is refused.
#[test]
fn a_restarted_producer_serves_its_unfolded_block_whole_and_a_peer_that_never_saw_it_grafts_it() {
    const DEPTH: u64 = 2;
    let party = || super::tests::testnet_party_with_fold_depth(DEPTH);
    let peer_at = |history: &History| -> Node {
        let mut p = party();
        for (b, at) in history {
            let whole = crate::block::gossip_decode(&crate::block::gossip_encode(b)).expect("the envelope decodes");
            assert!(matches!(p.ingest_block(whole, *at), RelayOutcome::Added(_)), "PRECONDITION: a peer grafts the producer's history");
        }
        p
    };
    let as_served = |b: &Block| crate::block::gossip_decode(&crate::block::gossip_encode(b)).expect("the envelope decodes");
    let mut node_a = party();
    let (history, blk, at, out, _tx) = lay_one_honest_spend(&mut node_a, 1406);
    let id = blk.id();
    assert!(node_a.unfolded_blocks.iter().any(|b| b.id() == id), "CALIBRATION: the spend block is still unfolded on its producer");
    assert!(!blk.output_notes.is_empty() && !blk.tx_bodies.is_empty(), "CALIBRATION: the block carries a body and its spend");
    // CONTROL: before any restart the producer serves the block whole and a peer that never saw it grafts it
    let served = node_a.full_block_by_id(&id).expect("the producer holds its block");
    assert_eq!(served.output_notes, blk.output_notes, "CONTROL: the producer serves its body");
    let mut control = peer_at(&history);
    assert!(matches!(control.ingest_block(as_served(&served), at), RelayOutcome::Added(_)), "CONTROL: a peer grafts the served copy");
    // THE RESTART, through the bytes a boot decodes (the carry's encoding drops every serde-skipped field)
    let (snap, fold) = node_a.checkpoint_for_test().expect("A's checkpoint");
    let bytes = crate::persist::encode_checkpoint(&snap, Some(&fold)).expect("the checkpoint encodes");
    let restart = || -> Node {
        let (snap, fold) = crate::persist::decode_checkpoint(&bytes).expect("the checkpoint decodes");
        let mut r = party();
        assert!(r.resume_from_checkpoint_for_test(snap, fold.expect("its fold record")), "PRECONDITION: A resumes from its checkpoint");
        r
    };
    let restarted = restart();
    let held = restarted.unfolded_blocks.iter().find(|b| b.id() == id).expect("the restarted producer holds its unfolded block");
    assert!(!held.pow_proof.is_empty(), "CALIBRATION: it holds the block with its witness");
    eprintln!(
        "[f14-restart] the restarted producer holds its unfolded block with {} note byte(s), {} spend(s), key {}",
        held.output_notes.len(),
        held.tx_bodies.len(),
        held.cover_key.is_some()
    );
    let served = restarted.full_block_by_id(&id).expect("the restarted producer serves its block by id");
    // the measured refusal, on a peer: the copy without its body is refused, and only the copy
    let mut bare = served.clone();
    bare.output_notes.clear();
    let mut peer = peer_at(&history);
    let refused = peer.ingest_block(as_served(&bare), at);
    assert!(
        matches!(refused, RelayOutcome::Invalid(crate::consensus::ConsensusError::SpendNotEvidenced)),
        "CALIBRATION: a copy without its body is refused at the peer's door (the measured real-node refusal): {refused:?}"
    );
    assert_eq!(
        served.output_notes.len(),
        blk.output_notes.len(),
        "⛔ a restarted producer serves its own unfolded block WITHOUT the body its header commits"
    );
    assert_eq!(served.output_notes, blk.output_notes, "the served body is the block's");
    assert_eq!(served.tx_bodies, blk.tx_bodies, "the restarted producer serves the block's spends");
    assert_eq!(served.cover_key, blk.cover_key, "the restarted producer serves the block's key");
    assert_eq!(
        restarted.selected_tip_full_block().map(|b| b.output_notes),
        Some(blk.output_notes.clone()),
        "⛔ the tip pull of a restarted producer serves its tip without its body"
    );
    let outcome = peer.ingest_block(as_served(&served), at);
    assert!(matches!(outcome, RelayOutcome::Added(_)), "⛔ a peer refused the copy a restarted producer serves by id: {outcome:?}");
    assert!(peer.holds_record_with_cm(&out), "⛔ the peer does not hold the payment the block carries");
    // TAMPER: the record is the only source, and only when it IS the body the header commits
    assert_eq!(restarted.body_from_record(&bare), Some(blk.output_notes.clone()), "CONTROL: the record completes a copy that lacks its body");
    let mut shell = bare.clone();
    shell.pow_proof.clear();
    assert_eq!(restarted.body_from_record(&shell), None, "a shell (no witness) is left a shell");
    let mut forged = restart();
    let rid = Node::da_record_id_for_block(&id, 0);
    let row = if forged.da_mem.contains_key(&rid) { rid } else { forged.da_record_ordinal(rid).expect("the record's row") };
    let (other, _) = Node::test_spendable_note(1499);
    forged.da_mem.get_mut(&row).expect("the held row").0 = vec![other];
    let at_i = forged.unfolded_blocks.iter().position(|b| b.id() == id).expect("the forged node holds the block");
    forged.unfolded_blocks[at_i].set_output_notes(Vec::new()); // as its carry placed it
    assert_eq!(forged.body_from_record(&bare), None, "⛔ notes the header does not commit were offered as a block's body");
    assert_eq!(forged.complete_held_bodies_from_records(), 0, "⛔ a record that is not the header's completed a held body");
    let lied = forged.full_block_by_id(&id).expect("it still serves the block it holds");
    assert!(lied.output_notes.is_empty(), "⛔ a node whose record is not the header's served a body all the same");
    let mut wary = peer_at(&history);
    let refused = wary.ingest_block(as_served(&lied), at);
    assert!(
        matches!(refused, RelayOutcome::Invalid(crate::consensus::ConsensusError::SpendNotEvidenced)),
        "⛔ a peer took a copy whose body its server could not prove: {refused:?}"
    );
    assert!(!wary.holds_record_with_cm(&out), "⛔ the refused copy left the payment on the peer");
    assert!(
        matches!(wary.ingest_block(as_served(&served), at), RelayOutcome::Added(_)),
        "the refusal condemned the copy, never the id: the whole copy is then accepted"
    );
}

/// THE ROW RULE, ON ITS OWN: the ways a row can state something nothing proves. Built from one evidence and a block's
/// cover cells, no proof and no node involved (the proofs are `spend_evidence_of`'s; this is what is done with a verdict).
#[test]
fn the_row_rule_refuses_every_row_that_states_what_no_transaction_proves() {
    use crate::note_transition::SpendTuple;
    use crate::spend_evidence::{rows_evidenced, Row, SpendEvidence};
    use std::collections::HashSet;
    use std::sync::Arc;
    let c = |tag: &[u8]| *blake3::hash(tag).as_bytes();
    let d4 = |k: u64| -> crate::spend_frontier::Digest4 { usdm_decider::poseidon2_compress::lanes_of(&[k, 1, 2, 3]) };
    let decoys: HashSet<[u8; 32]> = (0..8u8).map(|i| c(&[b'd', i])).collect();
    let cover_notes: HashSet<[u8; 32]> = (0..8u8).map(|i| c(&[b'n', i])).collect();
    let objects: HashSet<[u8; 32]> = [c(b"object-note"), c(b"object-tag")].into_iter().collect();
    let dec = |i: u8| c(&[b'd', i]);
    let cov = |i: u8| c(&[b'n', i]);
    let head = SpendTuple { out0_cm: c(b"out0"), out1_cm: c(b"out1"), nullifier: c(b"nf"), leaf_commit: c(b"lc"), tag1: c(b"claim") };
    let tags: Vec<[u8; 32]> = [c(b"nf"), c(b"claim"), c(b"t2"), c(b"t3")].to_vec();
    let ev = vec![Arc::new(SpendEvidence { tx_id: Hash32::hash(b"tx"), tuple: head, filing_d: d4(7), clock_ms: 3_600_000, anchor: d4(9), tags })];
    let row = |t: SpendTuple, d: u64| Row { tuple: t, filing_d: d4(d), justified: [false; 4] };
    let cover_row = row(SpendTuple { out0_cm: cov(0), out1_cm: cov(1), nullifier: dec(0), leaf_commit: c(b"lc'"), tag1: dec(1) }, 0);
    let object_row = row(SpendTuple { out0_cm: c(b"object-note"), out1_cm: cov(2), nullifier: c(b"object-tag"), leaf_commit: c(b"lc''"), tag1: dec(2) }, 0);
    let tail_row = row(SpendTuple { out0_cm: cov(3), out1_cm: cov(4), nullifier: c(b"t2"), leaf_commit: c(b"lc3"), tag1: c(b"t3") }, 0);
    let judge = |rows: &[Row], ev: &[Arc<SpendEvidence>], clock: u64| rows_evidenced(rows, &decoys, &cover_notes, &objects, ev, clock).map(|h| h.len());
    // CONTROL: the honest block — the spend's head, its tail, a cover row and an object's row
    assert_eq!(judge(&[row(head, 7), tail_row, cover_row, object_row], &ev, 3_600_000), Ok(1), "CONTROL: the honest rows are evidenced");
    assert_eq!(judge(&[cover_row, object_row], &[], 0), Ok(0), "CONTROL: a block that states no spend needs no evidence");
    // 1. a spend row with no transaction (the forged carrier's row)
    assert!(judge(&[row(head, 7), cover_row], &[], 3_600_000).is_err(), "⛔ a spend row with no transaction was admitted");
    // 2. the outputs credited, the nullifier swapped for a cover tag (the input never spent)
    let no_nf = SpendTuple { nullifier: dec(5), ..head };
    assert!(judge(&[row(no_nf, 7), cover_row], &ev, 3_600_000).is_err(), "⛔ outputs were credited without their nullifier");
    // 3. the nullifier burned on a row whose outputs are cover (the outputs never credited)
    let burn = row(SpendTuple { out0_cm: cov(5), out1_cm: cov(6), nullifier: c(b"nf"), leaf_commit: c(b"lc5"), tag1: dec(6) }, 0);
    assert!(judge(&[burn, cover_row], &ev, 3_600_000).is_err(), "⛔ a nullifier was burned without its spend's outputs");
    // 4. a victim's tag no stated spend carries
    let foreign = row(SpendTuple { out0_cm: cov(5), out1_cm: cov(6), nullifier: c(b"victim"), leaf_commit: c(b"lc6"), tag1: dec(7) }, 0);
    assert!(judge(&[row(head, 7), foreign], &ev, 3_600_000).is_err(), "⛔ a tag no stated spend carries was admitted");
    // 5. one output swapped (a note the transaction never made)
    let other_out = SpendTuple { out1_cm: c(b"made-up"), ..head };
    assert!(judge(&[row(other_out, 7)], &ev, 3_600_000).is_err(), "⛔ a note the transaction never made was admitted");
    // 6. another filing digest, and a ledger clock before the transaction's
    assert!(judge(&[row(head, 8)], &ev, 3_600_000).is_err(), "⛔ a spend row under another filing digest was admitted");
    assert!(judge(&[row(head, 7)], &ev, 0).is_err(), "⛔ a spend proven under a later clock than the ledger's was admitted");
    // 7. one transaction stated twice
    assert!(judge(&[row(head, 7), row(head, 7)], &ev, 3_600_000).is_err(), "⛔ one transaction was stated as two rows");
    // 8. a JUSTIFIED cell is not the ledger's to admit (its object admits it or nothing does): a wrapper's padding tag on
    //    a justified cell asks for no evidence, and the same tag on a cell the ledger itself admits is refused (4 above)
    let padding = Row { tuple: SpendTuple { out0_cm: cov(5), out1_cm: cov(6), nullifier: c(b"padding"), leaf_commit: c(b"lc7"), tag1: dec(7) }, filing_d: d4(0), justified: [false, false, true, false] };
    // (the spend's tail row rides along: a block that states a spend states all its tags, case 10)
    assert_eq!(judge(&[row(head, 7), tail_row, padding], &ev, 3_600_000), Ok(1), "a justified tag cell is the object door's, not this one's");
    // 9. a spend's head cannot hide a cell behind a justified flag
    let half = Row { tuple: head, filing_d: d4(7), justified: [false, true, false, false] };
    assert!(judge(&[half], &ev, 3_600_000).is_err(), "⛔ a spend's head with a justified cell was admitted");
    // 10. ⭐ THE OTHER DIRECTION (V2, 2026-11-16): every tag of a stated spend is stated. The head states `nf` and `claim`;
    //     leaving its tail row out leaves `t2`, `t3` (real nullifiers among the decoys) unstated, so they would never enter
    //     the set. Until now only the tag ledger's chain refused this; the joined proof carries no tag statement any more.
    assert!(
        judge(&[row(head, 7), cover_row, object_row], &ev, 3_600_000).is_err(),
        "⛔ a stated spend whose tail tags no row states was admitted"
    );
    let half_tail = row(SpendTuple { out0_cm: cov(3), out1_cm: cov(4), nullifier: c(b"t2"), leaf_commit: c(b"lc3"), tag1: dec(3) }, 0);
    assert!(judge(&[row(head, 7), half_tail, cover_row], &ev, 3_600_000).is_err(), "⛔ a stated spend with one tail tag left out was admitted");
}

/// ⭐ C1 (SPEED, 2026-11-12) — THE COMPACT ENVELOPE, judged by the PEER. A spend block's compact copy names its carried
/// transaction by id instead of carrying its 356 KB; a peer that POOLED the transaction (as every peer does once the
/// DB-444 relay has run) rebuilds the block from its own pool, and the rebuilt block is the full envelope's block BYTE FOR
/// BYTE, so it enters the door with exactly what a full copy hands it, grafts, and the peer holds the payment.
/// REFUSALS (each a `Miss`, never a block judged on bodies it did not carry): (1) a pool without the transaction; (2) a
/// pooled copy under the SAME id whose bytes differ in one place (CALIBRATION: the id alone would have taken it — the id
/// is the blob's, the flip is in the member carrier); (3) a full copy is still judged as before (the attacks above).
#[test]
fn c1_a_compact_block_rebuilds_from_the_peers_own_pool_and_a_missing_or_differing_body_is_a_miss() {
    use crate::block::{gossip_decode_compact, gossip_encode, gossip_encode_compact, CompactFill};
    let mut node_a = testnet_party_folding_at_tip();
    let (history, blk, at, out, tx) = lay_one_honest_spend(&mut node_a, 1411);
    assert_eq!(blk.tx_bodies.len(), 1, "CALIBRATION: the block carries its stated spend");
    let full = gossip_encode(&blk);
    let compact = gossip_encode_compact(&blk);
    let body = blk.tx_bodies[0].len();
    eprintln!("[c1] the spend block: full envelope {} B, compact {} B (the carried transaction {body} B)", full.len(), compact.len());
    // C3 MEASUREMENT — where a payment's bytes go (each field's own postcard length)
    let pc = |v: Result<Vec<u8>, postcard::Error>| v.map(|b| b.len()).unwrap_or(0);
    eprintln!(
        "[c3-bytes] payment {body} B: blob {} · member_carrier {} · spend_or_decoy {} · membership_carrier {} · nullifier_witnesses {} · nullifier_absence {} · output_notes {} · member_tuple {} · membership_tip {}",
        tx.blob.len(),
        tx.member_carrier.len(),
        tx.spend_or_decoy.len(),
        tx.membership_carrier.len(),
        pc(postcard::to_allocvec(&tx.nullifier_witnesses)),
        pc(postcard::to_allocvec(&tx.nullifier_absence)),
        tx.output_notes.len(),
        tx.member_tuple.len(),
        tx.membership_tip.len()
    );
    assert!(full.len() - compact.len() + 64 >= body, "⛔ the compact envelope still carries the transaction's bytes");
    // a peer that pooled the transaction through its own door
    let mut node_b = fresh_peer_node(&history);
    node_b.ingest_tx_prechecked(tx.clone()).expect("PRECONDITION: the peer pools the relayed transaction");
    let pooled = |n: &Node, id: &Hash32| n.mempool().get(id).and_then(|t| postcard::to_allocvec(t).ok());
    let rebuilt = match gossip_decode_compact(&compact, |id| pooled(&node_b, id)) {
        Some(CompactFill::Whole(b)) => b,
        other => panic!("⛔ a peer holding the transaction could not rebuild the block: {other:?}"),
    };
    assert_eq!(gossip_encode(&rebuilt), full, "⛔ the rebuilt block is not the full envelope's block byte for byte");
    assert_eq!(rebuilt.id(), blk.id(), "the rebuilt block is the block its id names");
    let outcome = node_b.ingest_block(rebuilt, at);
    assert!(matches!(outcome, RelayOutcome::Added(_)), "⛔ the peer refused the block it rebuilt from its own pool: {outcome:?}");
    assert!(node_b.holds_record_with_cm(&out), "⛔ the peer does not hold the payment of the block it rebuilt");
    // (1) a pool without the transaction
    assert!(
        matches!(gossip_decode_compact(&compact, |_| None), Some(CompactFill::Miss)),
        "⛔ a pool without the carried transaction rebuilt a block"
    );
    // (2) the same id, one byte different
    let mut twin = crate::chain_object::decode_exact::<PqTx>(&blk.tx_bodies[0]).expect("a transaction");
    let i = twin.member_carrier.len() / 2;
    twin.member_carrier[i] ^= 1;
    assert_eq!(twin.id, tx.id, "CALIBRATION: the differing copy carries the same id (the id names the blob alone)");
    let twin_bytes = postcard::to_allocvec(&twin).expect("encodes");
    assert_ne!(twin_bytes, blk.tx_bodies[0], "CALIBRATION: the copy's bytes differ");
    assert!(
        matches!(gossip_decode_compact(&compact, |id| (*id == tx.id).then(|| twin_bytes.clone())), Some(CompactFill::Miss)),
        "⛔ a pooled copy with other bytes under the same id rebuilt a block"
    );
    // a block that carries no transaction: its compact copy IS its full copy
    let quiet = &history.last().expect("history").0;
    assert_eq!(gossip_encode_compact(quiet), gossip_encode(quiet), "a block with nothing carried has one envelope");
}

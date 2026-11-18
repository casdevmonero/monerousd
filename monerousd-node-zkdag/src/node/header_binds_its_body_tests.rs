// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::header_binds_its_body_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::tests::{canon_nf_for_test, genesis_block, grind_tx};
use super::Node;
use crate::hash::Hash32;
use crate::relay::RelayOutcome;

/// ⛔ DB-223b — A TRANSITION FORGED ONTO A BLOCK IS REFUSED AT THE GOSSIP DOOR (the FORGE arm; MEASURED GREEN on
/// the tree before any fix: `ingest_block` verifies every carried `note_transition`, and a forged proof fails).
///
/// The OPEN arm, named here and pinned with the header root: `note_transition` / `cover_transition` are not folded
/// into the block id, and `None` is legal, so a relay can STRIP a genuine one and the copy keeps the block's id. A
/// peer holding no tx bodies then refuses the spend outputs a peer with the full copy records. That arm needs a
/// block with a genuine transition (a real spend), so it rides DB-223's two-node pin, where one header root binds
/// the note, cover and member transitions.
/// CALIBRATION: the honest block grafts.
/// TWO-PARTY-REVIEWED: one node produces; two fresh peers each receive one copy (the honest one, the tampered one).
/// ⛔⛔⛔ DB-223 — A BLOCK WHOSE GENUINE MEMBERSHIP TRANSITION WAS STRIPPED IN FLIGHT IS REFUSED (the STRIP arm).
///
/// The transition is the only evidence a body-less peer has that the block's spend inputs exist; stripped, the
/// copy kept the block's id (`None` is legal), so a peer grafting it would judge the spends against nothing while
/// every other peer judged them against the proof — two honest nodes, one id, two verdicts. With
/// `BlockHeader::transitions_root` in the preimage, the stripped copy no longer matches its header and the
/// gossip door refuses it. RED on the tree before the root by construction (the unbound field, `None` legal).
/// CALIBRATION: the block carrying its genuine transition grafts on a fresh peer.
/// TWO-PARTY-REVIEWED: one producer; two fresh peers, each fed one copy (the genuine, the stripped).
#[test]
fn db223b_a_block_whose_membership_transition_was_stripped_is_refused_by_the_gossip_door() {
    let mut producer = Node::new(genesis_block()).unwrap();
    let mut blk = producer.produce(5_000, Hash32::hash(b"fr"), Hash32::hash(b"mc")).expect("produced");
    // A GENUINE membership transition over this block's own notes root, sealed into the header and re-mined.
    let carriers = vec![
        crate::member_transition::test_member_carrier(1),
        crate::member_transition::test_member_carrier(2),
    ];
    blk.member_transition = crate::member_transition::build(&carriers, &blk.header.output_notes_root);
    assert!(blk.member_transition.is_some(), "PRECONDITION: the membership transition proves");
    blk.seal_transitions_root();
    super::tests::mine_fixture_block(&mut blk);
    let mut genuine_peer = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(genuine_peer.ingest_block(blk.clone(), 9_000), RelayOutcome::Added(_)),
        "CALIBRATION: the block carrying its genuine membership transition grafts"
    );
    let mut stripped = blk.clone();
    stripped.member_transition = None;
    assert_eq!(stripped.id(), blk.id(), "stripping a body field keeps the id — hence the header's commitment");
    let mut stripped_peer = Node::new(genesis_block()).unwrap();
    let got = stripped_peer.ingest_block(stripped, 9_000);
    assert!(
        matches!(got, RelayOutcome::Invalid(_)),
        "⛔⛔⛔ DB-223: a copy whose membership transition was STRIPPED kept the block's id and was admitted ({got:?})"
    );
}

#[test]
fn db223b_a_transition_forged_onto_a_block_is_refused_by_the_gossip_door() {
    let mut producer = Node::new(genesis_block()).unwrap();
    let blk = producer.produce(5_000, Hash32::hash(b"fr"), Hash32::hash(b"mc")).expect("produced");
    let mut honest_peer = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(honest_peer.ingest_block(blk.clone(), 9_000), RelayOutcome::Added(_)),
        "CALIBRATION: the honest block grafts"
    );
    let mut forged = blk.clone();
    forged.note_transition = Some(crate::note_transition::NoteTransition {
        tag_agg: Vec::new(),
        agg: vec![0xAB; 64],
        tuples: vec![0u8; crate::note_transition::TUPLE_BYTES],
        shape: [0; 8],
        clock_ms: 0,
        bodies: [0u8; 32],
    });
    let mut tampered_peer = Node::new(genesis_block()).unwrap();
    let got = tampered_peer.ingest_block(forged.clone(), 9_000);
    assert!(
        forged.id() != blk.id() || matches!(got, RelayOutcome::Invalid(_)),
        "⛔⛔⛔ DB-223b: a block carrying a FORGED note transition kept the honest block's id and was admitted \
         ({got:?}) — a relay can strip or replace a block's §BA justification and split two honest peers' records"
    );
}

/// ⭐⭐⭐ P2 — THE HEADER MUST COMMIT TO THE BODY, AND A TAMPERED BODY MUST BE REJECTED.
///
/// A receiver derives a block's id from its HEADER, so a commitment folded into the id does nothing
/// unless something CHECKS the body against it. `OutputNotesRootMismatch` was declared when
/// `output_notes_root` was added and was never returned from anywhere — so a relay could ship a block
/// whose notes did not match its own header commitment and every node accepted it under the same id.
///
/// The tag set is the spend-side twin and matters more now that A_tip folds at accept: strip or swap the
/// tags and two nodes hold ONE block id while folding DIFFERENT spend sets. The carried height-1 fold is
/// no defence — it is publicly re-provable in ~0 ms, so a tamperer mints a matching one.
///
/// TWO-PARTY: a producer builds a real block, a separate verifier accepts the honest copy and REFUSES
/// each tampered copy.
#[test]
fn a_verifier_refuses_a_block_whose_body_does_not_match_its_header_commitments() {
    let mut producer = Node::new(genesis_block()).unwrap();
    let need = producer.mempool().required_stamp_bits();
    let tx = grind_tx(b"p2-bind-tx", 1000, vec![canon_nf_for_test(b"p2-bind-nf")], need);
    producer
        .ingest_tx_unverified(tx)
        .expect("producer pools the tx");
    let blk = producer
        .produce(5_000, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
        .expect("producer mined a block");

    // CONTROL: the honest block is accepted by an independent verifier.
    let mut v = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v.ingest_block(blk.clone(), 9_000), RelayOutcome::Added(_)),
        "the honest block must graft — the binding may never refuse a well-formed block"
    );

    // TAMPER 1 — swap the carried NULLIFIER TAGS. Same header, same id, different spend set.
    let mut t1 = blk.clone();
    t1.nullifier_proof.padded_tags = vec![*canon_nf_for_test(b"swapped-tag").as_bytes()];
    assert_eq!(
        t1.id(),
        blk.id(),
        "the tamper does not change the id — which is exactly why a CHECK is required"
    );
    let mut v1 = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v1.ingest_block(t1, 9_000), RelayOutcome::Invalid(_)),
        "a block whose tag set does not match its header commitment MUST be refused — accepting it makes \
         two nodes fold DIFFERENT spends under one block id"
    );

    // TAMPER 2 — strip the tags entirely (the cheapest attack: costs the relay nothing).
    let mut t2 = blk.clone();
    t2.nullifier_proof.padded_tags.clear();
    let mut v2 = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v2.ingest_block(t2, 9_000), RelayOutcome::Invalid(_)),
        "a stripped tag set must be refused, not folded as an empty set"
    );

    // TAMPER 3 — alter the OUTPUT NOTES. This is the half that was declared and never enforced.
    let mut t3 = blk.clone();
    t3.output_notes = vec![9u8; 1153];
    let mut v3 = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v3.ingest_block(t3, 9_000), RelayOutcome::Invalid(_)),
        "a block whose notes do not match its header commitment MUST be refused — this is the defect the \
         `OutputNotesRootMismatch` variant was written for and never returned from"
    );
}

/// ⭐⭐⭐ P4′a — A STRIPPED FINDABILITY SIDECAR MUST BE REFUSED, NOT SILENTLY ACCEPTED.
///
/// This is the FUND-LOSS half of the same class, and it is nastier than the two above because it is
/// invisible: strip a block's `oli_tags` and the block still validates, still carries every note, still
/// folds the same spends — the notes simply enter NO locator index on the receiving node, so their owner
/// can never find them from their seed and can never spend them. Measured exactly that way on 2026-08-10:
/// node A indexed 4 tags, node B ingested the SAME blocks and indexed 2, and send 2's money sat on chain
/// invisible to its owner. `account_targets` is the same story one layer over — stripped, the recipient's
/// own node files nothing and serves an empty bucket.
///
/// It is also the precondition for P4′b: a restarted node rebuilds its locator index from sidecars an
/// ARBITRARY peer hands it, and the only thing that makes an arbitrary peer safe to accept from is that
/// the block id binds what it serves.
///
/// TWO-PARTY, and each tamper asserts `t.id() == blk.id()` first — which is precisely why a check is
/// required rather than relying on the id alone.
#[test]
fn a_verifier_refuses_a_block_whose_findability_sidecars_were_stripped_or_forged() {
    let mut producer = Node::new(genesis_block()).unwrap();
    let need = producer.mempool().required_stamp_bits();
    let mut tx = grind_tx(
        b"p4a-bind-tx",
        1000,
        vec![canon_nf_for_test(b"p4a-bind-nf")],
        need,
    );
    // ⛔ THE BLOCK MUST ACTUALLY CARRY A TAG, OR "STRIP THE TAGS" IS A NO-OP AND PROVES NOTHING.
    //
    // A `grind_tx` carries no output notes, so the block it lands in ships only the cover ENTROPY note
    // and `oli_tags` is empty — clearing an empty vec leaves the block byte-identical and any verifier
    // rightly accepts it. (Caught exactly that way: the first run of this test passed its own strip.)
    // So give the tx a real output note, register that note's locator clue the way an accepted tx does
    // (`record_note_clue` -> `pending_tags`), and the produce-time carry then attaches a REAL tag.
    // `stamp_work` covers only `id` + `pow_stamp`, so attaching notes after the grind keeps the stamp valid.
    let note = vec![7u8; crate::cover::PQ_NOTE_BYTES];
    let mut note_cm = [0u8; 32];
    note_cm.copy_from_slice(&note[0..32]);
    tx.output_notes = note.clone();
    let loc_sk = crate::oli::derive_loc_sk(blake3::hash(b"MUSD/oli/p4a/recipient").as_bytes());
    let clue = crate::oli::tag_clue_bytes(&crate::oli::locator_at(&loc_sk, "recv", 0));
    producer.record_note_clue(note_cm, clue);
    // Same reasoning for the OTHER sidecar: stage this note's account-DA target (the way `/submit_pq_tx`
    // stages one into `pending_bucket`) so the produce-time carry has a real target to attach and the
    // strip below is a real strip.
    producer.record_account_target(
        note_cm,
        *blake3::hash(b"MUSD/p4a/bucket").as_bytes(),
        vec![3u8; 32],
        None,
    );
    producer
        .ingest_tx_unverified(tx)
        .expect("producer pools the tx");
    let blk = producer
        .produce(5_000, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
        .expect("producer mined a block");
    // PRECONDITION, asserted rather than assumed: there is a tag here to strip.
    assert!(
        !blk.oli_tags.is_empty(),
        "the produced block must actually carry a locator tag, or the strip tamper below is vacuous"
    );
    // H5 / DB-273 (C): the per-wallet bucket linker is retired — a block carries NO account targets by
    // consensus (`validate_full_body_commitments` → `AccountTargetsCarried`). The target staged above is the
    // legacy hand-off a stale wallet can still make; the producer must drop it, never seal it.
    assert!(
        blk.account_targets.is_empty(),
        "⛔ the producer sealed a staged account target into its block — the retired bucket linker rides the wire"
    );

    // CONTROL: the honest block grafts. The producer seals both sidecar roots in `produce_template`
    // BEFORE the off-lock mine, so a well-formed block must never be refused by this binding.
    let mut v = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v.ingest_block(blk.clone(), 9_000), RelayOutcome::Added(_)),
        "the honest block must graft — the sidecar binding may never refuse a well-formed block"
    );

    // TAMPER 1 — STRIP the locator tags. The cheapest attack in the whole family: it costs the relay
    // nothing, leaves a perfectly valid-looking block, and permanently unfinds every note in it.
    let mut t1 = blk.clone();
    t1.oli_tags.clear();
    assert_eq!(
        t1.id(),
        blk.id(),
        "stripping the tags does not change the id — which is exactly why a CHECK is required"
    );
    let mut v1 = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v1.ingest_block(t1, 9_000), RelayOutcome::Invalid(_)),
        "a block whose locator tags were stripped MUST be refused — accepting it puts every note in it \
         outside the locator index, so its owner can never find or spend the money"
    );

    // TAMPER 2 — FORGE a locator tag. A garbage tag is worse than none: it occupies the index slot, so
    // the owner's own PIR probe resolves to nothing while the block looks fully tagged.
    let mut t2 = blk.clone();
    t2.oli_tags = vec![7u8; 32 + crate::oli::K_BYTES];
    assert_eq!(
        t2.id(),
        blk.id(),
        "forging a tag does not change the id either"
    );
    let mut v2 = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v2.ingest_block(t2, 9_000), RelayOutcome::Invalid(_)),
        "a forged locator tag must be refused, not indexed"
    );

    // TAMPER 3 — INJECT account targets in flight. Since H5 / DB-273 (C) the honest sidecar is EMPTY, so the
    // attack on it is no longer a strip but a relay that adds the retired per-wallet bucket linker (cm ‖
    // bucket ‖ recipient key) to an honest block: the id does not move, and a node that admitted it would
    // file and serve a linker that names which notes share one recipient.
    let mut t3 = blk.clone();
    t3.account_targets = [note_cm.as_slice(), blake3::hash(b"MUSD/p4a/bucket").as_bytes(), &[3u8; 32]].concat();
    assert_eq!(
        t3.id(),
        blk.id(),
        "injecting targets does not change the id either"
    );
    let mut v3 = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v3.ingest_block(t3, 9_000), RelayOutcome::Invalid(_)),
        "a block carrying injected account targets MUST be refused — the retired bucket linker may never \
         re-enter a node through a relay"
    );
}

/// ⭐⭐⭐ THE BOND CARRIER'S HEADER BINDING — same tamper pair as the deletion set above: a block's
/// carried validator-bond set can be neither STRIPPED nor SWAPPED in flight without becoming a
/// refused block, because `bond_set_root` rides the header preimage unconditionally.
#[test]
fn header_binds_its_bond_set_a_stripped_or_forged_one_is_refused() {
    const N: usize = 1153;
    let mut producer = Node::new(genesis_block()).unwrap();
    let need = producer.mempool().required_stamp_bits();
    // A bond-shaped tx (bond_notes >= 40) so the produced block CARRIES a non-empty bond_set —
    // otherwise "strip the set" is a no-op and proves nothing (the oli-tags test's lesson).
    let (pk, _sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let base = grind_tx(
        b"bond-bind-tx",
        1000,
        Vec::new() /* DB-73 (2026-09-19): a bond entry rides on its bond_notes, not on a spend; a two-output tx WITH a nullifier and no carrier is a USDm spend the template evicts at no depth */,
        need,
    );
    let mut output_notes = vec![0u8; 2 * N];
    output_notes[..32].copy_from_slice(&[0xD0u8; 32]);
    output_notes[N..N + 32].copy_from_slice(&[0xD1u8; 32]);
    let mut bond_notes = vid.to_vec();
    bond_notes.extend_from_slice(&5_000u64.to_le_bytes());
    producer
        .ingest_tx_unverified(crate::mempool::PqTx {
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            output_notes,
            bond_notes,
            ..base
        })
        .expect("pooled");
    let blk = producer
        .produce(5_000, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
        .expect("produced");
    assert!(
        crate::block::sidecar_real_len(&blk.bond_set) > 0,
        "PRECONDITION: the block carries a bond entry to strip"
    );
    assert_eq!(
        blk.header.bond_set_root,
        crate::block::da_sidecar_root_of(
            &blk.bond_set[..crate::block::sidecar_real_len(&blk.bond_set)]
        ),
        "the producer sealed the root over its real carry"
    );

    // The honest block grafts (the fake entry is refused at APPLY, never the block itself —
    // liveness: a bad item drops, chain progress is untouched).
    let mut v = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v.ingest_block(blk.clone(), 9_000), RelayOutcome::Added(_)),
        "the honest block must graft — the bond binding may never refuse a well-formed block"
    );

    // TAMPER 1 — STRIP the bond set: a relay could otherwise blind every ingesting peer's quorum
    // under the SAME block id (the exact validators=0 island this carrier exists to close).
    let mut t1 = blk.clone();
    t1.bond_set.clear();
    assert_eq!(
        t1.id(),
        blk.id(),
        "stripping bond_set does not change the id — hence the check"
    );
    let mut v1 = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v1.ingest_block(t1, 9_000), RelayOutcome::Invalid(_)),
        "a block whose bond set was stripped MUST be refused"
    );

    // TAMPER 2 — SWAP in a forged bond set under the same id.
    let mut t2 = blk.clone();
    t2.bond_set = blake3::hash(b"bondset-forged").as_bytes().to_vec();
    assert_eq!(
        t2.id(),
        blk.id(),
        "forging bond_set does not change the id either"
    );
    let mut v2 = Node::new(genesis_block()).unwrap();
    assert!(
        matches!(v2.ingest_block(t2, 9_000), RelayOutcome::Invalid(_)),
        "a forged bond set must be refused, not applied"
    );
}

/// ⭐⭐⭐ THE APPLY GATE IS SOUND, NEVER TRUSTING: a carried bond entry that decodes but cannot
/// re-pass the admission welds (no WHIR carrier, no membership fold) admits NO validator and
/// locks NO note — on the producer AND on an empty-mempool ingester. Malformed framing refuses
/// the tail without panicking. (The POSITIVE path — a real wallet bond with real carriers
/// admitting on every node — is the live-testnet proof this unit gate pairs with.)
#[test]
fn a_forged_carried_bond_admits_no_validator() {
    const N: usize = 1153;
    let mut producer = Node::new(genesis_block()).unwrap();
    let mut ingester = Node::new(genesis_block()).unwrap();
    let need = producer.mempool().required_stamp_bits();
    let (pk, _sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let base = grind_tx(
        b"bond-forge-tx",
        1000,
        Vec::new() /* DB-73 (2026-09-19): a bond entry rides on its bond_notes, not on a spend; a two-output tx WITH a nullifier and no carrier is a USDm spend the template evicts at no depth */,
        need,
    );
    let mut output_notes = vec![0u8; 2 * N];
    output_notes[..32].copy_from_slice(&[0xE0u8; 32]);
    output_notes[N..N + 32].copy_from_slice(&[0xE1u8; 32]);
    let mut bond_notes = vid.to_vec();
    bond_notes.extend_from_slice(&7_777u64.to_le_bytes());
    producer
        .ingest_tx_unverified(crate::mempool::PqTx {
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            output_notes,
            bond_notes,
            ..base
        })
        .expect("pooled");
    let blk = producer
        .produce(5_000, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
        .expect("produced");
    assert!(
        !blk.bond_set.is_empty(),
        "PRECONDITION: a bond entry rides the block"
    );

    // The producer itself refused its own unproven entry (one gate, both entry points).
    assert_eq!(
        producer.validators().bond_of(&vid),
        0,
        "no carrier ⇒ no weight, even on the producer"
    );

    // The empty-mempool ingester grafts the block and refuses the entry identically.
    assert!(
        matches!(ingester.ingest_block(blk, 9_000), RelayOutcome::Added(_)),
        "block grafts"
    );
    assert_eq!(
        ingester.validators().bond_of(&vid),
        0,
        "no carrier ⇒ no weight on the ingester"
    );
    assert_eq!(
        ingester.validators().len(),
        0,
        "the forged entry admitted nobody"
    );

    // Malformed framing: a length prefix pointing past the buffer refuses the tail, no panic,
    // nothing admitted.
    let mut junk = Vec::new();
    junk.extend_from_slice(&(1_000_000u32).to_le_bytes());
    junk.extend_from_slice(&[0xAB; 16]);
    ingester.apply_bond_set(&junk, 1, &[], &[], None);
    assert_eq!(
        ingester.validators().len(),
        0,
        "malformed framing admits nobody"
    );
}

/// ⭐ THE FINALITY QUORUM SURVIVES A SNAPSHOT — the v25 fields carry the set out and back, so a
/// restart no longer empties `validators` (the every-reboot finality kill this closes).
#[test]
fn the_bonded_validator_set_survives_a_snapshot_roundtrip() {
    let mut node = Node::new(genesis_block()).unwrap();
    node.produce(5_000, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
        .expect("produced");
    let (pk, _sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    node.admit_bond_unverified(vid, 5_000, vec![0x77u8; 1153], 1);
    let snap = node.export_snapshot().expect("snapshot");
    assert_eq!(
        snap.bonded_validators,
        vec![(vid, 5_000u128)],
        "the quorum rides the snapshot"
    );
    // Round-trip through the ValidatorSet import (the resume path's exact call).
    let mut fresh = Node::new(genesis_block()).unwrap();
    assert_eq!(fresh.validators().len(), 0);
    fresh.validators.import_state(
        snap.bonded_validators.clone(),
        snap.slashed_validators.clone(),
        snap.slashed_bond_burned,
        snap.validator_bond_commit,
        snap.validator_custody.clone(),
    );
    fresh.validators.import_finality_state(snap.finality_validators.clone()); // SATOSHI §6
    assert_eq!(
        fresh.validators().bond_of(&vid),
        5_000,
        "the resumed node weighs the same quorum"
    );
    assert_eq!(
        fresh.validators().total_bond(),
        5_000,
        "totals recomputed from the restored bonds"
    );
}


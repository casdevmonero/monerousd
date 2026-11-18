// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `note_transition::tests` — the tests of `note_transition` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `note_transition` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`note_transition::tests::…`), and `use super::*` reaches `note_transition`'s items through the node's re-export.

// the imports of `note_transition` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use crate::spend_frontier::Digest4;
#[allow(unused_imports)]
use usdm_decider::hiding_decider::Fa4;

use super::*;
use usdm_decider::poseidon2_compress::lanes_of;
use usdm_decider::whir_rec_block::{
    asset_note_cm, prove_spend_validity_carrier_with_commit_bytes, SpendValidityWitness,
    USDM_ASSET_TAG,
};

/// A REAL spend, proved the way production proves one, with the tuple the submission path derives.
/// ⭐ No Merkle path: the spend gate's path was pure width (§BY) and is deleted (gate D, 2026-09-30); membership
/// rides the accumulator, cross-bound by the blinded `leaf_commit`. `lc_blind` is PER SPEND, as a wallet draws it:
/// it also keys the spend's claim tag (`tag1 = slot_claim(lc_blind, 0)`), so one shared fixture blind gave every
/// spend of a block the same tag — a repeat the spent set and the §3.2 door both refuse.
/// The witness one spend stands over, split out so a gate can ask the PRODUCTION prover about the
/// same spend the tuple describes (§BB needs the spent note's own leaf, not just the tuple).
fn witness(i: u64) -> SpendValidityWitness {
    let sk = lanes_of(&[11 + i, 12, 13, 14]);
    let _ = asset_note_cm(5 + i, USDM_ASSET_TAG, lanes_of(&[1, 2, 3, 4]));
    SpendValidityWitness {
        value_in: 900 + i + 99900, // §BR-14: the input funds the protocol fee
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(sk),
        value_out: 800 + i,
        fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
        lc_blind: lanes_of(&[0x1cb1, i, 9, 9]),
        out0_value: 750 + i,
        out0_opening: lanes_of(&[7, 7, 7, 7]),
        out1_value: 50,
        out1_opening: sk,
    }
}

/// A real spend with no clue filed: `(blob, tuple, D)`, and a block filing nothing (`oli_tags` empty) verifies it.
fn spend(i: u64) -> (Vec<u8>, SpendTuple, Digest4) {
    let w = witness(i);
    let (blob, cms, nf, lc, d) = prove_unfiled_spend(&w).expect("the production spend proves");
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let tag1 = b(usdm_decider::whir_rec_block::spend_tag1(&w));
    (blob, SpendTuple { out0_cm: b(cms[0]), out1_cm: b(cms[1]), nullifier: b(nf), leaf_commit: b(lc), tag1 }, d)
}

fn roots2() -> (crate::hash::Hash32, crate::hash::Hash32) {
    (crate::hash::Hash32::hash(b"onr"), crate::hash::Hash32::hash(b"dsr"))
}

/// ⭐⭐⭐ DB-351 — A BLOCK'S TRANSITION VERIFIES ONLY UNDER THE FILING ITS SPENDS BOUND (the graft/ingress door).
///
/// The producer or a relay controls `Block::oli_tags`, the locator tags every peer FILES. Each spend's carrier bound
/// D over its outputs' `(cm, k)`, and a peer recomputes D from the block's tags, so the block verifies only if it
/// files exactly what each payer bound: a STRIPPED tag, a REWRITTEN key, an ADDED tag for an output the payer filed
/// nothing for, and a DUPLICATED record each refuse. A tag for some other note of the block changes nothing.
/// TWO-PARTY-REVIEWED: the producer's `build` and the peer's `verify` are the two parties, each the production
/// function; the peer holds no transaction body, only the block's own bytes.
#[test]
fn db351_a_transition_verifies_only_under_the_filing_its_spends_bound() {
    const K: usize = crate::oli::K_BYTES;
    let k = [7u8; K];
    let (blob, cms, nf, lc, d) = prove_filed_spend(&witness(60), [None, Some(k)]).expect("a filed spend proves");
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let tag1 = b(usdm_decider::whir_rec_block::spend_tag1(&witness(60)));
    let t = SpendTuple { out0_cm: b(cms[0]), out1_cm: b(cms[1]), nullifier: b(nf), leaf_commit: b(lc), tag1 };
    let (onr, _dsr) = roots2();
    let nt = build(&[(blob, t, d)], &onr).expect("the producer lays the transition");
    let tag = |cm: &[u8; 32], k: &[u8; K]| [cm.as_slice(), k.as_slice()].concat();
    let honest = tag(&t.out1_cm, &k);
    assert!(verify(&nt, &onr, &honest).is_some(), "CALIBRATION: the block filing exactly the bound key verifies");
    let unrelated = [honest.clone(), tag(&[9u8; 32], &[3u8; K])].concat();
    assert!(verify(&nt, &onr, &unrelated).is_some(), "a tag for another note of the block changes nothing");
    assert!(verify(&nt, &onr, &[]).is_none(), "⛔⛔ a block that STRIPPED the payer's tag verified — it settles unfiled");
    assert!(
        verify(&nt, &onr, &tag(&t.out1_cm, &[8u8; K])).is_none(),
        "⛔⛔ a block that REWROTE the payer's key verified — the note files under a relay's locator"
    );
    let added = [honest.clone(), tag(&t.out0_cm, &k)].concat();
    assert!(verify(&nt, &onr, &added).is_none(), "⛔⛔ a block that ADDED a tag the payer never filed verified");
    let duplicated = [honest.clone(), honest.clone()].concat();
    assert!(verify(&nt, &onr, &duplicated).is_none(), "⛔ a filing naming one cm twice is ambiguous and must refuse");
    assert!(verify(&nt, &onr, &honest[..honest.len() - 1]).is_none(), "⛔ a torn tag record must refuse");
}

/// DB-329 §7e/§7g — THE CLAIM RACE, two parties: A and B each pool a CLAIMING send of ONE slot `(key, d)` from a
/// DIFFERENT input, each lays it in its own block (X, Y — siblings, neither heard of the other), both graft both and
/// fold. Production's shape in miniature: fold lag 2, so the siblings meet while BOTH are unfolded (the DB-358
/// contest, decided in canonical order). Returns the parties, the two sends' first outputs and input nullifiers.
#[allow(clippy::type_complexity)]
fn claim_race() -> (crate::node::Node, crate::node::Node, [[u8; 32]; 2], [crate::hash::Hash32; 2]) {
    use crate::hash::Hash32;
    use crate::node::tests::{genesis_block, grind_tx};
    use crate::node::Node;
    // DB-223 Q7: both inputs are FUNDED on chain — the testnet identity admits the funding credit (DB-354).
    let mut a = crate::node::tests::testnet_party_with_fold_depth(2);
    let mut b = crate::node::tests::testnet_party_with_fold_depth(2);
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let (key, d) = (lanes_of(&[0x5107, 0xde71, 3, 4]), 1u64);
    let w = |k: u64| SpendValidityWitness {
        value_in: 1_000_000_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x329, k, 2, 2])),
        value_out: (1_000_000_000) - 100000,
        fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
        lc_blind: lanes_of(&[0x363, k, 9, 9]),
        out0_value: (999_999_000) - 100000,
        out0_opening: lanes_of(&[k, 1, 1, 1]),
        out1_value: 1_000,
        out1_opening: lanes_of(&[7, k, 1, 1]),
    };
    // DB-223 Q7: both inputs EXIST — funded in one block both nodes fold (A lays it plus `record_fold_depth` more, B
    // grafts all of them) — and each send proves its input from its own node's stream (its member leg).
    let (w1, w2) = (w(1), w(2));
    let tip_ts = |n: &Node| n.dag().get(&n.selected_tip().expect("tip")).expect("hdr").header.timestamp;
    let mut fts = tip_ts(&a) + a.params().target_spacing_ms;
    let funded = crate::node::tests::fund_inputs_for_test(&mut a, &mut [&mut b], &[&w1, &w2], fts);
    for i in 0..2u64 {
        fts += a.params().target_spacing_ms;
        let blk = a.produce(fts, Hash32::hash(&i.to_le_bytes()), Hash32::hash(b"claim-race-fold")).expect("A lays a fold block");
        assert!(matches!(b.ingest_block(blk, fts + 1), crate::relay::RelayOutcome::Added(_)), "B grafts it");
    }
    let _ = (a.fold_canonical_records(), b.fold_canonical_records());
    let spend = |node: &Node, w: &SpendValidityWitness, pad: &str, input: &[u8; 32]| {
        // The wallet's shape: a locator clue filed for BOTH outputs and the carrier proven under that filing's D.
        let clues: [Vec<u8>; 2] = [0u8, 1].map(|j| format!("{pad}-clue-{j}").into_bytes());
        let keys = [Some(crate::oli::index_key(&clues[0])), Some(crate::oli::index_key(&clues[1]))];
        let (blob, cms, nf, lc, _d, tag1) = prove_filed_claiming_spend(w, key, d, keys).expect("the claiming spend proves");
        let mut records: Vec<([u8; 32], Vec<u8>)> = vec![(b32(cms[0]), clues[0].clone()), (b32(cms[1]), clues[1].clone())];
        records.sort();
        let mut output_notes = Vec::with_capacity(2 * crate::cover::PQ_NOTE_BYTES);
        for cm in cms {
            let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            n[..32].copy_from_slice(&b32(cm));
            output_notes.extend_from_slice(&n);
        }
        let mut tx = grind_tx(&blob, blob.len() as u32, test_tag_list_claiming(nf, w, key, d, pad), node.mempool().required_stamp_bits());
        tx.output_notes = output_notes;
        tx.note_clues = Node::encode_note_clue_records(&records);
        tx.membership_leaf_commit = b32(lc);
        crate::node::tests::attach_member_leg_for_test(node, &mut tx, input, w, nf, &cms);
        (tx, b32(cms[0]), Hash32(b32(nf)), tag1)
    };
    let (txa, outa, nfa, ta) = spend(&a, &w1, "claim-race-a", &funded[0]);
    let (txb, outb, nfb, tb) = spend(&b, &w2, "claim-race-b", &funded[1]);
    assert_eq!(ta, tb, "CALIBRATION: both sends claim ONE slot");
    assert_ne!(nfa, nfb, "CALIBRATION: from two DIFFERENT inputs");
    a.ingest_tx_unverified(txa).expect("A pools its claiming send");
    b.ingest_tx_unverified(txb).expect("B, having heard nothing of A's, pools its own");
    let next = |n: &Node| {
        n.dag().get(&n.selected_tip().expect("tip")).expect("hdr").header.timestamp + n.params().target_spacing_ms
    };
    let (ts_a, ts_b) = (next(&a), next(&b));
    let x = a.produce(ts_a, Hash32::hash(b"claim-race-x"), Hash32::hash(b"claim-race-mc-a")).expect("A lays X");
    let y = b.produce(ts_b, Hash32::hash(b"claim-race-y"), Hash32::hash(b"claim-race-mc-b")).expect("B lays Y");
    let carries = |notes: &[u8], cm: [u8; 32]| notes.chunks(crate::cover::PQ_NOTE_BYTES).any(|n| n.len() >= 32 && n[..32] == cm);
    assert!(carries(&x.output_notes, outa), "CALIBRATION: X carries A's claiming send");
    assert!(carries(&y.output_notes, outb), "CALIBRATION: Y carries B's claiming send");
    assert!(x.note_transition.is_some() && y.note_transition.is_some(), "CALIBRATION: X and Y each STATE their claiming send");
    let now = ts_a.max(ts_b) + 400;
    assert!(matches!(a.ingest_block(y, now), crate::relay::RelayOutcome::Added(_)), "A grafts B's sibling");
    assert!(matches!(b.ingest_block(x, now), crate::relay::RelayOutcome::Added(_)), "B grafts A's sibling");
    let _ = a.fold_past_for_test(&mut [&mut b], now, b"claim-race-fold");
    eprintln!(
        "[db329-claim-race] recorded: A a={} b={} | B a={} b={}; input spent: A a={} b={} | B a={} b={}",
        a.holds_record_with_cm(&outa), a.holds_record_with_cm(&outb),
        b.holds_record_with_cm(&outa), b.holds_record_with_cm(&outb),
        a.is_nullifier_spent(&nfa), a.is_nullifier_spent(&nfb), b.is_nullifier_spent(&nfa), b.is_nullifier_spent(&nfb)
    );
    (a, b, [outa, outb], [nfa, nfb])
}

/// ⭐⭐ DB-329 §7e — TWO CLAIMS OF ONE SLOT IN SIBLING BLOCKS: EXACTLY ONE LANDS, THE SAME ONE ON BOTH PARTIES. The
/// fold treats the claim tag as one of the spend item's tags (`respend_items`), so the two sends are ONE contest,
/// decided in canonical order; the loser's outputs are revoked. The verdict is read from what each PEER holds.
/// TWO-PARTY-REVIEWED: A and B each produce and each graft the other's block; the claims are about both parties' state.
#[test]
fn db329_two_claims_of_one_slot_in_sibling_blocks_land_exactly_one_on_both_parties() {
    let (a, b, outs, _nfs) = claim_race();
    let held = |n: &crate::node::Node| [n.holds_record_with_cm(&outs[0]), n.holds_record_with_cm(&outs[1])];
    let (ha, hb) = (held(&a), held(&b));
    assert_eq!(u8::from(ha[0]) + u8::from(ha[1]), 1, "⛔⛔ A recorded {} claims of ONE slot", u8::from(ha[0]) + u8::from(ha[1]));
    assert_eq!(u8::from(hb[0]) + u8::from(hb[1]), 1, "⛔⛔ the peer B recorded {} claims of ONE slot", u8::from(hb[0]) + u8::from(hb[1]));
    assert_eq!(ha, hb, "⛔⛔ A and the peer B let DIFFERENT claims win");
}

/// ⛔⛔⛔ DB-329 §7g — THE LOSING CLAIM KEEPS ITS INPUT, ON BOTH PARTIES (the claim twin of DB-358 residual 5). The fold
/// revokes the loser's OUTPUTS, but at graft the spent-set view folds the grafted block's whole lane, so the loser's
/// input nullifier reads as spent with nothing to show for it. EXPECTED RED until DB-353 band landing 2 makes the band
/// (header lane minus the losers) the spent-set authority; the wallet's claim sends stay OFF until it is green.
/// TWO-PARTY-REVIEWED: A and B each produce and graft; the claim is about both parties' spent sets.
#[test]
fn db329_r5_the_losing_claim_keeps_its_input_on_both_parties() {
    let (a, b, outs, nfs) = claim_race();
    for (i, (out, nf)) in outs.iter().zip(nfs.iter()).enumerate() {
        assert!(a.holds_record_with_cm(out) || !a.is_nullifier_spent(nf), "⛔⛔⛔ on A, the losing claim {i}'s input is spent");
        assert!(b.holds_record_with_cm(out) || !b.is_nullifier_spent(nf), "⛔⛔⛔ on the peer B, the losing claim {i}'s input is spent");
    }
}

/// ⭐⭐ DB-329 §7f — THE CLAIM TAG IS PART OF WHAT A BLOCK STATES, AND ONLY THE CARRIER'S OWN CLAIM IS.
/// CALIBRATION: the honest tuple's carrier verifies, the producer lays it, and a peer holding only the block admits
/// both its nullifier AND its claim tag as deletions (the spent SET takes both). REFUSALS: the template refuses a
/// tuple whose tag1 is another send's claim (`carrier_verifies` false, so it is never laid); whatever the producer's
/// prover emits over that lie (`build` does not self-verify — MEASURED 08:45, it returned an aggregate), no peer
/// admits it; and a peer handed the honest aggregate with row 1 of a tuple rewritten admits nothing.
/// TWO-PARTY-REVIEWED: the producer's `build` and the peer's `verify` are the two parties, each the production
/// function; the peer holds no transaction body, only the block's own bytes.
#[test]
fn db329_a_tuple_whose_claim_tag_is_not_the_carriers_is_neither_laid_nor_admitted() {
    let (blob, t, d) = spend(71);
    assert!(carrier_verifies(&blob, &t, d), "CALIBRATION: the honest tuple's carrier verifies");
    let (onr, _dsr) = roots2();
    let nt = build(&[(blob.clone(), t, d)], &onr).expect("the producer lays the honest transition");
    let a = verify(&nt, &onr, &[]).expect("a peer admits the honest transition");
    assert!(a.admits_deletion(&t.nullifier), "the nullifier is admitted into the spent set");
    assert!(a.admits_deletion(&t.tag1), "the claim tag is admitted into the spent set beside it");
    let other_claim = crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::ordinary_claim_tag(
        usdm_decider::poseidon2_compress::lanes_of(&[0x363, 99, 98, 97]),
    ));
    let lying = SpendTuple { tag1: other_claim, ..t };
    assert!(!carrier_verifies(&blob, &lying, d), "⛔ a carrier verified under another send's claim tag");
    match build(&[(blob, lying, d)], &onr) {
        None => eprintln!("[db329] the producer's prover refused the lying tuple outright"),
        Some(forged) => {
            assert!(
                verify(&forged, &onr, &[]).is_none(),
                "⛔⛔ a peer admitted a transition stating a claim its carrier never proved"
            );
            eprintln!("[db329] the producer emitted an aggregate over the lying tuple; the peer refused it");
        }
    }
    let mut rewritten = nt.clone();
    rewritten.tuples[4 * 32..5 * 32].copy_from_slice(&other_claim);
    assert!(verify(&rewritten, &onr, &[]).is_none(), "⛔ a peer admitted a block whose row-1 claim was rewritten");
}

/// DB-73 (run 84, two real nodes): the wallet proved a send at SPEND_TREE_DEPTH while the producer laid the block
/// aggregate at depth 0 — its OWN verifier refused it and, one run earlier, the peer refused the block as
/// InvalidSettlement and forked at the first real spend. Gate D (the depth-d path) is DELETED (2026-09-30); the
/// class that pin guarded is closed by construction: `carrier_verifies` names no depth, a template keeps exactly
/// the spends whose carriers verify under their statement, and the aggregate over them verifies on every peer.
/// TAMPER: a tuple that is not the carrier's statement does not verify, so it is never laid.
#[test]
fn the_template_keeps_exactly_the_spends_whose_carriers_verify_and_lays_them_with_no_depth() {
    let (blob0, t0, d0) = spend(41);
    assert!(carrier_verifies(&blob0, &t0, d0), "the door's verifier accepts the honest carrier under its statement");
    let mut moved = t0;
    moved.leaf_commit[0] ^= 1;
    assert!(!carrier_verifies(&blob0, &moved, d0), "TAMPER: a tuple naming another cross-bind is not this carrier's");
    let (onr, _dsr) = roots2();
    let laid0 = build(&[(blob0, t0, d0)], &onr).expect("laid");
    assert!(
        verify(&laid0, &onr, &[]).is_some(),
        "⛔ the aggregate over a verified carrier must verify — the peer's gate and the producer's are one"
    );
}

/// ⭐⭐⭐ §CD RESOLVED 2026-09-15 — THE CARRIER **MUST NOT** BE BYTE-DETERMINISTIC. THAT IS PILLAR-1.
///
/// The block's nullifier DECOY SEED is derived from its nullifier-bearing transaction BLOBS (node.rs:
/// "the decoy seed is derived from the block's nullifier-bearing tx BLOBS, which are confidential").
/// A blob is a spend CARRIER. So if proving the same witness twice produces different bytes, two nodes
/// replaying the same chain derive different decoys, different `nf_acc` and different `nf_root` — which
/// is a fork, and it is invisible until something actually proves a carrier on a replay path.
///
/// MEASURED 2026-09-15, the moment the fuzz corpus began proving real carriers: five pins went red with
/// one signature — `uns_root`, `uns_fold`, `uns_leaves` and `nf_count` IDENTICAL across two replays of
/// the same (parties, seed, ops), and `nf_acc`/`nf_root` DIFFERENT. Everything the unspent side touches
/// agreed; only the nullifier accumulator moved. That is the shape a nondeterministic carrier makes.
///
/// §CA already recorded that Plonky3's graph-wide `parallel` feature makes proving nondeterministic —
/// `409739 B vs 409739 B, equal=false` at 10 threads — and turned it OFF for exactly this reason. This
/// asks the question again at the node's own entry point, because the decider now takes rayon directly.
#[test]
fn proving_the_same_spend_twice_must_differ_because_the_carrier_is_blinded() {
    let w = witness(3);
    let a = prove_unfiled_spend(&w).expect("prove 1");
    let b = prove_unfiled_spend(&w).expect("prove 2");
    eprintln!(
        "[§CD] carrier bytes: {} vs {} · equal={} · nullifier equal={} · leaf_commit equal={}",
        a.0.len(),
        b.0.len(),
        a.0 == b.0,
        a.2 == b.2,
        a.3 == b.3
    );
    //
    //   [§CD] carrier bytes: 138010 vs 138010 · equal=false · nullifier equal=true · leaf_commit equal=true
    //
    // ⭐ AND THAT INEQUALITY IS THE CORRECT ANSWER — I FILED IT AS A DEFECT AND IT IS NOT ONE.
    //
    // The spend carrier is proved through `committed_air::prove_air_blinded_bytes`, which draws fresh
    // OS entropy for its blinding and says why in as many words: *"this refuses to prove rather than
    // blinding with something predictable. A carrier that looks blinded but is not would leak exactly
    // as much as an unblinded one, with nobody looking."* A zero-knowledge proof producing IDENTICAL
    // bytes for the same statement would let an observer confirm two proofs are about the same spend —
    // a linkage leak, which is the privacy pillar. So byte-inequality is REQUIRED, and this gate now
    // asserts it rather than filing it.
    //
    // ⛔ WHAT I GOT WRONG, RECORDED SO THE NEXT READER DOES NOT REPEAT IT. I reasoned from §CA — which
    // measured a REAL nondeterminism in the aggregate prover and turned Plonky3's graph-wide `parallel`
    // off for it — and assumed the same signature meant the same cause. It did not: §CA's was an
    // unintended parallel-reduction artefact in a prover that must be reproducible; this is deliberate
    // blinding in a prover that must not be. The measurement was right; the diagnosis was wrong.
    //
    // NOTHING REQUIRES THE CARRIER TO BE REPRODUCIBLE. A wallet proves ONCE and gossips the bytes, so
    // every node folds the identical blob; and since §CE the nullifier decoy seed folds the block's
    // CARRIED TAGS rather than those blobs, so no accumulator depends on them either. The fuzz
    // fixture memoises one carrier per spend (`Node::test_spend_carrier`) because that is exactly what
    // production does — prove once, ship the bytes.
    assert_ne!(
        a.0, b.0,
        "⛔⛔⛔ THE SPEND CARRIER PROVED BYTE-IDENTICALLY TWICE — its blinding is not drawing fresh \
         entropy. A carrier that looks blinded but is not leaks exactly as much as an unblinded one: \
         an observer can confirm two proofs are about the same spend. Check \
         `committed_air::prove_air_blinded_bytes` still seeds from the system RNG."
    );
    // The statement must be STABLE while the proof moves, or this gate would pass on a prover that had
    // simply started proving something else each time.
    assert_eq!(a.3, b.3, "the nullifier is a public output and must not move between proves");
    assert_eq!(a.4, b.4, "the leaf_commit is a public output and must not move between proves");
}

/// ⭐⭐⭐ §BB → DB-363 (2026-09-30) — THE CROSS-BIND IS THE PROVER'S AND IT IS HIDING. `spend_cross_bind` (the node-side
/// recomputation of `leaf_commit` from the PUBLIC pair `(cm, nullifier)`) and `admits_deletion_of_cm` are deleted:
/// that recomputation was exactly the join that let any observer name the note a spend consumed. What remains
/// measurable, against the PRODUCTION prover rather than argued: the proven `leaf_commit` equals the membership
/// carrier's blinded formula over the prover's own leaf (`spend_input_leaf`, which exists so nobody re-derives it)
/// and the spend's blinding — so the two proofs meet on ONE value (§AO) — and the unblinded public pair does NOT
/// reproduce it (the DB-363 leak, refuted here as well as in the node's observer pin).
#[test]
fn the_provers_leaf_commit_is_the_blinded_membership_formula_and_never_the_public_join() {
    let w = witness(0);
    let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w)
        .expect("the production prover states the spent note's leaf");
    let (_blob, _cms, nf, lc, _d) = prove_unfiled_spend(&w).expect("the production spend proves");
    assert_eq!(
        lc,
        usdm_decider::note_membership_air::note_leaf_commitment(leaf, nf, w.lc_blind),
        "⛔⛔⛔ §AO — the validity carrier and the membership carrier spell this note's `leaf_commit` differently; \
         both honest, about different objects, and every membership-proving spend is refused"
    );
    assert_ne!(
        lc,
        usdm_decider::whir_rec_block::poseidon_pair(leaf, nf),
        "⛔⛔ DB-363 — the proven cross-bind is the PUBLIC one-hash join of (leaf, nullifier); every spend links to its receive"
    );
    // A peer fed only the block's transition still admits the change notes and the nullifier — the deletion
    // question is answered by the nullifier SET, never by recomputing a commitment.
    let (onr, _dsr) = roots2();
    let spends: Vec<(Vec<u8>, SpendTuple, Digest4)> = vec![spend(0)];
    let nt = build(&spends, &onr).expect("the producer lays a transition");
    let admit = verify(&nt, &onr, &[]).expect("a peer verifies it holding no transaction body");
    assert!(admit.admits_deletion(&spends[0].1.nullifier), "the proven nullifier is admitted for deletion");
    let foreign: [u8; 32] = core::array::from_fn(|i| ((i as u32 * 11 + 17) % 251) as u8);
    assert!(!admit.admits_deletion(&foreign), "⛔ a nullifier no verified spend revealed is not deletable");
}

/// ⭐⭐⭐ §BA/§BB — A PEER HOLDING NO TRANSACTION BODY CAN NOW TELL A REAL NOTE FROM A PLANTED ONE.
///
/// This is the whole mechanism in one place: the producer lays a transition over the spends it
/// selected; a peer that holds NONE of those transactions verifies it and gets back an ALLOW-list.
/// Every commitment a real spend published is admitted. A commitment the producer invented — the
/// §BA forgery, a note of the right on-chain shape whose opening the producer chose — is not, and
/// no amount of it being "in the block" changes that.
/// ⭐ §RF-3 / DB-378 (2026-10-24) — THE AGGREGATE IS ONE SIZE WHATEVER THE REAL SPEND COUNT; ONLY THE TUPLES AND
/// `shape[7]` GROW WITH n.
///
/// The O1-FOOTPRINT claim on `NoteTransition` ("the proof itself is a CONSTANT size at that slot count") was a
/// comment; this measures it. It also attributes the 408,120 B the shape probe weighs on a one-spend block:
/// 407,960 B of aggregate + 160 B per tuple. So DB-378's always-on cost is the aggregate's FLOOR on every quiet
/// block, not a per-spend cost, and the count leak lives in exactly two places: the tuple list and `shape[7]`.
#[test]
fn the_aggregate_is_one_size_whatever_the_real_spend_count() {
    let (onr, _dsr) = roots2();
    let one = build(&[spend(0)], &onr).expect("the producer lays a one-spend transition");
    let two = build(&[spend(0), spend(1)], &onr).expect("the producer lays a two-spend transition");
    eprintln!(
        "[§RF-3 agg] n=1 agg={} B tuples={} B · n=2 agg={} B tuples={} B",
        one.agg.len(),
        one.tuples.len(),
        two.agg.len(),
        two.tuples.len()
    );
    assert!(verify(&one, &onr, &[]).is_some() && verify(&two, &onr, &[]).is_some(), "both transitions verify");
    assert_eq!(one.agg.len(), two.agg.len(), "⛔ the aggregate's size tracks the real spend count");
    assert_eq!((one.tuples.len(), two.tuples.len()), (TUPLE_BYTES, 2 * TUPLE_BYTES), "n × TUPLE_BYTES tuples");
    let differing: Vec<usize> = (0..8).filter(|&i| one.shape[i] != two.shape[i]).collect();
    assert_eq!(differing, vec![7], "⛔ a shape word other than n tracks the real spend count");
}

#[test]
fn a_peer_admits_only_notes_a_verified_spend_published() {
    let spends: Vec<(Vec<u8>, SpendTuple, Digest4)> = (0..2).map(spend).collect();
    let (onr, _dsr) = roots2();
    let nt = build(&spends, &onr).expect("the producer lays a transition");
    eprintln!(
        "[§BA] transition: n={} agg={} B tuples={} B",
        nt.shape[7],
        nt.agg.len(),
        nt.tuples.len()
    );
    let admit = verify(&nt, &onr, &[]).expect("a peer verifies it holding no transaction body");

    // Every real output note is admitted, and every real nullifier.
    for (_, t, _) in &spends {
        assert!(admit.admits_note(&t.out0_cm), "a real output note was refused");
        assert!(admit.admits_note(&t.out1_cm), "a real output note was refused");
        assert!(admit.admits_deletion(&t.nullifier), "a real deletion was refused");
    }

    // ⛔⛔⛔ THE §BA FORGERY: a note of the real on-chain shape whose commitment the producer picked.
    let planted: [u8; 32] = core::array::from_fn(|i| ((i as u32 * 13 + 5) % 251) as u8);
    assert!(
        !admit.admits_note(&planted),
        "⛔⛔⛔ §BA LIVES: a peer would credit a note no verified spend ever published"
    );
    // ⛔⛔⛔ THE §BB MIRROR: a deletion of a note the producer does not own.
    let victim: [u8; 32] = core::array::from_fn(|i| ((i as u32 * 7 + 3) % 251) as u8);
    assert!(
        !admit.admits_deletion(&victim),
        "⛔⛔⛔ §BB LIVES: a peer would apply a deletion no verified spend justifies"
    );
    eprintln!("[§BA] ⭐ {} notes admitted; a planted note and a foreign deletion were REFUSED", admit.note_count());
}


/// ⭐⭐⭐ DB-83 END TO END: A BLOCK STATES A FIVE-REAL-INPUT SPEND AND A PEER ADMITS EVERY TAG.
///
/// The thing the submit door refused from 2026-09-19 to 2026-09-23. A transaction spending k > 1
/// real notes had its other k-1 real tags go UNSTATED — never in the allow-list, their deletions
/// refused, those notes still spendable. This lays the object that states them and asks a PEER, not
/// the producer, what it holds afterwards.
///
/// ⛔ AND IT REFUTES, because a transition that verifies without BINDING is worthless: a tampered
/// tag list, a different output-notes root, and a dropped transaction must each be refused.
#[test]
fn a_block_states_a_five_real_input_spend_and_a_peer_admits_every_tag() {
    use usdm_decider::nf_sparse_air::{cover_tag_native, prove_spend_or_decoy_bytes, TagWitness};
    use usdm_decider::nullifier_insert_air::poseidon_pair_native;
    let w = cover_tx_width();
    let bound = lanes_of(&[9u64, 9, 9, 9]);
    // One transaction with k REAL inputs padded to the protocol's constant width.
    let tx = |k: usize, seed: u64| -> (Vec<u8>, Vec<[u8; 32]>) {
        let mut tags = Vec::with_capacity(w);
        let mut wit = Vec::with_capacity(w);
        for j in 0..w {
            if j < k {
                let sk = lanes_of(&[100 + seed + j as u64, 2, 3, 4]);
                let leaf = lanes_of(&[200 + seed + j as u64, 5, 6, 7]);
                tags.push(poseidon_pair_native(sk, leaf));
                wit.push(TagWitness::RealSpend { key: sk, leaf });
            } else {
                tags.push(cover_tag_native(bound, j as u64));
                wit.push(TagWitness::Decoy);
            }
        }
        let p = prove_spend_or_decoy_bytes(bound, &tags, &wit).expect("the carrier proves");
        // ⭐ THE BYTES A BLOCK PUBLISHES ARE THE INJECTIVE FORM OF THE TAGS THE CIRCUIT PROVED —
        //   the same round trip the submit door makes, or the two would be different objects.
        (p, tags.iter().map(|t| crate::spend_frontier::leaf_to_cm_bytes(*t)).collect())
    };
    let covers = vec![tx(1, 0), tx(5, 1_000)];
    let onr = crate::hash::Hash32::hash(b"db83-e2e-output-notes-root");

    let t = std::time::Instant::now();
    let ct = build_cover(&covers, &onr).expect("⛔ DB-83: a block must be able to state this");
    eprintln!(
        "[db83-node] {} tx (k=1 and k=5 REAL inputs, width {w}) -> agg {} B + {} tag B in {} ms",
        covers.len(),
        ct.agg.len(),
        ct.tags.len(),
        t.elapsed().as_millis()
    );

    // ⭐ THE PEER'S VERDICT — it holds the block's public bytes and nothing else.
    let admit = verify_cover(&ct, &onr).expect("⛔ the honest transition must verify on a peer");
    for (_, tags) in &covers {
        for tg in tags {
            assert!(
                admit.admits_deletion(tg),
                "⛔⛔⛔ A CARRIED TAG WAS NOT ADMITTED — that note's deletion is refused and it stays \
                 spendable, which is the whole of DB-83"
            );
        }
    }

    // ⛔ 1. A TAMPERED TAG LIST. A peer recomputes the statement from the tags it holds.
    let mut bad = ct.clone();
    bad.tags[0] ^= 1;
    assert!(
        verify_cover(&bad, &onr).is_none(),
        "⛔⛔ A TAMPERED TAG LIST VERIFIED — the transition does not bind the spends it states"
    );

    // ⛔ 2. A DIFFERENT OUTPUT-NOTES ROOT: the proof must not stand over a delta the block does not
    //    apply, or a producer settles one thing and publishes another.
    assert!(
        verify_cover(&ct, &crate::hash::Hash32::hash(b"another-block")).is_none(),
        "⛔⛔ THE TRANSITION VERIFIED UNDER ANOTHER BLOCK'S ROOT"
    );

    // ⛔ 3. A DROPPED TRANSACTION: stating one spend while settling two must not verify.
    let mut short = ct.clone();
    short.tags.truncate(w * 32);
    assert!(
        verify_cover(&short, &onr).is_none(),
        "⛔⛔ A DROPPED TRANSACTION VERIFIED — the statement does not bind how many it stands over"
    );
}

/// ⭐⭐⭐ THE NODE'S TEMPLATE DOOR, ARMED AND NOT (docs/SIM-SPEED-TEMPLATE-BOUND-DOUBLE-20261022.md brick 3 — §9.6 point
/// 6, parity with the band door): an ARMED producer lays the bound double through the SAME `build_with` the real one
/// takes, an armed peer admits exactly the cms and deletions the real transition admits, and the forms never cross —
/// a REAL door refuses the double's transition, an armed door refuses a real one, and the process-wide verified cache
/// keeps the armed verdict apart: after an armed door has accepted (and cached) the double's bytes, a real door handed
/// the same bytes STILL refuses them. A moved block root is refused on the armed door.
/// TWO-PARTY-REVIEWED: the producer's `build_with` and the peer's `verify_with` are the two parties; the peer holds no
/// transaction body, only the block's own bytes.
#[test]
fn an_armed_template_door_takes_only_the_bound_double_and_a_real_door_never_reads_its_verdict() {
    let (blob, t, d) = spend(83);
    let (onr, other) = roots2();
    let real = build(&[(blob.clone(), t, d)], &onr).expect("the real producer lays the transition");
    let armed = build_with(&[(blob, t, d)], &onr, true).expect("the armed producer lays the double");
    assert_eq!((armed.tuples.as_slice(), armed.shape), (real.tuples.as_slice(), real.shape), "⛔ the double states another list or shape");
    assert!(armed.agg.len() < 64 && real.agg.len() > 100_000, "the double drops only the WHIR proof (bound {} B, real {} B)", armed.agg.len(), real.agg.len());
    let a_real = verify(&real, &onr, &[]).expect("CALIBRATION: a real door admits the real transition");
    let a_armed = verify_with(&armed, &onr, &[], true).expect("CALIBRATION: an armed door admits the double");
    for cm in [t.out0_cm, t.out1_cm] {
        assert!(a_real.admits_note(&cm) && a_armed.admits_note(&cm), "⛔ the double admits another note set");
    }
    for nf in [t.nullifier, t.tag1] {
        assert!(a_real.admits_deletion(&nf) && a_armed.admits_deletion(&nf), "⛔ the double admits another deletion set");
    }
    // ⛔ THE FORMS NEVER CROSS — and the armed TRUE now in the process-wide cache is never read by a real door.
    assert!(verify(&armed, &onr, &[]).is_none(), "⛔⛔⛔ a REAL door admitted the double (or read the armed door's cached verdict)");
    assert!(verify_with(&real, &onr, &[], true).is_none(), "⛔ an armed door admitted a real transition");
    assert!(verify_with(&armed, &other, &[], true).is_none(), "⛔ the double verified under another block's notes root");
    // the member class through the same switch: one statement, the forms never cross
    let carriers = vec![crate::member_transition::test_member_carrier(5)];
    let mreal = crate::member_transition::build(&carriers, &onr).expect("the real member transition lays");
    let marmed = crate::member_transition::build_with(&carriers, &onr, true).expect("the armed member double lays");
    assert_eq!(crate::member_transition::verify_with(&marmed, &onr, true), crate::member_transition::verify(&mreal, &onr), "⛔ the member double admits another tuple list");
    assert!(crate::member_transition::verify(&marmed, &onr).is_none(), "⛔⛔ a REAL member door admitted the double");
    assert!(crate::member_transition::verify_with(&mreal, &onr, true).is_none(), "⛔ an armed member door admitted a real transition");
}

/// DB-313 §3 — a REAL welded bond carrier (the production bond prover, at the class's one depth), with the tuple the
/// node derives. The weld proves `out0_value == weight`.
fn bond(i: u64) -> (Vec<u8>, BondTuple) {
    let sk = lanes_of(&[31 + i, 32, 33, 34]);
    let weight = 700 + i;
    let w = SpendValidityWitness {
        value_in: 900 + i + 99900, // §BR-14: the input funds the protocol fee
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(sk),
        value_out: 800 + i,
        fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        out0_value: weight,
        out0_opening: lanes_of(&[8, 8, 8, 8]),
        out1_value: 800 + i - weight,
        out1_opening: sk,
    };
    let (blob, cms, nf, lc) =
        usdm_decider::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(&w, weight)
            .expect("the production bond proves");
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let spend = BondSpend { out0_cm: b(cms[0]), out1_cm: b(cms[1]), nullifier: b(nf), leaf_commit: b(lc) };
    (blob, BondTuple { spend, weight })
}

/// ⭐⭐⭐ DB-313 §3 — A PEER FED ONLY THE BOND TRANSITION ADMITS THE CHANGE AND THE DELETION, NEVER THE LOCKED NOTE,
/// AND YIELDS EXACTLY THE PROVEN (locked note, nullifier, W). CALIBRATION: the honest transition verifies and
/// admits. TAMPERS (each REJECTS): the tuple list's W moved; a nullifier swapped; the transition under another
/// block's root; the bond aggregate read through the NOTE class; a list that drops a bond; a tolerated tail.
#[test]
fn db313_a_bond_transition_admits_the_change_and_the_weight_and_never_the_locked_note() {
    let bonds: Vec<(Vec<u8>, BondTuple)> = (0..2).map(bond).collect();
    let (onr, _) = roots2();
    for (blob, t) in &bonds {
        assert!(
            bond_carrier_verifies(blob, t),
            "CALIBRATION: each carrier verifies at the class's one depth with the door's own verifier"
        );
    }
    let bt = build_bond(&bonds, &onr).expect("the producer lays the bond transition");
    let a = verify_bond(&bt, &onr).expect("CONTROL: a peer admits the honest bond transition");
    for (_, t) in &bonds {
        assert!(a.admits_note(&t.spend.out1_cm), "the change is receivable");
        assert!(!a.admits_note(&t.spend.out0_cm), "⛔⛔ DB-313: the LOCKED note was admitted as receivable");
        assert!(a.admits_deletion(&t.spend.nullifier), "the consumed note's deletion is admitted");
        assert!(a.admits_bond(&t.spend.out0_cm, &t.spend.nullifier, t.weight), "the proven (lock, nf, W)");
        assert!(
            !a.admits_bond(&t.spend.out0_cm, &t.spend.nullifier, t.weight + 1),
            "⛔⛔⛔ DB-313: a weight one above the welded value was admitted"
        );
    }
    // TAMPER 1 — the tuple list's W moved by one: the digest a peer recomputes is not the proof's.
    let mut moved = bt.clone();
    moved.tuples[TUPLE_BYTES] ^= 1;
    assert!(verify_bond(&moved, &onr).is_none(), "⛔⛔⛔ DB-313: a bond transition whose weight moved verified");
    // TAMPER 2 — a swapped nullifier.
    let mut swapped = bt.clone();
    swapped.tuples.swap(2 * 32, BOND_TUPLE_BYTES + 2 * 32);
    assert!(verify_bond(&swapped, &onr).is_none(), "⛔⛔ DB-313: a bond transition with swapped nullifiers verified");
    // TAMPER 3 — under another block's root.
    assert!(
        verify_bond(&bt, &crate::hash::Hash32::hash(b"another-block")).is_none(),
        "⛔⛔ DB-313: the bond transition verified under another block's root"
    );
    // TAMPER 4 — the bond aggregate read through the NOTE class over the same four digests per bond, each given a
    // well-formed claim tag (DB-329 §7e) so the list is exactly the note class's shape and only the proof refuses.
    let mut spend_tuples = Vec::new();
    for (i, (_, t)) in bonds.iter().enumerate() {
        t.spend.write(&mut spend_tuples);
        let claim = usdm_decider::slot_ledger::slot_claim_native(usdm_decider::poseidon2_compress::lanes_of(&[0x313, i as u64]), 0);
        spend_tuples.extend_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(claim));
    }
    let as_note = NoteTransition { agg: bt.agg.clone(), tuples: spend_tuples, shape: bt.shape, tag_agg: Vec::new(), clock_ms: 0, bodies: [0u8; 32] };
    assert!(verify(&as_note, &onr, &[]).is_none(), "⛔⛔ DB-313: a bond aggregate verified as a note transition");
    // TAMPER 5 — a list that drops a bond while the shape still names two.
    let mut short = bt.clone();
    short.tuples.truncate(BOND_TUPLE_BYTES);
    assert!(verify_bond(&short, &onr).is_none(), "⛔⛔ DB-313: a dropped bond verified");
    // The ONE encoding of the framed object: strict round trip, no tolerated tail.
    assert_eq!(BondTransition::decode(&bt.encode()), Some(bt.clone()), "the framed object round-trips");
    let mut tail = bt.encode();
    tail.push(0);
    assert!(BondTransition::decode(&tail).is_none(), "⛔ a tolerated tail is a second encoding of one object");
}

/// A canonical 128-row list: strictly ascending `tag0`, flags in {0,1}, pinned cells zero, every other cell nonzero.
fn a_canonical_ledger_list() -> Vec<usdm_decider::settlement_delta::LedgerPublished> {
    use usdm_decider::slot_ledger::{PUB_DIGESTS, PUB_FLAGS, PUB_TAG0};
    (0..usdm_decider::settlement_delta::LEDGER_ROWS as u64)
        .map(|r| {
            let mut row = [[0u64; 8]; PUB_DIGESTS];
            for (k, d) in row.iter_mut().enumerate().take(PUB_DIGESTS - 1) {
                *d = core::array::from_fn(|c| 1 + r * 97 + (k as u64) * 13 + c as u64);
            }
            row[PUB_TAG0][0] = 1 + r;
            row[PUB_FLAGS] = [r & 1, 1, 0, 1, 0, 0, 0, 0];
            row
        })
        .collect()
}

/// §RF-3: the ledger list has ONE spelling, the same byte count quiet or busy, and the decode refuses every list the
/// class refuses — a wrong length, a non-canonical digest, a reordered list, an out-of-range flag.
#[test]
fn the_ledger_list_round_trips_at_one_constant_size_and_refuses_every_non_canonical_form() {
    use usdm_decider::slot_ledger::{PUB_DIGESTS, PUB_FLAGS};
    let list = a_canonical_ledger_list();
    let wire = encode_ledger_published(&list).expect("a canonical list encodes");
    assert_eq!(wire.len(), LEDGER_LIST_WIRE_BYTES);
    assert_eq!(LEDGER_LIST_WIRE_BYTES, 28_672);
    assert_eq!(decode_ledger_published(&wire).as_deref(), Some(&list[..]), "the decode is the encode's inverse");

    assert!(decode_ledger_published(&wire[..wire.len() - 1]).is_none(), "⛔ a short list");
    let mut long = wire.clone();
    long.push(0);
    assert!(decode_ledger_published(&long).is_none(), "⛔ a tolerated tail is a second encoding");
    let mut bit255 = wire.clone();
    bit255[31] |= 0x80;
    assert!(decode_ledger_published(&bit255).is_none(), "⛔ a digest with bit 255 set is not our form");
    let mut lane_p = wire.clone();
    lane_p[..4].copy_from_slice(&[0xff, 0xff, 0xff, 0x7f]);
    assert!(decode_ledger_published(&lane_p).is_none(), "⛔ a lane at or above p names no limb");
    let mut swapped = wire.clone();
    swapped.copy_within(LEDGER_ROW_WIRE_BYTES..2 * LEDGER_ROW_WIRE_BYTES, 0);
    assert!(decode_ledger_published(&swapped).is_none(), "⛔ tag0 not strictly ascending");
    let mut flag2 = list.clone();
    flag2[3][PUB_FLAGS][1] = 2;
    let bad = flag2.iter().flat_map(|r| r[..PUB_DIGESTS - 1].iter().flat_map(|d| crate::spend_frontier::leaf_to_cm_bytes(*d))).collect::<Vec<u8>>();
    assert!(decode_ledger_published(&bad).is_none(), "⛔ a flag outside {{0,1}}");
    assert!(encode_ledger_published(&flag2).is_none(), "⛔ a producer cannot write what no verifier reads");
    assert!(encode_ledger_published(&list[1..]).is_none(), "⛔ a 127-row list");
}

/// ⭐ §RF-3 — THE SLOT LEDGER, PRODUCER TO PEER (padding spec v2 §2–§3). A busy block (one real spend) and a quiet
/// block (the null carrier) lay ledgers of ONE wire shape; the peer's `verify_ledger` admits the spend's outputs and
/// both its tags, and nothing real from the quiet block. Each tamper REJECTS: another seed commit, a filing tag the
/// payer never bound (a moved row D), a flipped justification flag (a canonical list the proof did not state), a
/// shape word, a proof byte, the quiet proof under the busy list; and the producer refuses to lay a spend whose D is
/// not the block's filing. TWO-PARTY-REVIEWED: `build_ledger` and `verify_ledger` are the two production
/// functions; the peer holds only the block's bytes.
#[test]
fn rf3_the_ledger_transition_round_trips_at_one_shape_and_every_tamper_rejects() {
    use usdm_decider::slot_ledger::PUB_FLAGS;
    let (onr, _dsr) = roots2();
    let seed = lanes_of(&[0x5eed, 0x1ed6, 3, 4]);
    let (s70, payer_tags) = filed_spend(70);
    let spends = vec![s70];
    let t = &spends[0].1;
    let tags = uniform_ledger_filing(&spends, &[], &[], seed, &payer_tags).expect("the busy filing");
    let qtags = uniform_ledger_filing(&[], &[], &[], seed, &[]).expect("the quiet filing");
    let (member, ring) = member_for(70, t);
    let rc = crate::member_transition::ring_commit_of(&ring).expect("the ring states");
    let started = std::time::Instant::now();
    let (busy, commit) = build_ledger(&spends, &[member.clone()], &ring, &[], &[], seed, &onr, &tags).expect("a 1-spend ledger proves");
    let (quiet, commit_q) =
        build_ledger(&[], &[], &ring, &[], &[], seed, &onr, &qtags).expect("a quiet ledger proves on the null carriers");
    eprintln!("[rf3-ledger] two ledgers proved in {} ms, proof {} / {} B", started.elapsed().as_millis(), busy.agg.len(), quiet.agg.len());
    assert_eq!(commit, crate::block::cover_seed_commit_of(seed));
    assert_eq!(commit, commit_q, "one seed, one commitment");
    assert_eq!(busy.tuples.len(), LEDGER_LIST_WIRE_BYTES);
    assert_eq!((busy.tuples.len(), busy.shape), (quiet.tuples.len(), quiet.shape), "⛔ quiet ≠ busy on the wire shape");

    let a = verify_ledger(&busy, &onr, &commit, &tags, &hdr(&busy).0, &hdr(&busy).1, &rc).expect("the peer admits the honest busy ledger");
    assert!(a.admits_note(&t.out0_cm) && a.admits_note(&t.out1_cm), "the spend's outputs are admitted");
    assert!(a.admits_deletion(&t.nullifier) && a.admits_deletion(&t.tag1), "both its tags enter the spent set");
    assert_eq!(a.note_count(), 2 * usdm_decider::settlement_delta::LEDGER_ROWS, "every note cell, none justified");
    let q = verify_ledger(&quiet, &onr, &commit, &qtags, &hdr(&quiet).0, &hdr(&quiet).1, &rc).expect("the peer admits the honest quiet ledger");
    assert!(!q.admits_deletion(&t.nullifier) && !q.admits_note(&t.out0_cm), "a quiet block states nothing real");
    assert_eq!(q.note_count(), a.note_count(), "⛔ the admitted cell count names the spend count");

    let other = crate::block::cover_seed_commit_of(lanes_of(&[9, 9, 9, 9]));
    assert!(verify_ledger(&busy, &onr, &other, &tags, &hdr(&busy).0, &hdr(&busy).1, &rc).is_none(), "⛔ another header seed commit");
    let mut filed = tags.clone();
    let at = filed.chunks_exact(48).position(|r| r[..32] == t.out0_cm).expect("the spend output is filed") * 48;
    filed[at + 32..at + 48].copy_from_slice(&[7u8; crate::oli::K_BYTES]);
    assert!(verify_ledger(&busy, &onr, &commit, &filed, &hdr(&busy).0, &hdr(&busy).1, &rc).is_none(), "⛔ a filing the payer never bound");
    let mut rows = decode_ledger_published(&busy.tuples).expect("the producer's list decodes");
    let r = rows.iter().position(|p| p[PUB_FLAGS][0] == 0).expect("an unjustified note cell");
    rows[r][PUB_FLAGS][0] = 1;
    let flipped = NoteTransition { tuples: encode_ledger_published(&rows).expect("still canonical"), ..busy.clone() };
    assert!(verify_ledger(&flipped, &onr, &commit, &tags, &hdr(&flipped).0, &hdr(&flipped).1, &rc).is_none(), "⛔ a justification flag the proof never stated");
    let mut shape = busy.clone();
    shape.shape[7] ^= 1;
    assert!(verify_ledger(&shape, &onr, &commit, &tags, &hdr(&shape).0, &hdr(&shape).1, &rc).is_none(), "⛔ a shape word");
    let mut agg = busy.clone();
    let mid = agg.agg.len() / 2;
    agg.agg[mid] ^= 1;
    assert!(verify_ledger(&agg, &onr, &commit, &tags, &hdr(&agg).0, &hdr(&agg).1, &rc).is_none(), "⛔ a proof byte");
    let swapped = NoteTransition { agg: quiet.agg.clone(), ..busy.clone() };
    assert!(verify_ledger(&swapped, &onr, &commit, &tags, &hdr(&swapped).0, &hdr(&swapped).1, &rc).is_none(), "⛔ the quiet proof under the busy list");
    assert!(build_ledger(&spends, &[], &ring, &[], &[], seed, &onr, &tags).is_none(), "⛔ a producer lays a spend row with no member carrier");
    assert!(build_ledger(&spends, &[member.clone()], &ring[..1], &[], &[], seed, &onr, &tags).is_none(), "⛔ a producer lays an anchor outside its ring");
    assert!(build_ledger(&spends, &[member], &ring, &[], &[], seed, &onr, &filed).is_none(), "⛔ a producer lays a D the door refuses");
}

/// ⛔ §RF-3 THE ARMED LEDGER (sim-speed bound double): an armed producer lays the class's constant wire shape and
/// list in a 32 B seal, an armed peer admits exactly what the real door admits from the same block, and refuses
/// another seed commit and a moved shape word; the REAL door refuses the double. The decider's
/// `the_ledger_bound_double_admits_the_honest_ledger_and_refuses_every_tamper` carries the other direction (an armed
/// door refuses a real proof) and the list tampers. TWO-PARTY-REVIEWED: the peer holds only the block's bytes.
#[test]
fn rf3_an_armed_ledger_admits_what_the_real_door_admits_and_the_forms_never_cross() {
    r4_armed_admits_what_the_real_door_admits();
}

/// ⭐ R4 lever 4 steps C1 + C2 — THE REAL LEDGER'S NOTE, TAG AND MEMBER PROOFS ARE ONE JOINED BATCH: a real producer
/// lays it whole in `agg` with `tag_agg` empty, a real peer admits it with the member statement derived from the header's
/// ring commit, and the one block door admits the block only with an EMPTY member `agg`. Every other form is refused —
/// a flipped proof byte, a non-empty `tag_agg` (the old two-proof encoding), the joined proof under another seed commit
/// or a foreign ring commit, a door given no member statement, a note + tag proof of the C1 form (the member ledger
/// left out), and at the block door a member proof carried beside the joined one (a second encoding).
/// TWO-PARTY-REVIEWED: the producer's `build_ledger` and the peer's `verify_ledger` / `spends_proven_on_block_with`;
/// the peer holds only bytes and header words.
#[test]
fn r4_a_real_ledger_proves_note_tag_and_member_as_one_batch_and_every_other_form_is_refused() {
    use crate::member_transition::{spends_proven_on_block_with, LedgerDoor, MemberTransition};
    let (onr, _dsr) = roots2();
    let seed = lanes_of(&[0x5eed, 0x1ed6, 3, 4]);
    let (s71, payer_tags) = filed_spend(71);
    let spends = vec![s71];
    let t = &spends[0].1;
    let (member, ring) = member_for(71, t);
    let rc = crate::member_transition::ring_commit_of(&ring).expect("the ring states");
    let tags = uniform_ledger_filing(&spends, &[], &[], seed, &payer_tags).expect("the busy filing");
    let t0 = std::time::Instant::now();
    let (nt, commit) = build_ledger(&spends, &[member.clone()], &ring, &[], &[], seed, &onr, &tags).expect("a real producer lays");
    assert!(nt.tag_agg.is_empty(), "the joined form carries no separate tag proof");
    let triple_ms = t0.elapsed().as_millis();
    eprintln!("[r4-joined] the note (tree ledger) + member ledgers as one proof: {} B, laid + proved in {triple_ms} ms", nt.agg.len());
    assert_eq!(nt.agg.len(), bound_weight::LEDGER_JOINED, "⛔ the joined proof's length is not the constant the armed doubles weigh");
    let (hc, ht) = hdr(&nt);
    let a = verify_ledger(&nt, &onr, &commit, &tags, &hc, &ht, &rc).expect("a real peer admits the joined ledger");
    assert!(a.admits_note(&t.out0_cm) && a.admits_deletion(&t.nullifier), "the spend's output and tag are admitted");
    let mut flipped = nt.clone();
    let mid = flipped.agg.len() / 2;
    flipped.agg[mid] ^= 1;
    assert!(verify_ledger(&flipped, &onr, &commit, &tags, &hc, &ht, &rc).is_none(), "⛔ a flipped proof byte");
    let mut two = nt.clone();
    two.tag_agg = vec![0u8; 32];
    assert!(verify_ledger(&two, &onr, &commit, &tags, &hc, &ht, &rc).is_none(), "⛔ a non-empty tag_agg");
    let other = crate::block::cover_seed_commit_of(lanes_of(&[0x5eed, 0x1ed6, 3, 5]));
    assert!(verify_ledger(&nt, &onr, &other, &tags, &hc, &ht, &rc).is_none(), "⛔ the joined proof under another seed");
    // V2: the joined proof carries no member statement, so the door does not read the header's ring commit: a foreign one is
    // judged at the fold (`Node::member_anchors_at_fold` → `member_ring_commit_is_canonical`, then each spend's own anchor
    // against the node's recent roots), never here. The door admits the honest proof whatever ring commit it is handed.
    let foreign = crate::member_transition::ring_commit_of(&[ring[0], lanes_of(&[0xdec1])]).expect("a foreign ring states");
    assert!(verify_ledger(&nt, &onr, &commit, &tags, &hc, &ht, &foreign).is_some(), "the door does not judge the ring commit (the fold does)");
    // the one form: the same block's note statement proved alone IS the producer's proof (no tag, no member statement)
    let t1 = std::time::Instant::now();
    let (mut c1, _, st) = build_ledger_with(&spends, &[], &[], seed, &onr, &tags, false).expect("the statements lay");
    let st = st.expect("a real lay hands back its statements");
    c1.agg = usdm_decider::light_batch_merge::prove_joined(vec![st.note]).expect("the one-statement batch proves");
    let c1_ms = t1.elapsed().as_millis();
    assert!(verify_ledger(&c1, &onr, &commit, &tags, &hc, &ht, &rc).is_some(), "the note statement proved alone is the ledger proof");
    // THE ONE BLOCK DOOR: the member transition travels with an empty `agg` (the member is inside `nt.agg`)
    let class = ledger_shape_wire().expect("the ledger class states");
    let mt = MemberTransition { agg: Vec::new(), tuples: Vec::new(), shape: class };
    let door = |mt: &MemberTransition| {
        let l = LedgerDoor { real_notes: None, cover_key: None, padded_tags: &ht, seed_commit: &commit, ring_commit: &rc };
        spends_proven_on_block_with(&nt, Some(mt), &onr, &tags, Some(l), false, false)
    };
    let (d, members) = door(&mt).expect("⛔ the block door refuses the honest joined ledger");
    assert!(d.admits_deletion(&t.nullifier) && members.is_empty(), "the door admits the spend and publishes no anchor");
    let published = decode_ledger_published(&nt.tuples).expect("the list decodes");
    let t2 = std::time::Instant::now();
    let beside = crate::member_transition::build_member_ledger(&[member], &published, &ring, &onr, seed).expect("the separate member proof");
    // A/B in one process, one load: the C1 form (note + tag joined, the member proved apart) against the triple above
    eprintln!(
        "[r4-joined] A/B prove: C1 note+tag {c1_ms} ms + member {} ms (= {} + {} B) vs the triple {triple_ms} ms ({} B)",
        t2.elapsed().as_millis(),
        c1.agg.len(),
        beside.len(),
        nt.agg.len()
    );
    assert!(door(&MemberTransition { agg: beside, ..mt.clone() }).is_none(), "⛔ a member proof carried beside the joined one");
    assert!(door(&MemberTransition { agg: vec![0u8; 36], ..mt.clone() }).is_none(), "⛔ a real door admitted the armed member seal's length");
}

fn r4_armed_admits_what_the_real_door_admits() {
    let (onr, _dsr) = roots2();
    let seed = lanes_of(&[0x5eed, 0x1ed6, 3, 4]);
    let (s71, payer_tags) = filed_spend(71);
    let spends = vec![s71];
    let t = &spends[0].1;
    let tags = uniform_ledger_filing(&spends, &[], &[], seed, &payer_tags).expect("the busy filing");
    let (busy, commit, _) = build_ledger_with(&spends, &[], &[], seed, &onr, &tags, true).expect("an armed producer lays");
    // R4: the 32 B seal travels at the real note ledger's weight (`bound_weight`), so a simulated block weighs a real one
    assert_eq!(busy.agg.len(), bound_weight::NOTE_LEDGER, "the armed ledger weighs the real note ledger");
    assert_eq!(bound_weight::unpad(&busy.agg, bound_weight::NOTE_LEDGER).map(<[u8]>::len), Some(32), "inside it, the 32 B seal");
    assert_eq!((busy.tuples.len(), Some(busy.shape)), (LEDGER_LIST_WIRE_BYTES, ledger_shape_wire()), "the class's wire shape");
    let a = verify_ledger_with(&busy, &onr, &commit, &tags, &hdr(&busy).0, &hdr(&busy).1, true).expect("an armed peer admits the armed ledger");
    assert!(a.admits_note(&t.out0_cm) && a.admits_note(&t.out1_cm), "the spend's outputs are admitted");
    assert!(a.admits_deletion(&t.nullifier) && a.admits_deletion(&t.tag1), "both its tags enter the spent set");
    assert_eq!(a.note_count(), 2 * usdm_decider::settlement_delta::LEDGER_ROWS, "every note cell, none justified");
    let other = crate::block::cover_seed_commit_of(lanes_of(&[9, 9, 9, 9]));
    assert!(verify_ledger_with(&busy, &onr, &other, &tags, &hdr(&busy).0, &hdr(&busy).1, true).is_none(), "⛔ an armed door under another seed commit");
    let mut shape = busy.clone();
    shape.shape[7] ^= 1;
    assert!(verify_ledger_with(&shape, &onr, &commit, &tags, &hdr(&shape).0, &hdr(&shape).1, true).is_none(), "⛔ an armed door under a moved shape word");
    let rc = crate::member_transition::ring_commit_of(&[lanes_of(&[0xdec0])]).expect("a ring states");
    assert!(verify_ledger(&busy, &onr, &commit, &tags, &hdr(&busy).0, &hdr(&busy).1, &rc).is_none(), "⛔ the REAL door accepted the 32 B double");
}

/// ⛔ §FAST — THE ARMED NULL SPEND CARRIER IS ONE PER PROCESS, AND NOTHING OF IT IS PUBLISHED. Two armed quiet
/// ledgers under two header seeds share the process's one null carrier (`null_spend_carrier_for`), each is admitted
/// by an armed peer, neither list holds any digest the carrier states, and the two lists share no cell (the cover is
/// the seed's). The real form still proves a fresh carrier. TWO-PARTY-REVIEWED: the peer holds only the bytes.
#[test]
fn rf3_armed_quiet_ledgers_share_one_null_carrier_and_publish_nothing_of_it() {
    use p3_field::PrimeField64;
    let (onr, _dsr) = roots2();
    let shared = null_spend_carrier_for(true).expect("the process null carrier");
    assert_eq!(Some(&shared), null_spend_carrier_for(true).as_ref(), "the armed form is one carrier per process");
    assert_ne!(Some(&shared), null_spend_carrier_for(false).as_ref(), "⛔ the real form reused a null carrier");
    type D = usdm_decider::poseidon2_compress::Digest;
    // exactly the digests a ledger row reads off a carrier (`abs_of`: the bind's first ABS_DIGESTS digests; its
    // tail is zero lanes, which equal the published zero flags/pad cells and state nothing)
    let stated: std::collections::BTreeSet<D> = shared.1[1..]
        .chunks(core::mem::size_of::<D>() / 8)
        .take(usdm_decider::slot_ledger::ABS_DIGESTS)
        .map(|c| core::array::from_fn(|i| c[i].as_canonical_u64()))
        .collect();
    assert_eq!(stated.len(), usdm_decider::slot_ledger::ABS_DIGESTS, "the null carrier states six distinct digests");
    let mut lists = Vec::new();
    for k in [1u64, 2] {
        let seed = lanes_of(&[0x5eed, 0x9a11, k, 4]);
        let tags = uniform_ledger_filing(&[], &[], &[], seed, &[]).expect("the quiet filing");
        let (nt, commit, _) = build_ledger_with(&[], &[], &[], seed, &onr, &tags, true).expect("an armed producer lays a quiet ledger");
        assert!(verify_ledger_with(&nt, &onr, &commit, &tags, &hdr(&nt).0, &hdr(&nt).1, true).is_some(), "an armed peer admits it");
        let list = decode_ledger_published(&nt.tuples).expect("the list decodes");
        let hit: Vec<(usize, usize, D)> = list
            .iter()
            .enumerate()
            .flat_map(|(r, p)| p.iter().enumerate().map(move |(j, d)| (r, j, *d)))
            .filter(|(_, _, d)| stated.contains(d))
            .collect();
        assert!(hit.is_empty(), "⛔ seed {k}: a digest the null carrier states was published (row, slot, digest): {:?}; pb len {}", &hit[..hit.len().min(3)], shared.1.len());
        // the seed's cover cells (tags, outs, lc); D and the flags/pad cells are the filing's and the zero constant
        let cells = list.iter().flat_map(|p| p[usdm_decider::slot_ledger::PUB_TAG0..=usdm_decider::slot_ledger::PUB_LC].to_vec());
        lists.push(cells.collect::<std::collections::BTreeSet<D>>());
    }
    let common: Vec<&D> = lists[0].intersection(&lists[1]).take(3).collect();
    assert!(common.is_empty(), "⛔ two quiet blocks sharing the null carrier published a common cover cell: {common:?}");
}

/// The header an honest producer lays for a ledger (spec §2.4): its 256 note slots ARE the out cells and its 256
/// padded tags ARE the tag cells, read off the transition's own list. Empty on an undecodable list.
fn hdr(nt: &NoteTransition) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    use usdm_decider::slot_ledger::{PUB_OUT0, PUB_OUT1, PUB_TAG0, PUB_TAG1};
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let list = decode_ledger_published(&nt.tuples).unwrap_or_default();
    let cms = list.iter().flat_map(|p| [b(p[PUB_OUT0]), b(p[PUB_OUT1])]).collect();
    let tags = list.iter().flat_map(|p| [b(p[PUB_TAG0]), b(p[PUB_TAG1])]).collect();
    (cms, tags)
}

// ⭐ V2 (speed5, 2026-11-16): the joined proof carries NO tag statement, so its joint tie is gone with it. The property this
// test held — a tag row that is not its spend's tag set is refused — is read natively at the block door now, and pinned there:
// `node::a_block_states_only_spends_its_peers_verified_tests::the_row_rule_refuses_every_row_that_states_what_no_transaction_
// proves` (case 4: a tag no stated spend carries; case 10: a stated spend's tag no row states).
#[cfg(any())]
fn a_tag_row_that_is_not_its_note_row_is_refused_by_the_joint_tie() {
    use usdm_decider::light_batch_merge::{prove_joined, verify_joined};
    use usdm_decider::tag_ledger as tl;
    let (onr, _dsr) = roots2();
    let (o, d) = roots(&onr);
    let seed = lanes_of(&[0x5eed, 0x7a6, 3, 4]);
    let tags = uniform_ledger_filing(&[], &[], &[], seed, &[]).expect("the quiet filing");
    let lay = || {
        let (nt, _, st) = build_ledger_with(&[], &[], &[], seed, &onr, &tags, false).expect("the note and tag statements");
        (nt, st.expect("real statements"))
    };
    let (nt, honest) = lay();
    let published = decode_ledger_published(&nt.tuples).expect("the list");
    let (tag_carriers, mut rows) = lay_tag_ledger_rows(&[], &published, false).expect("the tag rows");
    rows[40].tags[0] = lanes_of(&[0xbad, 40]);
    let (mut forged, _) = tl::lay_tag_ledger_statement(&tag_carriers, &rows, &o, &d, seed).expect("the forged rows lay");
    forged.bind = honest.tag.bind.clone();
    let (_, second) = lay();
    let bytes = prove_joined(vec![second.note, forged]).expect("the prover does not judge its own ties");
    let sc = crate::block::cover_seed_commit_lanes(&crate::block::cover_seed_commit_of(seed)).expect("the commit's lanes");
    let digests: Vec<Digest4> = published.iter().map(|p| tl::pair_digest_native(&p[usdm_decider::slot_ledger::PUB_TAG0], &p[usdm_decider::slot_ledger::PUB_TAG1])).collect();
    let stated = || {
        (
            // V2: the note statement is the tree ledger (the producer's one encoding)
            usdm_decider::tree_ledger::tree_ledger_stated(domain(), &o, &d, sc, &published, 0).expect("the note statement"),
            tl::tag_ledger_stated_statement(&o, &d, sc, &digests).expect("the tag statement"),
        )
    };
    let (note, tag) = stated();
    assert!(!verify_joined(&bytes, vec![note, tag]), "⛔ a tag row that is not its note row was admitted");
    // the control: the same forged rows, proved and verified with the tie gone from both sides, are admitted
    let (_, third) = lay();
    let (mut forged2, _) = tl::lay_tag_ledger_statement(&tag_carriers, &rows, &o, &d, seed).expect("the forged rows lay");
    forged2.bind = honest.tag.bind.clone();
    forged2.joint.clear();
    let unbound = prove_joined(vec![third.note, forged2]).expect("the untied statement proves");
    let (note, mut tag) = stated();
    tag.joint.clear();
    assert!(verify_joined(&unbound, vec![note, tag]), "calibration: without the tie nothing else refuses these rows");
    // and the honest statement passes under the tie
    let (_, fourth) = lay();
    let ok = prove_joined(vec![fourth.note, fourth.tag]).expect("the honest pair proves");
    let (note, tag) = stated();
    assert!(verify_joined(&ok, vec![note, tag]), "an honest tag statement is admitted under the tie");
}

/// ⛔ §RF-3 spec §3.2 — THE LEDGER'S CELLS ARE THE HEADER'S SLOTS. Before this door check the peer admitted a ledger
/// whose cells were not the block's header slots, so `list ∩ header` named the spend rows (R5, filed 2026-10-24).
/// Now: the header's own slots in any order are admitted; one foreign note slot, one foreign tag, a duplicated
/// slot, a short header, or notes and tags crossed are each refused before any proof work. `header_note_cms` reads
/// the 256 slots off a fixed payload and refuses a short payload or a non-canonical front.
/// TWO-PARTY-REVIEWED: the peer holds only the block's bytes (header slots, oli_tags, the transition).
#[test]
fn rf3_the_ledger_door_admits_only_the_headers_own_slots() {
    use crate::cover::{BLOCK_FIXED_NOTE_COUNT, PQ_NOTE_BYTES};
    let (onr, _dsr) = roots2();
    let seed = lanes_of(&[0x5eed, 0x32, 3, 4]);
    let (s72, payer_tags) = filed_spend(72);
    let spends = vec![s72];
    let tags = uniform_ledger_filing(&spends, &[], &[], seed, &payer_tags).expect("the busy filing");
    let (busy, commit, _) = build_ledger_with(&spends, &[], &[], seed, &onr, &tags, true).expect("an armed producer lays");
    let (cms, ptags) = hdr(&busy);
    assert_eq!((cms.len(), ptags.len()), (BLOCK_FIXED_NOTE_COUNT, BLOCK_FIXED_NOTE_COUNT), "256 + 256 header slots");
    let door = |c: &[[u8; 32]], t: &[[u8; 32]]| verify_ledger_with(&busy, &onr, &commit, &tags, c, t, true);
    assert!(door(&cms, &ptags).is_some(), "the header's own slots are admitted");
    let (mut rc, mut rt) = (cms.clone(), ptags.clone());
    rc.reverse();
    rt.reverse();
    assert!(door(&rc, &rt).is_some(), "the header's slot order is the record's permutation, not the list's");
    let foreign = crate::spend_frontier::leaf_to_cm_bytes(lanes_of(&[0xf0, 0xe1, 0x9e, 7]));
    let mut c1 = cms.clone();
    c1[17] = foreign;
    assert!(door(&c1, &ptags).is_none(), "⛔ a header note slot the ledger never stated");
    let mut t1 = ptags.clone();
    t1[200] = foreign;
    assert!(door(&cms, &t1).is_none(), "⛔ a header tag the ledger never stated");
    let mut dup = cms.clone();
    dup[1] = dup[0];
    assert!(door(&dup, &ptags).is_none(), "⛔ a duplicated header slot");
    assert!(door(&cms[1..], &ptags).is_none(), "⛔ a 255-slot header");
    assert!(door(&ptags, &cms).is_none(), "⛔ notes and tags crossed");
    let mut payload = vec![0u8; BLOCK_FIXED_NOTE_COUNT * PQ_NOTE_BYTES];
    for (u, cm) in payload.chunks_exact_mut(PQ_NOTE_BYTES).zip(&cms) {
        u[..32].copy_from_slice(cm);
    }
    assert_eq!(header_note_cms(&payload).as_deref(), Some(&cms[..]), "the payload's 256 fronts are the header slots");
    assert!(header_note_cms(&payload[PQ_NOTE_BYTES..]).is_none(), "⛔ a 255-unit payload");
    payload[..32].fill(0xff);
    assert!(header_note_cms(&payload).is_none(), "⛔ a non-canonical commitment front");
}

/// R4 lever 4 C2 — the member carrier of [`filed_spend`]`(i)`'s input (the same witness: its input leaf, its nullifier
/// as binder, its lc blind, its two outputs), on a full-depth path, and a ring holding its anchor beside a decoy — what a
/// real ledger's joined proof needs for the spend row. Asserts the carrier speaks for exactly that spend (the cross-bind).
fn member_for(i: u64, t: &SpendTuple) -> ((Vec<u8>, usdm_decider::member_path_gate::MemberTuple), Vec<Digest4>) {
    let w = witness(i);
    let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w).expect("the spend's input leaf");
    let nf = crate::spend_frontier::cm_bytes_to_root(&t.nullifier).expect("canonical nullifier");
    let outs = crate::member_transition::outs_digest(&t.out0_cm, &t.out1_cm).expect("canonical outputs");
    let sibs: Vec<Digest4> = (0..usdm_decider::member_path_gate::MEMBER_PATH_DEPTH as u64).map(|l| lanes_of(&[l, i, 11])).collect();
    let dirs: Vec<bool> = (0..usdm_decider::member_path_gate::MEMBER_PATH_DEPTH).map(|l| (l as u64 + i) % 3 == 0).collect();
    let c = usdm_decider::member_path_gate::prove_member_path_carrier(leaf, &sibs, &dirs, nf, w.lc_blind, outs)
        .expect("an honest full-depth path proves");
    assert_eq!(c.1.leaf_commit, crate::spend_frontier::cm_bytes_to_root(&t.leaf_commit).expect("lc"), "the carrier's lc is the spend's");
    let ring = vec![lanes_of(&[0xdec0, i]), c.1.anchor];
    (c, ring)
}

/// A spend whose payer filed a locator key for both outputs, and the block's `oli_tags` for exactly those two.
fn filed_spend(i: u64) -> ((Vec<u8>, SpendTuple, Digest4), Vec<u8>) {
    let w = witness(i);
    let keys = [[i as u8; crate::oli::K_BYTES], [i as u8 ^ 0xa5; crate::oli::K_BYTES]];
    let (blob, cms, nf, lc, d) = prove_filed_spend(&w, keys.map(Some)).expect("the production spend proves");
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let tag1 = b(usdm_decider::whir_rec_block::spend_tag1(&w));
    let t = SpendTuple { out0_cm: b(cms[0]), out1_cm: b(cms[1]), nullifier: b(nf), leaf_commit: b(lc), tag1 };
    let mut recs = [(t.out0_cm, keys[0]), (t.out1_cm, keys[1])];
    recs.sort();
    let tags = recs.iter().flat_map(|(cm, k)| cm.iter().chain(k.iter()).copied()).collect();
    ((blob, t, d), tags)
}

/// ⭐ §RF-3 §12.1 — THE MEMBER LEDGER'S PUBLIC ROWS ARE ONE FUNCTION OF THE NOTE LEDGER, AT EVERY n (pin (1) of §12,
/// on the derivation the member proof will be verified against). Busy blocks of n = 0, 1, 3 real spends, each laid by
/// the armed production producer and admitted by the armed production door: the member rows are always
/// `LEDGER_ROWS` (the list never states n), no column holds a zero or a repeat (neither splits a class), and each
/// spend's own `(lc, nf, outs)` — the member carrier's cross-bind — is exactly one row. TAMPER: a 127-row list derives
/// nothing; a moved `lc` / `tag0` / `out1` moves exactly that row's cell.
/// TWO-PARTY-REVIEWED: the producer side is `build_ledger_with`; the peer side holds only the carried bytes
/// (`verify_ledger_with`, then `decode_ledger_published` of `nt.tuples`) and derives the rows from them — the member
/// list never crosses the boundary, which is the claim.
#[test]
fn rf3_member_ledger_rows_are_one_function_of_the_note_ledger_at_every_n() {
    use crate::member_transition::{ledger_member_rows, outs_digest};
    use usdm_decider::slot_ledger::{PUB_LC, PUB_OUT1, PUB_TAG0};
    let (onr, _dsr) = roots2();
    let r = crate::spend_frontier::cm_bytes_to_root;
    let mut last = None;
    for n in [0u64, 1, 3] {
        let seed = lanes_of(&[0x5eed, 0x12, n, 1]);
        let (spends, payer): (Vec<_>, Vec<_>) = (0..n).map(|i| filed_spend(80 + 10 * n + i)).unzip();
        let tags = block_filing(&spends, seed, &payer.concat());
        let (nt, commit, _) = build_ledger_with(&spends, &[], &[], seed, &onr, &tags, true).expect("the armed producer lays it");
        verify_ledger_with(&nt, &onr, &commit, &tags, &hdr(&nt).0, &hdr(&nt).1, true).expect("the armed door admits it");
        let published = decode_ledger_published(&nt.tuples).expect("the list decodes");
        let rows = ledger_member_rows(&published).expect("every row derives");
        assert_eq!(rows.len(), usdm_decider::settlement_delta::LEDGER_ROWS, "⛔ the member list's length names n = {n}");
        for c in 0..3 {
            let col: std::collections::BTreeSet<_> = rows.iter().map(|row| row[c]).collect();
            assert_eq!(col.len(), rows.len(), "⛔ n = {n}: member column {c} repeats a cell — a repeat splits a class");
            assert!(!col.contains(&[0u64; 8]), "⛔ n = {n}: member column {c} holds a zero — a zero splits a class");
        }
        for (_, t, _) in &spends {
            let own = [r(&t.leaf_commit).unwrap(), r(&t.nullifier).unwrap(), outs_digest(&t.out0_cm, &t.out1_cm).unwrap()];
            assert_eq!(rows.iter().filter(|row| **row == own).count(), 1, "⛔ n = {n}: a spend's cross-bind is not one row");
        }
        eprintln!("[rf3-member] n = {n}: {} member rows, 0 wire bytes, note list {} B", rows.len(), nt.tuples.len());
        last = Some((published, rows));
    }
    let (published, rows) = last.expect("the n = 3 block");
    assert!(ledger_member_rows(&published[1..]).is_none(), "⛔ a 127-row list derived member rows");
    for (cell, c) in [(PUB_LC, 0), (PUB_TAG0, 1), (PUB_OUT1, 2)] {
        let mut moved = published.clone();
        moved[7][cell][1] ^= 1;
        let m = ledger_member_rows(&moved).expect("a canonical moved cell derives");
        let diff: Vec<(usize, usize)> =
            (0..rows.len()).flat_map(|i| (0..3).map(move |k| (i, k))).filter(|&(i, k)| m[i][k] != rows[i][k]).collect();
        assert_eq!(diff, vec![(7, c)], "⛔ a moved note cell {cell} did not move exactly member row 7 column {c}");
    }
}

/// The filing a ledger block carries, as the producer lays it.
fn block_filing(spends: &[(Vec<u8>, SpendTuple, Digest4)], seed: Digest4, payer_tags: &[u8]) -> Vec<u8> {
    uniform_ledger_filing(spends, &[], &[], seed, payer_tags).expect("the producer files the block uniformly")
}

/// ⛔ §RF-3 §10 C1 — "IS FILED" SPLITS NO CLASS (hole H1). The CONTENT census at block level: for every published
/// note cell, "appears in the block's `oli_tags`" has the same outcome on spend rows and cover rows, and the
/// filing's record count is the same quiet or busy. RED when the block files only what payers filed (today: the
/// spend row's two outputs filed, every cover note not). Armed (bound) ledger: the census reads the list, not the
/// proof. TWO-PARTY-REVIEWED: the producer's `build_ledger_with` and the peer's `verify_ledger_with`.
#[test]
fn rf3_c1_is_filed_splits_no_class_and_the_filing_count_is_constant() {
    use usdm_decider::slot_ledger::{PUB_OUT0, PUB_OUT1};
    let (onr, _dsr) = roots2();
    let seed = lanes_of(&[0x5eed, 0xc1, 3, 4]);
    let (s, payer_tags) = filed_spend(72);
    let spends = vec![s];
    let t = &spends[0].1;
    let busy_tags = block_filing(&spends, seed, &payer_tags);
    let quiet_tags = block_filing(&[], seed, &[]);
    let (busy, commit, _) =
        build_ledger_with(&spends, &[], &[], seed, &onr, &busy_tags, true).expect("an armed producer lays the busy ledger");
    verify_ledger_with(&busy, &onr, &commit, &busy_tags, &hdr(&busy).0, &hdr(&busy).1, true).expect("the peer admits the busy ledger");
    let filed = filed_keys(&busy_tags).expect("a filing");
    let published = decode_ledger_published(&busy.tuples).expect("the list decodes");
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let mut split = Vec::new();
    for (c, col) in [(PUB_OUT0, "OUT0"), (PUB_OUT1, "OUT1")] {
        let (mut spend_filed, mut cover_filed) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
        for p in &published {
            let is_spend = b(p[PUB_OUT0]) == t.out0_cm;
            let f = filed.contains_key(&b(p[c]));
            if is_spend { spend_filed.insert(f) } else { cover_filed.insert(f) };
        }
        assert_eq!(spend_filed.len(), 1, "exactly one spend row is found");
        if spend_filed != cover_filed {
            split.push(format!("{col}: spend {spend_filed:?} vs cover {cover_filed:?}"));
        }
    }
    eprintln!("[rf3-c1] filing records busy {} quiet {}; split {split:?}", busy_tags.len() / 48, quiet_tags.len() / 48);
    assert!(split.is_empty(), "⛔ H1: 'is filed' names the spend rows: {split:?}");
    assert_eq!(busy_tags.len(), quiet_tags.len(), "⛔ the filing's record count names the spend count");
    assert_eq!(busy_tags.len(), 48 * 2 * usdm_decider::settlement_delta::LEDGER_ROWS, "every published note, once");

    // each non-uniform filing is refused by the door AND never laid by the producer
    let swap = |v: &[u8], i: usize| {
        let mut w = v.to_vec();
        let (a, b) = w.split_at_mut((i + 1) * 48);
        a[i * 48..].swap_with_slice(&mut b[..48]);
        w
    };
    let extra = [busy_tags.as_slice(), &[0xffu8; 48]].concat();
    let short = busy_tags[48..].to_vec();
    for (bad, why) in [
        (payer_tags.clone(), "the payers' filing only (cover notes unfiled)"),
        (swap(&busy_tags, 0), "two records out of order"),
        (extra, "a record for a note the block does not publish"),
        (short, "a published note left unfiled"),
    ] {
        assert!(verify_ledger_with(&busy, &onr, &commit, &bad, &hdr(&busy).0, &hdr(&busy).1, true).is_none(), "⛔ the door admitted {why}");
        assert!(build_ledger_with(&spends, &[], &[], seed, &onr, &bad, true).is_none(), "⛔ a producer laid {why}");
    }
    let unfiled = vec![spend(73)];
    assert!(uniform_ledger_filing(&unfiled, &[], &[], seed, &[]).is_none(), "⛔ a spend output its payer never filed");
}

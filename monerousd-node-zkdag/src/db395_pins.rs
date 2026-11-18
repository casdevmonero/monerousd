// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ DB-395 — THE SENDER OF A NOTE MUST HOLD NO SPEND AUTHORITY OVER IT, AND MUST NOT KNOW ITS NULLIFIER (T0 funds +
//! privacy; `docs/DB-395-SENDER-KNOWS-THE-RECIPIENTS-SPEND-KEY.md` C5). Judged on a PEER fed only blocks: a payer that can
//! still spend what it paid can reverse a settled payment, and a payer that can compute the payee's nullifier learns when
//! the payee spends. Each attack is paired with a CALIBRATION through the same path (the payee's own spend settles on the
//! peer), so a refusal for an unrelated reason can never read as the property.
//!
//! MEASURED RED-first (2026-10-05 06:54, before the fix, `consensus-db395-red1.log`): the claw-back SETTLED on the peer after
//! its calibration held, and the payer's nullifier equalled the payee's. The assertions below are unchanged since; what
//! changed is what each party HOLDS — the payer holds the note's seed, its opening and the payee's public `spk`, never the
//! payee's `(ask, nk)`.

use crate::faucet::RecipientSecrets;
use crate::hash::Hash32;
use crate::node::Node;
use crate::relay::RelayOutcome;
use crate::spend_frontier::Digest4;
use usdm_decider::whir_rec_block::{NoteOwner, SpendValidityWitness, USDM_ASSET_TAG};

/// The paid amount (the carrying fixture's credit object states 1,000 base units).
const VALUE: u64 = 1_000 + usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC; // §BR-14: a spend of it pays the fee

/// What the PAYER holds after sealing a note to a payee: everything the KEM handed it — the note's seed and its opening —
/// plus the payee's public address. It never holds the payee's `(ask, nk)`.
pub(crate) struct PayerView {
    seed: Digest4,
    opening: Digest4,
    payee_spk: Digest4,
}

/// A payer seals a `VALUE` note to the payee of `payee_seed`; producer `a` carries it in a block, peer `b` grafts and folds
/// it. Returns `(the note, its commitment, the payee's secrets, what the payer holds)`.
pub(crate) fn a_note_paid_to_a_payee(
    a: &mut Node,
    b: &mut Node,
    payee_seed: &[u8; 32],
    seal_seed: [u8; 32],
    ts: u64,
) -> (Vec<u8>, [u8; 32], RecipientSecrets, PayerView) {
    let payee = RecipientSecrets::for_test(payee_seed);
    let (payee_ek, _) = crate::faucet::kem_keypair_from_seed(payee_seed);
    let payee_spk = payee.spk();
    let (note, opening) = crate::faucet::seal_asset_note(&payee_ek, &payee_spk, VALUE, USDM_ASSET_TAG, Some(seal_seed))
        .expect("the payer seals to the payee's address");
    let cm: [u8; 32] = note[..32].try_into().expect("a note begins with its 32-byte commitment");
    let (block, _) = a.carry_notes_in_a_block_for_test(ts, &note);
    let _ = a.fold_canonical_records();
    assert!(matches!(b.ingest_block(block, ts + 500), RelayOutcome::Added(_)), "the payee's note reaches the peer");
    let _ = b.fold_canonical_records();
    // The payer ran the encapsulation, so it holds the shared secret and therefore the note's SEED — read here through the
    // payee's own opening (the same value), which is exactly what a payer can compute.
    let (_, owner, _) = payee.open_asset(&note).expect("the payee opens the note it was paid");
    (note.to_vec(), cm, payee, PayerView { seed: owner.seed, opening, payee_spk })
}

/// A spend of a `VALUE` note under `owner`, both outputs to `out_seed`'s lanes.
pub(crate) fn a_spend_under(owner: NoteOwner, out_seed: u64) -> SpendValidityWitness {
    let lanes = |x: u64| -> Digest4 { core::array::from_fn(|i| x.wrapping_add(i as u64)) };
    SpendValidityWitness {
        value_in: VALUE,
        owner,
        value_out: (VALUE - 100) - 99900,
        fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
        lc_blind: usdm_decider::whir_rec_block::fresh_lc_blind().expect("the OS CSPRNG draws a membership blinding"),
        out0_value: (VALUE - 150) - 99900,
        out0_opening: lanes(out_seed),
        out1_value: 50,
        out1_opening: lanes(out_seed ^ 0xFFFF),
    }
}

/// The payer's best attempt at an owner: the seed it holds, under spend secrets it can only GUESS (it never sees the payee's).
fn the_payers_forged_owner(p: &PayerView) -> NoteOwner {
    let guess = || usdm_decider::whir_rec_block::fresh_lc_blind().expect("the OS CSPRNG draws a guess");
    NoteOwner { ask: guess(), nk: guess(), seed: p.seed }
}

/// `a` pools the spend `w` of `cm`, lays the next block, and peer `b` grafts and folds it. Returns the nullifier the spend
/// published, or `None` when `a` could not even pool it (refused at the first door).
pub(crate) fn spend_and_relay(a: &mut Node, b: &mut Node, cm: &[u8; 32], w: &SpendValidityWitness, ts: u64) -> Option<[u8; 32]> {
    let (_, nf) = a.spend_tx_for_witness_for_test(cm, w).ok()?;
    let block = a.produce(ts, Hash32::hash(&ts.to_le_bytes()), Hash32::hash(b"db395-mc")).expect("A lays the next block");
    let _ = a.fold_canonical_records();
    let _ = b.ingest_block(block, ts + 500);
    let _ = b.fold_canonical_records();
    Some(nf)
}

/// ⛔⛔⛔ C5 pin 1 — THE CLAW-BACK. A payer seals a note to its payee and the note settles on both nodes; the payer then spends
/// it under everything it holds. A PEER must not settle that spend. CALIBRATION: on a second paid note the PAYEE's own spend
/// (its `(ask, nk)` and the seed its decapsulation recovers) settles on the same peer through the same path.
#[test]
fn db395_a_payer_cannot_spend_the_note_it_paid_and_its_payee_can() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    // CALIBRATION FIRST, on its own note: the payee spends what it was paid, and the peer settles it.
    let (note_c, cm_c, payee_c, _) = a_note_paid_to_a_payee(&mut a, &mut b, &[0x95; 32], [0x39; 32], 5_000);
    let (_, payee_owner, _) = payee_c.open_asset(&note_c).expect("the payee opens the note it was paid");
    let payee_nf = spend_and_relay(&mut a, &mut b, &cm_c, &a_spend_under(payee_owner, 0xCA11), 7_000)
        .expect("CALIBRATION: the payee pools a spend of its own note");
    assert!(
        b.is_nullifier_spent(&Hash32(payee_nf)),
        "CALIBRATION: the payee's own spend must settle on the peer, or this pin measures nothing"
    );
    // THE ATTACK, on a second note paid to another payee: the payer holds the seed, the opening and the payee's spk.
    let (_, cm, _, payer) = a_note_paid_to_a_payee(&mut a, &mut b, &[0x96; 32], [0x3A; 32], 9_000);
    let forged = the_payers_forged_owner(&payer);
    if let Some(nf) = spend_and_relay(&mut a, &mut b, &cm, &a_spend_under(forged, 0xC1A0), 11_000) {
        assert!(
            !b.is_nullifier_spent(&Hash32(nf)),
            "⛔⛔⛔ DB-395: a PEER settled the PAYER's spend of the note it paid — every payment is reversible by its payer"
        );
    }
    // And the payer cannot even OPEN the note as an input: no witness it can build names the note's commitment.
    let forged_spend = a_spend_under(forged, 0xC1A1);
    let named = usdm_decider::whir_rec_block::spend_input_leaf(&forged_spend).expect("states");
    assert_ne!(
        crate::spend_frontier::leaf_to_cm_bytes(named),
        cm,
        "⛔⛔⛔ DB-395: the payer's own witness opens the payee's commitment — the opening does not bind the payee's spend key"
    );
    let _ = (payer.opening, payer.payee_spk);
}

/// ⛔⛔⛔ C5 pin 2 — THE PRODUCING NODE CANNOT SPEND ITS OWN REWARD. The node seals every reward (it holds the note, the seed
/// and the opening, and the operator wallet's public `spk`); no input witness it can build names the reward's commitment.
/// CALIBRATION: the operator wallet's true owner names it exactly.
#[test]
fn db395_the_producing_node_cannot_spend_the_reward_it_sealed() {
    let seed = [0x7E; 32];
    let (rc, _dk) = crate::satoshi::RewardRecipient::for_test(&seed);
    let sealed = crate::satoshi::SatoshiRewardTx::seal(&rc, 0, 1_000, Some([0x5E; 32])).expect("a reward seals");
    let cm = sealed.note_cm().expect("a full-width note");
    let operator = RecipientSecrets::for_test(&seed);
    let (amount, owner, tag) = operator.open_asset(&sealed.note).expect("CALIBRATION: the operator's wallet opens its reward");
    let named_by = |owner: NoteOwner| {
        crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(amount, tag, owner.opening()))
    };
    assert_eq!(named_by(owner), cm, "CALIBRATION: the operator's owner names its reward as an input");
    // The node holds the seed (it ran the encapsulation) and the operator's public spk; its spend secrets are guesses.
    let guess = || usdm_decider::whir_rec_block::fresh_lc_blind().expect("the OS CSPRNG draws a guess");
    let node_owner = NoteOwner { ask: guess(), nk: guess(), seed: owner.seed };
    assert_ne!(named_by(node_owner), cm, "⛔⛔⛔ DB-395: the PRODUCING NODE names its own reward as an input — it can spend it");
    // ⛔ and the old shape is gone: the opening the node DOES hold is not a key (spending it as `ask` opens nothing).
    let as_key = NoteOwner { ask: owner.opening(), nk: owner.opening(), seed: owner.seed };
    assert_ne!(named_by(as_key), cm, "⛔⛔⛔ DB-395: the sealed reward's opening still spends it");
}

/// ⛔⛔⛔ C5 pin 3 — THE PAYER MUST NOT KNOW THE PAYEE'S NULLIFIER. The nullifier the payee's spend lays is read off the
/// production prover's own statement of that spend; none of the payer's computations from what it holds may equal it, or
/// the payer learns WHEN its payee spends (linkage across transactions).
#[test]
fn db395_the_payer_cannot_compute_the_nullifier_its_payees_spend_records() {
    let payee_seed = [0x97; 32];
    let payee = RecipientSecrets::for_test(&payee_seed);
    let (payee_ek, _) = crate::faucet::kem_keypair_from_seed(&payee_seed);
    let (note, opening) = crate::faucet::seal_asset_note(&payee_ek, &payee.spk(), VALUE, USDM_ASSET_TAG, Some([0x3B; 32]))
        .expect("the payer seals to the payee's address");
    let (_, owner, _) = payee.open_asset(&note).expect("the payee opens its note");
    let (_, _, recorded, _, _) =
        crate::note_transition::prove_unfiled_spend(&a_spend_under(owner, 0xCA12)).expect("the payee's spend proves");
    let cm = crate::spend_frontier::note_cm_of(&note).expect("a full-width note");
    assert_eq!(recorded, owner.nullifier(&cm), "CALIBRATION: the proven nullifier is P(nk, cm)");
    let pair = usdm_decider::whir_rec_block::poseidon_pair;
    for (what, guess) in [("opening", opening), ("seed", owner.seed), ("spk", payee.spk())] {
        assert_ne!(
            pair(guess, cm),
            recorded,
            "⛔⛔⛔ DB-395: the PAYER computes the nullifier its payee's spend records from the {what} — it learns when the payee spends"
        );
    }
}

/// ⛔⛔⛔ C5 pin 4 — C2 FAERIE GOLD UNDER THE NEW FORMAT, on a PEER. A payer that carries the SAME paid note twice pays twice
/// and the payee is credited ONCE: one commitment opens one owner, so both copies name ONE nullifier (`nf = P(nk, cm)`) and
/// the note is spendable exactly once. CALIBRATION: the first spend settles on the peer through the same path.
#[test]
fn db395_c2_a_note_carried_twice_is_spendable_once_on_a_peer() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    let (note, cm, payee, _) = a_note_paid_to_a_payee(&mut a, &mut b, &[0x98; 32], [0x3C; 32], 5_000);
    // The payer repeats the exact note bytes in a second block (a duplicate commitment only its sender or payee can make).
    let (again, _) = a.carry_notes_in_a_block_for_test(7_000, &note);
    let _ = a.fold_canonical_records();
    let _ = b.ingest_block(again, 7_500);
    let _ = b.fold_canonical_records();
    let (_, owner, _) = payee.open_asset(&note).expect("the payee opens the note it was paid");
    let nf1 = spend_and_relay(&mut a, &mut b, &cm, &a_spend_under(owner, 0xC2C2), 9_000)
        .expect("CALIBRATION: the payee pools a spend of its note");
    assert!(b.is_nullifier_spent(&Hash32(nf1)), "CALIBRATION: the first spend settles on the peer");
    // The second copy names the SAME nullifier — the same owner over the same commitment.
    let cm_d = crate::spend_frontier::note_cm_of(&note).expect("a full-width note");
    assert_eq!(
        crate::spend_frontier::leaf_to_cm_bytes(owner.nullifier(&cm_d)),
        nf1,
        "the duplicate copy's nullifier is the spent one: a commitment opens one owner and one nullifier"
    );
    let second = a_spend_under(owner, 0xC2C3);
    let out0 = crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(
        second.out0_value,
        USDM_ASSET_TAG,
        second.out0_opening,
    ));
    let _ = spend_and_relay(&mut a, &mut b, &cm, &second, 11_000);
    assert!(
        b.records_containing_cm(&out0).is_empty(),
        "⛔⛔⛔ DB-395 C2 (faerie gold): a note carried twice was spent a SECOND time on the peer — its payee was credited twice"
    );
}

/// ⛔⛔ C5 pin 5 — C3 MALLEABILITY, a CALIBRATION that holds on both sides of the change. An ordinary send reaches a node
/// through exactly two doors: its submitter's `/submit_pq_tx`, whose sound arm verifies the carrier over the transaction's OWN
/// recorded outputs (`verify_spend_validity_carrier_bytes`), and a peer's graft of the block that carries it (a gossiped send
/// is refused fail-closed — `admit_tx_shared`). So:
/// (1) the submit door's own verify refuses a valid proof under a MOVED output 0, and accepts the honest outputs;
/// (2) a producer that pools the moved spend PAST that verify (`ingest_tx_prechecked`, whose caller is supposed to have run it)
///     lays a block, and the PEER records no moved output and settles nothing.
/// CALIBRATION for (2), on a SECOND note so the two cannot interact: the honest spend through the same pool door settles on
/// the same peer.
/// (MEASURED 2026-10-05: the first draft asserted (2)'s pool door refused the move — it is the precheck door and verifies
/// nothing by contract; the question is what the PEER does. Then MEASURED green in 20.9 s, the line reading
/// `[db395-c3] moved spend pooled=true carried_by_block=false block_has_transition=false`: the producer's own template
/// verify (`note_transition::carrier_verifies`) drops the moved spend, so no block carries it. A ROGUE producer that skipped
/// that verify can lay no transition over the moved carrier (the transition's aggregate verifies each carrier), so its
/// unproven lane tag is the door `db367_a_lane_tag_nothing_proves_does_not_burn_a_victims_pending_spend_on_a_peer` pins.)
#[test]
fn db395_c3_a_relay_that_moves_an_output_under_a_valid_proof_is_refused() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    let (note, cm, payee, _) = a_note_paid_to_a_payee(&mut a, &mut b, &[0x99; 32], [0x3D; 32], 5_000);
    let (_, owner, _) = payee.open_asset(&note).expect("the payee opens the note it was paid");
    let w = a_spend_under(owner, 0xC3C3);
    let (blob, out_cms, nf, lc, filing) = crate::note_transition::prove_wallet_spend(&w).expect("the payee's spend proves");
    let tag1 = usdm_decider::whir_rec_block::spend_tag1(&w);
    // THE RELAY'S MOVE: output 0 now names a note the relay chose; the proof bytes are untouched.
    let moved = usdm_decider::poseidon2_compress::lanes_of(&[0x0BAD, 0xC0DE, 3, 4]);
    let verify = |o0| usdm_decider::verify_spend_validity_carrier_bytes(&blob, o0, out_cms[1], nf, lc, filing, tag1, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC);
    // (1) THE SUBMIT DOOR'S OWN VERIFY.
    assert!(verify(out_cms[0]), "CALIBRATION: the honest outputs verify at the submit door");
    assert!(!verify(moved), "⛔⛔ DB-395 C3: a valid proof verified under a MOVED output — a relay can redirect a payment");
    // (2) PAST THE SUBMIT DOOR, INTO A BLOCK: the peer records no moved output and settles nothing.
    let moved_cm = crate::spend_frontier::leaf_to_cm_bytes(moved);
    let pooled = a.spend_tx_from_carrier_for_test(&cm, (blob, [moved, out_cms[1]], nf, lc, tag1), &w);
    let nf_bytes = crate::spend_frontier::leaf_to_cm_bytes(nf);
    let block = a.produce(9_000, Hash32::hash(&9_000u64.to_le_bytes()), Hash32::hash(b"db395-c3")).expect("A lays the block");
    // Which defense met the move: the producer's template verify (`note_transition::carrier_verifies`) drops it before any
    // block carries it, or a block carries it and the peer's door refuses it. Either is a refusal; the line names which.
    let carried = pooled.as_ref().is_ok_and(|(id, _)| block.tx_ids.contains(id));
    eprintln!(
        "[db395-c3] moved spend pooled={} carried_by_block={carried} block_has_transition={}",
        pooled.is_ok(),
        block.note_transition.is_some()
    );
    let _ = a.fold_canonical_records();
    let _ = b.ingest_block(block, 9_500);
    let _ = b.fold_canonical_records();
    assert!(b.records_containing_cm(&moved_cm).is_empty(), "⛔⛔ DB-395 C3: the moved output was recorded on the peer");
    assert!(
        !b.is_nullifier_spent(&Hash32(nf_bytes)),
        "⛔⛔ DB-395 C3: the moved spend settled its input on the peer (pooled: {:?})",
        pooled.as_ref().map(|_| ())
    );
    // CALIBRATION, on a second note through the same pool door: the honest spend settles on the peer.
    let (note2, cm2, payee2, _) = a_note_paid_to_a_payee(&mut a, &mut b, &[0x9A; 32], [0x3E; 32], 11_000);
    let (_, owner2, _) = payee2.open_asset(&note2).expect("the second payee opens its note");
    let honest_nf = spend_and_relay(&mut a, &mut b, &cm2, &a_spend_under(owner2, 0xC3C4), 13_000)
        .expect("CALIBRATION: the honest spend pools");
    assert!(b.is_nullifier_spent(&Hash32(honest_nf)), "CALIBRATION: the honest spend settles on the peer");
}

/// ⛔⛔ THE C4 DETECTOR — does `bytes` carry digest `d` in any encoding a door could publish it in? The 248-bit packed form
/// (`digest_to_bytes`, every 32-byte commitment field), and every ADJACENT LANE PAIR as canonical u32 LE, Montgomery u32 LE
/// (the KoalaBear internal form), u64 LE and postcard varint — so a field element serialized by serde, a public input
/// written raw, or a digest dropped into a struct are all seen. Pairs, never single lanes: a lane is 31 bits, so a single-lane
/// match would fire by chance on a 100 KB proof; a pair is ≥ 62 bits (see [`census_checkable`]). Returns the encoding hit.
pub(crate) fn leak_of(bytes: &[u8], d: &Digest4) -> Option<&'static str> {
    digest_encodings(d).into_iter().find(|(_, pat)| bytes.windows(pat.len()).any(|w| w == &pat[..])).map(|(name, _)| name)
}

/// Every pattern [`leak_of`] searches for, by name.
pub(crate) fn digest_encodings(d: &Digest4) -> Vec<(&'static str, Vec<u8>)> {
    const P: u64 = 0x7F00_0001; // KoalaBear
    let mont = |x: u64| (((x % P) << 32) % P) as u32;
    let varint = |mut x: u64, out: &mut Vec<u8>| loop {
        let b = (x & 0x7F) as u8;
        x >>= 7;
        if x == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    };
    let mut out = vec![("packed-32", usdm_decider::poseidon2_compress::digest_to_bytes(d).to_vec())];
    for i in 0..d.len() - 1 {
        let (x, y) = (d[i] % P, d[i + 1] % P);
        if x < 1 << 20 || y < 1 << 20 {
            continue; // a pair with a small lane could match by chance; the packed form still covers the whole digest
        }
        out.push(("u32-le", [(x as u32).to_le_bytes(), (y as u32).to_le_bytes()].concat()));
        out.push(("mont-u32-le", [mont(x).to_le_bytes(), mont(y).to_le_bytes()].concat()));
        out.push(("u64-le", [x.to_le_bytes(), y.to_le_bytes()].concat()));
        let mut v = Vec::new();
        varint(x, &mut v);
        varint(y, &mut v);
        out.push(("varint", v));
    }
    out
}

/// Whether the census reaches `d` in every per-lane encoding: at least four adjacent pairs whose lanes are both ≥ 2^20, so each
/// searched pair carries ≥ 40 bits (≈ 2.5e-5 expected chance hits over every pattern of both C4 pins' bytes).
pub(crate) fn census_checkable(d: &Digest4) -> bool {
    (0..d.len() - 1).filter(|&i| d[i] % 0x7F00_0001 >= 1 << 20 && d[i + 1] % 0x7F00_0001 >= 1 << 20).count() >= 4
}

/// CALIBRATION shared by the C4 pins: every secret is checkable and the detector finds it, in every encoding, inside bytes
/// that carry it — so a clean census is a census that could have fired.
pub(crate) fn calibrate_c4_detector(secrets: &[(&str, Digest4)]) {
    for (name, d) in secrets {
        assert!(census_checkable(d), "CALIBRATION: the {name} has a lane too small for the census to tell a hit from chance");
        for (enc, pat) in digest_encodings(d) {
            let mut hay = vec![0xA5u8; 61];
            hay.extend_from_slice(&pat);
            hay.extend_from_slice(&[0x5Au8; 67]);
            assert_eq!(leak_of(&hay, d).is_some(), true, "CALIBRATION: the detector missed the {name} in its {enc} form");
        }
    }
}

/// ⛔⛔ C5 pin 6 — DB-395 C4 / DB-393 B4 C4: NOTHING A SPEND PUBLISHES NAMES A SECRET OF ITS INPUT'S OWNER. The spend
/// transaction (every field: the carrier, the member leg, the tag lane, the absence evidence), the block that carries it and
/// the input note itself are searched for the owner's `ask`, `nk`, the note's seed, its owner tag `o = P(spk, seed)` and the
/// address key `spk`. The owner tag is the B4 argument's premise: `o` may be public ONCE (at a reward's mint) only while no
/// spend re-publishes it; `spk` published would link every payment to its address. CALIBRATION: the detector finds each
/// secret in bytes that carry it, and the spend settles on the peer (so the census read a real, carried spend).
#[test]
fn db395_c4_a_spend_and_its_block_publish_no_secret_of_the_input_owner() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    let (note, cm, payee, _) = a_note_paid_to_a_payee(&mut a, &mut b, &[0x9B; 32], [0x3F; 32], 5_000);
    let (_, owner, _) = payee.open_asset(&note).expect("the payee opens the note it was paid");
    let secrets = [("ask", owner.ask), ("nk", owner.nk), ("seed", owner.seed), ("o", owner.opening()), ("spk", owner.spk())];
    calibrate_c4_detector(&secrets);
    let w = a_spend_under(owner, 0xC4C4);
    let (blob, out_cms, nf, lc, _) = crate::note_transition::prove_wallet_spend(&w).expect("the payee's spend proves");
    let tag1 = usdm_decider::whir_rec_block::spend_tag1(&w);
    let (tx, nf_bytes) = a.build_spend_tx_for_test(&cm, (blob, out_cms, nf, lc, tag1), w.lc_blind).expect("the spend builds");
    let tx_bytes = postcard::to_allocvec(&tx).expect("a transaction encodes");
    let id = a.ingest_tx_prechecked(tx).expect("the honest spend pools");
    let block = a.produce(9_000, Hash32::hash(&9_000u64.to_le_bytes()), Hash32::hash(b"db395-c4")).expect("A lays the block");
    assert!(block.tx_ids.contains(&id), "CALIBRATION: the block carries the spend");
    let block_bytes = postcard::to_allocvec(&block).expect("a block encodes");
    let _ = a.fold_canonical_records();
    let _ = b.ingest_block(block, 9_500);
    let _ = b.fold_canonical_records();
    assert!(b.is_nullifier_spent(&Hash32(nf_bytes)), "CALIBRATION: the census reads a spend the peer settled");
    eprintln!("[db395-c4] searched: spend tx {} B, its block {} B, the input note {} B", tx_bytes.len(), block_bytes.len(), note.len());
    for (what, bytes) in [("the spend transaction", &tx_bytes), ("the block carrying it", &block_bytes), ("the input note", &note)] {
        for (name, d) in &secrets {
            if let Some(enc) = leak_of(bytes, d) {
                panic!("⛔⛔ DB-395 C4: {what} publishes the input owner's {name} ({enc} form)");
            }
        }
    }
}

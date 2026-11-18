// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::order_fill_settlement_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! The DEX money path, at the node: a maker's resting order and a stranger's fill settle as ONE
//! atomic admission. The failures pinned here are the fund-loss shapes: double-fill, self-dealing,
//! a half-applied fill, and a credit nobody can find.

use super::*;
use usdm_decider::whir_rec_block::{
    prove_order_maker_half, prove_order_taker_half, wrapped_asset_tag_u32, MakerHalfWitness,
    OrderTerms, TakerHalfWitness,
};
use crate::node::tests::genesis_block;

fn terms() -> OrderTerms {
    // DEX-GRID (C3): through the one snap helper.
    OrderTerms {
        lot: crate::order_book::snap_to_grid(100_000),
        pay_b: crate::order_book::snap_to_grid(6_500_000),
        asset_a: wrapped_asset_tag_u32(1),
        asset_b: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
        expires_at_height: crate::order_book::snap_expiry(1_000_000),
    }
}

/// ⛔ RECORDS FOLD AT THE TIP IN THIS FIXTURE, AND THAT IS NOT A CONVENIENCE.
///
/// A membership cross-bind is FOLDED state: the carrier steps over the block roots this node has
/// folded. A node whose record-fold cursor lags its tip by the default depth has folded none of the
/// blocks a fixture just produced, so the bind builder correctly reports "this node has folded no
/// block roots, so no carrier can be built" and every fill is refused for the wrong reason. The live
/// fold band moves WHEN a note's membership becomes provable, never WHAT is provable — which is why
/// every cross-party fixture in this tree folds at depth 0.
/// ⛔ DB-354's fixture rule too: the fixture models the chain that ADMITS what it plants. `plant_trade` stages its
/// input notes through a bridge credit, and only the testnet identity derives the open-mint allowance that admits
/// one. MEASURED 2026-09-30 09:0x: on the default genesis every plant was refused ("the credited amount exceeds
/// this chain's genesis-derived open-mint allowance"), the notes never rode, and 9 of this module's 12 fills
/// answered `MembershipRefused` — a fixture verdict, not a chain one. Same shape as `dd_node` and the DEX
/// cross-party `party`.
fn a_node() -> Node {
    let mut p = crate::params::ChainParams::default();
    p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
    p.net_prefix_len = p.genesis_parity_commit.len();
    p.record_fold_depth = 0;
    let mut g = genesis_block();
    g.header = crate::block::genesis_header_for_network(&crate::params::network_genesis_prefix("testnet"));
    Node::with_params(g, p).expect("a fixture node builds")
}

fn note_for(cm: crate::spend_frontier::Digest4) -> Vec<u8> {
    let mut v = vec![0u8; 1153];
    v[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
    v
}

/// DB-273 §19.6 L3: a fill slot's owner is an OLI clue; a distinct non-empty value per tag.
fn owner(tag: u8) -> Vec<u8> {
    vec![tag; 8]
}

/// ⭐⭐⭐ DB-150 — PUT BOTH INPUT NOTES ON `n`'s CHAIN AND BUILD THE BINDS A FILL MUST CARRY.
///
/// A settlement may not credit notes this chain never held, so `execute_order_fill` now demands a
/// MEMBERSHIP cross-bind per half before any value moves. Every fixture below therefore has to do
/// what a real maker and taker each do first: receive the note on chain, then prove where it sits.
/// A fixture that skips this is not testing a lenient door — it is testing a trade between notes
/// that do not exist, which is exactly the hole DB-150 named.
///
/// The input commitments are derived with the decider's OWN `asset_note_cm` from the same seeds
/// `a_trade` proves with, so the planted note and the proven half can never drift apart. The binder
/// is the spend's NULLIFIER — the value the gate compares the carrier's output against.
fn plant_trade(
    n: &mut Node,
    t: &OrderTerms,
    maker_seed: u64,
    taker_seed: u64,
    mp: &usdm_decider::whir_rec_block::MakerHalfPublic,
    tp: &usdm_decider::whir_rec_block::TakerHalfPublic,
    now_ms: u64,
) -> ([Option<(Vec<u8>, Vec<u8>)>; 2], Vec<Block>) {
    // ⛔ A MEMBERSHIP BIND IS FOLDED STATE, SO THE FIXTURE MUST ACTUALLY FOLD. The carrier steps over
    // this node's FOLDED block roots; a node whose record-fold cursor lags its tip by the default
    // depth has folded none of the blocks a fixture just produced, and the bind builder correctly
    // reports "this node has folded no block roots, so no carrier can be built". A default-depth node
    // is right to lag — the fixture is what has to catch up, so it folds at depth 0 like every other
    // cross-party fixture in this tree.
    let lanes = |a: u64| usdm_decider::poseidon2_compress::lanes_of(&[a, a + 1, a + 2, a + 3]);
    // DB-395: each input commits to its OWNER's opening `P(spk, seed)` — the halves are built as
    // `NoteOwner::from_test_key(lanes(seed))`, so the planted note must open to that owner, never to the raw key.
    let cm = |v: u64, asset: [u64; 3], key: crate::spend_frontier::Digest4| -> [u8; 32] {
        crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(
            v,
            asset,
            usdm_decider::whir_rec_block::NoteOwner::from_test_key(key).opening(),
        ))
    };
    let (m, k) = (
        n.plant_note_and_bind_for_test(
            &cm(t.lot, t.asset_a, lanes(maker_seed)),
            mp.nullifier,
            b"ofst-maker-note",
            now_ms,
        ),
        n.plant_note_and_bind_for_test(
            &cm(10_000_000, t.asset_b, lanes(taker_seed)),
            tp.nullifier,
            b"ofst-taker-note",
            now_ms + 400,
        ),
    );
    let mut blocks = Vec::new();
    if let Some((_, _, b)) = m.as_ref() {
        blocks.push(b.clone());
    }
    if let Some((_, _, b)) = k.as_ref() {
        blocks.push(b.clone());
    }
    (
        [
            m.map(|(c, tip, _)| (c, tip)),
            k.map(|(c, tip, _)| (c, tip)),
        ],
        blocks,
    )
}

/// Build both halves the way two independent wallets would, plus the three notes the fill records.
#[allow(clippy::type_complexity)]
fn a_trade(
    t: &OrderTerms,
    maker_seed: u64,
    taker_seed: u64,
) -> (
    (Vec<u8>, usdm_decider::whir_rec_block::MakerHalfPublic),
    (Vec<u8>, usdm_decider::whir_rec_block::TakerHalfPublic),
    [Vec<u8>; 3],
) {
    let mw = MakerHalfWitness {
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[maker_seed, maker_seed + 1, maker_seed + 2, maker_seed + 3])),
        payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[maker_seed + 10, maker_seed + 11, maker_seed + 12, maker_seed + 13]),
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
    };
    let (mc, mp) = prove_order_maker_half(&mw, t).expect("maker half proves");
    let tw = TakerHalfWitness {
        value_in: 10_000_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[taker_seed, taker_seed + 1, taker_seed + 2, taker_seed + 3])),
        change_opening: usdm_decider::poseidon2_compress::lanes_of(&[taker_seed + 10, taker_seed + 11, taker_seed + 12, taker_seed + 13]),
        payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[taker_seed + 20, taker_seed + 21, taker_seed + 22, taker_seed + 23]),
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
    };
    let (tc, tp) = prove_order_taker_half(&tw, t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).expect("taker half proves");
    let notes = [note_for(mp.payout_cm), note_for(tp.payout_cm), note_for(tp.change_cm)];
    ((mc, mp), (tc, tp), notes)
}

/// ⭐⭐⭐ THE BOOK AND THE SETTLEMENT ARE ONE SYSTEM: a filled order LEAVES the book.
///
/// TWO PARTIES: a maker rests an order and goes offline; a stranger fills it. If the book kept
/// serving that order afterwards, every later taker would read a dead offer, build a fill, pay the
/// proving cost and be refused — a free denial-of-service on takers, and a book whose contents mean
/// nothing. The resting note is spent; the offer must go with it. A CANCEL retires an order through
/// the SAME door, because a cancel IS the maker self-spending that note.
#[test]
fn a_filled_order_leaves_the_book_so_no_later_taker_reads_a_dead_offer() {
    let t = terms();
    let mut a = a_node();
    let ((mc, mp), (tc, tp), [n0, n1, n2]) = a_trade(&t, 4_100, 4_200);
    // DB-150: both input notes go on chain and the fill carries their membership binds.
    let (binds, _planted) = plant_trade(&mut a, &t, 4_100, 4_200, &mp, &tp, 60_000);

    let resting = crate::order_book::RestingOrder {
        terms: t,
        maker: mp,
        maker_bytes: mc.clone(),
        // The maker's own pre-built payout note — an order without it is unfillable, so the book
        // carries the bytes and not merely their commitment.
        payout_note: n0.clone(),
        membership_carrier: crate::order_book::test_membership_bind().0,
        membership_tip: crate::order_book::test_membership_bind().1,
        payout_clue: crate::order_book::test_payout_clue(),
    };
    let level = a.post_order(resting.clone()).expect("the honest order rests");
    let pair = resting.pair();
    let (before, pad_before) = a.book_level(pair, level);
    assert_eq!(before.len(), 1, "PRECONDITION: the order is being served");

    assert_eq!(
        a.execute_order_fill(&mc, &mp, &tc, &tp, &t, &n0, &n1, &n2, [owner(1), owner(2), owner(3)], binds.clone()),
        OrderFillOutcome::Settled,
        "the resting order fills"
    );

    let (after, pad_after) = a.book_level(pair, level);
    assert!(
        after.is_empty(),
        "a FILLED order is still being served — every later taker would build a fill against a note \
         that is already spent, pay the proving cost, and be refused"
    );
    // ⛔ THE SERVED SHAPE MUST NOT CHANGE. Same slot total before and after, or the shape itself
    // would announce that a fill just happened here — the activity signal the constant shape exists
    // to withhold.
    assert_eq!(
        before.len() + pad_before,
        after.len() + pad_after,
        "the served slot shape must be identical before and after a fill"
    );
}

// ── THE PROTOCOL FILL FEE, AT THE NODE ─────────────────────────────────────────────────────────
//
// The decider's own suite proves a cheap half does not VERIFY. These prove the node actually asks
// that question, with ITS OWN governance rate — a node that verified against a hardcoded constant
// would pass every decider test and still collect nothing the day governance moved the rate.

/// ⛔⛔⛔ A FEE-FREE FILL IS REFUSED BY THE NODE. Not "detected and logged" — refused, because the
/// rate is an input to verification rather than a check beside it.
#[test]
fn a_taker_who_pays_no_fee_cannot_settle_on_the_node() {
    let t = terms();
    let mut a = a_node();
    let ((mc, mp), _, [n0, ..]) = a_trade(&t, 5_100, 5_200);

    // A taker who proves their half at ZERO bps: a real proof, of a trade that pays no fee.
    let tw = TakerHalfWitness {
        value_in: 10_000_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[5_200, 5_201, 5_202, 5_203])),
        change_opening: usdm_decider::poseidon2_compress::lanes_of(&[5_210, 5_211, 5_212, 5_213]),
        payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[5_220, 5_221, 5_222, 5_223]),
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
    };
    let (tc0, tp0) = prove_order_taker_half(&tw, &t, 0).expect("the fee-free half proves for ITS rate");
    let (f1, f2) = (note_for(tp0.payout_cm), note_for(tp0.change_cm));

    let resting = crate::order_book::RestingOrder {
        terms: t,
        maker: mp,
        maker_bytes: mc.clone(),
        payout_note: n0.clone(),
        membership_carrier: crate::order_book::test_membership_bind().0,
        membership_tip: crate::order_book::test_membership_bind().1,
        payout_clue: crate::order_book::test_payout_clue(),
    };
    let pair = resting.pair();
    let level = a.post_order(resting).expect("the honest order rests");

    assert_eq!(
        a.execute_order_fill(&mc, &mp, &tc0, &tp0, &t, &n0, &f1, &f2, [owner(1), owner(2), owner(3)], [None, None]),
        OrderFillOutcome::ProofRefused,
        "a fill that pays no fee must NOT settle"
    );
    // ⛔ AND NOTHING MOVED. A refusal that still burned the maker's note would be worse than
    // settling: the order would vanish and no trade would have happened.
    let (served, _) = a.book_level(pair, level);
    assert_eq!(served.len(), 1, "the refused fill must leave the order resting and unspent");
}

/// ⛔⛔⛔ THE NODE USES ITS OWN GOVERNANCE RATE, NOT A CONSTANT. This is the test that would fail if
/// someone "simplified" `execute_order_fill` to verify against `ORDER_FILL_FEE_BPS_DEFAULT` — which
/// would pass every other test in this file, because the default is what they all use. Governance
/// retunes the rate at runtime; a node deaf to that either collects nothing or splits from its peers.
#[test]
fn the_node_verifies_against_its_own_retuned_rate_and_not_the_default() {
    let t = terms();
    const RETUNED: u64 = 37; // deliberately not the default
    assert_ne!(RETUNED, crate::params::ORDER_FILL_FEE_BPS_DEFAULT);

    let mut a = a_node();
    let mut p = a.params().clone();
    p.order_fill_fee_bps = RETUNED;
    a.set_params(p);

    let ((mc, mp), (tc_default, tp_default), [n0, n1, n2]) = a_trade(&t, 6_100, 6_200);
    // DB-150: both input notes go on chain and the fill carries their membership binds.
    let (binds, _planted) = plant_trade(&mut a, &t, 6_100, 6_200, &mp, &tp_default, 60_000);
    let resting = crate::order_book::RestingOrder {
        terms: t,
        maker: mp,
        maker_bytes: mc.clone(),
        payout_note: n0.clone(),
        membership_carrier: crate::order_book::test_membership_bind().0,
        membership_tip: crate::order_book::test_membership_bind().1,
        payout_clue: crate::order_book::test_payout_clue(),
    };
    a.post_order(resting).expect("the honest order rests");

    // A half proved at the DEFAULT rate is now wrong for this node.
    assert_eq!(
        a.execute_order_fill(&mc, &mp, &tc_default, &tp_default, &t, &n0, &n1, &n2, [owner(1), owner(2), owner(3)], binds.clone()),
        OrderFillOutcome::ProofRefused,
        "after a retune, a half built at the OLD rate must be refused"
    );

    // The same taker, proving at the node's CURRENT rate, settles.
    let tw = TakerHalfWitness {
        value_in: 10_000_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[6_200, 6_201, 6_202, 6_203])),
        change_opening: usdm_decider::poseidon2_compress::lanes_of(&[6_210, 6_211, 6_212, 6_213]),
        payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[6_220, 6_221, 6_222, 6_223]),
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
    };
    let (tc, tp) = prove_order_taker_half(&tw, &t, RETUNED).expect("proves at the retuned rate");
    let (g1, g2) = (note_for(tp.payout_cm), note_for(tp.change_cm));
    assert_eq!(
        a.execute_order_fill(&mc, &mp, &tc, &tp, &t, &n0, &g1, &g2, [owner(1), owner(2), owner(3)], binds.clone()),
        OrderFillOutcome::Settled,
        "a half built at the node's live rate settles — the retune took effect, both directions"
    );
}

/// ⛔⛔⛔ P3 — CROSS-NODE FILL CONVERGENCE. A fill settled on ONE node is not settled.
///
/// TWO PARTIES, and the boundary is the whole point: node A admits a fill through
/// `execute_order_fill`, produces the block that follows it, and node B ingests that block. B must
/// independently reach the SAME spend state — both nullifiers burned — because a fill that exists
/// only on the node that received it is a chain split wearing a success message. The maker's lot is
/// gone on A and still restable on B; the same order can then be filled AGAIN against B, and the two
/// nodes disagree about who owns what. That is the double-fill the whole nullifier design exists to
/// make impossible, reintroduced one layer up.
///
/// This is the P3 exit criterion from the DEX completion plan, written as the test that decides it:
/// if it is RED, a settled fill needs a block carrier and node-local admission is not enough.
#[test]
fn a_fill_settled_on_one_node_reaches_the_same_spend_state_on_a_second_node() {
    let t = terms();
    let mut a = a_node();
    let mut b = a_node();
    let ((mc, mp), (tc, tp), [n0, n1, n2]) = a_trade(&t, 700, 800);
    // DB-150: both input notes go on chain and the fill carries their membership binds.
    let (binds, planted) = plant_trade(&mut a, &t, 700, 800, &mp, &tp, 60_000);
    // B holds the same chain — a note is only "on chain" when every party has the block that carried
    // it, and B is about to be asked whether it agrees about a spend of one of those very notes.
    for blk in &planted {
        b.ingest_block(blk.clone(), 60_500);
    }
    let _ = b.fold_canonical_records();

    // A admits the fill: both inputs burn on A.
    assert_eq!(
        a.execute_order_fill(&mc, &mp, &tc, &tp, &t, &n0, &n1, &n2, [owner(1), owner(2), owner(3)], binds.clone()),
        OrderFillOutcome::Settled,
        "PRECONDITION: the fill settles on node A"
    );

    // B has never seen it. B produces nothing; A produces the block that follows its own settlement,
    // and B ingests exactly that block — the only channel a real peer has.
    // ⏱️ AFTER the planting blocks, not before them: a produce timestamped behind this node's own tip
    // is not a block, and the fixture would be measuring its own clock rather than the settlement.
    let blk = a
        .produce(61_000, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
        .expect("A produces after settling");
    assert!(
        matches!(b.ingest_block(blk, 61_500), RelayOutcome::Added(_)),
        "the block must graft on B"
    );

    // THE PROPERTY: B agrees the maker's resting note is spent. Asked the way the ledger asks —
    // could a second taker still fill this same order against B?
    let mnf = crate::spend_frontier::leaf_to_cm_bytes(mp.nullifier);
    let tnf = crate::spend_frontier::leaf_to_cm_bytes(tp.nullifier);

    // ⛔⛔⛔ THE MEASUREMENT THIS TEST USED TO MAKE WAS WRONG, AND IT IS WORTH RECORDING WHY.
    //
    // It asserted `b.sparse_acc.verify_unspent(nf, copath).is_err()` and controlled that with a FRESH
    // node reporting is_ok(). That control was insufficient: it ruled out "a node that saw nothing"
    // but not "a node that INGESTED a block". MEASURED 2026-08-31 — on a node that only ingested, an
    // unrelated `[0x7B; 32]` reads exactly as "spent" as the real nullifier, because such a node holds
    // no sparse tree for the adopted root, cannot build a copath, and returns Err for EVERYTHING. The
    // old assertion therefore measured "B ingested a block", and would have stayed green while
    // convergence was completely broken.
    //
    // THE ACCUMULATOR ROOT is what B can actually answer and what actually carries the claim: B
    // VERIFIES the block's carried nullifier fold to reach a post-root, so if B's root equals A's,
    // B has independently reached the same spend state — including this fill's two burns. Agreement
    // on the root IS the consensus-level agreement, and a later spend of either note on B must be
    // proven against that root.
    let a_root = a.nf_unspent_acc();
    let b_root = b.nf_unspent_acc();
    // CONTROL: a node that never ingested this block must NOT already hold that root, or "equal"
    // would be measuring nothing.
    let control = a_node();
    assert_ne!(
        control.nf_unspent_acc(),
        a_root,
        "CONTROL FAILED: an untouched node already holds the settling node's accumulator, so root \
         equality below would prove nothing"
    );
    assert_eq!(
        a_root, b_root,
        "NODE B DID NOT REACH THE SAME SPEND STATE. B verifies the block's carried nullifier fold, so \
         a divergent root means the fill did not cross the node boundary: the order A already filled \
         could be filled AGAIN against B, and the two nodes disagree on who owns the lot."
    );


    // ⛔⛔⛔ THE OTHER HALF OF CONVERGENCE: THE MONEY MUST BE FINDABLE, NOT MERELY THE BURN.
    //
    // Agreeing that two notes are spent is only the destructive half. The maker is OWED a payout, and
    // a maker's wallet talks to whichever node it talks to — not necessarily the one that admitted the
    // fill. `account_bucket_blob` is exactly the query a wallet makes to find its own money. If B
    // burns the maker's lot and has no record of the maker's payout, then for every wallet pointed at
    // B the maker paid a lot and received nothing: view loss IS fund loss ([[feedback_da_is_the_ledger_no_note_loss]]).
    let maker_bucket = [1u8; 32]; // `owner(1)` — the maker's payout slot in this fill
    let on_a = a.account_bucket_blob(&maker_bucket);
    assert!(
        !on_a.is_empty(),
        "PRECONDITION: the settling node files the maker's payout under its owner"
    );
    // ⛔ CONTROL: buckets are cover-padded by design, so a blob can be non-empty for a bucket nobody
    // ever used. If an UNUSED bucket also answers non-empty, "non-empty" measures nothing and the
    // assertion below is vacuous — the property has to be the CONTENT, not the presence.
    let never_used = [0xABu8; 32];
    let cover_only = b.account_bucket_blob(&never_used);
    let on_b = b.account_bucket_blob(&maker_bucket);
    assert_ne!(
        on_b, cover_only,
        "CONTROL: B's answer for the maker's bucket is byte-identical to its answer for a bucket \
         nobody ever used — so B holds NO record of the maker's payout, and this assertion would \
         otherwise have passed on cover alone"
    );
    assert!(
        !on_b.is_empty(),
        "NODE B HAS NO RECORD OF THE MAKER'S PAYOUT while agreeing the maker's lot is BURNED. A maker \
         whose wallet asks B sees a spent lot and no payment — the fill's money leg does not cross \
         the node boundary, so a settled fill is only half-settled anywhere but the node that took it."
    );
}

/// ⛔⛔⛔ THE PAYOUT BINDING: AN HONEST PROOF IS NOT PERMISSION TO CREDIT OTHER NOTES.
///
/// TWO PARTIES, and the boundary is where the theft lives. A maker rests a real order and goes
/// offline. A stranger builds a genuinely HONEST fill — real proof, real terms, unspent inputs — and
/// then submits it with a DIFFERENT note in the maker's payout slot. Before the slot binding, every
/// gate passed: `verify_order_fill` is about three commitments, and none of the earlier gates ever
/// looks at the payloads. The maker's resting lot burned and the maker was credited a note only the
/// attacker can open — the whole lot stolen, with the chain showing a valid settlement.
///
/// The refusal must also be CLEAN: the maker's order stays fillable afterwards, because the binding
/// runs before the burns. A refusal that consumed the nullifiers would be the same theft with an
/// error message — the maker's lot gone and nothing paid.
#[test]
fn a_fill_that_swaps_in_a_note_the_proof_never_attested_is_refused_before_anything_burns() {
    let t = terms();
    let mut node = a_node();
    let ((mc, mp), (tc, tp), [n0, n1, n2]) = a_trade(&t, 100, 200);
    // DB-150: both input notes go on chain and the fill carries their membership binds.
    let (binds, _planted) = plant_trade(&mut node, &t, 100, 200, &mp, &tp, 60_000);

    // The attacker's substitute: a well-formed note that is simply NOT the proven maker payout.
    let stranger = note_for(usdm_decider::poseidon2_compress::lanes_of(&[0xDEAD, 0xBEEF, 0xFEED, 0xFACE]));
    assert_ne!(stranger[..32], n0[..32], "the substitute must differ from the proven payout");

    let v = node.execute_order_fill(
        &mc, &mp, &tc, &tp, &t, &stranger, &n1, &n2,
        [owner(1), owner(2), owner(3)],
     binds.clone());
    assert_eq!(
        v,
        OrderFillOutcome::PayoutNoteMismatch,
        "a note the proof never attested must be REFUSED — crediting it burns the maker's lot and \
         pays them something they cannot open"
    );

    // NOTHING BURNED: the same order still settles honestly afterwards. If the refusal had consumed
    // the nullifiers, this would come back OrderAlreadyFilled and the maker's lot would be gone.
    let v2 = node.execute_order_fill(
        &mc, &mp, &tc, &tp, &t, &n0, &n1, &n2,
        [owner(1), owner(2), owner(3)],
     binds.clone());
    assert_eq!(
        v2,
        OrderFillOutcome::Settled,
        "the refused attempt must have left the order untouched and still fillable"
    );
}

/// ⛔ SWAPPING TWO PROVEN SLOTS IS THEFT, NOT REORDERING. Every note here IS one the proof attests —
/// only the SLOTS are exchanged — so a set-comparison would pass this happily while paying the maker
/// the taker's change and handing the taker the difference.
#[test]
fn a_fill_that_swaps_the_makers_payout_with_the_takers_change_is_refused() {
    let t = terms();
    let mut node = a_node();
    let ((mc, mp), (tc, tp), [n0, n1, n2]) = a_trade(&t, 300, 400);
    // DB-150: both input notes go on chain and the fill carries their membership binds.
    let (binds, _planted) = plant_trade(&mut node, &t, 300, 400, &mp, &tp, 60_000);
    assert_ne!(n0[..32], n2[..32], "the two slots must differ for this to mean anything");

    let v = node.execute_order_fill(
        &mc, &mp, &tc, &tp, &t, &n2, &n1, &n0,
        [owner(1), owner(2), owner(3)],
     binds.clone());
    assert_eq!(
        v,
        OrderFillOutcome::PayoutNoteMismatch,
        "slots are positional — the maker's payout is not interchangeable with the taker's change"
    );
}

/// A payload too short to carry a commitment must REFUSE, never be waved through as "nothing to
/// check" — that is the shape a length guard skips and an unbound credit rides in on.
#[test]
fn a_note_too_short_to_carry_its_commitment_is_refused() {
    let t = terms();
    let mut node = a_node();
    let ((mc, mp), (tc, tp), [n0, n1, n2]) = a_trade(&t, 500, 600);
    // DB-150: both input notes go on chain and the fill carries their membership binds.
    let (binds, _planted) = plant_trade(&mut node, &t, 500, 600, &mp, &tp, 60_000);
    let _ = &n0;
    let v = node.execute_order_fill(
        &mc, &mp, &tc, &tp, &t, &vec![0u8; 31], &n1, &n2,
        [owner(1), owner(2), owner(3)],
     binds.clone());
    assert_eq!(v, OrderFillOutcome::PayoutNoteMismatch);
}

/// ⭐⭐⭐ AN HONEST FILL SETTLES ATOMICALLY, and a REPLAY of the same fill is refused as
/// already-filled — the double-spend gate IS the anti-double-fill, no new machinery.
#[test]
fn an_order_fill_settles_once_and_a_replay_is_refused_as_already_filled() {
    let t = terms();
    let mut node = a_node();
    let ((mc, mp), (tc, tp), [n0, n1, n2]) = a_trade(&t, 100, 200);
    // DB-150: both input notes go on chain and the fill carries their membership binds.
    let (binds, _planted) = plant_trade(&mut node, &t, 100, 200, &mp, &tp, 60_000);

    let v = node.execute_order_fill(
        &mc, &mp, &tc, &tp, &t, &n0, &n1, &n2, [owner(1), owner(2), owner(3)],
     binds.clone());
    assert_eq!(v, OrderFillOutcome::Settled, "an honest fill settles");

    let again = node.execute_order_fill(
        &mc, &mp, &tc, &tp, &t, &n0, &n1, &n2, [owner(1), owner(2), owner(3)],
     binds.clone());
    assert_eq!(
        again,
        OrderFillOutcome::OrderAlreadyFilled,
        "the SAME order cannot fill twice — the maker's nullifier is burned"
    );
}

/// ⛔⛔⛔ TWO TAKERS RACE ONE RESTING ORDER. The first settles; the second is refused, and the
/// second taker's OWN note stays unburned — losing a race must never cost the loser anything.
#[test]
fn the_second_taker_to_race_one_order_is_refused_and_loses_nothing() {
    let t = terms();
    let mut node = a_node();
    let mw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[100, 101, 102, 103])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[110, 111, 112, 113]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (mc, mp) = prove_order_maker_half(&mw, &t).unwrap();
    let mnote = note_for(mp.payout_cm);
    let build_taker = |seed: u64| {
        let tw = TakerHalfWitness {
            value_in: 10_000_000,
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[seed, seed + 1, seed + 2, seed + 3])),
            change_opening: usdm_decider::poseidon2_compress::lanes_of(&[seed + 10, seed + 11, seed + 12, seed + 13]),
            payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[seed + 20, seed + 21, seed + 22, seed + 23]),
            lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        };
        let (c, p) = prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).unwrap();
        let (pn, cn) = (note_for(p.payout_cm), note_for(p.change_cm));
        (c, p, pn, cn)
    };
    let (c1, p1, n1a, n1b) = build_taker(200);
    let (c2, p2, n2a, n2b) = build_taker(300);

    // DB-150: BOTH takers put their own input note on chain and build its bind, because the point of
    // this test is that the loser loses NOTHING — and a taker refused at the membership door before
    // the already-filled door would prove that for the wrong reason.
    let lanes = |a: u64| usdm_decider::poseidon2_compress::lanes_of(&[a, a + 1, a + 2, a + 3]);
    // DB-395: each input commits to its OWNER's opening `P(spk, seed)` — the halves are built as
    // `NoteOwner::from_test_key(lanes(seed))`, so the planted note must open to that owner, never to the raw key.
    let cm = |v: u64, asset: [u64; 3], key: crate::spend_frontier::Digest4| -> [u8; 32] {
        crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(
            v,
            asset,
            usdm_decider::whir_rec_block::NoteOwner::from_test_key(key).opening(),
        ))
    };
    let mbind = node
        .plant_note_and_bind_for_test(
            &cm(t.lot, t.asset_a, lanes(100)),
            mp.nullifier,
            b"race-maker-note",
            60_000,
        )
        .map(|(c, tip, _)| (c, tip));
    let t1 = node
        .plant_note_and_bind_for_test(
            &cm(10_000_000, t.asset_b, lanes(200)),
            p1.nullifier,
            b"race-taker-1",
            60_400,
        )
        .map(|(c, tip, _)| (c, tip));
    let t2 = node
        .plant_note_and_bind_for_test(
            &cm(10_000_000, t.asset_b, lanes(300)),
            p2.nullifier,
            b"race-taker-2",
            60_800,
        )
        .map(|(c, tip, _)| (c, tip));

    let first = node.execute_order_fill(
        &mc, &mp, &c1, &p1, &t, &mnote, &n1a, &n1b, [owner(1), owner(2), owner(3)],
     [mbind.clone(), t1]);
    assert_eq!(first, OrderFillOutcome::Settled, "the first taker wins the order");

    let second = node.execute_order_fill(
        &mc, &mp, &c2, &p2, &t, &mnote, &n2a, &n2b, [owner(1), owner(4), owner(5)],
     [mbind, t2]);
    assert_eq!(second, OrderFillOutcome::OrderAlreadyFilled, "the second is refused");
    let loser_nf = crate::spend_frontier::leaf_to_cm_bytes(p2.nullifier);
    let path = node.da_sparse_copath(&loser_nf);
    assert!(
        node.sparse_acc.verify_unspent(&loser_nf, &path).is_ok(),
        "the losing taker's input note is NOT burned — losing a race costs nothing"
    );
}

/// ⛔ A FILL BUILT FOR CHEAPER TERMS is refused by the COMPOSED proof — the node never checks the
/// halves separately, so a taker cannot pair their discount half with an honest maker half.
#[test]
fn a_cheaper_terms_fill_is_refused_by_the_composed_proof() {
    let t = terms();
    let mut node = a_node();
    let mw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[100, 101, 102, 103])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[110, 111, 112, 113]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (mc, mp) = prove_order_maker_half(&mw, &t).unwrap();
    let cheap = OrderTerms { pay_b: t.pay_b / 2, ..t };
    let tw = TakerHalfWitness {
        value_in: 10_000_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[200, 201, 202, 203])),
        change_opening: usdm_decider::poseidon2_compress::lanes_of(&[210, 211, 212, 213]),
        payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[220, 221, 222, 223]),
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
    };
    let (tc, tp) = prove_order_taker_half(&tw, &cheap, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).unwrap();
    let dummy = vec![0u8; 1153];
    let v = node.execute_order_fill(
        &mc, &mp, &tc, &tp, &t, &dummy, &dummy, &dummy, [owner(1), owner(2), owner(3)],
     [None, None]);
    assert_eq!(v, OrderFillOutcome::ProofRefused, "a half-price fill does not compose");
}

/// ⛔ SELF-DEALING: one note as both sides of its own trade never settles.
#[test]
fn a_note_cannot_be_both_sides_of_its_own_trade() {
    let t = terms();
    let mut node = a_node();
    let ((mc, mp), (tc, mut tp), [n0, n1, n2]) = a_trade(&t, 100, 200);
    // DB-150: both input notes go on chain and the fill carries their membership binds.
    let (binds, _planted) = plant_trade(&mut node, &t, 100, 200, &mp, &tp, 60_000);
    tp.nullifier = mp.nullifier; // forge: same input on both sides
    let v = node.execute_order_fill(
        &mc, &mp, &tc, &tp, &t, &n0, &n1, &n2, [owner(1), owner(2), owner(3)],
     binds.clone());
    assert_ne!(v, OrderFillOutcome::Settled, "self-dealing never settles");
}

/// ⛔ A MISSING OWNER refuses BEFORE any burn — an undiscoverable credit is worse than a refusal,
/// and the refusal must cost the parties nothing: the same order still fills afterwards.
#[test]
fn a_missing_owner_refuses_before_anything_burns() {
    let t = terms();
    let mut node = a_node();
    let ((mc, mp), (tc, tp), [n0, n1, n2]) = a_trade(&t, 400, 500);
    // DB-150: both input notes go on chain and the fill carries their membership binds.
    let (binds, _planted) = plant_trade(&mut node, &t, 400, 500, &mp, &tp, 60_000);
    let refused = node.execute_order_fill(
        &mc, &mp, &tc, &tp, &t, &n0, &n1, &n2, [owner(1), Vec::new(), owner(3)],
     binds.clone());
    assert_eq!(refused, OrderFillOutcome::MissingOwner);
    let settled = node.execute_order_fill(
        &mc, &mp, &tc, &tp, &t, &n0, &n1, &n2, [owner(1), owner(2), owner(3)],
     binds.clone());
    assert_eq!(settled, OrderFillOutcome::Settled, "the refusal burned nothing — the order still fills");
}

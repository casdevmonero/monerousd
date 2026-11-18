// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::on_chain_settlement_standard_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! ⭐⭐⭐ THE STANDARD (user 2026-08-31): *"all of our private uniswaps should settle on chain. on
//! chain settlements should be a standard for tx proof."*
//!
//! A DEX whose trades live anywhere but the chain is asking its users to trust an operator's ledger.
//! Every IonSwap swap therefore leaves the SAME on-chain evidence an ordinary send does — burned
//! nullifiers and recorded notes — so a trade is provable from chain state alone, by anyone, forever,
//! with no index and no server to ask.
//!
//! The division that makes this work: an ORDER is an OFFER and holds no value, so it may live in
//! DA/gossip with an expiry; a FILL moves value, so it settles on chain. This module pins both
//! halves, because either one drifting would break the standard.

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

/// A fixture node that folds records AT THE TIP. A membership cross-bind is FOLDED state, and a node
/// lagging its tip by the default fold depth has folded none of the blocks a fixture just produced,
/// so every fill would be refused at the membership door for the wrong reason.
/// ⛔ And on the TESTNET identity (DB-354's fixture rule): only it admits the bridge credit a plant stages, so on the
/// default genesis every planted input was refused and every fill here answered `MembershipRefused` (measured
/// 2026-09-30 09:0x in the sibling module) — a fixture verdict, not a chain one.
fn a_node() -> Node {
    let mut p = crate::params::ChainParams::default();
    p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
    p.net_prefix_len = p.genesis_parity_commit.len();
    p.record_fold_depth = 0;
    let mut g = genesis_block();
    g.header = crate::block::genesis_header_for_network(&crate::params::network_genesis_prefix("testnet"));
    Node::with_params(g, p).expect("a fixture node builds")
}

/// ⭐ DB-150 — put both input notes on chain and build the binds the fill must carry. The binder is
/// the spend's NULLIFIER; the commitments come from the decider's own `asset_note_cm`, never a local
/// formula, so the planted note and the proven half can never drift apart.
fn plant_both(
    n: &mut Node,
    t: &OrderTerms,
    mw: &MakerHalfWitness,
    tw: &TakerHalfWitness,
    mp: &usdm_decider::whir_rec_block::MakerHalfPublic,
    tp: &usdm_decider::whir_rec_block::TakerHalfPublic,
) -> ([Option<(Vec<u8>, Vec<u8>)>; 2], Vec<Block>) {
    let cm = |v: u64, asset: [u64; 3], sk: crate::spend_frontier::Digest4| -> [u8; 32] {
        crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(
            v, asset, sk,
        ))
    };
    let m = n.plant_note_and_bind_for_test(
        &cm(t.lot, t.asset_a, mw.owner.opening()),
        mp.nullifier,
        b"ocss-maker-note",
        60_000,
    );
    let k = n.plant_note_and_bind_for_test(
        &cm(tw.value_in, t.asset_b, tw.owner.opening()),
        tp.nullifier,
        b"ocss-taker-note",
        60_400,
    );
    let blocks = m
        .iter()
        .chain(k.iter())
        .map(|(_, _, b)| b.clone())
        .collect();
    (
        [
            m.map(|(c, tip, _)| (c, tip)),
            k.map(|(c, tip, _)| (c, tip)),
        ],
        blocks,
    )
}

fn note_for(cm: crate::spend_frontier::Digest4) -> Vec<u8> {
    let mut v = vec![0u8; 1153];
    v[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
    v
}

/// ⭐⭐⭐ A SWAP IS PROVABLE FROM CHAIN STATE ALONE. Before the fill both notes are unspent; after it
/// BOTH nullifiers are burned in the node's own accumulator. That evidence is what a user, an
/// auditor or a court can check without asking anybody — the definition of settling on chain.
#[test]
fn a_swap_leaves_its_proof_in_chain_state_not_in_a_server() {
    let t = terms();
    let mut node = a_node();
    let mw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[11, 12, 13, 14]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (mc, mp) = prove_order_maker_half(&mw, &t).unwrap();
    let tw = TakerHalfWitness {
        value_in: 10_000_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8])),
        change_opening: usdm_decider::poseidon2_compress::lanes_of(&[15, 16, 17, 18]),
        payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[25, 26, 27, 28]),
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
    };
    let (tc, tp) = prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).unwrap();

    // DB-150: both input notes go on chain first — a swap may not credit notes the chain never held,
    // and a fixture that skips this measures the membership door instead of the settlement.
    let (binds, planted) = plant_both(&mut node, &t, &mw, &tw, &mp, &tp);

    // BEFORE: neither input is spent, so the chain shows no trade.
    let mnf = crate::spend_frontier::leaf_to_cm_bytes(mp.nullifier);
    let tnf = crate::spend_frontier::leaf_to_cm_bytes(tp.nullifier);
    for nf in [&mnf, &tnf] {
        let path = node.da_sparse_copath(nf);
        assert!(node.sparse_acc.verify_unspent(nf, &path).is_ok(), "unspent before the swap");
    }

    let v = node.execute_order_fill(
        &mc,
        &mp,
        &tc,
        &tp,
        &t,
        &note_for(mp.payout_cm),
        &note_for(tp.payout_cm),
        &note_for(tp.change_cm),
        [vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]],
     binds.clone());
    assert_eq!(v, OrderFillOutcome::Settled);

    // ⭐ DB-325: WHILE POOLED, the in-flight double-fill gate is the POOL, not a local marking: the same order,
    // submitted again on this node before any block carries the first, is refused.
    let again = node.execute_order_fill(&mc, &mp, &tc, &tp, &t, &note_for(mp.payout_cm), &note_for(tp.payout_cm),
        &note_for(tp.change_cm),
        [vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]],
        binds);
    assert_eq!(again, OrderFillOutcome::OrderAlreadyFilled, "the pooled fill's order refuses a second fill");

    // ⭐⭐⭐ THE SECOND PARTY — "in chain state, not in a server" is only PROVEN across a boundary.
    // One node believing its own write proves nothing about where the proof lives: a value held in a
    // server would look identical from inside that server. So a SECOND node, which never saw the
    // fill submitted and holds no book, ingests the block and must reach the SAME verdict on both
    // nullifiers. That is what makes the chain — not this process — the place the swap is recorded.
    let mut peer = a_node();
    // The peer holds the same chain — the settlement block's ancestry INCLUDES the blocks that
    // carried the two input notes, so without them it would park as an orphan, not graft.
    for b in &planted {
        peer.ingest_block(b.clone(), 60_500);
    }
    let _ = peer.fold_canonical_records();
    // CONTROL: before ingesting, the peer must call both inputs UNSPENT. Without this the assertions
    // below could pass on an unbuildable copath and would be measuring nothing.
    for nf in [&mnf, &tnf] {
        let path = peer.da_sparse_copath(nf);
        assert!(
            peer.sparse_acc.verify_unspent(nf, &path).is_ok(),
            "CONTROL: a peer that never saw the swap must call the input unspent"
        );
    }
    // ⏱️ AFTER the planting blocks: a produce timestamped behind this node's own tip is not a block.
    let blk = node
        .produce(61_000, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
        .expect("the settling node produces");
    assert!(
        matches!(peer.ingest_block(blk, 61_500), RelayOutcome::Added(_)),
        "the block grafts on the peer"
    );
    // ⭐ DB-274 P4b / DB-353 P1 (the fixture made faithful, 2026-10-04): the fill applies at its block's canonical
    // FOLD and the spent set moves when that step's band transition is PROVEN — on the mesh by the band worker and
    // the relay, here by the one helper every fold pin uses (both nodes fold, the settler proves, the peer receives).
    // A bare ingest read the peer's set before either had happened.
    let _ = node.fold_past_stepped_for_test(&mut [&mut peer], 61_500, 500, b"swap-chain-state");
    for (who, nf) in [("maker", &mnf), ("taker", &tnf)] {
        let path = peer.da_sparse_copath(nf);
        assert!(
            peer.sparse_acc.verify_unspent(nf, &path).is_err(),
            "a PEER that only ingested the block must also see the {who}'s input spent — otherwise \
             the swap lived in the settling process, not in chain state"
        );
        // AFTER THE BLOCK: BOTH nullifiers are burned in the settling node's OWN accumulator too — from the
        // block it carried, exactly as on the peer. Nothing else had to be consulted: no index, no operator,
        // no book, and (DB-325) no local marking.
        let own = node.da_sparse_copath(nf);
        assert!(
            node.sparse_acc.verify_unspent(nf, &own).is_err(),
            "the {who}'s input is provably spent on chain after the swap's block"
        );
    }
}

/// ⭐⭐⭐ DB-325 — WHILE A FILL IS POOLED, THE POOL IS ITS DOUBLE-FILL GATE. The submit-time local marking this
/// replaced is gone; what refuses a second fill before any block carries the first is
/// `mempool.nullifier_is_claimed`, checked for BOTH inputs. Same order again → `OrderAlreadyFilled`; a different
/// order with the same taker note → `TakerNoteSpent`. GREEN before and after DB-325: it pins the gate that stays.
#[test]
fn db325_while_pooled_the_pool_refuses_a_second_fill_of_either_input() {
    let t = terms();
    let mut node = a_node();
    // A SECOND maker order on the same terms, planted FIRST so the pair's binds below are the newest.
    let mw2 = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[31, 32, 33, 34])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[41, 42, 43, 44]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (mc2, mp2) = prove_order_maker_half(&mw2, &t).unwrap();
    let cm2 = crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(
        t.lot, t.asset_a, mw2.owner.opening(),
    ));
    let bind2 = node
        .plant_note_and_bind_for_test(&cm2, mp2.nullifier, b"db325-maker-2", 59_600)
        .map(|(c, tip, _)| (c, tip));
    let mw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[11, 12, 13, 14]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (mc, mp) = prove_order_maker_half(&mw, &t).unwrap();
    let tw = TakerHalfWitness { value_in: 10_000_000, owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8])), change_opening: usdm_decider::poseidon2_compress::lanes_of(&[15, 16, 17, 18]), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[25, 26, 27, 28]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (tc, tp) = prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).unwrap();
    let (binds, _planted) = plant_both(&mut node, &t, &mw, &tw, &mp, &tp);
    let notes = [vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
    let v = node.execute_order_fill(&mc, &mp, &tc, &tp, &t, &note_for(mp.payout_cm), &note_for(tp.payout_cm),
        &note_for(tp.change_cm), notes.clone(), binds.clone());
    assert_eq!(v, OrderFillOutcome::Settled, "setup: the first fill settles and its settlement is POOLED");
    let again = node.execute_order_fill(&mc, &mp, &tc, &tp, &t, &note_for(mp.payout_cm), &note_for(tp.payout_cm),
        &note_for(tp.change_cm), notes.clone(), binds.clone());
    assert_eq!(
        again,
        OrderFillOutcome::OrderAlreadyFilled,
        "⛔ DB-325: a second fill of the SAME order was not refused while the first is pooled"
    );
    let other = node.execute_order_fill(&mc2, &mp2, &tc, &tp, &t, &note_for(mp2.payout_cm),
        &note_for(tp.payout_cm), &note_for(tp.change_cm), notes, [bind2, binds[1].clone()]);
    assert_eq!(
        other,
        OrderFillOutcome::TakerNoteSpent,
        "⛔ DB-325: a DIFFERENT order filled with the SAME pooled taker note was not refused"
    );
}

/// ⭐⭐⭐ DB-325 — A FILL THAT NEVER LANDS LEAVES NO PHANTOM SPEND. The settlement settles and pools; then it leaves
/// the pool without any block carrying it (expiry, eviction, a reorg). Its two inputs were never spent on chain,
/// so this node must answer exactly what a peer holding the same blocks answers. RED before DB-325 at its target:
/// the submit-time marking burned both tags into this node's accumulator AND view in lockstep, and since Z1 no
/// apply overwrites it.
#[test]
fn db325_a_fill_dropped_from_the_pool_unlanded_leaves_no_phantom_spend() {
    let t = terms();
    let mut node = a_node();
    let mw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[11, 12, 13, 14]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (mc, mp) = prove_order_maker_half(&mw, &t).unwrap();
    let tw = TakerHalfWitness { value_in: 10_000_000, owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8])), change_opening: usdm_decider::poseidon2_compress::lanes_of(&[15, 16, 17, 18]), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[25, 26, 27, 28]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (tc, tp) = prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).unwrap();
    let (binds, planted) = plant_both(&mut node, &t, &mw, &tw, &mp, &tp);
    let mnf = crate::spend_frontier::leaf_to_cm_bytes(mp.nullifier);
    let tnf = crate::spend_frontier::leaf_to_cm_bytes(tp.nullifier);
    let v = node.execute_order_fill(&mc, &mp, &tc, &tp, &t, &note_for(mp.payout_cm), &note_for(tp.payout_cm),
        &note_for(tp.change_cm),
        [vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]], binds);
    assert_eq!(v, OrderFillOutcome::Settled, "setup: the fill settles and its settlement is POOLED");
    let pooled: Vec<Hash32> = node.mempool.all_tx_ids().into_iter().map(Hash32).collect();
    assert!(!pooled.is_empty(), "CALIBRATION: the settlement is in the pool before it is dropped");
    node.mempool.remove(&pooled);
    assert!(node.mempool.is_empty(), "setup: the settlement left the pool UNLANDED");
    let mut peer = a_node();
    for b in &planted {
        peer.ingest_block(b.clone(), 60_500);
    }
    let _ = peer.fold_canonical_records();
    for (who, nf) in [("maker", &mnf), ("taker", &tnf)] {
        assert_ne!(
            peer.sparse_spent_verdict(nf),
            crate::nf_sparse::SpentVerdict::Spent,
            "CONTROL: a peer holding only the planting blocks must not read the {who}'s input spent"
        );
        assert_ne!(
            node.sparse_spent_verdict(nf),
            crate::nf_sparse::SpentVerdict::Spent,
            "⛔ DB-325: a fill dropped from the pool UNLANDED left a PHANTOM spend of the {who}'s input on the \
             executing node — no block ever carried it"
        );
    }
    assert_eq!(
        node.sparse_acc.root_bytes(),
        peer.sparse_acc.root_bytes(),
        "⛔ DB-325: the executing node's spent-set root differs from a peer's holding the SAME blocks — it would \
         serve and bundle a root no block justifies"
    );
}

/// ⛔⛔⛔ DB-330 + DB-273 §19.6 L3 — A FILL FILES ITS THREE OWNERS FROM THE OBJECT, AND A SIDECAR CHOOSES NOTHING.
///
/// The fill is submitted by the TAKER, whose node builds the settlement. A clue record naming the MAKER's payout
/// cm is therefore the taker (or any relay) choosing the maker's locator hint, and first-writer-wins makes it
/// permanent. RED before DB-330: every record the settlement carried was filed.
/// DECLARED AMENDMENT (§19.6 L3): DB-330 filed the taker's two from the sidecar and the maker's from nowhere. Now
/// every owner rides the object (`OrderFillTx::owner_clues`, slot 0 copied by the fill door from the maker's own
/// order), and the sidecar is ignored for a fill. The pin keeps DB-330's attack — a relay-written sidecar naming the
/// maker's payout (and the taker's two) with foreign clues — and asserts the peer files the OBJECT's three owners.
/// TWO-PARTY-REVIEWED: the settling node's pooled settlement, staged on a SECOND node.
#[test]
fn db330_a_fill_settlement_files_the_takers_two_clues_and_never_the_makers() {
    let t = terms();
    let mut node = a_node();
    let mw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[11, 12, 13, 14]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (mc, mp) = prove_order_maker_half(&mw, &t).unwrap();
    let tw = TakerHalfWitness { value_in: 10_000_000, owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8])), change_opening: usdm_decider::poseidon2_compress::lanes_of(&[15, 16, 17, 18]), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[25, 26, 27, 28]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (tc, tp) = prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).unwrap();
    let (binds, _planted) = plant_both(&mut node, &t, &mw, &tw, &mp, &tp);
    let v = node.execute_order_fill(&mc, &mp, &tc, &tp, &t, &note_for(mp.payout_cm), &note_for(tp.payout_cm),
        &note_for(tp.change_cm),
        [vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]], binds);
    assert_eq!(v, OrderFillOutcome::Settled, "setup: the fill settles and its settlement is POOLED");
    let ids = node.mempool.all_tx_ids();
    assert_eq!(ids.len(), 1, "CALIBRATION: exactly the settlement is pooled");
    let mut tx = node.mempool.get(&Hash32(ids[0])).cloned().expect("the pooled settlement");
    let cm = crate::spend_frontier::leaf_to_cm_bytes;
    let (t_pay, t_chg, m_pay) = (cm(tp.payout_cm), cm(tp.change_cm), cm(mp.payout_cm));
    let mut records = Vec::new();
    for (c, b) in [(t_pay, 0xA1u8), (t_chg, 0xA2u8), (m_pay, 0xEEu8)] {
        records.extend_from_slice(&c);
        records.extend_from_slice(&96u16.to_le_bytes());
        records.extend_from_slice(&[b; 96]);
    }
    tx.note_clues = records;
    let mut peer = a_node();
    peer.stage_carried_note_clues(&tx);
    assert_eq!(peer.note_clue(&t_pay), Some(&[2u8; 8][..]), "the taker's payout is filed under the OBJECT's slot-1 clue");
    assert_eq!(peer.note_clue(&t_chg), Some(&[3u8; 8][..]), "the taker's change is filed under the OBJECT's slot-2 clue");
    assert_eq!(
        peer.note_clue(&m_pay),
        Some(&[1u8; 8][..]),
        "⛔ DB-330 / §19.6 L3: the MAKER's payout is not filed under the object's slot-0 clue — a sidecar (the taker or a \
         relay) chose the maker's locator hint, or the maker's owner was lost"
    );
}

/// ⭐⭐⭐ THE CONTROL THAT KEEPS THE PROOFS ABOVE FROM BEING VACUOUS — DO NOT DELETE IT.
///
/// `verify_unspent(nf, copath).is_err()` means "spent" ONLY on a node holding the sparse tree for its
/// own root. On a node that merely INGESTED a block it returns Err for EVERY nullifier, real or
/// invented, so the same assertion there measures "this node ingested something" and would stay green
/// while two nodes had in fact diverged. connect-9f hit exactly that and correctly banned the
/// measurement for ingesting nodes (2026-08-31).
///
/// The tests above run on the node that EXECUTED the fill, which does hold its tree — but that is a
/// claim, and this is the experiment: after a real fill, an UNRELATED nullifier must STILL read as
/// unspent. If it ever does not, the assertion discriminates nothing and every proof resting on it is
/// worthless.
///
/// ⚠️ SCOPE, STATED HONESTLY: this module proves a SINGLE-NODE property. The two-device mesh proof
/// over the onion transport is a REMAINING GAP (de-island / follow-on, owed by the ecosystem gate),
/// and nothing here stands in for it.
#[test]
fn the_spentness_assertion_actually_discriminates_on_an_executing_node() {
    let t = terms();
    let mut node = a_node();
    let mw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[11, 12, 13, 14]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (mc, mp) = prove_order_maker_half(&mw, &t).unwrap();
    let tw = TakerHalfWitness { value_in: 10_000_000, owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8])), change_opening: usdm_decider::poseidon2_compress::lanes_of(&[15, 16, 17, 18]), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[25, 26, 27, 28]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (tc, tp) = prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT).unwrap();
    // DB-150: a settlement may not credit notes the chain never held.
    let (binds, planted) = plant_both(&mut node, &t, &mw, &tw, &mp, &tp);
    let v = node.execute_order_fill(&mc, &mp, &tc, &tp, &t,
        &note_for(mp.payout_cm), &note_for(tp.payout_cm), &note_for(tp.change_cm),
        [vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]], binds);
    assert_eq!(v, OrderFillOutcome::Settled);
    // Measured through the spent-set READER every cross-node value pin uses (`is_nullifier_spent`: the fold-point
    // set ∪ unfolded blocks). `sparse_acc` is the band's APPLIED root: it moves only when a proven band step lands
    // (DB-396), so it lags a block whose step no prover has applied yet and cannot be the authority here.
    let unrelated = [0x7Bu8; 32];
    let reads_unspent = !node.is_nullifier_spent(&Hash32(unrelated));
    assert!(reads_unspent,
        "CONTROL FAILED: an unrelated nullifier also reads as spent, so verify_unspent proves NOTHING here");

    // ⭐⭐⭐ THE SECOND PARTY — and here it makes the scope note above CONCRETE instead of a caveat.
    //
    // The point of this module is that a measurement must discriminate. So: prove that the SAME
    // measurement does NOT discriminate on an INGESTING node, which is the whole reason it is banned
    // there. A peer that only grafts the block holds no sparse tree for the adopted root, cannot build
    // a copath, and returns Err for EVERYTHING — so on that node the real burn and the unrelated
    // nullifier are INDISTINGUISHABLE. Asserting that indistinguishability is what turns the ban from
    // a rule someone must remember into a property the suite enforces.
    let mut peer = a_node();
    // The peer holds the same chain — the settlement block's ancestry INCLUDES the blocks that
    // carried the two input notes, so without them it would park as an orphan, not graft.
    for b in &planted {
        peer.ingest_block(b.clone(), 60_500);
    }
    let _ = peer.fold_canonical_records();
    // ⏱️ AFTER the planting blocks: a produce timestamped behind this node's own tip is not a block.
    let blk = node
        .produce(61_000, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
        .expect("the executing node produces");
    assert!(
        matches!(peer.ingest_block(blk, 61_500), RelayOutcome::Added(_)),
        "the block grafts on the peer"
    );
    // DB-325: the real burns are read AFTER the block that carries them — the settling node's spent set is written
    // by that block, never by the submit (the in-flight gate is the pool).
    // And it DOES discriminate (after its block): the real burns read spent on this same executing node, which is the
    // other half of "discriminates" — a measurement that says unspent for everything is equally useless.
    for (who, nf) in [("maker", mp.nullifier), ("taker", tp.nullifier)] {
        let b = crate::spend_frontier::leaf_to_cm_bytes(nf);
        assert!(
            node.is_nullifier_spent(&Hash32(b)),
            "the {who}'s real burn must read SPENT on the executing node — otherwise the measurement \
             discriminates in neither direction"
        );
    }
    let peer_unrelated = !peer.is_nullifier_spent(&Hash32(unrelated));
    let peer_real_burn = !peer.is_nullifier_spent(&Hash32(crate::spend_frontier::leaf_to_cm_bytes(mp.nullifier)));
    // ⭐⭐⭐ THE BAN IS OBSOLETE, AND THIS TEST NAMED ITS OWN RETIREMENT CONDITION.
    //
    // It used to assert the OPPOSITE — that these two verdicts are INDISTINGUISHABLE on an ingesting
    // node — and its own text said why that would change: *"if it ever starts telling a real burn
    // apart from an unrelated nullifier there, the ban is obsolete."* It has. Before DB-149 an
    // ingesting node's local Merkle view never advanced with the blocks it grafted, so it could build
    // no copath and returned Err for everything; the indistinguishability was a DEFECT being pinned as
    // a property. The view now advances over each block's carried tags on the ingest path, so a peer
    // that grafted and folded this settlement answers the question correctly — and a measurement that
    // crosses the node boundary is strictly better than a root comparison that only says "we agree".
    assert!(
        peer_unrelated,
        "the ingesting peer reads an UNRELATED nullifier as unspent — it is not answering Err to              everything, which is what made this measurement useless before DB-149"
    );
    assert!(
        !peer_real_burn,
        "and it reads the REAL burn as spent — the ingesting peer independently reaches the same              spend state as the node that executed the fill, which is the whole P3 claim"
    );

    // The peer CAN still answer the question that matters, and it is the one to use: the roots agree.
    assert_eq!(
        node.nf_unspent_acc(),
        peer.nf_unspent_acc(),
        "the executing node and the ingesting peer agree on the nullifier accumulator root — the \
         measurement that DOES cross the node boundary"
    );
}

/// ⛔⛔⛔ THE BOOK HOLDS NO VALUE, AND MUST NOT BECOME CONSENSUS STATE. An order is an OFFER: it
/// authorises a future consumption of a note that is still the maker's. Persisting the book into the
/// chain would add an O(open orders) growth axis AND make a cancelled or expired offer someone
/// else's problem to prune. Settlement is on chain; the offer is not.
#[test]
fn resting_orders_are_offers_and_never_move_value_by_themselves() {
    let t = terms();
    let mut node = a_node();
    let mw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[11, 12, 13, 14]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
    let (mc, mp) = prove_order_maker_half(&mw, &t).unwrap();

    let resting = crate::order_book::RestingOrder {
        terms: t,
        maker: mp,
        maker_bytes: mc,
        payout_note: note_for(mp.payout_cm),
        membership_carrier: crate::order_book::test_membership_bind().0,
        membership_tip: crate::order_book::test_membership_bind().1,
        payout_clue: crate::order_book::test_payout_clue(),
    };
    // The value question is the ACCUMULATOR ROOT (see the note below on why per-nullifier queries
    // cannot answer it on an ingesting node). Capture it before anything is offered.
    let node_root_before = node.nf_unspent_acc();
    node.post_order(resting.clone()).expect("the offer rests");

    // Posting moved NOTHING: the maker's note is still spendable, exactly as before.
    let mnf = crate::spend_frontier::leaf_to_cm_bytes(mp.nullifier);
    let path = node.da_sparse_copath(&mnf);
    assert!(
        node.sparse_acc.verify_unspent(&mnf, &path).is_ok(),
        "resting an order must NOT burn the maker's note — it is an offer, not a transfer"
    );

    // ⭐⭐⭐ THE SECOND PARTY — and here it is the load-bearing half of the claim. "The book is not
    // consensus state" is a statement about what OTHER nodes learn, and one node cannot make it: a
    // node that quietly folded offers into its own state would look exactly like this from inside.
    //
    // So a PEER holds the same offer in its own book (gossip delivers offers; it does not deliver
    // chain state) and must ALSO call the maker's note unspent — AND the settling node must produce a
    // block that teaches the peer nothing about the offer. If resting an order ever moved value, the
    // peer would see the maker's note burned after ingesting, and a maker would lose a note by
    // merely advertising a price.
    // This test plants nothing: resting an order moves no value, so there is no input note to put
    // on chain and no bind to build. The peer starts clean on purpose.
    let mut peer = a_node();
    let peer_root_before = peer.nf_unspent_acc();
    peer.post_order(resting).expect("the peer holds the same offer");
    let peer_path = peer.da_sparse_copath(&mnf);
    assert!(
        peer.sparse_acc.verify_unspent(&mnf, &peer_path).is_ok(),
        "a PEER holding the same resting offer must also see the maker's note unspent"
    );

    // ⛔⛔⛔ ASK A QUESTION EVERY NODE CAN ACTUALLY ANSWER — AND ONE THAT CAN FAIL.
    //
    // Two measurements were rejected before this one, both because they could not distinguish the
    // property from an artifact:
    //   1. `verify_unspent(nf, copath).is_ok()` is NOT a spentness test on a node that only INGESTED
    //      a block: it holds no sparse tree for the adopted root, cannot build a copath, and returns
    //      Err for EVERY nullifier. MEASURED — after ingest an unrelated `[0x7B; 32]` read exactly as
    //      "spent" as the real one. Asserting is_err() there measures "this node ingested a block".
    //   2. "the accumulator is unchanged after ingesting a block" is false for an honest reason: every
    //      block carries a cover-padded nullifier transition, so the root moves on EVERY block whether
    //      or not any order exists. MEASURED here: the peer's root moved on a block carrying no fill.
    //
    // What DOES carry the claim, and can fail: POSTING must not move the accumulator, on either node.
    // If resting an order ever touched value, this is the number that would move — and it moves for a
    // real fill, which is what `a_swap_leaves_its_proof_in_chain_state_not_in_a_server` pins.
    assert_eq!(
        node_root_before,
        node.nf_unspent_acc(),
        "posting an offer moved the POSTING node's nullifier accumulator — an offer is not a transfer"
    );
    assert_eq!(
        peer_root_before,
        peer.nf_unspent_acc(),
        "holding the same offer moved the PEER's nullifier accumulator — an offer that reached chain \
         state would let a maker lose a note by merely advertising a price"
    );
    assert_eq!(
        node.nf_unspent_acc(),
        peer.nf_unspent_acc(),
        "two nodes holding the same resting offer derive the SAME accumulator — the book is not \
         consensus state on either of them"
    );
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `ion_pool_tx::node_tests` — the pins of the IonSwap pool objects that drive two `Node`s: every order is built with the
//! real welded spends a wallet builds, published at one node's own door, carried in that node's block, and judged on the
//! OTHER node from the block alone. What is asserted is what the peer holds.

use super::*;
use crate::asset_tx::CreationFee;
use crate::hash::Hash32;
use crate::node::tests::one_step_membership_for_test;
use crate::node::{AssetSpendOutcome, Node};
use crate::relay::RelayOutcome;
use crate::spend_frontier::{cm_bytes_to_root, leaf_to_cm_bytes as b32};
use usdm_decider::poseidon2_compress::lanes_of;
use usdm_decider::whir_rec_block as wr;

const U: u64 = 100_000_000;
/// The pins' token: its id IS the id of the asset this key created (`asset_tx::asset_id_of_creator`), so the creator's
/// claim is signed for real. `(the token's id, the creator's public key, its secret key)`.
fn creator() -> &'static ([u8; 32], Vec<u8>, Vec<u8>) {
    static C: std::sync::OnceLock<([u8; 32], Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        (crate::asset_tx::asset_id_of_creator(crate::asset_tx::AssetKind::Token, "IONPIN", "Ion pool pin", [0u8; 32], &pk), pk, sk)
    })
}
fn tok() -> [u8; 32] {
    creator().0
}
/// The creator's word for the claim `bind` names, signed by `sk` and stating `pk`.
fn creator_word(bind: &[u8; 32], pk: &[u8], sk: &[u8]) -> IonCreatorAuth {
    IonCreatorAuth {
        kind: crate::asset_tx::AssetKind::Token,
        symbol: "IONPIN".to_string(),
        name: "Ion pool pin".to_string(),
        logo: [0u8; 32],
        pubkey: pk.to_vec(),
        sig: crate::pqauth::ml_dsa_sign(&ion_claim_msg(&tok(), bind), sk).expect("the key signs"),
    }
}
const F: u64 = wr::PROTOCOL_FEE_ATOMIC;

fn owner(i: u64) -> wr::NoteOwner {
    wr::NoteOwner::from_test_key(lanes_of(&[0x10A, i, i, i]))
}
fn clue(i: u64) -> Vec<u8> {
    let mut c = vec![0u8; crate::peg_in_tx::OWNER_CLUE_MAX];
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/test/ion-clue/v1");
    h.update(&i.to_le_bytes());
    h.finalize_xof().fill(&mut c);
    c
}
/// The owner an order's payout notes belong to: `who`'s keys with the order's own seed (a wallet takes the seed from the
/// shell's shared secret; a fixture names one), so its opening is fresh for every order.
fn payout_owner(who: u64, order: u64) -> wr::NoteOwner {
    let o = owner(who);
    wr::NoteOwner { ask: o.ask, nk: o.nk, seed: lanes_of(&[0x10D, who, order, 7]) }
}
/// An order's words. `order` tells two orders of one owner apart (their seed, so their opening, shell and locators).
fn core(kind: u8, x: u64, y: u64, shares: u64, min_out: u64, who: u64, order: u64) -> IonOrderCore {
    let word = |k: u64| *blake3::hash(&[who.to_le_bytes(), order.to_le_bytes(), k.to_le_bytes()].concat()).as_bytes();
    let mut shell_ct = vec![0u8; ION_SHELL_CT_BYTES];
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/test/ion-shell/v1");
    h.update(&word(9));
    h.finalize_xof().fill(&mut shell_ct);
    IonOrderCore {
        kind,
        x,
        y,
        shares,
        min_out,
        owner_opening: b32(payout_owner(who, order).opening()),
        shell_ct,
        shell_pad: word(8),
        shell_vt: who as u8,
        locators: [word(0), word(1), word(2)],
        hop: [0u8; 32],
        hop_min_out: 0,
        lock_from: 0,
        lock_until: 0,
    }
}
/// TEST — the fixed-width note payload whose first 32 bytes are `front` (what a block carries for a note).
fn note_of(front: [u8; 32]) -> Vec<u8> {
    // O1-INFINITY-REVIEWED: one fixed-width (`PQ_NOTE_BYTES`) in-memory note handed to a test's own block; nothing is persisted.
    let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    n[..32].copy_from_slice(&front);
    n
}

/// A produces a block, B takes it, both fold.
fn step(a: &mut Node, b: &mut Node, ts: &mut u64, tag: &[u8]) {
    *ts += 600;
    let blk = a.produce(*ts, Hash32::hash(tag), Hash32::hash(b"ion-mc")).expect("A produces");
    assert!(matches!(b.ingest_block(blk, *ts + 1), RelayOutcome::Added(_)), "⛔ B refused A's block");
    let _ = a.fold_canonical_records();
    let _ = b.fold_canonical_records();
}

/// Notes with these fronts ride a block A lays, B takes it, and both fold past it.
fn plant(a: &mut Node, b: &mut Node, ts: &mut u64, fronts: &[[u8; 32]]) {
    *ts += 600;
    let payload: Vec<u8> = fronts.iter().flat_map(|f| note_of(*f)).collect();
    let (blk, _) = a.carry_notes_in_a_block_for_test(*ts, &payload);
    assert!(matches!(b.ingest_block(blk, *ts + 1), RelayOutcome::Added(_)), "PRECONDITION: B takes the funding block");
    *ts = crate::node::tests::produce_past_the_fold(a, &mut [b], *ts + 20, 20);
    let _ = a.fold_canonical_records();
    let _ = b.fold_canonical_records();
    for f in fronts {
        assert!(a.holds_record_with_cm(f), "PRECONDITION: A holds the funded note's folded record");
    }
}

/// A USDm note of `amount + F + 7_000` owned by `who`, to be burned for `amount` into leg `k` of the order `bind` names.
fn usdm_witness(who: u64, amount: u64, bind: &[u8; 32], k: usize) -> wr::SpendValidityWitness {
    let value_in = amount + F + 7_000;
    wr::SpendValidityWitness {
        value_in,
        owner: owner(who),
        value_out: value_in - F,
        fee: F,
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        out0_value: amount,
        out0_opening: ion_burn_opening(bind, k),
        out1_value: 7_000,
        out1_opening: lanes_of(&[0x10B, who, 1, 1]),
    }
}

/// A note of `tag` worth `value_in` owned by `note_owner`, `amount` of it burned into leg `k` of the order.
fn asset_witness(note_owner: wr::NoteOwner, tag: [u64; 3], value_in: u64, amount: u64, bind: &[u8; 32], k: usize) -> wr::AssetSpendValidityWitness {
    wr::AssetSpendValidityWitness {
        value_in,
        owner: note_owner,
        value_out: value_in,
        fee: 0,
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        out0_value: amount,
        out0_opening: ion_burn_opening(bind, k),
        out1_value: value_in - amount,
        // the change note's opening names its ORDER (24 bits of the order's bind), as a wallet's fresh random opening would:
        // MEASURED 2026-11-13, a second removal of the same shares made the very note the first one had (the door refused it,
        // rightly, as a note already on the chain: `[admit] ⛔ REFUSE … a replay of an applied transaction`)
        out1_opening: lanes_of(&[0x10C, value_in, amount, 1, u64::from(bind[0]) | u64::from(bind[1]) << 8 | u64::from(bind[2]) << 16]),
        asset: tag,
    }
}

fn usdm_leg(a: &Node, w: &wr::SpendValidityWitness, amount: u64, who: u64) -> CreationFee {
    let (carrier, outs, nf, lc) = wr::prove_bond_validity_carrier_with_commit_bytes(w, amount).expect("the USDm burn proves");
    let leaf = wr::spend_input_leaf(w).expect("the witness states its leaf");
    let (membership_carrier, membership_tip) = one_step_membership_for_test(a, &b32(leaf), leaf, nf, w.lc_blind).expect("A holds the USDm note");
    CreationFee { nullifier: b32(nf), leaf_commit: b32(lc), carrier, membership_carrier, membership_tip, change_note: note_of(b32(outs[1])), change_clue: clue(1_000 + who) }
}

fn asset_leg(a: &Node, w: &wr::AssetSpendValidityWitness, amount: u64, who: u64) -> CreationFee {
    let (carrier, outs, nf, lc) = wr::prove_asset_bond_validity_carrier_bytes(w, amount).expect("the asset burn proves");
    let leaf = wr::asset_spend_input_leaf(w).expect("the witness states its leaf");
    let (membership_carrier, membership_tip) = one_step_membership_for_test(a, &b32(leaf), leaf, nf, w.lc_blind).expect("A holds the asset note");
    CreationFee { nullifier: b32(nf), leaf_commit: b32(lc), carrier, membership_carrier, membership_tip, change_note: note_of(b32(outs[1])), change_clue: clue(2_000 + who) }
}

/// A's node forms and pools every settlement it can, a block carries them, and both nodes fold it.
fn settle_round(a: &mut Node, b: &mut Node, ts: &mut u64, tag: &[u8]) -> usize {
    let n = a.publish_ion_settlements();
    step(a, b, ts, tag);
    n
}

/// The payout note of `asset` that order `order` of `who` was paid: `(its front, the owner that spends it)`.
fn payout(who: u64, order: u64, asset: IonAsset, amount: u64) -> ([u8; 32], wr::NoteOwner) {
    let o = payout_owner(who, order);
    (b32(wr::asset_note_cm(amount, ion_tag(&tok(), asset), o.opening())), o)
}

/// ⭐⭐⭐ IONSWAP POOLS, END TO END ON TWO NODES — A POOL IS OPENED BY A DEPOSIT, TRADED AGAINST, AND ITS PROVIDER TAKES ITS
/// LIQUIDITY OUT. Every order carries the welded spends a wallet builds; A publishes at its own door and lays the blocks;
/// B judges every object from the block alone. Asserted on BOTH nodes after every step: one contract-state root, the same
/// pending list, the same layer word, the same row, and every payout note in a folded record. Then:
/// - the provider REMOVES with the share note it was paid, and holds its tokens and its USDm again on both nodes;
/// - REPLAY: the same order published again is refused (its notes are spent);
/// - LIFT: a leg proven for one order does not verify inside another (another floor), so the order is refused;
/// - the layer word equals exactly what the pool still holds for its providers and its creator.
#[test]
fn a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    let mut ts = 5_000u64;
    let token_tag = ion_tag(&tok(), IonAsset::Token);
    let root0 = a.peg().contract_state_root();
    assert_eq!(root0, crate::contract_state::empty_root(), "CALIBRATION: no contract and no pool yet");

    // ── NO POOL YET (NO GROWTH): a buy into the token's pool before anyone opened it is handed back whole on both
    // nodes, and NOTHING is written for it: no leaf, no row, no pool counted. (RED before `IonSettled::opened`: every
    // settled batch wrote a row, so a network fee bought a row every node keeps for good.)
    let early = core(ION_BUY, 0, 5 * U, 0, 1, 6, 1);
    let early_w = usdm_witness(61, 5 * U, &ion_order_bind(&tok(), &early), 0);
    // O1-INFINITY-REVIEWED: the prover's leaf function computes ONE note's leaf in memory for this test's own block; nothing is stored by it.
    let early_leaf = b32(wr::spend_input_leaf(&early_w).expect("leaf"));
    plant(&mut a, &mut b, &mut ts, &[early_leaf]);
    let early_tx = IonOrderTx { token: tok(), core: early, legs: vec![usdm_leg(&a, &early_w, 5 * U, 6)], creator: None };
    assert!(matches!(a.publish_ion_order(&early_tx), AssetSpendOutcome::Published), "A's door takes a buy into a pool nobody has opened");
    step(&mut a, &mut b, &mut ts, b"ion-early");
    assert_eq!((a.peg().ion_pending().len(), b.peg().ion_pending().len()), (1, 1), "the early buy is pending on both nodes");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"ion-settle-early"), 1, "A forms the settlement that hands the buy back");
    let (back_front, _) = payout(6, 1, IonAsset::Usdm, 5 * U);
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.peg().ion_pending().is_empty(), "⛔ {who} still holds the handed-back buy as pending");
        assert!(n.holds_record_with_cm(&back_front), "⛔ {who} does not hold the buyer's returned USDm");
        assert_eq!(n.peg().ion_usdm_held(), 0, "⛔ {who}'s pool layer kept USDm for a pool that does not exist");
        assert_eq!(n.peg().contract_state_root(), root0, "⛔ {who} wrote a leaf for a pool nobody opened: a network fee buys a row every node keeps");
        assert_eq!(n.peg().ion_pools(), 0, "⛔ {who} counts a pool nobody opened");
        assert!(n.ion_cache().row(&tok()).is_none(), "⛔ {who} keeps a row for a pool nobody opened");
        assert!(n.ion_cache_is_current(), "{who}'s own tree is still the chain's");
    }

    // ── the provider (1) adds 1,000 tokens and 2,000 USDm
    let add = core(ION_ADD, 1_000 * U, 2_000 * U, 0, 0, 1, 1);
    let bind = ion_order_bind(&tok(), &add);
    let tw = asset_witness(owner(11), token_tag, 1_500 * U, 1_000 * U, &bind, 0);
    let uw = usdm_witness(12, 2_000 * U, &bind, 1);
    // the trader (2) and the seller (3) are funded in the same block
    let buy = core(ION_BUY, 0, 100 * U, 0, 1, 2, 1);
    let buy_w = usdm_witness(21, 100 * U, &ion_order_bind(&tok(), &buy), 0);
    let sell = core(ION_SELL, 40 * U, 0, 0, 1, 3, 1);
    let sell_w = asset_witness(owner(31), token_tag, 40 * U, 40 * U, &ion_order_bind(&tok(), &sell), 0);
    // every order pays the network fee through a USDm leg: a sale brings one atomic unit of USDm for it
    let sell_fee_w = usdm_witness(32, ION_FEE_UNIT, &ion_order_bind(&tok(), &sell), 1);
    // the creator (5) will claim its fee parts: its claim burns one atomic unit of USDm of its own
    let claim = core(ION_CLAIM, 0, 1, 0, 0, 5, 1);
    let claim_bind = ion_order_bind(&tok(), &claim);
    let claim_w = usdm_witness(51, 1, &claim_bind, 0);
    plant(
        &mut a,
        &mut b,
        &mut ts,
        &[
            b32(wr::asset_spend_input_leaf(&tw).expect("leaf")),
            b32(wr::spend_input_leaf(&uw).expect("leaf")),
            b32(wr::spend_input_leaf(&buy_w).expect("leaf")),
            b32(wr::asset_spend_input_leaf(&sell_w).expect("leaf")),
            b32(wr::spend_input_leaf(&claim_w).expect("leaf")),
            b32(wr::spend_input_leaf(&sell_fee_w).expect("leaf")),
            // the note the provider's REMOVAL will pay its fee from (the removal's words are not known yet; a note's
            // leaf is its value and its owner, whatever it is later spent into)
            b32(wr::spend_input_leaf(&usdm_witness(13, ION_FEE_UNIT, &[0u8; 32], 1)).expect("leaf")),
        ],
    );
    let add_tx = IonOrderTx { token: tok(), core: add.clone(), legs: vec![asset_leg(&a, &tw, 1_000 * U, 1), usdm_leg(&a, &uw, 2_000 * U, 1)], creator: None };
    assert_eq!(IonOrderTx::decode(&add_tx.encode()).as_ref(), Some(&add_tx), "the order round-trips");
    assert!(add_tx.legs_verify(), "the honest order's legs verify");
    assert!(crate::chain_object::admissible(&add_tx.wire(), 10, 0, false), "the honest order is admissible on its bytes");
    assert!(matches!(a.publish_ion_order(&add_tx), AssetSpendOutcome::Published), "A's door takes the provider's deposit");
    step(&mut a, &mut b, &mut ts, b"ion-add");
    for (who, n) in [("A", &a), ("B", &b)] {
        assert_eq!(n.peg().ion_pending().len(), 1, "⛔ {who} does not hold the deposit as a pending order");
        assert_eq!(n.peg().ion_usdm_held(), 2_000 * U, "⛔ {who}'s pool layer did not take the deposit's USDm");
        assert_eq!(n.peg().contract_state_root(), root0, "an order never moves a pool's leaf");
    }
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"ion-settle-add"), 1, "A forms the one settlement due");
    let shares = {
        let IonState::Pool(p) = a.ion_cache().row(&tok()).expect("A's fold wrote the pool's row").state else { panic!("a pool") };
        u64::try_from(p.shares - p.locked).expect("fits")
    };
    let (share_front, share_owner) = payout(1, 1, IonAsset::Share, shares);
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.peg().ion_pending().is_empty(), "⛔ {who} still holds the settled order as pending");
        assert_ne!(n.peg().contract_state_root(), root0, "⛔ {who}'s contract-state root did not take the pool's leaf");
        assert!(n.ion_cache_is_current(), "{who}'s own tree is the chain's");
        assert!(n.holds_record_with_cm(&share_front), "⛔ {who} does not hold the provider's share note");
    }
    assert_eq!(a.peg().contract_state_root(), b.peg().contract_state_root(), "⛔ two roots for one pool");
    assert_eq!(a.ion_cache().row(&tok()), b.ion_cache().row(&tok()), "⛔ two rows for one pool");

    // ── a buy and a sell in ONE block clear at one price
    let buy_tx = IonOrderTx { token: tok(), core: buy, legs: vec![usdm_leg(&a, &buy_w, 100 * U, 2)], creator: None };
    let sell_tx = IonOrderTx { token: tok(), core: sell, legs: vec![asset_leg(&a, &sell_w, 40 * U, 3), usdm_leg(&a, &sell_fee_w, ION_FEE_UNIT, 3)], creator: None };
    assert!(sell_tx.pays_network_fee() && buy_tx.pays_network_fee(), "every order pays the network fee");
    // an order with its fee leg removed is no order (a free sale would fill a pool's order slots at no cost)
    let mut unpaid = sell_tx.clone();
    unpaid.legs.pop();
    assert_eq!(IonOrderTx::decode(&unpaid.encode()), None, "⛔ a sale that pays no network fee decodes as an order");
    assert!(matches!(a.publish_ion_order(&buy_tx), AssetSpendOutcome::Published), "A's door takes the buy");
    assert!(matches!(a.publish_ion_order(&sell_tx), AssetSpendOutcome::Published), "A's door takes the sell");
    step(&mut a, &mut b, &mut ts, b"ion-trade");
    assert_eq!((a.peg().ion_pending().len(), b.peg().ion_pending().len()), (2, 2), "both trades are pending on both nodes");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"ion-settle-trade"), 1, "one settlement for the pool's two orders");
    let row = a.ion_cache().row(&tok()).expect("the row").clone();
    assert_eq!(Some(&row), b.ion_cache().row(&tok()), "⛔ the peer's row is not the producer's after the trades");
    assert_eq!(row.prices.len(), 2, "one price a batch");
    assert!(row.owed_creator_x > 0 && row.owed_creator_y > 0, "the creator's fee parts accrue in the row");
    let IonState::Pool(traded) = row.state else { panic!("a pool") };
    // REPLAY: the buy again — its note is spent
    assert!(!matches!(a.publish_ion_order(&buy_tx), AssetSpendOutcome::Published), "⛔ A's door took a replayed order");
    // LIFT: the sell's proven leg inside an order with another floor
    let mut lifted = sell_tx.clone();
    lifted.core.min_out = 2;
    assert!(!lifted.legs_verify(), "⛔ a leg proven for one order verifies inside another");
    assert!(!matches!(a.publish_ion_order(&lifted), AssetSpendOutcome::Published), "⛔ A's door took an order whose leg is another order's");

    // ── the provider LEAVES: it hands back every share it was paid
    let remove = core(ION_REMOVE, 0, 0, shares, 0, 1, 2);
    let rw = asset_witness(share_owner, ion_tag(&tok(), IonAsset::Share), shares, shares, &ion_order_bind(&tok(), &remove), 0);
    assert_eq!(b32(wr::asset_spend_input_leaf(&rw).expect("leaf")), share_front, "CALIBRATION: the removal spends the share note the pool paid");
    // the share note's record folds before it is spent
    ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 20, 20);
    let _ = a.fold_canonical_records();
    let _ = b.fold_canonical_records();
    let remove_fee_w = usdm_witness(13, ION_FEE_UNIT, &ion_order_bind(&tok(), &remove), 1);
    assert_eq!(wr::spend_input_leaf(&remove_fee_w).expect("leaf"), wr::spend_input_leaf(&usdm_witness(13, ION_FEE_UNIT, &[0u8; 32], 1)).expect("leaf"), "CALIBRATION: the removal's fee leg spends the note planted for it");
    let remove_tx = IonOrderTx { token: tok(), core: remove, legs: vec![asset_leg(&a, &rw, shares, 1), usdm_leg(&a, &remove_fee_w, ION_FEE_UNIT, 1)], creator: None };
    assert!(matches!(a.publish_ion_order(&remove_tx), AssetSpendOutcome::Published), "A's door takes the provider's removal");
    step(&mut a, &mut b, &mut ts, b"ion-remove");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"ion-settle-remove"), 1, "the removal's settlement");
    let after = a.ion_cache().row(&tok()).expect("the row").clone();
    let IonState::Pool(left) = after.state else { panic!("a pool") };
    assert_eq!(left.shares, left.locked, "⛔ a share that is not the locked minimum stayed in the pool");
    let (out_x, out_y) = (u64::try_from(traded.x - left.x).expect("fits"), u64::try_from(traded.y - left.y).expect("fits"));
    // WHAT A PROVIDER IS OWED: its part of the pool AS THE TRADES LEFT IT, never its two deposits back figure for figure.
    // The block's net flow was a buy (100 USDm in against 40 tokens in, about 80 USDm's worth at the opening price), so
    // the pool ends with FEWER tokens and MORE USDm than were deposited, and so does the provider. (This assertion first
    // asked for more of BOTH assets back, `out_x > 999 U`: wrong arithmetic for any pool that trades, found the first
    // time the pin reached this line.) What can never fall is the PRODUCT of the two: the pool's own invariant, which
    // every trade's fee raises and of which the locked minimum keeps a dust part (1,000 of about 1.4e11 share units).
    eprintln!("[ion-pin] deposited 1000 tokens + 2000 USDm; taken out {out_x} + {out_y} atomic after a net buy");
    assert!(out_x < 1_000 * U && out_y > 2_000 * U, "CALIBRATION: the net buy left the pool fewer tokens and more USDm ({out_x}, {out_y})");
    assert!(
        u128::from(out_x) * u128::from(out_y) > u128::from(1_000 * U) * u128::from(2_000 * U),
        "⛔ the provider's part came back worth less than it put in: the product of what it took out ({out_x} × {out_y}) is not above the product of its deposit, though two trades paid the pool fees"
    );
    // and it is the WHOLE of its part: what stays is the locked minimum's own share of each balance (rounded toward the
    // pool, so at most one atomic unit more), nothing of the provider's
    assert!(
        left.x * traded.shares <= traded.x * traded.locked + traded.shares && left.y * traded.shares <= traded.y * traded.locked + traded.shares,
        "⛔ more than the locked minimum's part stayed in the pool after its only provider left ({} tokens, {} USDm atomic of {} and {})",
        left.x,
        left.y,
        traded.x,
        traded.y
    );
    let (x_front, _) = payout(1, 2, IonAsset::Token, out_x);
    let (y_front, _) = payout(1, 2, IonAsset::Usdm, out_y);
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.holds_record_with_cm(&x_front), "⛔ {who} does not hold the provider's returned tokens");
        assert!(n.holds_record_with_cm(&y_front), "⛔ {who} does not hold the provider's returned USDm");
        assert_eq!(n.ion_cache().row(&tok()), Some(&after), "⛔ {who}'s row is not the pool's");
        // the layer word is exactly what the pool still holds: its USDm balance and what its creator is owed
        assert_eq!(u128::from(n.peg().ion_usdm_held()), left.y + after.owed_creator_y, "⛔ {who}'s pool layer does not hold exactly what its pools hold");
    }
    assert_eq!(a.peg().contract_state_root(), b.peg().contract_state_root(), "⛔ two roots for one pool at the end");
    assert!(cm_bytes_to_root(&x_front).is_some());

    // ── THE CREATOR CLAIMS ITS FEE PARTS. The token's id binds the creator's key; the claim is signed by it over the
    // claim's own bind (so its payout notes). Refused at A's door, each with nothing spent: a stranger's signature, the
    // creator's signature lifted onto another payout, and a claim with no creator's word.
    let (owed_x, owed_y) = (u64::try_from(after.owed_creator_x).expect("fits"), u64::try_from(after.owed_creator_y).expect("fits"));
    assert!(owed_x > 0 && owed_y > 0, "CALIBRATION: the two trades left the creator a part in each asset");
    let (pk, sk) = (&creator().1, &creator().2);
    let claim_tx = IonOrderTx { token: tok(), core: claim.clone(), legs: vec![usdm_leg(&a, &claim_w, 1, 5)], creator: Some(creator_word(&claim_bind, pk, sk)) };
    assert_eq!(IonOrderTx::decode(&claim_tx.encode()).as_ref(), Some(&claim_tx), "the claim round-trips");
    assert!(claim_tx.legs_verify() && claim_tx.creator_verifies(&crate::pqauth::MlDsaVerifier), "the creator's own claim verifies");
    let (pk2, sk2) = crate::pqauth::ml_dsa_keypair();
    let stranger = IonOrderTx { creator: Some(creator_word(&claim_bind, &pk2, &sk2)), ..claim_tx.clone() };
    assert!(!stranger.creator_verifies(&crate::pqauth::MlDsaVerifier), "⛔ a key that did not create the token passes as its creator");
    assert!(!matches!(a.publish_ion_order(&stranger), AssetSpendOutcome::Published), "⛔ A's door took a stranger's claim of the creator's fees");
    let mut redirected = claim_tx.clone();
    redirected.core.owner_opening = b32(payout_owner(9, 9).opening());
    assert!(!redirected.creator_verifies(&crate::pqauth::MlDsaVerifier), "⛔ the creator's signature verifies over another payout");
    assert!(!matches!(a.publish_ion_order(&redirected), AssetSpendOutcome::Published), "⛔ A's door took a claim paying somebody else");
    let wordless = IonOrderTx { creator: None, ..claim_tx.clone() };
    assert_eq!(IonOrderTx::decode(&wordless.encode()), None, "⛔ a claim with no creator's word decodes");
    assert!(!matches!(a.publish_ion_order(&wordless), AssetSpendOutcome::Published), "⛔ A's door took a claim nobody signed");
    let worded_buy = IonOrderTx { creator: claim_tx.creator.clone(), ..buy_tx.clone() };
    assert_eq!(IonOrderTx::decode(&worded_buy.encode()), None, "⛔ an order that is no claim carries a creator's word");
    assert!(crate::chain_object::admissible(&claim_tx.wire(), 10, 0, false) && !crate::chain_object::admissible(&stranger.wire(), 10, 0, false), "the gossip door asks the same question");
    // the real claim
    assert!(matches!(a.publish_ion_order(&claim_tx), AssetSpendOutcome::Published), "⛔ A's door refuses the creator's own claim");
    step(&mut a, &mut b, &mut ts, b"ion-claim");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"ion-settle-claim"), 1, "the claim's settlement");
    let claimed = a.ion_cache().row(&tok()).expect("the row").clone();
    assert_eq!((claimed.owed_creator_x, claimed.owed_creator_y), (0, 0), "⛔ the pool still holds what the creator claimed");
    assert_eq!(claimed.state, after.state, "⛔ a claim moved the pool's own balances");
    let (cx_front, _) = payout(5, 1, IonAsset::Token, owed_x);
    let (cy_front, _) = payout(5, 1, IonAsset::Usdm, owed_y + 1);
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.holds_record_with_cm(&cx_front), "⛔ {who} does not hold the creator's token part");
        assert!(n.holds_record_with_cm(&cy_front), "⛔ {who} does not hold the creator's USDm part (with the unit the claim burned)");
        assert_eq!(n.ion_cache().row(&tok()), Some(&claimed), "⛔ {who}'s row is not the pool's after the claim");
        assert_eq!(u128::from(n.peg().ion_usdm_held()), left.y, "⛔ {who}'s pool layer holds more or less than the pool's own USDm after the claim");
    }
    assert!(!matches!(a.publish_ion_order(&claim_tx), AssetSpendOutcome::Published), "⛔ A's door took the claim a second time");
    assert_eq!((a.peg().ion_pools(), b.peg().ion_pools()), (1, 1), "⛔ both ledgers count the one pool");

    // ── A RESTART: the cache a node checkpoints is installed only if it IS the tree under the ledger's root
    let root = a.peg().contract_state_root();
    let file = a.ion_cache().export();
    let mut resumed = crate::node::objects::ion_pool::IonCache::default();
    assert!(resumed.install_file(root, file.clone()), "⛔ a node's own checkpointed cache is refused at its restart");
    assert_eq!((resumed.tree().root(), resumed.row(&tok())), (root, a.ion_cache().row(&tok())), "the resumed cache is the cache");
    assert_eq!(resumed.export(), file, "⛔ the resumed cache does not carry the same undo log");
    let mut bent = file.clone();
    bent.leaves[0].1 = b32(lanes_of(&[9, 9, 9, 9]));
    assert!(!crate::node::objects::ion_pool::IonCache::default().install_file(root, bent), "⛔ a checkpoint with a leaf the root does not hold was installed");
    let mut false_rows = file.clone();
    false_rows.rows[0].batch += 1;
    assert!(!crate::node::objects::ion_pool::IonCache::default().install_file(root, false_rows), "⛔ a checkpoint with a row that is not its pool's leaf was installed");

    // ── A JOINER: B holds the ledger (the root, the pool count) and none of the tree, as after a certified state.
    // It keeps only what a peer's page PROVES against its own root, and is whole only with every pool's row.
    b.ion_cache_forget_for_test();
    assert!(!b.ion_cache_is_current() && b.ion_cache().row(&tok()).is_none(), "CALIBRATION: B holds the root and no tree");
    assert_eq!(b.ion_refill_cursor(), Some([0u8; 32]), "B's next ask starts at the first leaf");
    assert_eq!(b.ion_cache_page(&[0u8; 32]), None, "⛔ a node whose tree is not its ledger's answers a page");
    let page = a.ion_cache_page(&[0u8; 32]).expect("A, whose tree is its ledger's, answers a page");
    assert_eq!(IonCachePage::decode(&page.encode()).as_ref(), Some(&page), "the page round-trips");
    assert!(page.done && page.items.len() == 1 && page.rows.len() == 1, "CALIBRATION: one pool, one leaf, one row");
    // TAMPER 1: a leaf no path proves
    let mut bad_leaf = page.clone();
    bad_leaf.items[0].1 = b32(lanes_of(&[9, 9, 9, 9]));
    assert_eq!(b.ion_refill_page(&bad_leaf), 0, "⛔ B kept a leaf its root does not hold");
    // TAMPER 2: a page that names a root B's ledger never stood on, and one that names an EARLIER root of B's own
    // branch over paths read under the newest (a path opens the root it was read under and no other)
    let mut elsewhere = page.clone();
    elsewhere.root = b32(lanes_of(&[7, 7, 7, 7]));
    assert_eq!(b.ion_refill_page(&elsewhere), 0, "⛔ B kept a page read under a root that is not its own");
    let mut relabelled = page.clone();
    relabelled.root = b32(root0);
    assert_eq!(b.ion_refill_page(&relabelled), 0, "⛔ B kept a leaf whose path was read under another root");
    // TAMPER 3: the true leaf with a FALSE row (a peer that withholds or bends rows): the leaf is kept, the row is not,
    // and B does not call itself whole, because the ledger counts one pool and B holds no row
    let mut bad_row = page.clone();
    bad_row.rows[0].batch += 1;
    assert_eq!(b.ion_refill_page(&bad_row), 1, "B keeps the proven leaf of a page whose row is false");
    assert_eq!(b.ion_cache().tree().root(), root, "CALIBRATION: B's tree is now the ledger's");
    assert!(b.ion_cache().row(&tok()).is_none(), "⛔ B kept a row that is not its pool's leaf");
    assert!(!b.ion_cache_is_current(), "⛔ B calls its cache whole while it lacks a pool's row the ledger counts");
    // the honest page
    assert_eq!(b.ion_refill_page(&page), 1, "B keeps the true row of the pool whose leaf it holds");
    assert!(b.ion_cache_is_current(), "⛔ B is not whole after an honest page");
    assert_eq!(b.ion_cache().row(&tok()), a.ion_cache().row(&tok()), "⛔ B's refilled row is not the pool's");
    assert_eq!(b.ion_refill_cursor(), None, "a whole node asks for nothing");
    assert_eq!(b.ion_refill_page(&page), 0, "a whole node reads no page");
    assert_eq!(b.ion_cache_page(&[0u8; 32]).as_ref(), Some(&page), "the refilled node answers the same page");
}

/// What a node holds of the pool, whole: its contract-state root, its pending orders, its layer word and its row.
fn held(n: &Node) -> (crate::spend_frontier::Digest4, Vec<IonPending>, u64, Option<IonRow>) {
    (n.peg().contract_state_root(), n.peg().ion_pending().to_vec(), n.peg().ion_usdm_held(), n.ion_cache().row(&tok()).cloned())
}

/// THE ROGUE PRODUCER: B lays a block carrying `wire` with none of its own doors run (the object, its notes and its lane
/// tags, with the evidence B holds for them), and BOTH nodes judge that block. `at_its_door`: the peer must GRAFT the block,
/// so what refuses the object is its class door at the fold and the block stands (no chain halt). Without it (an object no
/// codec or leg check accepts) the peer may also refuse the whole block at a shape door; anything else (buffered, say)
/// means the arm measured something other than the object.
fn rogue_carries(a: &mut Node, b: &mut Node, ts: &mut u64, wire: &[u8], at_its_door: bool, seed: &[u8], what: &str) {
    *ts += 600;
    let (carriage, notes, tags) = match crate::chain_object::carriage_of(wire) {
        Some(c) => (
            c,
            crate::chain_object::carried_note_payloads(wire).expect("an object with a carriage names its notes").concat(),
            crate::chain_object::object_own_nullifiers(wire).unwrap_or_default(),
        ),
        None => (wire.to_vec(), Vec::new(), Vec::new()),
    };
    let rogue = crate::node::tests::dd_rogue_block_carrying_tags(b, carriage, notes, &tags, *ts, seed);
    // the rogue publishes every block it builds on (its own untouched sibling of an earlier rogue block included)
    for parent in &rogue.header.parents {
        if a.dag().get(parent).is_none() {
            if let Some(sibling) = b.full_block_by_id(parent) {
                let _ = a.ingest_block_preverified(sibling, *ts + 1);
            }
        }
    }
    let out_b = b.ingest_block_preverified(rogue.clone(), *ts + 1);
    let out_a = a.ingest_block_preverified(rogue, *ts + 1);
    eprintln!("[ion-rogue] the peer's verdict on a block carrying {what}: {out_a:?} (the rogue's own: {out_b:?})");
    assert!(
        matches!(out_a, RelayOutcome::Added(_)) || (!at_its_door && matches!(out_a, RelayOutcome::Invalid(_))),
        "CALIBRATION: the peer judged {what} at the door this arm names: {out_a:?}"
    );
    let _ = a.fold_canonical_records();
    let _ = b.fold_canonical_records();
}

/// A settlement that says its batch paid `payouts` out of the row `pre`: the bytes a node would form for that claim.
fn settlement_claiming(truth: &IonSettleTx, pre: IonRow, orders: &[IonPending], payouts: &[IonPayout]) -> IonSettleTx {
    IonSettleTx {
        token: tok(),
        cutoff: truth.cutoff,
        pre: Some(pre),
        path: truth.path.clone(),
        notes: payouts
            .iter()
            .map(|p| (ion_payout_note(&orders[p.order].core, p, ion_tag(&tok(), p.asset)), orders[p.order].core.locator_of(p.asset)))
            .collect(),
    }
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS — `IonOrder` and `IonSettle` × forge, strip, substitute, replay, burn, THROUGH A PEER. A pool is
/// open and a buy is pending on both nodes. The rogue producer B then lays, one block each, with no door of its own run:
/// - FORGE (settlement, a LYING PROVER): a settlement right in every word but the row it starts from, which says the pool
///   holds ten times its tokens, so the same arithmetic pays the buyer about ten times as many;
/// - SUBSTITUTE (settlement): the true settlement with the buyer's payout note swapped for a note the thief owns;
/// - STRIP (settlement): the true settlement less one payout note;
/// - FORGE (order): a buy whose USDm note NEVER EXISTED, its burn honestly proven, its membership lifted from the real buy;
/// - STRIP (order): the seller's order with its leg removed;
/// - SUBSTITUTE and BURN (order): the seller's real order with another floor under its proven leg, naming the seller's
///   own nullifier on the block's lane.
/// After every one of them the PEER holds exactly what it held: the same root, the same pending list, the same layer word,
/// the same row, and no note the false object carried. Then the CONTROL: the seller's real order publishes (nothing of it
/// was burned), the true settlement lands on both nodes and pays both orders. Then REPLAY: the settlement that landed and
/// the settled buy are carried again, and the peer holds exactly what it held after the control.
#[test]
fn ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    let mut ts = 5_000u64;
    let token_tag = ion_tag(&tok(), IonAsset::Token);
    let add = core(ION_ADD, 1_000 * U, 2_000 * U, 0, 0, 1, 1);
    let bind = ion_order_bind(&tok(), &add);
    let tw = asset_witness(owner(11), token_tag, 1_500 * U, 1_000 * U, &bind, 0);
    let uw = usdm_witness(12, 2_000 * U, &bind, 1);
    let buy = core(ION_BUY, 0, 100 * U, 0, 1, 2, 1);
    let buy_w = usdm_witness(21, 100 * U, &ion_order_bind(&tok(), &buy), 0);
    let sell = core(ION_SELL, 40 * U, 0, 0, 1, 3, 1);
    let sell_w = asset_witness(owner(31), token_tag, 40 * U, 40 * U, &ion_order_bind(&tok(), &sell), 0);
    // every order pays the network fee through a USDm leg: a sale brings one atomic unit of USDm for it
    let sell_fee_w = usdm_witness(32, ION_FEE_UNIT, &ion_order_bind(&tok(), &sell), 1);
    plant(
        &mut a,
        &mut b,
        &mut ts,
        &[
            b32(wr::asset_spend_input_leaf(&tw).expect("leaf")),
            b32(wr::spend_input_leaf(&uw).expect("leaf")),
            b32(wr::spend_input_leaf(&buy_w).expect("leaf")),
            b32(wr::asset_spend_input_leaf(&sell_w).expect("leaf")),
            b32(wr::spend_input_leaf(&sell_fee_w).expect("leaf")),
        ],
    );
    let add_tx = IonOrderTx { token: tok(), core: add, legs: vec![asset_leg(&a, &tw, 1_000 * U, 1), usdm_leg(&a, &uw, 2_000 * U, 1)], creator: None };
    assert!(matches!(a.publish_ion_order(&add_tx), AssetSpendOutcome::Published), "PRECONDITION: the provider's deposit publishes");
    step(&mut a, &mut b, &mut ts, b"ionr-add");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"ionr-settle-add"), 1, "PRECONDITION: the pool opens");
    let buy_tx = IonOrderTx { token: tok(), core: buy, legs: vec![usdm_leg(&a, &buy_w, 100 * U, 2)], creator: None };
    let sell_tx = IonOrderTx { token: tok(), core: sell, legs: vec![asset_leg(&a, &sell_w, 40 * U, 3), usdm_leg(&a, &sell_fee_w, ION_FEE_UNIT, 3)], creator: None };
    assert!(matches!(a.publish_ion_order(&buy_tx), AssetSpendOutcome::Published), "PRECONDITION: the buy publishes");
    step(&mut a, &mut b, &mut ts, b"ionr-buy");
    let before = held(&a);
    assert_eq!(before, held(&b), "PRECONDITION: one pool on both nodes");
    assert_eq!(before.1.len(), 1, "PRECONDITION: the buy is pending");

    // ── the true settlement of the pending buy, as the rogue's own node forms it, and what it pays
    let truth = b.ion_settlements_due().into_iter().next().expect("the rogue's node can form the true settlement");
    let orders = before.1.clone();
    let row = truth.pre.clone().expect("the pool has a row");
    let paid = settle(&tok(), Some(&row), &orders, truth.cutoff, 1).expect("the true batch computes").payouts;
    assert_eq!(settlement_claiming(&truth, row.clone(), &orders, &paid).notes, truth.notes, "CALIBRATION: the fixture rebuilds the true settlement's notes");

    // FORGE (a lying prover): the row says ten times the tokens
    let mut rich = row.clone();
    let IonState::Pool(p) = &mut rich.state else { panic!("a pool") };
    p.x *= 10;
    let lied = settle(&tok(), Some(&rich), &orders, truth.cutoff, 1).expect("the false row computes").payouts;
    assert!(lied[0].amount > paid[0].amount * 5, "CALIBRATION: the lie pays the buyer several times the tokens");
    let lie = settlement_claiming(&truth, rich, &orders, &lied);
    assert_eq!(IonSettleTx::decode(&lie.encode()).as_ref(), Some(&lie), "CALIBRATION: the lie is well formed");
    assert!(crate::chain_object::admissible(&lie.wire(), 10, 0, false), "CALIBRATION: the lie is admissible on its bytes");
    rogue_carries(&mut a, &mut b, &mut ts, &lie.wire(), true, b"ionr-forge-settle", "a settlement over a row the pool never had");
    assert_eq!(held(&a), before, "⛔ FORGE: a settlement over a false row moved the peer's pool");
    assert!(!a.holds_record_with_cm(&b32(lied[0].cm)), "⛔ FORGE: the peer holds the inflated payout note");

    // SUBSTITUTE: the buyer's payout note becomes the thief's
    let thief = payout_owner(9, 9);
    let stolen = IonPayout { cm: wr::asset_note_cm(paid[0].amount, ion_tag(&tok(), paid[0].asset), thief.opening()), ..paid[0].clone() };
    let mut swapped = truth.clone();
    swapped.notes[0].0 = ion_payout_note(&orders[0].core, &stolen, ion_tag(&tok(), stolen.asset));
    rogue_carries(&mut a, &mut b, &mut ts, &swapped.wire(), true, b"ionr-swap-settle", "a settlement whose payout note was swapped");
    assert_eq!(held(&a), before, "⛔ SUBSTITUTE: a settlement paying another owner moved the peer's pool");
    assert!(!a.holds_record_with_cm(&b32(stolen.cm)), "⛔ SUBSTITUTE: the peer holds the thief's payout note");

    // STRIP: one payout note fewer
    let mut short = truth.clone();
    short.notes.pop();
    rogue_carries(&mut a, &mut b, &mut ts, &short.wire(), false, b"ionr-strip-settle", "a settlement less one payout note");
    assert_eq!(held(&a), before, "⛔ STRIP: a settlement that does not pay its whole batch moved the peer's pool");

    // FORGE (order): a 5,000 USDm note that never existed, burned by an honest proof, under the real buy's membership
    let forged = core(ION_BUY, 0, 5_000 * U, 0, 1, 9, 1);
    let forged_w = usdm_witness(91, 5_000 * U, &ion_order_bind(&tok(), &forged), 0);
    let (carrier, outs, nf, lc) = wr::prove_bond_validity_carrier_with_commit_bytes(&forged_w, 5_000 * U).expect("the burn of an invented note proves");
    let forged_tx = IonOrderTx {
        token: tok(),
        core: forged,
        legs: vec![CreationFee {
            nullifier: b32(nf),
            leaf_commit: b32(lc),
            carrier,
            membership_carrier: buy_tx.legs[0].membership_carrier.clone(),
            membership_tip: buy_tx.legs[0].membership_tip.clone(),
            change_note: note_of(b32(outs[1])),
            change_clue: clue(1_091),
        }],
        creator: None,
    };
    assert!(forged_tx.legs_verify(), "CALIBRATION: the forged order's burn verifies; only its note is missing");
    rogue_carries(&mut a, &mut b, &mut ts, &forged_tx.wire(), true, b"ionr-forge-order", "an order burning a note that never existed");
    assert_eq!(held(&a), before, "⛔ FORGE: an order over a note that never existed entered the peer's pool");
    assert!(!a.holds_record_with_cm(&b32(outs[1])), "⛔ FORGE: the peer holds the change of a note that never existed");

    // STRIP (order): the seller's order with no leg
    let mut legless = sell_tx.clone();
    legless.legs.clear();
    rogue_carries(&mut a, &mut b, &mut ts, &legless.wire(), false, b"ionr-strip-order", "an order with its leg removed");
    assert_eq!(held(&a), before, "⛔ STRIP: an order that burns nothing entered the peer's pool");

    // SUBSTITUTE and BURN (order): another floor under the seller's proven leg, the seller's nullifier on the lane
    let mut lifted = sell_tx.clone();
    lifted.core.min_out = 2;
    rogue_carries(&mut a, &mut b, &mut ts, &lifted.wire(), false, b"ionr-lift-order", "an order whose floor was changed under its proven leg");
    assert_eq!(held(&a), before, "⛔ SUBSTITUTE: an order with a swapped floor entered the peer's pool");

    // ── CONTROL: nothing of the seller's was burned; the true settlement pays both orders on both nodes
    assert!(matches!(a.publish_ion_order(&sell_tx), AssetSpendOutcome::Published), "⛔ BURN: the peer refuses the seller's real order after the rogue named its nullifier");
    step(&mut a, &mut b, &mut ts, b"ionr-sell");
    assert_eq!((a.peg().ion_pending().len(), b.peg().ion_pending().len()), (2, 2), "CONTROL: both real orders are pending on both nodes");
    // a batch is ONE step's orders, the pool's earliest first: the buy's step settles, then the sale's
    let landed = a.ion_settlements_due().into_iter().next().expect("A forms the settlement of the earliest step");
    assert_eq!(landed, truth, "CALIBRATION: the batch of the buy's step is byte for byte the one the rogue's node formed before the sale joined (a later order changes nothing about an earlier step's batch)");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"ionr-settle"), 1, "CONTROL: the true settlement of the buy's step is pooled");
    assert_eq!((a.peg().ion_pending().len(), b.peg().ion_pending().len()), (1, 1), "CONTROL: the buy is paid and the sale waits for its own batch");
    let landed_sale = a.ion_settlements_due().into_iter().next().expect("A forms the settlement of the sale's step");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"ionr-settle-sale"), 1, "CONTROL: the true settlement of the sale's step is pooled");
    let after = held(&a);
    assert_eq!(after, held(&b), "CONTROL: one pool on both nodes after the true settlement");
    assert!(after.1.is_empty() && after.0 != before.0, "⛔ CONTROL: the true settlement did not settle the peer's pool");
    assert!(!landed.notes.is_empty() && !landed_sale.notes.is_empty(), "CONTROL: each true settlement pays its order");
    for (note, _) in landed.notes.iter().chain(&landed_sale.notes) {
        let front: [u8; 32] = note[..32].try_into().expect("a note's front");
        assert!(a.holds_record_with_cm(&front) && b.holds_record_with_cm(&front), "⛔ CONTROL: a payout note of the true settlement is in no record");
    }
    let IonState::Pool(left) = after.3.as_ref().expect("the row").state else { panic!("a pool") };
    assert_eq!(u128::from(after.2), left.y + after.3.as_ref().expect("the row").owed_creator_y, "⛔ the pool layer does not hold exactly what its pool holds");

    // ── REPLAY: the settlement that landed, the stale one formed before the sell joined, and the settled buy. (A block
    // naming a tag that is already spent may be refused whole or grafted with the object refused at the fold: either is
    // a refusal on the peer, and what is asserted is what the peer holds afterwards.)
    rogue_carries(&mut a, &mut b, &mut ts, &landed.wire(), false, b"ionr-replay-settle", "the settlement that already landed");
    assert_eq!(held(&a), after, "⛔ REPLAY: a re-carried settlement moved the peer's pool");
    rogue_carries(&mut a, &mut b, &mut ts, &landed_sale.wire(), false, b"ionr-replay-settle-2", "the second settlement that already landed");
    assert_eq!(held(&a), after, "⛔ REPLAY: a re-carried later settlement moved the peer's pool");
    rogue_carries(&mut a, &mut b, &mut ts, &buy_tx.wire(), false, b"ionr-replay-order", "the buy that already settled");
    assert_eq!(held(&a), after, "⛔ REPLAY: a re-carried order entered the peer's pool again");
    assert_eq!(held(&b), after, "the rogue's own node holds the same pool");
}


/// ⭐⭐⭐ A SWAP OF ONE TOKEN FOR ANOTHER, IN ONE ORDER, ON TWO NODES. Two pools are opened (this token and another). A
/// holder sells 50 of this token and names the other as what to buy with the proceeds, with a floor on each leg. A
/// publishes at its own door and lays the blocks; B judges everything from the blocks alone.
/// - The first pool's batch fills the sale: NO USDm note is paid; both nodes hold one pending BUY in the second pool of
///   exactly the USDm the sale earned, carrying the swap's own payout words.
/// - The second pool's batch pays the second token to the swap's own opening: the note is in a folded record on both
///   nodes, and its amount is exactly what left the second pool.
/// - Throughout, both nodes hold one root, one pending list and one layer word, and at the end the layer word is exactly
///   what the two pools hold for their providers and creators (the forwarded USDm never left the layer and is in the
///   second pool's balance now).
/// - A swap naming its own pool as the second one does not decode.
#[test]
fn a_swap_sells_in_one_pool_and_is_paid_in_another_token_on_two_nodes() {
    const OTHER: [u8; 32] = [0x7B; 32];
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    let mut ts = 5_000u64;
    let (tag1, tag2) = (ion_tag(&tok(), IonAsset::Token), ion_tag(&OTHER, IonAsset::Token));
    // the two providers' deposits, and the swapper's sale
    let add1 = core(ION_ADD, 1_000 * U, 2_000 * U, 0, 0, 1, 1);
    let add2 = core(ION_ADD, 4_000 * U, 2_000 * U, 0, 0, 2, 1);
    let (b1, b2) = (ion_order_bind(&tok(), &add1), ion_order_bind(&OTHER, &add2));
    let (t1, u1) = (asset_witness(owner(11), tag1, 1_000 * U, 1_000 * U, &b1, 0), usdm_witness(12, 2_000 * U, &b1, 1));
    let (t2, u2) = (asset_witness(owner(21), tag2, 4_000 * U, 4_000 * U, &b2, 0), usdm_witness(22, 2_000 * U, &b2, 1));
    let swap = IonOrderCore { hop: OTHER, hop_min_out: 1, ..core(ION_SELL, 50 * U, 0, 0, 1, 4, 1) };
    let bs = ion_order_bind(&tok(), &swap);
    let (st, su) = (asset_witness(owner(41), tag1, 50 * U, 50 * U, &bs, 0), usdm_witness(42, ION_FEE_UNIT, &bs, 1));
    plant(
        &mut a,
        &mut b,
        &mut ts,
        &[
            b32(wr::asset_spend_input_leaf(&t1).expect("leaf")),
            b32(wr::spend_input_leaf(&u1).expect("leaf")),
            b32(wr::asset_spend_input_leaf(&t2).expect("leaf")),
            b32(wr::spend_input_leaf(&u2).expect("leaf")),
            b32(wr::asset_spend_input_leaf(&st).expect("leaf")),
            b32(wr::spend_input_leaf(&su).expect("leaf")),
        ],
    );
    let add1_tx = IonOrderTx { token: tok(), core: add1, legs: vec![asset_leg(&a, &t1, 1_000 * U, 1), usdm_leg(&a, &u1, 2_000 * U, 1)], creator: None };
    let add2_tx = IonOrderTx { token: OTHER, core: add2, legs: vec![asset_leg(&a, &t2, 4_000 * U, 2), usdm_leg(&a, &u2, 2_000 * U, 2)], creator: None };
    assert!(matches!(a.publish_ion_order(&add1_tx), AssetSpendOutcome::Published) && matches!(a.publish_ion_order(&add2_tx), AssetSpendOutcome::Published), "PRECONDITION: both deposits publish");
    step(&mut a, &mut b, &mut ts, b"swap-adds");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"swap-open"), 2, "PRECONDITION: one settlement a pool opens both");
    assert_eq!((a.peg().ion_pools(), b.peg().ion_pools()), (2, 2), "the ledgers of both nodes count two pools");
    let pool_of = |n: &Node, t: &[u8; 32]| -> (crate::ion_pool::Pool, u128) {
        let r = n.ion_cache().row(t).expect("the pool's row").clone();
        let IonState::Pool(p) = r.state else { panic!("a pool") };
        (p, r.owed_creator_y)
    };
    let (p1_before, _) = pool_of(&a, &tok());
    let (p2_before, _) = pool_of(&a, &OTHER);
    let held_before = a.peg().ion_usdm_held();

    // ── the swap: one order
    let swap_tx = IonOrderTx { token: tok(), core: swap.clone(), legs: vec![asset_leg(&a, &st, 50 * U, 4), usdm_leg(&a, &su, ION_FEE_UNIT, 4)], creator: None };
    assert_eq!(IonOrderTx::decode(&swap_tx.encode()).as_ref(), Some(&swap_tx), "the swap round-trips");
    let own_pool = IonOrderTx { token: OTHER, ..swap_tx.clone() };
    assert_eq!(IonOrderTx::decode(&own_pool.encode()), None, "⛔ a swap whose second pool is its own decodes");
    assert!(matches!(a.publish_ion_order(&swap_tx), AssetSpendOutcome::Published), "⛔ A's door refuses a swap");
    step(&mut a, &mut b, &mut ts, b"swap-order");
    // the first pool's batch: the sale is filled and its USDm is FORWARDED
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"swap-leg-1"), 1, "the first pool's batch");
    let (p1_after, _) = pool_of(&a, &tok());
    let earned = u64::try_from(p1_before.y - p1_after.y).expect("fits");
    assert!(earned > 90 * U, "CALIBRATION: 50 of a token priced at 2 USDm earned about 95 USDm");
    for (who, n) in [("A", &a), ("B", &b)] {
        let pending = n.peg().ion_pending();
        assert_eq!(pending.len(), 1, "⛔ {who} holds {} pending order(s) after the first leg, not the one second leg", pending.len());
        let f = &pending[0];
        assert!(f.token == OTHER && f.core.kind == ION_BUY && f.core.y == earned && f.core.min_out == 1, "⛔ {who}'s second leg is not a buy in the second pool of exactly what the sale earned");
        assert_eq!((f.core.owner_opening, f.core.locators), (swap.owner_opening, swap.locators), "⛔ {who}'s second leg does not pay the swap's own notes");
        // the sale's USDm was not paid out: no USDm note of the swapper's exists, and the layer still holds it
        assert!(!n.holds_record_with_cm(&payout(4, 1, IonAsset::Usdm, earned).0), "⛔ {who} holds a USDm payout for a sale whose proceeds were forwarded");
        assert_eq!(n.peg().ion_usdm_held(), held_before + ION_FEE_UNIT, "⛔ {who}'s pool layer changed by more than the sale's fee unit: forwarded USDm left it");
    }
    assert_eq!(a.peg().ion_pending(), b.peg().ion_pending(), "⛔ two pending lists after the first leg");
    // the second pool's batch pays the second token to the swap's own opening
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"swap-leg-2"), 1, "the second pool's batch");
    let (p2_after, owed2) = pool_of(&a, &OTHER);
    let (p1_end, owed1) = pool_of(&a, &tok());
    let got = u64::try_from(p2_before.x - p2_after.x).expect("fits");
    assert!(got > 170 * U, "CALIBRATION: about 95 USDm bought about 180 of a token priced at 0.5 USDm");
    let paid = b32(wr::asset_note_cm(got, tag2, payout_owner(4, 1).opening()));
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.peg().ion_pending().is_empty(), "⛔ {who} still holds a pending order after the second leg");
        assert!(n.holds_record_with_cm(&paid), "⛔ {who} does not hold the swap's payout in the second token");
        assert_eq!(u128::from(n.peg().ion_usdm_held()), p1_end.y + owed1 + p2_after.y + owed2, "⛔ {who}'s pool layer is not exactly what the two pools hold");
    }
    assert_eq!(a.peg().contract_state_root(), b.peg().contract_state_root(), "⛔ two roots after the swap");
    assert_eq!((a.ion_cache().row(&tok()), a.ion_cache().row(&OTHER)), (b.ion_cache().row(&tok()), b.ion_cache().row(&OTHER)), "⛔ two rows for a pool after the swap");
}

/// ⭐⭐ A LIQUIDITY LOCK, HELD BY THE CHAIN ON BOTH NODES (spec §14; user 2026-11-12: "the optional ability to lock their
/// liquidity on ionswap with the ability to select the amount of time/unlock date"). A provider opens a pool on A and
/// LOCKS every share it holds until lock week 1 (the chain clock of these pins is in week 0). Asserted on BOTH nodes after
/// every step: the locked share note is in a folded record, the row lists the lock by its date and reads locked, and the
/// node names the locked note's tag as this pool's shares locked until week 1. Then:
/// - a REMOVAL of the locked shares while the chain clock is in week 0 is HANDED BACK on both nodes: the same locked
///   shares return to the provider, and the pool's balances and lock table do not move;
/// - the chain clock crosses Monday 5 January 1970 (week 1) on both nodes, and the removal sent again, spending the
///   handed-back note, PAYS both assets: the lock leaves the table and the provider holds its tokens and its USDm.
#[test]
fn a_lock_is_held_on_both_nodes_until_its_monday_and_then_its_liquidity_leaves() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    let mut ts = 5_000u64;
    let token_tag = ion_tag(&tok(), IonAsset::Token);
    let cid = ion_pool_cid(&tok());
    // the provider (1) opens the pool; three USDm notes pay the lock's, the early removal's and the late removal's fee
    let add = core(ION_ADD, 1_000 * U, 2_000 * U, 0, 0, 1, 1);
    let bind = ion_order_bind(&tok(), &add);
    let tw = asset_witness(owner(11), token_tag, 1_000 * U, 1_000 * U, &bind, 0);
    let uw = usdm_witness(12, 2_000 * U, &bind, 1);
    // O1-INFINITY-REVIEWED: the prover's leaf functions (`spend_input_leaf`, `asset_spend_input_leaf`) compute ONE note's
    // leaf in memory for this test's own blocks; nothing is stored by them (the same calls the pins above make).
    let fee_leaf = |who: u64| b32(wr::spend_input_leaf(&usdm_witness(who, ION_FEE_UNIT, &[0u8; 32], 1)).expect("leaf"));
    plant(
        &mut a,
        &mut b,
        &mut ts,
        &[b32(wr::asset_spend_input_leaf(&tw).expect("leaf")), b32(wr::spend_input_leaf(&uw).expect("leaf")), fee_leaf(13), fee_leaf(14), fee_leaf(15)],
    );
    let add_tx = IonOrderTx { token: tok(), core: add, legs: vec![asset_leg(&a, &tw, 1_000 * U, 1), usdm_leg(&a, &uw, 2_000 * U, 1)], creator: None };
    assert!(matches!(a.publish_ion_order(&add_tx), AssetSpendOutcome::Published), "A's door takes the deposit");
    step(&mut a, &mut b, &mut ts, b"lk-add");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"lk-settle-add"), 1, "the deposit's settlement");
    let shares = {
        let IonState::Pool(p) = a.ion_cache().row(&tok()).expect("the row").state else { panic!("a pool") };
        u64::try_from(p.shares - p.locked).expect("fits")
    };
    let (share_front, share_owner) = payout(1, 1, IonAsset::Share, shares);
    ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 20, 20);
    let _ = (a.fold_canonical_records(), b.fold_canonical_records());
    assert_eq!(lock_week_of(a.chain_time_ms() / 1_000), 0, "CALIBRATION: these pins' chain clock stands in lock week 0");

    // ── THE LOCK: every share until week 1
    let lock = IonOrderCore { lock_until: 1, ..core(ION_LOCK, 0, 0, shares, 0, 1, 2) };
    let lw = asset_witness(share_owner, ion_tag(&tok(), IonAsset::Share), shares, shares, &ion_order_bind(&tok(), &lock), 0);
    assert_eq!(b32(wr::asset_spend_input_leaf(&lw).expect("leaf")), share_front, "CALIBRATION: the lock spends the share note the pool paid");
    let lock_fee = usdm_witness(13, ION_FEE_UNIT, &ion_order_bind(&tok(), &lock), 1);
    let lock_tx = IonOrderTx { token: tok(), core: lock, legs: vec![asset_leg(&a, &lw, shares, 1), usdm_leg(&a, &lock_fee, ION_FEE_UNIT, 1)], creator: None };
    assert!(lock_tx.legs_verify(), "the lock's legs verify");
    assert!(matches!(a.publish_ion_order(&lock_tx), AssetSpendOutcome::Published), "A's door takes the lock");
    step(&mut a, &mut b, &mut ts, b"lk-lock");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"lk-settle-lock"), 1, "the lock's settlement");
    let (locked_front, locked_owner) = payout(1, 2, IonAsset::Locked(1), shares);
    let locked_tag = crate::directory::asset_tag_bytes(&locked_share_asset_id(&cid, 1));
    let before = a.ion_cache().row(&tok()).expect("the row").clone();
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.holds_record_with_cm(&locked_front), "⛔ {who} does not hold the provider's LOCKED share note");
        let row = n.ion_cache().row(&tok()).expect("the row");
        assert_eq!(row.locks, vec![(1, u128::from(shares))], "⛔ {who}'s row does not list the lock by its date");
        let (fixed, of) = row.unremovable_now(0);
        assert!(fixed * 2 > of, "⛔ {who} does not read the pool as locked");
        assert_eq!(n.ion_cache().share_of_tag(&locked_tag), Some((tok(), 1)), "⛔ {who} cannot name the locked share note's tag");
    }
    assert_eq!(a.peg().contract_state_root(), b.peg().contract_state_root(), "⛔ two roots after the lock");
    ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 20, 20);
    let _ = (a.fold_canonical_records(), b.fold_canonical_records());

    // ── THE EARLY REMOVAL (week 0 < 1): handed back on both nodes as the same locked shares
    let early = IonOrderCore { lock_from: 1, ..core(ION_REMOVE, 0, 0, shares, 0, 1, 3) };
    let ew = asset_witness(locked_owner, ion_tag(&tok(), IonAsset::Locked(1)), shares, shares, &ion_order_bind(&tok(), &early), 0);
    assert_eq!(b32(wr::asset_spend_input_leaf(&ew).expect("leaf")), locked_front, "CALIBRATION: the removal spends the locked note");
    let early_fee = usdm_witness(14, ION_FEE_UNIT, &ion_order_bind(&tok(), &early), 1);
    let early_tx = IonOrderTx { token: tok(), core: early, legs: vec![asset_leg(&a, &ew, shares, 1), usdm_leg(&a, &early_fee, ION_FEE_UNIT, 1)], creator: None };
    assert!(matches!(a.publish_ion_order(&early_tx), AssetSpendOutcome::Published), "A's door takes the removal (the date is the settlement's to judge)");
    step(&mut a, &mut b, &mut ts, b"lk-early");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"lk-settle-early"), 1, "the early removal's settlement");
    let (back_front, back_owner) = payout(1, 3, IonAsset::Locked(1), shares);
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.holds_record_with_cm(&back_front), "⛔ {who} does not hold the locked shares handed back");
        let row = n.ion_cache().row(&tok()).expect("the row");
        assert_eq!((row.state, &row.locks), (before.state, &before.locks), "⛔⛔ {who}: LOCKED LIQUIDITY LEFT THE POOL BEFORE ITS DATE");
    }
    ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 20, 20);
    let _ = (a.fold_canonical_records(), b.fold_canonical_records());

    // ── THE MONDAY: the chain clock moves into week 1 on both nodes. The clock is the selected chain's median-time-past
    // (`Node::chain_time_ms`, BIP113), so a few blocks stamped in week 1 do not move it: blocks are laid in week 1 until
    // the median has crossed on both nodes (MEASURED 2026-11-12 on main 083cef36: one fold-wait's worth of week-1 blocks
    // left both clocks at 8 s).
    ts = lock_week_start_secs(1) * 1_000 + 60_000;
    for _ in 0..8 {
        ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts, 600);
        let _ = (a.fold_canonical_records(), b.fold_canonical_records());
        if lock_week_of(a.chain_time_ms() / 1_000) >= 1 && lock_week_of(b.chain_time_ms() / 1_000) >= 1 {
            break;
        }
    }
    assert!(lock_week_of(a.chain_time_ms() / 1_000) >= 1 && lock_week_of(b.chain_time_ms() / 1_000) >= 1, "CALIBRATION: both nodes' chain clock reached week 1 ({} / {} s)", a.chain_time_ms() / 1_000, b.chain_time_ms() / 1_000);

    // ── THE REMOVAL AGAIN, spending the handed-back note: it pays both assets now
    let late = IonOrderCore { lock_from: 1, ..core(ION_REMOVE, 0, 0, shares, 0, 1, 4) };
    let lw2 = asset_witness(back_owner, ion_tag(&tok(), IonAsset::Locked(1)), shares, shares, &ion_order_bind(&tok(), &late), 0);
    assert_eq!(b32(wr::asset_spend_input_leaf(&lw2).expect("leaf")), back_front, "CALIBRATION: the removal spends the handed-back note");
    let late_fee = usdm_witness(15, ION_FEE_UNIT, &ion_order_bind(&tok(), &late), 1);
    let late_tx = IonOrderTx { token: tok(), core: late, legs: vec![asset_leg(&a, &lw2, shares, 1), usdm_leg(&a, &late_fee, ION_FEE_UNIT, 1)], creator: None };
    let late_door = a.publish_ion_order(&late_tx);
    assert!(matches!(late_door, AssetSpendOutcome::Published), "A's door takes the removal after the Monday: {late_door:?}");
    step(&mut a, &mut b, &mut ts, b"lk-late");
    assert_eq!(settle_round(&mut a, &mut b, &mut ts, b"lk-settle-late"), 1, "the late removal's settlement");
    let IonState::Pool(was) = before.state else { panic!("a pool") };
    let after = a.ion_cache().row(&tok()).expect("the row").clone();
    let IonState::Pool(left) = after.state else { panic!("a pool") };
    assert_eq!(left.shares, left.locked, "⛔ the unlocked removal left shares behind");
    assert!(after.locks.is_empty(), "⛔ the removed lock stayed on the table");
    let (out_x, out_y) = (u64::try_from(was.x - left.x).expect("fits"), u64::try_from(was.y - left.y).expect("fits"));
    let (x_front, _) = payout(1, 4, IonAsset::Token, out_x);
    let (y_front, _) = payout(1, 4, IonAsset::Usdm, out_y);
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.holds_record_with_cm(&x_front) && n.holds_record_with_cm(&y_front), "⛔ {who} does not hold what the provider took out on the lock's date");
        assert_eq!(n.ion_cache().row(&tok()), Some(&after), "⛔ {who}'s row is not the pool's after the removal");
    }
    assert_eq!(a.peg().contract_state_root(), b.peg().contract_state_root(), "⛔ two roots at the end");
}

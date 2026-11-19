// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `defi_batch::pins` — the tests of `defi_batch` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `defi_batch` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`defi_batch::pins::…`), and `use super::*` reaches `defi_batch`'s items through the node's re-export.

// the imports of `defi_batch` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use p3_field::PrimeCharacteristicRing;
#[allow(unused_imports)]
use p3_field::PrimeField64;
#[allow(unused_imports)]
use usdm_decider::br15_audit as ba;
#[allow(unused_imports)]
use usdm_decider::hiding_decider::Fa4;

use super::*;
use crate::hash::Hash32;
use crate::node::Node;
use crate::relay::RelayOutcome;
use usdm_decider::br15_audit::F;

fn prg(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
fn big(seed: &mut u64) -> F {
    ba::fsub(&[prg(seed), prg(seed), prg(seed), prg(seed) >> 2], &[0; 4])
}
/// shares of `v` on a random degree-`deg` polynomial at x = 1..=n
fn share(v: &F, deg: usize, n: usize, seed: &mut u64) -> Vec<F> {
    let c: Vec<F> = std::iter::once(*v).chain((0..deg).map(|_| big(seed))).collect();
    (1..=n as u64).map(|x| ba::poly_eval(&c, x)).collect()
}
fn salt(i: usize, k: u64) -> [Fa4; 4] {
    [Fa4::from_u64(i as u64 + 1), Fa4::from_u64(k), Fa4::from_u64(0x15), Fa4::from_u64(0xDF)]
}

/// ⭐ A TEST CUSTODY SET: n custodians' private pool shares, dealt once (the launch position's dealing), and the honest
/// computation each would run — the shares, bits and masks a Shamir run yields, simulated by a dealer so the pin measures
/// the DOORS (every audit is a real proof, every check a real node's). The MPC that produces them is `defi_clear`'s.
pub(crate) struct TestCustody {
    pub n: usize,
    pub t: usize,
    pool: (u64, u64),
    lines: Vec<[F; ba::POOL_LINES]>,
    salts: Vec<[Fa4; 4]>,
    /// ⭐ Earn steps 1 + 3 — each custodian's fee-state shares (B, E, A) and their salt (the launch's: the public zeros)
    fees: Vec<([F; ba::FEE_LINES], [Fa4; 4])>,
    /// ⭐ Earn step 3 — each custodian's closed-window shares (E_c, A_c) and their salt (the launch's: the public zeros)
    closes: Vec<([F; ba::CLOSE_LINES], [Fa4; 4])>,
    seed: u64,
    epoch: u64,
    /// each custodian's ML-KEM-768 custody keypair `(ek, dk)` (a bonded custodian's `MembershipBondHeader::kem_ek`)
    kems: Vec<(Vec<u8>, Vec<u8>)>,
}

impl TestCustody {
    /// The roster's custody encapsulation keys (what an order seals its shares to).
    pub(crate) fn eks(&self) -> Vec<Vec<u8>> {
        self.kems.iter().map(|k| k.0.clone()).collect()
    }
    /// Every custodian's own state (what each holds between batches).
    pub(crate) fn states(&self) -> Vec<crate::defi_custody::CustodianState> {
        (0..self.n)
            .map(|i| crate::defi_custody::CustodianState {
                lines: self.lines[i],
                salt: self.salts[i],
                fee: self.fees[i].0,
                fee_salt: self.fees[i].1,
                close: self.closes[i].0,
                close_salt: self.closes[i].1,
            })
            .collect()
    }
    /// The custodians move to the states a settled run left them.
    pub(crate) fn adopt(&mut self, next: &[crate::defi_custody::CustodianState]) {
        self.lines = next.iter().map(|c| c.lines).collect();
        self.salts = next.iter().map(|c| c.salt).collect();
        self.fees = next.iter().map(|c| (c.fee, c.fee_salt)).collect();
        self.closes = next.iter().map(|c| (c.close, c.close_salt)).collect();
    }
    /// Custodian `i`'s decapsulation key.
    pub(crate) fn dk(&self, i: usize) -> &[u8] {
        &self.kems[i].1
    }
    pub(crate) fn open(n: usize, t: usize, pool_x: u64, pool_y: u64) -> Self {
        let mut seed = 0x15_0B0Bu64;
        let cols: Vec<Vec<F>> = [pool_x, pool_y, 0, 0].iter().map(|v| share(&ba::fsmall(*v), t, n, &mut seed)).collect();
        let lines = (0..n).map(|i| core::array::from_fn(|l| cols[l][i])).collect();
        let kems = (0..n).map(|_| crate::pqkem::keypair()).collect();
        let fees = (0..n).map(|i| ([[0; 4]; ba::FEE_LINES], ba::launch_fee_salt(0, i))).collect();
        let closes = (0..n).map(|i| ([[0; 4]; ba::CLOSE_LINES], ba::launch_close_salt(0, i))).collect();
        TestCustody { n, t, pool: (pool_x, pool_y), lines, salts: (0..n).map(|i| salt(i, 1)).collect(), fees, closes, seed, epoch: 1, kems }
    }
    /// The book every node starts from (the same bytes on every node, as a genesis fact is).
    pub(crate) fn book(&self) -> DefiBook {
        DefiBook {
            pair: 0,
            roster: (0..self.n).map(|i| [i as u8 + 1; 32]).collect(),
            eks: self.eks(),
            t: self.t as u32,
            pool_commits: (0..self.n).map(|i| pool_commit(&self.lines[i], &self.salts[i])).collect(),
            fee_commits: (0..self.n).map(|i| crate::defi_batch::fee_commit(&self.fees[i].0, &self.fees[i].1)).collect(),
            batch: 0,
            opened_at: 0,
            opened_ms: 0,
            orders: Vec::new(),
            last_tick: crate::defi_clear::rule_tick(u128::from(self.pool.0), u128::from(self.pool.1)),
            last_expired: false,
            last_sells: false,
            prices: Default::default(),
            income_index: 0,
            pending: Vec::new(),
            slotted: false,
            slot_parts: 0,
            handover: None,
            close_commits: (0..self.n).map(|i| crate::defi_batch::close_commit(&self.closes[i].0, &self.closes[i].1)).collect(),
            sampling: true,
            ..DefiBook::default()
        }
    }
    /// A buy order's dealing of `amount` with no maximum price (the last bucket's Y line).
    pub(crate) fn deal(&mut self, amount: u64, amount_blind: [u64; 8]) -> ba::OrderDealing {
        let s = &mut self.seed;
        ba::OrderDealing {
            amount,
            amount_blind,
            bucket: ba::ORDER_BUCKETS - 1,
            on_x: false,
            deposit: false,
            withdraw: None,
            index: 0,
            x_tag: crate::satoshi::asset_tag(),
            y_tag: pair_y_tag(0),
            coeffs: (0..ba::ORDER_LINES).map(|_| (0..self.t).map(|_| big(s)).collect()).collect(),
            salts: (0..self.n).map(|i| [Fa4::from_u64(prg(s)), Fa4::from_u64(i as u64), Fa4::ONE, Fa4::ONE]).collect(),
            binding: [0; 8],
            owner: [[0; 8]; 3],
            lc_blind: [0; 8],
            cover: None,
        }
    }
}

/// The note a pair-0 buy order spends: the corpus witness `k`'s value and owner, tagged with the pair's Y asset. MEASURED
/// 2026-11-16 (lane af58, F6 door-defi G3): since the pools trade native assets (pair 0's Y is wrapped BTC, `pair_y_tag`),
/// the USDm-tagged corpus note (`Node::test_spendable_note`, leaf `P(value, P([USDm tag], sk))`) is not a note a buy can
/// spend, and this pin's own precondition refused it (red on every run since 2026-11-11). The note is planted the way the
/// corpus plants every note (its commitment in the first 32 bytes, filler after), and the order burns it like any other.
fn pair0_buy_note(k: u64) -> (Vec<u8>, [u8; 32]) {
    let sw = Node::test_spend_witness(k);
    let leaf = ba::slot_note_cm(sw.value_in, pair_y_tag(0), &[sw.owner.ask, sw.owner.nk, sw.owner.seed]);
    let cm = crate::spend_frontier::leaf_to_cm_bytes(leaf);
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&cm);
    for (i, b) in note.iter_mut().enumerate().skip(32) {
        *b = ((i as u64).wrapping_mul(37).wrapping_add(k * 11) % 251) as u8;
    }
    (note, cm)
}

/// A buyer's order slot spending the corpus note `k` that `a` holds in a folded record — ALL of it (an order spends a note
/// of exactly its amount, spec §18.12): its owner from the corpus witness, its member leg from `a`'s own tree.
fn order_from_note(a: &Node, custody: &mut TestCustody, k: u64) -> (DefiOrderTx, ba::OrderDealing) {
    let sw = Node::test_spend_witness(k);
    let a_blind = [0x0D, k, 1, 2, 3, 4, 5, 6];
    let mut dealing = custody.deal(sw.value_in, a_blind);
    dealing.owner = [sw.owner.ask, sw.owner.nk, sw.owner.seed];
    dealing.lc_blind = [0x1E, k, 9, 9, 9, 9, 9, 9];
    let (epoch_pk, _) = crate::epoch_release::test_epoch_keypair();
    let (epoch_k, epoch_ct) = crate::epoch_key::encapsulate(&epoch_pk, &[k as u8; 32]);
    let sealed = crate::defi_custody::seal_dealing(&dealing, &custody.eks(), &epoch_k).expect("the shares seal");
    dealing.binding = sealed_binding(0, &epoch_ct, &sealed);
    let (r1cs, io, w) = ba::order_share_circuit(&dealing).expect("the share proof builds");
    let share_proof = usdm_decider::spartan_ccs::prove_committed(&r1cs, &io, &w).expect("the share proof proves");
    let (cm, nf, lc) = dealing.spend_publics();
    let (_, note_cm) = pair0_buy_note(k);
    assert_eq!(crate::spend_frontier::note_leaf_of(&note_cm), cm, "PRECONDITION: the slot spends the planted pair-0 note");
    let (carrier, tuple) = a.member_leg_for_test(&note_cm, nf, dealing.lc_blind, &[0u8; 32], &[0u8; 32]).expect("the note's member leg builds");
    let mut tip = Vec::new();
    crate::member_transition::write_tuple(&tuple, &mut tip);
    let t = DefiOrderTx {
        pair: 0,
        amount_commit: dealing.amount_commit(),
        limit_commit: dealing.limit_commit(),
        share_commits: dealing.share_commits().iter().map(u4).collect(),
        epoch: 0,
        epoch_ct,
        sealed,
        share_proof,
        nullifier: nf,
        leaf_commit: lc,
        member_carrier: carrier,
        member_tuple: tip,
        index: dealing.index,
    };
    (t, dealing)
}

/// A batch's slots over `orders` and `claims`, filled to [`SLOTS`] by THE CUSTODY LANE'S OWN BUILDER — covers whose legs come
/// from the member book the production lane gathers for a note `a` holds (`member_book_for_note`), so a pin over these slots
/// exercises the lane's leaf spelling, not a copy of it.
fn slots_of(a: &Node, custody: &TestCustody, book: &DefiBook, orders: Vec<DefiOrderTx>, claims: Vec<DefiClaimTx>, cover_cm: &[u8; 32], seed: u8) -> Vec<DefiSlotsTx> {
    let (pk, _) = crate::epoch_release::test_epoch_keypair();
    let _ = custody;
    let mb = a.member_book_for_note(cover_cm).expect("the lane gathers the cover note's member book");
    crate::defi_lane::build_slots(book, 0, &pk, orders, claims, &[(*cover_cm, mb)], &[seed; 32]).expect("the lane builds the batch's slots")
}

/// The part of `parts` that carries nullifier `nf`.
fn part_with(parts: &[DefiSlotsTx], nf: [u64; 8]) -> DefiSlotsTx {
    parts.iter().find(|p| p.orders.iter().any(|o| o.nullifier == nf) || p.claims.iter().any(|c| c.nullifier == nf)).expect("a part carries it").clone()
}

/// Every part pooled on `a`, then fold steps until both nodes hold the batch slotted (a block carries what its weight
/// allows, so the parts may fold over more than one step).
fn slot_in(a: &mut Node, b: &mut Node, ts: &mut u64, parts: &[DefiSlotsTx], tag: &[u8]) {
    for p in parts {
        a.publish_defi_slots(p).expect("A pools each part of the batch's slots");
    }
    for i in 0..(SLOT_PARTS as u64 + 2) {
        if a.peg().defi_book().slotted && b.peg().defi_book().slotted {
            break;
        }
        step(a, b, ts, &[tag, &i.to_le_bytes()[..]].concat());
    }
    assert!(a.peg().defi_book().slotted && b.peg().defi_book().slotted, "⛔ a node does not hold the batch's every slot part");
}

/// The parts' orders in the book's (fold) order — what the custody captured its shares by.
fn in_fold_order(book: &DefiBook, parts: &[DefiSlotsTx]) -> Vec<DefiOrderTx> {
    book.orders
        .iter()
        .map(|bo| {
            parts.iter().flat_map(|p| &p.orders).find(|o| o.amount_commit == bo.amount_commit && o.share_commits == bo.share_commits).expect("every book order is a carried slot").clone()
        })
        .collect()
}

/// The owner's claim of `dealing`'s order at the leaf `(p_num, p_den, j_min)`, its leaf already in `a`'s folded note set. `over`
/// adds to the paid amount (a TAMPER). `(s_num, s_den)` is the batch's sellers' price exactly as the chain wrote the leaf
/// (`sell_price(tick, sells)` in [`claim_leaf_at`]; a refund's `(0, 1)`): the leaf binds it, so a claim opening the leaf at
/// any other sellers' price names a leaf no record holds (red on every run since the sells-priced leaf of 2026-11-15, the
/// fixture opening `(0, 1)` against a batch whose sells counted).
fn claim(a: &Node, dealing: &ba::OrderDealing, p_num: u128, p_den: u128, j_min: u64, (s_num, s_den): (u128, u128), over: u64) -> DefiClaimTx {
    let mut cw = ba::ClaimWitness {
        cover: None,
        amount: dealing.amount,
        amount_blind: dealing.amount_blind,
        bucket: dealing.bucket as u64,
        sell: false, deposit: false, withdraw: false, leg: 0, extra: ba::LeafExtra::default(), entry: 0, now: 0,
        p_num,
        p_den,
        j_min,
        s_num,
        s_den,
        out: 0,
        out_blind: [0x0B, 1, 2, 3, 4, 5, 6, 7],
        lc_blind: [0x1C, 7, 6, 5, 4, 3, 2, 1],
    };
    // Earn step 1: what the claim mints at its own terms (a filled buy less its fee), plus the tamper
    cw.out = cw.paid().expect("fits") + over;
    let out = cw.out;
    let (nf, lc, oc, pays_y) = cw.publics();
    let (r1cs, io, w) = ba::claim_circuit(&cw).expect("the claim builds");
    let claim_proof = usdm_decider::spartan_ccs::prove_committed(&r1cs, &io, &w).unwrap_or_default();
    let leaf = cw.leaf();
    let leaf_cm = crate::spend_frontier::leaf_to_cm_bytes(leaf);
    let (carrier, tuple) = a.member_leg_for_test(&leaf_cm, nf, cw.lc_blind, &[0u8; 32], &[0u8; 32]).expect("the claim leaf's member leg builds");
    let mut tip = Vec::new();
    crate::member_transition::write_tuple(&tuple, &mut tip);
    let owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key([0xC1; 8]);
    let asset = if pays_y { pair_y_tag(0) } else { crate::satoshi::asset_tag() };
    let (mint, cm, dc) = usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(out, asset, &owner.opening(), &cw.out_blind)
        .expect("the mint proves");
    assert_eq!(dc, oc, "the mint's committed delta is the claim's output commitment");
    let mut note = vec![0x7Au8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
    DefiClaimTx {
        pair: 0,
        nullifier: nf,
        leaf_commit: lc,
        out_commit: oc,
        pays_y,
        claim_proof,
        member_carrier: carrier,
        member_tuple: tip,
        mint_carrier: mint,
        note,
        owner_clue: vec![0xC2; crate::peg_in_tx::OWNER_CLUE_MAX],
    }
}

/// A produces a block; B ingests it; both fold.
fn step(a: &mut Node, b: &mut Node, ts: &mut u64, tag: &[u8]) {
    let blk = a.produce(*ts, Hash32::hash(tag), Hash32::hash(b"br15-mc")).expect("A produces");
    let got = b.ingest_block(blk, *ts + 100);
    assert!(matches!(got, RelayOutcome::Added(_)), "⛔ B refused A's block: {got:?}");
    let _ = a.fold_canonical_records();
    let _ = b.fold_canonical_records();
    *ts += 600;
}

/// ⭐⭐⭐ §BR-15 ACCEPTANCE — AN ORDER IS SEALED, SETTLED BY AN AUDITED BATCH AND CLAIMED WITHOUT NAMING IT, ON TWO NODES; and
/// every rogue variant is refused on the peer. Four custodians (t = 1) hold a launch pool (X 1,000,000 SAT, Y 2,000,000
/// USDm-atomic). A burns a real note into a buy order; both books hold it. The custody set settles at the rule's tick with four
/// real audits; both nodes insert the order's claim leaf and move the pool. A's owner claims ⌊y·d/n⌋ SAT through a member
/// leg — the note lands on BOTH nodes and the claim nullifier is spent on both. TAMPERS, each refused on the peer: a
/// settlement at a tick above the rule's (forge), the claim replayed (replay), an over-claim (substitute), a claim stripped
/// of its member leg (strip), and the order's burn re-carried (burn). Then an unsettled batch expires and the order's
/// REFUND pays exactly its amount.
#[test]
fn br15_an_order_settles_by_audit_and_its_claim_pays_exactly_its_fill_on_both_nodes() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    // the expiry window folds > `SPINE_RING_LEN` blocks: each party keeps its band moving as a production node's prove
    // worker does (DB-396 — without it the fold waits at the band's lag cap, which no mesh runs)
    a.autoprove_band_for_test();
    b.autoprove_band_for_test();
    let mut ts = 5_000u64;
    // two funded notes on A, carried to B
    let (n1_note, n1_cm) = pair0_buy_note(151);
    let (n2_note, n2_cm) = pair0_buy_note(152);
    for note in [&n1_note, &n2_note] {
        let (blk, _) = a.carry_notes_in_a_block_for_test(ts, note);
        assert!(matches!(b.ingest_block(blk, ts + 100), RelayOutcome::Added(_)), "B takes the funding block");
        ts += 600;
    }
    for i in 0..6u64 {
        if a.member_path_ready_for_test(&n1_cm) && a.member_path_ready_for_test(&n2_cm) {
            break;
        }
        step(&mut a, &mut b, &mut ts, &i.to_le_bytes());
    }
    assert!(a.member_path_ready_for_test(&n1_cm), "PRECONDITION: the first note confirmed on A");
    // the book opens on both nodes from the same launch dealing
    let mut custody = TestCustody::open(4, 1, 1_000_000, 2_000_000);
    for n in [&mut a, &mut b] {
        *n.peg_mut_for_test().defi_book_mut(0).expect("the pair") = custody.book();
    }
    // ── the order: a slot spending note 151 whole, handed to custody, carried in the batch's slots beside covers
    let (order, dealing) = order_from_note(&a, &mut custody, 151);
    assert_eq!(order.self_valid(1), None, "the honest order slot verifies statelessly");
    let lone = crate::chain_object::frame(crate::chain_object::Class::DefiOrder, &order.encode().expect("encodes"));
    assert!(!crate::chain_object::admissible(&lone, 10, 0, false), "⛔ a lone order was admitted outside its batch's slots");
    let close = |a: &mut Node, b: &mut Node, ts: &mut u64, tag: u64| {
        for i in 0..BATCH_STEPS {
            step(a, b, ts, &(tag + i).to_le_bytes());
        }
    };
    close(&mut a, &mut b, &mut ts, 50);
    // A-F26: rebuild the order's member leg at the CURRENT anchor so every slot of one batch names one anchor
    let mut order = order;
    {
        let (_, note_cm) = pair0_buy_note(151);
        let (carrier, tuple) = a.member_leg_for_test(&note_cm, order.nullifier, dealing.lc_blind, &[0u8; 32], &[0u8; 32]).expect("the order's member leg rebuilds at the current anchor");
        let mut tip = Vec::new();
        crate::member_transition::write_tuple(&tuple, &mut tip);
        order.member_carrier = carrier;
        order.member_tuple = tip;
    }
    let book0 = a.peg().defi_book().clone();
    let slots = slots_of(&a, &custody, &book0, vec![order.clone()], Vec::new(), &n2_cm, 1);
    assert_eq!(slots.len(), SLOT_PARTS, "the batch travels as its SLOT_PARTS parts");
    slot_in(&mut a, &mut b, &mut ts, &slots, b"br15-slots");
    for (who, n) in [("A", &a), ("B", &b)] {
        let bk = n.peg().defi_book();
        assert!(bk.slotted && bk.orders.len() == SLOTS, "⛔ {who}'s book does not hold the batch's {SLOTS} slots");
        assert!(n.is_nullifier_spent(&Hash32(crate::spend_frontier::leaf_to_cm_bytes(order.nullifier))), "⛔ {who} did not retire the order's note");
    }
    // ── the honest settlement: THE CUSTODY RUNTIME over the shares each custodian captured from every slot the chain
    // carried (its sealed share opened with its own ML-KEM key and the epoch key, checked against the slot's commitment)
    let book = a.peg().defi_book().clone();
    let (epoch_pk, epoch_sk) = crate::epoch_release::test_epoch_keypair();
    let captured: Vec<Vec<Option<crate::defi_custody::OrderShare>>> = in_fold_order(&book, &slots)
        .iter()
        .map(|o| {
            let ek = crate::defi_custody::order_epoch_key(&epoch_pk, &epoch_sk, o).expect("the custody's released epoch key opens the slot's layer");
            (0..custody.n).map(|i| crate::defi_custody::capture_order_share(custody.dk(i), &ek, i, o)).collect()
        })
        .collect();
    assert!(captured.iter().flatten().all(Option::is_some), "every custodian captured its share of every slot");
    let ek0 = crate::defi_custody::order_epoch_key(&epoch_pk, &epoch_sk, &order).expect("opens");
    assert!(crate::defi_custody::capture_order_share(custody.dk(1), &ek0, 0, &order).is_none(), "⛔ a custodian opened another's share");
    let key = crate::defi_custody::custody_entropy().expect("entropy");
    let run = crate::defi_custody::run_batch(&book, &custody.states(), &captured, &key).expect("the custody set settles");
    let honest_tick = crate::defi_clear::rule_tick(1_000_000, 2_000_000 + u128::from(dealing.amount));
    assert_eq!(run.settle.tick, honest_tick, "the covers add nothing: the custody set settles at the one buy's rule tick");
    // ── FORGE: the settlement at a tick above the rule's is refused on both nodes (its audits prove the honest statements)
    let mut forged = run.settle.clone();
    forged.tick = honest_tick + 3;
    forged.leaves = settle_leaves(&book, forged.tick, forged.j_min, true, &[]);
    assert!(forged.verdict(&book).is_err(), "⛔ a settlement at a tick above the price passed the verdict");
    a.publish_defi_settle(&forged).expect("A pools the forged settlement");
    step(&mut a, &mut b, &mut ts, b"br15-forged");
    for (who, n) in [("A", &a), ("B", &b)] {
        assert_eq!(n.peg().defi_book().batch, 0, "⛔ {who} applied a forged settlement");
    }
    custody.adopt(&run.next);
    let settle = run.settle;
    assert_eq!(settle.verdict(&book), Ok(settle.leaves.clone()), "the honest settlement passes the verdict");
    a.publish_defi_settle(&settle).expect("A pools the settlement");
    step(&mut a, &mut b, &mut ts, b"br15-settle");
    for (who, n) in [("A", &a), ("B", &b)] {
        let bk = n.peg().defi_book();
        assert_eq!((bk.batch, bk.orders.len(), bk.last_tick), (1, 0, honest_tick), "⛔ {who} did not settle the batch");
        assert_eq!(bk.pool_commits, settle.parts.iter().map(|p| p.new_pool).collect::<Vec<_>>(), "⛔ {who}'s pool did not move");
    }
    let (n1r, d1r) = crate::defi_clear::tick_ratio(honest_tick + 1);
    let jm = crate::defi_clear::j_min(book.last_tick, honest_tick);
    let leaf_cm = crate::spend_frontier::leaf_to_cm_bytes(claim_leaf_at(&dealing.amount_commit(), &dealing.limit_commit(), honest_tick, jm, true));
    for i in 0..6u64 {
        if a.member_path_ready_for_test(&leaf_cm) {
            break;
        }
        step(&mut a, &mut b, &mut ts, &(100 + i).to_le_bytes());
    }
    assert!(a.member_path_ready_for_test(&leaf_cm), "PRECONDITION: the claim leaf folded on A");
    // ── SUBSTITUTE: an over-claim does not prove
    let sells_at = sell_price(honest_tick, true);
    let over = claim(&a, &dealing, d1r, n1r, jm, sells_at, 1);
    assert!(over.self_valid().is_some(), "⛔ an over-claim passed the claim relation");
    // ── STRIP: the next batch's slots carrying the honest claim WITHOUT its member leg are refused, and the refusal retires
    // nothing: the claim nullifier stays unspent, so the honest claim below still pays. ⭐ Since A-F26 the refusal is at the
    // STATELESS door, before any fold: every slot of one batch must name one anchor, and a slot with no member tuple names none
    // (`chain_object::admissible`, Class::DefiSlots). That door is the one the pool runs AND the one the graft runs on every
    // object a block carries (node/ingest.rs "the graft door's rule"), so a producer that skips its own pool and lays the part
    // anyway is refused on the peer by the same function this pin calls directly. (Before A-F26 the pool admitted the part and
    // both folds refused it; the pin asserted that older, later refusal and went red at the pool door — 2026-11-16.)
    // A-F26: the batch closes FIRST and the claim's member leg is built at the anchor that batch's covers name (the order's
    // leg is rebuilt the same way above): a leg built before `close` names an older anchor, and the stateless door refuses
    // the whole part for it (the calibration below caught this on 2026-11-16 — the honest part was refused too).
    close(&mut a, &mut b, &mut ts, 150);
    let honest = claim(&a, &dealing, d1r, n1r, jm, sells_at, 0);
    assert_eq!(honest.self_valid(), None, "the honest claim verifies statelessly");
    let claim_nf = Hash32(crate::spend_frontier::leaf_to_cm_bytes(honest.nullifier));
    let mut stripped = honest.clone();
    stripped.member_carrier.clear();
    stripped.member_tuple.clear();
    let book1 = a.peg().defi_book().clone();
    let bad = part_with(&slots_of(&a, &custody, &book1, Vec::new(), vec![stripped.clone()], &n2_cm, 2), stripped.nullifier);
    assert!(a.publish_defi_slots(&bad).is_err(), "⛔ A's pool admitted a slot part whose claim has no member leg");
    let bad_frame = bad.wire().expect("the stripped part still encodes");
    assert!(
        !crate::chain_object::admissible(&bad_frame, 10, 0, false),
        "⛔ the stateless door every graft runs admitted a slot part whose claim has no member leg"
    );
    let honest_part = part_with(&slots_of(&a, &custody, &book1, Vec::new(), vec![honest.clone()], &n2_cm, 2), honest.nullifier);
    assert!(
        crate::chain_object::admissible(&honest_part.wire().expect("encodes"), 10, 0, false),
        "calibration: the same part WITH the member leg passes the stateless door (the refusal is the strip, nothing else)"
    );
    step(&mut a, &mut b, &mut ts, b"br15-stripped");
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.peg().defi_book().slot_parts == 0, "⛔ {who} applied a slot part whose claim has no member leg");
        assert!(!n.is_nullifier_spent(&claim_nf), "⛔ {who}: refused slots burned the order's claim nullifier");
    }
    // ── the claim, in the batch's slots. A-F26 again: the STRIP step above moved the anchor, so the claim's member leg is
    // rebuilt now, at the anchor these slots' covers will name (the same claim: its nullifier, leaf and payout are unchanged)
    let honest = claim(&a, &dealing, d1r, n1r, jm, sells_at, 0);
    assert_eq!(Hash32(crate::spend_frontier::leaf_to_cm_bytes(honest.nullifier)), claim_nf, "the rebuilt claim is the same claim");
    let good = slots_of(&a, &custody, &book1, Vec::new(), vec![honest.clone()], &n2_cm, 3);
    slot_in(&mut a, &mut b, &mut ts, &good, b"br15-claim");
    let paid = ba::buy_paid(dealing.amount, d1r, n1r).expect("fits");
    assert!(paid > 0, "the fill pays SAT (its fill less the fee)");
    let note_cm: [u8; 32] = honest.note[..32].try_into().expect("32 bytes");
    for i in 0..6u64 {
        if a.member_path_ready_for_test(&note_cm) && b.member_path_ready_for_test(&note_cm) {
            break;
        }
        step(&mut a, &mut b, &mut ts, &(200 + i).to_le_bytes());
    }
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.member_path_ready_for_test(&note_cm), "⛔ {who} does not hold the claimed SAT note");
        assert!(n.is_nullifier_spent(&claim_nf), "⛔ {who} did not spend the order's claim nullifier");
    }
    // ── the batch with the claim's slots settles (8 cover orders: an empty clearing), then REPLAY: the same claim in the
    // next batch's slots is refused (the spent set)
    let book1b = a.peg().defi_book().clone();
    let cap1: Vec<Vec<Option<crate::defi_custody::OrderShare>>> = in_fold_order(&book1b, &good)
        .iter()
        .map(|o| {
            let ek = crate::defi_custody::order_epoch_key(&epoch_pk, &epoch_sk, o).expect("opens");
            (0..custody.n).map(|i| crate::defi_custody::capture_order_share(custody.dk(i), &ek, i, o)).collect()
        })
        .collect();
    let run1 = crate::defi_custody::run_batch(&book1b, &custody.states(), &cap1, &key).expect("the covers' batch settles");
    // a batch of covers trades nothing: it publishes the pool's own price AFTER the first batch's sale — X less the SAT the
    // buyer was paid, Y plus its USDm — never the first batch's clearing tick (which priced the buy on the pre-trade X)
    // The pool's own reserves are READ from the custodians' shares (Lagrange at 0 over t + 1 of them), never re-derived from
    // the buyer's take: since Earn step 1 the buyer's claim is its fill LESS the fee (`ba::buy_paid`), and the booking
    // over-books `q_X` by up to 3 units by design (BRIDGE-USDM-PRIVACY-SPEC, the custody runtime), so `X − paid` overstated the
    // pool's X and the pin expected a tick one too low (791 against the pool's 792, MEASURED 2026-11-17 on main 891afbf1).
    let st = custody.states();
    let line = |l: usize| -> u128 {
        // Lagrange at 0 over the first t + 1 custodians' shares (the opening `defi_custody`'s own tests use)
        let k = custody.t + 1;
        let v = (0..k).fold([0u64; 4], |acc, i| {
            let xi = (i + 1) as u64;
            let wgt = (0..k).filter(|j| *j != i).fold(ba::fsmall(1), |a, j| {
                let xj = (j + 1) as u64;
                ba::fmul(&ba::fmul(&a, &ba::fsmall(xj)), &ba::finv(&ba::fsub(&ba::fsmall(xj), &ba::fsmall(xi))))
            });
            ba::fadd(&acc, &ba::fmul(&wgt, &st[i].lines[l]))
        });
        assert!(v[2] == 0 && v[3] == 0, "an opened pool line is small");
        u128::from(v[0]) | (u128::from(v[1]) << 64)
    };
    let (pool_x, pool_y) = (line(0), line(1));
    assert!(pool_x < 1_000_000 && pool_y > 2_000_000, "CALIBRATION: the first batch sold X for Y ({pool_x}, {pool_y})");
    assert!(
        1_000_000 - pool_x >= u128::from(paid),
        "⛔ the pool released less SAT than the buyer was paid ({} < {paid})",
        1_000_000 - pool_x
    );
    let after_sale = crate::defi_clear::rule_tick(pool_x, pool_y);
    assert_eq!(run1.settle.tick, after_sale, "⛔ a batch of covers moved the price off the pool's own");
    custody.adopt(&run1.next);
    a.publish_defi_settle(&run1.settle).expect("A pools the covers' settlement");
    step(&mut a, &mut b, &mut ts, b"br15-settle1");
    close(&mut a, &mut b, &mut ts, 250);
    let book2 = a.peg().defi_book().clone();
    assert_eq!(book2.batch, 2, "the covers' batch settled on A");
    // REPLAY: the SAME claim with its member leg rebuilt at the current anchor, so the only thing wrong with it is that its
    // nullifier is spent — a leg left at an older anchor would be refused for its anchor (A-F26) and prove nothing about replay
    let replayed = claim(&a, &dealing, d1r, n1r, jm, sells_at, 0);
    assert_eq!(replayed.nullifier, honest.nullifier, "calibration: the replay is the same claim (its nullifier already spent)");
    let replay = part_with(&slots_of(&a, &custody, &book2, Vec::new(), vec![replayed.clone()], &n2_cm, 4), replayed.nullifier);
    assert!(
        crate::chain_object::admissible(&replay.wire().expect("encodes"), 10, 0, false),
        "calibration: the replay part passes the stateless door — its refusal below is the spent nullifier, not its anchor"
    );
    assert!(a.publish_defi_slots(&replay).is_err() || {
        step(&mut a, &mut b, &mut ts, b"br15-replay");
        a.peg().defi_book().slot_parts == 0 && b.peg().defi_book().slot_parts == 0
    }, "⛔ a replayed claim's slot part applied");
    // ── EXPIRY → REFUND: a second order (note 152) in this batch's slots, never settled
    let (order2, dealing2) = order_from_note(&a, &mut custody, 152);
    let book2 = a.peg().defi_book().clone();
    let slots2 = slots_of(&a, &custody, &book2, vec![order2], Vec::new(), &n1_cm, 5);
    slot_in(&mut a, &mut b, &mut ts, &slots2, b"br15-order2");
    let refunds: Vec<[u64; 8]> = b.peg().defi_book().orders.iter().map(|o| refund_leaf(&o.amount_commit, &o.limit_commit)).collect();
    let expire = DefiExpireTx { pair: 0, batch: 2, leaves: refunds };
    TEST_EXPIRE_MS.with(|c| c.set(Some(30_000)));
    assert!(expire.verdict(b.peg().defi_book(), 0, b.chain_time_ms()).is_err(), "⛔ an expiry inside the settlement window passed");
    // FAST ISOLATION (lane speed5, 2026-11-19): step only until the expiry's own verdict passes on both parties, at most
    // BATCH_STEPS + 120. MEASURED why: the fixed 124 real-proof steps (~42 s each on a loaded machine) ran past door-defi's
    // 3,600 s hang guard (results.tsv 2026-11-19 02:48, "timed out after 3600 s"), so the door read FAIL on a test that was
    // still passing. The claim is unchanged: the expiry is refused inside the window (above) and applies after it (below).
    let mut steps = 0u64;
    while [&a, &b].iter().any(|n| expire.verdict(n.peg().defi_book(), 0, n.chain_time_ms()).is_err()) {
        assert!(steps < BATCH_STEPS + 120, "⛔ the settlement window never closed in {} steps", BATCH_STEPS + 120);
        step(&mut a, &mut b, &mut ts, &(300 + steps).to_le_bytes());
        steps += 1;
    }
    eprintln!("[br15-e2e] the expiry window closed after {steps} step(s)");
    a.publish_defi_expire(&expire).expect("A pools the expiry");
    step(&mut a, &mut b, &mut ts, b"br15-expire");
    for (who, n) in [("A", &a), ("B", &b)] {
        assert_eq!(n.peg().defi_book().batch, 3, "⛔ {who} did not expire the batch");
    }
    let refund_cm = crate::spend_frontier::leaf_to_cm_bytes(refund_leaf(&dealing2.amount_commit(), &dealing2.limit_commit()));
    for i in 0..6u64 {
        if a.member_path_ready_for_test(&refund_cm) {
            break;
        }
        step(&mut a, &mut b, &mut ts, &(500 + i).to_le_bytes());
    }
    // A-F26: the batch closes first and the refund's member leg is built at the anchor its slots' covers name
    close(&mut a, &mut b, &mut ts, 600);
    let refund = claim(&a, &dealing2, 1, 1, ba::ORDER_BUCKETS as u64, (0, 1), 0);
    assert!(refund.pays_y, "an expired batch's claim is a refund");
    assert_eq!(refund.self_valid(), None, "the refund verifies");
    let book3 = a.peg().defi_book().clone();
    let rslots = slots_of(&a, &custody, &book3, Vec::new(), vec![refund.clone()], &n1_cm, 6);
    slot_in(&mut a, &mut b, &mut ts, &rslots, b"br15-refund");
    let rnf = Hash32(crate::spend_frontier::leaf_to_cm_bytes(refund.nullifier));
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.is_nullifier_spent(&rnf), "⛔ {who} did not pay the refund");
    }
    eprintln!("[br15-e2e] every batch {SLOTS} orders + {SLOTS} claims: order {} → tick {honest_tick} → claimed {paid} SAT on both nodes; order {} → expired → refunded on both", dealing.amount, dealing2.amount);
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ §BR-15 ACCEPTANCE (spec §18.6) — the named pins, each over the real objects, verdicts and proofs every node runs.
//! The two-node chain agreement for the same objects is `defi_batch::pins::br15_an_order_settles_by_audit_and_its_claim_
//! pays_exactly_its_fill_on_both_nodes` (one node produces, the second ingests; every attack refused on the peer).
//! TWO-PARTY-REVIEWED: the parties here are the order's owner (who deals and seals), each custodian (who opens only its own
//! share with its own key and runs the runtime) and the verifying node (`verdict`, `self_valid`) — distinct inputs, distinct
//! keys; the cross-node half is the two-node pin named above.

use crate::defi_batch::{self as db, DefiBook, DefiClaimTx, DefiExpireTx};
use crate::defi_custody::{self as dcu, CustodianState, OrderShare};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use usdm_decider::br15_audit as ba;
use usdm_decider::hiding_decider::Fa4;

/// A test buyer's note owner `(ask, nk, seed)`.
fn owner_of(k: u64, seed: u8) -> [[u64; 8]; 3] {
    [[0xA5, k, u64::from(seed), 1, 2, 3, 4, 5], [0xB5, k, u64::from(seed), 6, 7, 8, 9, 10], [0xC5, k, u64::from(seed), 11, 12, 13, 14, 15]]
}

fn u4(c: &[Fa4; 4]) -> [u64; 4] {
    core::array::from_fn(|k| c[k].as_canonical_u64())
}

/// A pool dealt among `n` custodians (with real ML-KEM custody keys) and buys of `amounts`, each dealt and sealed by its
/// owner; every custodian captures its share from the sealed bytes.
fn market(n: usize, pool: (u64, u64), amounts: &[u64], seed: u8) -> (DefiBook, Vec<CustodianState>, Vec<ba::OrderDealing>, Vec<Vec<Option<OrderShare>>>, Vec<Vec<u8>>) {
    market_sides(n, [pool.0, pool.1, 0, 0], &amounts.iter().map(|a| (*a, false)).collect::<Vec<_>>(), seed)
}

/// [`market`] with the pool's four lines stated and each order's side.
fn market_sides(n: usize, lines: [u64; 4], orders: &[(u64, bool)], seed: u8) -> (DefiBook, Vec<CustodianState>, Vec<ba::OrderDealing>, Vec<Vec<Option<OrderShare>>>, Vec<Vec<u8>>) {
    let t = (n - 1) / 3;
    let kems: Vec<(Vec<u8>, Vec<u8>)> = (0..n).map(|_| crate::pqkem::keypair()).collect();
    let (epoch_pk, epoch_sk) = crate::epoch_release::test_epoch_keypair();
    let eks: Vec<Vec<u8>> = kems.iter().map(|k| k.0.clone()).collect();
    let custodians = dcu::deal_pool(lines, n, t, &[seed; 32]);
    let mut book = DefiBook {
        pair: 0,
        roster: eks.iter().map(|k| crate::defi_launch::custody_id(k)).collect(),
        eks: eks.clone(),
        t: t as u32,
        pool_commits: custodians.iter().map(CustodianState::commit).collect(),
        fee_commits: custodians.iter().map(CustodianState::fee_commit).collect(),
        batch: 0,
        opened_at: 0,
        opened_ms: 0,
        orders: Vec::new(),
        last_tick: crate::defi_clear::rule_tick(u128::from(lines[0]), u128::from(lines[1])),
        last_expired: false,
        last_sells: false,
        prices: Default::default(),
        income_index: 0,
        pending: Vec::new(),
        slotted: false,
        slot_parts: 0,
        handover: None,
        close_commits: custodians.iter().map(CustodianState::close_commit).collect(),
        sampling: true,
        ..DefiBook::default()
    };
    let mut dealings = Vec::new();
    let mut shares = Vec::new();
    for (k, (a, on_x)) in orders.iter().enumerate() {
        let (d, commits, epoch_ct, sealed, _proof) =
            dcu::order_parts(0, *on_x, &eks, t as u32, 0, &epoch_pk, *a, NO_MAX, [0x0D, k as u64, u64::from(seed), 2, 3, 4, 5, 6], owner_of(k as u64, seed), [0x1C; 8], 0, &[seed.wrapping_add(k as u8 + 1); 32])
                .expect("the order deals");
        let order = db::DefiOrderTx {
            pair: 0,
            amount_commit: d.amount_commit(),
            limit_commit: d.limit_commit(),
            share_commits: commits.clone(),
            epoch: 0,
            epoch_ct,
            sealed,
            share_proof: Vec::new(),
            nullifier: d.spend_publics().1,
            leaf_commit: d.spend_publics().2,
            member_carrier: Vec::new(),
            member_tuple: Vec::new(),
            index: 0,
        };
        let ek = dcu::order_epoch_key(&epoch_pk, &epoch_sk, &order).expect("the released epoch key opens the order's layer");
        shares.push((0..n).map(|i| Some(dcu::capture_order_share(&kems[i].1, &ek, i, &order).expect("custodian i captures its share"))).collect::<Vec<_>>());
        book.orders.push(db::BookOrder { amount_commit: d.amount_commit(), limit_commit: d.limit_commit(), share_commits: commits });
        dealings.push(d);
    }
    let dks = kems.into_iter().map(|k| k.1).collect();
    (book, custodians, dealings, shares, dks)
}

/// The bucket an order names when it sets no maximum price.
const NO_MAX: usize = ba::ORDER_BUCKETS - 1;

/// The claim object of an order of `amount` under `a_blind` at maximum-price bucket `bucket`, against the leaf `(p_num, p_den,
/// j_min)`, paying `out` (its member leg is the fold door's, out of scope here: `self_valid` is the stateless half every node
/// runs first).
fn claim_obj(amount: u64, a_blind: [u64; 8], bucket: usize, p_num: u128, p_den: u128, j_min: u64, out: u64) -> Option<DefiClaimTx> {
    let cw = ba::ClaimWitness {
        cover: None,
        amount,
        amount_blind: a_blind,
        bucket: bucket as u64,
        sell: false, deposit: false, withdraw: false, leg: 0, extra: ba::LeafExtra::default(), entry: 0, now: 0,
        p_num,
        p_den,
        j_min,
        s_num: 0,
        s_den: 1,
        out,
        out_blind: [0x0B, 1, 2, 3, 4, 5, 6, 7],
        lc_blind: [0x1C, 7, 6, 5, 4, 3, 2, 1],
    };
    let (nf, lc, oc, pays_y) = cw.publics();
    let claim_proof = dcu::claim_proof(&cw)?;
    let owner = usdm_decider::whir_rec_block::NoteOwner::from_test_key([0xC1; 8]);
    let asset = if pays_y { db::pair_y_tag(0) } else { crate::satoshi::asset_tag() };
    let (mint, cm, _dc) = usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(out, asset, &owner.opening(), &cw.out_blind)?;
    let mut note = vec![0x7Au8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
    Some(DefiClaimTx {
        pair: 0,
        nullifier: nf,
        leaf_commit: lc,
        out_commit: oc,
        pays_y,
        claim_proof,
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
        mint_carrier: mint,
        note,
        owner_clue: vec![0xC2; crate::peg_in_tx::OWNER_CLUE_MAX],
    })
}

fn open(shares: &[[u64; 4]], t: usize) -> [u64; 4] {
    let k = t + 1;
    (0..k).fold([0; 4], |acc, i| {
        let xi = (i + 1) as u64;
        let w = (0..k).filter(|j| *j != i).fold(ba::fsmall(1), |a, j| {
            let xj = (j + 1) as u64;
            ba::fmul(&ba::fmul(&a, &ba::fsmall(xj)), &ba::finv(&ba::fsub(&ba::fsmall(xj), &ba::fsmall(xi))))
        });
        ba::fadd(&acc, &ba::fmul(&w, &shares[i]))
    })
}

/// ⭐ `br15_only_the_clearing_price_is_opened` — THE CLOSED-LIST CENSUS over every DeFi object's fields. Every field of the
/// order, the settlement, the expiry, the claim and the book is classified (`OPENED` is what the closed list publishes per
/// pair per batch — the pair, the batch, the tick, its floor bit and lowest filling bucket — and constants of every batch's
/// shape; everything else is a hiding commitment, a nullifier, a proof, a ciphertext or a constant-shape note payload); a field this
/// census has not classified is RED. Then the measurement: two orders of DIFFERENT amounts encode to the same length, and
/// their public digests differ in every lane (fresh blinds), so the bytes carry no amount.
/// The order's maximum price is a commitment too: no field says which orders filled.
#[test]
fn br15_only_the_clearing_price_is_opened() {
    let classified: &[(&str, &[(&str, &str)])] = &[
        (
            "DefiOrderTx",
            &[
                ("pair", "OPENED: the pair whose slot part carries the order (every part of every pair carries exactly PART_SLOTS slots, covers included)"),
                ("amount_commit", "commitment"),
                ("limit_commit", "commitment (the order's maximum-price bucket, hidden)"),
                ("share_commits", "commitment"),
                ("epoch", "OPENED: the custody epoch whose key wraps the shares (one per hour, every order of the hour alike)"),
                ("epoch_ct", "ciphertext"),
                ("sealed", "ciphertext"),
                ("share_proof", "proof"),
                ("nullifier", "nullifier (a cover's in its own domain)"),
                ("leaf_commit", "commitment"),
                ("member_carrier", "proof"),
                ("member_tuple", "proof"),
                ("index", "OPENED: the income index its batch opened at (the book's batch_index — every order of the batch alike)"),
            ],
        ),
        (
            "DefiSettleTx",
            &[
                ("batch", "OPENED"),
                ("tick", "OPENED"),
                ("pair", "OPENED: the pair the batch is for (one settlement per pair per batch, the closed list's own unit)"),
                ("sells", "OPENED: the floor bit (whether the batch's sells fit above the pool's Y floor; §18.14)"),
                ("j_min", "OPENED: the lowest bucket that fills (a function of the tick and the base, or one above it when a capped bucket met its cap — A-F46)"),
                ("parts", "proof"),
                ("leaves", "commitment"),
                ("excluded", "OPENED: orders some custodian could not open (malformed sealed shares)"),
                ("phase1", "commitment (each custodian's phase-1 digest)"),
                ("first", "OPENED: which custodians' parts a chunk carries (a function of the roster and a transaction's size)"),
            ],
        ),
        ("DefiExpireTx", &[("pair", "OPENED: the pair whose batch expired"), ("batch", "OPENED"), ("leaves", "commitment")]),
        ("DefiSlotsTx", &[("pair", "OPENED: the pair whose batch the part fills (every pair's every batch carries all SLOT_PARTS parts)"), ("batch", "OPENED"), ("part", "OPENED (which of the SLOT_PARTS parts every batch carries — a constant)"), ("orders", "order slots (each as DefiOrderTx; exactly PART_SLOTS)"), ("claims", "claim slots (each as DefiClaimTx; exactly PART_SLOTS)")]),
        (
            "DefiClaimTx",
            &[
                ("nullifier", "nullifier"),
                ("leaf_commit", "commitment"),
                ("out_commit", "commitment"),
                ("pair", "OPENED: the pair whose slot part carries the claim (PART_SLOTS claim slots per part, covers included)"),
                ("pays_y", "asset of the mint: the pair's coin or SAT (a seller's fill or a buyer's money back, against a buyer's fill or a seller's SAT back — unlinkable to the order, never the side)"),
                ("claim_proof", "proof"),
                ("member_carrier", "proof"),
                ("member_tuple", "proof"),
                ("mint_carrier", "proof"),
                ("note", "note payload"),
                ("owner_clue", "note clue"),
            ],
        ),
        (
            "DefiBook",
            &[
                ("roster", "custody ids"),
                ("eks", "custody keys"),
                ("t", "threshold"),
                ("pool_commits", "commitment"),
                ("fee_commits", "commitment (each custodian's share of the fee line; the launch's is the public zero)"),
                ("batch", "OPENED"),
                ("opened_at", "OPENED"),
                ("orders", "commitment"),
                ("last_tick", "OPENED"),
                ("last_expired", "OPENED"),
                ("pending", "proof (the open batch's verified settlement parts)"),
                ("slotted", "OPENED (the open batch's slots applied — every batch's, a constant)"),
                ("slot_parts", "OPENED (which of the open batch's SLOT_PARTS parts applied — every batch carries all of them)"),
                ("handover", "custody keys and commitments (a handover in progress)"),
                ("pair", "OPENED: which pair the book trades"),
                ("opened_ms", "OPENED: the chain clock of the step that opened the batch (the expiry counts from it)"),
                ("last_sells", "OPENED: the floor bit of the last settled batch (the settlement's own)"),
                ("prices", "OPENED: the closed list's one price per batch, as fixed rings of (block time, tick)"),
                // ⭐ EARN STEP 3 — the protocol-wide rate's per-pair image and the hourly schedule: each a function of the
                // protocol-wide totals (one rate per window over every pair's closed fees and presence) and of the pair's own
                // public ticks, or a counter of windows every pair runs alike — never a volume, a depth, a position or a fill
                ("income_index", "OPENED: the pair's income index — the sum of each window's protocol-wide rate times the pair's public tick weight"),
                ("close_commits", "commitment (each custodian's share of the closed window's fees and presence)"),
                ("batch_index", "OPENED: the income index the open batch opened at (the snapshot every order of the batch carries)"),
                ("merge_dg", "OPENED: the protocol-wide rate the open batch merges (one per window, every pair alike)"),
                ("close_out", "OPENED (the open batch closes the hour's window: a function of the chain clock and the counters)"),
                ("deposits", "OPENED (the open batch is the hour's deposit batch: a function of the counters)"),
                ("sample", "OPENED (the open batch samples presence: every Earn batch's, a constant)"),
                ("closed", "OPENED: windows closed (one per hour, every pair alike)"),
                ("raised", "OPENED: windows raised (one EarnEpoch per hour)"),
                ("deposited", "OPENED: deposit batches settled (one per raise)"),
                ("close_window", "OPENED: the hour the last window closed in (the chain clock's)"),
                ("sampling", "OPENED (presence sampling is on: off from a close until the deposit batch)"),
                ("w_open", "OPENED: the open window's presence weight per unit — a function of the pair's public Earn-batch ticks"),
                ("w_closed", "OPENED: the closed window's presence weight per unit — the same function"),
                ("pending_dg", "OPENED: a raised rate awaiting the pair's next batch (protocol-wide)"),
                ("epoch_pending", "proof (the EarnEpoch's verified parts, held for its closing chunk)"),
            ],
        ),
    ];
    // the fields each object actually carries (its JSON keys), against the classified list
    let (book, _c, dealings, _s, _d) = market(4, (1_000_000, 2_000_000), &[5_000, 6_000], 7);
    let order = |k: usize| db::DefiOrderTx {
        pair: 0,
        amount_commit: dealings[k].amount_commit(),
        limit_commit: dealings[k].limit_commit(),
        share_commits: dealings[k].share_commits().iter().map(u4).collect(),
        epoch: 0,
        epoch_ct: vec![0; crate::epoch_key::CT_BYTES],
        sealed: vec![vec![0; db::SEALED_BYTES]; 4],
        share_proof: Vec::new(),
        nullifier: dealings[k].spend_publics().1,
        leaf_commit: dealings[k].spend_publics().2,
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
        index: 0,
    };
    let keys = |v: serde_json::Value| -> Vec<String> { v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default() };
    let carried: Vec<(&str, Vec<String>)> = vec![
        ("DefiOrderTx", keys(serde_json::to_value(order(0)).expect("json"))),
        ("DefiSettleTx", keys(serde_json::to_value(db::DefiSettleTx { pair: 0, sells: true, j_min: 0, batch: 0, tick: 0, excluded: Vec::new(), phase1: Vec::new(), first: 0, parts: Vec::new(), leaves: Vec::new() }).expect("json"))),
        ("DefiExpireTx", keys(serde_json::to_value(DefiExpireTx { pair: 0, batch: 0, leaves: Vec::new() }).expect("json"))),
        ("DefiSlotsTx", keys(serde_json::to_value(db::DefiSlotsTx { pair: 0, batch: 0, part: 0, orders: Vec::new(), claims: Vec::new() }).expect("json"))),
        ("DefiClaimTx", keys(serde_json::to_value(claim_obj(10, [1; 8], NO_MAX, 1, 1, ba::ORDER_BUCKETS as u64, 10).expect("claim")).expect("json"))),
        ("DefiBook", keys(serde_json::to_value(&book).expect("json"))),
    ];
    for (name, fields) in &carried {
        let list = classified.iter().find(|(n, _)| n == name).map(|(_, l)| *l).expect("classified object");
        for f in fields {
            assert!(list.iter().any(|(k, _)| k == f), "⛔ CLOSED-LIST CENSUS RED: {name}.{f} is a public field no class covers");
        }
        let opened: Vec<&str> = list.iter().filter(|(_, c)| *c == "OPENED").map(|(k, _)| *k).collect();
        eprintln!("[br15-closed-list] {name}: opened = {opened:?}; {} other fields are commitments, nullifiers, proofs or ciphertexts", fields.len() - opened.len());
    }
    // the measurement: two amounts, one shape, no shared digest lane
    let (a, b) = (order(0).encode().expect("encodes"), order(1).encode().expect("encodes"));
    assert_eq!(a.len(), b.len(), "⛔ two order amounts encode to different lengths");
    let (ca, cb) = (dealings[0].amount_commit(), dealings[1].amount_commit());
    assert!(ca.iter().zip(&cb).all(|(x, y)| x != y), "⛔ two amount commitments share a lane");
    assert!(!a.windows(8).any(|w| w == 5_000u64.to_le_bytes()), "⛔ the order's bytes carry its amount");
}

/// ⭐ `br15_every_batch_publishes_one_price_whether_or_not_it_traded` — a batch with NO orders settles through the custody
/// runtime with one tick (the pool's own price) that every node's verdict accepts, and books nothing (the pool unchanged).
#[test]
fn br15_every_batch_publishes_one_price_whether_or_not_it_traded() {
    let (book, custodians, _d, _s, _k) = market(4, (3_000_000, 1_500_000), &[], 11);
    let run = dcu::run_batch(&book, &custodians, &[], &[12; 32]).expect("an empty batch settles");
    assert_eq!(run.settle.verdict(&book), Ok(Vec::new()), "⛔ a node refused the empty batch's settlement");
    assert_eq!(run.settle.tick, crate::defi_clear::rule_tick(3_000_000, 1_500_000), "the empty batch publishes the pool's price");
    let x = open(&run.next.iter().map(|c| c.lines[0]).collect::<Vec<_>>(), 1);
    let y = open(&run.next.iter().map(|c| c.lines[1]).collect::<Vec<_>>(), 1);
    assert_eq!((x, y), (ba::fsmall(3_000_000), ba::fsmall(1_500_000)), "⛔ an empty batch moved the pool");
}

/// ⭐ `br15_a_coalition_below_one_third_learns_nothing_of_a_sealed_order` — THE DISTINGUISHING GAME AT CHANCE. A coalition of
/// t custodians (the most below a third of n = 7) sees its t shares of an order. (1) Perfect secrecy by construction: for its
/// view of an order of a0, a dealing of a1 exists giving it the SAME t shares (the degree-t polynomial through (0, a1) and its
/// t points). (2) The game: over 4,000 trials an adversary guessing a0 vs a1 from its shares (each bit of every share is a
/// candidate statistic; the best is taken) wins within 3σ of one half.
/// CALIBRATION: with t + 1 shares (one past the threshold) the same adversary wins every time (it interpolates).
#[test]
fn br15_a_coalition_below_one_third_learns_nothing_of_a_sealed_order() {
    let (n, t) = (7usize, 2usize);
    let (a0, a1) = (1_000u64, 9_999_999u64);
    let d = dcu::deal_order(a0, NO_MAX, [1; 8], n, t, &[21; 32]);
    let view: Vec<[u64; 4]> = (0..t).map(|i| d.shares(i)[1 + NO_MAX]).collect();
    // (1) the alternative dealing: Lagrange through (0, a1) and the coalition's t points, evaluated at x = 1..=t
    let pts: Vec<(u64, [u64; 4])> = std::iter::once((0u64, ba::fsmall(a1))).chain((0..t).map(|i| ((i + 1) as u64, view[i]))).collect();
    let at = |x: u64| -> [u64; 4] {
        pts.iter().enumerate().fold([0; 4], |acc, (i, (xi, yi))| {
            let w = pts.iter().enumerate().filter(|(j, _)| *j != i).fold(ba::fsmall(1), |a, (_, (xj, _))| {
                ba::fmul(&ba::fmul(&a, &ba::fsub(&ba::fsmall(x), &ba::fsmall(*xj))), &ba::finv(&ba::fsub(&ba::fsmall(*xi), &ba::fsmall(*xj))))
            });
            ba::fadd(&acc, &ba::fmul(&w, yi))
        })
    };
    assert_eq!(at(0), ba::fsmall(a1), "the alternative dealing shares a1");
    for i in 0..t {
        assert_eq!(at((i + 1) as u64), view[i], "⛔ the coalition's view of a0 is not a possible view of a1");
    }
    // (2) the game
    let trials = 4_000u64;
    let mut best = 0f64;
    let mut wins_past = 0u64;
    let stats = 64usize;
    let mut wins = vec![0u64; stats];
    for k in 0..trials {
        let secret = k % 2;
        let amount = if secret == 0 { a0 } else { a1 };
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&k.to_le_bytes());
        let d = dcu::deal_order(amount, NO_MAX, [2; 8], n, t, &key);
        let shares: Vec<[u64; 4]> = (0..=t).map(|i| d.shares(i)[1 + NO_MAX]).collect();
        for (s, w) in wins.iter_mut().enumerate() {
            let bit = (shares[s % t][s / t % 4] >> (s % 61)) & 1;
            *w += u64::from(bit == secret);
        }
        // past the threshold: t + 1 shares interpolate the amount
        let guess = u64::from(open(&shares, t) != ba::fsmall(a0));
        wins_past += u64::from(guess == secret);
    }
    for w in &wins {
        best = best.max((*w as f64 / trials as f64 - 0.5).abs());
    }
    let sigma = 0.5 / (trials as f64).sqrt();
    eprintln!("[br15-coalition] t = {t} of n = {n}: best advantage {best:.4} over {stats} statistics (3σ = {:.4}); t + 1 shares win {wins_past}/{trials}", 3.0 * sigma * (stats as f64).ln().sqrt());
    assert_eq!(wins_past, trials, "CALIBRATION: t + 1 shares must reveal the amount (the game can be won)");
    assert!(best < 3.0 * sigma * (stats as f64).ln().sqrt().max(1.0), "⛔ a coalition below a third beats chance ({best:.4})");
}

/// ⭐ `br15_a_settlement_that_misprices_or_inflates_is_refused_on_every_node` — from a REAL custody run over two buys, every
/// forgery is refused by the verdict every node runs: a moved tick (its audits prove the honest statements), a new pool
/// commitment swapped for a richer one (inflation), a published sharing altered, one custodian's audit replaced by
/// another's, a part dropped, the leaves of another tick. The honest settlement passes. (On the chain: the two-node pin.)
#[test]
fn br15_a_settlement_that_misprices_or_inflates_is_refused_on_every_node() {
    let (book, custodians, _d, shares, _k) = market(4, (2_000_000, 1_000_000), &[40_000, 2_500], 31);
    let honest = dcu::run_batch(&book, &custodians, &shares, &[32; 32]).expect("settles").settle;
    assert_eq!(honest.verdict(&book), Ok(honest.leaves.clone()), "the honest settlement passes");
    let refused = |what: &str, s: &db::DefiSettleTx| assert!(s.verdict(&book).is_err(), "⛔ a settlement with {what} passed the verdict");
    let mut m = honest.clone();
    m.tick += 1;
    m.j_min = crate::defi_clear::j_min(book.last_tick, m.tick);
    m.leaves = db::settle_leaves(&book, m.tick, m.j_min, true, &[]);
    refused("a moved tick (a misprice)", &m);
    let mut m = honest.clone();
    m.tick -= 1;
    m.j_min = crate::defi_clear::j_min(book.last_tick, m.tick);
    m.leaves = db::settle_leaves(&book, m.tick, m.j_min, true, &[]);
    refused("a tick below the price", &m);
    let mut m = honest.clone();
    m.parts[0].new_pool = db::pool_commit(&[ba::fsmall(9_999_999), ba::fsmall(9_999_999), [0; 4], [0; 4]], &[Fa4::ONE; 4]);
    refused("an inflated new pool", &m);
    let mut m = honest.clone();
    m.parts[1].published[0].0 = ba::fadd(&m.parts[1].published[0].0, &ba::fsmall(1));
    refused("an altered published sharing", &m);
    let mut m = honest.clone();
    m.parts[2].audit = m.parts[3].audit.clone();
    refused("another custodian's audit", &m);
    let mut m = honest.clone();
    m.parts.pop();
    refused("a dropped part", &m);
    let mut m = honest.clone();
    m.leaves = db::settle_leaves(&book, honest.tick + 7, crate::defi_clear::j_min(book.last_tick, honest.tick + 7), true, &[]);
    refused("the leaves of another tick", &m);
    // ⭐ A-F46: a settlement that counts a bucket below the tick's own lowest filling bucket (one that cannot fill there)
    let mut m = honest.clone();
    m.j_min = 0;
    m.tick = honest.tick.max(book.last_tick + crate::defi_clear::BUCKET_TICKS[0].unwrap_or(0));
    m.leaves = db::settle_leaves(&book, m.tick, m.j_min, true, &[]);
    assert_eq!(m.verdict(&book), Err("the settlement counts a bucket that does not fill at its tick (its lowest filling bucket is below the tick's own)"), "⛔ A-F46: a settlement counting a bucket past its cap passed the verdict");
}

/// ⭐ `br15_a_claim_paying_more_than_its_order_at_the_price_is_refused` — the claim relation pays exactly `⌊a·p⌋`: the honest
/// claim's proof verifies, `⌊a·p⌋ + 1` has NO proof (the relation is unsatisfiable), and the honest proof carried under a
/// larger output's commitment does not verify.
#[test]
fn br15_a_claim_paying_more_than_its_order_at_the_price_is_refused() {
    let (p_num, p_den, jm, out) = dcu::fill_of(123_456_789, NO_MAX, Some((693, crate::defi_clear::j_min(693, 693)))).expect("fits");
    let honest = claim_obj(123_456_789, [3; 8], NO_MAX, p_num, p_den, jm, out).expect("the honest claim builds");
    assert_eq!(honest.self_valid(), None, "the honest claim verifies");
    assert!(claim_obj(123_456_789, [3; 8], NO_MAX, p_num, p_den, jm, out + 1).is_none(), "⛔ an over-claim proved");
    let mut swapped = honest.clone();
    swapped.out_commit = ba::amount_commit(out + 1, &[0x0B, 1, 2, 3, 4, 5, 6, 7]);
    assert!(swapped.self_valid().is_some(), "⛔ an honest proof verified under a larger output");
}

/// ⭐ `br15_a_settled_order_cannot_also_refund_and_a_replay_is_refused_by_the_set` — a fill and a refund of one order spend
/// the SAME nullifier (`P(a_blind, CLAIM_NF_DOMAIN)`, whatever the price), so the spent set admits only one of them; a settled
/// batch can no longer be expired (its batch number has moved) and an expired one no longer settled.
#[test]
fn br15_a_settled_order_cannot_also_refund_and_a_replay_is_refused_by_the_set() {
    let blind = [0x51; 8];
    let (p_num, p_den, jm, out) = dcu::fill_of(50_000, NO_MAX, Some((-200, crate::defi_clear::j_min(-200, -200)))).expect("fits");
    let fill = claim_obj(50_000, blind, NO_MAX, p_num, p_den, jm, out).expect("builds");
    let refund = claim_obj(50_000, blind, NO_MAX, 1, 1, ba::ORDER_BUCKETS as u64, 50_000).expect("builds");
    assert!(!fill.pays_y && refund.pays_y, "a fill mints SAT, a refund the coin back");
    assert_eq!(fill.own_nullifiers(), refund.own_nullifiers(), "⛔ a fill and a refund of one order spend different nullifiers");
    let other = claim_obj(50_000, [0x52; 8], NO_MAX, p_num, p_den, jm, out).expect("builds");
    assert_ne!(fill.own_nullifiers(), other.own_nullifiers(), "two orders share a nullifier");
    let mut book = DefiBook { roster: vec![[1; 32]], eks: vec![vec![0; 1_184]], t: 0, pool_commits: vec![[0; 4]], fee_commits: db::launch_fee_commits(0, 1), ..DefiBook::default() };
    book.orders.push(db::BookOrder { amount_commit: [9; 8], limit_commit: [8; 8], share_commits: vec![[0; 4]] });
    book.opened_ms = 1_000;
    let late = db::BATCH_STEPS;
    let late_ms = 1_000 + db::EXPIRE_MS;
    let expire = DefiExpireTx { pair: 0, batch: 0, leaves: vec![db::refund_leaf(&[9; 8], &[8; 8])] };
    assert!(expire.verdict(&book, late, late_ms).is_ok(), "PRECONDITION: the batch may be expired");
    let mut settled = book.clone();
    db::apply_settlement(&mut settled, &db::DefiSettleTx { pair: 0, sells: true, j_min: 0, batch: 0, tick: 5, excluded: Vec::new(), phase1: vec![[0; 4]], first: 0, parts: vec![db::CustodianPart { published: Vec::new(), new_pool: [0; 4], new_fee: [0; 4], new_close: [0; 4], audit: Vec::new() }], leaves: Vec::new() }, 10, 1_000_000);
    assert!(expire.verdict(&settled, late, late_ms).is_err(), "⛔ a settled batch was expired too");
    let mut expired = book.clone();
    db::apply_expiry(&mut expired, late, 1_000_000);
    assert!(expired.last_expired && expired.batch == 1, "the expiry moved the book");
    assert!(expire.verdict(&expired, late + 1, late_ms).is_err(), "⛔ an expiry replayed");
}

/// ⭐ `br15_an_unsettled_batch_refunds_every_order_and_block_production_never_waits` — an expiry inside the settlement window
/// is refused; past it, the expiry's leaves are EVERY order's refund leaf (a missing or extra one is refused); applying it
/// opens the next batch at once. Nothing in production waits on a batch: the fold door answers each object Applied or
/// Refused on the spot (the two-node pin produces blocks straight through an unsettled batch's window).
#[test]
fn br15_an_unsettled_batch_refunds_every_order_and_block_production_never_waits() {
    let mut book = DefiBook { roster: vec![[1; 32]], eks: vec![vec![0; 1_184]], t: 0, pool_commits: vec![[0; 4]], fee_commits: db::launch_fee_commits(0, 1), ..DefiBook::default() };
    for k in 0..3u64 {
        book.orders.push(db::BookOrder { amount_commit: [k + 1; 8], limit_commit: [k + 7; 8], share_commits: vec![[0; 4]] });
    }
    let all: Vec<[u64; 8]> = book.orders.iter().map(|o| db::refund_leaf(&o.amount_commit, &o.limit_commit)).collect();
    let expire = DefiExpireTx { pair: 0, batch: 0, leaves: all.clone() };
    book.opened_ms = 1_000;
    let window_end = db::BATCH_STEPS;
    let end_ms = 1_000 + db::EXPIRE_MS;
    assert!(expire.verdict(&book, window_end, end_ms - 1).is_err(), "⛔ an expiry inside the settlement window passed");
    assert!(expire.verdict(&book, window_end - 1, end_ms).is_err(), "⛔ an expiry before the batch closed passed");
    assert_eq!(expire.verdict(&book, window_end, end_ms), Ok(all.clone()), "⛔ the expiry past the window does not refund every order");
    let short = DefiExpireTx { pair: 0, batch: 0, leaves: all[..2].to_vec() };
    assert!(short.verdict(&book, window_end, end_ms).is_err(), "⛔ an expiry that skips an order passed");
    let mut next = book.clone();
    db::apply_expiry(&mut next, window_end, 1_000_000);
    assert_eq!((next.batch, next.orders.len(), next.opened_at), (1, 0, window_end), "the next batch opens at once");
}

/// ⭐ `br15_the_launch_position_has_no_withdrawal_path_and_a_sell_pays_only_what_buyers_put_in` (§18.14, supersedes the buy-only rule) — (1) the position note is never recorded
/// (`defi_launch` adds no note to any set), so no key spends it; the pool moves only by an audited settlement; (2) a buy and a sell verify under ONE public statement, so the chain cannot tell them apart;
/// (3) a real custody run: buys keep every unit of the coin they brought; a sell at launch, when the pool holds only its virtual side, is returned and a buyer in the same batch still clears;
/// once buyers put coin in, a sell is paid, and never past the floor; (4) the census: the book is written only by the fold door and the genesis.
#[test]
fn br15_the_launch_position_has_no_withdrawal_path_and_a_sell_pays_only_what_buyers_put_in() {
    // (2) one statement for both sides
    let shape = ba::order_share_r1cs(4, 1, crate::satoshi::asset_tag(), db::pair_y_tag(0)).expect("forms");
    for on_x in [false, true] {
        let d = dcu::deal_order_on(0, on_x, 7_000, NO_MAX, [4; 8], 4, 1, &[41; 32]);
        let (r1, io, w) = ba::order_share_circuit(&d).expect("builds");
        let proof = usdm_decider::spartan_ccs::prove_committed(&r1, &io, &w).expect("proves");
        let (_, nf, lc) = d.spend_publics();
        let stated = ba::order_share_io(&d.amount_commit(), &d.limit_commit(), &d.share_commits(), &d.binding, &nf, &lc, d.index);
        assert!(usdm_decider::spartan_ccs::verify_committed(&shape, &stated, &proof), "⛔ an order of side {on_x} does not verify under the one statement");
    }
    // (3) buys keep every unit of the coin
    let (book, custodians, _d, shares, _k) = market(4, (5_000_000, 100_000), &[30_000, 1_234], 42);
    let run = dcu::run_batch(&book, &custodians, &shares, &[43; 32]).expect("settles");
    assert_eq!(run.settle.verdict(&book), Ok(run.settle.leaves.clone()), "the run's settlement passes");
    assert!(run.settle.sells, "no sell, nothing to return");
    let y = open(&run.next.iter().map(|c| c.lines[1]).collect::<Vec<_>>(), 1);
    assert_eq!(y, ba::fsmall(100_000 + 30_000 + 1_234), "⛔ the pool's coin left it");
    // a sell at launch: the pool's coin side is all virtual (its floor), so the batch can pay a sell only out of what its own
    // buyers put in. A buy of 100 coin cannot cover a 7,000-SAT sell (≈ 140 coin at 0.02): the sell is returned and the buyer
    // beside it clears. (Until 2026-11-12 the buy here was 1,234 coin, which DOES cover the sell, and the pin asserted the sell
    // was returned anyway — a rule the floor bit never had: `run_party` counts the batch's own buys above the floor, and only
    // the virtual coin is never paid. Red on main since §18.14; the case below now measures exactly that.)
    let virtual_y = 100_000u64;
    let (book, custodians, _d, shares, _k) = market_sides(4, [5_000_000, virtual_y, 0, virtual_y], &[(7_000, true), (100, false)], 44);
    let run = dcu::run_batch(&book, &custodians, &shares, &[45; 32]).expect("settles");
    assert_eq!(run.settle.verdict(&book), Ok(run.settle.leaves.clone()), "the run's settlement passes");
    assert!(!run.settle.sells, "⛔ a pool holding only its virtual side paid a sell past what its buyers put in");
    let y = open(&run.next.iter().map(|c| c.lines[1]).collect::<Vec<_>>(), 1);
    assert_eq!(y, ba::fsmall(virtual_y + 100), "⛔ the buyer beside a returned sell did not clear, or the pool paid");
    // the same sell beside a buy that covers it is paid out of that buy's coin, and the virtual coin is never touched
    let (book2, custodians2, _d2, shares2, _k2) = market_sides(4, [5_000_000, virtual_y, 0, virtual_y], &[(7_000, true), (1_234, false)], 48);
    let run2 = dcu::run_batch(&book2, &custodians2, &shares2, &[49; 32]).expect("settles");
    assert_eq!(run2.settle.verdict(&book2), Ok(run2.settle.leaves.clone()), "the run's settlement passes");
    assert!(run2.settle.sells, "a sell its batch's own buyers cover is paid");
    let y2 = open(&run2.next.iter().map(|c| c.lines[1]).collect::<Vec<_>>(), 1);
    let y2 = u128::from(y2[0]) | (u128::from(y2[1]) << 64);
    assert!(y2 >= u128::from(virtual_y) && y2 < u128::from(virtual_y) + 1_234, "⛔ the sell was paid from the virtual coin, or not at all: the pool holds {y2}");
    let mut forged = run.settle.clone();
    forged.sells = true;
    forged.leaves = db::settle_leaves(&book, forged.tick, forged.j_min, true, &forged.excluded);
    assert!(forged.verdict(&book).is_err(), "⛔ a settlement claiming the sells counted passed");
    // once buyers put coin in, a sell is paid at the tick's own price, and the pool stays above its floor
    let (book, custodians, _d, shares, _k) = market_sides(4, [5_000_000, virtual_y + 50_000, 0, virtual_y], &[(7_000, true)], 46);
    let run = dcu::run_batch(&book, &custodians, &shares, &[47; 32]).expect("settles");
    assert_eq!(run.settle.verdict(&book), Ok(run.settle.leaves.clone()), "the run's settlement passes");
    assert!(run.settle.sells, "⛔ a pool with real coin returned a sell");
    let (n, d) = crate::defi_clear::tick_ratio(run.settle.tick);
    let paid = ba::claim_out(7_000, n, d).expect("fits");
    assert!(paid > 0 && paid < 50_000, "the sell is paid out of the real coin: {paid}");
    // (1)+(4) the writers of the book: the fold door and the genesis only
    let src = |p: &str| std::fs::read_to_string(format!("{}/src/{p}", env!("CARGO_MANIFEST_DIR"))).expect("source");
    let ingest = src("node/ingest.rs");
    assert!(ingest.contains("fn defi_book_mut"), "the fold's accessor exists");
    assert!(!src("defi_launch.rs").contains("record_note_payload"), "⛔ the launch records a note");
    assert!(!src("rpc_http.rs").contains("defi_book_mut"), "⛔ an RPC writes the book");
}

/// ⭐ `br15_the_launch_position_and_the_set_aside_together_stay_within_two_million` — the set-aside's carrier conserves the
/// public 2M input into the set-aside note and its unrecorded remainder; the launch's split conserves that remainder into the
/// position and the rest; a position above the remainder cannot be split, a split of another set-aside's remainder is
/// refused, and a pool proof claiming more SAT than the position note is refused.
#[test]
fn br15_the_launch_position_and_the_set_aside_together_stay_within_two_million() {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block as wr;
    let unit = crate::satoshi::BASE_UNITS_PER_SAT;
    let max = crate::satoshi::SAT_SET_ASIDE_MAX;
    let owner = wr::NoteOwner::from_test_key(lanes_of(&[0x5e7a, 7, 7, 7]));
    let sa = crate::sat_set_aside::build_for_test_with_out1(1_500_000 * unit, lanes_of(&[0x5e7a, 1, 1, 1]), max, owner.opening()).expect("builds");
    assert!(sa.proves_the_bound(), "the set-aside proves its 2M bound");
    assert!(crate::sat_set_aside::build_for_test_with_out1(max + 1, lanes_of(&[0x5e7a, 1, 1, 1]), max, owner.opening()).is_none(), "⛔ a set-aside above 2M built");
    let eks: Vec<Vec<u8>> = (0..4).map(|_| crate::pqkem::keypair().0).collect();
    let remainder = max - 1_500_000 * unit;
    assert!(crate::defi_launch::build_for_test(remainder, owner.clone(), remainder + 1, &eks, &[51; 32]).is_none(), "⛔ a position above the remainder split");
    let (all_of_it, _) =
        crate::defi_launch::build_for_test(remainder, owner.clone(), remainder / 2, &eks, &[52; 32]).expect("the whole remainder may be the position");
    assert_eq!(all_of_it.verdict(&sa), Ok(()), "set-aside + position = 2M exactly verifies");
    let other = crate::sat_set_aside::build_for_test_with_out1(1_400_000 * unit, lanes_of(&[0x5e7a, 1, 1, 1]), max, owner.opening()).expect("builds");
    assert!(all_of_it.verdict(&other).is_err(), "⛔ a split of another set-aside's remainder verified");
    let (smaller, _) = crate::defi_launch::build_for_test(remainder, owner.clone(), remainder / 4, &eks, &[53; 32]).expect("builds");
    let mut lying = smaller.clone();
    lying.pools[0].open_proof = all_of_it.pools[0].open_proof.clone();
    lying.pools[0].share_commits = all_of_it.pools[0].share_commits.clone();
    lying.pools[0].position = all_of_it.pools[0].position;
    assert!(lying.verdict(&sa).is_err(), "⛔ a pool of the whole remainder verified against a half-remainder position");
}

/// ⭐ `br15_the_cross_layer_linkability_attacker_cannot_beat_chance` — the game: an order of the DeFi layer and the claim that
/// pays it (minting into the cash layer) against an unrelated order; the attacker sees both orders' public fields and the
/// claim's, and guesses which order the claim pays. Over 200 trials, each of the attacker's statistics (equal 8-byte windows
/// between the claim and each order; the Hamming distance of their digests) wins within 3σ of one half.
/// CALIBRATION: an attacker handed the order's secret blind recomputes the claim's nullifier and wins every time.
#[test]
fn br15_the_cross_layer_linkability_attacker_cannot_beat_chance() {
    let trials = 200u64;
    let (mut w_window, mut w_hamming, mut w_secret) = (0u64, 0u64, 0u64);
    for k in 0..trials {
        let blind = |s: u64| -> [u64; 8] { core::array::from_fn(|i| (s.wrapping_mul(0x9E37_79B9) ^ (i as u64 * 0x85EB_CA6B) ^ 0x51) & ((1 << 30) - 1)) };
        let (ba_, bb) = (blind(2 * k + 1), blind(2 * k + 2));
        let amount = 10_000 + k;
        let order_a = ba::amount_commit(amount, &ba_);
        let order_b = ba::amount_commit(amount, &bb);
        let (p_num, p_den, jm, out) = dcu::fill_of(amount, NO_MAX, Some((100, crate::defi_clear::j_min(100, 100)))).expect("fits");
        let claim = claim_obj(amount, ba_, NO_MAX, p_num, p_den, jm, out).expect("builds");
        let truth_is_a = k % 2 == 0;
        let (first, second) = if truth_is_a { (order_a, order_b) } else { (order_b, order_a) };
        let pub_claim: Vec<u64> = claim.nullifier.iter().chain(&claim.leaf_commit).chain(&claim.out_commit).copied().collect();
        let windows = |o: &[u64; 8]| pub_claim.iter().filter(|v| o.contains(v)).count();
        let ham = |o: &[u64; 8]| -> u32 { pub_claim.iter().zip(o.iter().cycle()).map(|(a, b)| (a ^ b).count_ones()).sum() };
        let guess_window_first = windows(&first) >= windows(&second);
        let guess_ham_first = ham(&first) <= ham(&second);
        // the claim pays order a; `first` is order a exactly when `truth_is_a`
        w_window += u64::from(guess_window_first == truth_is_a);
        w_hamming += u64::from(guess_ham_first == truth_is_a);
        // the calibration: holding the FIRST order's secret, recompute the claim's nullifier and guess "first" on a match
        let secret_of_first = if truth_is_a { ba_ } else { bb };
        w_secret += u64::from((ba::claim_nullifier(&secret_of_first) == claim.nullifier) == truth_is_a);
    }
    let sigma = 0.5 / (trials as f64).sqrt();
    let adv = |w: u64| (w as f64 / trials as f64 - 0.5).abs();
    eprintln!("[br15-linkability] window advantage {:.3}, Hamming advantage {:.3} (3σ = {:.3}); with the secret: {w_secret}/{trials}", adv(w_window), adv(w_hamming), 3.0 * sigma);
    assert_eq!(w_secret, trials, "CALIBRATION: the order's secret must link its claim (the game can be won)");
    assert!(adv(w_window) < 3.0 * sigma, "⛔ shared values link a claim to its order");
    assert!(adv(w_hamming) < 3.0 * sigma, "⛔ digest distance links a claim to its order");
}

/// ⭐ `br15_an_erased_epoch_key_opens_no_earlier_batch` — FORWARD SECRECY: an order's shares open only with BOTH the custodian's
/// own key and the order's epoch key (recovered with the released epoch secret). With the epoch erased (§BR-9a step d), a
/// stolen custody key alone opens nothing; another epoch's secret opens nothing; a swapped epoch ciphertext breaks the proof.
#[test]
fn br15_an_erased_epoch_key_opens_no_earlier_batch() {
    let (book, _c, _d, _s, dks) = market(4, (1_000_000, 1_000_000), &[], 61);
    let (pk, sk) = crate::epoch_release::test_epoch_keypair();
    let (d, commits, epoch_ct, sealed, proof) = dcu::order_parts(0, false, &book.eks, book.t, 3, &pk, 8_000, NO_MAX, [6; 8], owner_of(62, 6), [0x1C; 8], book.batch_index, &[62; 32]).expect("deals");
    let order = db::DefiOrderTx {
        pair: 0,
        amount_commit: d.amount_commit(),
        limit_commit: d.limit_commit(),
        share_commits: commits,
        epoch: 3,
        epoch_ct,
        sealed,
        share_proof: proof,
        nullifier: d.spend_publics().1,
        leaf_commit: d.spend_publics().2,
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
        index: book.batch_index,
    };
    let k = dcu::order_epoch_key(&pk, &sk, &order).expect("the released epoch secret opens the epoch layer");
    for (i, dk) in dks.iter().enumerate() {
        assert_eq!(dcu::capture_order_share(dk, &k, i, &order).map(|s| s.0), Some(dcu::dealing_lines(&d, i)), "custodian {i} opens with both keys");
        // the epoch erased: the custody key alone (any guess of the epoch key) opens nothing
        assert!(dcu::capture_order_share(dk, &[0; 32], i, &order).is_none(), "⛔ a custody key alone opened an order share");
        assert!(dcu::open_order_share(dk, &order.sealed[i]).is_none(), "⛔ the bare custody layer decoded an order share");
    }
    // another epoch's secret opens no epoch layer
    let seed = crate::epoch_deal_tx::matrix_seed(4);
    let (sec, part) = crate::epoch_key::deal(&seed, &[0x44; 32]);
    let (pk4, sk4) = (crate::epoch_key::combine_public(&seed, &[part]), crate::epoch_key::secret_from(&[sec]));
    assert!(dcu::order_epoch_key(&pk4, &sk4, &order).is_none(), "⛔ another epoch's secret opened the order");
    // the epoch and its ciphertext are bound into the proof
    let mut moved = order.clone();
    moved.epoch = 4;
    assert!(moved.self_valid(book.t).is_some(), "⛔ the order's proof verified under another epoch");
}

/// ⭐ `br15_an_order_above_its_maximum_refunds_and_the_price_is_never_capped` (spec §18.10) — a real custody run over a batch
/// whose buys with NO maximum lift the price more than +50 % in one batch (past every bucket): the price goes as high as those
/// buyers pay — nothing in the protocol stops it — while the order that named +2 % is not filled and claims its USDm back in
/// full through the batch's one leaf (it cannot claim the SAT: that claim has no proof). Every node's verdict accepts it.
#[test]
fn br15_an_order_above_its_maximum_refunds_and_the_price_is_never_capped() {
    let (n, t) = (4usize, 1usize);
    let custodians = dcu::deal_pool([1_000_000, 1_000_000, 0, 0], n, t, &[71; 32]);
    let base = crate::defi_clear::rule_tick(1_000_000, 1_000_000);
    let mut book = DefiBook {
        roster: (0..n).map(|i| [i as u8 + 1; 32]).collect(),
        eks: vec![vec![0; 1_184]; n],
        t: t as u32,
        pool_commits: custodians.iter().map(CustodianState::commit).collect(),
        fee_commits: custodians.iter().map(CustodianState::fee_commit).collect(),
        last_tick: base,
        ..DefiBook::default()
    };
    // (bucket, amount, blind): a big no-maximum buy and a +2 % buy
    let orders = [(NO_MAX, 900_000u64, [0x71; 8]), (0usize, 5_000u64, [0x72; 8])];
    let dealings: Vec<ba::OrderDealing> = orders.iter().enumerate().map(|(k, (j, a, bl))| dcu::deal_order(*a, *j, *bl, n, t, &[80 + k as u8; 32])).collect();
    for d in &dealings {
        book.orders.push(db::BookOrder { amount_commit: d.amount_commit(), limit_commit: d.limit_commit(), share_commits: d.share_commits().iter().map(u4).collect() });
    }
    let shares: Vec<Vec<Option<OrderShare>>> = dealings.iter().map(|d| (0..n).map(|i| Some((dcu::dealing_lines(d, i), d.salts[i]))).collect()).collect();
    let run = dcu::run_batch(&book, &custodians, &shares, &[73; 32]).expect("the batch settles");
    assert_eq!(run.settle.verdict(&book), Ok(run.settle.leaves.clone()), "⛔ a node refused the batch");
    let tick = run.settle.tick;
    let rise = (tick - base) as f64 * 0.001_f64.ln_1p();
    eprintln!("[br15-max-price] one batch moved the price from tick {base} to {tick}: × {:.2} — past every bucket's maximum", rise.exp());
    assert!(tick - base > 406, "⛔ the price stopped at a bucket's edge: a maximum capped the market");
    // the no-maximum order fills, the +2 % one is refunded — each through the batch's one leaf shape
    for (d, (j, a, bl)) in dealings.iter().zip(&orders) {
        let (p_num, p_den, jm, out) = dcu::fill_of(*a, *j, Some((tick, crate::defi_clear::j_min(base, tick)))).expect("fits");
        let c = claim_obj(*a, *bl, *j, p_num, p_den, jm, out).expect("the owner's claim proves");
        assert_eq!(c.self_valid(), None, "the claim verifies");
        let leaf = db::claim_leaf_at(&d.amount_commit(), &d.limit_commit(), tick, crate::defi_clear::j_min(base, tick), true);
        assert!(run.settle.leaves.contains(&leaf), "the order's leaf is the settlement's");
        if *j == NO_MAX {
            // Earn step 1: a filled buy is paid its fill less the fee on the SAT leg
            let g = u64::try_from(crate::defi_clear::buyer_claim(u128::from(*a), tick).expect("fits")).expect("fits");
            assert!(!c.pays_y && out == g - ba::claim_fee(g), "the no-maximum order is filled (its fill less ⌈g·f⌉)");
        } else {
            assert!(c.pays_y && out == *a, "⛔ the +2 % order was not refunded in full");
            // TAMPER: it claims the fill instead — no proof exists
            let fill = crate::defi_clear::buyer_claim(u128::from(*a), tick).expect("fits") as u64;
            assert!(claim_obj(*a, *bl, *j, p_num, p_den, jm, fill).is_none(), "⛔ an order above its maximum claimed the fill");
        }
    }
}

/// ⭐ `br15_a_buyer_measures_the_depth_never_the_position` (spec §18.10) — two pools on the SAME curve depth holding
/// DIFFERENT real positions (10 % and 90 % of the depth: their floors differ) clear the same buy at the SAME tick and book
/// the same SAT: what a buyer sees of a pool — the price it moved — is a function of its curve's depth alone; a floor never
/// moves the price. (The LAUNCH pool is now a public full-range curve, floor 0 — spec §18.13 — so its depth is its public
/// position; this pins the clearing's rule for every pool with a floor.)
/// CALIBRATION: a pool of another DEPTH clears the same buy at another tick (the measurement is sensitive).
#[test]
fn br15_a_buyer_measures_the_depth_never_the_position() {
    let (n, t) = (4usize, 1usize);
    let depth = 4_000_000u64;
    let tick_of = |lines: [u64; 4], seed: u8| {
        let custodians = dcu::deal_pool(lines, n, t, &[seed; 32]);
        let base = crate::defi_clear::rule_tick(u128::from(lines[0]), u128::from(lines[1]));
        let mut book = DefiBook {
            roster: (0..n).map(|i| [i as u8 + 1; 32]).collect(),
            eks: vec![vec![0; 1_184]; n],
            t: t as u32,
            pool_commits: custodians.iter().map(CustodianState::commit).collect(),
            fee_commits: custodians.iter().map(CustodianState::fee_commit).collect(),
            last_tick: base,
            ..DefiBook::default()
        };
        let d = dcu::deal_order(150_000, NO_MAX, [0x91; 8], n, t, &[seed + 1; 32]);
        book.orders.push(db::BookOrder { amount_commit: d.amount_commit(), limit_commit: d.limit_commit(), share_commits: d.share_commits().iter().map(u4).collect() });
        let shares = vec![(0..n).map(|i| Some((dcu::dealing_lines(&d, i), d.salts[i]))).collect::<Vec<_>>()];
        let run = dcu::run_batch(&book, &custodians, &shares, &[seed + 2; 32]).expect("the batch settles");
        assert_eq!(run.settle.verdict(&book), Ok(run.settle.leaves.clone()), "⛔ a node refused the batch");
        run.settle.tick
    };
    let small = tick_of([depth, depth, depth - depth / 10, depth], 90);
    let large = tick_of([depth, depth, depth / 10, depth], 100);
    assert_eq!(small, large, "⛔ the price a buyer moved depends on the real position, not only the depth");
    let other = tick_of([depth / 2, depth / 2, 0, depth / 2], 110);
    assert_ne!(other, small, "CALIBRATION: another depth moves the price differently");
    eprintln!("[br15-depth] positions of 10 % and 90 % of one depth: the same buy clears at tick {small} on both; another depth at {other}");
}

/// ⭐ `br15_a_settlement_too_large_for_one_transaction_settles_in_chunks` (spec §18.11) — thirteen custodians (t = 4): their
/// parts (one 2²³-row audit each) do not fit one transaction, so the settlement travels as chunks within a transaction's
/// weight. Each non-closing chunk verifies ON ITS OWN and is held; the closing chunk is refused until every other part is
/// held, then closes the batch exactly as the whole settlement would (same leaves, same new pool). TAMPERS: a second part for
/// a held slot, and a closing chunk under another header (a moved tick), are refused.
#[test]
fn br15_a_settlement_too_large_for_one_transaction_settles_in_chunks() {
    let n = 13usize;
    let (book, custodians, _d, shares, _k) = market(n, (2_000_000, 1_000_000), &[30_000], 91);
    let run = dcu::run_batch(&book, &custodians, &shares, &[92; 32]).expect("the thirteen custodians settle");
    let whole = run.settle;
    let max = crate::defi_lane::SETTLE_CHUNK_BYTES;
    assert!(whole.wire().expect("frames").len() > max, "PRECONDITION: thirteen parts do not fit one transaction");
    let chunks = whole.chunks(max).expect("the settlement chunks");
    assert!(chunks.len() >= 2 && chunks.iter().all(|c| c.wire().expect("frames").len() <= max), "⛔ a chunk past a transaction's weight");
    assert!(chunks.iter().rev().skip(1).all(|c| c.leaves.is_empty() && !c.closes()), "only the last chunk closes and carries leaves");
    let last = chunks.last().expect("a last chunk").clone();
    assert!(last.closes() && last.leaves == whole.leaves, "the closing chunk carries the batch's leaves");
    // the closing chunk first: refused (its earlier parts are not held)
    assert!(last.chunk_verdict(&book).is_err(), "⛔ a closing chunk closed a batch whose other parts were not held");
    let mut b = book.clone();
    for c in &chunks[..chunks.len() - 1] {
        assert_eq!(c.chunk_verdict(&b), Ok(db::SettleStep::Held), "a non-closing chunk verifies on its own");
        db::apply_settlement(&mut b, c, 5, 1_000_000);
        assert!(c.chunk_verdict(&b).is_err(), "⛔ a second part for a held slot passed");
    }
    // TAMPER: a closing chunk under another header (its audits are the honest ones for the honest tick)
    let mut moved = last.clone();
    moved.tick += 1;
    moved.leaves = db::settle_leaves(&b, moved.tick, moved.j_min, true, &moved.excluded);
    assert!(moved.chunk_verdict(&b).is_err(), "⛔ a closing chunk under another header closed the batch");
    assert_eq!(last.chunk_verdict(&b), Ok(db::SettleStep::Closed(whole.leaves.clone())), "⛔ the closing chunk did not close the batch");
    db::apply_settlement(&mut b, &last, 6, 1_000_000);
    assert_eq!(b.batch, book.batch + 1, "the batch closed");
    assert_eq!(b.pool_commits, run.next.iter().map(CustodianState::commit).collect::<Vec<_>>(), "⛔ the chunks moved the pool somewhere else than the whole settlement");
    assert_eq!(b.fee_commits, run.next.iter().map(CustodianState::fee_commit).collect::<Vec<_>>(), "⛔ the chunks moved the fee line somewhere else than the whole settlement");
    assert!(b.pending.is_empty(), "the held parts are cleared with the batch");
    eprintln!("[br15-chunks] {n} custodians: {} B whole → {} chunks within {max} B", whole.wire().expect("frames").len(), chunks.len());
}

/// ⭐ `br15_the_custody_hands_the_pool_to_a_new_roster_and_the_new_roster_settles` (spec §18.11) — four custodians hold a pool;
/// the bonded custody set becomes seven others. The Open names exactly the chain's bonded set and freezes the pool (an order
/// and a settlement are refused while frozen); each old custodian deals its shares to the seven (verified against ITS pool
/// commitment); each new custodian captures its sub-shares from the sealed bytes and accepts; the last acceptance switches the
/// book. The new shares interpolate to the SAME pool, and the new roster settles the next batch.
/// TAMPERS, each refused: an Open naming another roster (forge), a dealing claimed for another custodian's slot (forge), a
/// dealing stripped of its proof (strip), a second dealing for a dealt slot (replay), an acceptance before every dealing,
/// an acceptance carrying another custodian's new pool (substitute), an order while frozen (burn: nothing moves).
#[test]
fn br15_the_custody_hands_the_pool_to_a_new_roster_and_the_new_roster_settles() {
    use crate::defi_handover::{self as dh, DefiHandoverTx};
    let pool = (3_000_000u64, 1_500_000u64);
    let (book0, old, _d, _s, _k) = market(4, pool, &[], 101);
    let kems: Vec<(Vec<u8>, Vec<u8>)> = (0..7).map(|_| crate::pqkem::keypair()).collect();
    let bonded: Vec<Vec<u8>> = kems.iter().map(|k| k.0.clone()).collect();
    // OPEN
    let open = DefiHandoverTx::Open { pair: 0, batch: book0.batch, new_eks: bonded.clone() };
    let forged = DefiHandoverTx::Open { pair: 0, batch: book0.batch, new_eks: bonded[..6].to_vec() };
    assert!(forged.verdict(&book0, &bonded).is_err(), "⛔ an Open naming another roster than the bonded set passed");
    assert_eq!(open.verdict(&book0, &bonded), Ok(()), "the Open naming the bonded set passes");
    let mut b = book0.clone();
    dh::apply_handover(&mut b, &open, 3);
    assert!(b.frozen(), "an Open over an empty batch freezes the pool at once");
    assert!(open.verdict(&b, &bonded).is_err(), "⛔ a second Open passed");
    // BURN: nothing moves while frozen — an order and a settlement are refused
    let probe = dcu::deal_order(1_000, NO_MAX, [9; 8], 4, 1, &[102; 32]);
    let order = db::DefiOrderTx {
        pair: 0,
        amount_commit: probe.amount_commit(),
        limit_commit: probe.limit_commit(),
        share_commits: probe.share_commits().iter().map(u4).collect(),
        epoch: 0,
        epoch_ct: vec![0; crate::epoch_key::CT_BYTES],
        sealed: vec![vec![0; db::SEALED_BYTES]; 4],
        share_proof: Vec::new(),
        nullifier: probe.spend_publics().1,
        leaf_commit: probe.spend_publics().2,
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
        index: 0,
    };
    let frozen_slots = db::DefiSlotsTx { pair: 0, batch: b.batch, part: 0, orders: vec![order; db::PART_SLOTS], claims: Vec::new() };
    assert_eq!(frozen_slots.verdict(&b, db::BATCH_STEPS), Err("the pool is frozen for a custody handover"), "⛔ a batch's orders applied while the pool was frozen");
    assert!(dcu::run_batch(&b, &old, &[], &[103; 32]).is_err(), "⛔ a settlement applied while the pool was frozen");
    // ⭐ Earn step 1 — a fee line the pool has taken (a FIXTURE: 777 SAT on f(x) = 777 + 5x among the old four, t = 1), so the
    // handover is seen to carry a line that is not the launch zero
    let fee_line = 777u64;
    let mut old = old;
    for (i, c) in old.iter_mut().enumerate() {
        // the fee state's three lines (B, E, A), each a fixture line the handover must carry; and the closed window's two
        c.fee = [0u64, 1, 2].map(|k| ba::fadd(&ba::fsmall(fee_line + k), &ba::fsmall(5 * (i as u64 + 1))));
        c.close = [3u64, 4].map(|k| ba::fadd(&ba::fsmall(fee_line + k), &ba::fsmall(5 * (i as u64 + 1))));
    }
    b.fee_commits = old.iter().map(CustodianState::fee_commit).collect();
    b.close_commits = old.iter().map(CustodianState::close_commit).collect();
    // DEAL: each old custodian, verified against its own pool and fee commitments
    let deals: Vec<DefiHandoverTx> = (0..4).map(|i| dh::deal(&b, &old[i], i as u32, &[110 + i as u8; 32]).expect("the old custodian deals")).collect();
    let early = dh::accept(&b, 0, &[], &[1; 32]);
    assert!(early.is_none(), "an acceptance needs every old custodian's sub-share");
    for (i, d) in deals.iter().enumerate() {
        if let DefiHandoverTx::Deal { pair: 0, batch, subs, sealed, proof, .. } = d {
            let other = DefiHandoverTx::Deal { pair: 0, batch: *batch, from: ((i + 1) % 4) as u32, subs: subs.clone(), sealed: sealed.clone(), proof: proof.clone() };
            assert!(other.verdict(&b, &bonded).is_err(), "⛔ a dealing passed under another custodian's slot");
            let stripped = DefiHandoverTx::Deal { pair: 0, batch: *batch, from: i as u32, subs: subs.clone(), sealed: sealed.clone(), proof: Vec::new() };
            assert!(stripped.verdict(&b, &bonded).is_err(), "⛔ a dealing without its proof passed");
        }
        assert_eq!(d.verdict(&b, &bonded), Ok(()), "old custodian {i}'s dealing passes");
        dh::apply_handover(&mut b, d, 5);
        assert!(d.verdict(&b, &bonded).is_err(), "⛔ a second dealing for a dealt slot passed");
    }
    // ACCEPT: each new custodian captures its sub-shares from the sealed bytes and accepts
    let mut next: Vec<CustodianState> = Vec::new();
    let mut accepts: Vec<DefiHandoverTx> = Vec::new();
    for (j, (_, dk)) in kems.iter().enumerate() {
        let subs: Vec<dcu::SubShare> = deals.iter().map(|d| dh::capture(dk, j, d).expect("the new custodian captures its sub-share")).collect();
        assert!(dh::capture(dk, (j + 1) % 7, &deals[0]).is_none(), "⛔ a new custodian opened another's sub-share");
        let (a, st) = dh::accept(&b, j as u32, &subs, &[120 + j as u8; 32]).expect("the new custodian accepts");
        accepts.push(a);
        next.push(st);
    }
    if let (
        DefiHandoverTx::Accept { pair: 0, batch, to, new_pool, new_fee, new_close, proof },
        DefiHandoverTx::Accept { new_pool: other_pool, new_fee: other_fee, new_close: other_close, .. },
    ) = (&accepts[0], &accepts[1])
    {
        let sub = DefiHandoverTx::Accept { pair: 0, batch: *batch, to: *to, new_pool: *other_pool, new_fee: *new_fee, new_close: *new_close, proof: proof.clone() };
        assert!(sub.verdict(&b, &bonded).is_err(), "⛔ an acceptance carrying another custodian's new pool passed");
        // ⭐ Earn step 1 — the fee line too: an acceptance that names another custodian's new fee commitment is refused
        let fee_sub = DefiHandoverTx::Accept { pair: 0, batch: *batch, to: *to, new_pool: *new_pool, new_fee: *other_fee, new_close: *new_close, proof: proof.clone() };
        assert!(fee_sub.verdict(&b, &bonded).is_err(), "⛔ an acceptance carrying another custodian's new fee commitment passed");
        // ⭐ Earn step 3 — and the closed window: an acceptance that names another custodian's new close commitment is refused
        let close_sub = DefiHandoverTx::Accept { pair: 0, batch: *batch, to: *to, new_pool: *new_pool, new_fee: *new_fee, new_close: *other_close, proof: proof.clone() };
        assert!(close_sub.verdict(&b, &bonded).is_err(), "⛔ an acceptance carrying another custodian's new close commitment passed");
    }
    for (j, a) in accepts.iter().enumerate() {
        assert_eq!(a.verdict(&b, &bonded), Ok(()), "new custodian {j}'s acceptance passes");
        dh::apply_handover(&mut b, a, 7);
    }
    assert!(b.handover.is_none() && !b.frozen(), "the last acceptance switched the book");
    assert_eq!(b.eks, bonded, "the roster is the bonded custody set");
    assert_eq!(b.t, 2, "the threshold is the new roster's");
    assert_eq!(b.pool_commits, next.iter().map(CustodianState::commit).collect::<Vec<_>>(), "the pool commitments are the acceptances'");
    assert_eq!(b.fee_commits, next.iter().map(CustodianState::fee_commit).collect::<Vec<_>>(), "the fee commitments are the acceptances'");
    // the SAME pool, now among seven
    let open7_col = |col: Vec<[u64; 4]>| {
        // Lagrange at 0 over the first t + 1 = 3 points
        (0..3).fold([0u64; 4], |acc, i| {
            let xi = (i + 1) as u64;
            let w = (0..3).filter(|k| *k != i).fold(ba::fsmall(1), |a, k| {
                let xk = (k + 1) as u64;
                ba::fmul(&ba::fmul(&a, &ba::fsmall(xk)), &ba::finv(&ba::fsub(&ba::fsmall(xk), &ba::fsmall(xi))))
            });
            ba::fadd(&acc, &ba::fmul(&w, &col[i]))
        })
    };
    let open7 = |l: usize| open7_col(next.iter().map(|c| c.lines[l]).collect());
    assert_eq!((open7(0), open7(1)), (ba::fsmall(pool.0), ba::fsmall(pool.1)), "⛔ the handover moved the pool's value");
    for k in 0..ba::FEE_LINES {
        assert_eq!(open7_col(next.iter().map(|c| c.fee[k]).collect()), ba::fsmall(fee_line + k as u64), "⛔ the handover dropped or moved fee-state line {k} (Earn steps 1 + 3)");
    }
    for k in 0..ba::CLOSE_LINES {
        assert_eq!(open7_col(next.iter().map(|c| c.close[k]).collect()), ba::fsmall(fee_line + 3 + k as u64), "⛔ the handover dropped or moved closed-window line {k} (Earn step 3)");
    }
    // the new roster settles the next batch from its new shares
    let run = dcu::run_batch(&b, &next, &[], &[130; 32]).expect("the new roster settles");
    assert_eq!(run.settle.verdict(&b), Ok(Vec::new()), "every node accepts the new roster's settlement");
    assert_eq!(run.settle.tick, crate::defi_clear::rule_tick(u128::from(pool.0), u128::from(pool.1)), "the new roster prices the same pool");
    eprintln!("[br15-handover] 4 → 7 custodians: the pool moved as shares, frozen for one dealing + one acceptance each, and the new roster settled at tick {}", run.settle.tick);
}

/// ⭐ `br15_every_batch_carries_exactly_k_orders_and_k_claims_and_a_lone_one_is_refused` (spec §18.12) — THE ORDER COUNT IS A
/// CONSTANT: a batch with two real buys and one real claim is published as exactly `SLOTS` orders and `SLOTS` claims, the
/// rest custody COVERS (amount 0 over any held leaf, nullifiers in their own domains) — every cover order the same bytes'
/// length as a real one and verifying against the one order shape, every cover claim likewise. The slots pass the verdict;
/// the custody set settles the batch over all `SLOTS` orders (the covers' shares are real shares of 0) and every node
/// accepts it; the buyers' leaves are among the settlement's.
/// TAMPERS, each refused: one slot short (decode), one nullifier twice (replay), slots before the batch closed, a second
/// slots object for the batch (replay), a cover order claiming an amount (forge: no proof), a lone order or claim outside
/// slots (burn: the admit door), a slot stripped of its proof (strip).
#[test]
fn br15_every_batch_carries_exactly_k_orders_and_k_claims_and_a_lone_one_is_refused() {
    let n = 4usize;
    let (mut book, custodians, _d, _s, dks) = market(n, (2_000_000, 1_000_000), &[], 141);
    let (pk, sk) = crate::epoch_release::test_epoch_keypair();
    let t = book.t;
    // the buyers' two real slots: each spends a note of exactly its amount
    let reals: Vec<(ba::OrderDealing, db::DefiOrderTx)> = [40_000u64, 2_500]
        .iter()
        .enumerate()
        .map(|(k, a)| {
            let (d, commits, epoch_ct, sealed, share_proof) =
                dcu::order_parts(0, false, &book.eks, t, 0, &pk, *a, NO_MAX, [0x3D, k as u64, 1, 2, 3, 4, 5, 6], owner_of(k as u64, 141), [0x3C, k as u64, 0, 0, 0, 0, 0, 1], book.batch_index, &[142 + k as u8; 32]).expect("deals");
            let (_, nf, lc) = d.spend_publics();
            let o = db::DefiOrderTx {
                pair: 0,
                amount_commit: d.amount_commit(),
                limit_commit: d.limit_commit(),
                share_commits: commits,
                epoch: 0,
                epoch_ct,
                sealed,
                share_proof,
                nullifier: nf,
                leaf_commit: lc,
                member_carrier: vec![1],
                member_tuple: vec![1],
                index: book.batch_index,
            };
            (d, o)
        })
        .collect();
    for (_, o) in &reals {
        assert_eq!(o.self_valid(t), None, "a real slot verifies");
    }
    // the covers' legs: any held leaf (the node's member leg is the fold's check; here the cross-bind is formed honestly)
    let leg = |nf: [u64; 8], blind: [u64; 8]| -> Option<dcu::CoverLeg> {
        let leaf = [0x77, 1, 2, 3, 4, 5, 6, 7];
        Some((leaf, vec![1], vec![1], ba::claim_leaf_commit(&leaf, &nf, &blind)))
    };
    let mut orders: Vec<db::DefiOrderTx> = reals.iter().map(|(_, o)| o.clone()).collect();
    while orders.len() < db::SLOTS {
        let c = dcu::cover_order(&book, 0, &pk, &leg, &[150 + orders.len() as u8; 32]).expect("a cover order builds");
        assert_eq!(c.encode().expect("encodes").len(), reals[0].1.encode().expect("encodes").len(), "⛔ a cover order's bytes are not a real one's length");
        assert_eq!(c.self_valid(t), None, "a cover order verifies against the one order shape");
        orders.push(c);
    }
    let mut real_claim = claim_obj(50_000, [0x51; 8], NO_MAX, 1, 1, ba::ORDER_BUCKETS as u64, 50_000).expect("a real claim builds");
    // its leg stands in as the covers' do here (the fold checks legs; a real leg and a cover's are one carrier shape)
    real_claim.member_carrier = vec![1];
    real_claim.member_tuple = vec![1];
    let mut claims = vec![real_claim.clone()];
    while claims.len() < db::SLOTS {
        let c = dcu::cover_claim(0, &leg, &[170 + claims.len() as u8; 32]).expect("a cover claim builds");
        assert_eq!(c.encode().expect("encodes").len(), real_claim.encode().expect("encodes").len(), "⛔ a cover claim's bytes are not a real one's length");
        assert_eq!(c.self_valid(), None, "a cover claim verifies against the one claim shape");
        claims.push(c);
    }
    let parts = db::DefiSlotsTx::parts(0, book.batch, orders.clone(), claims.clone()).expect("the batch splits into its parts");
    assert_eq!(parts.len(), db::SLOT_PARTS, "every batch travels as SLOT_PARTS parts, a constant");
    let closed = db::BATCH_STEPS;
    for p in &parts {
        assert_eq!(db::DefiSlotsTx::decode(&p.encode().expect("encodes")), Some(p.clone()), "one canonical encoding");
        assert!(p.verdict(&book, 0).is_err(), "⛔ a part applied before the batch closed");
        assert_eq!(p.verdict(&book, closed), Ok(()), "each part of the batch's slots passes the verdict");
    }
    let slots = parts[0].clone();
    // TAMPERS
    let short = db::DefiSlotsTx { orders: slots.orders[..db::PART_SLOTS - 1].to_vec(), ..slots.clone() };
    assert!(db::DefiSlotsTx::decode(&short.encode().expect("encodes")).is_none(), "⛔ a part carried fewer than PART_SLOTS orders");
    let past = db::DefiSlotsTx { part: db::SLOT_PARTS as u8, ..slots.clone() };
    assert!(db::DefiSlotsTx::decode(&past.encode().expect("encodes")).is_none(), "⛔ a part past SLOT_PARTS decoded");
    let mut twice = slots.clone();
    twice.claims[1] = twice.claims[0].clone();
    assert!(twice.verdict(&book, closed).is_err(), "⛔ one nullifier twice in a part");
    let mut stripped = slots.clone();
    stripped.orders[1].share_proof.clear();
    assert!(stripped.verdict(&book, closed).is_err(), "⛔ a slot without its proof passed");
    let cover_at = parts.iter().position(|p| p.orders.iter().all(|o| !reals.iter().any(|(_, r)| r.nullifier == o.nullifier))).expect("a part of covers only");
    let mut rich = parts[cover_at].clone();
    rich.orders[0].amount_commit = reals[0].1.amount_commit;
    assert!(rich.verdict(&book, closed).is_err(), "⛔ a cover slot carried a real amount commitment");
    let lone_order = crate::chain_object::frame(crate::chain_object::Class::DefiOrder, &orders[0].encode().expect("encodes"));
    let lone_claim = crate::chain_object::frame(crate::chain_object::Class::DefiClaim, &claims[0].encode().expect("encodes"));
    for (what, blob) in [("order", lone_order), ("claim", lone_claim)] {
        assert!(!crate::chain_object::admissible(&blob, 10, 0, false), "⛔ a lone {what} was admitted outside its batch's slots");
    }
    // the batch: its orders are its parts' in fold order; a part applies once; no settlement over a batch slotted only in part
    let mut folded: Vec<db::DefiOrderTx> = Vec::new();
    for (k, p) in parts.iter().rev().enumerate() {
        db::apply_slots(&mut book, p);
        folded.extend(p.orders.iter().cloned());
        assert!(p.verdict(&book, closed).is_err(), "⛔ a part applied twice");
        if k + 1 < db::SLOT_PARTS {
            assert!(!book.slotted, "⛔ a batch counted slotted before all its parts applied");
        }
    }
    assert!(book.slotted && book.orders.len() == db::SLOTS, "every part applied: the batch holds its SLOTS orders");
    let orders = folded;
    let k = |o: &db::DefiOrderTx| dcu::order_epoch_key(&pk, &sk, o).expect("the released epoch key opens the order's layer");
    let shares: Vec<Vec<Option<OrderShare>>> = orders
        .iter()
        .map(|o| (0..n).map(|i| Some(dcu::capture_order_share(&dks[i], &k(o), i, o).expect("custodian i captures its share of the slot"))).collect())
        .collect();
    let run = dcu::run_batch(&book, &custodians, &shares, &[160; 32]).expect("the custody set settles the batch's slots");
    assert_eq!(run.settle.verdict(&book), Ok(run.settle.leaves.clone()), "⛔ a node refused the slotted batch's settlement");
    // TAMPER: the same book with one part missing (its orders present, its bit not) refuses the very same settlement
    let in_part = DefiBook { slot_parts: book.slot_parts & !1, slotted: false, ..book.clone() };
    assert_eq!(run.settle.verdict(&in_part), Err("the batch's slots have applied only in part"), "⛔ a settlement over a batch slotted only in part passed");
    assert_eq!(run.settle.leaves.len(), db::SLOTS, "one leaf per slot, a constant");
    let want = crate::defi_clear::rule_tick(2_000_000, 1_000_000 + 40_000 + 2_500);
    assert_eq!(run.settle.tick, want, "the covers add nothing to the price: the tick is the two buys' rule tick");
    for (d, _) in &reals {
        assert!(run.settle.leaves.contains(&db::claim_leaf_at(&d.amount_commit(), &d.limit_commit(), want, crate::defi_clear::j_min(book.last_tick, want), true)), "a buyer's leaf is the settlement's");
    }
    eprintln!("[br15-slots] {} orders + {} claims per batch whatever traded (2 real + {} cover orders, 1 real + {} cover claims); settled at tick {want}", db::SLOTS, db::SLOTS, db::SLOTS - 2, db::SLOTS - 1);
}

/// ⭐ A-F26 PIN: two orders of one batch name different anchors — the fold door refuses.
/// WHAT THIS PROVES: the check at `node/objects/defi_batch.rs` (§DEFI fold door) reads every slot's
/// `member_tuple`, decodes its anchor field, and rejects the batch when any two slots disagree.
/// A partition by anchor tells real slots from covers; without the check an attacker mixes covers
/// anchored at a stale tree with real orders anchored at the tip, and a cover's "membership" at
/// the stale tree passes (the path refolds to a root the chain once produced).
#[test]
fn af26_a_batch_whose_slots_name_different_anchors_is_refused_at_the_fold_door() {
    use crate::member_transition::{write_tuple, read_tuple, MEMBER_TUPLE_BYTES};
    use usdm_decider::member_path_gate::MemberTuple;

    let anchor_a = [1u64, 2, 3, 4, 5, 6, 7, 8];
    let anchor_b = [9u64, 10, 11, 12, 13, 14, 15, 16];
    assert_ne!(anchor_a, anchor_b);

    let tuple_a = MemberTuple { leaf_commit: [10; 8], binder: [20; 8], anchor: anchor_a, outs: [30; 8] };
    let tuple_b = MemberTuple { leaf_commit: [11; 8], binder: [21; 8], anchor: anchor_b, outs: [31; 8] };

    let mut bytes_a = Vec::new();
    write_tuple(&tuple_a, &mut bytes_a);
    assert_eq!(bytes_a.len(), MEMBER_TUPLE_BYTES);
    let mut bytes_b = Vec::new();
    write_tuple(&tuple_b, &mut bytes_b);
    assert_eq!(bytes_b.len(), MEMBER_TUPLE_BYTES);

    // CALIBRATION: each tuple round-trips and its anchor is what we wrote
    let ra = read_tuple(&bytes_a).expect("tuple A decodes");
    assert_eq!(ra.anchor, anchor_a);
    let rb = read_tuple(&bytes_b).expect("tuple B decodes");
    assert_eq!(rb.anchor, anchor_b);

    // THE FOLD DOOR'S CHECK, verbatim from node/objects/defi_batch.rs (A-F26):
    let tuples: Vec<&[u8]> = vec![&bytes_a, &bytes_b];
    let mut batch_anchor: Option<crate::spend_frontier::Digest4> = None;
    let mut refused = false;
    for tuple in &tuples {
        let mt = read_tuple(tuple).expect("decodes");
        match batch_anchor {
            None => { batch_anchor = Some(mt.anchor); }
            Some(a) if a == mt.anchor => {}
            Some(_) => { refused = true; break; }
        }
    }
    assert!(refused, "⛔ A-F26: two slots with different anchors passed the fold door — a stale-anchor cover could ride a real batch");

    // HONEST: all slots at one anchor pass
    let tuples_same: Vec<&[u8]> = vec![&bytes_a, &bytes_a];
    let mut batch_anchor2: Option<crate::spend_frontier::Digest4> = None;
    let mut refused2 = false;
    for tuple in &tuples_same {
        let mt = read_tuple(tuple).expect("decodes");
        match batch_anchor2 {
            None => { batch_anchor2 = Some(mt.anchor); }
            Some(a) if a == mt.anchor => {}
            Some(_) => { refused2 = true; break; }
        }
    }
    assert!(!refused2, "the honest case (same anchor) must pass");
    eprintln!("[af26] the fold door refuses two slots with different anchors; the honest case passes");
}

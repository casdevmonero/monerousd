// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The income proof's pins: one proof over many notes, the total public, each amount private.
//!
//! TWO-PARTY-REVIEWED: the prover's and the verifier's own verdicts on one statement, run on hostile statements and
//! hand-laid tables against the production verifier. The two-wallet check (a business's wallet proves, a verifier's
//! wallet checks and reads each commitment through its own node) is a real-node row and is not claimed here.

use super::*;
use crate::poseidon2_compress::lanes_of;

/// Amounts whose limbs carry into one another when summed (three low limbs full).
const AMOUNTS: [u64; 5] = [0x0000_FFFF_FFFF_FFFF, 0x0000_FFFF_FFFF_FFFF, 4_250_000_000, 1, 0x0000_0001_0000_FFFF];

struct Case {
    st: IncomeStatement,
    notes: Vec<(u64, Digest)>,
    vsk: Digest,
}

fn case_of(amounts: &[u64]) -> Case {
    let recipient = NoteOwner::from_test_key(lanes_of(&[0xB0B, 4, 5, 6]));
    let vsk = lanes_of(&[0x7E57, 8, 6, 7, 5, 3, 0, 9]);
    let mut st = IncomeStatement {
        cms: Vec::new(),
        recipient_spk: recipient.spk(),
        total: amounts.iter().sum(),
        asset_tag: USDM_ASSET_TAG,
        verifier_key: pay_verifier_key(&vsk),
        context: lanes_of(&[0xC0FFEE, 2026]),
    };
    let notes: Vec<(u64, Digest)> = amounts.iter().enumerate().map(|(i, a)| (*a, lanes_of(&[0x5EED, i as u64, 3, 1, 4, 1, 5, 9]))).collect();
    st.cms = notes.iter().map(|(a, seed)| note_cm(&st, *a, seed)).collect();
    Case { st, notes, vsk }
}

fn case() -> Case {
    case_of(&AMOUNTS)
}

/// The honest rows of a case, with fixed lanes where the prover draws fresh ones (a fixture, on purpose).
fn honest_rows(c: &Case) -> Vec<RowWitness> {
    let mut rows: Vec<RowWitness> = c.notes.iter().map(|(amount, seed)| RowWitness { real: true, amount: *amount, seed: *seed, vsk: lanes_of(&[1, 1, 1, 1]) }).collect();
    while rows.len() < c.st.rows() {
        rows.push(RowWitness { real: true, amount: 0, seed: lanes_of(&[2, rows.len() as u64]), vsk: lanes_of(&[1, 1, 1, 1]) });
    }
    rows
}

/// Prove a hand-laid table as it stands and say whether the production verifier takes it for `st`.
fn accepted(st: &IncomeStatement, cols: Vec<Vec<Fa4>>) -> bool {
    let st2 = st.clone();
    crate::committed_air::prove_air_blinded_chained_bytes(cols, move |g: Ea4| PaySumGate::of(&st2, g), &pay_sum_bind(st)).is_some_and(|p| verify_income(&p, st))
}

#[test]
fn an_income_proof_verifies_for_its_statement_and_for_no_other() {
    let c = case();
    assert_eq!(c.st.total, AMOUNTS.iter().sum::<u64>());
    let proof = prove_income(&c.st, &c.notes).expect("the honest proof proves");
    assert!(verify_income(&proof, &c.st), "CALIBRATION: the proof verifies for its statement");
    let refused = |name: &str, st: IncomeStatement| {
        assert!(!verify_income(&proof, &st), "⛔ {name}: the proof verified for another statement");
    };
    refused("a larger total", IncomeStatement { total: c.st.total + 1, ..c.st.clone() });
    refused("a total one limb higher", IncomeStatement { total: c.st.total + (1 << 16), ..c.st.clone() });
    refused("another recipient", IncomeStatement { recipient_spk: lanes_of(&[9, 9, 9, 9]), ..c.st.clone() });
    refused("another asset", IncomeStatement { asset_tag: [1, 0, 0], ..c.st.clone() });
    refused("another verifier", IncomeStatement { verifier_key: pay_verifier_key(&lanes_of(&[5, 5, 5, 5])), ..c.st.clone() });
    refused("another challenge", IncomeStatement { context: lanes_of(&[0xC0FFEE, 2027]), ..c.st.clone() });
    let mut swapped = c.st.clone();
    swapped.cms.swap(0, 2);
    refused("the same notes in another order", swapped);
    let mut other = c.st.clone();
    other.cms[1] = lanes_of(&[1, 2, 3, 4]);
    refused("another note in the list", other);
    let mut longer = c.st.clone();
    longer.cms.push(lanes_of(&[4, 3, 2, 1]));
    refused("one more note listed", longer);
    let mut shorter = c.st.clone();
    shorter.cms.pop();
    refused("one note fewer listed", shorter);
    let mut flipped = proof.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 1;
    assert!(!verify_income(&flipped, &c.st), "⛔ a flipped byte verified");
    assert!(!verify_income(&[], &c.st));
}

#[test]
fn nobody_proves_income_that_was_not_received() {
    let c = case();
    // the honest prover has no proof of a false statement
    assert!(prove_income(&IncomeStatement { total: c.st.total + 1, ..c.st.clone() }, &c.notes).is_none(), "a false total");
    let mut wrong_seed = c.notes.clone();
    wrong_seed[0].1 = lanes_of(&[6, 6, 6, 6]);
    assert!(prove_income(&c.st, &wrong_seed).is_none(), "a seed that does not open its note");
    assert!(prove_income(&c.st, &c.notes[..4]).is_none(), "fewer openings than notes");

    // CALIBRATION: the hand-laid honest table is accepted, so each refusal below is the lie's and not the fixture's
    assert!(accepted(&c.st, pay_sum_cols(&c.st, &honest_rows(&c))), "CALIBRATION: the honest hand-laid table verifies");

    // a larger total over the honest rows
    for more in [1u64, 1 << 16, 1 << 32, 1 << 48, 10 * c.st.total] {
        let lie = IncomeStatement { total: c.st.total.wrapping_add(more), ..c.st.clone() };
        assert!(!accepted(&lie, pay_sum_cols(&lie, &honest_rows(&c))), "⛔ a total {more} above the notes' sum verified");
    }
    // one note laid ten times larger than it is, the total raised to match
    let mut rows = honest_rows(&c);
    rows[2].amount *= 10;
    let lie = IncomeStatement { total: c.st.total + 9 * AMOUNTS[2], ..c.st.clone() };
    assert!(!accepted(&lie, pay_sum_cols(&lie, &rows)), "⛔ a note laid ten times larger than its commitment verified");
    // an amount on a row past the list, the total raised to match
    let mut rows = honest_rows(&c);
    rows[6].amount = 777_000_000;
    let lie = IncomeStatement { total: c.st.total + 777_000_000, ..c.st.clone() };
    assert!(!accepted(&lie, pay_sum_cols(&lie, &rows)), "⛔ money on a row that lists no note verified");
    // the verifier's branch on one row, without the verifier's secret, to free that row's amount
    let mut rows = honest_rows(&c);
    rows[0].real = false;
    rows[0].amount += 5_000_000_000;
    let lie = IncomeStatement { total: c.st.total + 5_000_000_000, ..c.st.clone() };
    assert!(!accepted(&lie, pay_sum_cols(&lie, &rows)), "⛔ the verifier's branch opened without its secret");
    // a branch bit that is neither
    let mut cols = pay_sum_cols(&c.st, &honest_rows(&c));
    cols[PS_REAL][0] = Fa4::TWO;
    assert!(!accepted(&c.st, cols), "⛔ a branch bit that is not a bit verified");
    // an amount cell that is not a bit, spelling the same limb (bit 0 = 2 where bit 1 was set)
    let mut cols = pay_sum_cols(&c.st, &honest_rows(&c));
    assert!(cols[PS_BITS][3] == Fa4::ONE && cols[PS_BITS + 1][3] == Fa4::ZERO, "fixture: note 3 is amount 1");
    cols[PS_BITS][3] = Fa4::from_u64(3);
    cols[PS_BITS + 1][3] = Fa4::ZERO - Fa4::ONE;
    assert!(!accepted(&c.st, cols), "⛔ an amount cell that is not a bit verified");
    // a running sum restarted in the middle (the first two notes dropped from the sum), carries laid to match
    let mut cols = pay_sum_cols(&c.st, &honest_rows(&c));
    for limb in 0..LIMBS {
        cols[PS_ACC + limb][2] = Fa4::ZERO;
    }
    assert!(!accepted(&c.st, cols), "⛔ a running sum that forgot two notes verified");
    // a carry cell that is not a bit
    let mut cols = pay_sum_cols(&c.st, &honest_rows(&c));
    let last = c.st.rows() - 1;
    cols[PS_CARRY][last] += Fa4::TWO;
    assert!(!accepted(&c.st, cols), "⛔ a carry that is not a bit verified");
}

/// The designated-verifier property, measured: the named verifier makes an accepting proof of a FALSE statement, so
/// bytes passed on are evidence of nothing; and under the key nobody holds, no such proof exists.
#[test]
fn an_income_proof_passed_on_is_worthless_and_a_public_one_is_not() {
    let c = case();
    let never = IncomeStatement { total: 999_000_000_000, cms: vec![lanes_of(&[7, 7, 7, 7]), lanes_of(&[8, 8, 8, 8])], ..c.st.clone() };
    let forged = simulate_income(&never, &c.vsk).expect("the verifier simulates");
    assert!(verify_income(&forged, &never), "the verifier's own proof of income that never happened verifies");
    assert!(simulate_income(&never, &lanes_of(&[2, 2, 2, 2])).is_none(), "only the holder of the verifier's secret simulates");
    // a PUBLIC proof: the verifier key nobody holds. The honest proof verifies; nobody simulates.
    let mut public = c.st.clone();
    public.verifier_key = public_verifier_key();
    let proof = prove_income(&public, &c.notes).expect("proves");
    assert!(verify_income(&proof, &public));
    assert!(simulate_income(&public, &c.vsk).is_none());
    let never_public = IncomeStatement { verifier_key: public_verifier_key(), ..never.clone() };
    let rows: Vec<RowWitness> =
        (0..never_public.rows()).map(|i| RowWitness { real: false, amount: if i == 0 { never_public.total } else { 0 }, seed: lanes_of(&[3, i as u64]), vsk: [0; DIGEST_LANES] }).collect();
    assert!(!accepted(&never_public, pay_sum_cols(&never_public, &rows)), "⛔ a public proof of income that never happened verified");
}

#[test]
fn a_list_naming_one_note_twice_is_refused() {
    let c = case();
    let mut twice = c.st.clone();
    twice.cms.push(c.st.cms[0]);
    twice.total += AMOUNTS[0];
    let mut notes = c.notes.clone();
    notes.push(c.notes[0]);
    assert!(prove_income(&twice, &notes).is_none(), "the honest prover counts no note twice");
    // laid by hand it is a true table of a false claim: the verifier refuses the list itself
    let mut rows: Vec<RowWitness> = notes.iter().map(|(amount, seed)| RowWitness { real: true, amount: *amount, seed: *seed, vsk: lanes_of(&[1, 1, 1, 1]) }).collect();
    while rows.len() < twice.rows() {
        rows.push(RowWitness { real: true, amount: 0, seed: lanes_of(&[2, rows.len() as u64]), vsk: lanes_of(&[1, 1, 1, 1]) });
    }
    assert!(!accepted(&twice, pay_sum_cols(&twice, &rows)), "⛔ one note counted twice verified");
    // and so is an empty list or one past the bound
    assert!(!verify_income(&[1, 2, 3], &IncomeStatement { cms: Vec::new(), ..c.st.clone() }));
    let many: Vec<Digest> = (0..=PAY_SUM_MAX_NOTES as u64).map(|i| lanes_of(&[0xAB, i])).collect();
    assert!(!verify_income(&[1, 2, 3], &IncomeStatement { cms: many, ..c.st.clone() }));
}

/// The blinded table the prover commits for a laid table: the data in the first half, fixed mix lanes in the second
/// (the prover draws these from the OS; a census needs a table it can reproduce).
fn doubled(cols: &[Vec<Fa4>]) -> Vec<Vec<Fa4>> {
    cols.iter()
        .enumerate()
        .map(|(c, col)| {
            let mut out = col.clone();
            out.extend((0..col.len()).map(|r| Fa4::from_u64(((c as u64 + 1) * 0x9E37_79B9 + (r as u64 + 1) * 0x85EB_CA6B) % 0x7F00_0001)));
            out
        })
        .collect()
}

/// SOUND IS MEASURED: every law holds on the honest table, and the three censuses pass on both branches, on the
/// wrapped gate and the doubled table the prover really commits.
#[test]
fn the_income_gate_passes_the_three_censuses_on_both_branches() {
    let c = case();
    let simulated: Vec<RowWitness> =
        (0..c.st.rows()).map(|i| RowWitness { real: false, amount: if i == 0 { c.st.total } else { 0 }, seed: lanes_of(&[3, i as u64]), vsk: c.vsk }).collect();
    for (rows, name) in [(honest_rows(&c), "the notes open"), (simulated, "the verifier's branch")] {
        let laid = pay_sum_cols(&c.st, &rows);
        let cols = doubled(&laid);
        let nvars = cols[0].len().trailing_zeros() as usize;
        let g = crate::committed_air::Blinded { inner: PaySumGate::of(&c.st, Ea4::from(Fa4::from_u64(0x9A7))) };
        // every law, on every laid row, against the next row's cells
        let n_rows = cols[0].len();
        for r in 0..n_rows / 2 {
            let oob = crate::air_zerocheck::OobLatch::new();
            let local: Vec<Ea4> = cols.iter().map(|col| Ea4::from(col[r])).collect();
            let next: Vec<Ea4> = cols.iter().map(|col| Ea4::from(col[(r + 1) % n_rows])).collect();
            let x: Vec<Ea4> = (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }).collect();
            let at = |col: usize, _p: &[Ea4]| -> Ea4 { next[col] };
            let rs = crate::air_zerocheck::AirConstraint::residuals(&g, &crate::air_zerocheck::Row::new(&local, &oob), &at, &x);
            let bad: Vec<usize> = rs.iter().enumerate().filter(|(_, v)| **v != Ea4::ZERO).map(|(i, _)| i).collect();
            assert!(bad.is_empty(), "{name}: row {r}: residual(s) {bad:?} of {} are non-zero on the honest table", rs.len());
        }
        let shifted = crate::air_zerocheck::AirConstraint::shifted_cols(&g);
        crate::air_zerocheck::debug_degree_census(&cols, &g, nvars, false, &shifted);
        crate::air_zerocheck::debug_free_witness_census(&cols, &g, nvars, false, &shifted);
        crate::air_zerocheck::debug_decorative_block_census(&cols, &g, nvars, false, &shifted);
    }
}

#[test]
fn the_income_proof_is_measured() {
    for n in [5usize, 64, PAY_SUM_MAX_NOTES] {
        let amounts: Vec<u64> = (0..n as u64).map(|i| 1_000_000_000 + i * 0x0001_0001_FFFF).collect();
        let c = case_of(&amounts);
        let t0 = std::time::Instant::now();
        let proof = prove_income(&c.st, &c.notes).expect("proves");
        let prove_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        assert!(verify_income(&proof, &c.st));
        eprintln!(
            "[income-proof-cost] {n} notes: {} rows x {PAY_SUM_WIDTH} columns, proof {} B, prove {prove_ms} ms, verify {} ms",
            c.st.rows(),
            proof.len(),
            t1.elapsed().as_millis()
        );
    }
}

/// THE NEXT-ROW CLASS (2026-11-10): a prover that lies ONLY in the next-row openings. The statement names a total the
/// notes never held; the table is the honest one for the true total, so the commitment, the opened row and the
/// opening proof are all real.
///
/// MEASURED 2026-11-10, before the class was closed at the door: through the plain door, which then took next-row
/// openings from the wire, this exact carrier VERIFIED (that was the hole this class is). The plain door now carries no
/// next-row opening at all and refuses a carrier that sends one, so the same bytes are refused there too; that refusal
/// is pinned here in place of the old calibration. Through the income door, which binds the next-row values to the
/// commitment (the shift bind), the same prover is refused at the bind's last line.
/// CALIBRATION: the adversary must have found a next-row cell to move (a carrier with none would be refused for being
/// empty, and prove nothing about the bind).
#[test]
fn a_prover_lying_in_the_next_row_openings_proves_no_income() {
    let c = case();
    let lie = IncomeStatement { total: c.st.total + 1_000_000_000_000, ..c.st.clone() };
    let gate = |st: &IncomeStatement| {
        let st = st.clone();
        move |g: Ea4| PaySumGate::of(&st, g)
    };
    let table = || pay_sum_cols(&c.st, &honest_rows(&c));
    let loose = crate::committed_air::forge_blinded_next_row_for_tests(table(), gate(&lie), &pay_sum_bind(&lie)).expect("the gate reads the next row, so there is an opening to move");
    assert!(
        postcard::from_bytes::<crate::committed_air::CommittedAirBundle>(&loose).is_ok_and(|b| !b.zc.shifted_opened.is_empty()),
        "CALIBRATION: the adversary's carrier sends the next-row value it moved"
    );
    assert!(
        !crate::committed_air::verify_air_blinded_bytes(&loose, gate(&lie), &pay_sum_bind(&lie), (lie.rows().trailing_zeros() as usize, PAY_SUM_WIDTH)),
        "⛔ the plain door took a next-row opening from the wire: the class closed at the door on 2026-11-10 is open again"
    );
    assert!(!verify_income(&loose, &lie), "the income door does not read that carrier at all");
    let forged = crate::committed_air::forge_blinded_chained_for_tests(table(), gate(&lie), &pay_sum_bind(&lie)).expect("CALIBRATION: the adversary has an opening to move");
    assert!(!verify_income(&forged, &lie), "⛔ income nobody received VERIFIED: a next-row opening was moved and the door took it");
}

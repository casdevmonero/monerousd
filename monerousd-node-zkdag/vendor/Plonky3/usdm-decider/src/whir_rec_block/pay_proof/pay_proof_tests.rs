// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The payment proof's pins (docs/PAYMENT-PROOFS-SPEC-20261109.md §7, the decider half).
//!
//! TWO-PARTY-REVIEWED: the prover's and the verifier's own verdicts on one statement, run on hostile statements
//! against the production verifier. The two-wallet check (A pays B through one real node, A proves it to a verifier
//! that reads the commitment through another) is the real-node row `pay-proof` and is not claimed here.

use super::*;
use crate::poseidon2_compress::lanes_of;

const AMOUNT: u64 = 4_250_000_000; // $42.50

struct Case {
    st: PaymentStatement,
    seed: Digest,
    vsk: Digest,
}

fn case() -> Case {
    let recipient = NoteOwner::from_test_key(lanes_of(&[0xB0B, 4, 5, 6]));
    let seed = lanes_of(&[0x5EED, 3, 1, 4, 1, 5, 9, 2]);
    let vsk = lanes_of(&[0x7E57, 8, 6, 7, 5, 3, 0, 9]);
    let opening = owner_opening(&recipient.spk(), &seed);
    let cm = asset_note_cm(AMOUNT, USDM_ASSET_TAG, opening);
    let st = PaymentStatement {
        cm,
        recipient_spk: recipient.spk(),
        amount: AMOUNT,
        asset_tag: USDM_ASSET_TAG,
        verifier_key: pay_verifier_key(&vsk),
        context: lanes_of(&[0xC0FFEE, 1042]),
    };
    Case { st, seed, vsk }
}

#[test]
fn a_payment_proof_verifies_for_its_statement_and_for_no_other() {
    {
        let c = case();
        assert_eq!(payment_note_cm(&c.st, &c.seed), c.st.cm, "the statement's spelling of the note is the chain's");
        let proof = prove_payment(&c.st, &c.seed).expect("the honest proof proves");
        assert!(verify_payment(&proof, &c.st), "CALIBRATION: the proof verifies for its statement");
        let refused = |name: &str, st: PaymentStatement| {
            assert!(!verify_payment(&proof, &st), "⛔ {name}: the proof verified for another statement");
        };
        refused("another amount", PaymentStatement { amount: AMOUNT + 1, ..c.st });
        refused("another recipient", PaymentStatement { recipient_spk: lanes_of(&[9, 9, 9, 9]), ..c.st });
        refused("another note", PaymentStatement { cm: lanes_of(&[1, 2, 3, 4]), ..c.st });
        refused("another asset", PaymentStatement { asset_tag: [1, 0, 0], ..c.st });
        refused("another verifier", PaymentStatement { verifier_key: pay_verifier_key(&lanes_of(&[5, 5, 5, 5])), ..c.st });
        refused("another challenge", PaymentStatement { context: lanes_of(&[0xC0FFEE, 1043]), ..c.st });
        let mut flipped = proof.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 1;
        assert!(!verify_payment(&flipped, &c.st), "⛔ a flipped byte verified");
        assert!(!verify_payment(&[], &c.st));
    }
}

#[test]
fn nobody_proves_a_payment_that_was_not_made() {
    let c = case();
    // the honest prover has no proof of a false statement
    assert!(prove_payment(&PaymentStatement { amount: AMOUNT + 1, ..c.st }, &c.seed).is_none());
    assert!(prove_payment(&c.st, &lanes_of(&[6, 6, 6, 6])).is_none(), "a seed that does not open the note");
    // a lying prover lays the first branch over the wrong seed and the gate refuses it
    let lie = PaymentStatement { amount: AMOUNT * 10, ..c.st };
    let row = pay_proof_row(&lie, true, &c.seed, &lanes_of(&[1, 1, 1, 1]));
    assert!(prove_pay_row(&lie, row).is_none_or(|p| !verify_payment(&p, &lie)), "⛔ a payment ten times larger than the note verified");
    // a lying prover takes the verifier's branch with a secret that is not the verifier's
    let row = pay_proof_row(&lie, false, &c.seed, &lanes_of(&[1, 1, 1, 1]));
    assert!(prove_pay_row(&lie, row).is_none_or(|p| !verify_payment(&p, &lie)), "⛔ the verifier's branch opened without its secret");
    // a branch bit that is neither
    let mut row = pay_proof_row(&c.st, true, &c.seed, &c.vsk);
    row[PP_REAL] = Fa4::TWO;
    assert!(prove_pay_row(&c.st, row).is_none_or(|p| !verify_payment(&p, &c.st)), "⛔ a branch bit that is not a bit verified");
}

/// The designated-verifier property, measured: the named verifier makes an accepting proof of a FALSE statement, so
/// bytes passed on are evidence of nothing; and under the key nobody holds, no such proof exists.
#[test]
fn a_proof_passed_on_is_worthless_and_a_public_proof_is_not() {
    let c = case();
    let never_paid = PaymentStatement { amount: 999_000_000_000, cm: lanes_of(&[7, 7, 7, 7]), ..c.st };
    let forged = simulate_payment(&never_paid, &c.vsk).expect("the verifier simulates");
    assert!(verify_payment(&forged, &never_paid), "the verifier's own proof of a payment that never happened verifies");
    assert!(simulate_payment(&never_paid, &lanes_of(&[2, 2, 2, 2])).is_none(), "only the holder of the verifier's secret simulates");
    // a PUBLIC proof: the verifier key nobody holds. The honest proof verifies; nobody simulates.
    let public = PaymentStatement { verifier_key: public_verifier_key(), ..c.st };
    let proof = prove_payment(&public, &c.seed).expect("proves");
    assert!(verify_payment(&proof, &public));
    assert!(simulate_payment(&public, &c.vsk).is_none());
    let never_public = PaymentStatement { verifier_key: public_verifier_key(), ..never_paid };
    let row = pay_proof_row(&never_public, false, &c.seed, &[0; DIGEST_LANES]);
    assert!(
        prove_pay_row(&never_public, row).is_none_or(|p| !verify_payment(&p, &never_public)),
        "⛔ a public proof of a payment that never happened verified"
    );
}

/// SOUND IS MEASURED: the three censuses on both branches of the gate.
#[test]
fn the_payment_proof_gate_passes_the_three_censuses_on_both_branches() {
    let c = case();
    for (real, name) in [(true, "the note opens"), (false, "the verifier's branch")] {
        let row = pay_proof_row(&c.st, real, &c.seed, &c.vsk);
        let g = PayProofGate::of(&c.st, Ea4::from(Fa4::from_u64(0x9A7)));
        let oob = crate::air_zerocheck::OobLatch::new();
        let vals: Vec<Ea4> = row.iter().map(|v| Ea4::from(*v)).collect();
        let rs = g.residuals(&crate::air_zerocheck::Row::new(&vals, &oob));
        let bad: Vec<usize> = rs.iter().enumerate().filter(|(_, r)| **r != Ea4::ZERO).map(|(i, _)| i).collect();
        assert!(bad.is_empty(), "{name}: residual(s) {bad:?} of {} are non-zero on the honest row", rs.len());
        let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|col| vec![row[col]; LIGHT_CARRIER_ROWS]).collect();
        let nvars = cols[0].len().trailing_zeros() as usize;
        crate::air_zerocheck::debug_degree_census(&cols, &g, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_free_witness_census(&cols, &g, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_decorative_block_census(&cols, &g, nvars, true, &Some(Vec::new()));
    }
}

#[test]
fn the_payment_proof_is_measured() {
    let c = case();
    let t0 = std::time::Instant::now();
    let proof = prove_payment(&c.st, &c.seed).expect("proves");
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    assert!(verify_payment(&proof, &c.st));
    eprintln!(
        "[pay-proof-cost] row {PAY_PROOF_WIDTH} columns, proof {} B, prove {prove_ms} ms, verify {} ms",
        proof.len(),
        t1.elapsed().as_millis()
    );
}

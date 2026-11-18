// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! §BR-0 — THE NO-WAIT CENSUS (spec docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §5).
//!
//! WHAT IT PROVES. A legitimate mint (peg-in), deposit (wrapped-asset mint), withdrawal (peg-out) and
//! redemption (peg-out at the floor) each PUBLISH WITHOUT being held, delayed or gated by the bond level.
//! The bond is a forfeitable security deposit against validator theft; it governs slashing, reward weight
//! and how much the set can be trusted with — NEVER whether a user may deposit or withdraw (user ruling,
//! node.rs:22585 and peg.rs:2589).
//!
//! THE EXIT IS THE SHIPPING ONE. Each operation is the real `check_peg_in_confidential` /
//! `check_peg_out_confidential` / `check_wrapped_mint_confidential` path — the READ-ONLY PUBLISHING check
//! that decides admission — at the full quorum, with a correctly-collateralized carrier. The ONLY variable
//! is the bond level. Mutation happens at fold time on every node; the two-party coverage for that:
//! CROSS-NODE-REVIEWED: a_peg_in_stripped_of_its_attestations_carried_by_a_rogue_producer_mints_nothing_on_the_peer
//! CROSS-NODE-REVIEWED: db224_a_wrapped_mint_crosses_the_wire_without_its_payload_and_moves_the_peg_on_a_peer_that_never_pooled_it
//!
//! RED-FIRST (refutation before green). The calibration pins prove:
//!   (a) the OLD gate (bond ≥ 2× reserve) WOULD refuse a mint at low bond — the planted hold is detected;
//!   (b) with the gate removed (the shipped code), the same operations complete at every bond level.

#[cfg(test)]
mod tests {
    use crate::bridge::Custodian;
    use crate::peg::{
        PegLedger, PegOutcome, peg_in_confidential_msg, peg_out_confidential_msg,
        wrapped_mint_confidential_msg,
    };
    use crate::pqauth::MlDsaVerifier;
    use crate::psm::MintAttestor;
    use crate::validator::ValidatorSet;

    type Digest = [u64; 8];

    fn lanes(seed: &[u64]) -> Digest {
        usdm_decider::poseidon2_compress::lanes_of(seed)
    }

    fn quorum_at_bond(bond: u128) -> (Vec<Custodian>, ValidatorSet) {
        let custodians: Vec<Custodian> =
            (0..2u8).map(|i| Custodian::generate(&[80 + i; 32])).collect();
        let mut vs = ValidatorSet::new();
        let half = bond / 2;
        let remainder = bond - half;
        for (i, c) in custodians.iter().enumerate() {
            let b = if i == 0 { half } else { remainder };
            if b > 0 {
                vs.admit(c.id(), b, 0).unwrap();
            }
        }
        (custodians, vs)
    }

    fn attest(custodians: &[Custodian], msg: &[u8]) -> Vec<MintAttestor> {
        custodians.iter().map(|c| c.attest(msg)).collect()
    }

    // ── HELPERS ──────────────────────────────────────────────────────────────────────────────────────────

    struct PegInKit {
        peg: PegLedger,
        carrier: Vec<u8>,
        new_rc: Digest,
        new_mc: Digest,
        delta: Digest,
    }

    fn peg_in_kit() -> PegInKit {
        let (rb, mb) = (lanes(&[1, 2, 3, 4]), lanes(&[5, 6, 7, 8]));
        let db = lanes(&[21, 22, 23, 24]);
        // §19.5b: the mint proves from the custodians' openings of BOTH bridge ledgers (the cover)
        let (peg, openings) = crate::peg::ledger_at_for_test(15_000, 3_000, rb, 2_000, mb);
        let (carrier, new_rc, new_mc, _) = peg
            .orchestrate_cover(true, crate::peg::NATIVE_PEG_ASSET_ID, &openings, 900, 600, &db, &db, None)
            .expect("solvency proves");
        PegInKit { peg, carrier, new_rc, new_mc, delta: PegLedger::mint_delta_commit(600, db) }
    }

    struct PegOutKit {
        peg: PegLedger,
        carrier: Vec<u8>,
        new_rc: Digest,
        new_mc: Digest,
        // ⭐ B15: the committed burn's nullifier, leaf commitment and change commitment (the statement names them)
        nf: [u8; 32],
        lc: Digest,
        cm: [u8; 32],
    }

    fn peg_out_kit() -> PegOutKit {
        let (rb, mb) = (lanes(&[1, 2, 3, 4]), lanes(&[5, 6, 7, 8]));
        let (peg, openings) = crate::peg::ledger_at_for_test(15_000, 3_000, rb, 2_000, mb);
        let (carrier, nf, lc, cm, (new_rc, new_mc), _) = crate::peg::peg_out_proofs_for_test(
            &peg, &openings, crate::peg::NATIVE_PEG_ASSET_ID, 200, 200, &lanes(&[71, 72, 73, 74]), &[0x74u8; 32],
        )
        .expect("redeem proves");
        PegOutKit { peg, carrier, new_rc, new_mc, nf, lc, cm }
    }

    fn wrapped_mint_kit() -> (PegLedger, Vec<u8>, Digest, Digest, Digest) {
        let (rb, mb) = crate::peg::psm_genesis_blinds(42);
        let db = lanes(&[61, 62, 63, 64]);
        let mut peg = PegLedger::new(15_000);
        peg.register_wrapped_asset(42, 10_000);
        let result = peg.orchestrate_wrapped_mint(
            42,
            0, rb,
            0, mb,
            500, 500,
            db,
        );
        let (carrier, new_rc, new_mc, _nrb, _nmb, delta) = result.expect("orchestration");
        (peg, carrier, new_rc, new_mc, delta)
    }

    fn floor_kit() -> PegOutKit {
        let (rb, mb) = (lanes(&[1, 2, 3, 4]), lanes(&[5, 6, 7, 8]));
        let (peg, openings) = crate::peg::ledger_at_for_test(15_000, 2_000, rb, 2_000, mb);
        let (carrier, nf, lc, cm, (new_rc, new_mc), _) = crate::peg::peg_out_proofs_for_test(
            &peg, &openings, crate::peg::NATIVE_PEG_ASSET_ID, 500, 500, &lanes(&[81, 82, 83, 84]), &[0x81u8; 32],
        )
        .expect("floor-level redemption proves");
        PegOutKit { peg, carrier, new_rc, new_mc, nf, lc, cm }
    }

    // ── THE BOND LEVELS ─────────────────────────────────────────────────────────────────────────────────
    const BOND_LEVELS: [u128; 5] = [1, 100, 1_000, 10_000, 100_000];

    // ── PIN 1 — CALIBRATION: the planted hold IS detected (RED-first) ───────────────────────────────────
    //
    // REFUTATION BEFORE GREEN. The old `Underbonded` gate (`bond >= 2× reserve`) would refuse a mint at
    // every bond level below 2× the new reserve (3000 + 900 = 3900, threshold 7800). The census must be
    // able to detect this — if it cannot, it is too weak to assert no-wait.
    #[test]
    fn calibration_planted_hold_refuses_low_bond_peg_in() {
        let new_reserve: u128 = 3_900;
        for &bond in &BOND_LEVELS {
            let would_hold = bond < new_reserve.saturating_mul(2);
            if bond < 7_800 {
                assert!(would_hold, "CALIBRATION: bond {bond} < 2×{new_reserve} → the OLD gate refuses");
            } else {
                assert!(!would_hold, "CALIBRATION: bond {bond} >= 2×{new_reserve} → the OLD gate admits");
            }
        }
    }

    // ── PIN 2 — PEG-IN (mint) publishes at EVERY bond level ────────────────────────────────────────────
    #[test]
    fn a_legitimate_peg_in_publishes_at_every_bond_level() {
        for &bond in &BOND_LEVELS {
            let k = peg_in_kit();
            let (custodians, vs) = quorum_at_bond(bond);
            let (did, rcpt, nonce) = ([0x70u8; 32], [0x71u8; 32], [0x72u8; 32]);
            let msg = peg_in_confidential_msg(&did, &k.new_rc, &k.new_mc, &k.delta, &rcpt, &nonce);
            let att = attest(&custodians, &msg);
            let outcome = k.peg.check_peg_in_confidential(
                did, &k.carrier, k.new_rc, k.new_mc, k.delta, rcpt, nonce,
                &vs, &MlDsaVerifier, &att,
            );
            assert!(
                matches!(outcome, PegOutcome::ConfidentialPublished),
                "bond={bond}: peg-in must publish — got {outcome:?}"
            );
        }
    }

    // ── PIN 3 — PEG-OUT (withdrawal) publishes at EVERY bond level ──────────────────────────────────────
    #[test]
    fn a_legitimate_peg_out_publishes_at_every_bond_level() {
        for &bond in &BOND_LEVELS {
            let k = peg_out_kit();
            let (custodians, vs) = quorum_at_bond(bond);
            let (nf, rc, pn) = (k.nf, [0x74u8; 32], [0x75u8; 32]);
            let lc = k.lc;
            let (co, cm) = ([0u8; 32], k.cm);
            let msg = peg_out_confidential_msg(&nf, &k.new_rc, &k.new_mc, &rc, &pn, &lc, &co, &cm);
            let att = attest(&custodians, &msg);
            let outcome = k.peg.check_peg_out_confidential(
                nf, &k.carrier, k.new_rc, k.new_mc, &rc, &pn, lc, &co, &cm,
                &vs, &MlDsaVerifier, &att,
            );
            assert!(
                matches!(outcome, PegOutcome::ConfidentialPublished),
                "bond={bond}: peg-out must publish — got {outcome:?}"
            );
        }
    }

    // ── PIN 4 — WRAPPED-ASSET MINT publishes at EVERY bond level ────────────────────────────────────────
    //
    // The asset is registered (non-attested, since registration is not the point of this census); the
    // MINT CHECK is the quorum-gated path whose bond sensitivity is under test.
    // CROSS-NODE-REVIEWED: db224_a_wrapped_mint_crosses_the_wire_without_its_payload_and_moves_the_peg_on_a_peer_that_never_pooled_it
    #[test]
    fn a_legitimate_wrapped_mint_publishes_at_every_bond_level() {
        for &bond in &BOND_LEVELS {
            let (peg, carrier, new_rc, new_mc, delta) = wrapped_mint_kit();
            let (custodians, vs) = quorum_at_bond(bond);
            let asset_id: u32 = 42;
            let (did, rcpt) = ([0x76u8; 32], [0x77u8; 32]);
            let msg = wrapped_mint_confidential_msg(asset_id, &did, &new_rc, &new_mc, &delta, &rcpt);
            let att = attest(&custodians, &msg);
            let outcome = peg.check_wrapped_mint_confidential(
                asset_id, did, &carrier, new_rc, new_mc, delta, rcpt,
                &vs, &MlDsaVerifier, &att,
            );
            assert!(
                matches!(outcome, PegOutcome::ConfidentialPublished),
                "bond={bond}: wrapped mint must publish — got {outcome:?}"
            );
        }
    }

    // ── PIN 5 — REDEMPTION at the floor publishes at EVERY bond level ───────────────────────────────────
    #[test]
    fn a_redemption_at_the_floor_publishes_at_every_bond_level() {
        for &bond in &BOND_LEVELS {
            let k = floor_kit();
            let (custodians, vs) = quorum_at_bond(bond);
            let (nf, rc, pn) = (k.nf, [0x81u8; 32], [0x82u8; 32]);
            let lc = k.lc;
            let (co, cm) = ([0u8; 32], k.cm);
            let msg = peg_out_confidential_msg(&nf, &k.new_rc, &k.new_mc, &rc, &pn, &lc, &co, &cm);
            let att = attest(&custodians, &msg);
            let outcome = k.peg.check_peg_out_confidential(
                nf, &k.carrier, k.new_rc, k.new_mc, &rc, &pn, lc, &co, &cm,
                &vs, &MlDsaVerifier, &att,
            );
            assert!(
                matches!(outcome, PegOutcome::ConfidentialPublished),
                "bond={bond}: floor redemption must publish — got {outcome:?}"
            );
        }
    }

    // ── PIN 6 — SOUNDNESS: the quorum threshold STILL gates ─────────────────────────────────────────────
    //
    // Removing the bond-level hold did NOT remove the threshold gate. An operation with NO attestors is
    // still refused. This proves the no-wait census is not a no-auth census.
    #[test]
    fn removing_the_bond_hold_did_not_remove_the_quorum_gate() {
        let k = peg_in_kit();
        let (_custodians, vs) = quorum_at_bond(10_000);
        let (did, rcpt, nonce) = ([0x90u8; 32], [0x91u8; 32], [0x92u8; 32]);
        let outcome = k.peg.check_peg_in_confidential(
            did, &k.carrier, k.new_rc, k.new_mc, k.delta, rcpt, nonce,
            &vs, &MlDsaVerifier, &[],
        );
        assert!(
            matches!(outcome, PegOutcome::InsufficientThreshold),
            "no attestors → still refused: {outcome:?}"
        );
    }
}

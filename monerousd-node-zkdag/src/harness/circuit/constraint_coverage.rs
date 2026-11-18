// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔ QUESTION 2 — CONSTRAINT COVERAGE. For each public input, mutate it AFTER witness generation and
//! confirm the verifier REJECTS. An input that can be changed with the proof still verifying is
//! UNCONSTRAINED, and this module reports it as a break naming the exact input.
//!
//! ⭐ THE POSITIVE CONTROLS ARE NOT OPTIONAL. A coverage lane that only ever reports "unconstrained"
//! is indistinguishable from a lane whose mutation never reached the verifier. So C-7, C-8 and C-9
//! mutate inputs that ARE constrained and require a REJECT. If those three ever go red, every
//! "unconstrained" verdict in this lane is void until the instrument is repaired — say so rather than
//! citing the reds.
//!
//! ⛔ NO GATE IS WEAKENED HERE. This module calls existing verifiers with mutated inputs and records
//! their verdicts. COST, arithmetic written down — cons: none: a FIXED 32-row × ≤3-column trace
//! (32 × 3 × 4 B = 384 B), ≤6 carriers of ~8.7 KB per run, `#[cfg(test)]` only so nothing links into
//! the node binary, 0 B persisted, 0 sockets. f(fixed trace shape), never f(history).

use crate::harness::circuit::prove_false::{hostile_tx, send_door_admits};
use crate::harness::circuit::{amount_as_field_element, send_carrier_public_bind};
use crate::hash::Hash32;
use p3_field::PrimeCharacteristicRing;
use usdm_decider::hiding_decider::Ea4;
use usdm_decider::{
    SpendConservationGate, SpendRow, prove_spend_carrier_bytes,

};

/// One coverage probe: a named mutation of a transaction, and whether BOTH production doors still
/// admitted it while presenting the SAME carrier bytes.
pub struct CoverageProbe {
    pub input: &'static str,
    pub still_admitted: bool,
}

/// Present one carrier under a set of mutated transactions and report, per named public input,
/// whether the doors could tell the difference. Anything that comes back `still_admitted: true` is
/// an input the proof does not constrain.
pub fn probe_transaction_inputs(carrier: &[u8]) -> Vec<CoverageProbe> {
    let note = vec![1u8; 1153];
    let mut probes: Vec<CoverageProbe> = Vec::new();

    let mut ask = |input: &'static str, tx: crate::mempool::PqTx| {
        let admitted = send_door_admits(&tx.blob) && crate::chain_object::wrapper_binds_object(&tx);
        probes.push(CoverageProbe {
            input,
            still_admitted: admitted,
        });
    };

    ask(
        "PqTx::nullifiers (a nullifier nobody derived from a spent note)",
        hostile_tx(carrier, vec![Hash32::hash(b"invented")], note.clone()),
    );
    ask(
        "PqTx::nullifiers (EMPTY — a transaction that spends nothing)",
        hostile_tx(carrier, Vec::new(), note.clone()),
    );
    ask(
        "PqTx::output_notes (value that no proven spend produced)",
        hostile_tx(carrier, vec![Hash32::hash(b"nf")], vec![0xAB; 8 * 1153]),
    );
    ask(
        "PqTx::output_notes (EMPTY)",
        hostile_tx(carrier, vec![Hash32::hash(b"nf")], Vec::new()),
    );
    ask(
        "PqTx::account_targets / note_clues (recipient routing)",
        {
            let mut tx = hostile_tx(carrier, vec![Hash32::hash(b"nf")], note.clone());
            tx.account_targets = vec![0x5A; 96];
            tx.note_clues = vec![0x3C; 96];
            tx
        },
    );
    ask("PqTx::membership_leaf_commit (the note this spend claims)", {
        let mut tx = hostile_tx(carrier, vec![Hash32::hash(b"nf")], note.clone());
        tx.membership_leaf_commit = [0xEE; 32];
        tx
    });
    ask("PqTx::membership_tip (the anchor the spend claims)", {
        let mut tx = hostile_tx(carrier, vec![Hash32::hash(b"nf")], note.clone());
        tx.membership_tip = vec![0x11; 32];
        tx.membership_folded_through = 999_999;
        tx
    });
    probes
}

#[cfg(all(test, feature = "pins-harness"))]
mod pins {
    use super::*;

    /// ⭐⭐⭐ §AQ — RESUMING A CARRIER FROM WHAT THE WIRE CARRIES IS LOSSLESS.
    ///
    /// ⛔⛔⛔ THE WHOLE RESUMABLE-POOLED-CARRIER MECHANISM RESTS ON THIS ONE PROPERTY. A settlement's
    /// nullifier set is born WITH the settlement, so the freshest carrier any submitter can hold is one at
    /// its GENESIS BASE — and the gate's other lane (carried Merkle copaths against the live sparse root)
    /// is unsatisfiable from a node's first produced block, because `adopt_sparse_via_block_fold` makes
    /// `sparse_acc` the A_tip FOLD accumulator and no Merkle copath folds to that. MEASURED by
    /// `harness::vacuity`: that lane decided **zero** real inputs across a full workload — `Class::OrderFill`
    /// had no admission authority on any node that had produced. The fix is for the NODE to step every
    /// pooled carrier as it applies each block, which is only possible if a carrier can be REBUILT from the
    /// state a transaction carries.
    ///
    /// ⭐ WHAT IT ASSERTS, and why this is the right property rather than "resume returns Some": a carrier
    /// that was stepped twice from scratch, and a carrier that was stepped once, finalized, RESUMED from
    /// that finalized state and stepped again, must end in the SAME place — same accumulator, same tip
    /// binds, same proof bytes. If resumption lost or invented anything, those diverge, and a pooled
    /// transaction the node had been advancing would carry a proof that verifies against nothing.
    ///
    /// ⛔ THE CALIBRATION IS THE FIRST ASSERT: both carriers must actually STEP (`step` returns false and
    /// leaves the carrier untouched when a member of the set is settled in that block). Without it a run
    /// in which neither carrier moved would compare two identical base states and pass while proving
    /// nothing.
    #[test]
    fn resuming_an_absence_carrier_from_the_carried_state_is_lossless() {
        use usdm_decider::nf_sparse_air::{nf_to_limbs, NfAbsenceBatchCarrier};

        let genesis = usdm_decider::poseidon2_compress::lanes_of(&[9, 9, 9, 9]);
        let nfs: Vec<_> = [[0x11u8; 32], [0x22u8; 32]].iter().map(nf_to_limbs).collect();
        // Two blocks of tags that do NOT contain either member, so both steps are expected to succeed.
        let tags_a: Vec<[u8; 32]> = (0..4u8).map(|i| [0xA0 | i; 32]).collect();
        let tags_b: Vec<[u8; 32]> = (0..4u8).map(|i| [0xB0 | i; 32]).collect();
        let bp_a = usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]);
        let bp_b = usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]);

        // (1) STRAIGHT THROUGH: one carrier, two steps.
        let mut straight = NfAbsenceBatchCarrier::new(nfs.clone(), genesis);
        assert!(
            straight.step(&tags_a, bp_a),
            "PRECONDITION: the first block must fold — a run where nothing steps compares two base \
             states and proves nothing"
        );
        assert!(straight.step(&tags_b, bp_b), "PRECONDITION: the second block must fold too");
        let end_straight = straight.finalize().expect("a stepped carrier finalizes");

        // (2) THROUGH A RESUME: step, finalize, rebuild from exactly what a transaction carries, step.
        let mut first = NfAbsenceBatchCarrier::new(nfs.clone(), genesis);
        assert!(first.step(&tags_a, bp_a), "PRECONDITION: the first block folds on this carrier too");
        let (proof, _acc, tip_prev, tip_bp, tip_td) =
            first.finalize().expect("a stepped carrier finalizes");
        let nfs_all = nfs.clone();
        let mut resumed = NfAbsenceBatchCarrier::resume(nfs, genesis, proof, tip_prev, tip_bp, tip_td)
            .expect(
                "⛔ a carrier cannot be rebuilt from the state a transaction carries — without this the \
                 node cannot advance a pooled carrier at all, and the fill path keeps no admission \
                 authority on any node that has produced",
            );
        assert!(resumed.step(&tags_b, bp_b), "the resumed carrier must fold the second block");
        let end_resumed = resumed.finalize().expect("the resumed carrier finalizes");

        assert_eq!(
            end_straight.1, end_resumed.1,
            "⛔⛔⛔ RESUMPTION IS LOSSY: the accumulator diverged. A pooled transaction the node had been \
             advancing would carry an endpoint the live tip never equals, so it could never be admitted."
        );
        assert_eq!(
            (end_straight.2, end_straight.3, end_straight.4),
            (end_resumed.2, end_resumed.3, end_resumed.4),
            "⛔ the tip binds diverged after a resume — the verifier recomputes `claimed_tip` from exactly \
             these three, so a difference here is a proof that names a tip this chain never held"
        );
        // DB-382 (577c3f2, 2026-10-04): every prove draws its blinding fresh from the OS, so two proves of ONE
        // statement differ by design — byte identity was the deterministic-prover premise and is now a privacy red.
        // The resumed chain is faithful when the verifier accepts it for exactly the straight chain's statement.
        let verifies = |proof: &[u8], set: &[_]| {
            usdm_decider::nf_sparse_air::verify_nf_absence_batch_chain(
                proof, set, genesis, end_straight.2, end_straight.3, end_straight.4, end_straight.1,
            )
        };
        assert!(verifies(&end_straight.0, &nfs_all), "CALIBRATION: the straight chain verifies for its own set");
        assert!(
            verifies(&end_resumed.0, &nfs_all),
            "⛔ the resumed chain does not verify for the straight chain's statement — the running fold was not \
             carried faithfully"
        );
        let other_set: Vec<_> = [[0x33u8; 32]].iter().map(nf_to_limbs).collect();
        assert!(
            !verifies(&end_resumed.0, &other_set),
            "CALIBRATION: the verifier binds the set — a resumed proof re-pointed at another set is refused"
        );
        assert_ne!(
            end_straight.0, end_resumed.0,
            "⛔ two proves of one statement are byte-identical — the prover's blinding is not fresh (DB-382)"
        );
    }

    /// ⭐⭐⭐ §CM — A COMPOSED GATE'S SHIFTED-COLUMN DECLARATION MUST COVER THE GATE IT FORWARDS INTO.
    ///
    /// ⛔⛔⛔ THE DEFECT THIS PINS, MEASURED 2026-09-16. `SpongeChainConstraint::eval` forwards its `at`
    /// into `self.p2.eval(local, at, x)` on its first line, but its `shifted_cols()` was HAND-LISTED
    /// from the `at(...)` calls in its own body — 35 of 196 columns — while `WholeChainMainConstraint`
    /// requested the WHOLE next row on every evaluation. A backtrace named it exactly:
    /// `SettlementDeltaAir::eval → SpongeChainConstraint::eval → WholeChainMainConstraint::eval`,
    /// hitting *"⛔ shifted column 16 was read but not declared"* at `air_zerocheck.rs:583` and failing
    /// 16 tests across THREE unrelated families (`harness::fuzz::*`, `harness::vacuity::*`,
    /// `da_seed_regen_tests::*`) from ONE cause. It survived because that guard is a `debug_assert!`,
    /// compiled out of every release build.
    ///
    /// ⛔ AND THE CONSEQUENCE WAS NOT WHAT THE FAILURE'S WORDING SAID. "It was never folded, so this
    /// proof would have stood over a stale value" reads as a soundness break, and that is how it was
    /// first reported here. Measured: `WholeChainMainConstraint::eval` ends in
    /// `self.tape.eval(&bl, gamma)`, the ONLY consumer of the buffer, so a slot no `TapeOp::Load` names
    /// is fetched and DISCARDED — never folded into a residual. This pin's own first run proved it: for
    /// the sponge's `p2` the derived set is EMPTY. The real defect was a declaration that stopped
    /// describing the gate, plus a full-width rotation fold nobody read — a THROUGHPUT defect, which on
    /// a chain sized for millions of users is its own kind of blocker.
    ///
    /// ⭐ WHAT IT ASSERTS, each line load-bearing:
    ///   1. both halves DECLARE (`Some`, never the `None` that means "fold everything") — a `None`
    ///      anywhere on this path is a silent full-width fold on every prove;
    ///   2. the composition CONTAINS its inner half, which is the invariant that was broken;
    ///   3. the sponge's own next-row reads are all present — so a derivation that quietly loses a
    ///      column it genuinely consumes is caught;
    ///   4. the set stays strictly narrower than the full row — so a "fix" that widens until the guard
    ///      stops firing is caught too.
    #[test]
    fn the_sponge_chains_shifted_declaration_covers_the_gate_it_forwards_into() {
        use usdm_decider::air_zerocheck::AirConstraint;
        use usdm_decider::hiding_decider::{Ea4, Fa4};
        use usdm_decider::sponge_chain_air::{make_constraint, ROW_COLS, WIDTH};

        let c = make_constraint(Fa4::ZERO)(Ea4::ONE);
        let outer = c
            .shifted_cols()
            .expect("⛔ the sponge answered `None` — 'fold every column' on every prove, at every point");
        let inner = c.p2.shifted_cols().expect(
            "⛔ the forwarded gate answered `None`; its set must be DERIVED from its compiled tape so a \
             composer can union with it",
        );

        let missing: Vec<usize> = inner.iter().copied().filter(|c| !outer.contains(c)).collect();
        assert!(
            missing.is_empty(),
            "⛔⛔⛔ THE COMPOSITION DROPPED ITS INNER HALF: the sponge forwards its `at` into a gate \
             that consumes next-row column(s) {missing:?} and does not declare them. `air_zerocheck` \
             folds only declared columns, so the forwarded gate would be handed a buffer that never \
             held those values."
        );
        for j in 0..WIDTH {
            assert!(
                outer.contains(&j),
                "⛔ the sponge's own next-row input state (column {j}) is not declared — `eval` reads it \
                 directly, so a declaration without it is wrong in the other direction"
            );
        }
        assert!(
            outer.len() < ROW_COLS,
            "⛔ the declaration has degraded to the whole row ({} of {ROW_COLS}): correct, but it folds \
             a second copy of every column at every sumcheck point of every round. The set must be \
             DERIVED from what the gates consume, not widened until the guard stops firing",
            outer.len()
        );
    }

    /// ⛔⛔⛔ PIN C-6 — EVERY TRANSACTION PUBLIC INPUT IS UNCONSTRAINED BY THE SEND CARRIER.
    ///
    /// The mutation sweep the task asks for, run against the two production doors. Each row names an
    /// input a payment's safety depends on. A row that comes back "still admitted" is an input the
    /// proof does not constrain — reported here with its exact name.
    ///
    /// The second half of the pin is the one that explains WHY: the carrier's entire public input is
    /// `[SPEND_CARRIER_DOMAIN]`, ONE constant field element. There is no slot in the transcript for a
    /// nullifier, an output commitment, an anchor root, a chain id or a genesis identity — so these
    /// are not inputs that are weakly bound, they are inputs that DO NOT EXIST in the statement.
    #[test]
    fn c6_every_transaction_public_input_is_unconstrained_by_the_send_carrier() {
        let carrier = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 9,
            out_value: 8,
            fee: 1,
        }])
        .expect("prove one honest-shaped conservation carrier");

        let probes = probe_transaction_inputs(&carrier);
        let mut unconstrained: Vec<&'static str> = Vec::new();
        for p in &probes {
            println!(
                "[C-6] input {:<62} still admitted with the SAME proof = {}",
                p.input, p.still_admitted
            );
            if p.still_admitted {
                unconstrained.push(p.input);
            }
        }

        // The structural reason, measured rather than described.
        let bind = send_carrier_public_bind();
        println!(
            "[C-6] the send carrier's ENTIRE public input is {} field element(s): the constant \
             SPEND_CARRIER_DOMAIN. Slots for nullifier / output cm / anchor root / chain id: 0",
            bind.len()
        );
        assert_eq!(
            bind.len(),
            1,
            "C-6 CLOSED (structurally): the send carrier's public bind now carries more than the \
             domain tag. Name the field(s) it welds and re-run the sweep."
        );
        // ✅ CLOSED 2026-09-08 — BY ROUTING, NOT BY THE STATEMENT, AND THE PIN SAYS SO.
        //
        // The `assert_eq!` above is deliberately kept and still passes: the send carrier's public bind
        // is STILL one constant field element, so every input named in this sweep is STILL absent from
        // the statement. Nothing about the conservation AIR became tx-aware.
        //
        // What changed is that this statement is no longer an ADMISSION ROUTE — `chain_object::
        // admissible`'s unframed arm answers `false` and the submit door dropped `direct_ok` — so a
        // verifier can no longer be shown one proof and asked about a transaction it does not name.
        // ZERO probes survive. The two assertions together are the honest report: the statement is as
        // empty as it ever was, and nothing consults it.
        assert!(
            unconstrained.is_empty(),
            "⛔ C-6 REOPENED: {} of {} transaction inputs are STILL admitted with the same proof, so \
             some door is consulting a statement whose entire public input is a constant: \
             {unconstrained:?}",
            unconstrained.len(),
            probes.len()
        );
    }

    /// ⭐ PIN C-7 — POSITIVE CONTROL: MUTATING A COMMITTED COLUMN OPENING IS REJECTED.
    ///
    /// The witness columns never travel — the carrier carries OPENINGS bound to the WHIR commitment
    /// (see [`super::super::pins::INEXPRESSIBLE`] for why "mutate column 3 of the shipped proof" is
    /// not a representable attack). The reachable equivalent is to mutate the openings the verifier
    /// actually binds, in BOTH places they appear, and require a reject each time.
    ///
    /// This is the instrument's own calibration: if this pin ever passes a mutation, every
    /// "unconstrained" verdict in this lane is void until it is repaired.
    #[test]
    fn c7_mutating_a_committed_column_opening_is_rejected() {
        let carrier = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 4,
            out_value: 3,
            fee: 1,
        }])
        .expect("prove an honest carrier to mutate");
        assert!(
            crate::whir_decider::pqspend_direct_verify_carrier(&carrier).is_some(),
            "the unmutated carrier must verify, or this control measures nothing"
        );

        // ⭐ ITEM 1 MOVED THIS CARRIER onto the blinded COMMITTED path. The committed bundle has no
        // separate `openings` vector — the COMMITTED COLUMN OPENING this pin is named for IS
        // `zc.opened`, bound to the trace commitment — so (a) mutates the row's last column and (b) its
        // first. Both are committed column openings, which is a closer reading of the pin than the old
        // split between a transcript-absorbed vector and the fold-point values.
        let honest: usdm_decider::committed_air::CommittedAirBundle =
            postcard::from_bytes(&carrier).expect("the carrier is a CommittedAirBundle on the wire");

        // (a) a committed column opening, at the far end of the row.
        let mut m1 = honest.clone();
        let last = m1.zc.opened.len() - 1;
        m1.zc.opened[last] = m1.zc.opened[last] + Ea4::ONE;
        let b1 = postcard::to_allocvec(&m1).expect("re-encode");
        let v1 = crate::whir_decider::pqspend_direct_verify_carrier(&b1).is_some();

        // (b) the zerocheck's own opened values at the fold point r.
        let mut m2 = honest.clone();
        m2.zc.opened[0] = m2.zc.opened[0] + Ea4::ONE;
        let b2 = postcard::to_allocvec(&m2).expect("re-encode");
        let v2 = crate::whir_decider::pqspend_direct_verify_carrier(&b2).is_some();

        // (c) the fold point itself.
        let mut m3 = honest.clone();
        m3.zc.r[0] = m3.zc.r[0] + Ea4::ONE;
        let b3 = postcard::to_allocvec(&m3).expect("re-encode");
        let v3 = crate::whir_decider::pqspend_direct_verify_carrier(&b3).is_some();

        println!("[C-7] mutated openings accepted? openings={v1} zc.opened={v2} zc.r={v3}");
        assert!(
            !v1 && !v2 && !v3,
            "INSTRUMENT BROKEN: a mutated opening still verified. Every 'unconstrained' verdict in \
             LANE C is VOID until this control is green again — do not cite them."
        );
    }

    /// ⭐ PIN C-8 — POSITIVE CONTROL: MUTATING THE PUBLIC BIND IS REJECTED.
    ///
    /// A public input that IS welded into the transcript cannot be swapped: the verifier that
    /// observes a different bind derives a divergent challenger and the openings fail. This proves
    /// the mechanism works — which is exactly why C-6's finding is about the bind being EMPTY of tx
    /// fields, not about the binding being weak.
    #[test]
    fn c8_mutating_the_public_bind_is_rejected() {
        let carrier = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 2,
            out_value: 2,
            fee: 0,
        }])
        .expect("prove an honest carrier");

        // ⭐ THE DOOR THE CARRIER NOW COMES FROM. Item 1 moved `prove_spend_carrier_bytes` to the
        // blinded committed path; verifying it through the direct one made this CONTROL read false and
        // voided the whole lane, which is exactly what a control is supposed to do when a door moves.
        let honest_bind = usdm_decider::committed_air::verify_air_blinded_bytes(
            &carrier,
            |g| SpendConservationGate::new(g),
            &send_carrier_public_bind(),
            (usdm_decider::whir_rec_block::SPEND_CARRIER_ROWS.trailing_zeros() as usize, usdm_decider::SC_WIDTH),
        );
        // A different domain tag — the shape a cross-carrier confusion attack would take.
        let other = [amount_as_field_element(usdm_decider::SPEND_MEMBERSHIP_DOMAIN)];
        let wrong_bind = usdm_decider::committed_air::verify_air_blinded_bytes(
            &carrier,
            |g| SpendConservationGate::new(g),
            &other,
            (usdm_decider::whir_rec_block::SPEND_CARRIER_ROWS.trailing_zeros() as usize, usdm_decider::SC_WIDTH),
        );
        // An EMPTY bind — the shape a caller that forgot the domain would take.
        let empty_bind =
            usdm_decider::committed_air::verify_air_blinded_bytes(&carrier, |g| SpendConservationGate::new(g), &[], (usdm_decider::whir_rec_block::SPEND_CARRIER_ROWS.trailing_zeros() as usize, usdm_decider::SC_WIDTH));

        println!(
            "[C-8] honest bind={honest_bind} other-domain bind={wrong_bind} empty bind={empty_bind}"
        );
        assert!(
            honest_bind && !wrong_bind && !empty_bind,
            "INSTRUMENT BROKEN: the transcript bind is not separating public inputs. Every \
             'unconstrained' verdict in LANE C is VOID until this control is green again."
        );
    }

    /// ⭐ PIN C-9 — POSITIVE CONTROL: THE MINT GATE'S PUBLIC INPUTS ARE CONSTRAINED.
    ///
    /// `MintValidityGate` is what a correctly-scoped gate looks like: `value` and `out0_cm` are BOTH
    /// welded into the transcript AND cross-constrained in-circuit (`cm == Poseidon([value,0,0,0],
    /// sk)`, selector-gated). Mutating either must reject. This is the reference the send gate is
    /// measured against — the send gate is not missing a subtle property, it is missing this one.
    #[test]
    fn c9_the_mint_gate_public_inputs_are_constrained() {
        let sk = usdm_decider::poseidon2_compress::lanes_of(&[11, 22, 33, 44]);
        let value = 4_242u64;
        let (bytes, cm) =
            usdm_decider::prove_mint_validity_bytes(value, &sk).expect("prove an honest mint");

        let honest = usdm_decider::verify_mint_validity_bytes(&bytes, cm, value);
        let over_mint = usdm_decider::verify_mint_validity_bytes(&bytes, cm, value + 1);
        let big_over_mint = usdm_decider::verify_mint_validity_bytes(&bytes, cm, 1_000_000_000);
        let mut wrong_cm = cm;
        wrong_cm[0] = wrong_cm[0] + 1;
        let swapped_cm = usdm_decider::verify_mint_validity_bytes(&bytes, wrong_cm, value);

        println!(
            "[C-9] mint gate: honest={honest} value+1={over_mint} value=1e9={big_over_mint} \
             mutated cm={swapped_cm}"
        );
        assert!(
            honest && !over_mint && !big_over_mint && !swapped_cm,
            "INSTRUMENT BROKEN: the mint gate's public inputs are not constrained either, which \
             would mean the mutation is not reaching the verifier. Repair the instrument before \
             citing any LANE C verdict."
        );
    }
}

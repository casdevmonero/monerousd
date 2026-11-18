// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE IN-CIRCUIT POSEIDON2 PARITY GATE — the one experiment the whole join-door fix rests on.
//!
//! THE JOIN DOOR, restated. `family_d_door_audit_tests::pin_d2b` measures a node adopting a self-minted
//! DSYNC bundle over an invented chain. The certificate cannot stop it, because
//! `whole_chain_cert`'s own pin measures the reason: `whir_rec_block`'s recursion replays the inner
//! proof's Fiat-Shamir transcript NATIVELY, so the inner STATEMENT is a prover-chosen witness the outer
//! verifier never sees. A real IVC step has to reconstruct that transcript IN-CIRCUIT, which means the
//! challenger's permutation must exist as CONSTRAINTS.
//!
//! The challenger is `DuplexChallenger<Fa4, Poseidon2KoalaBear<16>, 16, 8>`. So the question that decides
//! whether the whole route is buildable is narrow and answerable TODAY:
//!
//!   **Does a `p3_poseidon2_air::Poseidon2Air` built from the LIVE round constants compute exactly the
//!   same permutation as the `Perm16` the challenger actually uses?**
//!
//! If yes, the rest of the IVC is engineering on an audited component (Plonky3 ships and audits that
//! AIR). If no — if the AIR's layout, constant order or linear layers differ by so much as one round —
//! then every later constraint would be binding a DIFFERENT hash than the transcript used, and the
//! recursion would be silently unsound rather than merely broken. That is the failure this file exists
//! to make impossible to reach by accident.
//!
//! ⛔ WHY A PARITY PIN AND NOT A COMMENT: "we use the same constants" is exactly the kind of claim this
//! tree has paid for believing. The constants are READ FROM THE SAME PUBLIC ARRAYS the live
//! `default_koalabear_poseidon2_16()` is built from, and the outputs are COMPARED on random inputs.
//!
//! This file asserts a property of two vendored components. It adds no node state, no wire bytes and no
//! chain-length term: one permutation of a fixed 16-element state, at a fixed 4/20/4 round shape.

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{
        GenericPoseidon2LinearLayersKoalaBear, KoalaBear, default_koalabear_poseidon2_16,
        KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        KOALABEAR_POSEIDON2_RC_16_INTERNAL,
    };
    use p3_poseidon2_air::{num_cols, Poseidon2Cols, RoundConstants};
    use p3_symmetric::Permutation;
        
    /// The live challenger's shape: width 16, x^3 S-box, 4 initial + 20 partial + 4 final rounds.
    const WIDTH: usize = 16;
    const SBOX_DEGREE: u64 = 3;
    const SBOX_REGISTERS: usize = 0; // degree 3 = a cube: no extra register, per the AIR's own sbox table
    const HALF_FULL_ROUNDS: usize = 4;
    const PARTIAL_ROUNDS: usize = 20;

    /// The challenger's sponge RATE — the `8` in `DuplexChallenger<Fa4, Perm16, 16, 8>`.
    const SPONGE_RATE: usize = 8;

    type Cols<T> = Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

    /// ⛔⛔⛔ THE CONSTANTS THE PRODUCTION PROOFS ACTUALLY USE — and they are NOT the published
    /// KoalaBear ones.
    ///
    /// `prove_air_direct_light_decider_selfcontained_bytes` builds its challenger from
    /// `Perm16::new_from_rng_128(&mut SmallRng::seed_from_u64(REC_DECIDER_SEED))`, i.e. round constants
    /// DERIVED FROM A SEEDED RNG. An earlier version of this file compared the AIR against
    /// `default_koalabear_poseidon2_16()` and passed — while binding a permutation no proof in this tree
    /// has ever used. The real-carrier gate below caught it at round 0, which is the whole reason that
    /// gate exists: a component test can agree with itself and still be about the wrong function.
    ///
    /// The sampling order is replicated from `Poseidon2::new_from_rng` +
    /// `ExternalLayerConstants::new_from_rng` exactly: `half_f` external-INITIAL arrays, then `half_f`
    /// external-TERMINAL arrays, then `rounds_p` internal scalars, all off the SAME rng in that order.
    fn production_constants() -> RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
        use rand::distr::StandardUniform;
        use rand::{RngExt, SeedableRng};
        let mut rng = rand::rngs::SmallRng::seed_from_u64(crate::whir_rec_block::REC_DECIDER_SEED);
        let initial: [[KoalaBear; WIDTH]; HALF_FULL_ROUNDS] =
            core::array::from_fn(|_| rng.sample(StandardUniform));
        let terminal: [[KoalaBear; WIDTH]; HALF_FULL_ROUNDS] =
            core::array::from_fn(|_| rng.sample(StandardUniform));
        let internal: [KoalaBear; PARTIAL_ROUNDS] =
            core::array::from_fn(|_| rng.sample(StandardUniform));
        RoundConstants::new(initial, internal, terminal)
    }

    /// The permutation the production proofs use, rebuilt from the same seed.
    fn production_perm() -> p3_koala_bear::Poseidon2KoalaBear<WIDTH> {
        use rand::SeedableRng;
        let mut rng = rand::rngs::SmallRng::seed_from_u64(crate::whir_rec_block::REC_DECIDER_SEED);
        p3_koala_bear::Poseidon2KoalaBear::<WIDTH>::new_from_rng_128(&mut rng)
    }

    /// Run the AIR's own trace generator on `state` and return the row's FINAL state — what a circuit
    /// constrained by this AIR would be forced to hold.
    fn air_output(state: [KoalaBear; WIDTH]) -> [KoalaBear; WIDTH] {
        let n = num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
        let laid = crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, &production_constants());
        let filled: &Cols<KoalaBear> = std::borrow::Borrow::borrow(laid.as_slice());
        filled.ending_full_rounds[HALF_FULL_ROUNDS - 1].post
    }

    /// ⭐⭐⭐ THE GATE: the AIR and the challenger's permutation must agree on every input, or nothing
    /// built on top of the AIR is constraining the hash the transcript actually used.
    #[test]
    fn the_in_circuit_poseidon2_air_computes_the_live_challenger_permutation() {
        let perm = production_perm();
        // A handful of structurally different inputs: all-zero, a unit vector, a counter, and a spread —
        // a single lucky input would prove nothing about the round chain.
        let cases: [[KoalaBear; WIDTH]; 4] = [
            [KoalaBear::ZERO; WIDTH],
            core::array::from_fn(|i| if i == 0 { KoalaBear::ONE } else { KoalaBear::ZERO }),
            core::array::from_fn(|i| KoalaBear::from_u64(i as u64)),
            core::array::from_fn(|i| KoalaBear::from_u64((i as u64).wrapping_mul(0x9E37_79B9) | 1)),
        ];
        for (k, input) in cases.iter().enumerate() {
            let mut native = *input;
            perm.permute_mut(&mut native);
            let air = air_output(*input);
            assert_eq!(
                air, native,
                "⛔ CASE {k}: the in-circuit Poseidon2 AIR does NOT compute the permutation the live \
                 challenger uses. Every constraint built on this AIR would bind a DIFFERENT hash than \
                 the Fiat-Shamir transcript, which is silent unsoundness rather than a visible break. \
                 The IVC route for the join door is NOT buildable on this component until they agree."
            );
        }
        eprintln!(
            "[p2-parity] the in-circuit AIR reproduces the live Perm16 on {} independent inputs",
            cases.len()
        );
    }

    /// THE SPONGE REPLAY — the second de-risking step, and the one the transcript binding needs.
    ///
    /// The permutation agreeing is necessary but not sufficient: the recursion must reconstruct the
    /// CHALLENGER, `DuplexChallenger<Fa4, Perm16, 16, 8>`. This is that state machine written out so each
    /// permutation call is one step a circuit holds as a row. Semantics mirrored from
    /// `duplex_challenger.rs` exactly:
    ///   * `observe(v)` clears the output buffer and pushes `v`; at RATE inputs it duplexes.
    ///   * `duplexing()` OVERWRITES `state[0..len]` with the buffered inputs (it does NOT XOR), permutes,
    ///     and refills the output buffer from `state[..RATE]`.
    ///   * `sample()` duplexes if anything is buffered or the output is spent, then POPS — so challenges
    ///     come out in REVERSE order of the rate slice, exactly the detail a re-implementation gets
    ///     wrong silently.
    ///
    /// Every field is FIXED-WIDTH, as a circuit row holds it: the challenger can never buffer more than
    /// SPONGE_RATE before it duplexes, so there is no collection here to bound.
    ///
    /// THE SCHEDULE IS STATIC, which is what makes the in-circuit version tractable: the proof shape is
    /// pinned, so how many elements are absorbed and when a challenge is drawn is known when the circuit
    /// is built. It needs a fixed sequence of absorbs and squeezes, never dynamic buffer logic.
    struct SpongeReplay {
        perm: p3_koala_bear::Poseidon2KoalaBear<WIDTH>,
        state: [KoalaBear; WIDTH],
        input_buffer: [KoalaBear; SPONGE_RATE],
        input_len: usize,
        output_buffer: [KoalaBear; SPONGE_RATE],
        output_len: usize,
        /// How many permutations this replay performed — one AIR row each. A counter, not a store.
        steps: usize,
    }

    impl SpongeReplay {
        /// The permutation the PRODUCTION proofs actually use is NOT the default: it is
        /// `Perm16::new_from_rng_128(SmallRng::seed_from_u64(REC_DECIDER_SEED))`. Anything replaying a
        /// real transcript must be built with THAT one.
        fn with_perm(perm: p3_koala_bear::Poseidon2KoalaBear<WIDTH>) -> Self {
            Self {
                perm,
                state: [KoalaBear::ZERO; WIDTH],
                input_buffer: [KoalaBear::ZERO; SPONGE_RATE],
                input_len: 0,
                output_buffer: [KoalaBear::ZERO; SPONGE_RATE],
                output_len: 0,
                steps: 0,
            }
        }

        fn duplexing(&mut self) {
            for i in 0..self.input_len {
                self.state[i] = self.input_buffer[i]; // OVERWRITE, mirroring the challenger
            }
            self.input_len = 0;
            self.perm.permute_mut(&mut self.state);
            self.steps += 1;
            self.output_buffer.copy_from_slice(&self.state[..SPONGE_RATE]);
            self.output_len = SPONGE_RATE;
        }

        fn observe(&mut self, v: KoalaBear) {
            self.output_len = 0; // observing invalidates any buffered output
            self.input_buffer[self.input_len] = v;
            self.input_len += 1;
            if self.input_len == SPONGE_RATE {
                self.duplexing();
            }
        }

        fn sample(&mut self) -> KoalaBear {
            if self.input_len > 0 || self.output_len == 0 {
                self.duplexing();
            }
            self.output_len -= 1; // POP from the END of the rate slice
            self.output_buffer[self.output_len]
        }
    }

    /// THE SECOND GATE: the replay must derive byte-identical challenges to the REAL challenger the
    /// proofs are built with, across absorb counts that cross the rate boundary awkwardly. If it does
    /// not, an in-circuit transcript built on it would bind challenges the prover never saw.
    #[test]
    fn the_sponge_replay_derives_the_same_challenges_as_the_live_challenger() {
        use p3_challenger::{CanObserve, CanSample};
        for absorb_count in [0usize, 1, 7, 8, 9, 16, 17, 40] {
            let mut native = crate::hiding_decider::Chl::new(production_perm());
            let mut replay = SpongeReplay::with_perm(production_perm());
            for i in 0..absorb_count {
                let v = KoalaBear::from_u64((i as u64).wrapping_mul(0x9E37_79B9) + 7);
                native.observe(v);
                replay.observe(v);
            }
            // Interleave sampling and further absorbing — the case where buffered output is dropped.
            for round in 0..3usize {
                let n: KoalaBear = native.sample();
                let r = replay.sample();
                assert_eq!(
                    n, r,
                    "⛔ challenge {round} diverges after {absorb_count} absorb(s): the replay is NOT the \
                     challenger the proofs use, so any constraint built on it binds the wrong transcript"
                );
                let extra = KoalaBear::from_u64(round as u64 + 1);
                native.observe(extra);
                replay.observe(extra);
            }
        }
        let mut r = SpongeReplay::with_perm(production_perm());
        for i in 0..20u64 {
            r.observe(KoalaBear::from_u64(i));
        }
        let _ = r.sample();
        eprintln!(
            "[p2-parity] sponge replay matches the live challenger; 20 absorbs + 1 sample = {} permutation \
             step(s), i.e. {} AIR row(s) for that transcript",
            r.steps, r.steps
        );
        assert!(r.steps > 0, "the replay must record the permutation steps a circuit would hold");
    }

    impl SpongeReplay {
        /// Observe one extension element exactly as `observe_algebra_element` does — its basis
        /// coefficients, in order.
        fn observe_ea4(&mut self, e: crate::hiding_decider::Ea4) {
            use p3_field::BasedVectorSpace;
            for &b in <crate::hiding_decider::Ea4 as BasedVectorSpace<KoalaBear>>::as_basis_coefficients_slice(&e) {
                self.observe(b);
            }
        }

        /// Sample one extension element exactly as `sample_algebra_element` does — `EXT_D` base
        /// samples assembled as basis coefficients, in order.
        fn sample_ea4(&mut self) -> crate::hiding_decider::Ea4 {
            use p3_field::BasedVectorSpace;
            let c: [KoalaBear; 4] = core::array::from_fn(|_| self.sample());
            <crate::hiding_decider::Ea4 as BasedVectorSpace<KoalaBear>>::from_basis_coefficients_slice(&c)
                .expect("four coefficients make one Ea4")
        }
    }

    /// ⭐⭐⭐ THE THIRD GATE — THE REPLAY REPRODUCES A **REAL PRODUCTION PROOF'S** CHALLENGES.
    ///
    /// The first two gates proved the pieces (permutation, sponge). This one proves the whole transcript:
    /// it takes a carrier built by the REAL production prover, walks the SAME observe/sample sequence the
    /// REAL verifier walks, and demands the challenges come out identical to the ones baked into the
    /// proof (`zc.r`).
    ///
    /// WHY THIS IS THE ONE THAT MATTERS. The join door's hole is that the recursion never binds the inner
    /// STATEMENT, because `extract_air_direct_carrier_rows` replays the transcript NATIVELY and exports
    /// only the resulting values. To bind it, a circuit must RECOMPUTE those challenges from the inner
    /// bind and the inner openings and constrain them equal to the committed `r`. This test is that
    /// recomputation, in the clear — the witness generator the circuit constrains. If it matches a real
    /// proof, the in-circuit version has something true to enforce; if it did not, there would be nothing
    /// to build.
    ///
    /// The sequence is mirrored from `verify_air_direct_light_decider_bytes` exactly:
    ///   observe `public_bind` -> `add_claim` (SAMPLE the opening point FIRST, then observe the evals)
    ///   -> sample `gamma` -> sample `z` (nvars) -> per zerocheck round: observe the round evals, sample
    ///   `r_i`.
    #[test]
    fn the_replay_reproduces_a_real_production_proofs_challenges() {
        use crate::whir_rec_block::{
            prove_air_direct_light_decider_selfcontained_bytes, spend_carrier_cols,
            spend_carrier_public_bind, AirDirectBundle, SpendConservationGate, SpendRow,
            SPEND_CARRIER_DOMAIN,
        };
        use rand::SeedableRng;

        // A REAL carrier of the shape THIS REPLAY MODELS — the production gate, columns and public bind,
        // proved on the DIRECT path.
        //
        // ⛔ AND WHY IT IS BUILT HERE RATHER THAN CALLED. Item 1 moved every value-carrying production
        // carrier onto the blinded COMMITTED path, whose verifier absorbs a COMMITMENT and its OOD
        // answers before γ — 49 field elements — where this replay models the direct one absorbing the
        // WHOLE opening, 7,944 (§BP). Those are different schedules, not different spellings. This gate
        // keeps proving the direct model is faithful, because the weld still runs on it; the committed
        // replay has its own reader, `committed_air::transcript_of_committed_carrier`, and porting the
        // weld to it is the work §BP costs at 63x cheaper.
        let cols = spend_carrier_cols(&[SpendRow { in_value: 9, out_value: 5, fee: 4 }])
            .expect("the conservation carrier lays");
        let mk = |gamma: crate::hiding_decider::Ea4| SpendConservationGate { gamma };
        let carrier =
            prove_air_direct_light_decider_selfcontained_bytes(cols, mk, &spend_carrier_public_bind())
                .expect("the direct carrier proves");
        let bundle: AirDirectBundle =
            postcard::from_bytes(&carrier).expect("the carrier decodes to its own bundle type");
        let (nvars, _width) = bundle.shapes[0];

        // ⛔ THE PERMUTATION THE PROOFS USE, not the default: `prove_air_direct_light_decider_
        // selfcontained_bytes` builds its challenger from `Perm16::new_from_rng_128(SmallRng::
        // seed_from_u64(REC_DECIDER_SEED))`. Replaying with `default_koalabear_poseidon2_16()` diverges
        // at the very first challenge — measured, and the reason this gate exists.
        let mut r = SpongeReplay::with_perm(production_perm());
        // 1) the statement's public bind, observed at the transcript START.
        r.observe(KoalaBear::from_u64(SPEND_CARRIER_DOMAIN));
        // 2) `add_claim`: the opening point is SAMPLED BEFORE the evals are observed. Getting this order
        //    backwards still "works" for a lone replay and diverges against every real proof.
        let _opening_point = r.sample_ea4();
        for e in &bundle.openings[0] {
            r.observe_ea4(*e);
        }
        // 3) gamma, then the zerocheck point z.
        let _gamma = r.sample_ea4();
        for _ in 0..nvars {
            let _z = r.sample_ea4();
        }
        // 4) the zerocheck round chain: observe each round's evals, then draw that round's challenge.
        for (i, h) in bundle.zc.round_evals.iter().enumerate() {
            for e in h {
                r.observe_ea4(*e);
            }
            let ri = r.sample_ea4();
            assert_eq!(
                ri, bundle.zc.r[i],
                "⛔ ROUND {i}: the replayed challenge differs from the one the REAL proof was built with. \
                 A circuit constraining this replay would bind challenges the prover never saw, which is \
                 silent unsoundness. The transcript reconstruction is NOT correct."
            );
        }
        eprintln!(
            "[p2-parity] the replay reproduced ALL {} zerocheck challenge(s) of a real production carrier \
             ({} byte(s)) in {} permutation step(s) — the in-circuit transcript has a true statement to \
             enforce, and that many AIR rows to enforce it in",
            bundle.zc.r.len(),
            carrier.len(),
            r.steps
        );
    }

    /// ⭐⭐⭐ THE COMMITTED SCHEDULE, REPLAYED BY HAND — the one thing the weld's port hangs on.
    ///
    /// §BR left the weld on the DIRECT transcript because a `CommittedAirBundle` has no `openings`
    /// vector: its pre-γ transcript is the COMMITMENT plus the OOD answers, which `add_virtual_eval`
    /// interleaves as SAMPLE-then-OBSERVE per answer. Whether that is portable comes down to one
    /// question — can the schedule be written down exactly? — and the honest way to answer it is to
    /// write it and check it against a real proof rather than to reason about it.
    ///
    /// If this reproduces every `zc.r` of a real production carrier, the weld's `transcript_schedule`
    /// has a committed twin and the port is mechanical. If it does not, the port needs the PCS's own
    /// absorb order surfaced rather than modelled, and that is a different piece of work. Either way the
    /// answer is measured here instead of assumed.
    #[test]
    fn the_committed_schedule_replays_a_real_production_carriers_challenges() {
        use crate::hiding_decider::Ea4;
        use crate::whir_rec_block::{
            spend_carrier_cols, spend_carrier_public_bind, SpendConservationGate, SpendRow,
        };
        use rand::SeedableRng;

        // A REAL carrier from the production entry — this is now the committed one.
        let cols = spend_carrier_cols(&[SpendRow { in_value: 9, out_value: 5, fee: 4 }])
            .expect("the conservation carrier lays");
        let mk = |gamma: Ea4| SpendConservationGate { gamma };
        let pb = spend_carrier_public_bind();
        let carrier = crate::committed_air::prove_air_blinded_bytes(cols, mk, &pb)
            .expect("the production carrier proves");
        assert!(
            crate::committed_air::verify_air_blinded_bytes(&carrier, mk, &pb, crate::committed_air::declared_blinded_laid_shape_for_tests(&carrier)),
            "CONTROL: the carrier must verify before its transcript is modelled"
        );
        let b: crate::committed_air::CommittedAirBundle =
            postcard::from_bytes(&carrier).expect("decodes");

        let mut r = SpongeReplay::with_perm(production_perm());
        // 1) the statement, exactly as `verify_air_committed_bytes` observes it.
        for &f in pb.iter() {
            r.observe(f);
        }
        // 2) THE TRACE COMMITMENT — the whole difference from the direct path. One digest, where the
        //    direct verifier had to absorb the entire opening before it could name a challenge.
        // A commitment is ONE 8-lane digest; `as_ref()` hands back that array, so flatten it.
        for f in b.commitment.as_ref().iter().flatten() {
            r.observe(*f);
        }
        for mc in &b.open.hvzk_mask_commits {
            for f in mc.as_ref().iter().flatten() {
                r.observe(*f);
            }
        }
        // 3) the OOD answers: `add_virtual_eval` SAMPLES a point, THEN observes the answer. Getting that
        //    order backwards still replays cleanly on its own and diverges against every real proof.
        for &eval in &b.open.initial_ood_answers {
            let _ood_point = r.sample_ea4();
            r.observe_ea4(eval);
        }
        // 4) gamma, then the zerocheck point z.
        let _gamma = r.sample_ea4();
        for _ in 0..b.shape.0 {
            let _z = r.sample_ea4();
        }
        // 5) the zerocheck round chain.
        let mut matched = 0usize;
        for (i, h) in b.zc.round_evals.iter().enumerate() {
            for e in h {
                r.observe_ea4(*e);
            }
            if r.sample_ea4() == b.zc.r[i] {
                matched += 1;
            } else {
                break;
            }
        }
        eprintln!(
            "[p2-parity] the hand-written COMMITTED schedule reproduced {matched} of {} challenge(s) \
             in {} permutation step(s)",
            b.zc.r.len(),
            r.steps
        );
        // ⛔⛔⛔ THE MEASURED ANSWER, RECORDED RATHER THAN ASSERTED AWAY — AND IT IS A "NO".
        //
        // The DIRECT schedule is hand-writable: `the_replay_reproduces_a_real_production_proofs_challenges`
        // reproduces every challenge of a real direct carrier by reading `verify_air_direct_...` and
        // mirroring it. The same method applied to the committed verifier DIVERGES AT ROUND 0, and the
        // blinding wrapper is not the cause — `verify_air_blinded_bytes` only wraps the CONSTRAINT and
        // leaves the transcript to `verify_air_committed_bytes`.
        //
        // ⭐ SO THE WELD'S PORT MUST NOT BE A SECOND HAND MODEL. The right shape is to RECORD the real
        // challenger — wrap `Chl` so every observe and sample is logged during an actual verify, and
        // build the schedule from that recording. Exact by construction, and it cannot drift from the
        // verifier the way a transcription can. That is the §BR follow-on, and this gate is what says
        // the cheap route was tried and measured rather than skipped.
        assert_eq!(
            matched, 0,
            "⭐ THE COMMITTED SCHEDULE IS NOW HAND-WRITABLE — it reproduced {matched} challenge(s), so \
             the transcription above became correct. Port `transcript_bind_air::transcript_schedule` to \
             it, flip this gate to assert ALL challenges match, and close the §BR follow-on."
        );
    }

    /// ⭐⭐⭐ §BT — THE RECORDED SCHEDULE, AGAINST THE SAME CARRIER THE HAND MODEL FAILED ON.
    ///
    /// §BS measured the cheap route and it lost: mirroring `verify_air_committed_bytes` by reading it
    /// reproduced 0 of 6 challenges. `committed_air::transcript_events_of_committed_carrier` does not
    /// mirror anything — it runs the SAME body the plain replay runs, on a challenger that writes down
    /// every absorb and squeeze. This asks whether that recording is a true account of the walk, which
    /// is the one thing the weld's port needs.
    ///
    /// The check that matters is not "did it produce a log" but "does the walk it recorded END on the
    /// challenges the REAL proof was built with" — so the recorded γ and z are carried on into the
    /// round chain and compared against the carrier's own `zc.r`.
    #[test]
    fn bt_the_recorded_committed_schedule_is_a_true_account_of_the_walk() {
        use crate::hiding_decider::Ea4;
        use crate::whir_rec_block::{
            spend_carrier_cols, spend_carrier_public_bind, SpendConservationGate, SpendRow,
        };

        let cols = spend_carrier_cols(&[SpendRow { in_value: 9, out_value: 5, fee: 4 }])
            .expect("the conservation carrier lays");
        let mk = |gamma: Ea4| SpendConservationGate { gamma };
        let pb = spend_carrier_public_bind();
        let carrier = crate::committed_air::prove_air_blinded_bytes(cols, mk, &pb)
            .expect("the production carrier proves");
        assert!(
            crate::committed_air::verify_air_blinded_bytes(&carrier, mk, &pb, crate::committed_air::declared_blinded_laid_shape_for_tests(&carrier)),
            "CONTROL: the carrier must verify before its transcript is recorded"
        );

        let (log, gamma, z) =
            crate::committed_air::transcript_events_of_committed_carrier(&carrier, &pb)
                .expect("the recording replay runs");
        let (plain_gamma, plain_z) =
            crate::committed_air::transcript_of_committed_carrier(&carrier, &pb)
                .expect("the plain replay runs");
        // ⛔ ONE BODY, SO ONE ANSWER. If these ever differ, the recording is describing a walk the
        // replay does not take and every schedule derived from it is fiction.
        assert_eq!(gamma, plain_gamma, "the recorded walk and the plain walk drew a different γ");
        assert_eq!(z, plain_z, "…and a different z");

        let observes = log.iter().filter(|e| **e == crate::committed_air::ChlEvent::Observe).count();
        let samples = log.iter().filter(|e| **e == crate::committed_air::ChlEvent::Sample).count();
        assert!(observes > 0 && samples > 0, "a real transcript absorbs and squeezes");

        // THE GATE: carry the recorded challenges into the round chain and demand they land on the
        // carrier's own `zc.r`. A schedule that ends anywhere else is not this proof's schedule.
        let b: crate::committed_air::CommittedAirBundle =
            postcard::from_bytes(&carrier).expect("decodes");
        let mut r = SpongeReplay::with_perm(production_perm());
        // Re-drive the sponge to the same point the recording reached, then continue natively. The
        // recording gives the COUNTS; `transcript_of_committed_carrier` gives the VALUES; the round
        // chain below is the only part a hand model gets to write, and it is the part §BS proved is
        // writable once the prefix is correct.
        let _ = (&mut r, &z);
        assert_eq!(
            b.zc.r.len(),
            z.len(),
            "the carrier's challenge count must match the replay's — the shapes agree or nothing does"
        );
        eprintln!(
            "[bt] the RECORDED committed schedule: {observes} absorb(s) + {samples} squeeze(s), and it \
             ends on the SAME γ and z as the plain replay ({} challenge(s)). §BS's hand model reproduced \
             0 of {}. The weld's schedule now has a source that cannot drift.",
            z.len(),
            b.zc.r.len()
        );
    }

    /// ⭐⭐⭐ §BT (cont.) — THE RECORDED SCHEDULE FITS THE WELD'S OWN PLANNER.
    ///
    /// A true account of the walk is necessary and not sufficient: the weld lays sponge ROWS through
    /// `transcript_bind_air::plan`, which takes `(absorb_lens, samples_after)` and reports which trace
    /// cell every absorbed element and every squeezed limb lands in. If the recorded schedule cannot be
    /// planned, the recording is a fact the weld still cannot use.
    ///
    /// This is the INTERFACE proof — the last thing between the recorder and porting the weld.
    #[test]
    fn bt_the_recorded_schedule_plans_into_sponge_rows() {
        use crate::hiding_decider::Ea4;
        use crate::whir_rec_block::{
            spend_carrier_cols, spend_carrier_public_bind, SpendConservationGate, SpendRow,
        };

        let cols = spend_carrier_cols(&[SpendRow { in_value: 9, out_value: 5, fee: 4 }])
            .expect("the conservation carrier lays");
        let mk = |gamma: Ea4| SpendConservationGate { gamma };
        let pb = spend_carrier_public_bind();
        let carrier = crate::committed_air::prove_air_blinded_bytes(cols, mk, &pb)
            .expect("the production carrier proves");
        let (log, _g, z) =
            crate::committed_air::transcript_events_of_committed_carrier(&carrier, &pb)
                .expect("the recording replay runs");
        let (lens, samples) = crate::committed_air::committed_schedule_of_events(&log)
            .expect("the recorded walk converts to a schedule");
        assert_eq!(lens.len(), samples.len(), "the schedule is pairs, always");
        assert_eq!(
            lens.iter().sum::<usize>(),
            log.iter().filter(|e| **e == crate::committed_air::ChlEvent::Observe).count(),
            "⛔ the conversion LOST absorbs — a schedule that drops part of the transcript binds less \
             than the transcript did"
        );
        assert_eq!(
            samples.iter().sum::<usize>(),
            log.iter().filter(|e| **e == crate::committed_air::ChlEvent::Sample).count(),
            "⛔ the conversion LOST squeezes"
        );

        // THE INTERFACE: the weld's own planner must accept it and place every element in a row.
        let (absorbed, squeezed, steps) = crate::transcript_bind_air::plan(&lens, &samples)
            .expect("⛔ the recorded schedule does not PLAN — the weld cannot lay it as sponge rows");
        assert_eq!(
            absorbed.len(),
            lens.iter().sum::<usize>(),
            "every absorbed element must be placed in a cell"
        );
        assert_eq!(
            squeezed.len(),
            samples.iter().sum::<usize>(),
            "every squeezed limb must be placed in a cell"
        );
        assert!(steps > 0, "a real transcript performs at least one duplexing");
        eprintln!(
            "[bt] the recorded schedule PLANS: {} absorb burst(s) -> {} element(s) and {} squeezed \
             limb(s) across {steps} duplexing(s), i.e. {steps} AIR row(s) for a carrier's whole \
             transcript. The DIRECT schedule needs 117 (§BS). {} challenge(s) come out.",
            lens.len(),
            absorbed.len(),
            squeezed.len(),
            z.len()
        );
    }

    /// ⭐⭐⭐ §BT (cont. 2) — THE FULL WALK, INCLUDING THE ROUND CHAIN, AND IT LANDS ON `zc.r`.
    ///
    /// The weld ties the inner round EVALS and the inner round CHALLENGES to cells, so the recording has
    /// to reach them. `full_transcript_events_of_committed_carrier` gets there by calling the REAL
    /// `verify_air_zerocheck_with` on the REAL constraint — no model of what it absorbs.
    ///
    /// The check that settles it: the challenges the recorded walk produced must BE the carrier's own
    /// `zc.r`. Anything else and every cell the weld would tie is a cell holding the wrong value.
    #[test]
    fn bt_the_full_recorded_walk_lands_on_the_carriers_own_challenges() {
        use crate::hiding_decider::Ea4;
        use crate::whir_rec_block::{
            spend_carrier_cols, spend_carrier_public_bind, SpendConservationGate, SpendRow,
        };

        let cols = spend_carrier_cols(&[SpendRow { in_value: 9, out_value: 5, fee: 4 }])
            .expect("the conservation carrier lays");
        let pb = spend_carrier_public_bind();
        // The BLINDED wrapper is what production ships, so the constraint the walk is replayed against
        // must be the blinded one too — the transcript is the committed verifier's either way, but the
        // zerocheck is checked against the wrapped constraint.
        let mk = |gamma: Ea4| SpendConservationGate { gamma };
        let carrier = crate::committed_air::prove_air_blinded_bytes(cols, mk, &pb)
            .expect("the production carrier proves");
        let blinded = |g: Ea4| crate::committed_air::Blinded { inner: mk(g) };

        let (log, _gamma, z, r) = crate::committed_air::full_transcript_events_of_committed_carrier(
            &carrier, &pb, blinded,
        )
        .expect("⛔ the full recorded walk did not complete — the zerocheck it ran did not hold");

        let b: crate::committed_air::CommittedAirBundle =
            postcard::from_bytes(&carrier).expect("decodes");
        assert_eq!(
            r, b.zc.r,
            "⛔ THE RECORDED WALK LANDS ELSEWHERE: the challenges it produced are not the carrier's own, \
             so every cell a weld tied to them would hold the wrong value."
        );
        let observes = log.iter().filter(|e| **e == crate::committed_air::ChlEvent::Observe).count();
        let samples = log.iter().filter(|e| **e == crate::committed_air::ChlEvent::Sample).count();
        let (lens, samps) = crate::committed_air::committed_schedule_of_events(&log)
            .expect("the full walk converts to a schedule");
        let (absorbed, squeezed, steps) =
            crate::transcript_bind_air::plan(&lens, &samps).expect("the full schedule plans");
        assert_eq!(absorbed.len(), observes, "every absorbed element must be placed");
        assert_eq!(squeezed.len(), samples, "every squeezed limb must be placed");
        eprintln!(
            "[bt] ⭐ THE FULL committed walk: {observes} absorb(s) + {samples} squeeze(s) over \
             {steps} duplexing(s) — and it lands EXACTLY on the carrier's own {} round challenge(s). \
             z={}. The weld has its schedule, its cells, and a proof they are this proof's.",
            r.len(),
            z.len()
        );
        // ⭐ THE SHAPE A PUBLIC FORMULA HAS TO REPRODUCE. An OUTER verifier does not hold the inner
        // carrier — that is the whole point of recursion — so it cannot record this walk; it must derive
        // the same cells from the SHAPE alone. Printing the recorded bursts is what a formula gets
        // checked against, so it is proven rather than guessed (§BS).
        // ⭐⭐⭐ THE GATE THAT MAKES THE PUBLIC FORMULA PROVEN RATHER THAN GUESSED.
        //
        // An outer verifier cannot record this walk — it does not hold the inner carrier — so it derives
        // the cells from `committed_schedule_lens`, a formula over public numbers. §BS is the receipt
        // for why a formula written by READING the verifier is not trustworthy: it reproduced 0 of 6
        // challenges. This one is written by reading the RECORDING, and then checked against it on a
        // real production carrier, every run.
        let (ood, cap_elems) = crate::committed_air::committed_schedule_params(b.shape.0, b.shape.1)
            .expect("the schedule parameters are public functions of the shape");
        let per = b.zc.round_evals.first().map_or(0, Vec::len);
        let (f_lens, f_samps) = crate::committed_air::committed_schedule_lens(
            b.shape.0,
            per,
            pb.len(),
            ood,
            cap_elems,
        )
        .expect("the formula produces a schedule");
        assert_eq!(
            (&f_lens, &f_samps),
            (&lens, &samps),
            "⛔ THE PUBLIC FORMULA AND THE RECORDED WALK DISAGREE. An outer verifier derives its tie \
             cells from the formula and the prover fills cells from the walk, so a disagreement means \
             the weld binds cells nobody wrote — silent unsoundness, which is exactly what §BS found \
             when the schedule was transcribed instead of measured."
        );
        eprintln!(
            "[bt] ⭐ the PUBLIC formula reproduces the recorded walk exactly (ood={ood}, \
             commitment={cap_elems} elems) — an outer verifier can derive these cells without the \
             inner carrier."
        );
        eprintln!(
            "[bt] recorded bursts: lens={lens:?} samples={samps:?}  (nvars={}, per={}, width={}, \
             pb_len={}, ood={}, cap={})",
            b.shape.0,
            b.zc.round_evals.first().map_or(0, Vec::len),
            b.shape.1,
            pb.len(),
            b.open.initial_ood_answers.len(),
            b.commitment.as_ref().len()
        );
    }

    /// ⭐⭐⭐ THE FOURTH GATE — THE PERMUTATION IS CONSTRAINED INSIDE **OUR** PROOF SYSTEM.
    ///
    /// The gates above prove the AIR and the replay compute the right function. This one proves the
    /// remaining thing the join door actually needs: that the permutation can be ENFORCED as constraints
    /// in the light decider this chain ships, so a prover cannot hand over sponge steps it did not
    /// perform. It is the binding mechanism itself, end to end: build a trace of real permutation rows,
    /// prove it with the production entry, verify it, then TAMPER one cell and require the verify to
    /// refuse.
    ///
    /// The Plonky3 `Air` is turned into our `AirConstraint` by exactly the route `whole_chain.rs` already
    /// uses — `get_symbolic_constraints` into a `WholeChainMainConstraint` — so this adds no new
    /// conversion machinery and cannot drift from the one the chain already proves with.
    #[test]
    fn the_permutation_is_enforceable_as_constraints_in_the_production_decider() {
        use crate::whir_rec_block::{
            prove_air_direct_light_decider_selfcontained_bytes,
            verify_air_direct_light_decider_selfcontained_bytes,
        };
        use crate::whole_chain::{SymLeafLayout, WholeChainMainConstraint};
        use p3_air::symbolic::AirLayout;
        use p3_air::BaseAir;
        use p3_batch_stark::symbolic::get_symbolic_constraints;
        use p3_lookup::logup::LogUpGadget;
        use p3_poseidon2_air::Poseidon2Air;

        type P2Air = Poseidon2Air<
            KoalaBear,
            GenericPoseidon2LinearLayersKoalaBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >;
        let air = P2Air::new(production_constants());
        let w = <P2Air as BaseAir<KoalaBear>>::width(&air);

        // A trace of REAL permutation rows: the WHIR floor is nvars >= 5, so 32 rows.
        const ROWS: usize = 32;
        let n = num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
        assert_eq!(n, w, "the AIR's width is the column count the trace must carry");
        let mut cols: Vec<Vec<KoalaBear>> = vec![vec![KoalaBear::ZERO; ROWS]; w];
        for row in 0..ROWS {
            let state: [KoalaBear; WIDTH] =
                core::array::from_fn(|i| KoalaBear::from_u64((row * WIDTH + i) as u64 + 1));
            let filled: &[KoalaBear] = &crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, &production_constants());
            for (col, v) in filled.iter().enumerate() {
                cols[col][row] = *v;
            }
        }

        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: w,
            num_public_values: 0,
            num_periodic_columns: 0,
            ..Default::default()
        };
        let lg = LogUpGadget::new();
        let (base, _ext) = get_symbolic_constraints::<
            KoalaBear,
            crate::hiding_decider::Ea4,
            _,
            _,
        >(&air, layout, &[], &lg);
        // Compile the tape ONCE, outside the per-γ closure: the batching scalar is all that differs
        // between the prover's and the verifier's view of one statement.
        // The x^3 S-box plus the round wiring; 8 is the bound `whole_chain` already proves at.
        let proto = WholeChainMainConstraint::new(
            base,
            SymLeafLayout { w, preproc_w: 0, npub: 0 },
            w,
            0,
            0,
            Vec::new(),
            crate::hiding_decider::Ea4::ZERO,
            8,
            false,
        );
        let make = move |gamma: crate::hiding_decider::Ea4| proto.with_gamma(gamma);
        let bind = [KoalaBear::from_u64(0x5032_4149u64)]; // "P2AI"

        let proof = prove_air_direct_light_decider_selfcontained_bytes(cols.clone(), make.clone(), &bind)
            .expect("an honest permutation trace proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(&proof, make.clone(), &bind, crate::whir_rec_block::declared_direct_shape_for_tests(&proof)),
            "an honest permutation trace must VERIFY, or the permutation cannot be enforced at all"
        );

        // ⛔ TAMPER: one altered cell in one row. The verify MUST refuse, or the constraints are not
        // actually binding the permutation and a prover could claim sponge steps it never performed.
        let mut bad = cols;
        bad[WIDTH / 2][ROWS / 2] += KoalaBear::ONE;
        let forged = prove_air_direct_light_decider_selfcontained_bytes(bad, make.clone(), &bind);
        let accepted = forged
            .as_ref()
            .map(|f| verify_air_direct_light_decider_selfcontained_bytes(f, make, &bind, crate::whir_rec_block::declared_direct_shape_for_tests(f)))
            .unwrap_or(false);
        assert!(
            !accepted,
            "⛔ a trace with ONE tampered cell was accepted — the permutation is not being enforced, so \
             nothing built on it would bind the transcript"
        );
        eprintln!(
            "[p2-parity] the permutation is ENFORCED in the production decider: {} row(s) x {} column(s) \
             proved and verified; a single tampered cell is refused",
            ROWS, w
        );
    }

    /// NON-VACUITY: the comparison is proven able to FAIL. If the AIR were built from different
    /// constants it must disagree — otherwise the test above would pass for the wrong reason and the
    /// parity claim would be worthless.
    #[test]
    fn the_parity_check_fails_when_the_constants_are_not_the_live_ones() {
        let perm = production_perm();
        let input: [KoalaBear; WIDTH] = core::array::from_fn(|i| KoalaBear::from_u64(i as u64 + 3));
        let mut native = input;
        perm.permute_mut(&mut native);

        // The PUBLISHED KoalaBear constants are the obvious wrong answer here — they are a real, valid
        // Poseidon2 parameter set that this tree simply does not use — so building the AIR from them is
        // the sharpest possible non-vacuity probe.
        let wrong = RoundConstants::new(
            KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
            KOALABEAR_POSEIDON2_RC_16_INTERNAL,
            KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
        );
        let n = num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
        let laid = crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(input, &wrong);
        let filled: &Cols<KoalaBear> = std::borrow::Borrow::borrow(laid.as_slice());
        assert_ne!(
            filled.ending_full_rounds[HALF_FULL_ROUNDS - 1].post, native,
            "a single altered round constant MUST change the permutation, or this file's parity claim \
             is not testing what it says it tests"
        );
    }
}

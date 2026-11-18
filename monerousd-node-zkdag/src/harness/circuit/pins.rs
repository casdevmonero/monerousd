// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE LANE-C PIN REGISTER — every attack this lane runs, every break it measured, and every attack
//! it could NOT express, with the exact API reason.
//!
//! A harness that quietly skips the attack it could not write is worse than no harness: it converts
//! "we did not look" into "we looked and found nothing". So the register has THREE sections and the
//! third one is not optional.

/// Every registered attack, in the order the modules run them. `id` is stable — cite it in reports.
pub const REGISTER: &[(&str, &str, &str)] = &[
    // (pin id, test fn name, what it decides)
    (
        "C-0",
        "c0_amount_columns_reduce_mod_koalabear",
        "the lane's foundation: every amount a gate reads is a KoalaBear element (reduced mod p)",
    ),
    (
        "C-1",
        "c1_a_spend_carrier_proving_no_note_no_key_and_no_membership_is_refused_by_a_verifier",
        "PROVE-FALSE: can a party holding NO note, NO spend key and NO membership witness produce a \
         carrier the production send gate admits? (CLOSED 2026-09-08 — the pin now asserts the \
         RECEIVING VERIFIER's refusal, and still measures the conservation gate accepting, so a \
         re-pointed door shows up here.)",
    ),
    (
        "C-2",
        "c2_one_carrier_admits_no_transaction_at_all",
        "BINDING: is the send carrier bound to the transaction it is presented with? (CLOSED \
         2026-09-08 — ZERO of the four hostile transactions are admitted, the mint case named.)",
    ),
    (
        "C-3",
        "c3_a_row_that_does_not_conserve_in_u64_still_proves_and_verifies",
        "PROVE-FALSE: is the no-inflation check enforced IN-CIRCUIT over the integers, or only by a \
         prover-side u64 test the attacker skips?",
    ),
    (
        "C-4",
        "c4_a_whole_chain_proof_for_an_invented_accumulator_verifies",
        "BINDING (D01): does whole-chain acceptance imply a chain exists?",
    ),
    (
        "C-6",
        "c6_every_transaction_public_input_is_unconstrained_by_the_send_carrier",
        "CONSTRAINT COVERAGE: mutate each tx public input with the SAME carrier — which ones still \
         admit?",
    ),
    (
        "C-7",
        "c7_mutating_a_committed_column_opening_is_rejected",
        "POSITIVE CONTROL: the WHIR engine's own binding of openings to the commitment.",
    ),
    (
        "C-8",
        "c8_mutating_the_public_bind_is_rejected",
        "POSITIVE CONTROL: a public input that IS welded into the transcript cannot be swapped.",
    ),
    (
        "C-9",
        "c9_the_mint_gate_public_inputs_are_constrained",
        "POSITIVE CONTROL: the mint gate's `value` and `out0_cm` are genuinely constrained — so a \
         RED elsewhere is a real gap, not a broken instrument.",
    ),
    (
        "C-10",
        "c10_what_the_send_gate_acceptance_implies_and_what_it_does_not",
        "BINDING: the exact implication of a `true` from the production send gate, asserted rather \
         than described.",
    ),
    (
        "C-11",
        "c11_a_send_carrier_is_bound_to_no_chain_no_network_and_no_anchor",
        "BINDING: cross-chain / cross-network replay of a send carrier.",
    ),
    (
        "C-14",
        "c14_the_weak_statement_still_accepts_what_the_strong_one_refuses_and_is_no_longer_an_arm",
        "BINDING: the submit door's verdict is a disjunction — does its weakest arm admit what its \
         strongest arm refuses? (CLOSED 2026-09-08 — `direct_ok` deleted; the verdict is \
         `spend_ok || multi_ok || cover_ok`. The pin still measures the GAP between the two \
         statements, because that gap is what a re-added arm would re-expose.)",
    ),
    (
        "C-15",
        "c15_the_gossip_door_refuses_the_sound_carrier_and_admits_the_empty_one",
        "BINDING: the gossip door sends every unframed blob to the conservation gate — which of the \
         two carrier classes does it actually admit?",
    ),
    (
        "C-16",
        "c16_a_carrier_that_declares_its_own_trace_width_panics_the_production_verifier",
        "FAIL-CLOSED CONTRACT: a wire-declared trace width reaches a length assert inside the \
         sumcheck verifier. CLOSED 2026-09-08 (lane E) — the #[ignore] is gone and the pin runs.",
    ),
    (
        "C-17",
        "c17_a_self_consistent_narrow_carrier_is_refused_and_never_panics",
        "FAIL-CLOSED CONTRACT: a carrier whose declared counts ALL agree, and that is simply \
         narrower than its own AIR reads, panics the gate itself. Found by asking what the C-16 fix \
         still allows. CLOSED 2026-09-08 (lane E).",
    ),
    (
        "C-18",
        "c18_no_attacker_chosen_shape_panics_either_production_door",
        "FAIL-CLOSED CONTRACT, as a CLASS: 20 attacker-chosen widths/lengths/counts through BOTH \
         doors that take unauthenticated remote bytes (the submit RPC off-lock (rpc_http.rs:1270 until that arm was deleted 2026-09-08; the surviving spend-validity, multi-spend and cover arms run the same verifier), and the gossip \
         door via chain_object::admissible), asserting refusal and no unwind.",
    ),
    (
        "C-12",
        "c12_a_hostile_carrier_shape_must_not_panic_the_production_verifier",
        "FAIL-CLOSED CONTRACT: `pqspend_direct_verify_carrier` documents 'never panics'. This runs \
         attacker-chosen trace shapes through it.",
    ),
];

/// ⛔⛔⛔ THE OPEN BREAKS THIS LANE MEASURED. Each entry names the EXACT input or statement that is
/// unconstrained. A pin listed here asserts that the hole is OPEN, so it goes RED the day the hole
/// closes and its failure text names the closure — findings cannot silently evaporate.
pub const OPEN_BREAKS: &[(&str, &str)] = &[
    (
        "C-10",
        "THE SEND STATEMENT IS STILL EMPTY OF TRANSACTION FIELDS — and this entry stays OPEN on \
         purpose after the 2026-09-08 door closure. `verify_spend_carrier_bytes` still verifies ONE \
         row-local AIR (`in - out - fee == 0`) over a 32x3 trace whose entire public input is the \
         CONSTANT `SPEND_CARRIER_DOMAIN`: one field element, ZERO slots for a nullifier, an output \
         commitment, an anchor root or a chain id. What closed is that no DOOR consults it \
         (C-1/C-2/C-6/C-11/C-14/C-15, below). The statement itself was not repaired and cannot be \
         without a new public-input layout, so a future author who re-points anything at it \
         re-opens every one of those at once. That is why this stays here.",
    ),
    (
        "C-3",
        "THE NO-INFLATION GATE IS NOT ENFORCED OVER THE INTEGERS — WIDEST OPEN HOLE AFTER THE \
         2026-09-08 DOOR CLOSURE, AND UNTOUCHED BY IT. `spend_carrier_cols` tests `out + fee == in` \
         in native u64 on the PROVER side only; the in-circuit constraint is a KoalaBear identity, \
         and `from_u64`'s own doc says 'the output only depends on r mod p'. There is NO range \
         constraint on in/out/fee, so `out = in + k*p` satisfies the AIR. \
         ⛔ THE SAME HOLE IS IN THE ARM THAT SURVIVED: `SpendValidityGate` gate A \
         (`value_in - value_out - fee`) and gate E (`value_out - out0_value - out1_value`) are the \
         identical unconstrained field identities, and that gate IS `spend_ok`. \
         ⛔ THE NUMBER: KoalaBear p = 2,130,706,433 and USDm is 1e8 atomic units, so amounts ALIAS \
         AT 21.31 USDm — two amounts differing by p share a note commitment and satisfy the same \
         conservation. Closing it needs range-constrained (or multi-limb) amount columns in the AIR: \
         a trace-layout change, therefore a carrier-format change, therefore a coordinated \
         wallet+node landing behind a version door — not a code fix at a call site.",
    ),
    (
        "C-4",
        "THE WHOLE-CHAIN DECIDER PROVES A FIXED PUBLIC AIR WITH NO WITNESS (D01, already recorded in \
         `whir_decider::WhirDecider`'s doc and pins D-1..D-4). This lane re-measures it independently \
         so the finding does not rest on one lane's word.",
    ),
];

/// ✅ BREAKS THIS LANE MEASURED AND THIS PROJECT CLOSED. Each entry carries the RED measurement, the
/// fix that closed it, and the pin that now guards it, so the record survives the fix.
pub const CLOSED_BREAKS: &[(&str, &str)] = &[
    (
        "C-1 / C-2 / C-6 / C-11 / C-14 / C-15",
        "THE PRODUCTION SEND GATE PROVED NOTHING ABOUT THE TRANSACTION — CLOSED 2026-09-08 BY \
         DELETING THE STATEMENT AS AN ADMISSION ROUTE. \
         RED AS MEASURED: `whir_decider::pqspend_direct_verify_carrier` -> \
         `usdm_decider::verify_spend_carrier_bytes` verified ONE row-local AIR whose entire public \
         input was the CONSTANT `SPEND_CARRIER_DOMAIN`, so PqTx::nullifiers (including EMPTY), \
         ::output_notes (including EMPTY), ::bond_notes, ::stake_notes, ::account_targets, \
         ::note_clues, ::membership_leaf_commit, ::membership_tip, the anchor root, the chain id and \
         the genesis identity were EACH measured still admitted with the SAME proof. One carrier \
         admitted every transaction, and C-1 measured that building it needed no secret at all. The \
         mint shape was reachable by any submitter: EMPTY nullifiers (so the spend gates never \
         engage) plus arbitrary `output_notes`, which `wrapper_binds_object` waves through because \
         an unframed blob is not a framed object. \
         THE FIX, one class at its two doors: (1) `chain_object::admissible`'s unframed arm no \
         longer calls that verify — it answers `false`, because a spend's statement is welded to the \
         TRANSACTION and to the node's anchor root, so NO blob-only rule can judge one; \
         (2) `rpc_http`'s `/submit_pq_tx` verdict dropped `direct_ok` and is now \
         `spend_ok || multi_ok || cover_ok`, every arm of which binds this transaction; \
         (3) `Node::admit_tx_shared`'s unframed branch returns the submit door's own verdict \
         (`carrier_prechecked`) instead of falling through to the deleted arm; \
         (4) HYGIENE, at source: the wallet's `build_spend_carrier` / `transfer_rows` / \
         `carrier_selfverifies` and their test are DELETED, along with the \
         `prove/verify_spend_carrier_bytes` imports — they had no production caller, so the producer \
         for an unsound statement is gone rather than merely unreferenced. \
         GUARDED BY: c1_..._is_refused_by_a_verifier, c2_one_carrier_admits_no_transaction_at_all, \
         c6_... (sweep now returns ZERO admitted), c11_... (refused on every chain), c14_... \
         (`!send_door_admits`), c15_... (the empty statement refused). \
         ⛔ NOT CLOSED BY THIS: C-10 (the statement is still empty of tx fields — nothing consults \
         it) and C-3 (conservation is still a field identity with no range constraint, in \
         `SpendValidityGate` too). Both remain in OPEN_BREAKS.",
    ),
    (
        "C-5",
        "THE COINBASE REWARD `value` WAS SELF-DECLARED — CLOSED 2026-09-08. \
         RED AS MEASURED: `pow::verify_block_pow` ran \
         `coinbase_pow_bind_verify(pi, &header.miner_commitment, &c)` and NEVER compared `pi.value` \
         to anything. `pi` is self-describing and carries its own `value` beside a carrier that \
         binds `cm <-> value` soundly, so consensus verified CONSISTENCY and never AUTHORITY: a \
         miner holding a real coinbase key could grind a real nonce to a real target and declare any \
         reward it liked. The sweep accepted 0, 1, 1e6 and 1e12 alike. \
         THE FIX, one shared definition: `pow::COINBASE_REWARD_VALUE` (= 0, the zero-issuance \
         constant — a block's reward is a confidential redistribution of fees / reserve-yield, never \
         emission) is produced by `coinbase_secrets` AND is a REQUIRED ARGUMENT of \
         `whir_decider::coinbase_pow_bind_verify`, which refuses `pi.value != expected_value` before \
         anything else. It is a parameter, not an internal constant, so no future caller can forget \
         to ask. \
         RETIRED 2026-09-18 WITH THE COINBASE BIND ITSELF: the chain is zero-emission, the 94 KB carrier \
         was 73% of every block and more bytes per second than a Tor circuit carries at 500 ms spacing, \
         and the key it bound guarded nothing. A block now carries NO coinbase carrier; the refusal that \
         remains — bind bytes or a non-zero header bind on any block — is GUARDED BY \
         pow::a_block_carrying_bind_bytes_or_a_nonzero_bind_is_refused.",
    ),
    (
        "C-16",
        "REMOTE DENIAL OF SERVICE — `pqspend_direct_verify_carrier` PANICKED on an attacker-chosen \
         trace width. MEASURED 2026-09-08: `shapes[0].1 = 64` against three shipped openings unwound \
         vendor/Plonky3/sumcheck/src/layout/verifier.rs:132, `assertion left == right failed  \
         left: 64  right: 3`, because `verify_air_direct_light_decider_bytes` took `(nvars, width)` \
         from the ATTACKER's bundle and handed `(0..width)` to `add_claim`, which asserts rather \
         than refuses. Reachable off-lock at the submit RPC (rpc_http.rs:1270 as measured; that arm was deleted 2026-09-08 and the surviving arms run the same verifier) and on the gossip path through \
         `chain_object::admissible`. \
         CLOSED 2026-09-08 (lane E) by ONE shared validation — \
         `usdm_decider::whir_rec_block::air_carrier_table_shape_admissible`, run at all three wire \
         entries (direct, batch, batch-with-bus) BEFORE the layout planner, before any \
         `(0..width)`/`(0..nvars)` range and before the first `add_claim`. Every count the wire \
         declares is compared with the data actually shipped, and the `1usize << nvars` shift and \
         the `width * 2^nvars` product are checked for overflow. \
         MEASURED GREEN: usdm-decider pin E-1, `28 attacker-chosen shapes refused, 0 panics`; \
         `test result: ok. 2 passed; 0 failed`. GUARDED BY: C-16, C-18 (node), E-1 (usdm-decider).",
    ),
    (
        "C-17",
        "REMOTE DENIAL OF SERVICE, CHEAPER THAN C-16, FOUND BY RE-READING THE C-16 FIX. A carrier \
         whose declared counts ALL AGREE — shapes[0] = (0, 1), one opening, one `zc.opened`, one \
         `zc.shifted_opened`, no rounds — passes every shape cross-check and then walks into the \
         gate, which reads `local[0] - local[1] - local[2]`. MEASURED RED 2026-09-08 against the \
         pre-fix tree at ~100 attacker bytes: `index out of bounds: the len is 1 but the index is 1` \
         at usdm-decider/src/whir_rec_block.rs:4655 (`SpendConservationGate::eval`), test result \
         `FAILED. 0 passed; 1 failed`. Same two doors as C-16. \
         CLOSED 2026-09-08 (lane E) by making the ROW the guard rather than any gate: \
         `usdm_decider::air_zerocheck::Row` latches an out-of-range read and the carrier is REFUSED \
         on that latch, so all ~60 AIR gates are covered without one of them changing. The \
         substituted value can only cause a rejection — zero-filling a short row and USING it would \
         let a party satisfy a mint gate with columns it never committed, a strictly worse break \
         than the panic. MEASURED GREEN: the same E-1 run above, shapes \
         'self-consistent (nvars,width)=(0,1)' and '=(0,2)' both `verified=false`, no unwind. \
         GUARDED BY: C-17, C-18 (node), E-1 (usdm-decider).",
    ),
    (
        "C-5",
        "THE COINBASE REWARD `value` WAS SELF-DECLARED — and this lane's entry for it had ROTTED in \
         two separate ways, both found on 2026-09-08 while triaging. \
         (1) THE CLAIM IS NO LONGER TRUE OF THIS TREE. `pow::verify_block_pow` now passes the chain's \
         own reward as a fourth argument — `coinbase_pow_bind_verify(pi, &header.miner_commitment, \
         &c, COINBASE_REWARD_VALUE)` (pow.rs:198-203) — and `whir_decider::coinbase_pow_bind_verify` \
         opens with `if pi.value != expected_value { return false; }` (whir_decider.rs:271-273), with \
         `COINBASE_REWARD_VALUE = 0` at pow.rs:50 (zero issuance). The self-declared amount is refused. \
         (2) THERE WAS NEVER A TEST BEHIND THE ENTRY. `c5_a_coinbase_pow_bind_for_an_arbitrary_reward_\
         value_verifies` was named in REGISTER and in OPEN_BREAKS, and MEASURED 2026-09-08 a search of \
         every file under src/harness/ for `fn c5_...` returns NOTHING, while the same search finds all \
         14 other registered pins. So the closure could not have turned this pin red, because there was \
         no pin — the register asserted a measurement nobody had taken. \
         The register's own completeness test only checked that the id/name/description strings were \
         non-empty, which a phantom name satisfies; it now reads the sibling sources and REQUIRES a \
         matching `fn` for every registered id (`cr_the_lane_register_is_complete_and_unique`), so this \
         exact rot cannot recur.",
    ),
    (
        "C-19",
        "CARRIER MALLEABILITY, found by this lane's OWN pin against this lane's OWN fix. The first \
         shape gate allowed `zc.shifted_opened` to be EMPTY (the old `verify_air_zerocheck` rule), \
         so a carrier with that vector STRIPPED still verified — the production send gate is \
         row-local and never reads it. MEASURED 2026-09-08: E-1 shape 'zc.shifted_opened emptied' \
         -> `verified=true`, `FAIL-CLOSED BROKEN ... VERIFIED`. Two distinct byte strings verifying \
         for one statement is the shape that bites wherever a proof is cached, deduped or identified \
         by its bytes. CLOSED in the same change: the gate now requires EXACTLY `width` next-row \
         openings, which `prove_air_zerocheck` fills unconditionally for every column of every AIR. \
         MEASURED GREEN after: that shape `verified=false`, and pin E-2 re-measured honest carriers \
         at 1, 2, 7, 31 and 32 rows — `[E-2] honest carriers at 1,2,7,31,32 rows all still verify`.",
    ),
];

/// ⛔ ATTACKS THIS LANE COULD NOT EXPRESS, and the exact API reason. Never a silent skip.
pub const INEXPRESSIBLE: &[(&str, &str)] = &[
    (
        "mutate a single WITNESS COLUMN of an EXISTING send carrier and re-verify",
        "The direct engine commits the trace inside `prove_air_direct_light_decider_bytes` and the \
         carrier bytes carry only OPENINGS (`AirDirectBundle::openings`, `zc.opened`) plus the HVZK \
         mask — never the columns. There is no representation of 'the same proof with column 3 \
         changed'. The equivalent attack IS expressible and is what C-3 and C-7 run: re-prove from a \
         MUTATED trace (C-3), and mutate the openings the verifier binds (C-7).",
    ),
    (
        "attack the nullifier-derivation and Merkle-membership constraints ON THE PRODUCTION SEND PATH",
        "There is nothing to attack there: the production path does not run them. \
         `SpendMainGate` (nullifier), `SpendMembershipGate` (membership) and the composed \
         `SpendValidityGate` exist in `usdm_decider` and are sound gates, but the node's send door \
         (`chain_object::admissible` -> `pqspend_direct_verify_carrier`) calls ONLY \
         `verify_spend_carrier_bytes` (conservation). That absence is finding C-1, not a skipped test.",
    ),
    (
        "forge the Fiat-Shamir transcript to accept a proof for a different public bind",
        "Expressible only as a grind of ~|F| = KoalaBear^4 (2^124) transcript samples; the challenger \
         is a duplex sponge over a pinned permutation with no shortcut exposed by the API. C-8 runs \
         the CHEAP half (present the honest proof under a different bind) which is the shape a real \
         attacker gets for free.",
    ),
];

#[cfg(all(test, feature = "pins-harness"))]
mod register_pin {
    /// PIN C-R — the register is not allowed to drift from the pins. Every id is unique, every entry
    /// names a test, and the break list cites only registered ids.
    #[test]
    fn cr_the_lane_register_is_complete_and_unique() {
        let mut ids: Vec<&str> = super::REGISTER.iter().map(|e| e.0).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate pin id in the LANE C register");

        // ⛔⛔⛔ A REGISTERED PIN MUST EXIST. This used to check only that the three strings were
        // non-empty — which a name for a test NOBODY WROTE satisfies perfectly.
        //
        // MEASURED 2026-09-08 (lane E triage): `C-5` was registered, was listed as an OPEN BREAK with a
        // paragraph of detail, and had NO `fn c5_...` anywhere under src/harness/. The break it named
        // was meanwhile FIXED in `pow::verify_block_pow`, and nothing went red, because the thing that
        // was supposed to go red did not exist. A register that can name a measurement nobody took is
        // the same failure this lane's module doc rejects in its first paragraph.
        //
        // The sources are read at COMPILE time, so this cannot be satisfied by a stale artifact.
        const SOURCES: &[&str] = &[
            include_str!("binding.rs"),
            include_str!("constraint_coverage.rs"),
            include_str!("prove_false.rs"),
            include_str!("mod.rs"),
        ];
        for (id, name, decides) in super::REGISTER {
            assert!(!id.is_empty() && !name.is_empty() && !decides.is_empty());
            let needle = format!("fn {name}");
            assert!(
                SOURCES.iter().any(|s| s.contains(&needle)),
                "PHANTOM PIN {id}: the register names `{name}`, and no such test function exists in \
                 this lane. Write the pin or delete the entry — a register that claims a measurement \
                 nobody took is worse than an empty one, because its findings cannot go red when they \
                 are fixed (that is exactly how C-5 rotted)."
            );
        }
        assert!(
            !super::OPEN_BREAKS.is_empty(),
            "if this lane ever measures ZERO open breaks, DELETE this assertion in the same commit \
             that closes the last one — an empty break list must be a deliberate statement, never a \
             default"
        );
        println!("[lane-c] {} pins registered", super::REGISTER.len());
        for (ids, what) in super::OPEN_BREAKS {
            println!("[lane-c] OPEN BREAK {ids}: {what}");
        }
        // A closed break is printed too, with its RED measurement and its guard pin: a reader must be
        // able to tell "this was never a problem" from "this was a problem, and here is what stops it".
        for (ids, what) in super::CLOSED_BREAKS {
            println!("[lane-c] CLOSED BREAK {ids}: {what}");
        }
        for (attack, why) in super::INEXPRESSIBLE {
            println!("[lane-c] INEXPRESSIBLE: {attack} -- {why}");
        }
    }
}

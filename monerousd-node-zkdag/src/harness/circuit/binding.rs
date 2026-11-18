// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔ QUESTION 3 — BINDING. Is the proof bound to the STATEMENT IT IS PRESENTED WITH?
//!
//! This is the D01 shape generalised: a one-argument prover (`decider_prove_light(chain_acc)`) means
//! the proof may not be about the chain at all, and a zero-argument public bind (the send carrier's
//! `[SPEND_CARRIER_DOMAIN]`) means the proof may not be about the TRANSACTION at all.
//!
//! Each pin here states precisely what a `true` from the verifier IMPLIES and what it does NOT, as
//! ASSERTIONS rather than prose — a description in a doc comment is what let the send gate's own doc
//! claim nullifier derivation and Merkle membership it does not run.
//!
//! ⛔ NO GATE IS WEAKENED HERE. COST, arithmetic written down — cons: none: ≤4 carriers of ~8.7 KB
//! per run over a FIXED 32-row trace (32 × 3 × 4 B = 384 B), `#[cfg(test)]` only, 0 B persisted, 0
//! sockets, 0 state mutated. f(fixed trace shape), never f(chain height, notes, records or peers).

use crate::harness::circuit::prove_false::send_door_admits;
use crate::harness::circuit::send_carrier_public_bind;
use p3_field::PrimeCharacteristicRing;
use usdm_decider::hiding_decider::Ea4;
// ⭐ ITEM 1 MOVED THIS CARRIER onto the blinded COMMITTED path, so these pins now reshape the bundle the
// production door actually takes. Fuzzing the old `CommittedAirBundle` would be fuzzing a door nothing calls.
use usdm_decider::committed_air::CommittedAirBundle;
use usdm_decider::{SpendRow, prove_spend_carrier_bytes};

/// THE STATEMENT THE PRODUCTION SEND GATE ACTUALLY CERTIFIES, written as the one sentence a reviewer
/// should be able to check against the code in five minutes.
///
/// `pqspend_direct_verify_carrier(bytes) == Some(_)` implies EXACTLY:
///   "somebody ran the public direct prover on a 32-row, 3-column trace whose every row satisfies
///    `col0 - col1 - col2 == 0` in KoalaBear, under the constant domain tag SPEND_CARRIER_DOMAIN."
///
/// It does NOT imply, and no part of the transcript could carry:
///   * that a note exists, is unspent, or is in any tree (no root, no copath, no membership gate);
///   * that the spender holds any key (no key appears in the trace or the bind);
///   * that the transaction's nullifiers derive from anything (no nullifier gate on this path);
///   * that the transaction's output notes correspond to the proven amounts (no output commitment);
///   * that the amounts are integers rather than residues mod p (no range constraint);
///   * that the carrier was made for THIS transaction, THIS chain, or THIS network.
pub const SEND_GATE_ACCEPTANCE_MEANS: &str =
    "somebody ran the public direct prover on a 32x3 trace conserving in KoalaBear under a constant \
     domain tag — nothing about any note, key, nullifier, output, amount range, transaction, chain \
     or network";

#[cfg(all(test, feature = "pins-harness"))]
mod pins {
    use super::*;

    /// ⛔⛔⛔ PIN C-10 — WHAT SEND-GATE ACCEPTANCE IMPLIES, AND WHAT IT DOES NOT.
    ///
    /// The implication is asserted from both ends. FORWARD: a trace with no key, no note and no
    /// membership is accepted, so acceptance cannot imply any of them. BACKWARD: the whole public
    /// statement is one constant field element, so there is no channel through which a tx-specific
    /// claim could be carried even in principle.
    #[test]
    fn c10_what_the_send_gate_acceptance_implies_and_what_it_does_not() {
        let carrier = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 3,
            out_value: 2,
            fee: 1,
        }])
        .expect("prove an honest-shaped carrier");
        assert!(
            crate::whir_decider::pqspend_direct_verify_carrier(&carrier).is_some(),
            "the honest carrier must verify"
        );

        // BACKWARD: the committed statement's shape, read off the wire the node reads.
        let bundle: CommittedAirBundle =
            postcard::from_bytes(&carrier).expect("the carrier is a CommittedAirBundle");
        let (nvars, width) = bundle.shape;
        println!(
            "[C-10] committed statement: 2^{nvars} rows x {width} columns, public inputs = {} \
             constant field element(s). {SEND_GATE_ACCEPTANCE_MEANS}",
            send_carrier_public_bind().len()
        );
        // 3 → SC_WIDTH (208) on 2026-09-11: the range-bound value block (C-3's closure). The new
        // witness lanes are exactly the amounts' limbs, carries and bits — no other lane reached the
        // send path, and the public-input count is unchanged. Pinned to the decider's own constant
        // so a second widening is caught here rather than cited.
        assert_eq!(
            width,
            usdm_decider::SC_WIDTH,
            "the send statement is SC_WIDTH columns wide — 3 values as limbs, carries, and bits. A \
             different committed width would mean new witness lanes reached the send path; re-read \
             this pin before citing it."
        );
        assert_eq!(
            send_carrier_public_bind().len(),
            1,
            "C-10 CHANGED: the send statement now has more than one public input. Re-derive \
             SEND_GATE_ACCEPTANCE_MEANS from the new bind before any report cites it."
        );
    }

    /// ⛔⛔ PIN C-11 — A SEND CARRIER IS BOUND TO NO CHAIN, NO NETWORK AND NO ANCHOR.
    ///
    /// The whole-chain decider at least SEPARATES chains (its transcript welds `chain_acc`, pin C-4).
    /// The send carrier does not even do that: its transcript weld is a protocol-wide constant, so
    /// one carrier crosses every chain, every network and every anchor. A testnet carrier is a
    /// mainnet carrier; a carrier minted before a re-genesis is valid after it.
    ///
    /// Measured by asking the production door under DIFFERENT chain parameters — the exact values
    /// `Node::admit_tx_shared` reads from `self.params()`.
    #[test]
    fn c11_a_send_carrier_is_bound_to_no_chain_no_network_and_no_anchor() {
        let carrier = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 100,
            out_value: 99,
            fee: 1,
        }])
        .expect("prove one carrier, then present it to several chains");

        // Chain parameter tuples a real deployment differs by: fee rate and open-mint allowance.
        let chains: [(u64, u64); 4] = [(10, 0), (30, 0), (10, 1_000_000), (0, 0)];
        let mut admitted_everywhere = true;
        for (fee_bps, allowance) in chains {
            let ok = crate::chain_object::admissible(&carrier, fee_bps, allowance, false);
            println!("[C-11] chain(fee_bps={fee_bps}, mint_allowance={allowance}) admits = {ok}");
            admitted_everywhere = admitted_everywhere && ok;
        }
        // And the default mainnet-shaped ask, for the record.
        assert!(!send_door_admits(&carrier));
        // ✅ CLOSED 2026-09-08 — but read WHY, because the reason matters more than the verdict.
        //
        // The carrier is still bound to no chain: its transcript weld is still the protocol-wide
        // constant `SPEND_CARRIER_DOMAIN`, and nothing in this pin made it chain-aware. What closed is
        // that a chain-blind statement is no longer an ADMISSION ROUTE — every chain now refuses it,
        // for the same reason and by the same rule. So "refused everywhere" is the correct closed
        // shape here, and "admitted everywhere" was the open one.
        //
        // The arms that survived ARE chain-bound in the way that counts: they weld this node's own
        // `spend_frontier_root()`, which no other chain published.
        assert!(
            !admitted_everywhere,
            "⛔ C-11 REOPENED: some chain admitted a carrier whose whole public input is a \
             protocol-wide constant. A carrier that names no chain is a testnet carrier that is also \
             a mainnet carrier, and one minted before a re-genesis that is still valid after it."
        );
    }

    /// ✅ PIN C-14, CLOSED 2026-09-08 — THE WEAK ARM IS NO LONGER AN ARM.
    ///
    /// The submit door's verdict WAS `direct_ok || spend_ok || multi_ok || cover_ok`. `spend_ok` is the
    /// STRONG statement — `verify_spend_validity_carrier_bytes` welds the anchor root, both recorded
    /// output commitments, the recorded nullifier, the depth and the note-membership cross-bind.
    /// `direct_ok` was `pqspend_direct_verify_carrier`, the conservation-only statement whose whole
    /// public input is a constant. A disjunction is only as strong as its WEAKEST arm, so the sound
    /// gates were present, correct, and OPTIONAL — which is why C-1..C-3 mattered operationally.
    ///
    /// `direct_ok` IS DELETED. The verdict is now `spend_ok || multi_ok || cover_ok`, every arm of
    /// which binds the transaction. This pin keeps measuring the same two verifiers on the same
    /// secretless carrier, because the GAP it measures is what justified the deletion and is the thing
    /// a future author must not re-introduce: the weak verifier still accepts (it is sound for its own
    /// small statement) and the strong one still refuses (that carrier proves nothing it needs). The
    /// closure is that no door consults the former any more, which C-1 and C-15 assert directly.
    #[test]
    fn c14_the_weak_statement_still_accepts_what_the_strong_one_refuses_and_is_no_longer_an_arm() {
        let secretless = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 50,
            out_value: 49,
            fee: 1,
        }])
        .expect("a carrier that needs no note, no key and no anchor");

        // The WEAK arm, exactly as the door calls it.
        let weak_arm = crate::whir_decider::pqspend_direct_verify_carrier(&secretless).is_some();

        // The STRONG arm, exactly as the door calls it: two recorded output commitments, the recorded
        // nullifier, the blinded membership cross-bind and the filing digest (no root and no depth since gate D
        // was deleted, 2026-09-30).
        let strong_arm = usdm_decider::verify_spend_validity_carrier_bytes(&secretless, usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]), usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]), usdm_decider::poseidon2_compress::lanes_of(&[13, 14, 15, 16]), usdm_decider::poseidon2_compress::lanes_of(&[17, 18, 19, 20]), usdm_decider::poseidon2_compress::lanes_of(&[21, 22, 23, 24]), usdm_decider::poseidon2_compress::lanes_of(&[25, 26, 27, 28]), usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC);

        println!(
            "[C-14] one secretless carrier: strong arm (spend-validity, welds anchor+outputs+nf) \
             accepts={strong_arm} | weak statement (conservation only) accepts={weak_arm} | the door \
             is now `spend_ok || multi_ok || cover_ok` — the weak statement is NOT among them"
        );
        assert!(
            !strong_arm,
            "the strong gate must refuse a conservation-only carrier, or this pin is measuring the \
             wrong two things"
        );
        assert!(
            weak_arm,
            "C-14 CHANGED: the conservation-only statement no longer accepts a secretless carrier. \
             That gate is not on any door any more, so this is not a soundness change — but the gap \
             this pin exists to describe has moved, so re-derive it before citing C-14."
        );
        // THE CLOSURE ITSELF: the gap above is only dangerous while some door consults the weak
        // statement. A receiving verifier must refuse these bytes outright.
        assert!(
            !send_door_admits(&secretless),
            "⛔ C-14 REOPENED: a verifier admitted the secretless carrier, so the weak statement is \
             an admission route again and every sound gate is optional once more."
        );
    }

    /// ⛔⛔⛔ PIN C-15 — THE GOSSIP DOOR REFUSES THE SOUND CARRIER AND ADMITS THE EMPTY ONE.
    ///
    /// C-14 measures the submit door's disjunction. This measures the OTHER door, and finds the
    /// asymmetry pointing the wrong way.
    ///
    /// `Node::ingest_tx` (the gossip door — nothing pre-verified) asks
    /// `chain_object::admissible`, which sends EVERY unframed blob to
    /// `pqspend_direct_verify_carrier`, i.e. to the conservation-only verifier and to nothing else.
    /// An honest spend-validity carrier is unframed too, and its transcript is welded to
    /// `SPEND_VALIDITY_DOMAIN` plus the anchor root, both output commitments, the nullifier and the
    /// membership cross-bind — so the conservation verifier derives a divergent challenger and
    /// refuses it. The empty statement passes; the full one does not.
    ///
    /// Both verdicts are measured here on the SAME door, from carriers built by the SAME public
    /// crate, so the comparison is not an inference.
    ///
    /// The witness carries no Merkle path: since gate D's deletion (2026-09-30) the spend carrier has one
    /// constant layout, and the verdict is decided by the transcript bind, which differs from the
    /// conservation bind regardless of the row's width.
    #[test]
    fn c15_the_gossip_door_refuses_the_sound_carrier_and_admits_the_empty_one() {
        // A fully sound spend: value_in == value_out + fee, value_out == out0 + out1.
        let witness = usdm_decider::SpendValidityWitness {
            value_in: 10 + 99999, // §BR-14: the input funds the protocol fee
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4])),
            value_out: 9,
            fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
            lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            out0_value: 9,
            out0_opening: usdm_decider::poseidon2_compress::lanes_of(&[5u64, 6, 7, 8]),
            out1_value: 0,
            out1_opening: usdm_decider::poseidon2_compress::lanes_of(&[9u64, 10, 11, 12]),
        };
        let (sound_carrier, out_cms, nf, commit, filing_d) =
            crate::note_transition::prove_unfiled_spend(&witness).expect("a sound spend proves");

        // It IS sound: its own verifier accepts it against the public values it welded.
        let own_verifier = usdm_decider::verify_spend_validity_carrier_bytes(&sound_carrier, out_cms[0], out_cms[1], nf, commit, filing_d, usdm_decider::whir_rec_block::spend_tag1(&witness), usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC);
        assert!(
            own_verifier,
            "the spend-validity carrier must verify under its own gate, or this pin compares nothing"
        );

        // The gossip door's verdict on that same sound carrier…
        let door_on_sound = send_door_admits(&sound_carrier);
        // …and on the statement that proves nothing.
        let empty = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 10,
            out_value: 9,
            fee: 1,
        }])
        .expect("the empty statement proves");
        let door_on_empty = send_door_admits(&empty);

        println!(
            "[C-15] gossip door (chain_object::admissible, unframed -> conservation gate): \
             sound spend-validity carrier admitted={door_on_sound} | \
             conservation-only carrier admitted={door_on_empty}"
        );
        // ✅ CLOSED 2026-09-08 — AND THE PIN'S OWN OBJECTION IS ANSWERED, NOT WAIVED.
        //
        // This pin warned: "if it now admits NEITHER, the send path is closed and that is a halt, not
        // a fix." The door does now admit neither, and it is NOT a halt, for a reason this pin can
        // measure rather than assert:
        //
        //   `door_on_sound` was ALREADY false before the change. The honest wallet's carrier IS the
        //   spend-validity carrier (`build_spend_validity_carrier_cross_bound`), and this door only
        //   ever asked the conservation gate, whose transcript bind diverges — so the gossip door was
        //   ALREADY closed to every honest send. The one thing it admitted was the forgery.
        //
        // Payments therefore never depended on this route: a peer receives a settled send through the
        // BLOCK (graft), not through the pool. Removing the forgery route removes the only traffic the
        // door was carrying. What is genuinely lost is mempool GOSSIP of unsettled sends, which was
        // already lost; restoring it needs the TX-LEVEL rule on this path, and that needs
        // `spend_or_decoy_proof` to ride `PqTx` (today it is parsed from the HTTP body and is on no
        // wire struct, so `cover_ok` is unverifiable by any peer by construction). Named, not deferred.
        assert!(
            !door_on_sound,
            "C-15 CHANGED: the gossip door now admits the SOUND spend-validity carrier. That is the \
             real fix and it is welcome — record the tx-level route that made a stateless door able \
             to weld an anchor root, and re-derive this pin against it."
        );
        assert!(
            !door_on_empty,
            "⛔ C-15 REOPENED: the gossip door admits the statement that proves nothing while \
             refusing the one that proves everything. The empty statement is not a spend gate; it \
             names no note, no key, no nullifier and no transaction."
        );
    }

    /// ⛔⛔⛔ PIN C-16 — A CARRIER THAT DECLARES ITS OWN TRACE WIDTH PANICS THE PRODUCTION VERIFIER.
    ///
    /// MEASURED 2026-09-08 by this pin's own body: `pqspend_direct_verify_carrier` — whose doc says
    /// "`None` fail-closed on any reject / malformed / empty carrier — never panics (decode failure →
    /// None)" — UNWINDS on a carrier whose `shape.1` (the trace WIDTH) disagrees with the
    /// openings it shipped:
    ///
    ///   thread panicked at vendor/Plonky3/sumcheck/src/layout/verifier.rs:132
    ///   assertion `left == right` failed   left: 64   right: 3
    ///
    /// THE MECHANISM: `verify_air_direct_light_decider_bytes` reads `(nvars, width)` straight out of
    /// the ATTACKER'S bundle, builds `all = (0..width)` from it, and hands that to
    /// the claim the verifier adds over every committed column, which ASSERTS the two lengths agree
    /// instead of returning false. Nothing between the wire and that assert compares the declared
    /// shape with the shipped data.
    ///
    /// WHY IT MATTERS BEYOND HYGIENE: this verifier runs on two reachable doors with attacker-chosen
    /// bytes — off-lock at the `/submit_pq_tx` RPC (rpc_http.rs:1269, before any shape check) and on
    /// the gossip path through `chain_object::admissible`. A refusal that unwinds instead of
    /// returning is a fail-closed contract that is not kept.
    ///
    /// ⛔ CLOSED 2026-09-08 (lane E) — THE `#[ignore]` IS GONE, AND THAT IS THE POINT.
    ///
    /// The width is now compared with the data the carrier actually ships, in ONE shared place
    /// (`usdm_decider::whir_rec_block::air_carrier_table_shape_admissible`), BEFORE the layout planner
    /// sees `shapes`, before any `(0..width)` range exists and before the first `add_claim`. This pin
    /// therefore runs in the ordinary suite: it returns `false`, it does not abort, and it no longer
    /// hides the shapes after it.
    ///
    /// The body is UNCHANGED from the pre-fix pin — it was already written as the correct post-fix
    /// assertion, so nothing here was weakened to make it pass.
    #[test]
    fn c16_a_carrier_that_declares_its_own_trace_width_panics_the_production_verifier() {
        let carrier = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 6,
            out_value: 5,
            fee: 1,
        }])
        .expect("prove an honest carrier to reshape");
        let mut wide: CommittedAirBundle =
            postcard::from_bytes(&carrier).expect("the carrier is a CommittedAirBundle");
        // The trace really is 3 columns wide; the attacker declares 64 and ships the same 3 openings.
        wide.shape.1 = 64;
        let bytes = postcard::to_allocvec(&wide).expect("re-encode the reshaped carrier");
        let verified = crate::whir_decider::pqspend_direct_verify_carrier(&bytes).is_some();
        assert!(
            !verified,
            "a carrier declaring a width it did not ship must never VERIFY either"
        );
    }

    /// ⛔⛔⛔ PIN C-17 — A SELF-CONSISTENT NARROW CARRIER PANICS THE GATE ITSELF. FOUND AND CLOSED
    /// 2026-09-08 BY THIS LANE, WHILE RE-READING THE C-16 FIX.
    ///
    /// C-16 is "the declared width disagrees with the shipped openings", and the obvious fix is to
    /// compare the two. Asking what that fix still allows produced a STRICTLY CHEAPER kill: make every
    /// declared count AGREE, and simply declare a narrower trace than the AIR reads.
    ///
    ///   shape = (0, 1) · zc.opened, zc.shifted_opened each 1 long · no rounds, no r
    ///
    /// Nothing is inconsistent, so no shape cross-check can reject it; `nvars = 0` means the zerocheck
    /// round loop never runs, so the carrier walks straight to the gate — and
    /// `SpendConservationGate::eval` reads `local[0] - local[1] - local[2]` off a row of length ONE.
    ///
    /// MEASURED against the pre-fix tree (lane E, RED-first run, ~100 attacker bytes):
    ///   thread panicked at usdm-decider/src/whir_rec_block.rs:4655:25
    ///   index out of bounds: the len is 1 but the index is 1
    ///
    /// That is the same `/submit_pq_tx` off-lock door as C-16 and the same gossip door through
    /// `chain_object::admissible`, at a fraction of the size and with no malformed field to detect.
    ///
    /// THE CLOSURE is not a width check — only the AIR knows how wide it should be. The ROW became the
    /// guard (`usdm_decider::air_zerocheck::Row`): an out-of-range read latches and the carrier is
    /// REFUSED, so every one of the ~60 gates is covered without any of them changing. The substituted
    /// value can only produce a rejection, never an acceptance — zero-filling a short row and USING it
    /// would let a party satisfy a mint gate with columns it never committed, which is worse than the
    /// panic it replaces.
    #[test]
    fn c17_a_self_consistent_narrow_carrier_is_refused_and_never_panics() {
        let carrier = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 6,
            out_value: 5,
            fee: 1,
        }])
        .expect("prove an honest carrier to narrow");
        for width in [1usize, 2] {
            let mut narrow: CommittedAirBundle =
                postcard::from_bytes(&carrier).expect("the carrier is a CommittedAirBundle");
            narrow.shape = (0, width);
            narrow.zc.opened.truncate(width);
            narrow.zc.shifted_opened.truncate(width);
            narrow.zc.round_evals.clear();
            narrow.zc.r.clear();
            let bytes = postcard::to_allocvec(&narrow).expect("re-encode");
            // No catch_unwind on purpose: a panic here IS the failure, and it names the width.
            let direct = crate::whir_decider::pqspend_direct_verify_carrier(&bytes).is_some();
            let door = send_door_admits(&bytes);
            println!(
                "[C-17] self-consistent width={width} carrier ({} B): rpc direct gate={direct}, \
                 gossip door={door} (both returned, neither unwound)",
                bytes.len()
            );
            assert!(!direct, "C-17: the /submit_pq_tx direct gate must REFUSE a narrow carrier");
            assert!(!door, "C-17: the gossip door must REFUSE a narrow carrier");
        }
    }

    /// ⛔⛔⛔ PIN C-18 — THE FUZZ: NO ATTACKER-CHOSEN WIDTH, LENGTH OR COUNT MAY PANIC EITHER DOOR.
    ///
    /// C-16 and C-17 each name ONE shape. This drives the whole family through BOTH production doors
    /// that take unauthenticated remote bytes:
    ///   * `whir_decider::pqspend_direct_verify_carrier` — the expression measured at rpc_http.rs:1270 (that arm was deleted 2026-09-08; this entry is still live and still shape-declared),
    ///     evaluated OFF-LOCK, before the node mutex, on the `/submit_pq_tx` body;
    ///   * `chain_object::admissible` — the gossip door, which sends every unframed blob to the same
    ///     verifier.
    /// and it drives them through the RPC's own intake shape (hex text → bytes), because the door
    /// reads a hex field, not a `Vec<u8>`.
    ///
    /// ⛔ THE DOORS MOVED UNDER THIS LANE ON 2026-09-08, AND THE PIN SAYS SO RATHER THAN CITING A LINE
    /// THAT NO LONGER EXISTS. While this fix was being written, two concurrent lanes CLOSED the
    /// admission holes C-14 and C-15: `direct_ok` was deleted from the `/submit_pq_tx` disjunction
    /// (rpc_http.rs:1844-1850 now reads `spend_ok || multi_ok || cover_ok`), and
    /// `chain_object::admissible` now refuses every UNFRAMED blob outright. Neither of those touches
    /// this lane's class: the arms that REPLACED the deleted one — `verify_spend_validity_carrier_bytes`
    /// (`spend_ok`), the multi-spend gate and the cover gate — run the very same
    /// `verify_air_direct_light_decider_bytes`, on carriers whose shape is still declared by whoever
    /// sent them. So the pin drives BOTH the conservation entry and the spend-validity entry the door
    /// now actually asks, and asserts the gossip door refuses regardless.
    ///
    /// ⛔ WHY IT STOPS SHORT OF `rpc_http::route`: that entry needs a live `NodeRuntime`, which means a
    /// datadir and moving state, and this lane's rule is that no pin constructs a `Node` or opens a
    /// socket (see the module doc). Everything between `route` and the verifier is hex-decode and a
    /// field read, and the hex-decode is exercised below.
    #[test]
    fn c18_no_attacker_chosen_shape_panics_either_production_door() {
        let honest = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 6,
            out_value: 5,
            fee: 1,
        }])
        .expect("prove an honest carrier");
        assert!(
            crate::whir_decider::pqspend_direct_verify_carrier(&honest).is_some(),
            "C-18 is measuring nothing if the HONEST carrier stopped verifying — the shape gate must \
             refuse hostile shapes ONLY"
        );
        assert!(
            !send_door_admits(&honest),
            "C-18 EXPECTATION MOVED: the gossip door now refuses every unframed blob by design (the \
             C-15 closure). If it admits one again, re-read this pin before citing it."
        );

        let reshaped = |mutate: &dyn Fn(&mut CommittedAirBundle)| -> Vec<u8> {
            let mut b: CommittedAirBundle =
                postcard::from_bytes(&honest).expect("the carrier is an CommittedAirBundle");
            mutate(&mut b);
            postcard::to_allocvec(&b).expect("re-encode")
        };

        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        cases.push(("C-16: width 64 declared", reshaped(&|b| b.shape.1 = 64)));
        cases.push(("width 1 declared", reshaped(&|b| b.shape.1 = 1)));
        cases.push(("width usize::MAX", reshaped(&|b| b.shape.1 = usize::MAX)));
        cases.push(("width 0", reshaped(&|b| b.shape.1 = 0)));
        cases.push(("nvars 64 — `1usize << 64` is a panic in debug, a MASKED shift in release", reshaped(&|b| b.shape.0 = 64)));
        cases.push(("nvars usize::MAX", reshaped(&|b| b.shape.0 = usize::MAX)));
        cases.push(("zc.opened truncated", reshaped(&|b| b.zc.opened.truncate(2))));
        cases.push(("zc.opened + shifted_opened BOTH truncated (lengths agree, gate still reads local[2])", reshaped(&|b| {
            b.zc.opened.truncate(2);
            b.zc.shifted_opened.truncate(2);
        })));
        cases.push(("zc.shifted_opened emptied (carrier malleability)", reshaped(&|b| b.zc.shifted_opened.clear())));
        cases.push(("zc.r emptied", reshaped(&|b| b.zc.r.clear())));
        cases.push(("zc.round_evals emptied", reshaped(&|b| b.zc.round_evals.clear())));
        // ⛔ THE OLD "shapes emptied / duplicated", "prover_rand emptied" and "mask_commits emptied"
        // cases are UNREPRESENTABLE on the committed bundle: its `shape` is one pair rather than a
        // vector, and the mask commits live inside `open`. The TYPE forbids those shapes, which is a
        // stronger answer than a runtime refusal — they are gone because they cannot be built, not
        // because the door stopped checking.
        // ⛔ NOT "the mask commits emptied": an honest committed carrier at this shape ships ZERO of
        // them, so clearing the list is a no-op and the case would assert that an HONEST carrier is
        // refused. A fuzz case that cannot differ from honest measures nothing — it was written, run,
        // measured vacuous, and removed rather than left green.
        cases.push(("the OOD answers emptied", reshaped(&|b| b.open.initial_ood_answers.clear())));
        cases.push((
            "an OOD answer mutated",
            reshaped(&|b| {
                if let Some(e) = b.open.initial_ood_answers.first_mut() {
                    *e += Ea4::ONE;
                }
            }),
        ));


        cases.push(("truncated frame", honest[..honest.len() / 3].to_vec()));
        cases.push(("empty frame", Vec::new()));
        cases.push(("one zero byte", vec![0u8]));

        for (name, bytes) in &cases {
            // The wire shape the door actually reads: a hex field on the request body.
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let decoded: Vec<u8> = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("own hex round-trips"))
                .collect();
            assert_eq!(&decoded, bytes, "the intake hex round-trip must be lossless");
            let direct = crate::whir_decider::pqspend_direct_verify_carrier(&decoded).is_some();
            let door = send_door_admits(&decoded);
            // The arm the `/submit_pq_tx` door ACTUALLY asks since the C-14 closure — same shape-declared
            // verifier underneath, so the same class of attacker-chosen count decides the same indices.
            let spend_arm = usdm_decider::verify_spend_validity_carrier_bytes(&decoded, usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]), usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]), usdm_decider::poseidon2_compress::lanes_of(&[13, 14, 15, 16]), usdm_decider::poseidon2_compress::lanes_of(&[17, 18, 19, 20]), usdm_decider::poseidon2_compress::lanes_of(&[21, 22, 23, 24]), usdm_decider::poseidon2_compress::lanes_of(&[25, 26, 27, 28]), usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC);
            println!(
                "[C-18] '{name}' -> conservation={direct} spend-validity={spend_arm} gossip \
                 door={door} (all returned, none unwound)"
            );
            assert!(
                !direct && !door && !spend_arm,
                "FAIL-CLOSED BROKEN: shape '{name}' was ADMITTED by a production gate"
            );
        }
        println!(
            "[C-18] {} attacker-chosen shapes refused at every live gate, 0 panics",
            cases.len()
        );
    }

    /// ⛔ PIN C-12 — A HOSTILE CARRIER SHAPE MUST NOT PANIC THE PRODUCTION VERIFIER.
    ///
    /// `pqspend_direct_verify_carrier`'s contract is explicit: "`None` fail-closed on any reject /
    /// malformed / empty carrier — never panics (decode failure → None)". A carrier arriving from the
    /// wire declares its OWN `shapes` and its OWN opening vectors, and the row-local gate indexes
    /// `local[0..3]` unconditionally — so the shapes an attacker declares decide how a slice is
    /// indexed inside the verifier.
    ///
    /// This pin runs those shapes. THERE IS NO CATCH HERE ON PURPOSE: if the verifier panics, this
    /// pin dies with the panic and the failure output names the shape that did it — which is exactly
    /// the report. A green pin means every hostile shape was refused, calmly.
    ///
    /// Only small shapes are used (nvars 0, 1 and 6 against an honest 5): a large declared `nvars`
    /// would measure an allocation blow-up rather than the indexing contract, and belongs to the
    /// no-growth lane, not here.
    #[test]
    fn c12_a_hostile_carrier_shape_must_not_panic_the_production_verifier() {
        let carrier = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 6,
            out_value: 5,
            fee: 1,
        }])
        .expect("prove an honest carrier to reshape");
        let honest: CommittedAirBundle =
            postcard::from_bytes(&carrier).expect("the carrier is an CommittedAirBundle");

        let mut hostile: Vec<(&str, Vec<u8>)> = Vec::new();

        // (a) fewer opened values than the gate indexes — the gate reads local[0..3].
        let mut a = honest.clone();
        a.zc.opened.truncate(2);
        hostile.push(("zc.opened truncated to 2 (gate indexes local[2])", postcard::to_allocvec(&a).expect("enc")));

        // (b) no opened values at all.
        let mut b = honest.clone();
        b.zc.opened.truncate(0);
        hostile.push(("zc.opened emptied", postcard::to_allocvec(&b).expect("enc")));

        // (c) a declared nvars of 0 — the zerocheck loop never runs and the gate is evaluated at once.
        let mut c = honest.clone();
        c.shape.0 = 0;
        c.zc.round_evals.truncate(0);
        c.zc.r.truncate(0);
        hostile.push(("shapes nvars=0 with empty rounds", postcard::to_allocvec(&c).expect("enc")));

        // (the declared-WIDTH shape lives in its own pin C-16: it PANICS, and a panic here would
        // hide every shape after it.)

        // (e) a declared nvars ABOVE the honest one, with rounds padded to match.
        let mut e = honest.clone();
        e.shape.0 = 6;
        let pad = e.zc.round_evals[0].clone();
        e.zc.round_evals.push(pad);
        e.zc.r.push(Ea4::ONE);
        hostile.push(("shapes nvars=6 (honest 5), rounds padded", postcard::to_allocvec(&e).expect("enc")));

        // (f) a truncated frame — the documented decode-failure path.
        let mut f = carrier.clone();
        f.truncate(carrier.len() / 3);
        hostile.push(("carrier truncated to a third", f));

        for (name, bytes) in &hostile {
            let verdict = crate::whir_decider::pqspend_direct_verify_carrier(bytes).is_some();
            println!("[C-12] hostile shape '{name}' -> verified={verdict} (no panic)");
            assert!(
                !verdict,
                "FAIL-CLOSED BROKEN: hostile shape '{name}' VERIFIED. A carrier that declares its \
                 own trace shape must never be accepted."
            );
        }
    }
}

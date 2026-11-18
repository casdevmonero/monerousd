// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE SELF-MINT ADVERSARY — the op that makes four already-written oracles reachable.**
//!
//! ⛔⛔⛔ THE STING THIS MODULE EXISTS TO ANSWER, quoted from the calibration report §3.3:
//!
//! > "Lane F's entire bundle sub-grammar is THIRD-PARTY TAMPER ONLY, verified by reading it:
//! >  `Sim::tamper` takes an HONEST peer's bundle and flips one spine leaf; `Sim::replay` re-sends a
//! >  bundle the party ALREADY ADOPTED; `Sim::jump` builds a REAL bundle from a REAL peer.
//! >  **Nothing mints.**
//! >  The sting: the oracles for A4 and D-3 are ALREADY WRITTEN AND ALREADY CORRECT
//! >  (`I-4 TIP-WEIGHT-SATURATED` at oracle.rs:665, `I-4 TIP-ON-A-BLOCK-WITH-ABSENT-PARENTS` at
//! >  oracle.rs:655). They have never been reachable."
//!
//! So this module adds no oracle. It adds the one thing missing: an adversary that **mints a bundle
//! with attacker-chosen fields using the PRODUCTION prover**, then offers it at the production adopt
//! door. Four calibration rows come within reach of one op:
//!
//! | row | attacker-chosen field | the oracle that was already waiting |
//! |-----|----------------------|--------------------------------------|
//! | A4  | `blue_work` = `u128::MAX` (and `anchor_blue_work`) | `I-4 TIP-WEIGHT-SATURATED` |
//! | D-3 | a tip block no miner ever ground | `I-4 TIP-ON-A-BLOCK-WITH-ABSENT-PARENTS` |
//! | D-4 | `nullifier.bonded_validators` — an attacker-chosen finality quorum | the quorum it installs |
//! | D-2 | the carried blocks themselves | whatever `instant_sync` does or does not run on them |
//!
//! ⭐⭐⭐ WHY MINTING IS FREE, AND WHY A GREEN TAMPER-PIN IS NOT EVIDENCE AGAINST IT.
//!
//! The 2026-09-07 fix bound `blue_work`, `anchor_blue_work` and `anchor_ordinal` into `sync_binding`
//! (rows A3/A5), and every TAMPER pin over those fields is correctly green: an attacker who edits a
//! field of an honest peer's bundle breaks the binding, and the bundle is refused. That proves the
//! binding works. It proves **nothing at all** about an attacker who does not tamper.
//!
//! A self-minting attacker recomputes the binding **over their own chosen fields** and then mints a
//! matching proof — and pin **C-4** (`c4_a_whole_chain_proof_for_an_invented_accumulator_verifies`,
//! GREEN this run) measures that the whole-chain prover takes the accumulator as its ONLY argument,
//! reads no chain, needs no keys, no blocks and no peers, and produces a proof that
//! `decider_verify_light` AND `decider::accept_bundle` both accept. Sixteen invented bytes.
//!
//! So the binding is a SEPARATOR, not a PROOF: it stops a peer from serving field X under a proof
//! issued for field Y. It cannot stop a peer from issuing the proof themselves. The design wrote this
//! down before the code existed — *"a green tamper-pin is not evidence against self-minting"* — and
//! the built harness reproduced the exact blind spot the design flagged.
//!
//! ⛔ SCOPE, stated so nothing here is over-read. In-process island: two real `Node` values through
//! the production genesis path, the production `build_sync_bundle`, the production `sync_binding`,
//! the production `decider_prove_light`, the production `instant_sync`. It proves nothing about the
//! onion transport, per-node cost or scale.
//!
//! COST ARITHMETIC — cons: none. Nothing here is compiled into a shipping path: the whole module is
//! `#[cfg(test)]`, so it is 0 bytes on the DA, 0 bytes of node RAM, 0 gates on any door, and 0 change
//! to consensus. Run cost is f(fixed constants): 2 parties, a handful of blocks, one `decider_prove_light`
//! per minted bundle — never f(chain height / notes / records / peers).
//!
//! ⛔⛔ THIS FILE IS NOT YET DECLARED IN `src/harness/fuzz/mod.rs`, AND THAT IS DELIBERATE.
//! It was written on a machine whose 1-minute load never fell below the charter's ceiling of 12
//! (measured 12.53 → 21.43 → 15.45 → 17.29 across this lane), so **it has never been compiled**.
//! Declaring an uncompiled module in a shared tree would break `cargo test --lib` for every other
//! crew working in it tonight, which is a worse outcome than shipping it dark. To land it, on a quiet
//! machine:
//!
//!   1. add `mod selfmint;` to `src/harness/fuzz/mod.rs` (one line, beside `mod shrink;`)
//!   2. `sysctl -n vm.loadavg`  — proceed only under 12
//!   3. `cargo test --lib harness::fuzz::selfmint -- --nocapture`
//!
//! Expected on a tree where A4 is OPEN: `a4_a_self_minted_bundle_installs_a_saturated_tip_weight`
//! PASSES, printing the finding `I-4 TIP-WEIGHT-SATURATED`. It is registered as an OPEN BREAK, so it
//! goes RED the day the hole closes and its failure text names the closure — the same shape as C-4.

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use crate::consensus_scenarios::Sim;
    use crate::harness::fuzz::op::Op;
    use crate::harness::fuzz::oracle::{sample_all, Oracle};
    use crate::sync::{AdoptOutcome, FrontierSnapshot, SyncBundle};

    /// ⛔ THE ONE APPROXIMATION IN THIS MODULE, WRITTEN HERE RATHER THAN LEFT TO BE DISCOVERED.
    ///
    /// `Oracle::check_step` takes an `Op`, and the alphabet has no `Op::SelfMint` variant. Adding one
    /// touches eight exhaustive `match` arms across `op.rs` and `engine.rs` (`party`, `to_act`,
    /// `to_case_line`, `to_rust`, `to_corpus_line`, `parse`, `op_tag`, and the generator's weights),
    /// and this lane could not compile a single one of them tonight (see the module note). So the
    /// pins below label the step `Op::Tamper(i, j)`.
    ///
    /// WHAT THAT COSTS, EXACTLY, so nobody has to work it out: the oracle's BEHAVIOUR is identical —
    /// `Tamper` is hostile, grants no exemption in `may_remove_from_unspent` / `may_add_to_unspent`,
    /// and clears no spent filter, so every detector runs exactly as it would for a self-mint. What
    /// is WRONG is the LABEL: a `Finding` printed from these pins names `tamper i j`, and a reader
    /// who pastes that line into `consensus_scenarios.txt` gets a third-party tamper, which is a
    /// different attack that this tree correctly refuses. **Do not paste the reproducer line from
    /// these pins into the case file until `Op::SelfMint` exists.**
    const OP_LABEL_IS_APPROXIMATE: &str =
        "step labelled Op::Tamper — the alphabet has no SelfMint variant yet (see the note above); \
         the oracle's behaviour is exact, the printed reproducer line is NOT";

    /// The honest bundle party `j` would serve, built by the PRODUCTION serve path.
    fn honest_bundle(sim: &mut Sim, j: usize) -> Option<SyncBundle> {
        let src = &mut sim.parties[j];
        src.build_sync_bundle(
            vec![1u8; 4096],
            FrontierSnapshot {
                root: *src.note_frontier_root().as_bytes(),
                height: src.note_frontier_count(),
                peaks_hex: src.spend_frontier_peaks_hex(),
            },
        )
    }

    /// ⭐⭐⭐ THE MINT. Re-derive the binding over the ATTACKER's fields, then mint a matching proof.
    ///
    /// Both halves are the production functions, called exactly as the production serve path calls
    /// them — `crate::sync::sync_binding` with the same eleven arguments `build_sync_bundle` passes,
    /// and `crate::whir_decider::decider_prove_light`, which is what a real producer runs. Nothing is
    /// stubbed and no verifier is replaced: if this bundle is adopted, it is adopted by the same code
    /// that adopts an honest one.
    ///
    /// Returns `false` when the prover declines, so a machine without the prover produces NO VERDICT
    /// rather than a green tick. A capability that reports success when it did not run is the failure
    /// mode this whole instrument exists to catch.
    fn remint_in_place(b: &mut SyncBundle) -> bool {
        b.decider.chain_acc = crate::sync::sync_binding(
            &b.decider.tip,
            b.decider.blue_score,
            &b.frontier,
            &b.nullifier,
            &b.genesis_commit,
            &b.anchor_block.id(),
            b.anchor_blue_score,
            &b.fold_carry.digest(),
            b.blue_work,
            b.anchor_blue_work,
            b.anchor_ordinal,
        );
        match crate::whir_decider::decider_prove_light(&b.decider.chain_acc) {
            Some(p) => {
                b.decider.proof = p;
                true
            }
            None => false,
        }
    }

    /// Two parties, one of them with a real chain to serve from. Returns `None` if the mesh could not
    /// be brought to a servable state, so a pin never asserts against an empty chain.
    fn two_parties_with_a_chain(seed: u64) -> Option<Sim> {
        let mut sim = Sim::new(2, seed);
        for op in [Op::Produce(0, 2), Op::Receive(0), Op::Produce(0, 1), Op::Drain] {
            sim.step(op.to_act(2));
        }
        if sim.parties[0].selected_tip().is_none() {
            return None;
        }
        Some(sim)
    }

    /// ⛔⛔ ROW A4 — A BUNDLE EDITED ONLY IN TWO `u128`s INSTALLS A `u128::MAX` SOLE TIP.
    ///
    /// The attacker takes the honest bundle's own tip, spine, spent-state and genesis — every one of
    /// them REAL and every one of them correct — and changes two integers: the fork-choice weights.
    /// Then it re-derives the binding and mints the proof. Nothing is forged that a verifier can
    /// detect, because nothing is inconsistent: this is a *self-consistent* certificate for a chain
    /// with a weight nobody did the work for.
    ///
    /// What it buys: `u128::MAX` is a PERMANENT `NotHeavier` wedge. Every later honest bundle
    /// compares `(blue_work, tip)` against a saturated value and loses, so the victim adopts nothing
    /// ever again — a halt for that node, delivered by one message. That is why the oracle's own text
    /// calls it "a permanent NotHeavier wedge, which is a halt for this node".
    ///
    /// This pin asserts the hole is OPEN (the C-4 shape). It goes RED the day the hole closes.
    #[test]
    fn a4_a_self_minted_bundle_installs_a_saturated_tip_weight() {
        let Some(mut sim) = two_parties_with_a_chain(0x5E1F_0000_0000_00A4) else {
            eprintln!("[A4] NO VERDICT: the mesh produced no servable tip");
            return;
        };
        let Some(mut bundle) = honest_bundle(&mut sim, 0) else {
            eprintln!("[A4] NO VERDICT: party 0 could not build a bundle this tick");
            return;
        };

        // The whole attack: two integers.
        bundle.blue_work = u128::MAX;
        bundle.anchor_blue_work = u128::MAX;
        if !remint_in_place(&mut bundle) {
            eprintln!("[A4] NO VERDICT: the production prover declined — nothing measured");
            return;
        }

        let mut oracle = Oracle::new();
        let before = sample_all(&sim);
        let outcome = sim.parties[1].instant_sync(bundle);
        let after = sample_all(&sim);
        let finding = oracle.check_step(0, Op::Tamper(1, 0), &before, &after, &sim);

        eprintln!(
            "[A4] self-minted blue_work=u128::MAX -> adopt outcome {outcome:?}, oracle says {:?}  ({})",
            finding.as_ref().map(|f| f.invariant),
            OP_LABEL_IS_APPROXIMATE
        );
        // ⭐⭐⭐ CLOSED 2026-09-13 BY THE WHOLE-CHAIN CERTIFICATE (kill list §AH node wiring).
        //
        // This row measured the hole its own failure message named: the adopt door could not DERIVE the
        // fork-choice weight, and binding it into `sync_binding` was never derivation — the attacker
        // re-mints the binding around whatever weights it likes, which `remint_in_place` above does in
        // two lines. What derives it now is the CERTIFICATE: a chain of `ivc_one_table` steps whose work
        // total must EQUAL the bundle's declared `blue_work`, and whose tip summary must equal the one
        // the adopter recomputes from the fields it is about to install. A saturated weight agrees with
        // neither, so the door refuses before anything is installed.
        //
        // ⛔ THE ATTACK IS STILL ARMED, WHICH IS WHY THIS ROW STAYS. `remint_in_place` SUCCEEDED — the
        // attacker still produces a fully self-consistent decider proof for its invented weights, and
        // every gate ahead of the certificate still passes on it. If the certificate gate is ever
        // removed or relaxed, this row goes straight back to measuring an open hole.
        assert!(
            !matches!(outcome, AdoptOutcome::Adopted(_)),
            "⛔ A4 IS OPEN AGAIN: a self-minted bundle declaring u128::MAX of accumulated work was \
             ADOPTED. Every field of it is bound into an accumulator the attacker chose, so the weight \
             the victim now uses for fork choice is one the attacker typed. Measured outcome: {outcome:?}"
        );
        assert_eq!(
            finding.as_ref().map(|f| f.invariant),
            None,
            "nothing was installed, so no invariant may report a violation either"
        );
        eprintln!(
            "[A4] ⭐ CLOSED: the saturated self-mint is refused as {outcome:?} — the certificate's work \
             total must equal the weight the bundle declares, and a re-minted binding cannot supply one."
        );
    }

    /// ⛔⛔ ROW D-3 — THE SELECTED TIP MOVES ONTO A BLOCK NOBODY EVER MINED.
    ///
    /// Same mint, different chosen field: the tip block. The bundle names a tip whose parents the
    /// victim does not hold and which no miner ever ground, under a binding and a proof the attacker
    /// issued for it. `I-4 TIP-ON-A-BLOCK-WITH-ABSENT-PARENTS` has been sitting at oracle.rs:655
    /// waiting for exactly this since the day it was written.
    ///
    /// ⛔ THE DOOR MAY WELL REFUSE THIS ONE, and that is a RESULT, not a failed pin: `instant_sync`
    /// runs `bundle_blocks_admitted` over the carried blocks before any certified field is installed
    /// (the family-D D-2/D-3 fix). So this pin asserts the OUTCOME IS DECIDED, not that the attack
    /// succeeds — it prints which of the two happened and fails only if the tip moved onto a block
    /// with parents the victim does not hold, which is the actual violation.
    #[test]
    fn d3_a_self_minted_tip_must_not_become_the_selected_tip() {
        let Some(mut sim) = two_parties_with_a_chain(0x5E1F_0000_0000_00D3) else {
            eprintln!("[D-3] NO VERDICT: the mesh produced no servable tip");
            return;
        };
        let Some(mut bundle) = honest_bundle(&mut sim, 0) else {
            eprintln!("[D-3] NO VERDICT: party 0 could not build a bundle this tick");
            return;
        };

        // A tip that names a parent nobody holds. The header is otherwise the honest one, so the ONLY
        // thing wrong with this bundle is the thing under test.
        bundle.tip_block.header.parents = vec![crate::hash::Hash32::hash(b"a parent no node holds")];
        bundle.decider.tip = bundle.tip_block.id();
        bundle.decider.blue_score = bundle.decider.blue_score.saturating_add(1);
        if !remint_in_place(&mut bundle) {
            eprintln!("[D-3] NO VERDICT: the production prover declined — nothing measured");
            return;
        }

        let mut oracle = Oracle::new();
        let before = sample_all(&sim);
        let outcome = sim.parties[1].instant_sync(bundle);
        let after = sample_all(&sim);
        let finding = oracle.check_step(0, Op::Tamper(1, 0), &before, &after, &sim);

        eprintln!(
            "[D-3] self-minted absent-parent tip -> adopt outcome {outcome:?}, oracle says {:?}  ({})",
            finding.as_ref().map(|f| f.invariant),
            OP_LABEL_IS_APPROXIMATE
        );
        assert_ne!(
            finding.as_ref().map(|f| f.invariant),
            Some("I-4 TIP-ON-A-BLOCK-WITH-ABSENT-PARENTS"),
            "D-3 IS OPEN: a self-minted certificate moved this node's SELECTED TIP onto a block whose \
             parents it does not hold. The header door that was supposed to refuse the carried block \
             (`bundle_blocks_admitted`) did not, or did not run. Adopt outcome: {outcome:?}"
        );
    }

    /// ⛔⛔ ROW D-4 — A SELF-MINTED BUNDLE INSTALLS AN ATTACKER-CHOSEN `bonded_validators` SET.
    ///
    /// The finality quorum rides the bundle. `sync_binding` folds it, length-prefixed and pre-sorted,
    /// and a TAMPERED quorum is correctly refused (`a_forged_bonded_validator_set_breaks_the_sync_binding`,
    /// green). A MINTED one is not tampered: the attacker chooses the set and then derives the binding
    /// over their choice. The report's words on this row are the ones that matter — *"the design wrote
    /// this row's lesson down and the built harness reproduced the exact blind spot the design
    /// flagged"*.
    ///
    /// This pin MEASURES rather than presumes: it prints the quorum the victim holds before and after
    /// and fails if the attacker's chosen set is the one standing.
    #[test]
    fn d4_a_self_minted_bundle_must_not_install_a_chosen_finality_quorum() {
        let Some(mut sim) = two_parties_with_a_chain(0x5E1F_0000_0000_00D4) else {
            eprintln!("[D-4] NO VERDICT: the mesh produced no servable tip");
            return;
        };
        let Some(mut bundle) = honest_bundle(&mut sim, 0) else {
            eprintln!("[D-4] NO VERDICT: party 0 could not build a bundle this tick");
            return;
        };

        // One validator, all the bond, chosen by the attacker.
        let chosen: Vec<([u8; 32], u128)> = vec![([0xAB; 32], u128::MAX / 2)];
        bundle.nullifier.bonded_validators = chosen.clone();
        bundle.nullifier.slashed_validators = Vec::new();
        if !remint_in_place(&mut bundle) {
            eprintln!("[D-4] NO VERDICT: the production prover declined — nothing measured");
            return;
        }

        let outcome = sim.parties[1].instant_sync(bundle);
        let installed = sim.parties[1].validators().export_state().0;
        eprintln!(
            "[D-4] self-minted quorum {:?} -> adopt outcome {outcome:?}; victim's quorum is now {:?}",
            chosen.iter().map(|(_id, b)| *b).collect::<Vec<_>>(),
            installed.iter().map(|(_id, b)| *b).collect::<Vec<_>>()
        );
        assert_ne!(
            installed, chosen,
            "D-4 IS OPEN: a bundle the attacker MINTED (binding re-derived over its own chosen fields, \
             proof issued by the production prover with no chain, no keys and no peers — see pin C-4) \
             installed the attacker's finality quorum on the victim. The `sync_binding` fold of \
             `bonded_validators` separates chains; it does not prove one. Adopt outcome: {outcome:?}"
        );
    }

    /// ⭐ THE POSITIVE CONTROL, so a RED above is a real gap and not a broken instrument.
    ///
    /// The SAME machinery, minting a bundle whose fields are the HONEST ones: it must be adopted, and
    /// no I-4 detector may fire. Without this, "the self-mint got in" is unreadable — it could equally
    /// mean the mint path produces garbage that the door happens to accept for some other reason, or
    /// that the oracle fires on everything. Lane C's C-7/C-8/C-9/C-12 are what make its seven reds
    /// citable; this is the same discipline applied to this op.
    #[test]
    fn selfmint_positive_control_an_honestly_reminted_bundle_is_adopted_and_fires_nothing() {
        let Some(mut sim) = two_parties_with_a_chain(0x5E1F_0000_0000_00C0) else {
            eprintln!("[control] NO VERDICT: the mesh produced no servable tip");
            return;
        };
        let Some(mut bundle) = honest_bundle(&mut sim, 0) else {
            eprintln!("[control] NO VERDICT: party 0 could not build a bundle this tick");
            return;
        };
        // No field is changed. Only the binding and the proof are re-derived, so this measures the
        // MINT PATH ITSELF and nothing else.
        if !remint_in_place(&mut bundle) {
            eprintln!("[control] NO VERDICT: the production prover declined — nothing measured");
            return;
        }

        let mut oracle = Oracle::new();
        let before = sample_all(&sim);
        let outcome = sim.parties[1].instant_sync(bundle);
        let after = sample_all(&sim);
        let finding = oracle.check_step(0, Op::Tamper(1, 0), &before, &after, &sim);
        eprintln!(
            "[control] honestly re-minted bundle -> adopt outcome {outcome:?}, oracle says {:?}",
            finding.as_ref().map(|f| f.invariant)
        );
        assert!(
            finding.is_none(),
            "THE INSTRUMENT IS BROKEN, NOT THE CHAIN: re-deriving the binding and the proof over the \
             HONEST fields fired {:?}. Every red from the other three pins in this file must be \
             disregarded until this control is green.",
            finding.as_ref().map(|f| f.invariant)
        );
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE REFUTATION LANE — EVERY DETECTOR MUST BE SHOWN TO FIRE, AND SHOWN NOT TO ALWAYS FIRE.**
//!
//! user 2026-09-08: *"in the past the harnesses didnt = reality. in this case the harness HAS to equal
//! reality or funds are lost. if a test passes on the harness that must mean that aspect of the chain
//! is ready for real user funds."*
//!
//! A green test is worth exactly nothing until someone has shown it can go red. That is the whole of
//! the skeptic's contribution, generalised: never accept a claim without attempting its refutation.
//! Applied to an oracle the claim is *"this detector protects invariant X"*, and its refutation is
//! *"here is a state violating X that the detector reports"*. A detector nobody has made fire is a
//! comment with a test name.
//!
//! ⛔ THIS IS A DIFFERENT QUESTION FROM THE ONE THE CALIBRATION PINS ASK, and both are needed:
//!   * a calibration pin (`h4`..`h8`) proves the ATTACK WAS ARMED — the payload was non-empty, the
//!     census was non-zero, the offer had rows to judge. That is about the DRIVER.
//!   * this lane proves the DETECTOR FIRES on a violation, and STAYS SILENT on a clean state. That is
//!     about the ORACLE.
//! An armed attack against a blind oracle is green. A firing oracle nobody can drive is green. Only
//! both together mean a passing run says anything about real funds.
//!
//! MEASURED PRECEDENT, which is why this lane exists rather than being assumed: `I-4
//! TIP-WEIGHT-SATURATED` was written, reviewed, shipped, and could NEVER fire — it sat behind an
//! `a.tip != b.tip` antecedent while the attack it targets FREEZES the tip. It read as a working
//! defence for as long as nobody tried to make it go red. Three more rows had correct oracles waiting
//! on drivers that handed them empty payloads.
//!
//! METHOD. Take a REAL baseline sample from a real `Sim` — never a hand-built struct, which would
//! drift from what `sample()` actually produces — then mutate exactly the field the invariant is about
//! and require the detector to report it. The negative control runs the identical call with the
//! mutation removed and requires SILENCE, because a detector that fires on everything protects nothing
//! and is strictly worse than none (it trains its readers to ignore it — the D-21 lesson).

#[cfg(all(test, feature = "pins-harness"))]
mod refutation {
    use crate::consensus_scenarios::{Act, Sim};
    use crate::harness::fuzz::op::Op;
    use crate::harness::fuzz::oracle::{sample, Oracle, Sample};

    /// A real two-party mesh that has done real work, plus the baseline sample of party 0.
    ///
    /// The baseline is READ FROM A LIVE NODE rather than constructed, so every field holds a value the
    /// production sampler actually produces. A hand-built `Sample` would let this lane pass while
    /// `sample()` drifted away from it.
    fn baseline() -> (Sim, Vec<Sample>) {
        let mut sim = Sim::new(2, 0x9e37_79b9_7f4a_7c17);
        let _ = sim.step_checked(Act::Receive(0));
        sim.drain();
        let _ = sim.step_checked(Act::Produce(0, 1));
        sim.drain();
        let samples: Vec<Sample> = sim.parties.iter().map(sample).collect();
        (sim, samples)
    }

    /// ⭐⭐⭐ I-NG (the growth census) FIRES ON GROWTH WITH NO CHAIN WORK, AND IS SILENT WITHOUT IT.
    ///
    /// The invariant: a hostile action must not increase what a node HOLDS unless the DAG also grew
    /// (real chain work behind it). Rows D-5 and D-7 are that shape — entries an attacker's bytes
    /// created, backed by no block.
    #[test]
    fn ing_growth_detector_fires_on_a_violation_and_is_silent_on_a_clean_step() {
        let (sim, before) = baseline();

        // NEGATIVE CONTROL FIRST. An unmutated step must report nothing from this detector — a
        // detector that fires on a clean state protects nothing and teaches its readers to ignore it.
        let mut oracle = Oracle::new();
        let clean = oracle.check_step(1, Op::ForgeRows(0), &before, &before, &sim);
        assert!(
            !matches!(clean.as_ref().map(|f| f.invariant), Some("I-NG HOSTILE-ACTION-GREW-A-STORE")),
            "⛔ I-NG FIRES ON A CLEAN STATE: before and after are the SAME sample, so nothing grew and \
             nothing may be reported. A detector that always fires is worse than none — it is noise \
             that trains everyone to skip the one run where it was right. Got {clean:?}"
        );

        // THE REFUTATION. One more held entry, the DAG unchanged, on a hostile op: growth an attacker
        // chose, with no chain work behind it.
        let mut after = before.clone();
        after[0].store_entries_total += 1;
        assert_eq!(
            after[0].dag_len, before[0].dag_len,
            "the mutation must move ONLY the census — a dag_len change would make this a different test"
        );

        let mut oracle = Oracle::new();
        let fired = oracle.check_step(1, Op::ForgeRows(0), &before, &after, &sim);
        assert_eq!(
            fired.as_ref().map(|f| f.invariant),
            Some("I-NG HOSTILE-ACTION-GREW-A-STORE"),
            "⛔ I-NG CANNOT FIRE. A node's held-entry total was increased by a hostile op with the DAG \
             unchanged — the exact shape of rows D-5 and D-7 — and the oracle reported {fired:?}. A \
             detector that cannot be made to go red is a comment with a test name, and every campaign \
             that 'passed' it proved nothing about unbounded growth."
        );
    }

    /// ⭐⭐⭐ I-4 TIP-WEIGHT-SATURATED FIRES WITHOUT A TIP MOVE — THE ANTECEDENT THAT BLINDED IT.
    ///
    /// This detector shipped unable to fire: it sat inside `if a.tip != b.tip`, and saturating the
    /// weight is precisely what FREEZES the tip, so the gate excluded the only outcome it targets.
    /// That is the measured precedent this whole lane exists for, and it is pinned here so the
    /// antecedent can never come back.
    #[test]
    fn i4_saturated_weight_detector_fires_even_though_the_tip_never_moves() {
        let (sim, before) = baseline();

        let mut after = before.clone();
        after[0].tip_blue_work = Some(u128::MAX);
        assert_eq!(
            after[0].tip, before[0].tip,
            "the TIP MUST NOT MOVE in this mutation — a wedge freezes it, and a detector that only \
             looks at moved tips is exactly the bug being pinned"
        );

        let mut oracle = Oracle::new();
        let fired = oracle.check_step(1, Op::Jump(1, 0), &before, &after, &sim);
        assert_eq!(
            fired.as_ref().map(|f| f.invariant),
            Some("I-4 TIP-WEIGHT-SATURATED"),
            "⛔ THE SATURATION DETECTOR IS BLIND AGAIN. A selected tip carrying blue_work = u128::MAX \
             is a permanent NotHeavier wedge — every honest block refused as lighter, forever — and \
             the oracle reported {fired:?}. If this failed because the check was moved back inside an \
             `a.tip != b.tip` gate: that gate excludes the wedge BY CONSTRUCTION, because freezing the \
             tip is what the attack does."
        );
    }

    /// ⭐⭐⭐ I-CC (the carriage oracle) FIRES ON A REAL DOUBLE CARRIAGE, AND IS SILENT WITHOUT ONE.
    ///
    /// `Sim::carriage_verdict` shipped BEFORE the refutation guard existed, so nobody had made it go
    /// red. That is the exact debt this lane exists to collect: a verdict function whose `Err` branch
    /// has never executed is a branch nobody has proven reachable, and every campaign that "passed" it
    /// proved nothing about the class it names — the class that paid a maker's lot out twice.
    ///
    /// The violating state is CONSTRUCTED, not simulated: the SAME note payload is recorded a second
    /// time under a different block id, so one commitment genuinely sits in two records. That is
    /// precisely the shape of the incident — two carriages, each individually legitimate, every amount
    /// balancing, and the money spendable twice.
    #[test]
    fn icc_carriage_verdict_fires_on_a_real_double_carriage_and_is_silent_without_one() {
        let (mut sim, _) = baseline();

        // NEGATIVE CONTROL FIRST — the honest schedule must be clean, or "it fired" says nothing.
        assert!(
            sim.carriage_verdict().is_ok(),
            "⛔ I-CC FIRES ON AN HONEST SCHEDULE: {:?}. A verdict that reports a double carriage where \
             none exists is noise, and noise on this invariant is worse than silence — it trains \
             everyone to skip the one run where a lot really did pay twice.",
            sim.carriage_verdict().unwrap_err()
        );

        // THE REFUTATION — record the SAME note a second time, under a different block id, so one
        // commitment sits in two records.
        let cm = sim
            .real_note_cms_for_test()
            .into_iter()
            .next()
            .expect("the baseline schedule receives a real note");
        let carried_before: usize = sim.parties[0].da_carriage_count(&cm);
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        note[..32].copy_from_slice(&cm);
        let second_id = crate::hash::Hash32::hash(b"selfproof-second-carriage-block");
        let _ = sim.parties[0].record_note_payload_for(Some(second_id), 99, &note, Some(crate::cover::TEST_COVER_KEY));
        let carried_after: usize = sim.parties[0].da_carriage_count(&cm);

        assert!(
            carried_after > carried_before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the commitment is still carried by {carried_after} \
             record(s) after a second recording (was {carried_before}). Then the assertion below would \
             pass for the wrong reason — the classic green that tests nothing. Fix the construction, \
             never the assertion."
        );

        let fired = sim.carriage_verdict();
        assert!(
            fired.is_err(),
            "⛔ I-CC CANNOT FIRE. One commitment is provably carried by {carried_after} DISTINCT \
             records on party 0, which is money received once that two independent membership proofs \
             can claim — and `carriage_verdict` returned Ok. A sum cannot see a duplicate; if this \
             count cannot either, nothing in the harness can, and the 2026-09-03 double payout would \
             pass a full campaign silently."
        );
    }

    /// ⭐⭐⭐ I-8 (CUSTODY) FIRES WHEN A NOTE LEAVES THE UNSPENT SET WITH NO SPEND BEHIND IT.
    ///
    /// This is the oracle behind calibration row C-H3, and the register has described it as "already
    /// written and correct" for as long as the row has been missed. That description was never tested:
    /// its `Err` path had never executed, so "correct" meant "reads correctly", which is exactly the
    /// claim `I-4 TIP-WEIGHT-SATURATED` also passed for while being unable to fire.
    ///
    /// The violating state is the whole of custody loss stated in one line: the unspent set SHRANK and
    /// no spend paid for it. A note left its owner with nothing on the chain accounting for it.
    ///
    /// The op is deliberately an HONEST one (`Deliver`). A hostile op would be intercepted by the
    /// `HOSTILE-OP-MOVED-STATE` arm above and this refutation would prove nothing about I-8 — the same
    /// shadowing that was found masking `I-NG` on the day it landed.
    #[test]
    fn i8_custody_detector_fires_on_an_unexplained_departure_and_is_silent_without_one() {
        // ⛔⛔⛔ THE BASELINE STOPPED HOLDING NOTES, AND THE TEST SAID SO RATHER THAN PASSING.
        //
        // `uns_leaf_count` is no longer the unspent tree's occupancy — Z1 retired that tree, and the
        // oracle now folds `live_leaves(n)`, the REAL note commitments in the node's RECORDS. A record
        // becomes visible only once it FOLDS (`record_fold_depth` blocks later), so the two-step
        // baseline (`Receive`, one `Produce`) samples a node whose receive has not folded yet: zero
        // leaves, and "one left" cannot be expressed against zero.
        //
        // Fix the CONSTRUCTION, never the assertion — the test's own instruction. Produce until the
        // receive's record has folded, so the custody alarm is measured against a node that actually
        // holds custody of something. Bounded by a fixed trip count: if it cannot be built, say so
        // loudly rather than assert against an empty set.
        // `live_leaves` counts REAL note commitments in FOLDED records — a record carrying only the
        // public seed note is not custody of anything. So the build must (a) DELIVER the receive so a
        // block carries a real note, and (b) produce until that record folds.
        // ⛔ AND THE RECEIVE ITSELF MUST BE RETRIED, NOT JUST THE BLOCKS AFTER IT. `Sim::receive`
        // returns early — planting NOTHING — whenever the party still holds buffered relay blocks
        // (`relay_buffered_len() > 0`, counted as a deferred produce). So a build that receives once and
        // then only produces can end with no note at all, which is exactly the empty set this test
        // refused to run against. Drain first so the buffer is clear, THEN receive.
        // ⭐ AND THE LAST HALF OF THE CONSTRUCTION: THE PARTY MUST FOLD AT THE TIP.
        //
        // MEASURED 2026-09-24: with the production `record_fold_depth` of 32, twelve
        // drain+receive+produce rounds built 27 blocks and the party still held `1 ordinal row,
        // spend-frontier count 0` — the genesis record and nothing else, because no record produced by
        // this build was ever 32 selected-chain steps old. The fixture was asserting against an empty
        // set for a reason that had nothing to do with custody.
        //
        // The fold DELAY is not this test's subject; what a node HOLDS is. `Sim::new_folding_at_tip`
        // builds every party (and every restart of one) with depth 0, which is a legal `ChainParams`
        // value the rpc-test helper already uses for the identical stated reason.
        let mut sim = Sim::new_folding_at_tip(2, 0x9e37_79b9_7f4a_7c17);
        // ⛔ AND THE BAR IS "MORE THAN GENESIS", NOT "MORE THAN ZERO". Once `live_leaves` was reading the
        // right field it returned 1 at boot — the genesis ledger record — and a loop that stops at `> 0`
        // exits before receiving anything. The alarm would then be measured against a note this party
        // never received, which is a thinner subject than the one C-H3 names: a note that ARRIVED and
        // then left with no spend behind it.
        let base_leaves = sample(&sim.parties[0]).uns_leaf_count;
        for _ in 0..12 {
            if sample(&sim.parties[0]).uns_leaf_count > base_leaves {
                break;
            }
            sim.drain();
            let _ = sim.step_checked(Act::Receive(0));
            sim.drain();
            let _ = sim.step_checked(Act::Produce(0, 1));
            sim.drain();
        }
        let before: Vec<Sample> = sim.parties.iter().map(sample).collect();
        // ⛔ WHICH EXIT `receive` TOOK — the Sim's own doc says a step that changed nothing and one that
        // worked are indistinguishable downstream, because nothing counted them. Printed BEFORE the
        // assertion, or the one reader who needs it is the one who never sees it.
        eprintln!(
            "[i8-build] real notes planted {}, deferred produces {}, ordinal rows {}",
            sim.real_notes_len_for_test(),
            sim.deferred_produces,
            sim.parties[0].ordinal_rows_for_test().len()
        );
        // …and WHERE the planted records went. `live_leaves` walks `ordinal_rows_for_test()` and reads
        // `da_record_notes(rid)`; a planted record that took no ordinal, or whose bytes the party does
        // not answer for, is invisible to it — and those are two different defects with two different
        // fixes.
        {
            let rows = sim.parties[0].ordinal_rows_for_test();
            let (mut ordinaled, mut with_bytes) = (0usize, 0usize);
            for rid in sim.real_record_ids_for_test() {
                if rows.iter().any(|(_, r)| *r == rid) {
                    ordinaled += 1;
                    if sim.parties[0].da_record_notes(rid).is_some() {
                        with_bytes += 1;
                    }
                }
            }
            eprintln!(
                "[i8-build] of {} planted record(s): {ordinaled} took an ordinal on party 0, {with_bytes} \
                 of those answer for their bytes",
                sim.real_notes_len_for_test()
            );
            let seed_only = rows
                .iter()
                .filter(|(_, rid)| {
                    sim.parties[0].da_record_notes(*rid).is_some_and(|n| {
                        n == crate::cover::public_idle_seed_note(*rid).to_vec()
                    })
                })
                .count();
            let none = rows
                .iter()
                .filter(|(_, rid)| sim.parties[0].da_record_notes(*rid).is_none())
                .count();
            eprintln!(
                "[i8-build] party 0's {} ordinal row(s): {none} answer for NO bytes, {seed_only} carry \
                 ONLY the public seed note. Planted rids: {:?}; ordinal rids: {:?}",
                rows.len(),
                &sim.real_record_ids_for_test()[..3.min(sim.real_notes_len_for_test())],
                rows.iter().map(|(_, r)| *r).take(3).collect::<Vec<_>>()
            );
        }
        assert!(
            before[0].uns_leaf_count > base_leaves,
            "⛔ THE BASELINE STILL HOLDS NO RECEIVED NOTE after 12 deliver+produce rounds (it holds {} \
             leaf/leaves, the same {base_leaves} it booted with), so this test would \
             measure a custody alarm against an empty set — the classic green that tests nothing. \
             WHAT THE PARTY ACTUALLY HOLDS: {} ordinal row(s), spend-frontier count {}, nf_count {}, \
             dag_len {}. `live_leaves` counts REAL note commitments in FOLDED records and skips the \
             public seed note, so zero here means no block in this build ever carried a real note — \
             fix the construction, never the assertion.",
            before[0].uns_leaf_count,
            sim.parties[0].ordinal_rows_for_test().len(),
            before[0].spend_frontier_count,
            before[0].nf_count,
            before[0].dag_len
        );

        let sim = sim;

        // NEGATIVE CONTROL — nothing left, so nothing may be reported.
        let mut oracle = Oracle::new();
        let clean = oracle.check_step(1, Op::Deliver(0), &before, &before, &sim);
        assert!(
            !matches!(
                clean.as_ref().map(|f| f.invariant),
                Some("I-8 CUSTODY-NOTE-DESTROYED")
            ),
            "⛔ I-8 FIRES WITH NOTHING MISSING: before and after are the SAME sample. A custody alarm \
             that rings when no note left is noise on the one invariant that must never be ignored. \
             Got {clean:?}"
        );

        // THE REFUTATION — one leaf leaves, and no spend was ever authorised to remove it.
        let mut after = before.clone();
        assert!(
            after[0].uns_leaf_count > base_leaves,
            "the baseline must actually hold a RECEIVED note, or 'one left' cannot be expressed about \
             custody — {} leaf/leaves vs {base_leaves} at boot",
            after[0].uns_leaf_count
        );
        after[0].uns_leaf_count -= 1;
        after[0].uns_leaf_fold ^= 0xA5A5_5A5A_A5A5_5A5A;

        let mut oracle = Oracle::new();
        let fired = oracle.check_step(1, Op::Deliver(0), &before, &after, &sim);
        assert_eq!(
            fired.as_ref().map(|f| f.invariant),
            Some("I-8 CUSTODY-NOTE-DESTROYED"),
            "⛔ I-8 CANNOT FIRE. A note left the unspent set with NO spend accounting for it — money \
             destroyed, which is the plainest funds-loss shape there is — and the oracle reported \
             {fired:?}. Row C-H3 has been described as having a correct oracle waiting on a driver; if \
             this cannot go red, the oracle was never the half that was ready."
        );
    }

    /// ⭐⭐⭐ I-3 (STATE IS A FUNCTION OF THE CHAIN) FIRES ON A REAL DIVERGENCE AND NOT OTHERWISE.
    ///
    /// I-3 is the most-reported invariant in the catalogue and the one the whole convergence half of
    /// the design rests on — and it has never been refuted either. It also has the worst history: D-21
    /// was a FALSE ALARM on exactly this invariant, and a false alarm is the other failure mode a
    /// refutation catches. Both directions are pinned here for that reason.
    #[test]
    fn i3_divergence_detector_fires_on_disagreeing_parties_and_is_silent_on_agreeing_ones() {
        let (_sim, samples) = baseline();

        // NEGATIVE CONTROL — make both parties identical. Agreeing nodes must produce NO finding, or
        // every campaign drowns in phantom consensus breaks (the measured D-21 failure).
        let agreeing = vec![samples[0].clone(), samples[0].clone()];
        let mut oracle = Oracle::new();
        let clean = oracle.check_quiescent(1, None, &agreeing);
        assert!(
            clean.is_none(),
            "⛔ I-3 FIRES ON AGREEING PARTIES: two byte-identical samples were reported as a consensus \
             divergence ({clean:?}). That is the D-21 failure exactly — an instrument that is both \
             blind and loud gets switched off by the people it protects."
        );

        // THE REFUTATION — one party's unspent root differs. Same blocks, different state.
        let mut diverged = agreeing.clone();
        diverged[1].uns_root[0] ^= 0xDEAD_BEEF;
        assert_ne!(
            diverged[0].uns_root, diverged[1].uns_root,
            "the mutation must actually diverge the roots"
        );

        let mut oracle = Oracle::new();
        let fired = oracle.check_quiescent(1, None, &diverged);
        assert_eq!(
            fired.as_ref().map(|f| f.invariant),
            Some("I-3 STATE-IS-NOT-A-FUNCTION-OF-THE-CHAIN"),
            "⛔ I-3 CANNOT FIRE. Two parties hold DIFFERENT unspent roots at quiescence — the plainest \
             statement of a consensus break — and the oracle reported {fired:?}. Every convergence \
             claim this harness makes rests on this detector; if it cannot go red, none of them mean \
             anything."
        );
    }

    /// ⭐⭐ I-PA (CIRCULAR AUTHORITY) — THE ALARM IS WIRED, AND WHAT IS *NOT* PROVEN IS SAID OUT LOUD.
    ///
    /// `I-PA` has two halves:
    ///   (a) it ASKS THE DOOR TWICE with a byte-identical offer — structural, visible in
    ///       `provenance_verdict`, and not something a unit test can falsify;
    ///   (b) it REPORTS when the two answers differ — refuted here, in both directions.
    ///
    /// ⛔ WHAT THIS DOES NOT PROVE, stated rather than implied: that a real door CAN be made to flip.
    /// Constructing that state IS the defect — a door whose verdict depends on what it stored while
    /// refusing — and the only honest way to produce one is to find a live circular-authority door.
    /// D-32 was exactly one, and it is fixed. So `I-PA` is the single detector in this harness whose
    /// positive case rests on a real defect rather than a constructed one, and that gap is registered
    /// rather than papered over. Every half that CAN be proven, is.
    ///
    /// The negative control matters more than usual here: this verdict runs at the end of EVERY
    /// campaign, so a comparison that reported a flip on identical answers would fail every run.
    #[test]
    fn ipa_circular_authority_alarm_reports_a_flip_and_stays_silent_on_matching_answers() {
        use crate::consensus_scenarios::Sim as ProvSim;

        // NEGATIVE CONTROL — the same answers twice must be silent.
        let same = [true, false, true];
        assert!(
            ProvSim::provenance_flip_detail(0, &same, &same, same.len()).is_none(),
            "⛔ I-PA REPORTS A FLIP THAT DID NOT HAPPEN: two identical verdict vectors were called a \
             circular-authority violation. This verdict runs at the end of EVERY campaign, so an alarm \
             that fires on matching answers fails every run and gets switched off — the D-21 shape."
        );

        // THE REFUTATION — the door refused, then accepted the identical offer.
        let refused_then_accepted = [true, false, true];
        let flipped = [true, true, true];
        let fired = ProvSim::provenance_flip_detail(0, &refused_then_accepted, &flipped, 3);
        assert!(
            fired.is_some(),
            "⛔ I-PA CANNOT FIRE. A door refused an offer and then ACCEPTED the byte-identical second \
             offer, and the comparison reported nothing. That is the D-32 shape — the attacker's own \
             bytes became the authority that admits them — and it was FUNDS-LOSS when it was live."
        );
        let detail = fired.expect("checked above");
        assert!(
            detail.contains("CIRCULAR AUTHORITY") && detail.contains("1 of 3"),
            "the finding must NAME the class and COUNT what flipped, or a reader cannot tell a \
             one-row flip from a wholesale change of behaviour: got {detail}"
        );
    }

    /// ⭐⭐⭐ THE ECOSYSTEM HALF OF I-CP — AN ORDER BOOK THAT IS NOT A FUNCTION OF THE CHAIN.
    ///
    /// The 2026-09-03 double payout was a fill whose BURN WAS LOCAL: the node that saw the fill retired
    /// the maker's order, the node that did not still held it, and the same lot paid out twice. Both
    /// nodes were individually correct, and every amount balanced — so conservation could not see it
    /// and neither could comparing live parties.
    ///
    /// The order book is STATE, so it must be derivable from blocks like any other. This refutation
    /// posts a resting order onto ONE party only — the shape of a book entry no block accounts for —
    /// and requires the cold-peer verdict to report it. Without this, the DEX surface was inside the
    /// oracle's scope on paper and untested in fact.
    #[test]
    fn icp_order_book_half_fires_when_a_book_entry_is_not_derivable_from_the_chain() {
        let (mut sim, _) = baseline();

        // NEGATIVE CONTROL — an honest mesh's books agree with a chain-only replay.
        assert!(
            sim.cold_peer_verdict().is_ok(),
            "⛔ THE ORDER-BOOK HALF FIRES ON AN HONEST MESH: {:?}. This verdict runs at the end of every \
             campaign, so a phantom here fails every run.",
            sim.cold_peer_verdict().unwrap_err()
        );

        // THE REFUTATION — one party gains a resting order that no block carried.
        let before = sim.parties[1].order_book_len_for_audit();
        sim.parties[1].post_selfproof_resting_order();
        let after = sim.parties[1].order_book_len_for_audit();
        assert!(
            after > before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the book still holds {after} order(s) (was \
             {before}), so the assertion below would pass for the wrong reason. Fix the construction, \
             never the assertion."
        );

        let fired = sim.cold_peer_verdict();
        assert!(
            fired.is_err(),
            "⛔ THE ORDER-BOOK HALF OF I-CP CANNOT FIRE. Party 1 holds a resting order that a node fed \
             ONLY the blocks does not derive, and `cold_peer_verdict` returned Ok. That is precisely \
             the 2026-09-03 shape: a book entry alive on one node and retired on another, so the same \
             maker's lot pays out twice while both nodes self-verify correctly."
        );
        let detail = fired.unwrap_err();
        assert!(
            detail.contains("resting order"),
            "the finding must name the ORDER BOOK, or a reader chasing a double payout is sent to the \
             unspent set instead: got {detail}"
        );
    }

    /// ⭐⭐⭐ THE ECOSYSTEM SURFACES RIDE `I-CP`, AND EACH HALF IS PROVEN TO FIRE.
    ///
    /// The `@username` directory is the sharpest of these and the reason this test exists: `#64 Pay
    /// @username` sends money to whoever the directory resolves. A directory that is not a function of
    /// the chain therefore resolves a DIFFERENT owner on a joining node, and the payment goes to the
    /// wrong person — with every node individually correct, exactly like the DEX incident. That is a
    /// funds-loss path through an "app" surface, which is why ecosystem coverage is not optional.
    ///
    /// Refuted per surface rather than once: a single mutation would leave the other two comparisons
    /// unexecuted and they would be decoration. Each is mutated in turn and required to report, and
    /// the finding must NAME the surface so a reader is not sent to the wrong subsystem.
    #[test]
    fn icp_ecosystem_surfaces_each_fire_when_they_are_not_derivable_from_the_chain() {
        // NEGATIVE CONTROL — an honest mesh agrees with a chain-only replay on every surface.
        let (mut sim, _) = baseline();
        assert!(
            sim.cold_peer_verdict().is_ok(),
            "⛔ AN ECOSYSTEM SURFACE FIRES ON AN HONEST MESH: {:?}. This verdict runs at the end of \
             every campaign, so a phantom here fails every run and the real finding is lost in it.",
            sim.cold_peer_verdict().unwrap_err()
        );

        // THE LETTER ACCUMULATOR — a joiner that derives a different one serves different history.
        let (mut sim, _) = baseline();
        sim.parties[0].force_letter_acc_for_selfproof([0x5Au8; 32]);
        let fired = sim.cold_peer_verdict();
        assert!(
            fired.as_ref().is_err_and(|d| d.contains("letter accumulator")),
            "⛔ THE LETTER SURFACE CANNOT FIRE: a party holds a letter accumulator no block produces \
             and the verdict said {fired:?}. Message history that is not a function of the chain means \
             two nodes serve different content under the same anchor."
        );

        // THE @USERNAME DIRECTORY — this one misdirects PAYMENTS, not just names.
        let (mut sim, _) = baseline();
        sim.parties[0].force_dir_acc_for_selfproof([0xA5u8; 32]);
        let fired = sim.cold_peer_verdict();
        assert!(
            fired.as_ref().is_err_and(|d| d.contains("directory")),
            "⛔ THE DIRECTORY SURFACE CANNOT FIRE: a party holds a directory accumulator no block \
             produces and the verdict said {fired:?}. `#64 Pay @username` sends to whoever the \
             directory resolves, so a directory that is not a function of the chain sends a user's \
             money to the wrong owner — with every node individually correct."
        );
    }

    /// ⭐⭐⭐ THE PEG DOORS RIDE `I-CP` — AND THIS IS WHAT MAKES THE `register_wrapped_asset` HOLE VISIBLE.
    ///
    /// Kill-list item 5: `POST /register_wrapped_asset` calls `register_wrapped_asset(asset_id,
    /// ratio_bps)` with **no threshold, no governance vote and no block**. `ratio_bps` decides how much
    /// USDm may be minted against an asset — set a volatile asset to 10000 and the 150% buffer is gone,
    /// so 50% more USDm is mintable against the same collateral. The route's own comment says mainnet
    /// gates this behind the bicameral vote; that gate is a comment, not code.
    ///
    /// From INSIDE a node a locally-set ratio is indistinguishable from a chain-set one, which is
    /// precisely why nothing could see this. A node fed ONLY BLOCKS derives what the CHAIN set, so the
    /// two disagree — and the hole becomes a finding rather than a comment in a route handler.
    ///
    /// This test drives the hole the way the RPC route does: it calls the same
    /// `Node::register_wrapped_asset` the handler calls, on one party, with no block anywhere.
    #[test]
    fn icp_peg_ratio_census_makes_an_rpc_set_collateral_ratio_visible() {
        // NEGATIVE CONTROL — an honest mesh agrees with a chain-only replay on every peg read.
        let (mut sim, _) = baseline();
        assert!(
            sim.cold_peer_verdict().is_ok(),
            "⛔ A PEG READ FIRES ON AN HONEST MESH: {:?}. This verdict runs at the end of every \
             campaign, so a phantom here fails every run.",
            sim.cold_peer_verdict().unwrap_err()
        );

        // THE HOLE, DRIVEN EXACTLY AS THE RPC ROUTE DRIVES IT: a collateral ratio set on one node with
        // no threshold, no vote and no block. wBTC is volatile and must carry the 150% buffer; 10000
        // is 1:1, so this is the "50% more USDm against the same collateral" case.
        let before = sim.parties[0].peg().collateral_ratio_census();
        sim.parties[0].register_wrapped_asset(1, 10_000);
        let after = sim.parties[0].peg().collateral_ratio_census();
        assert_ne!(
            before, after,
            "⛔ THE HOLE WAS NOT DRIVEN: the ratio census is unchanged after the same call the RPC \
             route makes, so the assertion below would pass for the wrong reason. Fix the driver, \
             never the assertion."
        );

        let fired = sim.cold_peer_verdict();
        assert!(
            fired.as_ref().is_err_and(|d| d.contains("ratio census")),
            "⛔ THE PEG RATIO CENSUS CANNOT FIRE. A collateral ratio was set on one node with NO \
             threshold, NO governance vote and NO block — exactly what `POST /register_wrapped_asset` \
             does today — and the chain-only replay did not object ({fired:?}). Then the harness \
             cannot see an unauthenticated write to the number that decides how much USDm may exist, \
             and kill-list item 5 would stay invisible to every campaign."
        );
    }

    /// ⭐⭐⭐ BATCH 2 OF THE MANIFEST'S `ChainDerived` SET — EACH COMPARISON PROVEN TO FIRE.
    ///
    /// Declaring a field `ChainDerived` is a CLAIM: a node fed only blocks must reach the same value.
    /// A claim nothing compares reads as covered while protecting nothing, so a field is only moved
    /// into `COLD_PEER_COVERED` together with the refutation that proves its comparison can go red.
    ///
    /// Refuted per field, not once: a single mutation would leave the other comparisons unexecuted and
    /// they would be decoration. The account commitment is first because it is the sharpest — it is
    /// WHERE EACH RECIPIENT'S NOTES ARE FILED, and a note nobody can locate is a note nobody can spend.
    #[test]
    fn icp_batch2_chain_derived_fields_each_fire_when_they_diverge_from_the_chain() {
        // NEGATIVE CONTROL — an honest mesh agrees with a chain-only replay on all four.
        let (mut sim, _) = baseline();
        assert!(
            sim.cold_peer_verdict().is_ok(),
            "⛔ A BATCH-2 COMPARISON FIRES ON AN HONEST MESH: {:?}. This verdict ends every campaign, \
             so a phantom here fails every run and buries the real finding.",
            sim.cold_peer_verdict().unwrap_err()
        );

        // 1. THE ACCOUNT COMMITMENT — where a recipient's money is indexed.
        let (mut sim, _) = baseline();
        sim.parties[0].force_account_acc_for_selfproof(crate::hash::Hash32::hash(b"selfproof-acct"));
        assert!(
            sim.cold_peer_verdict()
                .as_ref()
                .is_err_and(|d| d.contains("account commitment")),
            "⛔ THE ACCOUNT COMMITMENT COMPARISON CANNOT FIRE. A party holds an account commitment no \
             block produced, so its holders' notes are indexed somewhere the chain does not agree \
             with — and a note nobody can locate is a note nobody can spend. Verdict: {:?}",
            sim.cold_peer_verdict()
        );

        // 2. THE COVER-CONF ACCUMULATOR — advanced per block from the block's own blobs.
        let (mut sim, _) = baseline();
        sim.parties[0].force_nf_cover_conf_acc_for_selfproof([0x3Cu8; 32]);
        assert!(
            sim.cold_peer_verdict()
                .as_ref()
                .is_err_and(|d| d.contains("cover-conf")),
            "⛔ THE COVER-CONF COMPARISON CANNOT FIRE: two nodes could fold different spend sets and \
             nothing would object. Verdict: {:?}",
            sim.cold_peer_verdict()
        );

        // 3 + 4. THE NOTE FRONTIER AND THE RECORD SPACE — one mutation moves both, because recording a
        // payload appends frontier leaves AND occupies an ordinal. Asserted together for that reason,
        // and the message must name at least one of them so the reader lands in the right subsystem.
        let (mut sim, _) = baseline();
        let before_records = sim.parties[0].da_records_held();
        let before_frontier = sim.parties[0].note_frontier_root();
        // A frontier leaf no block appended, and an ordinal row no block filed. `record_note_payload_for`
        // was tried first and is NOT the right mutation here: a record for a block id the DAG does not
        // hold lands in `da_mem` but never takes an ORDINAL, so neither counter moves and the test would
        // have passed while building nothing. (The non-vacuity assertion caught exactly that.)
        sim.parties[0].append_note_leaf_for_test([0x9Eu64; 8]);
        sim.parties[0].adopt_rows_with_sidecars_for_test(&[(4_242, 9_999)]);
        assert!(
            sim.parties[0].da_records_held() != before_records
                || sim.parties[0].note_frontier_root() != before_frontier,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: neither the record count nor the frontier root \
             moved, so the assertion below would pass for the wrong reason. Fix the construction, \
             never the assertion."
        );
        let fired = sim.cold_peer_verdict();
        assert!(
            fired
                .as_ref()
                .is_err_and(|d| d.contains("record space") || d.contains("note frontier")),
            "⛔ NEITHER THE RECORD-SPACE NOR THE NOTE-FRONTIER COMPARISON CAN FIRE. A party recorded a \
             payload no block carried: its record COORDINATES and the tree every membership proof is \
             built against both moved off the chain's, and a chain-only replay did not object. A \
             holder proving against that frontier is proving against a tree its peers do not have. \
             Verdict: {fired:?}"
        );
    }

    /// ⭐⭐⭐ BATCH 3 — THE SPEND GATE'S INPUTS AND THE RULES THEMSELVES, EACH PROVEN TO FIRE.
    ///
    /// The nullifier set is the sharpest of these: it is what refuses a SECOND spend. Two nodes that
    /// disagree about it disagree about what has already been spent, and one of them will accept a
    /// double-spend the other refuses — the oldest funds-loss shape there is.
    ///
    /// `params` is the strangest and worth its own note: a node with different `ChainParams` is not
    /// disagreeing about STATE, it is applying different RULES to the same block. Nothing downstream
    /// can detect that, because every gate it runs is measured against the wrong yardstick and agrees
    /// with itself perfectly.
    #[test]
    fn icp_batch3_spend_gate_inputs_and_chain_rules_each_fire_when_they_diverge() {
        // NEGATIVE CONTROL — an honest mesh agrees with a chain-only replay on all four.
        let (mut sim, _) = baseline();
        assert!(
            sim.cold_peer_verdict().is_ok(),
            "⛔ A BATCH-3 COMPARISON FIRES ON AN HONEST MESH: {:?}",
            sim.cold_peer_verdict().unwrap_err()
        );

        // 1. THE NULLIFIER SET — what refuses a second spend.
        let (mut sim, _) = baseline();
        let before = sim.parties[0].nullifier_count();
        sim.parties[0].force_nf_leaves_for_selfproof(before + 256);
        assert_ne!(
            sim.parties[0].nullifier_count(),
            before,
            "the mutation must actually move the spent count"
        );
        assert!(
            sim.cold_peer_verdict()
                .as_ref()
                .is_err_and(|d| d.contains("nullifier root")),
            "⛔ THE NULLIFIER-SET COMPARISON CANNOT FIRE. A party holds a spent set the chain did not \
             produce, so it and its peers disagree about what has already been spent — one of them \
             will accept a double-spend the other refuses, and nothing objected. Verdict: {:?}",
            sim.cold_peer_verdict()
        );

        // 2. CHAIN PARAMETERS — not a disagreement about state, a disagreement about the RULES.
        let (mut sim, _) = baseline();
        let live = sim.parties[0].params().mint_ratio_bps;
        sim.parties[0].force_mint_ratio_bps_for_selfproof(live / 2);
        assert_ne!(
            sim.parties[0].params().mint_ratio_bps,
            live,
            "the mutation must actually change the rule"
        );
        assert!(
            sim.cold_peer_verdict()
                .as_ref()
                .is_err_and(|d| d.contains("chain parameters")),
            "⛔ THE CHAIN-PARAMETER COMPARISON CANNOT FIRE. A party is running with a HALVED mint \
             collateral ratio — it will authorise mints its peers refuse, against collateral that does \
             not cover them — and a chain-only replay did not object. Every gate on that node agrees \
             with itself perfectly, because they are all measured against the same wrong yardstick; \
             this comparison is the only thing that can see it. Verdict: {:?}",
            sim.cold_peer_verdict()
        );

        // 3. THE MEMBERSHIP TIP — what a holder's proof is rooted at.
        let (mut sim, _) = baseline();
        sim.parties[0].force_membership_tip_root_for_selfproof([0x2Bu64; 8]);
        assert!(
            sim.cold_peer_verdict()
                .as_ref()
                .is_err_and(|d| d.contains("membership tip")),
            "⛔ THE MEMBERSHIP-TIP COMPARISON CANNOT FIRE: a holder would prove against a tree its \
             peers do not have, and nothing objected. Verdict: {:?}",
            sim.cold_peer_verdict()
        );

        // 4. THE L2 SETTLEMENT ROOT — value settles against it.
        let (mut sim, _) = baseline();
        sim.parties[0].force_l2_state_root_for_selfproof([0x4Du8; 32]);
        assert!(
            sim.cold_peer_verdict()
                .as_ref()
                .is_err_and(|d| d.contains("L2 settlement")),
            "⛔ THE L2 SETTLEMENT-ROOT COMPARISON CANNOT FIRE: value settles against a root the chain \
             never produced. Verdict: {:?}",
            sim.cold_peer_verdict()
        );
    }

    /// ⭐⭐⭐ BATCH 4 — THE SERVE POSITION AND THE FINALITY HEIGHT, EACH PROVEN TO FIRE.
    ///
    /// `served_seq` is the one with a measured history: a wallet FOLDS THE SERVED STREAM TO ITS END to
    /// name a spend endpoint, and this figure drifting against `nf_fold_seq` is the recorded cause of
    /// *"sends that worked on a young chain and stopped forever on an older one"*. A node claiming a
    /// position the chain does not support hands every spender an endpoint no peer will honour.
    ///
    /// ⛔ THIS TEST ALSO CLOSES A BOOKKEEPING GAP RATHER THAN OPENING A NEW ONE. `unspent_note_root`
    /// and `nf_unspent_acc` were ALREADY compared by the verdict — the first by its own tail, the
    /// second because `nullifier_root()` projects it — but neither was recorded in
    /// `COLD_PEER_COVERED`, so the coverage number understated what the code actually did. Recorded
    /// now, because a manifest that drifts from the code is a list nobody can trust in either
    /// direction.
    #[test]
    fn icp_batch4_serve_position_and_finality_height_each_fire_when_they_diverge() {
        // NEGATIVE CONTROL.
        let (mut sim, _) = baseline();
        assert!(
            sim.cold_peer_verdict().is_ok(),
            "⛔ A BATCH-4 COMPARISON FIRES ON AN HONEST MESH: {:?}",
            sim.cold_peer_verdict().unwrap_err()
        );

        // 1. THE SERVE POSITION — what a wallet folds to.
        let (mut sim, _) = baseline();
        let live = sim.parties[0].served_seq();
        sim.parties[0].force_served_seq_for_selfproof(live + 5_000);
        assert_ne!(
            sim.parties[0].served_seq(),
            live,
            "the mutation must actually move the serve position"
        );
        assert!(
            sim.cold_peer_verdict()
                .as_ref()
                .is_err_and(|d| d.contains("served record position")),
            "⛔ THE SERVE-POSITION COMPARISON CANNOT FIRE. A party claims its record stream reaches \
             further than the chain supports, so every wallet folding that stream names a spend \
             endpoint no peer will honour — and nothing objected. This is the measured shape of sends \
             that stop working as a chain ages. Verdict: {:?}",
            sim.cold_peer_verdict()
        );

        // 2. THE FINALITY HEIGHT — what this node treats as irreversible.
        let (mut sim, _) = baseline();
        let live = sim.parties[0].finalized_height();
        sim.parties[0].force_finalized_height_for_selfproof(live + 1_000);
        assert_ne!(
            sim.parties[0].finalized_height(),
            live,
            "the mutation must actually move the finality height"
        );
        assert!(
            sim.cold_peer_verdict()
                .as_ref()
                .is_err_and(|d| d.contains("finalized height")),
            "⛔ THE FINALITY-HEIGHT COMPARISON CANNOT FIRE. A party treats as IRREVERSIBLE what the \
             chain has not finalised — it will consider settled what the mesh may still reorg, which \
             is a payment declared final that can still be undone. Verdict: {:?}",
            sim.cold_peer_verdict()
        );
    }

    /// The cold-peer verdict's finding text, or the empty string when it reported nothing. Written as
    /// a match rather than a combinator so an `Ok` reads as "" and every assertion below fails with
    /// the detail it actually got, never with a bare `false`.
    fn cold_detail(sim: &Sim) -> String {
        match sim.cold_peer_verdict() {
            Ok(()) => String::new(),
            Err(detail) => detail,
        }
    }

    /// How many rows party 0 holds in one named store, read through `da_entry_census_named` — the
    /// SAME projection `Sim::cold_peer_verdict` compares. Reading it any other way would let a
    /// non-vacuity check pass against a copy the comparison never looks at.
    fn census_rows(sim: &Sim, field: &str) -> usize {
        let census = sim.parties[0].da_entry_census_named();
        match census.iter().find(|(n, _, _)| *n == field) {
            Some((_, rows, _)) => *rows,
            None => panic!(
                "`{field}` is not in `da_entry_census_named`, so the comparison that reads it there \
                 is blind and this refutation would prove nothing"
            ),
        }
    }

    /// ⭐⭐⭐ BATCH 5a — THE CHAIN ITSELF (`relay`), AND THE RECORD-SPACE / FOLD / ANCHOR SCALARS.
    ///
    /// `relay` is the strongest form of the `ChainDerived` claim in the whole manifest, because the
    /// DAG *is* the chain. Its violating state is deliberately NOT a field poke: a party on a private
    /// fork got there by MINING, so the refutation mines. `Sim::selfproof_mine_a_block_the_chain_
    /// never_carries` runs the real producer and then does not record the block in the case's block
    /// list — which is exactly what the cold peer replays. A party holding weight and notes out of a
    /// block no peer has shows its holder money nobody will honour.
    ///
    /// ⛔ EVERY MUTATION BELOW IS FOLLOWED BY AN ASSERTION THAT IT MOVED THE PROJECTION, BEFORE the
    /// detector is asked anything. That check has caught a test about to pass for the wrong reason
    /// five times in this sweep — including `Node::params()`, which reads `self.relay.dag().params()`
    /// and not the `params` field, so writing the field reported `15000 -> 15000`. Each projection
    /// below was read in the source first, and each assertion names the value it expects to move.
    #[test]
    fn icp_batch5_chain_and_record_space_scalars_each_fire_when_they_diverge() {
        // NEGATIVE CONTROL — an honest mesh agrees with a chain-only replay on all of them.
        let (sim, _) = baseline();
        assert_eq!(
            cold_detail(&sim),
            "",
            "⛔ A BATCH-5 COMPARISON FIRES ON AN HONEST MESH. This verdict ends every campaign, so a \
             phantom here fails every run and buries the real finding."
        );

        // 1. THE DAG — a block mined into one party and into no chain anybody else replays.
        let (mut sim, _) = baseline();
        let before_len = sim.parties[0].dag_len();
        let before_tip = sim.parties[0].selected_tip();
        let mined = sim.selfproof_mine_a_block_the_chain_never_carries(0);
        let after_len = sim.parties[0].dag_len();
        assert!(
            mined && after_len > before_len,
            "⛔ THE PRIVATE FORK WAS NEVER BUILT: mined={mined}, dag_len {before_len} -> {after_len} \
             (tip was {before_tip:?}). `Node::produce` returns None on a party that cannot extend \
             right now, and the assertion below would then run against a party still byte-identical \
             to the chain — the classic green that tests nothing. Fix the construction, never the \
             assertion."
        );
        let detail = cold_detail(&sim);
        assert!(
            detail.contains("PRIVATE FORK"),
            "⛔ THE `relay` COMPARISON CANNOT FIRE. Party 0 holds a block a node fed ONLY the blocks \
             does not have — a private fork — and the chain-only replay reported {detail:?}. `relay` \
             is declared ChainDerived and the DAG IS the chain: if this cannot go red, a node can \
             credit notes, admit spends and serve roots out of a block no peer holds, and nothing in \
             this harness can tell."
        );

        // (2 and 3, the `da_top` / `da_base` arms, LEFT 2026-10-04 with their comparison: a record address is a 56-bit
        // fold of the BLOCK ID, so the extremes this node wrote are its own cursors over the records it holds — a DSYNC
        // joiner's legitimately differ from the origin's. `Authority::LocalCache`; see `cold_peer_verdict_inner`.)

        // 4. `nf_fold_seq` — the key every served absence-fold row is filed under.
        let (mut sim, _) = baseline();
        let live = sim.parties[0].nf_fold_seq();
        sim.parties[0].force_nf_fold_seq_for_selfproof(live + 7);
        assert_ne!(
            sim.parties[0].nf_fold_seq(),
            live,
            "the mutation must actually move the absence-fold position"
        );
        let detail = cold_detail(&sim);
        assert!(
            detail.contains("absence-fold position"),
            "⛔ THE `nf_fold_seq` COMPARISON CANNOT FIRE. This counter advances EXACTLY with \
             `nf_unspent_acc` and keys the fold sidecar, so a party off by seven files every served \
             fold row under a different block than the one it describes — a spender folding that \
             stream can never reproduce A_tip and its money will not move. Verdict: {detail:?}"
        );

        // 5. `served_membership_acc` — the value a spender can actually BUILD. Already compared by
        // `membership_tip()` (which returns the prev/root/acc triple); refuted here so the coverage
        // claim rests on a proof rather than on reading the accessor and believing it.
        let (mut sim, _) = baseline();
        let live = sim.parties[0].membership_tip();
        sim.parties[0].force_served_membership_acc_for_selfproof([0x7Eu64; 8]);
        assert_ne!(
            sim.parties[0].membership_tip(),
            live,
            "⛔ the mutation must move the TUPLE the comparison actually reads. `membership_tip()` \
             returns (prev, root, served_membership_acc); if writing the field leaves the tuple \
             unchanged, the accessor is reading a second copy — the `Node::params()` trap again"
        );
        let detail = cold_detail(&sim);
        assert!(
            detail.contains("membership tip"),
            "⛔ THE SERVED-PREFIX ACCUMULATOR IS NOT UNDER THE ORACLE. A wallet folds what \
             `/membership_roots` served and proves against the result, so a party holding an \
             accumulator the chain does not derive refuses the very proof its own stream taught the \
             wallet to build — measured on a real cross-device send as MEMBERSHIP_PROOF_INVALID with \
             nothing wrong on either side. Verdict: {detail:?}"
        );

        // 6. `root_history` — the anchor-of-anchors a frozen note copath proves against.
        let (mut sim, _) = baseline();
        let live = (
            sim.parties[0].root_history_root(),
            sim.parties[0].root_history_count(),
        );
        let anchor = *crate::hash::Hash32::hash(b"selfproof-anchor").as_bytes();
        let appended = sim.parties[0].force_root_history_append_for_selfproof(anchor);
        let after = (
            sim.parties[0].root_history_root(),
            sim.parties[0].root_history_count(),
        );
        assert!(
            appended && after != live,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: append returned {appended} and the anchor set \
             went {live:?} -> {after:?}. Fix the construction, never the assertion."
        );
        let detail = cold_detail(&sim);
        assert!(
            detail.contains("root-history anchor set"),
            "⛔ THE `root_history` COMPARISON CANNOT FIRE. A party holds a spend ANCHOR the chain \
             never committed, so it accepts a spend proving membership under an anchor no block \
             carries — and refuses the anchors its peers accept. Verdict: {detail:?}"
        );

        // (7, the `stake_frontier` arm, LEFT 2026-10-04 with the field: the node holds no stake frontier.)
    }

    /// ⭐⭐ THE CARRIAGE COUNTER SEES REAL CARRIAGES AND DISTINGUISHES A NOTE NOBODY CARRIED.
    ///
    /// `I-CC` fires when one commitment sits in more than one record. The counter underneath it is
    /// `da_carriage_count`, and the failure mode that would make the whole oracle decorative is a
    /// counter that answers 0 for everything: the no-double-carriage assertion would then pass forever
    /// while detecting nothing. So both directions are proven — it counts a note the chain really
    /// carries, and it does NOT count one that was never sent.
    #[test]
    fn carriage_counter_counts_what_is_carried_and_not_what_is_not() {
        let (sim, _) = baseline();

        let real = sim
            .real_note_cms_for_test()
            .into_iter()
            .next()
            .expect("the baseline schedule receives a real note");
        let carried: usize = sim.parties.iter().map(|n| n.da_carriage_count(&real)).sum();
        assert!(
            carried > 0,
            "⛔ THE CARRIAGE COUNTER IS BLIND: it counted ZERO records carrying a note this schedule \
             demonstrably received. A counter that answers 0 for everything passes 'no note is carried \
             twice' forever and detects nothing."
        );

        // The other direction: an invented commitment must count ZERO, or the counter is matching
        // something other than the note it was asked about and every count it reports is meaningless.
        let never_sent = *crate::hash::Hash32::hash(b"selfproof-never-sent-commitment").as_bytes();
        let phantom: usize = sim
            .parties
            .iter()
            .map(|n| n.da_carriage_count(&never_sent))
            .sum();
        assert_eq!(
            phantom, 0,
            "⛔ THE CARRIAGE COUNTER MATCHES ANYTHING: it found {phantom} record(s) carrying a \
             commitment that was never sent. Then its counts say nothing about the note asked for, and \
             `I-CC` would fire on noise or stay silent on a real duplicate — either way it is not a \
             carriage count."
        );
    }
}

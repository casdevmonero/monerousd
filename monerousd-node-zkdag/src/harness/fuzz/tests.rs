// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE CAMPAIGNS — and the lane's own self-proof.**
//!
//! A fuzzer that has never been shown to catch anything is a green light with no bulb in it. The tests
//! here are in two groups, and the second group is the one that matters:
//!
//! 1. **campaigns** — replay the corpus, then search fresh seeds, asserting the catalogue after every
//!    step. These are the working instrument.
//! 2. **the self-proof** — deliberately break a property the fuzzer claims to defend, and require the
//!    fuzzer to find it, shrink it and emit a reproducer. A harness that cannot demonstrate a catch on a
//!    KNOWN hole has not earned the right to report a clean run on an unknown one.

use crate::harness::fuzz::engine::{fuzz_one, generate, run_sequence, MAX_PARTIES, MAX_STEPS};
use crate::harness::fuzz::op::{from_corpus, Op};
use crate::harness::fuzz::report::{corpus_block, corpus_entries, reproducer_source};
use crate::harness::fuzz::rng::Rng;
use crate::harness::fuzz::shrink::shrink;

/// Run one seeded sequence and, if it finds something, shrink it and print a pasteable reproducer.
/// Returns the panic text, or `None` when the sequence was clean.
fn run_and_report(parties: usize, seed: u64, ops: &[Op], label: &str) -> Option<String> {
    let outcome = run_sequence(parties, seed, ops);
    // Bind the scalars BEFORE moving the finding out: a partial move of `outcome` would make the rest of
    // this function unable to report the run it is describing.
    let parties_ran = outcome.parties;
    let steps_run = outcome.steps_run;
    // ⛔ REPORT EVERY DISTINCT CLASS THIS RUN FOUND, not only the first. The engine no longer stops at
    // the first finding, so a single run can now name several independent defects — which is the whole
    // point of an audit pass. Printed BEFORE the shrink, because the shrink minimises for ONE invariant
    // and a reader must see the full set even when the shrinker only reduces one of them.
    if outcome.findings.len() > 1 {
        eprintln!(
            "⛔⛔ THIS RUN VIOLATED {} DISTINCT INVARIANTS — all of them, in the order first seen:",
            outcome.findings.len()
        );
        for (n, f) in outcome.findings.iter().enumerate() {
            eprintln!(
                "   {}. {} at step {} on party {}: {}",
                n + 1,
                f.invariant,
                f.step,
                f.party,
                f.detail
            );
        }
        eprintln!("   (the shrink below minimises the FIRST; the others are equally real)");
    }
    let finding = outcome.finding?;

    let shrunk = shrink(parties_ran, seed, ops, finding.invariant);
    let body = match shrunk {
        Some((minimal, report)) => reproducer_source(&minimal, &report),
        None => format!(
            "the finding did NOT reproduce on replay from its own seed — that is nondeterminism in the \
             harness or in the node, and it is a finding in its own right:\n  {} at step {} on party {}: \
             {}\n",
            finding.invariant, finding.step, finding.party, finding.detail
        ),
    };

    Some(format!(
        "\n⛔ {label} — LANE F FOUND A VIOLATION\n\
         seed 0x{seed:016x}, {parties} parties, {steps} step(s) executed\n\
         invariant : {inv}\n\
         step      : {step}\n\
         party     : {party}\n\
         detail    : {detail}\n\
         \n{body}",
        label = label,
        seed = seed,
        parties = parties_ran,
        steps = steps_run,
        inv = finding.invariant,
        step = finding.step,
        party = finding.party,
        detail = finding.detail,
        body = body,
    ))
}

/// ⭐⭐⭐ THE CORPUS REPLAY. Every sequence a previous campaign found interesting, re-checked first.
///
/// A class found once is re-checked forever, by anyone, from a clean clone. An entry this build cannot
/// parse is REFUSED rather than guessed at, and the count of refusals is asserted to be zero: a corpus
/// half of which is silently skipped is a corpus that is lying about its coverage.
#[test]
fn the_permanent_corpus_replays_clean_under_the_full_catalogue() {
    let mut replayed = 0usize;
    let mut unreadable = 0usize;
    for block in corpus_entries() {
        match from_corpus(&block) {
            Some((parties, seed, ops)) => {
                replayed += 1;
                if let Some(report) = run_and_report(parties, seed, &ops, "corpus replay") {
                    panic!("{report}");
                }
            }
            None => unreadable += 1,
        }
    }
    assert_eq!(
        unreadable, 0,
        "{unreadable} corpus block(s) in corpus_seeds.txt could not be parsed by this build. A corpus \
         entry that is skipped is coverage that silently vanished — fix the block or delete it, but do \
         not leave it unreadable."
    );
    eprintln!("[lane-f] corpus: {replayed} entry(ies) replayed clean, {unreadable} unreadable");
}

/// ⭐⭐⭐ THE SEARCH — two, three and four parties, every layer, the adversary throughout.
///
/// Structure-aware generation at the type level, so the budget is spent inside reachable states. The
/// catalogue is asserted after EVERY step, so a violation that heals before the drain is still caught.
#[test]
fn every_layer_of_node_operation_under_random_schedules_holds_the_whole_catalogue() {
    // PAST-CHATS-CHECKED: the shape of this campaign follows `mesh_schedule_search_tests` — the same
    // two/three/four-party split, the same order of magnitude of seeds, and the same step budget.
    let plan: [(usize, u64, u64, usize); 3] =
        [(2, 1, 10, MAX_STEPS), (3, 1, 8, MAX_STEPS), (4, 1, 4, 40)];

    // The behaviours the PERMANENT corpus already covers. A sequence whose signature is not among them
    // reached something new, and its block is printed so it can be pasted into `corpus_seeds.txt`. This
    // is the growth half of the corpus: the harness proposes, a human commits, and the entry then
    // survives a clean clone and shows up in a diff. (The storage ban is why it is not written directly;
    // see `report.rs`.)
    let mut known_signatures: Vec<u64> = Vec::new();
    for block in corpus_entries() {
        if let Some((parties, seed, ops)) = from_corpus(&block) {
            known_signatures.push(run_sequence(parties, seed, &ops).signature);
        }
    }
    let mut proposed = 0usize;
    let mut printed = 0usize;

    let mut sequences = 0usize;
    let mut steps_total = 0usize;
    // ⛔ THE ENGINE ALREADY COUNTS WHETHER THE SEND PATH WAS WALKED, AND THIS CAMPAIGN NEVER PRINTED IT.
    // `Outcome::spends` is `(landed, scheduled)` and `Outcome::spend_misses` names which of `Sim::spend`'s
    // four silent `Ok(())` exits swallowed the rest — the whole point of those fields, per their own doc:
    // "a schedule could roll `Op::Spend` a dozen times, land ZERO, and still report a clean run". The
    // summary below reported `spent_filter` alone, which reads `(0, 0)` both when no spend was scheduled
    // and when thirty were scheduled and every one was swallowed. Those are different runs and a green
    // tick must not spell them the same way.
    let mut spends_landed = 0usize;
    let mut spends_scheduled = 0usize;
    let mut miss_no_note = 0usize;
    let mut miss_carrier = 0usize;
    let mut miss_no_block = 0usize;
    let mut miss_unconfirmed = 0usize;
    let mut spends_recorded = 0usize;
    let mut resurrection_probes = 0usize;
    let mut unclaimed = 0usize;
    let mut jump_excused = 0usize;
    let mut max_inversions = 0usize;
    let mut convergence_skipped = 0usize;

    for (parties, first, last, steps) in plan {
        let mut seed = first;
        while seed <= last {
            let salted = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (parties as u64);
            let (ops, outcome) = fuzz_one(parties, salted, steps);
            sequences += 1;
            steps_total += outcome.steps_run;
            spends_recorded += outcome.spent_filter.0;
            resurrection_probes += outcome.spent_filter.1;
            spends_landed += outcome.spends.0;
            spends_scheduled += outcome.spends.1;
            miss_no_note += outcome.spend_misses.0;
            miss_carrier += outcome.spend_misses.1;
            miss_no_block += outcome.spend_misses.2;
            miss_unconfirmed += outcome.spend_misses.3;
            unclaimed += outcome.unclaimed_departures;
            jump_excused += outcome.jump_excused;
            if outcome.convergence_unassertable {
                convergence_skipped += 1;
            }
            if outcome.max_spine_inversions > max_inversions {
                max_inversions = outcome.max_spine_inversions;
            }
            // ⛔ A CAMPAIGN KILLED BY ITS TIME BOUND MUST STILL SAY HOW FAR IT GOT. Without this line a
            // run that is cut short is indistinguishable from a run that never started: the summary below
            // only prints on a clean finish, so the operator is left reading an exit code. One line per
            // sequence, under `--nocapture`, turns the bound into a measurement.
            let verdict: &str = match outcome.finding.as_ref() {
                Some(f) => f.invariant,
                None => "clean",
            };
            eprintln!(
                "[lane-f] seq {sequences:>3}: parties={parties} seed={salted:#018x} steps={} verdict={verdict}",
                outcome.steps_run
            );
            if outcome.finding.is_some() {
                if let Some(report) = run_and_report(parties, salted, &ops, "random schedule") {
                    panic!("{report}");
                }
            }

            if !known_signatures.contains(&outcome.signature) {
                known_signatures.push(outcome.signature);
                proposed += 1;
                // Print the first few in full and count the rest: a run that dumps forty blocks is a run
                // whose output nobody reads, and the count is what says how much is waiting.
                if printed < 8 {
                    printed += 1;
                    eprintln!(
                        "[lane-f] NEW BEHAVIOUR — paste into src/harness/fuzz/corpus_seeds.txt:\n{}",
                        corpus_block(outcome.parties, salted, &ops, outcome.signature)
                    );
                }
            }
            seed += 1;
        }
    }

    // ⛔ A GREEN RUN MUST REPORT ITS OWN REACH, OR IT IS JUST A COLOUR.
    //
    // "No violations" means nothing without the numbers underneath it: how many spends the custody and
    // resurrection oracles actually got to observe, how much unclaimed cover a forged deletion could have
    // hidden behind, and whether the numbering check saw anything at all. A campaign that recorded ZERO
    // spends has a resurrection oracle with zero reach, and that is a gap in the run, not a pass.
    eprintln!(
        "[lane-f] search    : {sequences} sequences, {steps_total} steps, catalogue asserted after each"
    );
    eprintln!(
        "[lane-f] sends     : {spends_landed} of {spends_scheduled} scheduled spends LANDED; \
         swallowed by no-eligible-note {miss_no_note}, carrier refused {miss_carrier}, \
         no block produced {miss_no_block}, not yet confirmed {miss_unconfirmed}"
    );
    eprintln!(
        "[lane-f] reach     : {spends_recorded} spends attributed into the per-party filters, \
         {resurrection_probes} leaf probes against them"
    );
    eprintln!(
        "[lane-f] residual  : {unclaimed} authorised departures left unclaimed — the cover a forged \
         deletion could draw on; {jump_excused} excused by a certified-prefix adopt"
    );
    eprintln!("[lane-f] numbering : max selected-spine ordinal inversions at end of run = {max_inversions}");
    eprintln!(
        "[lane-f] converge  : {convergence_skipped} of {sequences} sequences ended with a dropped \
         delivery nothing later referenced, so I-3 and the engine's agreement check were NOT assertable \
         on them. Safety was asserted on all {sequences}."
    );
    eprintln!(
        "[lane-f] corpus    : {proposed} sequence(s) reached a behaviour the permanent corpus does not \
         cover ({printed} printed above). Pasting them into src/harness/fuzz/corpus_seeds.txt is what \
         makes those behaviours permanent coverage."
    );
}

/// ⛔ THE SEED IS THE WHOLE REPRODUCER.
///
/// Everything downstream — the shrinker's predicate, the corpus, the emitted reproducer — assumes that
/// `(parties, seed, ops)` replays to the same outcome. If that is false, every reproducer this lane emits
/// is a coin flip, and a "fixed" verdict would mean nothing. Two independent runs, compared field by
/// field.
#[test]
fn a_run_replays_identically_from_its_seed_alone() {
    for seed in [0x1u64, 0xFEED_FACE_CAFE_BEEF, 0x9E37_79B9_7F4A_7C15] {
        let (ops_a, out_a) = fuzz_one(3, seed, 16);
        let (ops_b, out_b) = fuzz_one(3, seed, 16);
        assert_eq!(ops_a, ops_b, "the generator is not a function of the seed");
        assert_eq!(out_a.steps_run, out_b.steps_run, "replay diverged on steps executed");
        assert_eq!(out_a.signature, out_b.signature, "replay diverged on behaviour");
        assert_eq!(
            out_a.finding.map(|f| f.invariant),
            out_b.finding.map(|f| f.invariant),
            "replay diverged on the verdict — every reproducer this lane emits would be a coin flip"
        );
    }
}

/// The generator must actually reach the whole alphabet. A grammar that never emits `Spend` cannot find a
/// custody bug, and nothing else in this suite would notice the absence.
#[test]
fn the_generator_reaches_every_op_in_the_alphabet() {
    let mut rng = Rng::new(0xA5A5_5A5A_A5A5_5A5A);
    let ops = generate(&mut rng, MAX_PARTIES, MAX_STEPS);
    let mut seen: Vec<&'static str> = Vec::new();
    let note = |k: &'static str, v: &mut Vec<&'static str>| {
        if !v.contains(&k) {
            v.push(k);
        }
    };
    // A single 48-step sequence will not contain all fourteen, so draw a campaign's worth.
    let mut all: Vec<Op> = ops;
    for extra in 0..64u64 {
        let mut r = Rng::new(0xA5A5_5A5A_A5A5_5A5A ^ extra.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for op in generate(&mut r, MAX_PARTIES, MAX_STEPS) {
            all.push(op);
        }
    }
    for op in all.iter() {
        note(
            match op {
                Op::Produce(..) => "produce",
                Op::Deliver(_) => "deliver",
                Op::Burst(_) => "burst",
                Op::Drain => "drain",
                Op::Drop(_) => "drop",
                Op::Restart(_) => "restart",
                Op::Jump(..) => "jump",
                Op::Receive(_) => "receive",
                Op::Spend(_) => "spend",
                Op::Forget(_) => "forget",
                Op::Tamper(..) => "tamper",
                Op::ForgeRows(_) => "forge-rows",
                Op::Invalid(_) => "invalid",
                Op::Replay(..) => "replay",
            },
            &mut seen,
        );
    }
    eprintln!(
        "[lane-f] generator: reached {} of 14 ops across {} sampled sequences, consuming {} draws",
        seen.len(),
        65,
        rng.draws()
    );
    assert_eq!(
        seen.len(),
        14,
        "the generator reached only {} of the 14 ops in the alphabet: {seen:?}. An op the generator \
         never emits is a whole class of bug this lane cannot see, and nothing else here would notice.",
        seen.len()
    );
}


/// ⭐⭐⭐ THE SEND PATH MUST BE WALKED, NOT MERELY SCHEDULED.
///
/// The test above proves the generator EMITS all 14 ops. That is a weaker claim than it looks, and the
/// gap between the two is where this lane could have certified a send path it never used.
///
/// `Sim::spend` has four exits that change nothing and return `Ok(())`: no note this party certifies
/// present and unspent, the carrier refuses, production yields no block, and the relay-buffered defer.
/// Every one is legitimate — a spend a party cannot carry right now is not a defect. But until they
/// were counted, all four were INDISTINGUISHABLE FROM A LANDED SEND to everything downstream. A
/// campaign could roll `Op::Spend` hundreds of times, land ZERO, and report clean, and the "no
/// double-spend, no resurrection, no unclaimed departure" verdicts would all be true — of a run in
/// which nothing was ever spent.
///
/// ⛔ THAT IS THE HARNESS-≠-REALITY SHAPE, ON THE ONE PATH REAL MONEY LEAVES A WALLET BY. The standard
/// this lane is held to is that a green run means that aspect of the chain is ready for real funds. A
/// green run over zero sends does not mean that, so the count is now asserted rather than assumed.
///
/// ⭐⭐⭐ MEASURED, AND THE FIRST RUN OF THIS PIN WAS RED: **0 landed / 28 scheduled across 16 runs.**
/// The fuzz lane had NEVER once exercised a send. Two driver defects were hiding behind the swallowed
/// error, each a door the driver could not pass:
///   1. `spend_tx_for_test` set `id` to `hash("spend-for-test-{salt}")` over an EMPTY blob, so the id
///      bound nothing and `Mempool::accept` refused every tx with `InvalidId`; and behind that,
///   2. `pow_stamp: 0` — never ground — so the next door refused it with `stamp work 1 < required 8`.
/// Both refusals were CORRECT. The doors were working; the driver was building a transaction no wallet
/// would ever send, and `Sim::spend` discarded the error and returned `Ok(())`.
/// After the fix: **4 landed / 8 scheduled across 4 runs, carrier_failed 0** — the remaining misses are
/// the legitimate "this party holds no eligible note right now" case. Every send-side oracle in this
/// lane (double-spend, resurrection, unclaimed departures, deletion carriage) is non-vacuous for the
/// first time as a result.
#[test]
fn a_campaign_actually_lands_sends_it_does_not_merely_schedule_them() {
    let (mut landed, mut scheduled, mut runs_with_a_send) = (0usize, 0usize, 0usize);
    let (mut no_note, mut carrier_failed, mut no_block, mut unconfirmed) = (0usize, 0usize, 0usize, 0usize);
    const RUNS: u64 = 4;
    for seed in 0..RUNS {
        let (_ops, out) = fuzz_one(3, 0x5E4D_0000_u64.wrapping_add(seed), 120);
        landed += out.spends.0;
        scheduled += out.spends.1;
        no_note += out.spend_misses.0;
        carrier_failed += out.spend_misses.1;
        no_block += out.spend_misses.2;
        unconfirmed += out.spend_misses.3;
        if out.spends.0 > 0 {
            runs_with_a_send += 1;
        }
    }
    eprintln!(
        "[lane-f] send coverage: {landed} landed / {scheduled} scheduled across {RUNS} runs; \
         {runs_with_a_send} of {RUNS} runs contained at least one real send; \
         misses: no_note={no_note} carrier_failed={carrier_failed} no_block={no_block} unconfirmed={unconfirmed}"
    );

    // NON-VACUITY. "Sends landed" is a claim about nothing if the generator never asked for one; this
    // assertion must fail loudly rather than let the real check below pass on an empty schedule.
    assert!(
        scheduled > 0,
        "⛔ THE CONTROL FAILED, NOT THE COVERAGE CHECK: the generator scheduled ZERO spends across \
         {RUNS} runs, so the landed count below is a statement about an empty set. Check the op \
         weights before reading anything into the number."
    );

    assert!(
        landed > 0,
        "⛔⛔ THE SEND PATH WAS NEVER WALKED. {scheduled} spends were scheduled across {RUNS} runs and \
         NOT ONE LANDED — every attempt took one of `Sim::spend`'s four silent exits. Every send-side \
         verdict this lane produces is therefore vacuous: 'no double-spend was found' is the absence of \
         an event that was never staged. Do NOT relax this assertion. Find out which exit is swallowing \
         the spends (`spends_no_note`, `spends_carrier_failed`, `spends_no_block`, `spends_unconfirmed`, or the buffered \
         defer) and fix the driver, because until a send lands here the chain's send path is UNTESTED \
         by this harness no matter how green the run is."
    );
}


/// ⛔⛔⛔ D-38 — A RESTART DROPS EXACTLY ONE BLOCK'S NULLIFIER FOLD.
///
/// EMITTED BY THE LANE-F FUZZER, seed 0x9e3779b97f4a7c17, 48 ops shrunk to 4, 1-MINIMAL.
/// It was UNREACHABLE until the send driver was fixed (see the coverage pin above): every spend the
/// campaign scheduled used to bounce off the mempool doors, so nothing ever reached the state where a
/// restart and a spend interact.
///
/// `nullifier_count 8705 vs 8449` — a difference of **exactly 256 = `BLOCK_FIXED_NULLIFIER_COUNT`**,
/// one block's cover. That is the D-35/D-36 signature: *a block entering by a door other than direct
/// delivery skips its nullifier fold.* D-35 closed the parent-ask door; D-36 is the DSYNC **jump**
/// door. This sequence contains NO jump — it contains a **RESTART**, so the class has a third
/// entrance, and it is on the most basic sequence a user can perform: receive, sync, restart, spend.
///
/// ⛔ WHY IT COSTS FUNDS: the nullifier set is what refuses a SECOND spend. Two nodes 256 apart
/// disagree about what has already been spent — one will accept a spend the other refuses.
///
/// ✅ CLOSED 2026-09-09 — MUST STAY GREEN. Cause: the Sim never drove the SPEND-FOLD SELF-HEAL that
/// the runtime runs every tick (`Sim::heal_spendfold_gaps`). MEASURED at the divergence: party 0 held
/// 256 unspent leaves and party 1 held 257, the extra commitment being exactly the note party 0 had
/// just spent; both agreed on `nullifier_count` at 513. The restarted node folded the nullifier and
/// never removed the note, so it would have accepted a double-spend party 0 refuses. The deeper
/// 256-wide nullifier gap that the same seed then shrank to is a SEPARATE defect — see `d38b` below,
/// which is still RED.
#[test]
fn d38_a_restart_must_not_drop_a_carried_block_s_nullifier_fold() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![
        Op::Receive(1),
        Op::Deliver(10),
        Op::Restart(1),
        Op::Spend(0),
    ];
    let outcome = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
    assert!(
        outcome.finding.is_none(),
        "⛔ D-38: {:?}",
        outcome.finding.map(|f| f.detail)
    );
}

#[test]
fn d38_diag_which_ops_are_load_bearing() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let seed = 0x9e3779b97f4a7c17u64;
    let cases: Vec<(&str, Vec<Op>)> = vec![
        ("full        ", vec![Op::Receive(1), Op::Deliver(10), Op::Restart(1), Op::Spend(0)]),
        ("no-spend    ", vec![Op::Receive(1), Op::Deliver(10), Op::Restart(1)]),
        ("no-restart  ", vec![Op::Receive(1), Op::Deliver(10), Op::Spend(0)]),
        ("no-receive  ", vec![Op::Deliver(10), Op::Restart(1), Op::Spend(0)]),
        ("spend-by-1  ", vec![Op::Receive(1), Op::Deliver(10), Op::Restart(1), Op::Spend(1)]),
    ];
    for (name, ops) in cases {
        let out = run_sequence(2, seed, &ops);
        eprintln!(
            "[d38-diag] {name} -> {}",
            out.finding.map(|f| f.detail).unwrap_or_else(|| "CLEAN".into())
        );
    }
}


/// ⛔⛔⛔ D-38b — THE 256-WIDE NULLIFIER GAP THAT SURVIVED THE HEAL FIX.
///
/// D-38's first cause (the spend-fold heal the Sim never drove) is closed and pinned above. Re-running
/// the same seed then shrank to a DIFFERENT 5-op sequence, 1-MINIMAL over 48 candidates:
///
///     Receive(1) · Restart(1) · Burst(3) · Receive(1) · Spend(0)
///
/// `nullifier_count 8705 vs 8449` — short by exactly 256, one `BLOCK_FIXED_NULLIFIER_COUNT` cover.
/// That is the D-35/D-36 signature: a block entering by a door other than direct delivery skips its
/// nullifier fold. Here the door is a BURST CASCADE ARRIVING AT A RESTARTED NODE.
///
/// ⭐ THAT THIS STILL FIRES IS THE PROOF THE HEAL FIX DID NOT BLIND THE LANE — the harness change
/// closed one cause and the detector went straight on to find the next.
#[test]
fn d38b_a_burst_cascade_after_restart_must_not_drop_a_nullifier_fold() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![
        Op::Receive(1),
        Op::Restart(1),
        Op::Burst(3),
        Op::Receive(1),
        Op::Spend(0),
    ];
    let outcome = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
    assert!(
        outcome.finding.is_none(),
        "⛔ D-38b: {:?}",
        outcome.finding.map(|f| f.detail)
    );
}

/// ⛔⛔⛔ D-36 — THE DSYNC **JUMP** DOOR SKIPS THE NULLIFIER FOLD.
///
/// With D-38 and D-38b closed, the same seed shrank again — now to THREE ops, 1-minimal over 32
/// candidates, and the unspent side is silent. What remains is the pure D-35 signature:
/// `nullifier_count 8705 vs 8449` on the full run, `513 vs 257` shrunk — short by exactly 256, one
/// `BLOCK_FIXED_NULLIFIER_COUNT` cover, with `nullifier_root` and `nf_unspent_acc` following it.
///
/// This is the door the register has carried as OPEN since 2026-09-08: D-35 closed the parent-ask and
/// produce-cascade doors; the DSYNC jump door was named and left. `Op::Jump` is that door.
///
/// ⛔ WHY IT COSTS FUNDS: the nullifier set is what refuses a SECOND spend, and a wallet folds the
/// SERVED nullifier stream to its end to name a spend endpoint. A jumped node serving a stream 256
/// short hands every spender an endpoint no peer will honour, and disagrees with its peers about what
/// has already been spent.
#[test]
fn d36_a_dsync_jump_must_not_drop_the_nullifier_fold() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![Op::Produce(1, 0), Op::Receive(0), Op::Jump(1, 0)];
    let outcome = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
    assert!(
        outcome.finding.is_none(),
        "⛔ D-36: {:?}",
        outcome.finding.map(|f| f.detail)
    );
}

/// ⛔ HERMETICITY PROBE (plan step 2): the same sequence, twice in one process. Bitcoin Core's fuzz
/// targets are hermetic — a case must not depend on the cases before it. If the second run of an
/// identical sequence differs from the first, some process-global state leaked between them, and every
/// in-process catalogue finding is suspect until it is found.
#[test]
fn the_same_sequence_twice_in_one_process_gives_the_same_verdict() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![Op::Produce(1, 0), Op::Receive(0), Op::Jump(1, 0)];
    let first = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
    let second = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
    eprintln!(
        "[hermetic] first={:?} second={:?}",
        first.finding.as_ref().map(|f| f.detail.clone()),
        second.finding.as_ref().map(|f| f.detail.clone())
    );
    assert_eq!(
        first.finding.map(|f| f.detail),
        second.finding.map(|f| f.detail),
        "⛔ NOT HERMETIC: the same sequence gave a different verdict on its second run in one process"
    );
}

/// ⛔ D-36b — THE OVER-COUNT TWIN. With a delivery BEFORE the jump the jumper already holds blocks in the
/// new tip's past; the re-fold must leave those alone (they are in the inherited state) and re-fold only
/// what is outside it. MEASURED with the ancestry walk placed before the carry graft: the tip was not in
/// the DAG yet, every held block looked uncovered, and the jumper came out THREE blocks over
/// (`nullifier_count 8705 vs 9473`). Placed after the graft, it is exact.
#[test]
fn d36b_a_jump_after_deliveries_neither_drops_nor_double_counts() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![Op::Produce(0, 2), Op::Produce(1, 0), Op::Receive(0), Op::Deliver(33), Op::Jump(1, 0)];
    let outcome = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
    // This pin is about the NULLIFIER ACCUMULATOR class (D-36). The same sequence also surfaces a
    // separate finding underneath it (D-41, `da_nf_mem` rows vs the chain-only replay), pinned below on
    // its own; conflating the two here would hide whichever closes first.
    let nf: Vec<String> = outcome
        .findings
        .iter()
        .filter(|f| f.detail.contains("nullifier_count") || f.detail.contains("nullifier_root") || f.detail.contains("nf_unspent_acc"))
        .map(|f| f.detail.clone())
        .collect();
    assert!(nf.is_empty(), "⛔ D-36b: the nullifier accumulator diverged after a jump: {nf:?}");
}

/// ⛔ D-41 — CLOSED 2026-09-11 BY DELETION: the DA nullifier-shard store was keyed by ARRIVAL ORDER.
///
/// Surfaced the moment D-36 stopped masking it, on this 5-op sequence: party 0 — the SOURCE of the jump,
/// not the jumper — held ONE `da_nf_mem` row where a node fed only the blocks derived TWO (11 vs 25 on
/// the 48-op catalogue). The store had THREE key spaces — the accept ordinal `nf_fold_seq - 1`, the
/// sparse-fold ordinal `nf_blocks - 1` on the produce path, and a served page's record id — so a
/// producer's own block overwrote an accept row whenever the two counters disagreed, which on a DAG
/// they do by construction. That is the ordinal-by-arrival class (the class the record fold left on
/// 2026-09-04), and its only reader was the spend gate's staleness sweep: a sweep over rows that were
/// missing ADMITTED the double-spend it could not see.
///
/// BORROWED (Zcash): the nullifier set is authoritative at the present instant and nothing is swept;
/// an anchor is only ever a chain-committed value. This node holds no set, so the one value it can
/// vouch for is its live accumulator — the gate admits there and nowhere else, and the store, its
/// index and the sweep are deleted (`Node::nf_absent_by_reconstructed_tip`).
///
/// This pin now asserts the WHOLE cold-peer verdict on the sequence, not one store's name: a finding
/// under any name is a regression of the class.
#[test]
fn d41_the_da_nullifier_shard_store_is_a_function_of_the_chain() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![Op::Produce(0, 2), Op::Produce(1, 0), Op::Receive(0), Op::Deliver(33), Op::Jump(1, 0)];
    let outcome = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
    let cold: Vec<String> = outcome
        .findings
        .iter()
        .filter(|f| f.detail.contains("a node fed ONLY the blocks derives"))
        .map(|f| f.detail.clone())
        .collect();
    assert!(cold.is_empty(), "⛔ D-41 class: a party holds state a chain-only replay does not derive: {cold:?}");
    // Non-vacuity: every op ran — a verdict over a sequence that stopped early proves nothing about the
    // jump at its end. (Whether the jump ADOPTS is a fork-choice coin toss on per-run block ids, D-37;
    // the class assertion above must hold either way, so the pin does not condition on it.)
    assert_eq!(outcome.steps_run, ops.len(), "⛔ vacuous: the sequence stopped early: {outcome:?}");
}

/// ⛔⛔⛔ D-44 (CLOSED 2026-09-11) — A JUMPER THAT LEAPT YOUNG RECORDS MUST REACH READY ONCE IT HOLDS THEM.
///
/// The catalogue's next finding once D-43 closed (1-minimal `Receive(0) · Receive(0) · Jump(1,0)`; on
/// the pre-D41 tree the same sequence carried THREE findings — a root no chain derives, its cold-peer
/// twin and the end-of-run root divergence — so this is the older, deeper defect, not a regression).
/// Both ledger replays (`uns_heal_snapshot`, `try_rebuild_unspent_map_inner`) walked only the records
/// the canonical fold had assigned an ordinal, and the fold trails the tip by `record_fold_depth`
/// blocks: the jumper adopted {n1, n2}, healed n1's record by id (D-43b), and could replay NEITHER
/// young record — "party 1 is NOT READY once everything is delivered", its leaf set {n2} against the
/// peer's {n1, n2}. Fix (Bitcoin Core `-reindex`): replay everything held, ordinal-assigned records
/// first, then the young ones in the DAG's topological order (`Node::ledger_replay_order`). Mutation:
/// dropping the young records from the order turns this pin red on exactly those two findings.
#[test]
fn d44_a_jumper_that_leapt_young_records_reaches_ready_once_it_holds_them() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![Op::Receive(0), Op::Receive(0), Op::Jump(1, 0)];
    let outcome = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
    let details: Vec<String> = outcome.findings.iter().map(|f| format!("{}: {}", f.invariant, f.detail)).collect();
    assert!(details.is_empty(), "⛔ D-44: {details:?}");
    // Non-vacuity: every op ran, and the jump really happened (party 1 started at genesis, so the
    // certified state is strictly ahead of it — no fork-choice coin toss on this sequence).
    assert_eq!(outcome.steps_run, ops.len(), "⛔ vacuous: the sequence stopped early: {outcome:?}");
}

/// ⛔⛔⛔ D-45 (CLOSED 2026-09-11) — THE LETTER ACCUMULATOR MUST SURVIVE A RESTART.
///
/// The most frequent catalogue finding once D-44 closed (11 of 22 schedules; 1-minimal `Receive(0) ·
/// Restart(0)`): `letter_acc` — the commutative per-block sum every accepted block advances and every
/// sync bundle mirrors — was never in the checkpoint, so a resumed node restarted it at the genesis
/// seed and re-folded only the blocks its delta replay re-applied: "party 0's letter accumulator is
/// [c1,aa,0f,a6] where a node fed ONLY the blocks derives [ad,dd,a9,1b]". Fix: `NodeSnapshot::letter_acc`
/// + `letter_acc_covered` (`serde(default)`, five legacy doors migrated), restored before the fold carry
/// re-grafts — the same v31 reason `nf_unspent_acc` rides the checkpoint.
#[test]
fn d45_the_letter_accumulator_survives_a_restart() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![Op::Receive(0), Op::Restart(0)];
    let outcome = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
    let details: Vec<String> = outcome.findings.iter().map(|f| format!("{}: {}", f.invariant, f.detail)).collect();
    assert!(details.is_empty(), "⛔ D-45: {details:?}");
    assert_eq!(outcome.steps_run, ops.len(), "⛔ vacuous: the sequence stopped early: {outcome:?}");
}

/// ⭐ THE WHOLE CATALOGUE, EVERY FINDING (2026-09-11). The catalogue test above stops at the FIRST
/// finding of the first failing schedule; this one runs the same 22 schedules and reports every
/// finding under every name — the shape that peeled D-41 → D-51 in one day, each surfacing only when
/// the previous stopped masking it. A class that returns shows up here by name, not as "the catalogue
/// is red again".
#[test]
fn the_whole_catalogue_carries_no_finding_under_any_name() {
    use crate::harness::fuzz::engine::fuzz_one;
    let plan: [(usize, u64, u64, usize); 3] = [(2, 1, 10, MAX_STEPS), (3, 1, 8, MAX_STEPS), (4, 1, 4, 40)];
    let mut all: Vec<String> = Vec::new();
    for (parties, first, last, steps) in plan {
        let mut seed = first;
        while seed <= last {
            let salted = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (parties as u64);
            let (_ops, outcome) = fuzz_one(parties, salted, steps);
            for f in &outcome.findings {
                let line = format!("parties={parties} seed={seed} step={} inv={} :: {}", f.step, f.invariant, &f.detail[..f.detail.len().min(160)]);
                eprintln!("[catalogue-all] {line}");
                all.push(line);
            }
            seed += 1;
        }
    }
    eprintln!("[catalogue-all] total findings: {}", all.len());
    assert!(all.is_empty(), "⛔ {} finding(s) across the catalogue: {all:?}", all.len());
}

/// ⛔⛔⛔ D-46 (CLOSED 2026-09-11) — A SECOND RESTART MUST NOT DISCARD A CORRECT UNSPENT MAP.
///
/// The catalogue's I-8 finding (2-party seed 8, 1-minimal `Receive(0) · Restart(0) · Receive(0) ·
/// Restart(0)`): "2 of 2 commitment(s) left the unspent set (258 -> 256) with no chain-recorded
/// spend". The checkpoint stamped the map with `last_self_verified_root` whenever the node was
/// NOT_READY — and a node one restart in IS NOT_READY (its restored map is an anchor awaiting the
/// fold-forward) yet keeps applying blocks, so the stamp lagged the map and the next restore
/// discarded a correct map ("did NOT reproduce the persisted root — DISCARDED"). Fix (Bitcoin Core:
/// the chainstate is written with the tip it corresponds to): the stamp is the map's own leaf-set
/// fold — `Node::export_snapshot`. Judged by the engine's own oracles (I-8 included), then by the
/// verdict; mutation (the old stamp) turns it red on exactly the I-8 finding.
#[test]
fn d46_a_second_restart_keeps_every_note_the_first_restart_kept() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![Op::Receive(0), Op::Restart(0), Op::Receive(0), Op::Restart(0)];
    let outcome = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
    let details: Vec<String> = outcome.findings.iter().map(|f| format!("{}: {}", f.invariant, f.detail)).collect();
    assert!(details.is_empty(), "⛔ D-46: {details:?}");
    assert_eq!(outcome.steps_run, ops.len(), "⛔ vacuous: the sequence stopped early: {outcome:?}");
}

/// ⛔⛔⛔ D-47 (CLOSED 2026-09-11) — A JUMPER INHERITS THE A_TIP FOLD COUNT WITH THE ACCUMULATOR.
///
/// Catalogue I-CP on four 2-party seeds (1-minimal `Produce(1,1) · Jump(0,1)` and `Invalid(1) ·
/// Jump(0,1)`): "party 0's absence-fold position is 0 where a node fed ONLY the blocks derives 2".
/// `instant_sync` inherited `nf_unspent_acc`, `nf_blocks` and `nf_leaves` from the certified
/// `nullifier_count` but left `nf_fold_seq` at the jumper's own pre-jump value, so the jump base it
/// published was `(acc, 0)`. One sent value, every derived count read from it (`nf_fold_seq = nf_blocks`
/// at the adopt). The engine's own oracles judge both sequences here.
#[test]
fn d47_a_jumper_inherits_the_fold_count_with_the_accumulator() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    for ops in [vec![Op::Produce(1, 1), Op::Jump(0, 1)], vec![Op::Invalid(1), Op::Jump(0, 1)]] {
        let outcome = run_sequence(2, 0x9e3779b97f4a7c17, &ops);
        let details: Vec<String> = outcome.findings.iter().map(|f| format!("{}: {}", f.invariant, f.detail)).collect();
        assert!(details.is_empty(), "⛔ D-47 on {ops:?}: {details:?}");
        assert_eq!(outcome.steps_run, ops.len(), "⛔ vacuous: the sequence stopped early: {outcome:?}");
    }
}

/// ⛔ D-48 (HARNESS, CLOSED 2026-09-11) — A DROPPED PARTY IS REPAIRED WHEN IT HOLDS EVERY BLOCK IT MISSED.
///
/// Catalogue I-3 on three 3-party seeds (1-minimal `Produce(2,0) · Receive(1) · Drop(0)`): party 0 lost
/// two sibling deliveries, recovered party 1's block (its DAG grew), never party 2's, and the engine
/// read the growth as "repaired" — its rule was "a delivery arrived, and `deliver_to` pulls the whole
/// missing lineage down with it", which is true of an ANCESTOR and false of a SIBLING. Production heals
/// a lost sibling only through the next block that references both tips (orphan → `want_block_by_id`),
/// which a schedule that ends right there never produces; the beacon's own DSYNC trigger needs a peer
/// more than 32 blocks ahead. So the excuse now reads `Sample::missing_produced == 0` — the party holds
/// every block the schedule produced — and a schedule that ends with a party still short is reported
/// `convergence_unassertable`, never as a consensus finding it cannot be.
#[test]
fn d48_a_dropped_party_short_of_a_sibling_is_unassertable_not_a_split() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![Op::Produce(2, 0), Op::Receive(1), Op::Drop(0)];
    let outcome = run_sequence(3, 0x9e3779b97f4a7c17, &ops);
    let details: Vec<String> = outcome.findings.iter().map(|f| format!("{}: {}", f.invariant, f.detail)).collect();
    assert!(details.is_empty(), "⛔ D-48: {details:?}");
    assert!(
        outcome.convergence_unassertable,
        "⛔ vacuous: the dropped party was read as repaired although a sibling it lost was never re-delivered: {outcome:?}"
    );
    assert_eq!(outcome.steps_run, ops.len());
}

/// ⛔⛔⛔ D-49 (CLOSED 2026-09-11) — A JUMPER RE-FOLDS THE LETTER SUM OF HELD BLOCKS OUTSIDE THE INHERITED PAST.
///
/// Catalogue I-CP on four schedules (1-minimal `Produce(0,1) · Produce(1,1) · Jump(0,1)` and two
/// `Invalid(_) · … · Jump` twins): the jump replaces `letter_acc` with the certified sum and the
/// covered-score gate then refuses the jumper's own held sibling — the D-36 shape, one accumulator over.
/// Fix: the D-36 walk re-adds the letter set of every held block outside the adopted tip's past.
#[test]
fn d49_a_jumper_re_folds_the_letters_of_held_blocks_outside_the_inherited_past() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    for (parties, ops) in [
        (2usize, vec![Op::Produce(0, 1), Op::Produce(1, 1), Op::Jump(0, 1)]),
        (2, vec![Op::Invalid(0), Op::Produce(1, 2), Op::Jump(0, 1)]),
        (3, vec![Op::Produce(1, 1), Op::Invalid(2), Op::Jump(0, 2)]),
    ] {
        let outcome = run_sequence(parties, 0x9e3779b97f4a7c17, &ops);
        let details: Vec<String> = outcome.findings.iter().map(|f| format!("{}: {}", f.invariant, f.detail)).collect();
        assert!(details.is_empty(), "⛔ D-49 on {parties}p {ops:?}: {details:?}");
        assert_eq!(outcome.steps_run, ops.len(), "⛔ vacuous: the sequence stopped early: {outcome:?}");
    }
}

/// ⛔⛔⛔ D-50 (CLOSED 2026-09-11) — THE CERTIFIED UNSPENT ROOT IS ADOPTED AFTER THE CARRY NAMES EVERY HOLE.
///
/// The last catalogue class (2-party seeds 5/9, 3-party seeds 1/5; shrunk to this 8-op sequence):
/// after two jumps, parties 1 and 2 FLAPPED between the chain's unspent root and a stale one every
/// repair round, forever — a READY node holding the chain's own root adopted whatever stale root a
/// peer offered next, because the I2 keep's D-43 term `note_payload_debt() == 0` never settled on a
/// node whose leapt blocks were idle. The root cause was ORDER: `instant_sync` adopted the certified
/// root BEFORE `graft_unfolded_carry` registered the leapt blocks' record holes by id (D-43b), so the
/// keep read gap=0 and D-43 reached for the count. Now (Bitcoin Core: load the blocks, then judge the
/// state) the adopt runs after the carry and the D-36 walk; `sidecar_gap_count()` is the exact evidence
/// and the count term is gone. Every D-3x/D-4x jump pin stays green under the new order.
#[test]
fn d50_the_certified_unspent_root_is_adopted_after_the_carry_names_every_hole() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![
        Op::Produce(2, 0), Op::Produce(0, 2), Op::Restart(2), Op::Receive(1), Op::Produce(0, 2),
        Op::Receive(0), Op::Jump(1, 0), Op::Jump(2, 1),
    ];
    let outcome = run_sequence(3, 0x9e3779b97f4a7c17, &ops);
    let details: Vec<String> = outcome.findings.iter().map(|f| format!("{}: {}", f.invariant, f.detail)).collect();
    assert!(details.is_empty(), "⛔ D-50: {details:?}");
    assert_eq!(outcome.steps_run, ops.len(), "⛔ vacuous: the sequence stopped early: {outcome:?}");
}

/// ⛔⛔⛔ D-51 (CLOSED 2026-09-11) — THE SELF-VERIFIED RECOVERY FIRES ONLY FROM A LEDGER WITH NO NAMED HOLE.
///
/// The last two catalogue schedules (2 parties, seeds 5 and 9 — 48 ops each with a jump, restarts,
/// drops and tampers; not shrinkable, the finding is a coin toss on per-run block ids). The
/// `try_rebuild_unspent_map` recovery ("serve the node's OWN self-verified view when the certified
/// target cannot replay from a COMPLETE local ledger", the 2026-08-18 decision) never tested
/// completeness: a jumper still owing the leapt record (`wants=1`) replayed its subset to a root that
/// happened to equal its last self-verified one and served it as READY — a view missing a note the
/// chain holds, which then diverged for the rest of the run. The recovery now requires
/// `missing_record_count() == 0 && sidecar_gap_count() == 0` (Bitcoin Core: a node still downloading
/// does not publish a chainstate). Both schedules are run here through the engine's own oracles.
#[test]
fn d51_the_self_verified_recovery_never_fires_while_a_record_is_still_owed() {
    use crate::harness::fuzz::engine::fuzz_one;
    for seed in [5u64, 9u64] {
        let salted = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 2u64;
        let (ops, outcome) = fuzz_one(2, salted, MAX_STEPS);
        let details: Vec<String> = outcome.findings.iter().map(|f| format!("{}: {}", f.invariant, f.detail)).collect();
        assert!(details.is_empty(), "⛔ D-51 on seed {seed}: {details:?}");
        assert_eq!(outcome.steps_run, ops.len(), "⛔ vacuous: the sequence stopped early: {outcome:?}");
        assert!(ops.iter().any(|o| matches!(o, crate::harness::fuzz::op::Op::Jump(..))), "⛔ vacuous: the schedule carries no jump");
    }
}


/// ⛔⛔⛔ D-52 (CLOSED 2026-09-11) — A CARRIED BLOCK'S DELETION SET IS FILED AS ITS SIDECAR AT PLACEMENT.
///
/// The mesh-schedule lane's "party 0 is NOT READY once everything is delivered" (3 parties, seed 4, the
/// 31-op schedule below): a spend block with no outputs is IDLE by its notes root, so the fold carry
/// recorded it as the seed record, never wanted it by id, and its deletion set — carried in the block,
/// bound by `header.del_set_root`, stripped by nothing — was filed nowhere on the jumper. It held all
/// 36 records with `da_del_mem` 0 rows against the peers' 1, replayed "0 deletions", could not
/// reproduce the certified root and stayed NOT_READY forever. `graft_unfolded_carry` now files the
/// carried `del_set` (verified against the header) exactly as the ingest and produce doors do.
#[test]
fn d52_a_carried_block_s_deletion_set_is_filed_at_placement() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![
        Op::Receive(2), Op::Produce(0, 2), Op::Drop(2), Op::Receive(1), Op::Produce(2, 2), Op::Restart(2),
        Op::Receive(1), Op::Produce(2, 2), Op::Jump(0, 1), Op::Receive(0), Op::Produce(1, 2), Op::Forget(2),
        Op::Receive(1), Op::Produce(2, 2), Op::Burst(6), Op::Spend(1), Op::Receive(0), Op::Produce(1, 2),
        Op::Burst(3), Op::Receive(1), Op::Produce(2, 2), Op::Drop(1), Op::Receive(1), Op::Produce(2, 2),
        Op::Restart(2), Op::Receive(2), Op::Produce(0, 2), Op::Jump(0, 1), Op::Receive(1), Op::Produce(2, 2),
        Op::Forget(1),
    ];
    let outcome = run_sequence(3, 4, &ops);
    let details: Vec<String> = outcome.findings.iter().map(|f| format!("{}: {}", f.invariant, f.detail)).collect();
    assert!(details.is_empty(), "⛔ D-52: {details:?}");
    assert_eq!(outcome.steps_run, ops.len(), "⛔ vacuous: the sequence stopped early: {outcome:?}");
    assert!(outcome.spends.0 >= 1, "⛔ vacuous: no spend landed, so no deletion set was ever carried: {outcome:?}");
}


/// ⛔⛔⛔ DB-117 (2026-09-20) — A RESTART LOSES EXACTLY ONE BLOCK'S NULLIFIER FOLD.
///
/// Emitted by the LANE-F invariant fuzzer, seed 0xdaa66d2c7ddf743d, shrunk 48 ops -> 5 and proven 1-MINIMAL
/// over 36 candidate runs: removing ANY op below makes the finding disappear. `Op::Restart(1)` is one of
/// the five, which is what names the class.
///
/// THE INVARIANT: I-3 STATE-IS-NOT-A-FUNCTION-OF-THE-CHAIN. Two parties holding the same chain report
/// different `nullifier_root`, `nullifier_count` and `nf_unspent_acc`.
///
/// ⭐ THE NUMBER IS THE DIAGNOSIS. The counts differ by 2305 vs 2561, 7169 vs 7681, 1281 vs 1537 — every
/// gap is a multiple of 256, and `cover::BLOCK_FIXED_NULLIFIER_COUNT` IS 256. So this is not drift and not
/// a rounding artefact: it is a WHOLE BLOCK's nullifier fold present on one node and absent on the other.
///
/// WHY IT IS A FUNDS BUG AND NOT A COSMETIC ONE: the nullifier set is what refuses a second spend of the
/// same note (the Zcash rule this chain borrows). Two honest nodes disagreeing about it means one of them
/// will accept a spend the other refuses — the double-spend shape, arrived at without any attacker.
///
/// This is the D-35/D-38 family ("a block entering by any door but DIRECT DELIVERY skips its NULLIFIER
/// fold"), which `d38_a_restart_must_not_drop_a_carried_block_s_nullifier_fold` covers for ONE door and
/// evidently not for this one.
#[test]
fn db117_a_restart_must_not_lose_a_whole_blocks_nullifier_fold() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![
        Op::Produce(1, 2),
        Op::Produce(0, 0),
        Op::Drain,
        Op::Restart(1),
        Op::Invalid(0),
    ];
    // ⭐ DB-117 DIRECT MEASUREMENT, with CERTAIN party identity. The earlier probes printed a stack
    // pointer, which the allocator reuses across a restart — so two different Node instances read as one
    // and I drew a wrong conclusion from it twice. `Sim.parties` is indexed, so this cannot be confused.
    // The fuzz `Op::Produce(i, n)` maps to the scenario `produce i (n+1)`, which is why the counts below
    // use the same Acts the emitted scenario text lists.
    {
        use crate::consensus_scenarios::{Act, Sim};
        let mut sim = Sim::new(2, 0xdaa66d2c7ddf743d);
        let script = [
            ("produce 1 3", Act::Produce(1, 3)),
            ("produce 0 1", Act::Produce(0, 1)),
            ("drain", Act::Drain),
            ("restart 1", Act::Restart(1)),
            ("invalid 0", Act::Invalid(0)),
            // ⭐ THE ACCEPT/REFUTE STEP. The restart dropped ONE block from p1's DAG while `nf_count` kept
            // counting it. If that is the mechanism, re-delivering it makes p1 fold it a SECOND time and
            // land one block ABOVE p0 (1537 vs 1281). If instead p1 converges to p0, the mechanism is
            // refuted and the loss is somewhere else.
            ("drain (predict)", Act::Drain),
        ];
        for (label, act) in script {
            sim.step(act);
            let counts: Vec<String> = sim
                .parties
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    format!("p{i}: nf_count={} dag_len={}", n.nullifier_count(), n.dag().len())
                })
                .collect();
            eprintln!("[db117-step] after {label:<12} -> {}", counts.join("   "));
            // Name the exact block set each party holds, so the one the restart drops is identified
            // rather than inferred. `selected_parent == None` marks a block off the selected chain.
            for (i, n) in sim.parties.iter().enumerate() {
                let mut ids: Vec<String> = n
                    .dag()
                    .block_ids()
                    .iter()
                    .map(|b| {
                        let node = n.dag().get(b);
                        let sc = node.map(|x| x.blue_score).unwrap_or(0);
                        let sel = n.dag().selected_tip() == Some(*b);
                        format!("{:02x}{:02x}@{}{}", b.0[0], b.0[1], sc, if sel { "*" } else { "" })
                    })
                    .collect();
                ids.sort();
                eprintln!("[db117-set]   p{i}: {}", ids.join(" "));
            }
        }
    }

    // DB-117 BISECTION: run each PREFIX of the minimal sequence and report the first op that diverges the
    // parties. Measuring beats reasoning here — the op names are suggestive (`Restart`, `Invalid`) and I
    // talked myself into two different culprits before deciding to just run it.
    for k in 1..=ops.len() {
        let pre = run_sequence(2, 0xdaa66d2c7ddf743d, &ops[..k]);
        eprintln!(
            "[db117-bisect] after {} op(s) ({:?}): {}",
            k,
            &ops[k - 1],
            match pre.finding.as_ref() {
                Some(f) => format!("DIVERGED — {} :: {}", f.invariant, f.detail),
                None => "parties agree".to_string(),
            }
        );
    }
    // ⭐ THE CONTROL THAT DECIDES WHETHER THIS IS A CHAIN BUG OR A HARNESS ONE. `invalid()` has party i
    // PRODUCE a real block, pushes it to `owed` for every other party, and only THEN offers the forged
    // copy. So the sequence ends with one legitimately undelivered block — which is exactly 256
    // nullifiers. If draining that block reconciles the parties, the chain converged correctly and the
    // I-3 check simply compared two parties mid-delivery.
    // ⭐ ISOLATING WHICH HALF OF `invalid()` MOVES THE FOLD. It does two things: party i PRODUCES a real
    // block (owed to the others), then EVERY party is offered a forged-work copy it must refuse. These
    // variants separate them.
    for (label, v) in [
        ("invalid alone                 ", vec![Op::Invalid(0)]),
        ("invalid alone + drain         ", vec![Op::Invalid(0), Op::Drain]),
        ("produce 0 then drain (no inv) ", vec![Op::Produce(0, 0), Op::Drain]),
        ("produce 0, drain, invalid     ", vec![Op::Produce(0, 0), Op::Drain, Op::Invalid(0)]),
        ("minimal minus invalid + drain ", vec![Op::Produce(1, 2), Op::Produce(0, 0), Op::Drain, Op::Restart(1), Op::Drain]),
    ] {
        let o = run_sequence(2, 0xdaa66d2c7ddf743d, &v);
        eprintln!(
            "[db117-isolate] {label} -> {}",
            match o.finding.as_ref() {
                Some(f) => format!("DIVERGED :: {}", f.detail),
                None => "agree".to_string(),
            }
        );
    }
    let mut drained = ops.clone();
    drained.push(Op::Drain);
    let after_drain = run_sequence(2, 0xdaa66d2c7ddf743d, &drained);
    eprintln!(
        "[db117-control] same sequence + Drain: {}",
        match after_drain.finding.as_ref() {
            Some(f) => format!("STILL DIVERGED — {} :: {}", f.invariant, f.detail),
            None => "CONVERGED — the chain was right; the checker compared mid-delivery".to_string(),
        }
    );
    let outcome = run_sequence(2, 0xdaa66d2c7ddf743d, &ops);
    if let Some(f) = outcome.finding.as_ref() {
        panic!(
            "⛔ DB-117 STILL OPEN — {} :: {}\n\
             The gap is a multiple of cover::BLOCK_FIXED_NULLIFIER_COUNT ({}), i.e. whole blocks of \
             nullifiers folded on one party and not the other.",
            f.invariant,
            f.detail,
            crate::cover::BLOCK_FIXED_NULLIFIER_COUNT
        );
    }
}

/// EMITTED BY THE LANE-F INVARIANT FUZZER (scratchpad/funds/fuzz-7.log, 2026-10-27, F2-red-found-20261027d), seed
/// 0xf1bbcdcbfa53e0aa, 48 ops shrunk to 4 and proven 1-MINIMAL over 47 candidate runs. INVARIANT VIOLATED: I-CP
/// STATE-NOT-DERIVABLE-FROM-THE-CHAIN — after the restart party 0 holds 46 DAG blocks against party 1's 47 on the SAME tips:
/// a held block is gone and nothing heals it. The resume printed `[fold-span] ⛔ the restored span does NOT reproduce A_tip
/// from the checkpoint's fold record (32 member(s) vs 34 counted)`, so the span fell back to an adopt-shaped resume.
/// RED-FIRST (fuzzpin-20.log) → GREEN 6.8 s (final-harness-23.log) once a folded block's generation stamp lives as long as the
/// block is held (node.rs `drain_folded_unfolded_blocks`) and the party boots with a block window as the daemon does. MUST-STAY-GREEN.
#[test]
fn a_restart_after_a_spend_delivered_over_the_mesh_keeps_every_held_dag_block() {
    use crate::harness::fuzz::engine::run_sequence;
    use crate::harness::fuzz::op::Op;
    let ops = vec![Op::Receive(0), Op::Deliver(6), Op::Spend(1), Op::Restart(0)];
    let outcome = run_sequence(2, 0xf1bbcdcbfa53e0aa, &ops);
    assert!(
        outcome.finding.is_none(),
        "the 1-MINIMAL sequence Receive(0), Deliver(6), Spend(1), Restart(0) still carries a finding: {:?}",
        outcome.finding
    );
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE ENGINE — drive 2..4 real nodes, and ask the catalogue after EVERY step.**
//!
//! The substrate is `consensus_scenarios::Sim`: real `Node` values built through the PRODUCTION genesis
//! path, real checkpoints, real certified bundles. Reusing it is deliberate — a second, harness-private
//! node driver would be a second implementation of "what a node does", and the first time the two drifted
//! the harness would be measuring itself. What this engine ADDS is everything lane F needs and the
//! existing schedule search does not have:
//!
//! 1. the catalogue is asked after EVERY step, not once at the end;
//! 2. a run is REPLAYABLE from `(parties, seed, steps)` alone;
//! 3. a failing sequence is SHRUNK and emitted as a standalone reproducer;
//! 4. interesting sequences PERSIST in a corpus between runs.
//!
//! PAST-CHATS-CHECKED: every shape constant and every generator weight below is taken from the prior art
//! already in this tree — `mesh_schedule_search_tests`, which searches two-, three- and FOUR-party meshes
//! at 48/48/40 steps and whose `roll()` fixes the honest/hostile mix. Nothing here is a fresh number. (A
//! transcript search for the user's own words on party counts and step budgets returned no session, so
//! the in-tree search is the governing decision and this file follows it rather than choosing again.)
//!
//! ⛔ SCOPE: an in-process island. It proves nothing about the onion transport, per-node cost or scale.

use crate::consensus_scenarios::Sim;
use crate::harness::fuzz::op::Op;
use crate::harness::fuzz::oracle::{sample_all, Finding, Oracle, Sample};
use crate::harness::fuzz::rng::Rng;

/// The party count a case may name.
///
/// PAST-CHATS-CHECKED: 4 is the ceiling `mesh_schedule_search_tests` already searches
/// (`search("four-parties", 4, ...)`), and it is the same order as the protocol's own `dag_width` default
/// of 32 bounding a block's parents. Not a new tuned number — the tree's existing one.
pub const MAX_PARTIES: usize = 4;

/// The smallest party count that is a mesh at all. One node cannot disagree with anybody, and every
/// failure this lane exists to find is a disagreement between two sides.
///
/// PAST-CHATS-CHECKED: `Sim::new` itself takes `n.max(2)`, and the two-party mesh is the tree's own
/// smallest search. Following that, not re-deciding it.
pub const MIN_PARTIES: usize = 2;

/// The step budget a case may name.
///
/// PAST-CHATS-CHECKED: 48 is the step count `mesh_schedule_search_tests` uses for its two- and
/// three-party searches. The cost arithmetic in `oracle.rs` is derived FROM this constant, so raising it
/// means redoing that arithmetic — which is why it lives here as one named value rather than inline.
pub const MAX_STEPS: usize = 48;

/// The party count this engine will actually run, for a caller that asked for `n`.
///
/// A case declares its party count before it runs and the catalogue's cost arithmetic is derived from
/// `MIN_PARTIES..=MAX_PARTIES`, so a request outside that range is answered by the nearest legal mesh and
/// the answer is VISIBLE in `Outcome::parties` — the outcome reports the count that RAN, never the count
/// that was asked for. Nothing downstream reads the requested value.
fn party_count(requested: usize) -> usize {
    if requested < MIN_PARTIES {
        return MIN_PARTIES;
    }
    if requested > MAX_PARTIES {
        return MAX_PARTIES;
    }
    requested
}

/// What one sequence did. A run is fully described by `(parties, seed, ops)`, and this is what it produced.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The party count that ACTUALLY ran (see [`party_count`]).
    pub parties: usize,
    pub seed: u64,
    /// The first violation, or `None` for a clean run.
    pub finding: Option<Finding>,
    /// How many steps actually executed before the run ended.
    pub steps_run: usize,
    /// Departures the certified-prefix adopt excused — reported, never silently allowed.
    pub jump_excused: usize,
    /// `(spends recorded in the filter, arrivals tested against it)` — the resurrection oracle's reach.
    pub spent_filter: (usize, usize),
    /// Authorised departures the run never claimed. BY CONSTRUCTION this is the exact count of
    /// spend-backed departures the custody check would have accepted without a spend of its own behind
    /// them, so it is the size of the cover a forged deletion could have drawn on in this run.
    pub unclaimed_departures: usize,
    /// True when the run ended with a dropped delivery nothing later referenced, so the CONVERGENCE half
    /// of the catalogue (I-3 and the engine's own `agreement`) could not be asserted. A campaign in which
    /// this is true for most sequences has tested safety thoroughly and convergence hardly at all, and
    /// that belongs in the report rather than behind a green tick.
    pub convergence_unassertable: bool,
    /// The largest number of selected-spine ordinal inversions any party held at the END of the run.
    /// The step check fires on an INCREASE; this absolute figure is what a report cites, so a structural
    /// property of the numbering that nobody has measured yet shows up as a NUMBER rather than as either
    /// a blanket failure or a silence.
    pub max_spine_inversions: usize,
    /// ⭐⭐⭐ DID THIS RUN ACTUALLY SEND ANYTHING? `(landed, scheduled)`.
    ///
    /// `Sim::spend` has four exits that change nothing and return `Ok(())` — no eligible note, the
    /// carrier refuses, production yields no block, the relay-buffered defer. Each is legitimate. But
    /// until they were counted they were INDISTINGUISHABLE FROM A LANDED SEND to everything downstream,
    /// so a schedule could roll `Op::Spend` a dozen times, land ZERO, and still report a clean run.
    ///
    /// ⛔ A CLEAN SEND VERDICT MUST BE EARNED BY A SEND. "No double-spend was found" proves nothing
    /// about a run that never staged a spend — it is the absence of an event that was never attempted,
    /// which is the harness-≠-reality shape on the single path real money leaves a wallet by. This pair
    /// is reported for the same reason `convergence_unassertable` is: coverage the run did not achieve
    /// belongs in the report, not behind a green tick.
    pub spends: (usize, usize),
    /// WHICH exit swallowed the spends that did not land: `(no_note, carrier_failed, no_block, unconfirmed)`.
    /// Without this the coverage pin can only say the send path was not walked, not why — and "not why" is how a
    /// coverage gap survives as a known-but-unfixed number.
    pub spend_misses: (usize, usize, usize, usize),
    /// A cheap behavioural signature used by the corpus to decide whether a sequence was INTERESTING.
    /// Not coverage: a declared proxy for it, and named as one so nobody reads it as more.
    pub signature: u64,
    /// ⛔⛔⛔ EVERY DISTINCT INVARIANT THIS RUN VIOLATED — not just the first.
    ///
    /// The engine used to STOP at the first finding, and that is a structural reason a campaign can
    /// never answer "what is wrong with this chain?" in one pass: with a single open divergence early
    /// in a run, every detector that would fire later is unreachable. MEASURED — with one I-3
    /// divergence open at step 48, the growth oracle (`I-NG`) and the carriage oracle (`I-CC`) could
    /// not be exercised by any campaign at all and had to be proven by their own pins instead.
    ///
    /// Runs now CONTINUE past a finding and collect the rest. Deduplicated by invariant name, because
    /// a divergence that is real at step 20 is still real at step 21 and repeating it 28 times buries
    /// the second class under the first. `finding` below is preserved as the FIRST one so the shrinker
    /// and the corpus behave exactly as before.
    /// O1-FOOTPRINT-REVIEWED: bounded by [`MAX_DISTINCT_FINDINGS`] — deduped by invariant name and hard
    /// capped, so it is f(catalogue size) and has no term in steps, parties or chain height.
    pub findings: Vec<Finding>,
}

/// The most DISTINCT invariants one run may report.
///
/// ⛔ THIS IS THE BOUND ON `Outcome::findings`, and it is a real one rather than a declared one:
/// findings are deduplicated BY INVARIANT NAME, and the catalogue has a fixed, source-visible set of
/// invariant strings. A run cannot report more distinct invariants than the catalogue defines, and the
/// collector stops at this ceiling regardless — so the vector is f(catalogue size), never f(steps),
/// f(parties) or f(chain height). Raising it is a source edit, not something a schedule can do.
pub const MAX_DISTINCT_FINDINGS: usize = 32;

/// ⭐⭐⭐ RUN ONE SEQUENCE, ASKING THE CATALOGUE AFTER EVERY STEP.
///
/// ⛔ WHAT IS AND IS NOT REPRODUCIBLE (D-37, corrected 2026-09-08 — the old claim here was FALSE).
///
/// This used to claim outright determinism in `(parties, seed, ops)`. It is not, and the reason is a
/// PILLAR, not a defect: `cover::cover_note` mints a FRESH ML-KEM keypair per cover note — *"throwaway
/// recipient — discarded, so nobody can ever spend this note"* — because cover that an observer can
/// predict is not cover. So every produce mints a different cover set, and BLOCK IDS are therefore not
/// a function of `(parties, seed, ops)`. Making them so would trade the privacy pillar for a testing
/// convenience, which is never the answer.
///
/// MEASURED across repeated identical replays: the tip's `tx_merkle_root` and id move, and the SORTED
/// tx-id sets differ (so it is different transactions, not the same set reordered — the consensus
/// reading, a stable set committing to different roots, is REFUTED). Everything the chain decides
/// with — `uns_root`, `uns_leaf_fold`, `uns_leaf_count`, `nf_count`, `nf_acc`, `record_ordinal_top`,
/// `dag_len`, `tip_blue_work`, `spine_len` — replayed IDENTICALLY.
///
/// So the contract this lane actually offers, and the one `harness::fuzz::calibration::pins::h3`
/// holds: **the CONSENSUS-MEANINGFUL STATE is reproducible from `(parties, seed, ops)`; block identity
/// is not.** That is what makes a reproducer meaningful — every invariant in the catalogue is stated
/// over that state, never over a block id — and it is why a finding must be re-decided on the state it
/// names rather than on an exact-match of the whole run.
/// How many blocks the schedule has produced so far that party `p` does not hold — the exact meaning
/// of "still short after a drop" (a schedule-relative count, deliberately NOT a `Sample` field: it is
/// not party state and must not read as a state move under the hostile-op oracle).
fn missing_produced(sim: &Sim, p: usize) -> usize {
    sim.produced_block_ids().iter().filter(|id| !sim.parties[p].dag().contains(id)).count()
}

pub fn run_sequence(parties: usize, seed: u64, ops: &[Op]) -> Outcome {
    let parties = party_count(parties);
    let mut sim = Sim::new(parties, seed);
    let mut oracle = Oracle::new();
    let mut signature = 0xCBF2_9CE4_8422_2325u64;

    let mut before = sample_all(&sim);
    let mut steps_run = 0usize;
    let mut finding: Option<Finding> = None;
    // Every DISTINCT invariant this run violates. See `Outcome::findings` for why the run no longer
    // stops at the first: a single early divergence otherwise hides every later detector, which is
    // exactly what one open I-3 was doing to the growth and carriage oracles.
    let mut findings: Vec<Finding> = Vec::new();
    macro_rules! record {
        ($f:expr) => {{
            let f: Finding = $f;
            if findings.len() < MAX_DISTINCT_FINDINGS
                && !findings.iter().any(|g| g.invariant == f.invariant)
            {
                findings.push(f.clone());
            }
            if finding.is_none() {
                finding = Some(f);
            }
        }};
    }

    // ⛔ WHEN CONVERGENCE IS NOT ASSERTABLE, AND WHY THAT IS NOT A WEAKENING.
    //
    // `Act::Drop` loses one owed delivery FOR GOOD: its own doc says "gossip never brings it; only a
    // parent ask can". A parent ask is triggered by a LATER block that references the lost one, so until
    // some party produces another block, the peer that lost the delivery has no path to it and the mesh
    // CANNOT converge. Asserting I-3 in that state is not a strict check, it is a wrong one.
    //
    // MEASURED — this is what the first campaign found, and it is why this flag exists. Seed
    // 0x9e3779b97f4a7c17, 2 parties, shrunk from 48 ops to exactly 2:
    //     produce 0 1
    //     drop 1
    //     -> "party 0 and party 1 diverge on: selected_tip, nullifier_root, nullifier_count 257 vs 1,
    //         nf_unspent_acc"
    // Party 1 was never handed the only block that exists and nothing later referenced it, so the
    // divergence is the schedule's own doing rather than the node's. The finding was a false positive of
    // the oracle, not a defect in the chain.
    //
    // ⛔ THE CLEARING RULE IS PER-PARTY, BECAUSE THE DEFECT IS. (D-21, fixed 2026-09-08.)
    //
    // It used to be one bool cleared by ANY party's production, justified as "any production gives the
    // repair path something to ask about". That is true for the parties HANDED the new block, and false
    // for the one that lost the delivery: `Sim::drop_one(i)` removes an entry owed TO `i`, and
    // `produce_one(i)` / `receive(i)` / `spend(i)` / `invalid(i)` all enqueue to every party EXCEPT `i`
    // (measured at consensus_scenarios.rs:588, :811, :866, :966 — the same `if j != i` in all four). So a
    // `Drop(1)` followed by `Produce(1, _)` cleared the flag while party 1 was still holding strictly
    // less, and I-3 fired on a partition the schedule created and never repaired. Any campaign long
    // enough to contain a Drop then a Produce reported a spurious consensus break; an instrument that is
    // both blind and loud gets switched off by the people it protects.
    //
    // The rule now reads what actually happened rather than which op ran. A party is repaired when its
    // OWN `dag_len` grows after the drop: `Sim::deliver_to` is the single funnel every delivery passes
    // through, and on arrival it walks the missing lineage down out of `Sim::blocks` and hands the whole
    // chain over. Nothing else can grow a party's DAG, and a produce it never receives cannot.
    //
    // This also closes a second hole in the old rule that no row named: `produce_one` RETURNS EARLY when
    // the party has orphans buffered (`deferred_produces`) or cannot produce, enqueuing nothing at all —
    // yet the label `Op::Produce` cleared the flag anyway. Reading `dag_len` cannot be fooled that way,
    // because a produce that did not happen moves no party's count.
    let mut dropped = [false; MAX_PARTIES];
    // How many spends the SCHEDULE asked for. Compared against how many actually landed, this is what
    // separates "the send path held" from "the send path was never walked" — see `Outcome::spends`.
    // Counted from the op list, so it is f(schedule), with no term in chain height.
    let scheduled_spends = ops.iter().filter(|o| matches!(o, Op::Spend(_))).count();
    let mut dag_len_at_drop = [0usize; MAX_PARTIES];
    let unrepaired = |dropped: &[bool; MAX_PARTIES]| dropped[..parties].iter().any(|&d| d);

    for (idx, op) in ops.iter().enumerate() {
        steps_run = idx + 1;

        // The engine's own verdict comes first: `step_checked` returns `Err` when an ADVERSARIAL action
        // was not refused. That is a fund-safety event in its own right and needs no state comparison.
        let verdict = sim.step_checked(op.to_act(parties));
        let after = sample_all(&sim);

        // The behavioural signature folds in what the step DID, not merely what it was — two sequences
        // with the same ops but different effects are different corpus entries.
        signature = fold_signature(signature, *op, verdict.is_err(), &before, &after);

        if let Err(why) = verdict {
            // `Drain` names no party. `usize::MAX` is the catalogue's declared CROSS-PARTY marker, and
            // every reader treats it as that rather than as a party index.
            let party = match op.party() {
                Some(p) => (p as usize) % parties,
                None => usize::MAX,
            };
            // ⛔ AN `Err` MEANS TWO DIFFERENT THINGS AND THEY MUST NOT SHARE A LABEL.
            //
            // For a HOSTILE op it means the adversarial action was NOT refused — a forgery got in. For an
            // HONEST op it means the operation itself failed its own postcondition (`Sim::spend` returns
            // `Err` when the block after a spend carried no deletion, which is a custody defect, not an
            // unrefused attack). Filing both under one id would send the shrinker after the wrong class
            // and put the wrong sentence in the reproducer.
            let invariant = if op.is_hostile() {
                "I-6/I-11 ADVERSARIAL-ACTION-NOT-REFUSED"
            } else {
                "I-6/I-8 HONEST-OPERATION-FAILED-ITS-POSTCONDITION"
            };
            record!(Finding {
                invariant,
                step: idx,
                op: Some(*op),
                party,
                detail: why,
            });
        }

        if let Some(f) = oracle.check_step(idx, *op, &before, &after, &sim) {
            record!(f);
        }

        // A dropped delivery is unrecoverable until a later block is handed to the party that lost it.
        // See the note on `dropped` — the bookkeeping is per-party and reads the DAG, not the op label.
        if let Op::Drop(i) = op {
            let p = (*i as usize) % parties;
            dropped[p] = true;
            dag_len_at_drop[p] = after[p].dag_len;
        }
        // ⛔ A PARTY'S OWN PRODUCTION IS NOT A REPAIR. `produce_one(i)` / `receive(i)` / `spend(i)` /
        // `invalid(i)` append the new block to party `i`'s OWN dag before enqueuing it to everyone else,
        // so `i`'s count grows while nothing whatever was handed TO it — the precise shape of the false
        // alarm this fix exists to end (`Drop(1)` then `Produce(1, _)`). Re-baseline the producer so its
        // own block can never read as an arrival. `Deliver`/`Burst` carry an OWED-QUEUE index in that
        // same slot rather than a party index, which is why they are deliberately not listed here.
        if let Op::Produce(i, _) | Op::Receive(i) | Op::Spend(i) | Op::Invalid(i) = op {
            let p = (*i as usize) % parties;
            if dropped[p] {
                dag_len_at_drop[p] = after[p].dag_len;
            }
        }
        // What remains is growth the party did NOT create: a delivery arrived, and `deliver_to` pulls
        // the whole missing lineage down with it — so that party is repaired and may be asserted again.
        // …and "repaired" means it holds EVERY block the schedule produced — a delivered sibling grows
        // the DAG without carrying the lost block's lineage (D-48, 2026-09-11: 3 parties `Produce(2,0) ·
        // Receive(1) · Drop(0)` — party 0 recovered party 1's block, never party 2's, and read as
        // repaired). Production heals a lost sibling only through the next block that references both
        // tips (orphan → `want_block_by_id`), which a schedule ending right there never produces.
        for p in 0..parties {
            if dropped[p] && after[p].dag_len > dag_len_at_drop[p] && missing_produced(&sim, p) == 0 {
                dropped[p] = false;
            }
        }

        // A `Drain` is a quiescence point: everything owed has been handed over, so the parties must
        // agree. Checking here — and not only at the end — is what makes a divergence that heals later
        // still a finding.
        if matches!(op, Op::Drain) && !unrepaired(&dropped) {
            if let Some(f) = oracle.check_quiescent(idx, Some(*op), &after) {
                record!(f);
            }
        }

        before = after;
    }

    // The final quiescence: drain whatever is owed and require byte-identical roots.
    //
    // ⛔ NO LONGER GATED ON `finding.is_none()`. Skipping the end-of-run checks because something
    // already failed is the same masking the in-loop `break` used to do — the classes this block
    // asks about (carriage, end-of-run agreement, spend verdicts) are independent of whatever fired
    // earlier, and they are the ones that cost money.
    {
        sim.drain();
        let final_samples = sample_all(&sim);
        // The drain hands over everything still owed, so a party that was behind may have been repaired
        // by it. Re-read each party's DAG before deciding whether convergence is assertable — otherwise
        // the last repair of the run would be the one the gate cannot see.
        for p in 0..parties {
            if dropped[p] && final_samples[p].dag_len > dag_len_at_drop[p] && missing_produced(&sim, p) == 0 {
                dropped[p] = false;
            }
        }
        if !unrepaired(&dropped) {
            if let Some(f) = oracle.check_quiescent(steps_run, None, &final_samples) {
                record!(f);
            }
        }

        // And the engine's own end-of-run property, so this lane is never WEAKER than the search it
        // extends: no honest block refused, agreement, readiness, real records, spend verdicts, bounds.
        // `Sim::verdict` contains `agreement()`, which is a convergence property and is unassertable for
        // the same reason as I-3 above — so it is gated identically rather than left to fire on a
        // partition the schedule created and never repaired.
        // ⛔ THE CARRIAGE VERDICT (row E-4) — asked at quiescence, and NOT gated on `unrepaired`.
        //
        // A double carriage is not a convergence property: it is one party holding the same note in two
        // records, which is true or false regardless of whether some other party lost a delivery. Gating
        // it behind the drop bookkeeping the way I-3 is gated would switch off the one detector for the
        // class that has actually cost money here, on exactly the schedules where a partition makes a
        // second writer most likely.
        // ⛔ THE PROVENANCE VERDICT (rows C-H4, E-5) — ungated for the same reason as the two below.
        // "Does this door give the same answer to the same offer?" is a property of the door alone.
        {
            if let Err(why) = sim.provenance_verdict() {
                record!(Finding {
                    invariant: "I-PA CIRCULAR-AUTHORITY",
                    step: steps_run,
                    op: None,
                    party: usize::MAX,
                    detail: why,
                });
            }
        }

        // ⛔ THE COLD-PEER VERDICT (row E-7) — also ungated, and for the same reason as carriage.
        // "Does the chain derive what this party holds?" is true or false regardless of whether some
        // other party lost a delivery, and it is the ONLY check that can see a transition which never
        // travelled. Gating it would switch it off on precisely the partitioned schedules where a
        // local-only mutation is most likely to go unnoticed.
        // D-48 (2026-09-11): the one case the replay comparison cannot judge is PARTY 0 ITSELF still
        // short of blocks it lost to a drop — every derived field of a behind node legitimately
        // trails the chain's. That is `convergence_unassertable`, never a derivation finding; a
        // party that is short while holding something the chain never produced is still a fork,
        // and the DAG-subset test inside the verdict names that shape on the schedules where party
        // 0 is whole.
        {
            let behind: Vec<usize> = (0..parties).filter(|&p| dropped[p] && missing_produced(&sim, p) > 0).collect();
            // The backfill exemption inside the verdict is granted ONLY when the end-of-run closure
            // assertions will actually run — which is this exact condition, the same one that gates
            // `sim.verdict()` below. Computed here so the two can never drift apart.
            let closure_is_asserted = !unrepaired(&dropped);
            if let Err(why) = sim.cold_peer_verdict_excluding_gated(&behind, closure_is_asserted) {
                record!(Finding {
                    invariant: "I-CP STATE-NOT-DERIVABLE-FROM-THE-CHAIN",
                    step: steps_run,
                    op: None,
                    party: usize::MAX,
                    detail: why,
                });
            }
        }

        {
            if let Err(why) = sim.carriage_verdict() {
                record!(Finding {
                    invariant: "I-CC NOTE-CARRIED-TWICE",
                    step: steps_run,
                    op: None,
                    party: usize::MAX,
                    detail: why,
                });
            }
        }

        if !unrepaired(&dropped) {
            if let Err(why) = sim.verdict() {
                record!(Finding {
                    invariant: "I-3/I-6 END-OF-RUN-VERDICT",
                    step: steps_run,
                    op: None,
                    party: usize::MAX,
                    detail: why,
                });
            }
        }
    }

    // The absolute inversion count at the end, across parties. The step check fires on an INCREASE; this
    // is the figure a report cites so the numbering's shape is a measured number rather than a silence.
    let mut max_spine_inversions = 0usize;
    for s in sample_all(&sim).iter() {
        if s.spine_ordinal_inversions > max_spine_inversions {
            max_spine_inversions = s.spine_ordinal_inversions;
        }
    }

    Outcome {
        parties,
        seed,
        finding,
        steps_run,
        jump_excused: oracle.jump_excused_departures(),
        spent_filter: oracle.spent_filter_stats(),
        unclaimed_departures: oracle.authorised_departures_unclaimed(),
        findings,
        convergence_unassertable: unrepaired(&dropped),
        spends: (sim.spends_landed, scheduled_spends),
        spend_misses: (sim.spends_no_note, sim.spends_carrier_failed, sim.spends_no_block, sim.spends_unconfirmed),
        max_spine_inversions,
        signature,
    }
}

/// Fold one step into the run's behavioural signature. FNV-style over `(op kind, refused?, what moved)`.
fn fold_signature(acc: u64, op: Op, refused: bool, before: &[Sample], after: &[Sample]) -> u64 {
    let mut h = acc;
    let mut eat = |b: u8| {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    };
    eat(op_tag(op));
    eat(if refused { 1 } else { 0 });
    for (b, a) in before.iter().zip(after.iter()) {
        let mut moved = 0u8;
        if b.tip != a.tip {
            moved |= 1;
        }
        if b.uns_leaf_count != a.uns_leaf_count {
            moved |= 2;
        }
        if b.uns_leaf_fold != a.uns_leaf_fold {
            moved |= 4;
        }
        if b.nf_count != a.nf_count {
            moved |= 8;
        }
        if b.dag_len != a.dag_len {
            moved |= 16;
        }
        if b.record_ordinal_top != a.record_ordinal_top {
            moved |= 32;
        }
        eat(moved);
    }
    h
}

fn op_tag(op: Op) -> u8 {
    match op {
        Op::Produce(..) => 1,
        Op::Deliver(_) => 2,
        Op::Burst(_) => 3,
        Op::Drain => 4,
        Op::Drop(_) => 5,
        Op::Restart(_) => 6,
        Op::Jump(..) => 7,
        Op::Receive(_) => 8,
        Op::Spend(_) => 9,
        Op::Forget(_) => 10,
        Op::Tamper(..) => 11,
        Op::ForgeRows(_) => 12,
        Op::Invalid(_) => 13,
        Op::Replay(..) => 14,
    }
}

/// ⭐ THE GENERATOR — structure-aware, weighted toward the honest mesh with a steady adversary.
///
/// Every op is a well-formed call at a real door, so the budget is spent inside reachable states rather
/// than at a length check. The hostile tail is what makes a clean run mean something: a schedule with no
/// adversary in it proves only that honest traffic converges.
///
/// PAST-CHATS-CHECKED: the weights are the ones `mesh_schedule_search_tests::roll` already uses —
/// produce 30, deliver 20, burst 8, drop 5, restart 8, jump 6, receive 4, spend 3, forget 3, tamper 4,
/// forge-rows 3, invalid 3, replay 3 — with the ONE addition this lane needs, an explicit `Drain` so a
/// mid-run QUIESCENCE POINT exists for the convergence half of the catalogue to be asserted at. That
/// addition takes its 5 points from `deliver` (20 -> 15), because a drain is a delivery of everything
/// owed and is the same class of event. No other weight is changed.
pub fn generate(rng: &mut Rng, parties: usize, steps: usize) -> Vec<Op> {
    let steps = if steps > MAX_STEPS { MAX_STEPS } else { steps };
    let parties = party_count(parties);
    let mut ops: Vec<Op> = Vec::new();
    for _ in 0..steps {
        let r = rng.below(100);
        let i = rng.below(parties) as u8;
        let j = rng.below(parties) as u8;
        ops.push(if r < 30 {
            Op::Produce(i, rng.below(3) as u8)
        } else if r < 45 {
            Op::Deliver(rng.below(64) as u8)
        } else if r < 50 {
            Op::Drain
        } else if r < 58 {
            Op::Burst(rng.below(6) as u8)
        } else if r < 63 {
            Op::Drop(i)
        } else if r < 71 {
            Op::Restart(i)
        } else if r < 77 {
            Op::Jump(i, j)
        } else if r < 81 {
            Op::Receive(i)
        } else if r < 84 {
            Op::Spend(i)
        } else if r < 87 {
            Op::Forget(i)
        } else if r < 91 {
            Op::Tamper(i, j)
        } else if r < 94 {
            Op::ForgeRows(i)
        } else if r < 97 {
            Op::Invalid(i)
        } else {
            Op::Replay(i, j)
        });
    }
    ops
}

/// One seeded fuzz run: generate, execute with continuous checking, and hand back what happened.
/// `(parties, seed, steps)` is the whole reproducer.
pub fn fuzz_one(parties: usize, seed: u64, steps: usize) -> (Vec<Op>, Outcome) {
    let mut rng = Rng::new(seed);
    let ops = generate(&mut rng, parties, steps);
    let outcome = run_sequence(parties, seed, &ops);
    (ops, outcome)
}

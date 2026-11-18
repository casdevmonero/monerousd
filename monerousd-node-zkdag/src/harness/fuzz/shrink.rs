// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE SHRINKER — a 48-step find is not a bug report, it is a rumour.**
//!
//! A raw fuzz find is a schedule nobody can read: forty-eight ops across four nodes, most of them
//! irrelevant to the violation. Nobody fixes that. `ddmin` (Zeller's delta debugging) reduces it to a
//! sequence where **removing any remaining op makes the finding disappear** — which is the difference
//! between "the fuzzer went red somewhere" and "these three ops destroy a note".
//!
//! ⛔ THE PREDICATE IS THE INVARIANT ID, NOT "IT FAILED".
//!
//! Shrinking against "any finding" is how a minimiser turns a custody violation into an unrelated
//! liveness one and reports the wrong bug with total confidence. The predicate here requires the SAME
//! `Finding::invariant` to come back, so a minimal case reproduces the finding that was actually found.
//!
//! This also does the work of confirming the resurrection oracle's one-sided error: a Bloom false
//! positive is a coincidence of one schedule, and a coincidence does not survive having its schedule
//! reduced op by op. A finding that shrinks is a finding; one that evaporates was the filter's error and
//! is dropped here rather than reported.
//!
//! **Nothing in this file is a store.** `shrink` hands the minimal sequence BACK to its caller beside a
//! scalar-only report rather than parking it in a struct field: the reproducer is a value in flight, it
//! is consumed by the emitter and dropped, and no type declared here owns a collection at all.
//!
//! **cons: TIME, on the harness only, bounded by fixed constants, and ZERO on a green run.** The
//! shrinker executes only when a finding already exists — a campaign that finds nothing never enters this
//! file. When it does run, every term is f(the case's fixed constants) and none is f(chain history):
//!
//! * one candidate = one `engine::run_sequence` of at most `MAX_STEPS` = 48 steps over at most
//!   `MAX_PARTIES` = 4 nodes, i.e. ≤ 192 node-steps;
//! * candidates are capped at `SHRINK_MAX_CANDIDATES` = 48² = 2,304 (the `ddmin` worst case), so the
//!   absolute worst shrink is 2,304 × 192 = **442,368 node-steps**;
//! * `ddmin` converges in O(n log n) in practice, ≈ 48 × log₂48 ≈ **270 candidates** ≈ 51,840 node-steps.
//!
//! The cost is per FIND, not per block, per note or per peer, and it buys the difference between a
//! 48-op rumour and a 3-op reproducer a person can act on.
//!
//! ⛔⛔ **cons: DISK — and this term was MISSED in the first version of this file, which is exactly the
//! omission the no-cardinal-swap rule exists to catch. The arithmetic, written down now.**
//!
//! Every candidate calls `Sim::new`, which builds a party per `ScenarioDataDir`, and a persisting party
//! is a real directory holding a real `state.snap`. Until 2026-09-08 nothing removed one, so the
//! shrinker's candidate count was a DIRECTORY count, not just a time cost:
//!
//! * MEASURED on this machine after one campaign plus one shrink: **11,161 `musd-scenario-*` datadirs
//!   from 373 distinct test processes**, on a volume 98% full with ~20 GiB left.
//! * ⛔ The first write-up of this sampled three of them at 1.5–2.4 MB and reported "≈ 20 GB". Deleting
//!   all 11,161 actually reclaimed **~3 GB** — the sample was the tail, not the average. Recorded because
//!   an extrapolated figure that goes unchecked is how a real defect gets dismissed when someone later
//!   measures the true one; the DEFECT is the unreleased axis, not the constant.
//! * A worst-case shrink alone was `SHRINK_MAX_CANDIDATES` × `MAX_PARTIES` = 2,304 × 4 = **9,216 node
//!   datadirs for ONE find**, plus one per `Restart` op in every candidate — ≈ 4 GB at the measured
//!   average, **≈ 22 GB at the largest snapshot observed**, none of it released until the machine was.
//!
//! ⛔ That was a disk-exhaustion vector in the instrument itself, on a project that has already taken an
//! ENOSPC outage.
//!
//! ✅ **CLOSED 2026-09-08, at the layer that produces the directory** — `consensus_scenarios::ScenarioDataDir`,
//! an RAII guard `Sim` holds one of per party. The shrinker's disk term is now **f(MAX_PARTIES), not
//! f(SHRINK_MAX_CANDIDATES)**: a whole worst-case shrink owns at most 4 datadirs at a time (≈ 8 MB), each
//! reused across every candidate and every `Restart`, and each removed when its `Sim` drops — including
//! while unwinding from the panic a failing candidate raises. A killed process is covered too: the next
//! run sweeps the datadirs of any `musd-scenario-*` PID that is no longer alive.
//!
//! ⛔ The candidate count remains a TIME budget and nothing here relaxes it — `SHRINK_MAX_CANDIDATES`
//! bounds the run, and a shrink that reaches it still reports `budget_exhausted` rather than claiming a
//! minimality it did not prove.

use crate::harness::fuzz::engine::run_sequence;
use crate::harness::fuzz::op::Op;

/// The most sequences one shrink is allowed to execute.
///
/// PAST-CHATS-CHECKED: not a tuned number — it is derived. `ddmin` over an `engine::MAX_STEPS` = 48
/// sequence needs O(n²) candidates in the worst case (48² = 2,304), and each candidate is a full
/// multi-node run, so the figure is that worst case rather than a number that felt right. A shrink that
/// reaches it returns the smallest case it got to and SAYS SO (`ShrinkReport::budget_exhausted`), rather
/// than running unbounded or silently claiming minimality it did not prove.
pub const SHRINK_MAX_CANDIDATES: usize = 2_304;

/// What the shrink produced, in scalars. The minimal SEQUENCE travels beside this rather than inside it
/// — see the module note — so this type owns no collection and can never become a store.
#[derive(Clone, Debug)]
pub struct ShrinkReport {
    pub parties: usize,
    pub seed: u64,
    /// The invariant id the minimal case still reproduces.
    pub invariant: &'static str,
    /// The finding text from the MINIMAL case — what a reproducer asserts. Never the original run's text.
    pub detail: String,
    /// Ops before and after, so a report can state the reduction rather than claim it.
    pub before_len: usize,
    pub after_len: usize,
    /// How many candidate sequences were executed.
    pub candidates_run: usize,
    /// True when the candidate budget ran out before the case was provably 1-minimal.
    pub budget_exhausted: bool,
}

/// Does this sequence still reproduce `invariant`?
///
/// cons: one `run_sequence` — ≤ 48 steps × ≤ 4 parties = ≤ 192 node-steps, f(the case's fixed step
/// budget), never f(chain height, notes or peers).
fn reproduces(parties: usize, seed: u64, ops: &[Op], invariant: &str) -> bool {
    if ops.is_empty() {
        return false;
    }
    match run_sequence(parties, seed, ops).finding {
        Some(f) => f.invariant == invariant,
        None => false,
    }
}

/// Build the candidate that omits the span `[start, start + len)`.
///
/// cons: none — ONE pass over at most `engine::MAX_STEPS` = 48 ops, and the result is strictly shorter
/// than the input. The bound is the case's fixed step budget; there is no term in chain height, block
/// count, note count or peer count anywhere in it.
fn without(ops: &[Op], start: usize, len: usize) -> Vec<Op> {
    let mut out: Vec<Op> = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        if i < start || i >= start + len {
            out.push(*op);
        }
    }
    out
}

/// ⭐⭐⭐ SHRINK A FAILING SEQUENCE TO A MINIMAL REPRODUCER.
///
/// `ddmin` with granularity doubling: try removing large spans first, halve the span when nothing more
/// can go, and stop when every single op is load-bearing. Also tries reducing the PARTY COUNT, because a
/// three-party reproducer that is really a two-party bug is three times harder to read than it needs to
/// be.
///
/// Returns `(minimal ops, report)`. The sequence is handed back to the caller and dropped there; nothing
/// here retains it.
///
/// cons: the per-find TIME computed in the module note (≈270 candidates typical, 2,304 worst case, each
/// ≤192 node-steps). Zero on a green run, and every bound is f(`MAX_STEPS`, `MAX_PARTIES`) — the case's
/// own fixed constants — rather than f(chain history).
pub fn shrink(
    parties: usize,
    seed: u64,
    ops: &[Op],
    invariant: &'static str,
) -> Option<(Vec<Op>, ShrinkReport)> {
    let before_len = ops.len();
    let mut candidates_run = 0usize;

    // The find must reproduce at all before anything is minimised. A find that does not replay from its
    // own seed is not a find — it is nondeterminism, and reporting it as a bug would waste a day.
    candidates_run += 1;
    if !reproduces(parties, seed, ops, invariant) {
        return None;
    }

    let mut best: Vec<Op> = ops.to_vec();
    let mut best_parties = parties;
    let mut budget_exhausted = false;

    // Fewer parties first: a smaller mesh makes every later candidate cheaper too.
    // cons: none — at most `MAX_PARTIES` - `MIN_PARTIES` = 2 iterations, a fixed protocol shape.
    let mut p = best_parties;
    while p > 2 {
        let smaller = p - 1;
        candidates_run += 1;
        if candidates_run > SHRINK_MAX_CANDIDATES {
            budget_exhausted = true;
            break;
        }
        if reproduces(smaller, seed, &best, invariant) {
            best_parties = smaller;
            p = smaller;
        } else {
            break;
        }
    }

    // ddmin over the op sequence.
    // cons: TIME, bounded twice over — by `SHRINK_MAX_CANDIDATES` = 2,304 on the outside and by
    // `best.len()` ≤ `engine::MAX_STEPS` = 48 on the inside. Both are the case's fixed constants; neither
    // grows with the chain, and the loop terminates because every iteration either shrinks `best` or
    // doubles the granularity toward `best.len()`.
    let mut granularity = 2usize;
    while !budget_exhausted && best.len() >= 2 {
        let span = (best.len() / granularity).max(1);
        let mut removed_any = false;
        let mut start = 0usize;
        while start < best.len() {
            let candidate = without(&best, start, span);
            candidates_run += 1;
            if candidates_run > SHRINK_MAX_CANDIDATES {
                budget_exhausted = true;
                break;
            }
            if reproduces(best_parties, seed, &candidate, invariant) {
                best = candidate;
                removed_any = true;
                // Do not advance `start`: the span now holds different ops and they may go too.
            } else {
                start += span;
            }
        }
        if budget_exhausted {
            break;
        }
        if removed_any {
            // Something went; try the same granularity again before refining.
            granularity = 2;
        } else if granularity < best.len() {
            granularity *= 2;
        } else {
            break; // 1-minimal: no single op can be removed.
        }
    }

    // The minimal case is re-run once more so the reported detail comes from the case that will actually
    // be pasted into a pin — never from the original 48-step run.
    let outcome = run_sequence(best_parties, seed, &best);
    let finding = outcome.finding?;
    if finding.invariant != invariant {
        return None;
    }

    let report = ShrinkReport {
        parties: best_parties,
        seed,
        invariant,
        detail: finding.detail,
        before_len,
        after_len: best.len(),
        candidates_run,
        budget_exhausted,
    };
    Some((best, report))
}

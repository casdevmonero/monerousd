// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ **IS THIS CHAIN SAFE FOR REAL FUNDS?** — ONE VERDICT, COMPOSED FROM EVERY CENSUS.
//!
//! ⛔⛔⛔ WHY THIS EXISTS, AND IT IS A CRITICISM OF HOW THE WORK WAS BEING DONE.
//!
//! Asked on 2026-09-24 — *"how close are we to completion and do you actually know when to call the
//! chain completed?"* — the honest answer was **no**. Defects were being found one at a time, each
//! measured, each fixed, each written up. That is unbounded: a hunt with no termination condition can
//! never say "yes", and every green it reports is worth less than it looks because nothing states what
//! the greens have to ADD UP TO.
//!
//! The censuses were already there and each answers its own question well —
//! [`crate::harness::e2e_claims`] (can a user MOVE this?), [`crate::harness::fund_loss`] (can a note a
//! user ALREADY OWNS stop being findable?), [`crate::harness::privacy`] (does viewing this leak?),
//! [`crate::harness::value_creation`] (AUTHORITY / AMOUNT / ONCE / TRAVELS), [`crate::harness::seam`]
//! (cited everywhere, called nowhere), [`crate::harness::vacuity`] (did the gate EXECUTE on an input
//! that could fail it), `harness::fuzz::authority` (do two honest nodes AGREE). **Nothing composed
//! them**, so "are we done" had no answer and could not be given one.
//!
//! ## WHAT COMPLETION MEANS HERE, STATED SO IT CAN BE FALSIFIED
//!
//! Real funds are safe when, and only when, EVERY criterion below is met AT ITS TARGET. Each one names
//! how it is measured. A criterion that cannot be measured is not a criterion — it is an opinion, and
//! this module refuses to carry one.
//!
//! ⛔ THE LIST IS SHRINK-ONLY IN THE "NOT MET" DIRECTION, and every target is a CEILING that may be
//! LOWERED and never raised ([[feedback_never_argue_a_security_bound_down]]).
//!
//! ⭐ AND IT IS DELIBERATELY NOT A PASS/FAIL TEST THAT BLOCKS A BUILD. It is a REPORT: the number, the
//! blockers, and what each blocker is waiting on. A readiness gate that fails the suite would be muted
//! within a day, and a muted gate is how a chain ships unsafe.

use std::fmt;

/// How a criterion is measured — the thing that makes it falsifiable rather than an opinion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Measured {
    /// Computed inside THIS process, right now, from a census this module reads directly. The strongest
    /// kind: it cannot go stale.
    Live,
    /// Measured by a named test that must be RUN (it is too slow or too stateful for this report), with
    /// the last observed value recorded beside it. ⛔ A recorded number is a SNAPSHOT and says so.
    ByTest(&'static str),
    /// Measured on real `usdmd-node` processes or the live pair — the standard
    /// ([[feedback_real_node_test_is_the_standard]]).
    OnRealNodes(&'static str),
}

/// One condition that must hold before a person's money is safe here.
#[derive(Debug, Clone, Copy)]
pub struct Criterion {
    /// What must be true, in the words a person would use.
    pub name: &'static str,
    /// How it is measured. No criterion may exist without one.
    pub how: Measured,
    /// Where it stands NOW: `(current, target)`. Met when `current <= target` for a ceiling, or the
    /// criterion's own predicate for a live one.
    pub current: u64,
    pub target: u64,
    /// `true` when lower is better (a ceiling); `false` when the numbers are "proven out of total".
    pub ceiling: bool,
    /// What the gap is waiting on. Names the BLOCKER, never the intention.
    pub blocker: &'static str,
}

impl Criterion {
    #[must_use]
    pub fn met(&self) -> bool {
        if self.ceiling {
            self.current <= self.target
        } else {
            self.current >= self.target
        }
    }
}

/// ⏸ Criteria the USER has deferred (user 2026-09-28, usage rule 3). They stay in the standard and stay UNMET, so a
/// deferral is never a pass and "N of 13" is unchanged. The report marks them ⏸, which keeps them out of the drift
/// guard's open rows: no agent spends tokens on a criterion only the user can unblock.
pub const DEFERRED_BY_USER: &[(&str, &str)] = &[(
    "nodes across >=2 devices at the scale floor",
    "the second device (the iPhone) is unavailable; the user deferred 2-device work on 2026-09-27",
)];

/// Why the user deferred this criterion, if they did.
#[must_use]
pub fn deferred_by_user(name: &str) -> Option<&'static str> {
    DEFERRED_BY_USER.iter().find(|(n, _)| *n == name).map(|(_, why)| *why)
}

impl fmt::Display for Criterion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mark = if self.met() {
            "✅"
        } else if deferred_by_user(self.name).is_some() {
            "⏸"
        } else {
            "⛔"
        };
        let how = match self.how {
            Measured::Live => "live".to_string(),
            Measured::ByTest(t) => format!("test {t}"),
            Measured::OnRealNodes(t) => format!("REAL NODES {t}"),
        };
        write!(
            f,
            "{mark} {:<46} {:>9} / {:<9} [{}]",
            self.name,
            self.current,
            self.target,
            how
        )
    }
}

/// ⭐⭐⭐ THE LIVE HALF — every criterion this process can measure for itself, right now.
///
/// These read the censuses directly, so they can never be stale and never need maintaining. A census
/// that grows a new hole shows up here on the next run with no edit anywhere.
#[must_use]
pub fn live_criteria() -> Vec<Criterion> {
    use crate::harness::{e2e_claims, privacy, value_creation};

    // ── 1. CAN A REAL USER MOVE EVERY KIND OF VALUE? (the question people actually ask)
    // ⭐⭐⭐ DB-197 — THE DENOMINATOR IS CLASSES THAT ACTUALLY MOVE VALUE.
    //
    // `Moved::NoValueOfItsOwn` entries stay in the register (so their absence is never read as
    // coverage) but asking "can a user MOVE this" of a resting offer is the wrong question, and while
    // they counted here the target could never be reached no matter what anyone built. A criterion that
    // cannot be met is permanent red for a reason that is not a defect.
    let total = e2e_claims::VALUE_CLASSES
        .iter()
        .filter(|(_, m)| !matches!(m, e2e_claims::Moved::NoValueOfItsOwn(_)))
        .count() as u64;
    // ⭐ DB-218 — A CLASS COUNTS ONLY IF THE PIN IT NAMES EXISTS. The variant alone is a claim; the pin is
    // the evidence, and the same reader backs the register's own completeness test, so the two cannot
    // disagree about which pins are real.
    let pin_exists = e2e_claims::claimed_pins_that_exist();
    // ⛔⛔⛔ JOURNEY LEDGER (user 2026-10-03): a real-node row counts while its journey's MOST RECENT recorded run PASSED
    // (`e2e_claims::real_node_pins_whose_latest_run_passed`), never because its pin spawns the binary. A failed re-run demotes
    // it, and a later pass restores it. MEASURED why: rows stood on journeys that had been red for days (the OrderFill drip,
    // two DSYNC known reds), while passes that DID happen were never counted as evidence.
    let passed = e2e_claims::real_node_pins_whose_latest_run_passed();
    let mut unverified: Vec<&str> = Vec::new();
    let real = e2e_claims::VALUE_CLASSES
        .iter()
        .filter(|(_, m)| match m {
            e2e_claims::Moved::RealNodes(pin) if pin_exists(pin) => {
                let ok = passed(pin);
                if !ok {
                    unverified.push(pin);
                }
                ok
            }
            _ => false,
        })
        .count() as u64;
    let backfilled = e2e_claims::real_node_pins_counting_on_backfill();
    if !backfilled.is_empty() {
        eprintln!(
            "[readiness] {} RealNodes row(s) count on a BACKFILLED pass (documented, not yet re-run since the ledger began — the \
             nightly batch re-verifies these first): {}",
            backfilled.len(),
            backfilled.join(", ")
        );
    }
    if !unverified.is_empty() {
        eprintln!(
            "[readiness] {} RealNodes row(s) whose latest recorded run is not a PASS ({}): {}",
            unverified.len(),
            e2e_claims::JOURNEY_PASS_LEDGER,
            unverified.join(", ")
        );
    }
    let proven = e2e_claims::VALUE_CLASSES
        .iter()
        .filter(|(_, m)| {
            matches!(
                m,
                e2e_claims::Moved::RealNodes(pin) | e2e_claims::Moved::CrossNode(pin) if pin_exists(pin)
            )
        })
        .count() as u64;

    // ── 2. DOES VIEWING THE CHAIN LEAK? (content / shape / linkage / ordering, per surface)
    // ⭐⭐⭐ DB-196b — AN OPEN SURFACE **OR** A CENSUS THAT NO LONGER COVERS THE BLOCK.
    //
    // Counting `SURFACES` alone means a field added to `Block` tomorrow is invisible to a viewer-leak
    // criterion, because the criterion only counts the surfaces somebody already wrote down. Counting
    // the universe gaps here makes that impossible: the census stops covering the block, the criterion
    // goes red, with no edit anywhere. Same shape as the value-creation side above.
    let priv_gaps = privacy::census_universe_gaps();
    let priv_open = privacy::SURFACES.iter().filter(|s| !s.is_closed()).count() as u64
        + priv_gaps.len() as u64;

    // ── 3. CAN VALUE BE CREATED WITHOUT AUTHORITY, IN THE WRONG AMOUNT, TWICE, OR LOCALLY?
    // ⭐⭐⭐ DB-196 — AN OPEN SITE **OR** A CENSUS THAT NO LONGER COVERS ITS UNIVERSE.
    //
    // This line used to count open `SITES` only, so it reported ✅ on 2026-09-25 while
    // `every_local_note_minting_function_is_in_the_census` was RED. A criterion backed by a census is
    // only as good as that census still covering its universe; counting the universe gaps here means a
    // census that stops covering it turns the criterion red by construction, with no edit anywhere.
    let vc_gaps = value_creation::census_universe_gaps();
    let vc_open = value_creation::SITES.iter().filter(|s| !s.is_closed()).count() as u64
        + vc_gaps.len() as u64;

    vec![
        Criterion {
            name: "value classes a user can move AT ALL",
            how: Measured::Live,
            current: proven,
            target: total,
            ceiling: false,
            // The count is the row's own `current / target` beside this text; a number written here went
            // stale (it said 13 while the register filed 6) — each Unproven row names its own blocker.
            blocker: "every class filed Unproven in the e2e register has no pin that carries the value and \
                      asserts on a second party — each row names its own blocker. As of 2026-09-30 the four are \
                      YieldClaim, stake_note and bond_note (the bond pause: DB-274 P4 → P5 → unpause; P4a waits on \
                      the §8.13 shell-set carry) and Liquidation (after the peg ledger joins the fold, P6). ble_tap_pay \
                      is proven on real processes (2026-09-27); DB-240 closed PriceMark and PegIn (2026-09-26)",
        },
        Criterion {
            name: "value classes proven on REAL NODE PROCESSES",
            how: Measured::Live,
            current: real,
            target: total,
            ceiling: false,
            blocker:
                "an in-process second party shares your address space, so a LOCAL MUTATION and a chain \
                 object look identical — the exact class this register exists to catch",
        },
        Criterion {
            name: "privacy surfaces still leaking",
            how: Measured::Live,
            current: priv_open,
            target: 0,
            ceiling: true,
            blocker:
                "each open surface names its own gap (content / shape / linkage / ordering). DB-165 \
                 closed the two that leaked VOLUME — `output_notes` (0 B quiet / 5,765 B busy = exactly \
                 five notes) and `credit_set` (0 / 6,015) — by taking them off the wire and committing \
                 256 constant-width note commitments instead; and it REFUTED two declarations that were \
                 never measured (`pow_proof` measures 32 B flat, `cover_transition` was not probed at \
                 all).",
        },
        Criterion {
            name: "value-creation sites not fully answered",
            how: Measured::Live,
            current: vc_open,
            target: 0,
            ceiling: true,
            blocker:
                "each open site names which of AUTHORITY / AMOUNT / ONCE / TRAVELS is missing — and \
                 since DB-196 this count also includes any gap in the census's own UNIVERSE (a minting \
                 function in no census, or a reader that found too few to have established one), so a \
                 census that stops covering what it audits can no longer read green here",
        },
        // ── CUSTODY KEY SAFETY (user 2026-09-28: "add custody key safety to the score").
        Criterion {
            name: "custody key safety gaps",
            how: Measured::Live,
            current: crate::harness::custody::open_gaps() as u64,
            target: 0,
            ceiling: true,
            blocker:
                "every secret a node keeps is owner-only (umask 077 first in main), per node, never served, and no \
                 key-safety feature can stop a node (sealing at rest is the operator's OPT-IN, never a start gate; \
                 user 2026-09-28). A bonded identity is derived from the operator's seed and provisioned \
                 automatically by the wallet's bond flow (no setup, no password), and /sign_bond signs only for it, \
                 so no lost file strands a bond. The census is harness::custody; any gap it counts is named there",
        },
    ]
}

/// ⛔ THE MEASURED-ELSEWHERE HALF — conditions whose measurement is too slow, too stateful or too
/// REAL to run inside a unit report. Each carries the number last observed and the test that produced
/// it, so a reader can re-run the measurement rather than trust this line.
///
/// ⛔⛔⛔ EVERY NUMBER HERE IS A SNAPSHOT AND IS DATED. A snapshot that drifts is exactly the defect
/// [[feedback_stale_note_guard]] names, so each entry says which test re-measures it.
#[must_use]
pub fn measured_elsewhere() -> Vec<Criterion> {
    vec![
        // ── THE LIVE DOUBLE SPEND. Nothing else on this list outranks it.
        Criterion {
            name: "DB-160: below-base double spend, % of tags refusable",
            how: Measured::ByTest("the_gate_refuses_every_below_base_tag_at_every_mesh_size_when_the_copath_is_omitted"),
            current: 1000, // per mille of sampled below-base tags the GATE refuses at a 1,024-node mesh
            target: 1000, // 100.0%
            ceiling: false,
            blocker:
                "⛔⛔⛔ DB-358 (2026-09-28): THIS ROW MEASURES THE POOL GATE ONLY. The block path was measured RED \
                 (`a_peer_refuses_a_second_spend_of_one_nullifier_carried_in_a_later_block`: a peer fed only the blocks \
                 credited a producer's second spend of one nullifier). It now refuses it at the canonical record fold, \
                 through a restart too. The joiner and deep-reorg residuals (docs/DB-358 §8) stay the ordinary-spend \
                 site's ONCE gap in the census (`value_creation::SITES`). ⭐ CLOSED BY DB-217 (2026-09-25) FOR \
                 THE POOL GATE, RE-MEASURED 2026-09-26 THROUGH THE GATE ITSELF. The row \
                 used to name `the_db160_containment_covers_only_a_shrinking_share_…`, a MODEL that \
                 computes owned/total from the shard policy and calls no gate — it read 0.4% because an \
                 omitted copath returned `Unprovable`, which PASSED. DB-217 made the gate require a \
                 POSITIVE `Unspent` for every tag (carried copath, else this node's own view); `Unprovable` \
                 REFUSES. The named test drives `nf_absent_by_reconstructed_tip` with a valid absence \
                 carrier and NO copath for 16 below-base tags at meshes 4..1,024 and asserts every one \
                 refused, with a calibration that the view is blind to most of them at 1,024 — it prints \
                 `criterion 5: 1000 per mille`. ⛔ THE COST, measured in the same test: an honest spend \
                 with no copath is refused where this node's view cannot see its tag (fail-closed on the \
                 item) — DB-221's recent-root ring admits a carried copath up to 63 blocks old, and a \
                 viewless node's liveness is criterion 11's number, not this one's.",
        },
        // ── PILLAR 4: the constant-proof ceiling.
        Criterion {
            name: "per-block folded carrier bytes",
            how: Measured::ByTest("the_fold_one_carrier_replaces_per_block_witnesses_and_rejects_a_broken_chain"),
            current: 89_013,
            target: 1_800_000,
            ceiling: true,
            blocker:
                "⭐ DB-213 (2026-09-25): 4,998,510 -> 89,013 B (56.2x). The per-item-table carrier paid a \
                 full set of column openings PER INSERT; the 256 walks now fold onto ONE table (the \
                 zerocheck is high-bit-first and a walk is 2^8 rows, so the low 8 variables index the row \
                 within an insert and every selector survives — at n=1 the AIR is identical to the \
                 per-table one, pinned). ⛔ DB-213b: the batch verifier read the ROW COUNT from the \
                 carrier, and a 2-insert table presented as a 1-insert statement VERIFIED (calibration \
                 arm) — a forged nullifier root; both sparse block verifiers now pin their shapes, and the \
                 audit of every other production verifier is a claimed lane. ⛔ WHAT THIS DOES NOT CLAIM: \
                 no production block carries this proof yet — MEASURED prove time 24,608 ms against the \
                 500 ms block (DB-153's residual, unchanged by a size fix), verify 4 ms; it is still 1.77x \
                 the 50,176 B of compressed witnesses; and it is 3.6x over the owner's <=25 KB-per-block Tor \
                 target, which needs the recursive fold across blocks",
        },
        // ── NO GROWTH ON ANY AXIS.
        // ⛔⛔⛔ TARGET FOLLOWS THE USER'S DECISION (2026-09-28, [[feedback_db223_q2_mesh_sharded_witness_index]]): the
        // nullifier view GROWS, split mesh-wide by SOUND sharding (DB-353's shard + band: a block carries per-tag band
        // values, +8,192 B/block at s=8, not built yet). The target is each node's SHARE of a block's cover width at the
        // 5-node scale floor, ceil(width × replication ÷ 5), not 0. It is met only by sound sharding; a view that drops
        // what it must hold is refused by the DB-160 and DB-353 pins. The share falls as the mesh grows: at 40 nodes it
        // is ceil(256 × 4 ÷ 40) = 26.
        Criterion {
            name: "retained nullifier-view entries per block per node",
            how: Measured::ByTest("runtime_footprint_is_flat_while_producing"),
            current: 256,
            target: (crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64
                * crate::node::Node::NF_SHARD_REPLICATION as u64)
                .div_ceil(5),
            ceiling: true,
            blocker:
                "the sparse nullifier view grows by the fixed cover width every block = O(height) on \
                 the produce path. ⛔ AND IT CANNOT SIMPLY BE DEFERRED OFF THE APPLY LOCK — DB-171 tried \
                 exactly that (enqueue on ingest, budgeted pump, flush on produce) on the reasoning that \
                 the view is a SERVING cache, and D-38 went red in one run: *party 0 reads published \
                 nullifier #0 as Unspent — this party would admit that note a second time*. Updating a \
                 sparse Merkle root on insert REQUIRES the copath, and the copath IS the tree walk, so \
                 `sparse_acc` is not separable from the view and deferring the view defers the SPENT SET. \
                 Reverted. Retiring it breaks DB-160 soundness instead; DB-154 dissolves both",
        },
        // ── THE CHAIN MUST BE ABLE TO CONVERGE, ON REAL NODES.
        Criterion {
            name: "ecosystem gate runs converged (of 3 sampled)",
            how: Measured::OnRealNodes("ecosystem-check.sh step 1"),
            current: 3,
            target: 3,
            ceiling: false,
            blocker:
                "⭐ RE-MEASURED 2026-09-27 22:3x FROM THE GATE SCOREBOARD (scratchpad/gate-scoreboard.tsv), NOT FROM \
                 A STREAK READ AS A RATE: the last three gate RUNS each converged at step 1 — Q13 (821ef964, 17:44, \
                 h1=969 h2=966), Q14 (43f868e8, 21:42, h1=79 h2=79 at t+63 s, one selected chain) and Q16 (ea0bdc41, \
                 22:29, h1=61 h2=57 at t+47 s, one selected chain); Q15 was a BUILD failure, not a run. Q11 and Q12 \
                 converged too: 5 consecutive since Q10 failed step 1 at 14:05. What makes this more than the old \
                 streak below is a MECHANISM measured before it: the netsim rule (a pair is one chain iff relay \
                 latency < the per-node block interval: 100% at 4 s per node, 8-17% at <= 2 s) and the relay floor \
                 built on it (each node spaces its own blocks >= PRODUCTION_RELAY_FLOOR_MS = 4 s), which landed \
                 before Q14. This counts the criterion's OWN window (3 sampled); the next run that fails step 1 \
                 puts the number back. THE EARLIER RECORD: ⛔ I MARKED THIS MET AND IT IS NOT. Gates 21-29 gave a six-run converging streak and I \
                 recorded 3/3; the NEXT NINE runs are 4/9 (35✅ 36❌ 37✅ 38✅ 39❌ 40✅ 41❌ 42❌ 43❌). A \
                 streak is not a rate, and this module exists to hold numbers that can be falsified — so \
                 the number goes back to 1 until a measured sample supports otherwise. Over every \
                 unconfounded run since DB-181 it is 13/19 (~68%). ⛔ THE FAILURES ARE NOT ONE CAUSE: \
                 every recent run carries Tor-bootstrap noise (`unpublished-service: our onion is not \
                 yet reachable`, `ZERO inbound messages drained, 0 known peer(s)`) but it does NOT \
                 predict the outcome — gate 38 PASSED with 21 such events and gate 39 FAILED with 4. \
                 The convergence work below is real and the numbers it cites hold; what is not \
                 established is that convergence is RELIABLE, and that is what this criterion asks. \
                 THE WORK THAT GOT IT THIS FAR: It took EIGHT distinct \
                 defects, each hidden behind the one in front of it: DB-167 (every Poseidon re-derived \
                 its round constants per hash, 3,619 -> 936 ns), DB-172/173/175 (the catch-up stall \
                 detector was fed only by the event it exists to unblock, waited out a 90 s horizon on a \
                 widening gap, and read any shrinkage at all as 'closing it' — 61 -> 57 over 91 s projects \
                 22 minutes), DB-174 (the node 141 blocks AHEAD decided 7 times of 9 that nobody was \
                 behind it, because the lighter-beacon stamp sat inside `if !dag.holds(peer.tip)` and a \
                 peer that is behind has a tip you DO hold), DB-177/180 (the have-list answered two \
                 different questions with one list, so naming an orphan deleted the ancestors that would \
                 connect it: `candidates 0 — page 0` -> `candidates 23 — page 23`), DB-181 (two uncounted \
                 `continue`s in the emit loop) and DB-182 (DB-165's rehydration was wired into \
                 `ingest_block` but NOT `ingest_block_preverified`, the path every gossiped block takes). \
                 THE ORIGINAL TEXT, KEPT because the causes it names are what the fixes removed: (1) DB-167: every Poseidon re-derived its round constants per hash — \
                 `apply_preverified` median 872/935 ms against a 500 ms block on BOTH nodes. Fixed \
                 (3.9x); gate 8 then CONVERGED h1=154 h2=153 in 116 s and the money path passed in 4 s, \
                 the first convergence in four runs. (2) With apply at ~21% duty the remaining failure is \
                 SYNC, not apply: every gossiped peer block arrives as an ORPHAN (gate 12: 23 of 23 \
                 `Buffered`) and the by-id lane cannot supply their parents — the server has pruned below \
                 its retention floor and reports `candidates 0` while holding 128 blocks. The code names \
                 the designed answer itself: that gap belongs to the certified bundle. (3) DB-172: the \
                 catch-up STALL detector was fed only by bundle ARRIVALS while the ask was suppressed \
                 inside the depth — no ask, no sample, no verdict, no ask. Fed from the beacon now, and \
                 the `no jump` refusal went 2 -> 0 with a real adopt landing. (4) DB-173: a WIDENING gap \
                 is a stall immediately, which moved the adopt from 96% through the run to 59%. STILL \
                 RED: gate 13 h1=177 h2=318, the behind node asking 4 times and adopting 0",
        },
        Criterion {
            name: "ecosystem gate steps passed (of 8)",
            how: Measured::OnRealNodes("ecosystem-check.sh"),
            // ⭐ MEASURED 2026-09-27 21:42, gate Q14 (lane-dsol-zkvm; node 43f868e8 + harness a24984c3, both built from
            // the live tree at 21:29-21:30; scoreboard row): DEPTH 8, steps 1-8 all pass, 14 green checks. Converged
            // h1=h2=79 at t+63 s on ONE selected chain; faucet 25 spendable; the ROLLING RESTART kept 25.0 on both nodes
            // (the step that held Q11-Q13 at depth 2); cross-node send 7.0 landed; letter + profile resolved cross-node.
            // The change that moved it: the per-node relay floor (fair_share_spacing_ms >= 4 s, derived from the Tor
            // relay cadence and measured in netsim). ONE run: a single depth-8 sample after three depth-2 runs is not a
            // rate, and the next gate must hold 8 before anyone calls it stable.
            current: 8,
            target: 8,
            ceiling: false,
            blocker:
                "steps 1 and 2 now PASS on real nodes (convergence 50-130 s; the faucet credit spendable \
                 in 4-5 s). Step 3, the rolling restart, is the next and its cause is now named exactly \
                 rather than guessed at — the restarted node prints \
                 `[da-want] 32 record(s) wanted by id but the headers-first span is still OPEN, so the \
                 ask is held` while showing ZERO refusals of any kind and 499 records verified. Heights \
                 track perfectly throughout (gap 0-3, roots EQUAL), so consensus is sound; only the DA \
                 backfill is stuck, behind a span that will not close. ⛔ DB-187 tried giving that span's \
                 roots-run ask its own in-flight slot and consensus priority; two gate runs showed it \
                 REGRESSED step 1 without reducing the refusals, and it was reverted",
        },
        // ── THE LIVE CHAIN MUST BE ALIVE. It is not.
        Criterion {
            name: "live testnet nodes producing blocks",
            how: Measured::OnRealNodes("/get_info height sampled over 60s"),
            current: 2,
            target: 2,
            ceiling: false,
            blocker:
                "⭐ MEASURED 2026-09-28 19:2x after the completed RE-GENESIS (pre-authorized by the user): 27780 blue \
                 614 → 668 (408 produced) and 28901 blue 614 → 671 (21 produced since its restart), one chain. \
                 27780 had been exit-97 looping on a schema-35 snapshot. 28901 had built its own branch (blue 210, two \
                 tips) and never reorged onto the heavier one: that is the pair-divergence class, kept as evidence in \
                 `*.divergedBranch-20260928`. Re-sample `/get_info` over 60 s before trusting this row",
        },
        // ── A NODE THAT RESTARTS MUST STILL BE ABLE TO PROVE A NOTE UNSPENT.
        Criterion {
            name: "minutes a restarted node cannot serve Lane A",
            how: Measured::OnRealNodes("/get_nf_copath + nf_view_matches_acc across a rolling restart AND a DSYNC jump"),
            current: 9,
            target: 0,
            ceiling: true,
            blocker:
                "⛔ THE WORSE MEASURED RESTART PATH COUNTS. 2026-09-28 [slotJ2jump], the UNCONFOUNDED rerun (no build of mine \
                 in the window; one other lane's compile ran ~40 s and was cancelled), node a11686c4, testbin 45d3f3e1: \
                 `a_real_node_that_jumped_by_dsync_warms_its_nullifier_view_to_the_certified_spent_state` GREEN (1 passed, \
                 1290 s): the restarted joiner jumped 795 blocks and its view was present+matching after 490.4 s -> ceil = 9 \
                 minutes. J1's 395.4 s on 772 blocks was NOT load-inflated (the quiet rerun is slower). WHAT THE 490 s IS, \
                 read from the joiner's log in 10 s pump windows: restart + Tor bootstrap + the 795-block adopt, then the \
                 warm: the first page waits ~50 s for the bulk client, 266,515 tags stream at ~10 s per 16,384-tag page \
                 (~50 KB/s, one Tor bulk circuit), and ~80 s more heal the 68,608 tags the chain grew DURING the warm. It is \
                 O(spent set) + O(tail grown while streaming): parallel key-range streams can cut it, only a restart with no \
                 view to rebuild (the certificate program) reaches 0. THE ROLLING-RESTART PATH: MEASURED 2026-09-28 on two real usdmd-node processes (M7 = one snapshot of the live tree, node \
                 f12258b5, harness f9f84999), `a_rolling_restart_of_a_producing_real_pair_leaves_both_processes_serving_lane_a` \
                 x2, both GREEN: the node restarted first served Lane A 70.1 s / 90.2 s after its restart, the PRODUCER \
                 120.2 s / 115.2 s — the latter through DB-339 part 3 (the warm healed from 177 tags of the producer's OWN \
                 pre-pivot blocks that the server's key-ordered stream never carried; before it, on M4, the producer never \
                 served in 450 s). ceil(120.2 s / 60) = 3, MEASURED ON A CHAIN OF A FEW HUNDRED BLOCKS. The residual is the \
                 warm itself: a restarted node streams the WHOLE replicated spent set and checks it against its certified \
                 root before it serves — linear in the spent set, so this number grows with the chain; 0 needs a view \
                 that survives the restart or a recursive certificate that replaces the warm",
        },
        // ── THE SCALE FLOOR. A 2-node island proves money movement, never scale.
        Criterion {
            name: "nodes across >=2 devices at the scale floor",
            how: Measured::OnRealNodes("the 5-node standard"),
            current: 0,
            target: 5,
            ceiling: false,
            blocker:
                "⭐ MEASURED 2026-09-28 01:24 ([slotB14], node 1f4bb815): FIVE real daemons on this Mac reached \
                 quorum on EVERY node after 431 s (`[wallet] 5-node quorum on every node`) — the 9/24 island \
                 (quorum [1,0,0,0,0], no node established its own onion) did not recur. What stays open: the \
                 money half of that run was not measured (its wallet binary predated the 23:38 decider change, \
                 so it was stopped as invalid), and the criterion counts nodes across >=2 DEVICES — one Mac is \
                 one device, and the second device (the iPhone) is deferred by the user (2026-09-27)",
        },
        // ── AND THE THING THAT SHIPS.
        Criterion {
            name: "deploy gate PASS on the shipping binary",
            how: Measured::OnRealNodes("ecosystem-check.sh writes ~/.usdmd-node/ecosystem-check.pass"),
            current: 0,
            target: 1,
            ceiling: false,
            blocker: "blocked by the convergence and step-3 criteria above",
        },
    ]
}

/// The whole standard, live half first.
#[must_use]
pub fn all_criteria() -> Vec<Criterion> {
    let mut v = live_criteria();
    v.extend(measured_elsewhere());
    v
}

/// ⭐ THE ONE NUMBER: criteria met, out of the whole standard. `true` only when a person's money is safe.
#[must_use]
pub fn ready_for_real_funds() -> (usize, usize, bool) {
    let all = all_criteria();
    let met = all.iter().filter(|c| c.met()).count();
    (met, all.len(), met == all.len())
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;

    /// ⭐⭐⭐ DB-196 — THE LIVE CRITERIA ACTUALLY CONSUME THEIR CENSUSES' UNIVERSE CHECKS.
    ///
    /// ⛔ THE HOLE THIS PINS SHUT, MEASURED 2026-09-25. Criterion 4 read **✅ 0 open** while
    /// `value_creation::every_local_note_minting_function_is_in_the_census` was FAILING, because
    /// `live_criteria` counted open `SITES` and never asked whether the census still covered its
    /// universe. Wiring `census_universe_gaps()` into the count fixes it — and a wiring is exactly the
    /// kind of thing a later edit drops without noticing, because nothing it computes changes today
    /// (both censuses are currently clean, so both addends are zero).
    ///
    /// So this asserts the ARITHMETIC rather than the outcome: each criterion's `current` must equal
    /// open-items PLUS universe-gaps. If someone removes the `+ gaps.len()`, this goes red even though
    /// the report still prints ✅.
    #[test]
    fn the_live_criteria_count_census_universe_gaps_not_just_open_items() {
        use crate::harness::{privacy, value_creation};
        let all = live_criteria();

        let pg = privacy::census_universe_gaps();
        let po = privacy::SURFACES.iter().filter(|s| !s.is_closed()).count() as u64;
        let pc = all
            .iter()
            .find(|c| c.name == "privacy surfaces still leaking")
            .expect("the privacy criterion is in the live list");
        assert_eq!(
            pc.current,
            po + pg.len() as u64,
            "⛔ the privacy criterion no longer counts its census's UNIVERSE gaps ({} open surface(s), \
             {} universe gap(s), criterion reads {}). A block field added tomorrow would be invisible \
             to a viewer-leak criterion that only counts surfaces somebody already wrote down.",
            po,
            pg.len(),
            pc.current
        );

        let vg = value_creation::census_universe_gaps();
        let vo = value_creation::SITES.iter().filter(|s| !s.is_closed()).count() as u64;
        let vc = all
            .iter()
            .find(|c| c.name == "value-creation sites not fully answered")
            .expect("the value-creation criterion is in the live list");
        assert_eq!(
            vc.current,
            vo + vg.len() as u64,
            "⛔ the value-creation criterion no longer counts its census's UNIVERSE gaps ({} open \
             site(s), {} universe gap(s), criterion reads {}). This is the exact shape that let \
             criterion 4 read ✅ on 2026-09-25 while its own completeness test was red.",
            vo,
            vg.len(),
            vc.current
        );
    }

    /// ⭐⭐⭐ **THE REPORT.** Run this to answer "is the chain safe for real funds yet, and what is left".
    ///
    /// It does NOT fail on an unmet criterion — see the module note: a readiness gate that fails the
    /// suite gets muted, and a muted gate is how a chain ships unsafe. It fails only on the two things
    /// that would make the REPORT itself dishonest.
    #[test]
    fn report_whether_this_chain_is_safe_for_real_funds() {
        let all = all_criteria();
        let (met, total, ready) = ready_for_real_funds();

        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════════════════════════════╗");
        eprintln!(
            "║  SAFE FOR REAL FUNDS: {:<58} ║",
            if ready { "YES".to_string() } else { format!("NO — {met} of {total} criteria met") }
        );
        eprintln!("╚══════════════════════════════════════════════════════════════════════════════════╝");
        for c in &all {
            eprintln!("  {c}");
        }
        eprintln!();
        eprintln!("  BLOCKERS, in the order they must be cleared:");
        for (i, c) in all.iter().filter(|c| !c.met()).enumerate() {
            eprintln!("   {}. {}", i + 1, c.name);
            if let Some(why) = deferred_by_user(c.name) {
                eprintln!("      ⏸ DEFERRED BY THE USER (still unmet): {why}");
            }
            eprintln!("      {}", c.blocker);
        }
        eprintln!();

        // ⛔ THE ONLY TWO FAILURES: a criterion with no way to measure it is an opinion, and a standard
        // with nothing in it passes vacuously. Both would make this report a lie rather than a number.
        assert!(
            all.len() >= 12,
            "the standard has shrunk to {} criteria — a readiness bar that shrinks is how 'done' gets \
             declared by deletion",
            all.len()
        );
        for c in &all {
            assert!(
                !c.blocker.is_empty() || c.met(),
                "criterion '{}' is NOT met and names no blocker — an unmet criterion without a named \
                 blocker is an intention, not a measurement",
                c.name
            );
        }
    }

    /// ⛔ EVERY LIVE CRITERION MUST ACTUALLY READ ITS CENSUS. A readiness report whose numbers are
    /// hand-typed drifts the moment anyone forgets, which is the defect class it exists to catch
    /// ([[reference_derived_guards_not_hand_lists]]).
    #[test]
    fn the_live_criteria_are_derived_from_the_censuses_not_typed_in() {
        use crate::harness::{e2e_claims, privacy, value_creation};
        let live = live_criteria();
        assert_eq!(live.len(), 5, "five live criteria are derived; got {}", live.len());
        // The fifth (user 2026-09-28): custody key safety reads its own census, never a typed number.
        let custody = live
            .iter()
            .find(|c| c.name == "custody key safety gaps")
            .expect("the custody criterion is in the live list");
        assert_eq!(custody.current, crate::harness::custody::open_gaps() as u64, "custody reads harness::custody");

        // Each target must equal the census's OWN size, so adding a class/surface/site moves the bar
        // automatically rather than silently passing under an old one.
        //
        // ⭐⭐⭐ DB-197 — AND THE ONLY WAY OUT OF THE DENOMINATOR IS A FILING THAT IS ITSELF AUDITED.
        //
        // This guard exists to stop the bar being shrunk to meet it, and when `OrderPost` was re-filed
        // as `NoValueOfItsOwn` it caught that change — correctly. It is made PRECISE here, not relaxed:
        // the bar is every entry that MOVES VALUE, and an entry leaves that set only by being filed
        // `NoValueOfItsOwn`, which
        //   * keeps it listed in the register (its own reason asks for exactly that), and
        //   * is held to the same >=80-character blocker bar by
        //     `e2e_claims::every_unproven_entry_names_its_blocker`, so "it carries no value" has to say
        //     WHY and WHAT carries it instead.
        // So a class still cannot be dropped silently: it can only be re-described, in public, with a
        // reason another test reads.
        let movable = e2e_claims::VALUE_CLASSES
            .iter()
            .filter(|(_, m)| !matches!(m, e2e_claims::Moved::NoValueOfItsOwn(_)))
            .count() as u64;
        assert_eq!(
            live[0].target, movable,
            "the movable-value bar must be every class that MOVES VALUE"
        );
        assert_eq!(
            live[1].target, movable,
            "the real-node bar must be every class that MOVES VALUE"
        );
        // ⛔ AND THE ESCAPE HATCH STAYS NARROW. If this ever grows, the bar is being shrunk one filing
        // at a time — which is the slow version of the thing this guard was written to stop.
        let excused = e2e_claims::VALUE_CLASSES.len() as u64 - movable;
        assert!(
            excused <= 2,
            "⛔ {excused} entries are filed as carrying no value of their own. One (`OrderPost`, a \
             resting offer) is the case the variant was added for; a growing list is the bar being \
             shrunk by re-description."
        );
        assert!(
            privacy::SURFACES.len() >= 5 && value_creation::SITES.len() >= 5,
            "the privacy ({}) and value-creation ({}) censuses must be non-trivial, or their zero \
             targets are met vacuously",
            privacy::SURFACES.len(),
            value_creation::SITES.len()
        );
        for c in &live {
            assert!(
                matches!(c.how, Measured::Live),
                "criterion '{}' is in the LIVE half but is not measured live",
                c.name
            );
        }
    }

    /// ⛔ AND THE SNAPSHOT HALF MUST SAY WHO RE-MEASURES IT. A number with no test behind it is a
    /// memory, and memories drift ([[feedback_stale_note_guard]]).
    #[test]
    fn every_snapshot_criterion_names_the_test_that_re_measures_it() {
        for c in measured_elsewhere() {
            let named = match c.how {
                Measured::Live => "",
                Measured::ByTest(t) | Measured::OnRealNodes(t) => t,
            };
            assert!(
                !named.is_empty(),
                "criterion '{}' carries a recorded number with no test to re-measure it",
                c.name
            );
        }
    }
}

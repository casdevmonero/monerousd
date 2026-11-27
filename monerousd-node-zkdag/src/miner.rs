// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Block production (brick 4): the adaptive work-adjustment algorithm (DAA) + block-template
//! assembly. A template is built from the tips the node already holds + the mempool — no parent
//! bodies are re-fetched — so every node can produce.
//!
//! The concrete PoW-grind engine (PQ-PoUW preimage folding the #73 non-outsourceable bind, via
//! the WHIR pow-bind engine) fills `nonce` + `pow_bind` on the returned template; that engine is
//! wired in the next increment. This brick lands the DAA + assembly the engine grinds over.

use crate::block::{BlockHeader, BlockId};
use crate::dag::Dag;
use crate::hash::Hash32;
use crate::mempool::Mempool;

/// Block header version this producer stamps.
pub const BLOCK_VERSION: u32 = 1;
/// Bootstrap work when there is not yet any history to measure (genesis seed + no-tip fallback ONLY —
/// `adaptive_work` clamps to `avg/4..avg*4` with no floor at this value, so the DAA is free to move away
/// from it from block 1). Calibrated LOW to the PQ-PoUW light hash rate (~tens of H/s) so the FIRST
/// blocks grind in well under the 1s target and the chain bootstraps; the adaptive DAA then climbs to the
/// live equilibrium (mainnet's fast-mode + many-miner aggregate rate lands far higher from this SAME seed —
/// testnet == production parity, calibration not a difficulty pin). A seed too high for the light rate
/// dead-locks bootstrap: no block ever grinds ⇒ the DAA never runs ⇒ work never lowers (the Δ0-blocks bug).
pub const BOOTSTRAP_WORK: u128 = 16;
// Target spacing, the DAA sample span, and the max block weight are governance-tunable (crate::params).

/// A block ready for the PoW grind: the header is fully formed EXCEPT `nonce` + `pow_bind`, which
/// the PoW engine fills. `tx_ids` are the mempool selection the header's `tx_merkle_root` commits.
#[derive(Clone, Debug)]
pub struct BlockTemplate {
    pub header: BlockHeader,
    pub tx_ids: Vec<Hash32>,
}

/// The adaptive per-block work that holds the 1s target spacing: measure the recent selected-chain
/// sample's ACTUAL timespan vs the target, and scale the average work by `target / actual` (so
/// too-fast blocks raise work, too-slow lower it), clamped to a 4x step. Never pinned.
pub fn adaptive_work(dag: &Dag, selected_tip: Option<BlockId>) -> u128 {
    adaptive_work_checked(dag, selected_tip).0
}

/// ⛔⛔⛔ THE DAA FIGURE **AND WHETHER THIS NODE IS ENTITLED TO JUDGE BY IT** (2026-09-08, §9.6
/// door audit MUST-FIX 1).
///
/// [`adaptive_work`] has always returned a number even when the walk that produced it ran off the
/// bottom of what this node holds. That number is AUTHORITY at the gossip door — where the parents
/// are present by construction, so the walk is the chain's — and it is a GUESS everywhere else.
/// This crate has already paid for the difference: MEASURED by the restart schedule search
/// (2026-09-03), two nodes refused each other's HONEST blocks with `WrongWork { expected: 5, got:
/// 4 }` both ways after one restart, because one side's walk ended on an anchor with no samples
/// beneath it and the other side's did not.
///
/// So the walk now reports both: `(figure, complete)`. COMPLETE means the sample IS the chain's, by
/// one of exactly two terminations that admit no other reading —
/// * it filled `daa_sample_len` samples (the whole span the protocol defines), or
/// * it ran out at this DAG's OWN GENESIS (`Dag::genesis`, by id) — nothing exists below genesis to
///   be missing, so a short sample rooted there is complete, not truncated.
///
/// INCOMPLETE means the walk stopped on something this node does not hold: a `Dag::get` miss, or a
/// parentless block that is NOT genesis whose samples did not fill the span. There this node has no
/// standing to call an honest peer's figure wrong, and the door that consumes this verdict says so
/// rather than refusing — a truncated view of the chain must never become a refusal OF the chain.
///
/// ⛔ AND INCOMPLETE WHENEVER A PEER SUPPLIED PART OF THE SAMPLE, however long it ended up. This is
/// the answer to "what does this verdict make possible that was impossible before": a jumped node
/// whose span was FILLED from a set it was handed would otherwise report COMPLETE and begin
/// refusing honest blocks over a difficulty it read from a third party — the same two-way
/// `WrongWork` above, re-introduced through the new verdict at four more doors than the one that
/// carried the equality before. A supplied set is a legitimate FIGURE (a jumped node must be able
/// to build a template) and is never AUTHORITY.
///
/// ROOT-LAYER: the completeness verdict is PRODUCED by the same walk that produces the figure. A
/// caller cannot re-derive it without re-walking, and a re-walk is the second copy that drifts —
/// which is why `adaptive_work` became a wrapper over this instead of the predicate being written
/// beside it.
/// MUST-STAY-GREEN: every existing caller reads `.0` through the unchanged `adaptive_work`, so the
/// gossip door's `WrongWork` verdict, `build_template`, `dag.rs` and `ghostdag.rs` are byte-identical
/// behaviour — the same walk, with one extra `bool` computed from WHERE IT STOPPED.
/// cons: one `Dag::genesis()` read per walk. No allocation, no extra traversal, no new term in
/// history — f(FIXED PROTOCOL CONSTANTS) exactly as before.
/// The retarget's per-block clamp: one block moves the work target by at most this factor either way. ⛔ ONE SPELLING:
/// `Node::view_quality` (DB-380, the chain-quality signal) reads THIS constant as its floor — a view whose work target
/// FELL by ≥ `DAA_CLAMP` across one window, or whose block rate fell to ≤ 1/`DAA_CLAMP` of the target (plus the estimator's
/// 3σ margin, `Node::view_rate_floor_x1000`), is DEGRADED. A
/// second literal for the same number is the drift class (two crates, two ideas of one width).
pub const DAA_CLAMP: u128 = 4;

pub fn adaptive_work_checked(dag: &Dag, selected_tip: Option<BlockId>) -> (u128, bool) {
    let tip = match selected_tip {
        Some(t) => t,
        // No tip at all: the bootstrap seed is a SEED, never a judgement about anyone's chain.
        None => return (BOOTSTRAP_WORK, false),
    };
    // A-F67 (lane deathfix, 2026-11-15): the walk and the window's endpoints are the two helpers below, so the producer's
    // own timer (`node_runtime::dag_share_spacing_ms`, through `measured_mesh_span`) reads the SAME span this DAA
    // judges by. Moved verbatim; the figure and the completeness verdict are byte-identical.
    let (sample, complete) = daa_sample_at(dag, tip);
    if sample.len() < 2 {
        // NOT A DEFAULT AND NOT A RESCUE: this arm is the pre-existing figure, unchanged, and the
        // `bool` beside it is the honest verdict on it. A one-sample chain rooted at genesis is a
        // DETERMINISTIC answer every node of the network computes identically (the genesis header
        // is the same object on all of them), so it keeps whatever the walk found. A `Dag::get`
        // miss on the tip itself is not a reading of ANY chain, so it is never complete — the
        // caller is told "no verdict", never handed a seed dressed as one.
        // ROOT-LAYER: produced with the figure, at the one site that knows why the sample is short.
        // MEASURED: this arm is the one the §9.6 MUST-FIX 2 fixture lands in — a fabricated anchor
        // naming the victim's genesis as its parent, sample len 1, rooted at genesis ⇒ complete,
        // expected = the genesis header's own work, got = 1 ⇒ the door refuses.
        // MUST-STAY-GREEN: `adaptive_work`'s returned figure is unchanged in this arm.
        return (
            dag.get(&tip)
                .map(|n| n.header.work)
                .unwrap_or(BOOTSTRAP_WORK),
            complete && dag.get(&tip).is_some(),
        );
    }
    // ⭐⭐⭐ DB-394 (2026-10-27) — THE WINDOW'S ENDPOINTS ARE MEDIANS, NEVER THE RAW NEWEST AND OLDEST SAMPLE.
    //
    // The raw scheme read `actual_ms = ts[0] − ts[n−1]`: the newest sample's own stamp. The header door admits a
    // stamp up to `max_ts_drift_ms` (30 s) past the validator's clock, and the window is `daa_sample_len` (60) ×
    // `target_spacing_ms` (500 ms) = 30 s of chain — so ONE block stamped at the bound doubled the measured timespan
    // and the next block needed about half the work. MEASURED (scratchpad/verify/f1-flatness-db394-20261022-0452.log,
    // the pin below): honest child 1,000 → drift-bound child 495 (49.5 %); a child stamped at the median floor 1,113.
    // A minority producer that re-stamps every block it lays takes ~2× its share of blocks (reward theft) and tilts
    // the DB-380 eclipse signal, which reads the same window. The 4× clamp bounds one STEP, not the stamp.
    //
    // BORROWED SHAPE (Bitcoin Cash 2017 DAA; Bitcoin's MTP-11): each end of the window is a group of
    // `mtp_sample_len` (11) selected-chain samples, and the endpoint is the group's MEDIAN — the median timestamp
    // for the timespan and the median blue score for the block count, each a robust statistic of the group. One
    // lying stamp cannot move a median of 11: moving it takes 6 of 11 consecutive selected-chain blocks, the same
    // majority the header door's MTP rule already concedes. Kaspa reaches the same bound by width (a 2,641-block
    // window against a 132 s drift, ~5 %); a window 20× the drift here would be 1,200 blocks — a 10-minute DAA and
    // a 10-minute eclipse time-to-fire, so the median is the shape that keeps both responsive.
    //
    // ARITHMETIC. n = 60, e = 11: newest median = the 6th-newest sample (index 5), oldest median = index 54 — an
    // honest on-target chain measures 49 blocks over 49 × 500 ms and keeps its work exactly (the control pins
    // `daa_holds_on_target…` and `daa_counts_every_blue_block…` are unchanged in their numbers). A drift-bound stamp
    // sorts to the top of its group and moves nothing; a median-floor stamp inserts beside the median and moves the
    // timespan by at most one spacing (≤ 500 ms of 24,500 ms ≈ 2 %; it was 9 % on the raw endpoint). Short windows
    // (e > n/2, the dag/pins fixtures at `daa_sample_len` 4) shrink the groups to n/2 and, at a group of 1 or 2, read
    // exactly the raw endpoints they did before. ONE definition, read by every door: the template, the gossip and
    // sync doors (`adaptive_work_checked`), `dag.rs`, `ghostdag.rs` and `relay.rs` all compute this figure.
    // §9.6: (1) PoW unchanged — the grind is judged against this figure; (2) a pure function of the chain the node
    // holds; (3)/(4) no value moves, nothing to replay; (5) two sorts of ≤ 11 u64 per call, no state, no wire bytes;
    // (6) parity: every caller reads the one function; the completeness verdict is untouched.
    // cons: the DAA trails the newest stamp by ~5 blocks (≈ 2.5 s at 500 ms) and the effective span is 49 of the 60
    // samples; a sustained floor-stamper still shortens the span by ≤ 1 spacing per lie (bounded griefing, no gain).
    // PINS: `one_block_stamped_at_the_drift_bound_does_not_cut_the_next_blocks_work`,
    // `one_block_stamped_at_the_median_floor_does_not_raise_the_next_blocks_work`,
    // `six_of_eleven_stamped_blocks_do_move_the_work_so_the_median_is_not_decorative`, `h10_clock_skew…`.
    let (blocks_in_window, actual_ms, _, _) = daa_span(dag, &sample);
    let target_ms = blocks_in_window * dag.params().target_spacing_ms as u128;
    // ⛔ A-F110 (lane speed5, 2026-11-19) — ASERT, anchored at the window's oldest sample (docs/CONSENSUS-WEIGHT-DEEP-AUDIT-20261119.md
    // W6-W9). The window rule (`avg × target / actual`, 4× clamp) reacted over a 60-sample average: with production found by the
    // grind it let a 1,000-node crowd run the mesh over its target long enough for a 467 s download wait (W5). ASERT moves the work
    // by how far the window ran ahead of or behind its schedule, exponentially with a fixed half-life (BORROWED: Bitcoin Cash's
    // aserti3-2d, its integer reference). The debt of running AHEAD is clamped at `ASERT_AHEAD_HALVES` half-lives, so a burst a cheap
    // genesis work allowed can never hold the work at a height no producer reaches (MEASURED in the model: 3,000 producers at genesis
    // halted with no clamp); running BEHIND is never clamped, since a falling work is what restores production (NO CHAIN HALTS).
    // The window's median endpoints (DB-394, `daa_span`) still decide the elapsed time, so one stamped block moves nothing.
    // What protects it: (b) code — the rule every node computes from the same window. SCALE: a constant in nodes, items and height.
    // cons: a different difficulty path than the window rule: a consensus change, at height 1 with the testnet reset. `complete`
    // says only whether the samples it was computed from ARE the chain's.
    // NETWORK UPGRADE 1 (params::upgrade1_active): ASERT for a block whose selected parent is `tip`, from the activation height on;
    // below it the window rule, byte-identical to every block the chain already holds, so the chain's history keeps its work.
    let child_blue = dag.get(&tip).map_or(0, |n| n.blue_score).saturating_add(1);
    if !crate::params::upgrade1_active(dag.params(), child_blue) {
        let count = sample.len() as u128;
        let sum_work: u128 = sample.iter().map(|(_, w, _)| *w).sum();
        let avg = (sum_work / count).max(1);
        let mut next = avg.saturating_mul(target_ms) / actual_ms;
        let lo = (avg / DAA_CLAMP).max(1);
        let hi = avg.saturating_mul(DAA_CLAMP);
        if next < lo {
            next = lo;
        }
        if next > hi {
            next = hi;
        }
        return (next.max(1), complete);
    }
    let anchor = sample.last().map_or(1, |(_, w, _)| *w).max(1);
    let half_ms = (ASERT_HALF_LIFE_TARGETS as u128).saturating_mul(dag.params().target_spacing_ms as u128).max(1);
    (asert_work(anchor, target_ms, actual_ms, half_ms, ASERT_AHEAD_HALVES).max(1), complete)
}

/// A-F110: the ASERT half-life, in targets (the model's measured choice, W6-W9: 4 targets halted, 8 and 16 held every steady size).
pub const ASERT_HALF_LIFE_TARGETS: u64 = 16;
/// A-F110: the most half-lives of running AHEAD the work answers for (W9: the ahead-only bound at 8 held the 3,000-node crowd's
/// longest gap at 18 s).
pub const ASERT_AHEAD_HALVES: i128 = 8;

/// ⛔⛔ A-F145 RELIEF — how long a block may follow its parent before the work it must meet starts to fall: one DAA window, in targets.
pub const RELIEF_GRACE_TARGETS: u64 = 60;
/// ⛔⛔ A-F145 RELIEF — past the grace, the work a block must meet halves every this many targets of its own wait.
pub const RELIEF_HALF_TARGETS: u64 = 8;

/// ⛔⛔ A-F145 RELIEF (lane livediag, 2026-11-27) — THE WORK A BLOCK MUST MEET FALLS WITH ITS OWN WAIT, SO NO CHAIN CAN STAND ON ITS
/// DIFFICULTY. MEASURED (live origin 27780, 13:13-14:41): a backlog merge read as the chain running ahead lifted the work 1 → 1,140 →
/// 25,017 in two blocks; block 12,796 then took 2,602,644 ms and carried 27,313, because the window's median endpoints (DB-394) ignore
/// one late block, and the work falls only after ~6 slow blocks (hours at the origin's ~10 hashes a second): uptime 0 % for the hour.
/// A window rule computes the work from blocks that EXIST, and a stalled chain has none. BORROWED: Bitcoin testnet's 20-minute rule,
/// bounded: past one DAA window (`RELIEF_GRACE_TARGETS`) the work halves every `RELIEF_HALF_TARGETS` of the block's own gap after
/// its selected parent, down to 1. Every door holds both stamps, so every door computes the same figure; the header door's drift
/// bound stops a faked gap, so only a real wait lowers it; a cheap block adds only its own small work to its chain's weight, so
/// relief never lets a minority outweigh a working chain. What protects it: (b) code; the weight is still work spent. SCALE: a shift.
#[must_use]
pub fn relieved_work(work: u128, parent_ts: u64, child_ts: u64, spacing_ms: u64) -> u128 {
    let grace = RELIEF_GRACE_TARGETS.saturating_mul(spacing_ms);
    let half = RELIEF_HALF_TARGETS.saturating_mul(spacing_ms).max(1);
    let gap = child_ts.saturating_sub(parent_ts);
    if gap <= grace {
        return work.max(1);
    }
    let halves = (gap - grace) / half;
    if halves >= 127 {
        return 1;
    }
    (work >> halves).max(1)
}

/// ⛔⛔ A-F145 RELIEF — THE WORK A BLOCK STAMPED `child_ts` ON `selected_parent` MAY CARRY: from the relieved figure (its own wait
/// applied, [`relieved_work`]) up to the window's figure ([`adaptive_work_checked`]), with the window's completeness verdict.
/// A RANGE, NOT A NEW EQUALITY, so the rule needs no activation height and splits no history: every block the chain already holds
/// carries the window's figure, the top of its range, and stays valid under this rule; a relieved block is admitted by every node
/// that runs it and refused by an older one (a declared NETWORK-UPGRADE: the release tells every node to take it). The top bound
/// keeps the rule the DAA's: no block may claim more than the window asks.
#[must_use]
pub fn admitted_work(dag: &Dag, selected_parent: Option<BlockId>, child_ts: u64) -> (u128, u128, bool) {
    let (hi, complete) = adaptive_work_checked(dag, selected_parent);
    let parent_ts = selected_parent.and_then(|p| dag.get(&p)).map(|n| n.header.timestamp);
    let lo = parent_ts.map_or(hi, |pts| relieved_work(hi, pts, child_ts, dag.params().target_spacing_ms));
    (lo, hi, complete)
}

/// ⛔⛔ A-F145 RELIEF — the work a producer stamps on a block at `child_ts`: the bottom of its admitted range (its own wait applied).
#[must_use]
pub fn adaptive_work_at(dag: &Dag, selected_parent: Option<BlockId>, child_ts: u64) -> u128 {
    admitted_work(dag, selected_parent, child_ts).0
}

/// `anchor × 2^((target − actual) / half)`, the exponent clamped above at `ahead_halves`, in integer fixed point: the exponent in
/// 1/65536 units, 2^frac by aserti3-2d's cubic, the integer part as a shift. Pure, so it is pinned directly.
#[must_use]
pub fn asert_work(anchor: u128, target_ms: u128, actual_ms: u128, half_ms: u128, ahead_halves: i128) -> u128 {
    let num = (target_ms as i128).saturating_sub(actual_ms as i128).saturating_mul(65_536);
    let ex = (num / (half_ms.max(1) as i128)).min(ahead_halves.saturating_mul(65_536)).max(-120 * 65_536);
    let shifts = ex >> 16; // floor
    let frac = (ex - (shifts << 16)) as u128; // 0..65536
    let factor = 65_536u128
        + ((195_766_423_245_049u128 * frac + 971_821_376u128 * frac * frac + 5_127u128 * frac * frac * frac + (1u128 << 47)) >> 48);
    let scaled = anchor.saturating_mul(factor);
    let out = if shifts >= 0 {
        let s = shifts as u32;
        if s >= 64 || scaled.leading_zeros() < s { u128::MAX } else { scaled << s }
    } else {
        let s = (-shifts) as u32;
        if s >= 127 { 0 } else { scaled >> s }
    };
    (out >> 16).max(1)
}

/// The DAA's sample at `tip`: up to `daa_sample_len` selected-chain `(timestamp, work, blue score)`, newest first, and whether
/// the walk is this node's own complete reading of the chain. ONE walk, read by [`adaptive_work_checked`] and by
/// [`measured_mesh_span`].
fn daa_sample_at(dag: &Dag, tip: BlockId) -> (Vec<crate::dag::DaaSample>, bool) {
    let mut complete = false;
    // ⛔ SET WHEN THE WALK HAD TO READ SAMPLES A PEER SUPPLIED RATHER THAN BLOCKS THIS NODE HOLDS.
    // This is the answer to "what does the completeness verdict make possible that was impossible
    // before": without it, a jumped node whose span was FILLED from a carried sample set would
    // report COMPLETE and start refusing an honest peer's blocks over a difficulty it read from a
    // third party — which is precisely the failure the restart schedule search MEASURED (two-way
    // `WrongWork { expected: 5, got: 4 }`), re-introduced through the new verdict instead of the
    // old one. A carried set is fine as a FIGURE (it is bound into the certified accumulator and
    // the producer needs a number); it is not this node's own reading of the chain, so it is never
    // AUTHORITY to refuse with.
    let mut read_supplied_samples = false;
    // Walk back up to the DAA sample span of selected-chain blocks: (timestamp, work), newest first.
    let daa_sample_len = dag.params().daa_sample_len;
    let mut sample: Vec<crate::dag::DaaSample> = Vec::new();
    let mut cur = Some(tip);
    while let Some(c) = cur {
        if sample.len() as u64 >= daa_sample_len {
            break;
        }
        match dag.get(&c) {
            Some(n) => {
                sample.push((n.header.timestamp, n.header.work, n.blue_score));
                cur = n.selected_parent;
                if cur.is_none() {
                    // an anchor: continue into the window it carried (v31 fold carry)
                    if let Some(w) = dag.window_below(&c) {
                        for smp in w.iter() {
                            if sample.len() as u64 >= daa_sample_len {
                                break;
                            }
                            sample.push(*smp);
                            read_supplied_samples = true;
                        }
                    }
                    // The walk reached the bottom of what this node holds. That is the CHAIN's
                    // bottom only when the block it stopped on is this DAG's own genesis, by id.
                    // ROOT-LAYER: the verdict is set HERE, inside the walk that PRODUCES the
                    // figure, at the exact statement that discovers where the walk ended — a
                    // reader cannot recover that fact from the returned `u128`, and re-deriving it
                    // outside would be the second copy that drifts.
                    // MEASURED: the restart schedule search (2026-09-03) recorded the failure this
                    // verdict exists to prevent — `WrongWork { expected: 5, got: 4 }` in BOTH
                    // directions after one restart, from a walk that ended on a parentless anchor
                    // and was treated as authority anyway.
                    // MUST-STAY-GREEN: `adaptive_work` returns `.0` and is byte-identical, so the
                    // gossip door's `WrongWork` verdict, `build_template`, `dag.rs` and
                    // `ghostdag.rs` are untouched by this line.
                    complete = dag.genesis() == Some(c);
                }
            }
            // A block this node does not hold: what was gathered is a TRUNCATION of the chain, not
            // the chain. `complete` stays false.
            None => break,
        }
    }
    // A full span of blocks THIS NODE HOLDS is the span the protocol defines, and there is nothing
    // further back for the DAA to read — so it is complete however far it walked.
    if sample.len() as u64 >= daa_sample_len {
        complete = true;
    }
    // ⛔ AND NEVER WHEN A PEER SUPPLIED PART OF IT. See `read_supplied_samples` above: a span filled
    // from a set this node was handed is a usable FIGURE and is never AUTHORITY.
    // ROOT-LAYER: applied at the one site that knows how the sample was assembled; a consumer
    // holding only the returned `u128` cannot tell a walked sample from a supplied one.
    // MEASURED: the restart schedule search's two-way `WrongWork { expected: 5, got: 4 }` is the
    // failure this line prevents the new verdict from re-introducing at four more doors.
    // MUST-STAY-GREEN: `adaptive_work`'s figure is untouched — a jumped node still PRODUCES on the
    // supplied samples exactly as it does today; only its standing to REFUSE is withheld.
    if read_supplied_samples {
        complete = false;
    }
    (sample, complete)
}

/// DB-394's window over a sample of at least two (see the comment in [`adaptive_work_checked`]): `(blue blocks the window
/// spans, its measured milliseconds, the oldest end's blue score, the newest end's blue score)`, each end the median of a
/// group of `mtp_sample_len`. ONE definition, read by the DAA and by [`measured_mesh_span`].
fn daa_span(dag: &Dag, sample: &[crate::dag::DaaSample]) -> (u128, u128, u64, u64) {
    let n = sample.len();
    let ends = dag.params().mtp_sample_len.max(1).min(n / 2).max(1);
    let group_median = |range: std::ops::Range<usize>, newest: bool, key: fn(&crate::dag::DaaSample) -> u64| -> u64 {
        let mut v: Vec<u64> = sample[range].iter().map(key).collect();
        v.sort_unstable();
        // an even group has two middles: the newest end takes the upper one, the oldest end the lower one, so a
        // group of 2 reads its raw endpoint (index 0, index n−1) exactly as the pre-DB-394 figure did
        if newest { v[v.len() / 2] } else { v[(v.len() - 1) / 2] }
    };
    let newest_ts = group_median(0..ends, true, |s| s.0);
    let newest_blue = group_median(0..ends, true, |s| s.2);
    let oldest_ts = group_median(n - ends..n, false, |s| s.0);
    let oldest_blue = group_median(n - ends..n, false, |s| s.2);
    let (newest_idx, oldest_idx) = (ends / 2, n - ends + (ends - 1) / 2);
    let actual_ms = newest_ts.saturating_sub(oldest_ts).max(1) as u128;
    // ⭐⭐⭐ DAG-WIDE (2026-09-18): the window's block count is every BLUE block between its two chain
    // points — the blue-score difference — not the number of chain steps. With one producer the two are
    // equal; with N producers the chain merges their siblings and the count grows N-fold, so the work
    // rises N-fold and the mesh keeps ONE block rate whatever the node count. Measured before this (run
    // 26, two real producers): the chain kept its 500 ms spacing while the DAG carried ~4 blocks/s and
    // every node's intake grew with the producer count — the opposite of Bitcoin, whose difficulty
    // targets the NETWORK's rate. Kaspa's rule for a block-DAG, borrowed.
    let blue_span = newest_blue.saturating_sub(oldest_blue) as u128;
    let blocks_in_window = blue_span.max((oldest_idx - newest_idx) as u128).max(1);
    (blocks_in_window, actual_ms, oldest_blue, newest_blue)
}

/// The DAA's window as a producer's timer reads it ([`measured_mesh_span`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshSpan {
    /// Blue blocks the window spans — every producer's, merged (DAG-wide, as the DAA counts them).
    pub blocks: u128,
    /// The window's measured milliseconds of consensus time (median-stamped ends, DB-394).
    pub ms: u128,
    /// The blue score at the window's oldest end: blocks below it were made before the window began.
    pub oldest_blue: u64,
    /// The blue score at the window's newest end.
    pub newest_blue: u64,
}

/// ⭐ A-F67 (lane deathfix, 2026-11-15) — WHAT THE MESH ACTUALLY PRODUCES, READ FROM THE DAG: the DAA's own window at the
/// selected tip, so a producer's timer can be held to the blocks the chain carries and never to how many connections it
/// holds. A FIGURE, never authority: a jumped node's carried samples count (the completeness verdict is the DAA's business,
/// not the timer's). `None` with fewer than two samples (no tip, or a one-block chain).
/// cons: one walk of `daa_sample_len` (60) held blocks and two sorts of ≤ 11 u64 per production attempt; no state, no bytes.
#[must_use]
pub fn measured_mesh_span(dag: &Dag) -> Option<MeshSpan> {
    let (sample, _) = daa_sample_at(dag, dag.selected_tip()?);
    (sample.len() >= 2).then(|| {
        let (blocks, ms, oldest_blue, newest_blue) = daa_span(dag, &sample);
        MeshSpan { blocks, ms, oldest_blue, newest_blue }
    })
}

/// A binary merkle root over the block's tx ids (blake3; odd node duplicates the last). Empty = 0.
pub fn tx_merkle_root(tx_ids: &[Hash32]) -> Hash32 {
    if tx_ids.is_empty() {
        return Hash32::ZERO;
    }
    let mut level: Vec<Hash32> = tx_ids.to_vec();
    while level.len() > 1 {
        let mut next: Vec<Hash32> = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(pair[0].as_bytes());
            buf[32..].copy_from_slice(pair.get(1).unwrap_or(&pair[0]).as_bytes());
            next.push(Hash32::hash(&buf));
        }
        level = next;
    }
    level[0]
}

/// Fold this block's O(1) advisory chain-accumulator from the selected tip's acc + the new roots.
pub fn fold_chain_acc(prev_acc: &[u8; 16], tx_root: &Hash32, frontier_root: &Hash32) -> [u8; 16] {
    let mut buf = [0u8; 80];
    buf[..16].copy_from_slice(prev_acc);
    buf[16..48].copy_from_slice(tx_root.as_bytes());
    buf[48..80].copy_from_slice(frontier_root.as_bytes());
    let mut acc = [0u8; 16];
    acc.copy_from_slice(&Hash32::hash(&buf).as_bytes()[..16]);
    acc
}

/// Build a block template on the CURRENT tips + a mempool selection. `now_ts` is the producer's
/// timestamp (ms); `frontier_root` is the note-tree root after applying the selected txs (supplied
/// by the state layer); `miner_commitment` is the confidential reward-note commitment.
pub fn build_template(
    dag: &Dag,
    mempool: &Mempool,
    now_ts: u64,
    frontier_root: Hash32,
    nullifier_root: Hash32,
    miner_commitment: Hash32,
    // The O(1) account-DA accumulator as of this template — committed in the header id so an instant
    // one-lookup restore can verify the bucket it was served against the chain, not against the server.
    account_root: Hash32,
    // DB-154: the MERKLE root of the spent set before this block. LAST in the signature, which is
    // where every call site passes it — inserted mid-signature it type-checked (every parameter
    // here is `Hash32`) and the header silently committed `miner_commitment` instead.
    sparse_root: Hash32,
    // DB-443: this template's SECRET draw (`Node::template_draw`) — the pool's inclusive selection reads it.
    draw: &[u8; 32],
) -> BlockTemplate {
    build_template_reserving(
        dag,
        mempool,
        now_ts,
        frontier_root,
        nullifier_root,
        miner_commitment,
        account_root,
        sparse_root,
        crate::mempool::TemplateReserve::NONE,
        draw,
    )
}

/// [`build_template`] for a producer that lays its own objects after selection (its SATOSHI reward): `reserve` is held
/// back from the block's fixed tag and note budgets (`Mempool::select_for_template_reserving`).
#[allow(clippy::too_many_arguments)]
pub fn build_template_reserving(
    dag: &Dag,
    mempool: &Mempool,
    now_ts: u64,
    frontier_root: Hash32,
    nullifier_root: Hash32,
    miner_commitment: Hash32,
    account_root: Hash32,
    sparse_root: Hash32,
    reserve: crate::mempool::TemplateReserve,
    draw: &[u8; 32],
) -> BlockTemplate {
    // DB-361: the tips whose merge keeps this block inside its merge depth (Kaspa `pick_virtual_parents`).
    let parents = dag.template_parents();
    // ⛔ THE BLOCK'S OWN SELECTED PARENT, never `dag.selected_tip()`: the work and the chain accumulator are functions of the
    // parents this block names, read through the one function the contextual door reads (`Dag::selected_parent_of`). The
    // selected tip's key leads with this node's FINALITY verdict, so when the floor demoted the heaviest tip the template
    // built on that tip with another's figure and its own graft refused it (`WrongWork` ×72 in one n=8 load window).
    let selected_parent = dag.selected_parent_of(&parents);
    let work = adaptive_work_at(dag, selected_parent, now_ts); // ⛔ A-F145 RELIEF: the template's own stamp
    let tx_ids = mempool.select_for_template_reserving(dag.params().max_block_weight, reserve, draw);
    let tx_root = tx_merkle_root(&tx_ids);
    let prev_acc = selected_parent
        .and_then(|t| dag.get(&t))
        .map(|n| n.header.chain_acc)
        .unwrap_or([0u8; 16]);
    let chain_acc = fold_chain_acc(&prev_acc, &tx_root, &frontier_root);

    let header = BlockHeader {
        note_commitments_root: crate::hash::Hash32::hash(&[]),
        // A template carries no notes, so this IS its true commitment: the hash of the empty payload.
        // `produce` re-seals it (`Hash32::hash(&block.output_notes)`) once notes are assembled and BEFORE
        // the id is taken, so the value is never stale for a block that actually ships notes.
        output_notes_root: Hash32::hash(&[]),
        // A template carries no tag set yet — `produce` re-seals this from the block's real tags BEFORE the
        // id is taken (same lifecycle as `output_notes_root`), so a shipped block always commits its own set.
        nullifier_tags_root: crate::block::nullifier_tags_root_of(&[]),
        // P4′a — same lifecycle as the two above: a TEMPLATE carries neither sidecar, so these are the
        // honest empty-payload commitments, and `produce_template` re-seals both from the block's real
        // carries BEFORE the off-lock mine (so the PoW binds them and the id never moves afterwards).
        oli_tags_root: crate::block::da_sidecar_root_of(&[]),
        // ⭐ §BA — this construction carries no credit set, so its commitment is the DERIVED empty
        // sidecar root, never a magic constant: the same `da_sidecar_root_of` every verifier uses.
        credit_set_root: crate::block::da_sidecar_root_of(&[]),
        transitions_root: crate::block::empty_transitions_root(),
        cover_seed_commit: crate::hash::Hash32::ZERO,
        member_ring_commit: crate::hash::Hash32::ZERO,
        account_targets_root: crate::block::da_sidecar_root_of(&[]),
        // Same lifecycle: `produce` re-seals this from the block's real bond set BEFORE the mine.
        bond_set_root: crate::block::da_sidecar_root_of(&[]),
        dir_set_root: crate::block::da_sidecar_root_of(&[]),
        letter_set_root: crate::block::da_sidecar_root_of(&[]),
        tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
        level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
        version: BLOCK_VERSION,
        parents,
        timestamp: now_ts,
        nonce: 0, // filled by the PoW engine
        work,
        pow_bind: Hash32::ZERO, // filled by the PoW engine (#73 H(pi))
        tx_merkle_root: tx_root,
        frontier_root,
        nullifier_root,
        sparse_root,
        chain_acc,
        miner_commitment,
        account_root,
    };
    BlockTemplate { header, tx_ids }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    /// Two producers braided into one DAG: every chain block merges one sibling (both blue at k=32), so the
    /// window holds twice the blocks of a lone chain at the same spacing.
    fn braided_chain(len: usize, spacing_ms: u64, work: u128) -> (Dag, BlockId) {
        let blk = |parents: Vec<BlockId>, nonce: u64, ts: u64| Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: hdr(parents, nonce, ts, work),
            tx_ids: vec![],
            pow_proof: Vec::new(),
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            note_transition: None,
            nullifier_proof: crate::block::NfBlockProof::default(),
            cover_transition: None,
            member_transition: None,
        };
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 0, 0)).unwrap();
        let mut prev = g;
        for i in 1..len {
            let ts = i as u64 * spacing_ms;
            let sibling = dag.add_block(blk(vec![prev], 100_000 + i as u64, ts)).unwrap();
            let chain = dag.add_block(blk(vec![prev, sibling], i as u64, ts)).unwrap();
            prev = chain;
        }
        (dag, prev)
    }
    // Build a linear selected chain with fixed spacing (ms) and fixed per-block work.
    fn linear_chain(len: usize, spacing_ms: u64, work: u128) -> (Dag, BlockId) {
        let mut dag = Dag::new();
        let g = dag
            .add_block(Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
                header: hdr(vec![], 0, 0, work),
                tx_ids: vec![],
                pow_proof: Vec::new(),
                output_notes: Vec::new(),
                oli_tags: Vec::new(),
                account_targets: Vec::new(),
                bond_set: Vec::new(),
                // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
                credit_set: Vec::new(),
                dir_set: Vec::new(),
                letter_set: Vec::new(),
                tag_evidence: Vec::new(),
                note_transition: None,
                nullifier_proof: crate::block::NfBlockProof::default(),
                cover_transition: None,
            member_transition: None,
            })
            .unwrap();
        let mut prev = g;
        for i in 1..len {
            let b = dag
                .add_block(Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
                    header: hdr(vec![prev], i as u64, i as u64 * spacing_ms, work),
                    tx_ids: vec![],
                    pow_proof: Vec::new(),
                    output_notes: Vec::new(),
                    oli_tags: Vec::new(),
                    account_targets: Vec::new(),
                    bond_set: Vec::new(),
                    // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
                    credit_set: Vec::new(),
                    dir_set: Vec::new(),
                    letter_set: Vec::new(),
                    tag_evidence: Vec::new(),
                    note_transition: None,
                    nullifier_proof: crate::block::NfBlockProof::default(),
                    cover_transition: None,
            member_transition: None,
                })
                .unwrap();
            prev = b;
        }
        (dag, prev)
    }
    fn hdr(parents: Vec<BlockId>, nonce: u64, ts: u64, work: u128) -> BlockHeader {
        BlockHeader {
            note_commitments_root: crate::hash::Hash32::hash(&[]),
            nullifier_tags_root: crate::hash::Hash32::hash(&[]),
            output_notes_root: crate::hash::Hash32::hash(&[]),
            // P4'a fixture: this block ships no locator tags and no account targets, so both sidecar
            // commitments are the empty-payload hash the verifier re-derives.
            oli_tags_root: crate::block::da_sidecar_root_of(&[]),
            // ⭐ §BA — no credit set here, so the DERIVED empty sidecar root, never a magic constant.
            credit_set_root: crate::block::da_sidecar_root_of(&[]),
            transitions_root: crate::block::empty_transitions_root(),
            cover_seed_commit: crate::hash::Hash32::ZERO,
            member_ring_commit: crate::hash::Hash32::ZERO,
            account_targets_root: crate::block::da_sidecar_root_of(&[]),
            bond_set_root: crate::block::da_sidecar_root_of(&[]),
            dir_set_root: crate::block::da_sidecar_root_of(&[]),
            letter_set_root: crate::block::da_sidecar_root_of(&[]),
            tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
            level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
            version: 1,
            parents,
            timestamp: ts,
            nonce,
            work,
            pow_bind: Hash32::ZERO,
            tx_merkle_root: Hash32::ZERO,
            frontier_root: Hash32::ZERO,
            nullifier_root: Hash32::ZERO,
            sparse_root: crate::hash::Hash32::ZERO,
            chain_acc: [0u8; 16],
            miner_commitment: Hash32::ZERO,
            account_root: Hash32::ZERO,
        }
    }
    use super::*;
    use crate::block::{Block, BlockHeader, BlockId};
    use crate::hash::Hash32;

    // Build a linear selected chain with fixed spacing (ms) and fixed per-block work.
    /// A-F110 (lane af110, 2026-11-19): the DAA is ASERT — `anchor × 2^((target − actual) / half)` over the window, the ahead
    /// exponent clamped at `ASERT_AHEAD_HALVES`. The window rule this replaced answered 1000 / 2000 / 500 here (`avg × target /
    /// actual`); the figures below are ASERT's, computed from its definition, so the pin states the rule, not a remembered number.
    #[test]
    fn daa_holds_on_target_and_hardens_when_fast() {
        crate::params::UPGRADE1_AT_GENESIS_FOR_TEST.store(true, std::sync::atomic::Ordering::Relaxed);
        let expect = |spacing: u64| {
            let (dag, tip) = linear_chain(30, spacing, 1000);
            let (sample, _) = daa_sample_at(&dag, tip);
            let (blocks, actual, _, _) = daa_span(&dag, &sample);
            let target = blocks as f64 * dag.params().target_spacing_ms as f64;
            let half = ASERT_HALF_LIFE_TARGETS as f64 * dag.params().target_spacing_ms as f64;
            let ex = ((target - actual as f64) / half).min(ASERT_AHEAD_HALVES as f64);
            (adaptive_work(&dag, Some(tip)), 1000.0 * 2f64.powf(ex))
        };
        // On target (500 ms, the fixture's `target_spacing_ms`): the work stays at the anchor's.
        let (on, _) = expect(500);
        assert_eq!(on, 1000, "on target the work is the anchor's");
        // Twice too fast: harder, by exactly ASERT's factor (within the cubic's 0.1 %); twice too slow: easier, the same way.
        for spacing in [250u64, 1000] {
            let (got, want) = expect(spacing);
            assert!(((got as f64) - want).abs() <= want * 0.001 + 1.0, "spacing {spacing}: ASERT gives {want:.1}, the DAA answered {got}");
        }
        assert!(expect(250).0 > 1000 && expect(1000).0 < 1000, "fast hardens, slow eases");
        // No tip => bootstrap.
        assert_eq!(adaptive_work(&Dag::new(), None), BOOTSTRAP_WORK);
    }

    /// ⛔ A-F145 RELIEF PIN — inside one DAA window of its parent a block's admitted range is the window's figure alone; past it the
    /// bottom halves every `RELIEF_HALF_TARGETS` of the block's own wait, down to 1; the live stall's gap (2,602,644 ms on work
    /// 27,313) relieves it to 1; a drift-sized gap (30 s) relieves nothing; and the top is always the window's figure, so every block
    /// already on a chain (it carries that figure) stays admitted — the rule splits no history.
    #[test]
    fn af145_relief_the_work_falls_with_the_blocks_own_wait_and_history_stays_admitted() {
        let spacing = crate::params::ChainParams::default().target_spacing_ms;
        let (grace, half) = (RELIEF_GRACE_TARGETS * spacing, RELIEF_HALF_TARGETS * spacing);
        let w = 27_313u128;
        assert_eq!(relieved_work(w, 1_000, 1_000 + grace, spacing), w, "⛔ a block inside the grace was relieved");
        assert_eq!(relieved_work(w, 1_000, 1_000 + 30_000, spacing), w, "⛔ a drift-sized gap (30 s) relieved the work");
        assert_eq!(relieved_work(w, 1_000, 1_000 + grace + half, spacing), w >> 1, "⛔ one half-life past the grace is not half");
        assert_eq!(relieved_work(w, 1_000, 1_000 + grace + 3 * half, spacing), w >> 3, "⛔ three half-lives past the grace");
        assert_eq!(relieved_work(w, 0, 2_602_644, spacing), 1, "⛔ the live stall's gap did not relieve the work to 1");
        assert_eq!(relieved_work(w, 5_000, 1_000, spacing), w, "⛔ a stamp before its parent relieved the work");
        // the empty DAG: no parent, so the range is the window's figure alone (the top of every range is that figure by
        // construction of `admitted_work`, so every block already on a chain stays admitted)
        let (lo, hi, _) = admitted_work(&Dag::new(), None, 10_000_000);
        assert_eq!((lo, hi), (BOOTSTRAP_WORK, BOOTSTRAP_WORK), "⛔ a parentless range is not the bootstrap figure alone");
    }

    /// A-F110: `asert_work` is `anchor × 2^ex` to within the cubic's error over the whole range, and only running AHEAD is clamped:
    /// a chain far behind its schedule keeps easing (falling work is what restores production; NO CHAIN HALTS).
    #[test]
    fn af110_asert_matches_its_definition_and_clamps_only_ahead() {
        crate::params::UPGRADE1_AT_GENESIS_FOR_TEST.store(true, std::sync::atomic::Ordering::Relaxed);
        let half = 16_000u128;
        for d in [-200_000i128, -48_000, -8_000, -1, 0, 1, 7_999, 8_000, 40_000, 127_999] {
            let (target, actual) = if d >= 0 { (200_000u128 + d as u128, 200_000u128) } else { (200_000u128, 200_000u128 + (-d) as u128) };
            let got = asert_work(1_000_000, target, actual, half, ASERT_AHEAD_HALVES) as f64;
            let want = 1_000_000.0 * 2f64.powf((d as f64 / half as f64).min(ASERT_AHEAD_HALVES as f64));
            assert!((got - want).abs() <= want * 0.001 + 1.0, "d {d}: want {want:.1}, got {got}");
        }
        let far_ahead = asert_work(1_000, 10_000_000, 1_000, half, ASERT_AHEAD_HALVES);
        assert_eq!(far_ahead, 1_000 << ASERT_AHEAD_HALVES, "⛔ A-F110: running ahead is clamped at {ASERT_AHEAD_HALVES} half-lives");
        let far_behind = asert_work(1u128 << 40, 1_000, 1_000 + 30 * half, half, ASERT_AHEAD_HALVES);
        assert_eq!(far_behind, 1u128 << 10, "⛔ running behind is never clamped: 30 half-lives behind is 2^-30 of the anchor");
    }

    /// ⭐⭐⭐ H10 — CLOCK SKEW AND TIMESTAMP MANIPULATION, MEASURED (2026-10-05, the register's network row). The rules
    /// in `consensus.rs`: a header stamped past `now + max_ts_drift_ms` (30 s) is REFUSED structurally
    /// (`TimestampTooFarFuture`); one stamped at or below the median-time-past of its selected parent is REFUSED
    /// contextually (`TimestampTooEarly`). The DAA half: ONE block stamped at the drift bound — the furthest stamp a
    /// producer can place and still be admitted — moves the next block's work by at most `DAA_CLAMP` (4×), so stamping
    /// cannot drive the work down (or up) faster than the clamp. The bound is measured here, never quoted.
    #[test]
    fn h10_clock_skew_a_stamp_past_the_drift_bound_is_refused_and_one_at_the_bound_moves_the_work_by_at_most_the_clamp() {
        let (mut dag, tip) = linear_chain(30, 500, 1000);
        let params = dag.params().clone();
        let tip_ts = dag.get(&tip).unwrap().header.timestamp;
        let base = adaptive_work(&dag, Some(tip));
        assert_eq!(base, 1000, "calibration: on-target spacing keeps the work");
        // 1. FUTURE: one millisecond past now + drift is refused
        let past_bound = hdr(vec![tip], 31, tip_ts + params.max_ts_drift_ms + 1, base);
        assert!(
            matches!(
                crate::consensus::validate_header_structural(&past_bound, &[], Some(tip_ts), &params),
                Err(crate::consensus::ConsensusError::TimestampTooFarFuture { .. })
            ),
            "⛔ a header stamped past now + max_ts_drift_ms must be refused"
        );
        // 2. PAST: at or below the median-time-past is refused
        let too_early = hdr(vec![tip], 31, tip_ts.saturating_sub(5 * 500), base);
        assert!(
            matches!(crate::consensus::validate_contextual(&dag, &too_early), Err(crate::consensus::ConsensusError::TimestampTooEarly { .. })),
            "⛔ a header stamped at or below its parent's median-time-past must be refused"
        );
        // 3. THE DAA BOUND: a block stamped AT the drift bound is admitted; the next work moves by at most the clamp
        let at_bound = hdr(vec![tip], 31, tip_ts + params.max_ts_drift_ms, base);
        let b = dag
            .add_block(Block {
                cover_key: None,
                wide_objects: Vec::new(),
                tx_bodies: Vec::new(),
                agg_tables: Vec::new(),
                note_commitments: Vec::new(),
                header: at_bound,
                tx_ids: vec![],
                pow_proof: Vec::new(),
                output_notes: Vec::new(),
                oli_tags: Vec::new(),
                account_targets: Vec::new(),
                bond_set: Vec::new(),
                credit_set: Vec::new(),
                dir_set: Vec::new(),
                letter_set: Vec::new(),
                tag_evidence: Vec::new(),
                note_transition: None,
                nullifier_proof: crate::block::NfBlockProof::default(),
                cover_transition: None,
                member_transition: None,
            })
            .unwrap();
        let w = adaptive_work(&dag, Some(b));
        // DB-394 (2026-10-27): the endpoint is the MEDIAN of the 11 newest samples, so one stamp at the bound sorts to
        // the top of its group and moves nothing — before, it read as 30 s of slow blocks and LOWERED the work.
        assert_eq!(w, base, "⛔ ONE block stamped at the drift bound moved the next work from {base} to {w}");
        assert!(
            w * DAA_CLAMP >= base && w <= base * DAA_CLAMP,
            "⛔ ONE block stamped at the drift bound moved the work from {base} to {w} — past the {DAA_CLAMP}× clamp"
        );
    }

    /// DB-394 fixture: `len` on-target blocks, then one child of the tip stamped at `ts`, by `dag.add_block` (no door — the
    /// DAA is a pure function of the chain, and the door's own bounds are proven in `h10_clock_skew…`).
    fn chain_then_child(len: usize, spacing: u64, work: u128, nonce: u64, ts_of: impl Fn(u64) -> u64) -> (Dag, BlockId, u64) {
        let (mut dag, tip) = linear_chain(len, spacing, work);
        let tip_ts = dag.get(&tip).expect("the tip").header.timestamp;
        let child = dag
            .add_block(Block {
                cover_key: None,
                wide_objects: Vec::new(),
                tx_bodies: Vec::new(),
                agg_tables: Vec::new(),
                note_commitments: Vec::new(),
                header: hdr(vec![tip], nonce, ts_of(tip_ts), work),
                tx_ids: vec![],
                pow_proof: Vec::new(),
                output_notes: Vec::new(),
                oli_tags: Vec::new(),
                account_targets: Vec::new(),
                bond_set: Vec::new(),
                credit_set: Vec::new(),
                dir_set: Vec::new(),
                letter_set: Vec::new(),
                tag_evidence: Vec::new(),
                note_transition: None,
                nullifier_proof: crate::block::NfBlockProof::default(),
                cover_transition: None,
                member_transition: None,
            })
            .expect("the child grafts");
        (dag, child, tip_ts)
    }

    /// ⛔ DB-394 (RED-first 2026-10-05 on lane/harness, lost; re-landed 2026-10-27): the DAA window is 60 × 500 ms = 30 s
    /// of chain and the header door admits a stamp 30 s ahead, so on the raw endpoint ONE block stamped at the bound
    /// doubled the measured timespan and cut the next block's work to 495 of 1,000 (MEASURED
    /// scratchpad/verify/f1-flatness-db394-20261022-0452.log). A minority producer re-stamping every block it lays took
    /// ~2× its share of blocks. With median endpoints the stamp moves nothing.
    #[test]
    fn one_block_stamped_at_the_drift_bound_does_not_cut_the_next_blocks_work() {
        let params = crate::params::ChainParams::default();
        let (spacing, work) = (params.target_spacing_ms, 1000u128);
        let len = params.daa_sample_len as usize + 1;
        let (dag_h, honest, _) = chain_then_child(len, spacing, work, 9_001, |t| t + spacing);
        let (dag_s, stamped, _) = chain_then_child(len, spacing, work, 9_002, |t| t + spacing + params.max_ts_drift_ms);
        let (w_honest, w_stamped) = (adaptive_work(&dag_h, Some(honest)), adaptive_work(&dag_s, Some(stamped)));
        eprintln!(
            "[daa-stamp] MEASURED window {} samples × {spacing} ms = {} ms of chain vs drift bound {} ms: the block after an \
             honest stamp needs {w_honest} work, after a drift-bound stamp {w_stamped} ({:.1} % of honest)",
            params.daa_sample_len,
            params.daa_sample_len * spacing,
            params.max_ts_drift_ms,
            100.0 * w_stamped as f64 / w_honest as f64
        );
        assert_eq!(w_honest, work, "CALIBRATION: an honest block at the target spacing keeps the work exactly");
        assert_eq!(
            w_stamped, w_honest,
            "⛔ ONE block stamped at the drift bound cut the next block's work to {w_stamped} of {w_honest} — the DAA window \
             ({} ms) is no wider than the drift the header door admits ({} ms) and the endpoint followed the stamp",
            params.daa_sample_len * spacing,
            params.max_ts_drift_ms
        );
    }

    /// ⛔ DB-394, the floor side: a block stamped at its parent's median-time-past + 1 (the earliest stamp the door admits)
    /// read as a SHORTER window on the raw endpoint and raised the next work to 1,113 of 1,000 (same log). The median
    /// endpoint bounds it to one spacing of the span: a stamp can insert beside the median, never replace the group.
    #[test]
    fn one_block_stamped_at_the_median_floor_does_not_raise_the_next_blocks_work() {
        let params = crate::params::ChainParams::default();
        let (spacing, work) = (params.target_spacing_ms, 1000u128);
        let len = params.daa_sample_len as usize + 1;
        let mtp_floor = (params.mtp_sample_len as u64 / 2) * spacing; // the median of the 11 newest stamps trails the tip by 5 spacings
        let (dag_h, honest, _) = chain_then_child(len, spacing, work, 9_003, |t| t + spacing);
        let (dag_f, floored, _) = chain_then_child(len, spacing, work, 9_004, move |t| t - mtp_floor + 1);
        let (w_honest, w_floored) = (adaptive_work(&dag_h, Some(honest)), adaptive_work(&dag_f, Some(floored)));
        let bound_ms = (params.mtp_sample_len as u64 / 2) * 2 * spacing; // the span between the two median endpoints, less…
        let span_ms = (params.daa_sample_len - params.mtp_sample_len as u64) * spacing; // …is ~49 spacings
        let _ = bound_ms;
        eprintln!(
            "[daa-floor] MEASURED: honest {w_honest}, floor-stamped {w_floored} ({:.1} % of honest); one spacing of the \
             {span_ms} ms span is {:.1} %",
            100.0 * w_floored as f64 / w_honest as f64,
            100.0 * spacing as f64 / span_ms as f64
        );
        assert_eq!(w_honest, work, "CALIBRATION: an honest block at the target spacing keeps the work exactly");
        // bounded by ONE spacing of the span (2.0 % at 500 ms over 49 spacings), rounded up to 3 %
        assert!(
            w_floored >= w_honest && w_floored * 100 <= w_honest * 103,
            "⛔ ONE block stamped at the median floor raised the next block's work to {w_floored} of {w_honest} — more than \
             one spacing of the span"
        );
    }

    /// The stated bound, measured, so the median is not decorative: SIX of the eleven newest selected-chain blocks stamped
    /// at the drift bound DO move the work (that is a majority of recent production — the bound the MTP rule concedes).
    #[test]
    fn six_of_eleven_stamped_blocks_do_move_the_work_so_the_median_is_not_decorative() {
        let params = crate::params::ChainParams::default();
        let (spacing, work) = (params.target_spacing_ms, 1000u128);
        let len = params.daa_sample_len as usize + 1;
        let (mut dag, tip) = linear_chain(len, spacing, work);
        let base = adaptive_work(&dag, Some(tip));
        assert_eq!(base, work, "calibration");
        let majority = params.mtp_sample_len / 2 + 1;
        let mut prev = tip;
        let mut prev_ts = dag.get(&tip).expect("tip").header.timestamp;
        let mut w_after = Vec::new();
        for i in 0..majority {
            prev_ts += spacing + params.max_ts_drift_ms; // every attacker block re-stamps at its own bound
            prev = dag
                .add_block(Block {
                    cover_key: None,
                    wide_objects: Vec::new(),
                    tx_bodies: Vec::new(),
                    agg_tables: Vec::new(),
                    note_commitments: Vec::new(),
                    header: hdr(vec![prev], 9_100 + i as u64, prev_ts, work),
                    tx_ids: vec![],
                    pow_proof: Vec::new(),
                    output_notes: Vec::new(),
                    oli_tags: Vec::new(),
                    account_targets: Vec::new(),
                    bond_set: Vec::new(),
                    credit_set: Vec::new(),
                    dir_set: Vec::new(),
                    letter_set: Vec::new(),
                    tag_evidence: Vec::new(),
                    note_transition: None,
                    nullifier_proof: crate::block::NfBlockProof::default(),
                    cover_transition: None,
                    member_transition: None,
                })
                .expect("grafts");
            w_after.push(adaptive_work(&dag, Some(prev)));
        }
        eprintln!("[daa-majority] work after each of {majority} drift-bound stamps: {w_after:?} (base {base})");
        assert!(
            w_after[..majority - 1].iter().all(|w| *w == base),
            "a MINORITY of the newest eleven ({} of {}) must move nothing: {w_after:?}",
            majority - 1,
            params.mtp_sample_len
        );
        assert!(
            w_after[majority - 1] < base,
            "⛔ {majority} of {} stamped blocks did not move the work — the median is decorative, or wider than stated",
            params.mtp_sample_len
        );
    }

    /// ⭐⭐⭐ DAG-WIDE DIFFICULTY (2026-09-18): two producers at the chain's own spacing DOUBLE the work,
    /// because the window counts the merged siblings; a lone chain is unchanged (the linear pin above).
    /// This is what makes per-node bandwidth a constant in the node count: N producers raise the work
    /// N-fold and the mesh keeps one block rate.
    #[test]
    fn daa_counts_every_blue_block_so_two_producers_share_one_block_rate() {
        let (lone, lone_tip) = linear_chain(30, 500, 1000);
        let (braid, braid_tip) = braided_chain(30, 500, 1000);
        let bs_lone = lone.get(&lone_tip).unwrap().blue_score;
        let bs_braid = braid.get(&braid_tip).unwrap().blue_score;
        assert!(bs_braid > bs_lone, "the braid's siblings are blue: {bs_braid} vs {bs_lone}");
        assert_eq!(adaptive_work(&lone, Some(lone_tip)), 1000, "a lone chain on target keeps its work");
        assert_eq!(
            adaptive_work(&braid, Some(braid_tip)),
            2000,
            "⛔ two producers at the same chain spacing must DOUBLE the work — the DAG's block rate, not \
             one chain's spacing, is the target"
        );
        let (braid_fast, tip_fast) = braided_chain(30, 250, 1000);
        assert_eq!(adaptive_work(&braid_fast, Some(tip_fast)), 4000, "the ×4 clamp still bounds one step");
    }

    /// ⛔ THE VERDICT BESIDE THE FIGURE — WHAT THIS NODE IS AND IS NOT ENTITLED TO JUDGE.
    ///
    /// `adaptive_work_checked` exists so four block doors can bind `header.work` to the DAA value
    /// without a node ever refusing an honest peer over a difficulty it has no standing to judge.
    /// Both directions are asserted, because either alone would let the verdict be wrong: a walk
    /// that ran out at this DAG's OWN genesis IS the chain and may judge; a walk that ran out on
    /// something this node does not hold is a TRUNCATION and may not. The refusal shape this
    /// prevents was MEASURED by the restart schedule search as two-way `WrongWork { expected: 5,
    /// got: 4 }` — and it is exactly what a verdict-free equality would re-introduce at four more
    /// doors than the one that carried it.
    ///
    /// ROOT-LAYER: asserted on the function that PRODUCES the verdict, not on a door that consumes
    /// it — a door holding only the returned `u128` cannot tell a complete reading from a partial
    /// one, which is why the bool is returned beside it rather than re-derived.
    /// MUST-STAY-GREEN: `daa_holds_on_target_and_hardens_when_fast` above — every FIGURE is
    /// unchanged in every case; only the standing to refuse is withheld.
    /// cons: none — one 3-block chain and two calls. f(FIXED CONSTANTS).
    #[test]
    fn the_daa_verdict_judges_its_own_chain_and_never_a_truncated_reading() {
        let (dag, tip) = linear_chain(3, 500, 1000);
        let (figure_own, complete_own) = adaptive_work_checked(&dag, Some(tip));
        assert!(
            complete_own,
            "a walk that ran out at this DAG's OWN genesis has nothing below it to be missing — it \
             IS the chain, and a door that cannot judge here can never judge at all"
        );

        // A block this node does not hold: the walk gathers nothing, and the seed it hands back is
        // a SEED, never a reading of anyone's chain.
        let absent = Hash32::hash(b"a block this node has never seen");
        let (figure_absent, complete_absent) = adaptive_work_checked(&dag, Some(absent));
        eprintln!(
            "[daa-verdict] own=({figure_own},{complete_own}) \
             absent=({figure_absent},{complete_absent})"
        );
        assert!(
            !complete_absent,
            "A NODE WITH NO READING OF THE CHAIN CLAIMED AUTHORITY OVER A PEER'S DIFFICULTY. The \
             figure {figure_absent} is legitimate to PRODUCE on — a node must always be able to \
             build a template — but it is not a reading of any chain, so it must never become a \
             refusal of an honest block."
        );
        assert!(
            figure_absent > 0,
            "the FIGURE must still be produced — withholding the verdict must never withhold the \
             number a producer needs"
        );
    }

    #[test]
    fn template_builds_on_tips_with_adaptive_work() {
        let (dag, _tip) = linear_chain(10, 500, 1000); // on-target spacing (500ms) => template work stays 1000
        let mp = Mempool::new();
        let fr = Hash32::hash(b"frontier");
        let nr = Hash32::hash(b"nullifier");
        let mc = Hash32::hash(b"reward");
        let tmpl = build_template(&dag, &mp, 10_000, fr, nr, mc, Hash32::ZERO, Hash32::ZERO, &[0u8; 32]);
        // parents == current tips
        let mut got = tmpl.header.parents.clone();
        got.sort();
        let mut want = dag.tips();
        want.sort();
        assert_eq!(got, want);
        assert_eq!(tmpl.header.work, 1000);
        assert_eq!(tmpl.header.frontier_root, fr);
        assert_eq!(tmpl.header.miner_commitment, mc);
        // empty mempool => empty tx set + zero merkle root, and nonce/pow_bind unfilled.
        assert!(tmpl.tx_ids.is_empty());
        assert_eq!(tmpl.header.tx_merkle_root, Hash32::ZERO);
        assert_eq!(tmpl.header.nonce, 0);
        assert_eq!(tmpl.header.pow_bind, Hash32::ZERO);
        // chain_acc folded (non-zero once we have roots).
        assert_ne!(tmpl.header.chain_acc, [0u8; 16]);
    }

    /// ⛔ THE TEMPLATE'S WORK IS ITS OWN SELECTED PARENT'S DAA FIGURE (2026-10-20, link 63). `validate_contextual` expects
    /// `adaptive_work(dag, heaviest of the block's OWN parents)`; the template read it from `dag.selected_tip()`, which is
    /// FINALITY-BOUNDED (node-local: a tip that does not descend from this node's floor along its selected chain ranks
    /// below every one that does). When the floor demotes the heaviest tip, the template builds on that tip (its parents
    /// are ordered by the plain key) with the figure of another — and its own graft refuses it. MEASURED
    /// night/perf-load-20261020-230237-n8.log: 75 `[produce] ⛔ this node's OWN mined block was not grafted:
    /// Invalid(WrongWork { expected: 11, got: 12 })`-shaped refusals against 89 blocks the load window kept — each one a
    /// proved and ground block thrown away. The fixture: two branches from genesis, the heavier one fast (its DAA figure
    /// rises), the lighter one slow, and a floor on the lighter branch.
    #[test]
    fn a_templates_work_is_its_own_selected_parents_daa_figure_when_the_finality_floor_moves_the_selected_tip() {
        let blk = |parents: Vec<BlockId>, nonce: u64, ts: u64| Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: hdr(parents, nonce, ts, 1000),
            tx_ids: vec![],
            pow_proof: Vec::new(),
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            note_transition: None,
            nullifier_proof: crate::block::NfBlockProof::default(),
            cover_transition: None,
            member_transition: None,
        };
        let mut dag = Dag::new();
        let g = dag.add_block(blk(vec![], 0, 0)).unwrap();
        let (mut fast, mut slow) = (g, g);
        let mut slow_first = None;
        for i in 1..=24u64 {
            fast = dag.add_block(blk(vec![fast], i, i * 125)).unwrap();
        }
        for i in 1..=6u64 {
            slow = dag.add_block(blk(vec![slow], 1_000 + i, i * 2_000)).unwrap();
            slow_first.get_or_insert(slow);
        }
        dag.set_finality_floor(slow_first);
        let heaviest = *dag.tips().iter().max_by(|a, b| dag.order_key(a).cmp(&dag.order_key(b))).unwrap();
        assert_eq!(heaviest, fast, "fixture: the fast branch is the heavier tip");
        assert_eq!(dag.selected_tip(), Some(slow), "fixture: the floor on the slow branch demotes the heavier tip");
        assert_ne!(adaptive_work(&dag, Some(fast)), adaptive_work(&dag, Some(slow)), "fixture: the two tips' DAA figures differ");

        let tmpl = build_template(&dag, &Mempool::new(), 60_000, Hash32::ZERO, Hash32::ZERO, Hash32::ZERO, Hash32::ZERO, Hash32::ZERO, &[0u8; 32]);
        // the selected parent a validator reads: the heaviest of the template's OWN parents (GHOSTDAG's plain key)
        let sp = *tmpl.header.parents.iter().max_by(|a, b| dag.order_key(a).cmp(&dag.order_key(b))).unwrap();
        // A-F37 (lane goods, 2026-11-11) moved the template onto the FINALITY-RESPECTING head, and A-F58 keeps a heavier
        // sibling that abandons the floor out of it: the heaviest of its own parents is the slow branch's tip. (This line
        // asserted the plain-heaviest tip, the pre-A-F37 template, and was red on main from A-F37 on.) The claim the pin
        // exists for is unchanged and still asserted below: the work is the DAA figure of THAT parent, and the producer's
        // own template passes the door its graft runs.
        assert_eq!(sp, slow, "the template builds on the finality-respecting head; a heavier tip that abandons the floor is no parent");
        assert!(!tmpl.header.parents.contains(&fast), "⛔ A-F54: a heavier tip that abandons the floor is merged into the template");
        assert_eq!(
            tmpl.header.work,
            adaptive_work(&dag, Some(sp)),
            "⛔ the template's work must be the DAA figure of the selected parent the validator reads — the heaviest of its \
             OWN parents — never the finality-bounded selected tip's"
        );
        assert_eq!(
            crate::consensus::validate_contextual(&dag, &tmpl.header),
            Ok(()),
            "⛔ the producer's own template must pass the contextual door its graft runs"
        );
    }

    #[test]
    fn merkle_root_is_deterministic_and_order_sensitive() {
        let a = Hash32::hash(b"a");
        let b = Hash32::hash(b"b");
        let c = Hash32::hash(b"c");
        assert_eq!(tx_merkle_root(&[]), Hash32::ZERO);
        assert_eq!(tx_merkle_root(&[a, b, c]), tx_merkle_root(&[a, b, c]));
        assert_ne!(tx_merkle_root(&[a, b, c]), tx_merkle_root(&[c, b, a]));
    }






}
